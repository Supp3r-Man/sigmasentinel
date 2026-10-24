"""Run the engine over simulated logs, score it against ground truth, write report.md and refresh heatmap.html.

Usage: python evaluate.py [--rules rules] [--logs data/logs.jsonl] [--truth data/truth.jsonl]
"""
import argparse
import json
import re
from collections import defaultdict
from pathlib import Path

from engine.engine import evaluate, load_rules, read_jsonl, write_jsonl

ROOT = Path(__file__).parent
MARK = re.compile(r"/\*DATA\*/.*?/\*END\*/", re.S)


def pct(x):
    return "n/a" if x is None else f"{x:.0%}"


def score(rules, alerts, truth):
    malicious = {t["event_id"] for t in truth}
    instances = defaultdict(lambda: {"events": set(), "rule": None, "scenario": None})
    for t in truth:
        inst = instances[t["instance"]]
        inst["events"].add(t["event_id"])
        inst["rule"], inst["scenario"] = t["expected_rule"], t["scenario"]
    rows = []
    for rule in rules:
        mine = [a for a in alerts if a["rule_id"] == rule.id]
        tp = sum(1 for a in mine if malicious & set(a["matched_event_ids"]))
        seen = set().union(*(set(a["matched_event_ids"]) for a in mine))
        expected = {k: v for k, v in instances.items() if v["rule"] == rule.id}
        found = {k for k, v in expected.items() if v["events"] & seen}
        rows.append({
            "id": rule.id, "title": rule.title, "technique": rule.technique, "level": rule.level,
            "falsepositives": rule.raw["falsepositives"],
            "alerts": len(mine), "tp": tp, "fp": len(mine) - tp,
            "precision": tp / len(mine) if mine else None,
            "instances": len(expected), "detected": len(found),
            "recall": len(found) / len(expected) if expected else None,
            "missed": sorted({expected[k]["scenario"] for k in expected if k not in found}),
        })
    return rows


def write_report(path, rows, n_events, n_alerts):
    tp, fp = sum(r["tp"] for r in rows), sum(r["fp"] for r in rows)
    inst, det = sum(r["instances"] for r in rows), sum(r["detected"] for r in rows)
    lines = [
        "# SigmaSentinel evaluation report", "",
        f"{n_events} events, {n_alerts} alerts. Synthetic data, so these scores flatter reality.", "",
        "| Rule | Technique | Level | Alerts | TP | FP | Precision | Detected | Recall |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for r in rows:
        lines.append(f"| {r['id']} {r['title']} | {r['technique']} | {r['level']} | {r['alerts']} | {r['tp']} | {r['fp']} "
                     f"| {pct(r['precision'])} | {r['detected']}/{r['instances']} | {pct(r['recall'])} |")
    lines.append(f"| **Total** | | | {n_alerts} | {tp} | {fp} | {pct(tp / n_alerts if n_alerts else None)} "
                 f"| {det}/{inst} | {pct(det / inst if inst else None)} |")
    lines += ["", "## Missed attack scenarios", ""]
    missed = [f"- {r['id']}: {', '.join(r['missed'])}" for r in rows if r["missed"]]
    lines += missed or ["- none (suspiciously good; see the disclaimer)"]
    lines += ["", "## False positives and the usual suspects", ""]
    noisy = [f"- {r['id']}: {r['fp']} FP alert(s). Known causes: {'; '.join(r['falsepositives'])}" for r in rows if r["fp"]]
    lines += noisy or ["- none"]
    lines += ["", "## Definitions", "",
              "- Alert is a TP when it contains at least one event labelled malicious in truth.jsonl; otherwise FP.",
              "- Precision = TP alerts / alerts. Recall = attack instances where the expected rule fired / instances expected for it.",
              "- Several attack variants are deliberately evasive, so recall below 100% is by design."]
    Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")


def refresh_heatmap(path, rows):
    p = Path(path)
    if not p.exists():
        return
    payload = json.dumps({"rules": rows}).replace("</", "<\\/")
    p.write_text(MARK.sub(lambda _: f"/*DATA*/{payload}/*END*/", p.read_text(encoding="utf-8")), encoding="utf-8")


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--rules", default=str(ROOT / "rules"))
    p.add_argument("--logs", default=str(ROOT / "data" / "logs.jsonl"))
    p.add_argument("--truth", default=str(ROOT / "data" / "truth.jsonl"))
    p.add_argument("--alerts", default=str(ROOT / "data" / "alerts.jsonl"))
    p.add_argument("--report", default=str(ROOT / "report.md"))
    p.add_argument("--heatmap", default=str(ROOT / "heatmap.html"))
    args = p.parse_args(argv)
    if not (Path(args.logs).exists() and Path(args.truth).exists()):
        raise SystemExit("logs/truth not found: run `python simulate.py` first")
    rules = load_rules(args.rules)
    events, truth = read_jsonl(args.logs), read_jsonl(args.truth)
    alerts = evaluate(rules, events)
    write_jsonl(args.alerts, alerts)
    rows = score(rules, alerts, truth)
    write_report(args.report, rows, len(events), len(alerts))
    refresh_heatmap(args.heatmap, rows)
    print(f"{len(alerts)} alerts -> {args.alerts}; report -> {args.report}; heatmap refreshed")


if __name__ == "__main__":
    main()
