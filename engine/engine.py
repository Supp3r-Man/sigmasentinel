"""SigmaSentinel rule engine: Sigma-like YAML rules evaluated against JSONL logs.

Usage: python -m engine.engine --rules rules --logs data/logs.jsonl --out data/alerts.jsonl
"""
import argparse
import json
import operator
import re
from collections import defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path

import yaml

REQUIRED = ("id", "title", "logsource", "detection", "level", "attack_technique", "falsepositives")
UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}
CMP = {">=": operator.ge, ">": operator.gt, "<=": operator.le, "<": operator.lt, "==": operator.eq}
NUM_MODS = {"gt": operator.gt, "gte": operator.ge, "lt": operator.lt, "lte": operator.le}
STR_MODS = {
    "eq": lambda v, e: v == e,
    "contains": lambda v, e: e in v,
    "startswith": lambda v, e: v.startswith(e),
    "endswith": lambda v, e: v.endswith(e),
}
AGG_RE = re.compile(
    r"^count\(\s*(?:distinct\s+(?P<distinct>[\w.]+))?\s*\)"
    r"(?:\s+by\s+(?P<by>[\w.,\s]+?))?\s*(?P<op>>=|<=|==|>|<)\s*(?P<n>\d+)$"
)
TOKEN_RE = re.compile(r"[()]|[^\s()]+")


def parse_timeframe(text):
    m = re.fullmatch(r"(\d+)([smhd])", str(text).strip())
    if not m:
        raise ValueError(f"bad timeframe {text!r} (use e.g. 30s, 5m, 1h)")
    return timedelta(seconds=int(m[1]) * UNITS[m[2]])


def parse_ts(text):
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


def _parse_condition(text):
    """Boolean expression over selection names: and / or / not / parentheses."""
    toks = TOKEN_RE.findall(text)
    pos = [0]

    def peek():
        return toks[pos[0]].lower() if pos[0] < len(toks) else None

    def take():
        pos[0] += 1
        return toks[pos[0] - 1]

    def or_():
        node = and_()
        while peek() == "or":
            take()
            node = ("or", node, and_())
        return node

    def and_():
        node = not_()
        while peek() == "and":
            take()
            node = ("and", node, not_())
        return node

    def not_():
        if peek() == "not":
            take()
            return ("not", not_())
        return atom()

    def atom():
        if peek() == "(":
            take()
            node = or_()
            if peek() != ")":
                raise ValueError(f"unbalanced parentheses in condition: {text!r}")
            take()
            return node
        if peek() is None or peek() in ("and", "or", ")"):
            raise ValueError(f"unexpected token in condition: {text!r}")
        return ("sel", take())

    node = or_()
    if pos[0] != len(toks):
        raise ValueError(f"trailing tokens in condition: {text!r}")
    return node


def _names(node):
    if node[0] == "sel":
        return {node[1]}
    return set().union(*(_names(n) for n in node[1:]))


def _eval(node, hits):
    kind = node[0]
    if kind == "sel":
        return hits[node[1]]
    if kind == "not":
        return not _eval(node[1], hits)
    left = _eval(node[1], hits)
    if kind == "and":
        return left and _eval(node[2], hits)
    return left or _eval(node[2], hits)


def _parse_agg(text, rule_id):
    m = AGG_RE.match(text)
    if not m:
        raise ValueError(f"rule {rule_id}: cannot parse aggregation {text!r}")
    by = [f.strip() for f in (m["by"] or "").split(",") if f.strip()]
    return {"distinct": m["distinct"], "by": by, "op": CMP[m["op"]], "n": int(m["n"])}


def _compare(value, op, expected):
    if value is None or expected is None:
        return value is None and expected is None and op == "eq"
    if op in NUM_MODS:
        try:
            return NUM_MODS[op](float(value), float(expected))
        except (TypeError, ValueError):
            return False
    if op == "re":
        return re.search(str(expected), str(value), re.I) is not None
    if op not in STR_MODS:
        raise ValueError(f"unknown field modifier: {op}")
    return STR_MODS[op](str(value).lower(), str(expected).lower())


def _match_field(key, expected, event):
    field, *mods = key.split("|")
    require_all = "all" in mods
    mods = [m for m in mods if m != "all"]
    op = mods[0] if mods else "eq"
    wanted = expected if isinstance(expected, list) else [expected]
    results = (_compare(event.get(field), op, w) for w in wanted)
    return all(results) if require_all else any(results)


def _match_selection(selection, event):
    if isinstance(selection, list):  # list of maps = OR
        return any(_match_selection(s, event) for s in selection)
    return all(_match_field(key, expected, event) for key, expected in selection.items())


class Rule:
    def __init__(self, raw):
        missing = [k for k in REQUIRED if k not in raw]
        if missing:
            raise ValueError(f"rule {raw.get('id', '?')} is missing fields: {', '.join(missing)}")
        det = raw["detection"]
        if "condition" not in det:
            raise ValueError(f"rule {raw['id']} has no detection.condition")
        self.raw = raw
        self.id, self.title, self.level = raw["id"], raw["title"], raw["level"]
        self.technique = raw["attack_technique"]
        self.logsource = raw["logsource"] or {}
        self.selections = {k: v for k, v in det.items() if k not in ("condition", "timeframe")}
        cond, _, agg = str(det["condition"]).partition("|")
        self.expr = _parse_condition(cond)
        unknown = _names(self.expr) - set(self.selections)
        if unknown:
            raise ValueError(f"rule {self.id}: condition uses undefined selections {sorted(unknown)}")
        self.agg = _parse_agg(agg.strip(), self.id) if agg.strip() else None
        self.window = parse_timeframe(det["timeframe"]) if "timeframe" in det else None
        if self.agg and self.window is None:
            raise ValueError(f"rule {self.id}: count() needs detection.timeframe")

    def matches(self, event):
        if any(event.get(k) != v for k, v in self.logsource.items()):
            return False
        hits = {name: _match_selection(sel, event) for name, sel in self.selections.items()}
        return _eval(self.expr, hits)


def load_rules(path):
    rules = []
    for f in sorted(Path(path).glob("*.yml")):
        try:
            rules.append(Rule(yaml.safe_load(f.read_text(encoding="utf-8"))))
        except (ValueError, AttributeError) as exc:
            raise ValueError(f"{f.name}: {exc}") from exc
    ids = [r.id for r in rules]
    dupes = sorted({i for i in ids if ids.count(i) > 1})
    if dupes:
        raise ValueError(f"duplicate rule ids: {dupes}")
    return rules


def _alert(rule, event, matched, group):
    return {
        "ts": event["ts"],
        "rule_id": rule.id,
        "title": rule.title,
        "level": rule.level,
        "attack_technique": rule.technique,
        "group": group,
        "matched_event_ids": [e["id"] for e in matched],
    }


def _run_rule(rule, timed):
    windows, last_fire = defaultdict(deque), {}
    for ts, event in timed:
        if not rule.matches(event):
            continue
        if rule.agg is None:
            yield _alert(rule, event, [event], None)
            continue
        key = tuple(event.get(f) for f in rule.agg["by"])
        window = windows[key]
        window.append((ts, event))
        while window[0][0] < ts - rule.window:
            window.popleft()
        if key in last_fire and ts - last_fire[key] < rule.window:
            continue  # cooldown: one alert per group per window, not one per event
        if rule.agg["distinct"]:
            value = len({e.get(rule.agg["distinct"]) for _, e in window} - {None})
        else:
            value = len(window)
        if rule.agg["op"](value, rule.agg["n"]):
            last_fire[key] = ts
            yield _alert(rule, event, [e for _, e in window], dict(zip(rule.agg["by"], key)))


def evaluate(rules, events):
    timed = sorted(((parse_ts(e["ts"]), e) for e in events), key=lambda p: p[0])
    alerts = [a for rule in rules for a in _run_rule(rule, timed)]
    return sorted(alerts, key=lambda a: parse_ts(a["ts"]))


def read_jsonl(path):
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def write_jsonl(path, rows):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        for row in rows:
            fh.write(json.dumps(row) + "\n")


def main(argv=None):
    p = argparse.ArgumentParser(description="Evaluate Sigma-like rules against JSONL logs.")
    p.add_argument("--rules", default="rules")
    p.add_argument("--logs", default="data/logs.jsonl")
    p.add_argument("--out", default="data/alerts.jsonl")
    args = p.parse_args(argv)
    rules = load_rules(args.rules)
    events = read_jsonl(args.logs)
    alerts = evaluate(rules, events)
    write_jsonl(args.out, alerts)
    print(f"{len(rules)} rules, {len(events)} events -> {len(alerts)} alerts ({args.out})")


if __name__ == "__main__":
    main()
