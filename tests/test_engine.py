import json
import re
from datetime import datetime, timedelta, timezone

import pytest

from engine.engine import Rule, evaluate, load_rules, main, parse_timeframe, read_jsonl

T0 = datetime(2026, 1, 12, 9, 0, tzinfo=timezone.utc)
BASE = {"id": "T-1", "title": "t", "logsource": {}, "level": "low", "attack_technique": "T1000", "falsepositives": ["x"]}
COUNT = {"selection": {"x": 1}, "timeframe": "1m", "condition": "selection | count() by host >= 3"}
RULE_YAML = """\
id: T-1
title: t
logsource: {}
detection:
  selection:
    x: 1
  condition: selection
level: low
attack_technique: T1000
falsepositives: [x]
"""


def rule(detection, **extra):
    return Rule({**BASE, "detection": detection, **extra})


def ev(i, sec=0, **fields):
    return {"id": f"e{i}", "ts": (T0 + timedelta(seconds=sec)).strftime("%Y-%m-%dT%H:%M:%SZ"), **fields}


def test_parse_timeframe():
    assert parse_timeframe("90s") == timedelta(seconds=90)
    assert parse_timeframe("2h") == timedelta(hours=2)
    with pytest.raises(ValueError):
        parse_timeframe("soon")


def test_shipped_rules_are_well_formed(rules):
    assert len(rules) == 12
    for r in rules.values():
        assert re.fullmatch(r"T\d{4}(\.\d{3})?", r.technique), r.id
        assert r.raw["falsepositives"], r.id
        assert r.level in {"low", "medium", "high", "critical"}, r.id


def test_missing_required_field_is_rejected():
    with pytest.raises(ValueError, match="missing fields"):
        Rule({"id": "X"})


def test_undefined_selection_is_rejected():
    with pytest.raises(ValueError, match="undefined selections"):
        rule({"selection": {"a": 1}, "condition": "selection and other"})


def test_count_without_timeframe_is_rejected():
    with pytest.raises(ValueError, match="timeframe"):
        rule({"selection": {"a": 1}, "condition": "selection | count() >= 2"})


def test_unparseable_aggregation_is_rejected():
    with pytest.raises(ValueError, match="aggregation"):
        rule({"selection": {"a": 1}, "timeframe": "1m", "condition": "selection | sum() > 3"})


def test_duplicate_rule_ids_are_rejected(tmp_path):
    (tmp_path / "a.yml").write_text(RULE_YAML)
    (tmp_path / "b.yml").write_text(RULE_YAML)
    with pytest.raises(ValueError, match="duplicate"):
        load_rules(tmp_path)


@pytest.mark.parametrize("sel,event,hit", [
    ({"cmd|contains": "WHOAMI"}, {"cmd": "cmd /c whoami"}, True),
    ({"cmd|startswith": "cmd"}, {"cmd": "CMD /c dir"}, True),
    ({"cmd|endswith": ".exe"}, {"cmd": "a.exe"}, True),
    ({"cmd|endswith": ".exe"}, {"cmd": "a.dll"}, False),
    ({"cmd|re": r"^a\d+$"}, {"cmd": "a42"}, True),
    ({"n|gt": 5}, {"n": 6}, True),
    ({"n|gt": 5}, {"n": 5}, False),
    ({"n|gte": 5}, {"n": 5}, True),
    ({"n|lt": 5}, {"n": "4"}, True),
    ({"n|lte": 5}, {"n": "x"}, False),
    ({"cmd|contains|all": ["a", "b"]}, {"cmd": "ab"}, True),
    ({"cmd|contains|all": ["a", "z"]}, {"cmd": "ab"}, False),
    ({"cmd": ["x", "y"]}, {"cmd": "Y"}, True),
    ({"missing": "x"}, {"cmd": "x"}, False),
])
def test_field_modifiers(sel, event, hit):
    r = rule({"selection": sel, "condition": "selection"})
    assert bool(evaluate([r], [ev(1, **event)])) is hit


def test_condition_boolean_logic():
    det = {"a": {"x": 1}, "b": {"y": 1}, "c": {"z": 1}}
    cases = [
        ("a and b", {"x": 1, "y": 1}, True),
        ("a and b", {"x": 1}, False),
        ("a or b", {"y": 1}, True),
        ("a and not b", {"x": 1, "y": 1}, False),
        ("a and not b", {"x": 1}, True),
        ("(a or b) and c", {"x": 1}, False),
        ("(a or b) and c", {"y": 1, "z": 1}, True),
    ]
    for cond, fields, hit in cases:
        r = rule({**det, "condition": cond})
        assert bool(evaluate([r], [ev(1, **fields)])) is hit, cond


def test_list_of_maps_is_or():
    r = rule({"selection": [{"x": 1}, {"y": 2}], "condition": "selection"})
    assert len(evaluate([r], [ev(1, x=1), ev(2, y=2), ev(3, z=3)])) == 2


def test_logsource_filters_events():
    r = rule({"selection": {"x": 1}, "condition": "selection"}, logsource={"category": "dns"})
    alerts = evaluate([r], [ev(1, x=1, category="dns"), ev(2, x=1, category="auth")])
    assert [a["matched_event_ids"] for a in alerts] == [["e1"]]


def test_count_fires_at_threshold_and_carries_events():
    alerts = evaluate([rule(COUNT)], [ev(i, i * 10, x=1, host="a") for i in range(3)])
    assert len(alerts) == 1
    assert alerts[0]["matched_event_ids"] == ["e0", "e1", "e2"]
    assert alerts[0]["group"] == {"host": "a"}


def test_count_below_threshold_or_outside_window_does_not_fire():
    assert not evaluate([rule(COUNT)], [ev(i, i * 10, x=1, host="a") for i in range(2)])
    assert not evaluate([rule(COUNT)], [ev(i, i * 40, x=1, host="a") for i in range(3)])


def test_count_groups_are_independent():
    events = [ev(i, i, x=1, host="ab"[i % 2]) for i in range(4)]
    assert not evaluate([rule(COUNT)], events)


def test_count_alerts_once_per_window():
    assert len(evaluate([rule(COUNT)], [ev(i, i * 5, x=1, host="a") for i in range(8)])) == 1


def test_distinct_count():
    r = rule({"selection": {"x": 1}, "timeframe": "1h", "condition": "selection | count(distinct country) by user >= 2"})
    same = [ev(i, i, x=1, user="u", country="US") for i in range(5)]
    assert not evaluate([r], same)
    assert len(evaluate([r], same[:1] + [ev(9, 30, x=1, user="u", country="RO")])) == 1


def test_events_are_processed_in_time_order():
    events = [ev(i, s, x=1, host="a") for i, s in [(0, 20), (1, 0), (2, 10)]]
    alerts = evaluate([rule(COUNT)], events)
    assert alerts[0]["matched_event_ids"] == ["e1", "e2", "e0"]


def test_cli_writes_jsonl_alerts(tmp_path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "r.yml").write_text(RULE_YAML)
    logs, out = tmp_path / "logs.jsonl", tmp_path / "out" / "alerts.jsonl"
    logs.write_text("\n".join(json.dumps(e) for e in [ev(1, x=1), ev(2, x=2)]) + "\n")
    main(["--rules", str(rules_dir), "--logs", str(logs), "--out", str(out)])
    alerts = read_jsonl(out)
    assert [a["rule_id"] for a in alerts] == ["T-1"]
    assert alerts[0]["matched_event_ids"] == ["e1"]
