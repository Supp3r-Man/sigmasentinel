# Architecture

```
  simulate.py                engine/engine.py               evaluate.py              heatmap.html
 +-------------+  logs.jsonl +----------------+ alerts.jsonl +--------------+ rows  +--------------+
 | benign      |------------>| load rules     |------------->| score vs     |------>| ATT&CK matrix|
 | + noise     |             | match events   |              | truth.jsonl  |       | coverage /   |
 | + attacks   |  truth.jsonl| count/window   |              | (TP/FP/recall)|      | alert counts |
 |  (labelled) |------------>+----------------+              +------+-------+       +--------------+
 +-------------+                    ^                               |
                                    |                               v
                            rules/*.yml (12)                    report.md
```

## Data contracts

- **Log event** (JSONL): `id`, `ts` (UTC ISO-8601), `product`, `category`, `event_type`, plus free-form fields.
- **Truth row** (JSONL, malicious events only): `event_id`, `scenario`, `instance`, `expected_rule`.
- **Alert** (JSONL): `ts`, `rule_id`, `title`, `level`, `attack_technique`, `group`, `matched_event_ids`.

## Rule format (Sigma-like, not Sigma-compatible)

Required: `id, title, logsource, detection, level, attack_technique, falsepositives`.

- `logsource` keys must equal the event's fields (`product`, `category`).
- `detection` holds named selections plus `condition` and optional `timeframe`.
- Selection = map of `field|modifier: value(s)`. A list of values is OR; `|all` makes it AND. A list of maps is OR.
- Modifiers: `contains startswith endswith re gt gte lt lte`. String compares are case-insensitive.
- `condition` = `and / or / not / ( )` over selection names, optionally followed by an aggregation:
  `| count() by user,src_ip >= 10` or `| count(distinct geo_country) by user >= 2` (needs `timeframe`).

## Engine behaviour

1. Events are sorted by timestamp, then each rule is run independently over the stream.
2. Without an aggregation, every matching event raises one alert.
3. With one, matching events go into a sliding window per `by` group. The alert fires when the count or distinct count passes the threshold, then the group is muted for one window (otherwise one burst means hundreds of alerts).

## Scoring

An alert is a TP when it contains any event labelled malicious. Recall is per attack instance: did the expected rule fire on any of its events. Evasive variants are included on purpose, so recall is below 100%.

## Heatmap

`evaluate.py` replaces the JSON between the `/*DATA*/ ... /*END*/` markers in `heatmap.html`, so the page stays a single file that works offline from `file://`.
