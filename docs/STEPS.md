# Steps

1. Install deps: `pip install pyyaml pytest`.
2. Look at `rules/`: one YAML file per detection, each with an ATT&CK technique and known false positives.
3. `python simulate.py` writes `data/logs.jsonl` (events) and `data/truth.jsonl` (which events are malicious). Seeded, so reruns are identical.
4. `python -m engine.engine` runs the rules over the logs and writes `data/alerts.jsonl`.
5. `python evaluate.py` runs the engine too, scores alerts against the truth file, writes `report.md` and refreshes `heatmap.html`.
6. Open `heatmap.html`. Toggle Coverage / Alert count, hover a cell for rules and FP notes, or switch to the table view.
7. `pytest` runs the engine tests and one test per rule.
8. Tune: pick a noisy rule from `report.md`, add a `filter_*` selection, rerun, and watch precision move (and recall, if you are careless).

# Interview Q&A

**1. What are the benefits of detection-as-code?**
Rules live in version control, so changes are reviewed, diffed, tested and rolled back like any code. Each rule can ship with unit tests and documented false positives, and CI can block a rule that breaks. It also removes the console-only knowledge problem: anyone can see why a rule exists and who changed it.

**2. Precision vs recall: which matters more?**
Neither alone. Precision is the share of alerts that are real, recall is the share of real attacks you catch. High recall with poor precision buries analysts; high precision with poor recall hides misses. Weight by impact: ransomware precursors justify noisy tolerance, while a medium-severity heuristic that pages someone at 3 a.m. does not. Report both per rule, never one blended number.

**3. How do you deal with alert fatigue?**
Measure FP rate per rule, then tune or retire the worst offenders first. Use thresholds and windows (the engine's cooldown emits one alert per burst), allow-list known-good actors with documented filters, aggregate related alerts into cases, and route by severity. A rule nobody acts on is worse than no rule because it trains people to ignore the next one.

**4. ATT&CK coverage vs detection quality?**
A green cell only says a rule exists. It does not say the rule catches the technique's variants, has acceptable precision, or has the log source behind it. Here the heatmap shows both alert counts and FP notes, and `report.md` lists missed variants (for example `-ec` instead of `-enc`). Treat coverage as a map of gaps, not a score to maximize.

**5. How do you tune a rule?**
Start from real alerts: classify them as TP or FP, find what separates them (parent process, account type, host group), then add a narrow filter or raise a threshold. Change one thing at a time, re-run against labelled data, and record the reason in the rule's `falsepositives`. Re-test recall, because every filter is also a potential evasion path.

**6. What are log source gaps and why do they matter?**
A rule is blind if the telemetry never arrives: no command-line auditing, no DNS logs, no auth logs from a SaaS app. Map each rule to the log source it needs, monitor that the source is actually flowing (a silent source looks like a quiet network), and track gaps as risk. Here the rules assume process, auth, DNS, file and account events exist.

**7. Sigma vs vendor-specific rules?**
Sigma is a vendor-neutral format that compiles to many SIEM query languages, so rules are portable and shareable. Vendor rules can use native features (behavioural analytics, ML, enrichment, response actions) that Sigma cannot express. Use Sigma for portable logic and community content, vendor-native where capability or performance requires it. This project is Sigma-like only: its count syntax is simplified and not interchangeable with real Sigma tooling.

**8. What would you add for production?**
Real log ingestion and parsing with a normalized schema; Sigma conversion to the SIEM's backend; CI running rule tests and linting on pull requests; staged rollout (shadow mode first); enrichment such as asset criticality, identity and threat intel; alert deduplication and case management; log source health monitoring; suppression with expiry dates; metrics on MTTD, FP rate and rule age; and replay against real historical data instead of synthetic logs.
