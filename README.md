# SigmaSentinel
**🚨 We wrote the attackers a script, then caught them reading it.**
## What it does
12 Sigma-like rules, a small Python engine, synthetic logs and an ATT&CK heatmap. Detection-as-code, local only, concept only.
## Run it
`pip install pyyaml pytest`, then `python simulate.py && python evaluate.py`, open `heatmap.html`, and `pytest` if you feel brave.
## Rule of the week
SS-005 log clearing: the digital equivalent of shredding the receipt while whistling "nothing to see here".
## Honest disclaimer
The data is synthetic, so the scores flatter reality. Real networks are ruder.
## Things that went wrong while building this
- Nothing was run during the build, so your first `pytest` may find a typo before any attacker does.
- It is Sigma-like, not Sigma-compatible: the `count() by` syntax is our own, and real Sigma tooling will politely refuse it.

Tune your rules, mind your false positives, and may your pager stay quiet. ☕
