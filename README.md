# SOC Detection Engine with Explainable ML Triage

[![CI](https://github.com/niketkrishnan/explainable-ai-soc/actions/workflows/ci.yml/badge.svg)](https://github.com/niketkrishnan/explainable-ai-soc/actions/workflows/ci.yml)

A SOC detection pipeline that pairs transparent, rule-based signals with an Isolation Forest anomaly model, then correlates the results into incidents with evidence an analyst can actually inspect and challenge. Built to explore a question detection engineering keeps running into: a model that just outputs a risk score isn't useful to an analyst who has to justify escalating it -- the evidence behind the score matters as much as the score itself.

This project only scores telemetry that's handed to it. It doesn't scan networks, touch endpoints, or reach out to any external system.

## How it works

```
CSV/JSONL telemetry -> normalized SecurityEvent -> rules engine + Isolation Forest
                                  |
                        evidence + composite risk score
                                  |
                          incident correlation
                                  |
                         JSON analyst report
```

The core design choice: rule evidence and the anomaly score are kept separate rather than blended into one opaque number. An analyst can trust, tune, or override either signal independently -- which matters more in practice than squeezing out marginal accuracy from a single fused score.

## Try it

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
python evaluate.py
pytest
```

This runs the pipeline against a small local telemetry fixture and writes `artifacts/demo_results.json`. The fixture exists to demonstrate the mechanics end-to-end -- it's not a production benchmark, and no accuracy numbers are claimed from it.

## What's actually being evaluated (in progress)

The next milestone is running rules-only, ML-only, and hybrid detection side by side on a licensed public benchmark (UNSW-NB15 or CICIDS2017, pending license verification) and reporting real precision, recall, F1, false positives per 1,000 events, and detection latency. That comparison -- not the local fixture -- is what will make any accuracy claim in this repo meaningful, and it's the reason no such claim exists yet.

## Where to look first

- `src/soc_detector.py` -- the event, alert, model, and correlation logic
- `tests/test_soc_detector.py` -- the regression suite
- `artifacts/demo_results.json` -- the reproducible demo output

## What this project actually taught me

A working anomaly model isn't enough on its own. What determines whether a SOC analyst can trust a detection is the evidence trail behind it, a schema stable enough to build automation on top of, sensible incident grouping instead of alert floods, and being explicit about where the evaluation boundaries are. It's easy to build a detector that looks good on a demo fixture and says nothing true about production behavior -- this project is as much about being honest about that gap as it is about the detection logic itself.

## Roadmap

- Public benchmark importer (UNSW-NB15 / CICIDS2017) with documented schema mapping
- FastAPI endpoints + a minimal analyst dashboard
- MITRE ATT&CK technique coverage reporting and alert-deduplication metrics
- Versioned evaluation artifacts wired into CI

## Limitations

The committed telemetry is a small local fixture -- it does not establish production precision, recall, latency, or cross-organization generalization. Any future benchmark claim in this repo will come with dataset terms, version, split strategy, baseline comparison, and the exact commands to reproduce it.
