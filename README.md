# Explainable AI SOC Detection and Triage Platform

A defensive portfolio project that combines transparent detection rules, an Isolation Forest anomaly model, incident correlation, and evidence-based analyst explanations. It is designed to demonstrate detection engineering and responsible use of ML in a SOC workflow.

> **Authorized-use notice:** This repository scores supplied telemetry only. It does not scan networks, execute endpoint commands, or access external systems.

## Current MVP

The MVP loads a small local telemetry fixture, trains the anomaly detector, applies security rules, creates explanations, correlates alerts into incidents, and writes `artifacts/demo_results.json`. The fixture is intentionally small and is not a production benchmark.

## Run locally

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
python evaluate.py
pytest
```

## Architecture

```text
CSV/JSONL telemetry -> normalized SecurityEvent -> rules + Isolation Forest
                                  |                     |
                                  +--------> evidence + risk score
                                                        |
                                              incident correlation
                                                        |
                                               JSON analyst report
```

## Evaluation plan

The next milestone is to compare rules-only, ML-only, and hybrid detection on a licensed public benchmark such as UNSW-NB15 or CICIDS2017 after verifying its terms. The repository will report precision, recall, F1, false positives per 1,000 events, detection latency, and explanation completeness. No performance claims are made from the starter fixture.

## Project structure

```text
src/soc_detector.py       Core event, alert, model, and correlation logic
data/events.csv           Local defensive demo fixture
evaluate.py               Reproducible demo evaluation
tests/                    Regression tests
```

## Roadmap

- Add a public licensed benchmark importer with a documented schema mapping.
- Add FastAPI endpoints and a minimal analyst dashboard.
- Add ATT&CK technique coverage reports and alert-deduplication metrics.
- Add CI and a versioned evaluation artifact.

## Development milestones

The repository history is organized into incremental documentation, implementation, testing, evaluation, and release milestones.
