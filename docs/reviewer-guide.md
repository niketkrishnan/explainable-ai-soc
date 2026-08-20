# Reviewer Guide

## Five-minute path

1. Run `python evaluate.py` and inspect the committed JSON artifact.
2. Read the normalized event schema and rule evidence in `src/soc_detector.py`.
3. Review tests for invalid events, risky rules, incident correlation, and explanation completeness.
4. Discuss the rules-only versus ML-assisted trade-off and the fixture-only evaluation boundary.

## Evidence of engineering judgment

The project separates detection, explanation, correlation, and reporting. It avoids active response and keeps the evidence contract testable.
