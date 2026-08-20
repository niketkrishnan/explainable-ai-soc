# Contributing

Contributions should preserve the defensive scope of **Explainable AI SOC Detection and Triage Platform**.
Add tests for behavior changes, document data provenance, and keep credentials
out of commits. Pull requests should explain the threat model, expected
operational effect, and any new limitations.


## Local quality checks

Before opening a pull request, run `python -m compileall -q src tests
evaluate.py`, `pytest -q`, and `python evaluate.py`. Keep changes small enough
that the threat-model impact and regression behavior are easy to review.
