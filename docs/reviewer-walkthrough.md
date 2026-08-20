# Reviewer walkthrough

Run `python evaluate.py` and open `artifacts/demo_results.json`.

The checked-in defensive fixture contains 10 events. The evaluation creates 10 alerts and groups them into 4 incidents. Five alerts carry visible rule reasons, including failed authentication, privilege change, unusual outbound transfer, and risky process names. The output also records four ATT&CK technique identifiers: T1041, T1059, T1098, and T1110.

This is local evidence for a code path, not a benchmark claim. The next serious evaluation step is a licensed dataset importer with explicit labels, split strategy, and rules-only versus ML-only baselines.
