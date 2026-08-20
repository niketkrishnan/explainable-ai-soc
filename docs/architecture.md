# Architecture

```text
local defensive telemetry fixtures plus a future licensed public-benchmark importer -> normalized input -> security analysis -> explainable result
                                                |
                                         tests and evaluation
```

The repository keeps the core analysis logic independent from the command-line
evaluation entry point. This supports deterministic unit tests and makes it
possible to add an API or dashboard without changing the security boundary.


## Extension points

New detections should be introduced as small, explainable functions with a named
technique, a regression fixture, and an explicit false-positive consideration.
Model changes should expose feature names and preserve the rules-only baseline.
