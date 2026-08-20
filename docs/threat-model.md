# Threat Model

## Protected capability

This project addresses hybrid SOC detection, anomaly scoring, incident correlation, and evidence-based analyst explanations.

## In-scope threats

The main in-scope threats are credential abuse, privilege changes, suspicious processes, unusual transfers, and noisy security telemetry.

## Trust boundaries

Inputs are untrusted telemetry, configuration, dependency metadata, identity
events, or application text depending on the project. The analysis layer is
read-only in demo mode. No external system is scanned or modified.

## Out of scope

Production access, credential collection, unrestricted tool execution, active
exploitation, and unauthorized data collection are out of scope.
