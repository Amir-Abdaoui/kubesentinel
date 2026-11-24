# KubeSentinel benchmark (REAL cluster, dry-run)

reps per attack: 10, gap 35s, seed 7, benign phase 30 min with 44 admin drills

| Attack | Detected | Correct label | High severity | ML flagged | Rules flagged | Time-to-detect p50 / p95 |
|---|---|---|---|---|---|---|
| exfiltration | 100% (10/10, 95% CI 72-100%) | 100% (10/10, 95% CI 72-100%) | 100% (10/10, 95% CI 72-100%) | 100% (10/10, 95% CI 72-100%) | 100% (10/10, 95% CI 72-100%) | 3.4s / 5.9s |
| reverse_shell | 100% (10/10, 95% CI 72-100%) | 100% (10/10, 95% CI 72-100%) | 100% (10/10, 95% CI 72-100%) | 0% (0/10, 95% CI 0-28%) | 100% (10/10, 95% CI 72-100%) | 2.9s / 5.4s |
| stealth_c2 | 100% (10/10, 95% CI 72-100%) | 100% (10/10, 95% CI 72-100%) | 100% (10/10, 95% CI 72-100%) | 60% (6/10, 95% CI 31-83%) | 100% (10/10, 95% CI 72-100%) | 4.6s / 5.7s |
| container_escape | 100% (10/10, 95% CI 72-100%) | 100% (10/10, 95% CI 72-100%) | 100% (10/10, 95% CI 72-100%) | 100% (10/10, 95% CI 72-100%) | 100% (10/10, 95% CI 72-100%) | 3.9s / 6.3s |
| cryptominer | 100% (10/10, 95% CI 72-100%) | 100% (10/10, 95% CI 72-100%) | 100% (10/10, 95% CI 72-100%) | 100% (10/10, 95% CI 72-100%) | 100% (10/10, 95% CI 72-100%) | 4.2s / 5.8s |
| credential_theft | 100% (10/10, 95% CI 72-100%) | 100% (10/10, 95% CI 72-100%) | 100% (10/10, 95% CI 72-100%) | 100% (10/10, 95% CI 72-100%) | 100% (10/10, 95% CI 72-100%) | 3.0s / 6.3s |

**Overall detection:** 100% (60/60, 95% CI 94-100%)  |  **correct classification:** 100% (60/60, 95% CI 94-100%)  |  **high severity (would contain):** 100% (60/60, 95% CI 94-100%)

**False alarms in benign phase:** 15 in 30 min = 29.8 per hour (14 high, would have quarantined a benign pod)
**Unmatched alerts during attack phase:** 9

Benign false-alarm detail: Interactive shell in container, Unclassified behavioural anomaly

Notes: intervals are wall-clock ground truth; an alert within 30s after an attack ends counts for it. Detection requires >=1 alert; 'correct label' requires the expected ATT&CK label.
