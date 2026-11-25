# KubeSentinel benchmark (REAL cluster, dry-run)

reps per attack: 8, gap 35s, seed 21, benign phase 30 min with 46 admin drills

| Attack | Detected | Correct label | High severity | ML flagged | Rules flagged | Time-to-detect p50 / p95 |
|---|---|---|---|---|---|---|
| exfiltration | 100% (8/8, 95% CI 68-100%) | 100% (8/8, 95% CI 68-100%) | 100% (8/8, 95% CI 68-100%) | 100% (8/8, 95% CI 68-100%) | 100% (8/8, 95% CI 68-100%) | 3.3s / 5.6s |
| cryptominer | 100% (8/8, 95% CI 68-100%) | 100% (8/8, 95% CI 68-100%) | 100% (8/8, 95% CI 68-100%) | 100% (8/8, 95% CI 68-100%) | 100% (8/8, 95% CI 68-100%) | 3.8s / 6.3s |
| reverse_shell | 100% (8/8, 95% CI 68-100%) | 100% (8/8, 95% CI 68-100%) | 100% (8/8, 95% CI 68-100%) | 100% (8/8, 95% CI 68-100%) | 100% (8/8, 95% CI 68-100%) | 4.1s / 5.7s |
| exfiltration_nosh | 100% (8/8, 95% CI 68-100%) | 100% (8/8, 95% CI 68-100%) | 100% (8/8, 95% CI 68-100%) | 100% (8/8, 95% CI 68-100%) | 100% (8/8, 95% CI 68-100%) | 5.1s / 7.5s |
| stealth_c2_nosh | 100% (8/8, 95% CI 68-100%) | 100% (8/8, 95% CI 68-100%) | 100% (8/8, 95% CI 68-100%) | 100% (8/8, 95% CI 68-100%) | 100% (8/8, 95% CI 68-100%) | 5.5s / 7.8s |
| container_escape | 100% (8/8, 95% CI 68-100%) | 100% (8/8, 95% CI 68-100%) | 100% (8/8, 95% CI 68-100%) | 100% (8/8, 95% CI 68-100%) | 100% (8/8, 95% CI 68-100%) | 3.6s / 5.7s |
| stealth_c2 | 100% (8/8, 95% CI 68-100%) | 100% (8/8, 95% CI 68-100%) | 100% (8/8, 95% CI 68-100%) | 100% (8/8, 95% CI 68-100%) | 100% (8/8, 95% CI 68-100%) | 4.2s / 5.0s |
| reverse_shell_nosh | 100% (8/8, 95% CI 68-100%) | 100% (8/8, 95% CI 68-100%) | 0% (0/8, 95% CI 0-32%) | 100% (8/8, 95% CI 68-100%) | 0% (0/8, 95% CI 0-32%) | 3.2s / 5.2s |
| credential_theft | 100% (8/8, 95% CI 68-100%) | 100% (8/8, 95% CI 68-100%) | 100% (8/8, 95% CI 68-100%) | 100% (8/8, 95% CI 68-100%) | 100% (8/8, 95% CI 68-100%) | 3.4s / 5.7s |

**Overall detection:** 100% (72/72, 95% CI 95-100%)  |  **correct classification:** 100% (72/72, 95% CI 95-100%)  |  **high severity (would contain):** 89% (64/72, 95% CI 80-94%)

**False alarms in benign phase:** 7 in 30 min = 13.8 per hour (0 high, would have quarantined a benign pod)
**Unmatched alerts during attack phase:** 12

Benign false-alarm detail: Interactive shell in container, Unclassified behavioural anomaly

Notes: intervals are wall-clock ground truth; an alert within 30s after an attack ends counts for it. Detection requires >=1 alert; 'correct label' requires the expected ATT&CK label.
