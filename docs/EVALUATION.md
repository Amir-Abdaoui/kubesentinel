# Evaluation protocol (this is what earns the marks)
1. **Synthetic benchmark** — `make evaluate` (already in docs/RESULTS.md) validates logic only.
2. **Real benchmark (you must run this):** learn baseline ≥1h → run `attacks/run_all.sh` **×30 repetitions**, plus ≥1h of benign
   load (hey/k6 against victim-web, kubectl exec admin sessions). Log ground truth (attack start/end timestamps).
3. Report per method (rules / IForest / hybrid): precision, recall, FPR, F1, **time-to-detect, time-to-contain (p50/p95)**, with 95% CIs.
4. Ablation: without guard, without explainability, window 5/10/30 s.
5. Verify containment: after quarantine, `kubectl exec <pod> -- nc -z 1.1.1.1 443` must fail; evidence hashes verify.
6. Limitations to state honestly: tumbling-window latency, baseline poisoning, evasion by low-and-slow mimicry, single-cluster scope.
