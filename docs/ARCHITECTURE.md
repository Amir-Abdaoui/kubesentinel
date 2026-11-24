# Architecture
```mermaid
flowchart LR
  A[Attack scripts] --> V[victim-web pod]
  V -->|syscalls| F[Falco eBPF + KS rules]
  F --> S[falcosidekick]
  S -->|HTTPS webhook + token| D[KubeSentinel API]
  D --> W[Window aggregator] --> M[IForest + guard] --> H[Hybrid decision]
  R[Signature rules] --> H
  H --> MAP[ATT&CK/CWE + explain]
  H -->|severity=high| RS[Responder]
  RS -->|label| NP[Calico NetworkPolicy deny-all]
  RS --> EV[Evidence + SHA-256]
  MAP --> DB[(SQLite)] --> UI[SOC dashboard]
```
**Features (11):** exec count, unique procs, shells, connections, unique dst, unique ports, external connections,
sensitive reads, sensitive writes, Falco alert count, max priority.
**Design decisions:** tumbling windows (simple, deterministic); FPR-calibrated threshold (2% on training scores);
out-of-support guard (|z|≥8); response only on *high* severity; dry-run default; allow-listed namespaces.
