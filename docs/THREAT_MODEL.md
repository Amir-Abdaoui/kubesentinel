# Threat model (STRIDE + ATT&CK for Containers)
| Scenario | ATT&CK | STRIDE | Script | Expected signal |
|---|---|---|---|---|
| Reverse shell | T1059.004, T1071 | E | attacks/reverse_shell.sh | shell + external connect |
| Crypto-mining | T1496 | D | cryptominer.sh | renamed binary + pool connects |
| Credential theft | T1552.007 | I | credential_theft.sh | SA token / shadow reads |
| Container escape (sim) | T1611 | E | container_escape.sh | writes under /etc,/usr/bin |
| Exfiltration | T1041 | I | exfiltration.sh | connection burst to external IP |
| Stealth C2 | T1071 | — | stealth_c2.sh | low-rate beaconing (hardest) |

**Attacks on KubeSentinel itself:** forged webhook events (token auth, TLS via mesh/ingress → future), responder abuse
(namespace allow-list, Role-scoped RBAC), model poisoning during learn mode (learn only in a trusted window; review baseline),
alert flooding (cooldown), evasion by mimicking baseline (documented limitation).
