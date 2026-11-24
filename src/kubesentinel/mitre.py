"""Map an anomalous window to ATT&CK (containers) + CWE using behavioural heuristics.

Heuristic by design: uses feature counts plus the processes / destination ports seen in the window.
Documented limitation: port/process lists are signatures; a labelled-data classifier is future work.
"""
from .features import FEATURES

I = {k: i for i, k in enumerate(FEATURES)}
MINERS = {"xmrig", "minerd", "cpuminer", "ethminer", "nbminer", "kdevtmpfsi", "kinsing"}
STRATUM_PORTS = {3333, 5555, 7777, 14444, 45700}      # common mining-pool ports
SHELL_C2_PORTS = {4444, 1337, 9001, 31337}            # common reverse-shell listener ports


def classify(vec, procs=(), ports=()):
    g = lambda k: vec[I[k]]
    procs = set(procs)
    ports = {int(p) for p in ports if str(p).isdigit()}
    ext = g("n_external_conn")
    if g("n_write_sensitive") > 0:
        return dict(label="Container escape / privilege escalation", tactic="Privilege Escalation",
                    technique="T1611 Escape to Host", cwe="CWE-250")
    if g("n_sensitive_open") >= 3:
        return dict(label="Credential access (SA token / secrets)", tactic="Credential Access",
                    technique="T1552.007 Container API / T1552.001", cwe="CWE-522")
    if ext >= 50:
        return dict(label="Data exfiltration over network", tactic="Exfiltration",
                    technique="T1041 Exfiltration Over C2 Channel", cwe="CWE-200")
    if procs & MINERS or (ext >= 4 and ports and ports <= STRATUM_PORTS):
        return dict(label="Crypto-mining / resource hijacking", tactic="Impact",
                    technique="T1496 Resource Hijacking", cwe="CWE-400")
    if ext >= 1 and (ports & SHELL_C2_PORTS):
        return dict(label="Reverse shell / interactive C2", tactic="Execution",
                    technique="T1059.004 Unix Shell + T1071", cwe="CWE-78")
    if ext >= 1:
        return dict(label="Suspicious external beaconing", tactic="Command and Control",
                    technique="T1071 Application Layer Protocol", cwe="CWE-923")
    if g("n_shell") >= 1:
        return dict(label="Interactive shell in container", tactic="Execution",
                    technique="T1609 Container Administration Command", cwe="CWE-78")
    return dict(label="Unclassified behavioural anomaly", tactic="Unknown", technique="-", cwe="-")
