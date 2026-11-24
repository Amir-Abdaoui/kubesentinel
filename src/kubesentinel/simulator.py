"""Synthetic telemetry generator (benign workloads + attack scenarios).

Lets you develop/evaluate without a cluster. Results from it are SYNTHETIC; the real
numbers must come from the kind-cluster + attacks/ scripts (see docs/EVALUATION.md).
"""
import time
import numpy as np

SENS = ["/etc/passwd", "/etc/shadow", "/var/run/secrets/kubernetes.io/serviceaccount/token"]
WRITE = ["/etc/cron.d/x", "/usr/bin/payload", "/etc/ld.so.preload"]
INT = [f"10.96.{i}.{j}" for i in range(3) for j in range(1, 5)]
EXT = [f"203.0.113.{i}" for i in range(1, 30)]


def P(exec_, procs, shell, conn, dsts, ports, sens, write, alert, prio="Notice"):
    return dict(exec=exec_, procs=procs, shell=shell, conn=conn, dsts=dsts, ports=ports,
                sens=sens, write=write, alert=alert, prio=prio)


BENIGN = {
    "web": P(0.8, ["nginx"], 0.02, 20, INT[0:3], [5432, 6379], 0.03, 0, 0.01),
    "api": P(1.5, ["python", "gunicorn"], 0.03, 40, INT[4:8], [5432, 443, 9092], 0.05, 0, 0.02),
    "worker": P(4, ["python", "sh", "curl"], 0.3, 12, INT[8:11], [443, 5672], 0.05, 0, 0.02),
    "db": P(0.3, ["postgres"], 0, 6, INT[0:2], [5432], 0.02, 0, 0.0),
    "admin_debug": P(5, ["ls", "ps", "cat"], 1.5, 3, INT[0:3], [443], 1.2, 0, 0.3),  # hard benign case
}
BENIGN_W_TEST = {"web": .35, "api": .3, "worker": .2, "db": .1, "admin_debug": .05}
BENIGN_W_TRAIN = {"web": .36, "api": .31, "worker": .21, "db": .1, "admin_debug": .02}

ATTACKS = {
    "reverse_shell": P(4, ["sh", "nc", "bash"], 1.5, 3, EXT[:3], [4444, 9001], 0.2, 0, 0.8, "Warning"),
    "cryptominer": P(1.5, ["xmrig", "sh"], 0.3, 8, EXT[3:5], [3333, 4444], 0, 0, 0.3, "Warning"),
    "credential_theft": P(3, ["cat", "sh", "curl"], 1, 4, ["10.96.0.1"], [443], 5, 0, 0.6, "Error"),
    "container_escape": P(6, ["nsenter", "mount", "sh"], 1, 1, EXT[5:6], [443], 2, 2, 1.2, "Error"),
    "exfiltration": P(1, ["curl"], 0, 90, EXT[6:8], [443], 0.3, 0, 0.1),          # stealthy
    "stealth_c2": P(2, ["curl"], 0, 10, EXT[8:9], [8443], 0, 0, 0.0),              # hardest
}


def gen_events(profile, pod, rng, ns="ks-demo", scale=None):
    p, s = profile, scale if scale is not None else rng.uniform(0.7, 1.3)
    t, ev = time.time(), []
    base = {"time": t, "pod": pod, "namespace": ns}
    for _ in range(rng.poisson(p["exec"] * s)):
        ev.append({**base, "type": "exec", "proc": str(rng.choice(p["procs"]))})
    for _ in range(rng.poisson(p["shell"] * s)):
        ev.append({**base, "type": "exec", "proc": "sh"})
    for _ in range(rng.poisson(p["conn"] * s)):
        ev.append({**base, "type": "connect", "dst_ip": str(rng.choice(p["dsts"])),
                   "dst_port": int(rng.choice(p["ports"]))})
    for _ in range(rng.poisson(p["sens"] * s)):
        ev.append({**base, "type": "open", "write": False, "file": str(rng.choice(SENS))})
    for _ in range(rng.poisson(p["write"] * s)):
        ev.append({**base, "type": "open", "write": True, "file": str(rng.choice(WRITE))})
    for _ in range(rng.poisson(p["alert"] * s)):
        ev.append({**base, "type": "alert", "rule": "falco", "priority": p["prio"]})
    return ev


def dataset(n_benign, n_attack_each, weights, seed):
    """Returns events-per-window list and labels (0 benign, else attack name)."""
    rng = np.random.default_rng(seed)
    names, w = list(weights), np.array(list(weights.values()), float)
    out, labels = [], []
    for i in range(n_benign):
        k = rng.choice(names, p=w / w.sum())
        out.append(gen_events(BENIGN[k], f"{k}-{i}", rng)); labels.append(0)
    for a, prof in ATTACKS.items():
        for i in range(n_attack_each):
            out.append(gen_events(prof, f"{a}-{i}", rng)); labels.append(a)
    return out, labels
