"""Event normalisation + per-pod window feature extraction."""
import ipaddress
import os
import threading
import time
from collections import defaultdict

FEATURES = [
    "n_exec", "n_unique_proc", "n_shell", "n_connect", "n_unique_dst",
    "n_unique_ports", "n_external_conn", "n_sensitive_open",
    "n_write_sensitive", "n_alerts", "max_priority",
]
SHELLS = {"sh", "bash", "dash", "zsh", "ash"}
PRIORITY = {"Debug": 0, "Informational": 1, "Notice": 2, "Warning": 3,
            "Error": 4, "Critical": 5, "Alert": 6, "Emergency": 7}

# Destinations inside these networks are "internal". On Kubernetes set KS_INTERNAL_CIDRS to the
# service + pod CIDRs (kind/Calico: 10.96.0.0/12,192.168.0.0/16) so e.g. a Docker-network host counts as external.
_INTERNAL = [ipaddress.ip_network(c.strip()) for c in os.environ.get(
    "KS_INTERNAL_CIDRS", "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8").split(",") if c.strip()]


def is_internal(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in _INTERNAL)


TELEMETRY = {
    "KS Telemetry Exec": "exec",
    "KS Telemetry Connect": "connect",
    "KS Telemetry Sensitive Open": "open",
    "KS Telemetry Sensitive Write": "write",
}


def from_falco(p):
    """Convert a Falco/falcosidekick JSON payload to a normalised event (or None)."""
    f = p.get("output_fields") or {}
    pod, ns = f.get("k8s.pod.name"), f.get("k8s.ns.name")
    if not pod or pod == "<NA>":
        return None
    ev = {"time": time.time(), "pod": pod, "namespace": ns or "default"}
    kind = TELEMETRY.get(p.get("rule", ""))
    if kind == "exec":
        ev.update(type="exec", proc=f.get("proc.name", ""), cmdline=f.get("proc.cmdline", ""))
    elif kind == "connect":
        ev.update(type="connect", dst_ip=f.get("fd.sip", ""), dst_port=f.get("fd.sport", 0))
    elif kind in ("open", "write"):
        ev.update(type="open", write=(kind == "write"), file=f.get("fd.name", ""))
    else:
        ev.update(type="alert", rule=p.get("rule", ""), priority=p.get("priority", "Notice"))
    return ev


def vectorize(events):
    procs, dsts, ports = set(), set(), set()
    v = dict.fromkeys(FEATURES, 0)
    for e in events:
        t = e.get("type")
        if t == "exec":
            v["n_exec"] += 1
            procs.add(e.get("proc", ""))
            if e.get("proc") in SHELLS:
                v["n_shell"] += 1
        elif t == "connect":
            v["n_connect"] += 1
            ip = str(e.get("dst_ip", ""))
            dsts.add(ip)
            ports.add(str(e.get("dst_port", "")))
            if not is_internal(ip):
                v["n_external_conn"] += 1
        elif t == "open":
            if e.get("write"):
                v["n_write_sensitive"] += 1
            else:
                v["n_sensitive_open"] += 1
        elif t == "alert":
            v["n_alerts"] += 1
            v["max_priority"] = max(v["max_priority"], PRIORITY.get(e.get("priority"), 2))
    v["n_unique_proc"], v["n_unique_dst"], v["n_unique_ports"] = len(procs), len(dsts), len(ports)
    return [float(v[k]) for k in FEATURES]


class WindowAggregator:
    """Thread-safe event buffer keyed by (namespace, pod) with sliding-window snapshots."""

    def __init__(self):
        self._buf = defaultdict(list)
        self._lock = threading.Lock()

    def add(self, ev):
        with self._lock:
            self._buf[(ev["namespace"], ev["pod"])].append(ev)

    def snapshot(self, window_s, now=None):
        """Events of the last `window_s` seconds per pod; older events are dropped."""
        cutoff = (now or time.time()) - window_s
        out = {}
        with self._lock:
            for k in list(self._buf):
                self._buf[k] = [e for e in self._buf[k] if e["time"] >= cutoff]
                if self._buf[k]:
                    out[k] = list(self._buf[k])
                else:
                    del self._buf[k]
        return out
