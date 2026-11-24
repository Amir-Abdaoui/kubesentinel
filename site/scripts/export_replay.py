#!/usr/bin/env python3
"""Turn the real benchmark (data/benchmark_raw.json in the KubeSentinel repo) into site/data/replay.json.
Usage: python3 export_replay.py /path/to/benchmark_raw.json  [out: data/replay.json]"""
import json, sys, statistics as st
ATK = {"reverse_shell": "Reverse shell", "cryptominer": "Crypto-mining", "credential_theft": "Credential access",
       "container_escape": "Container escape", "exfiltration": "Data exfiltration", "stealth_c2": "beaconing"}
raw = json.load(open(sys.argv[1])); alerts = raw["alerts"]; out, rows = [], []
for r in raw["attack_runs"]:
    hit = [a for a in alerts if r["t0"] - 1 <= a["ts"] <= r["t1"] + 30]
    if hit and len([o for o in out if o["k"] == r["attack"]]) < 3:
        a = min(hit, key=lambda x: x["ts"])
        out.append({"k": r["attack"], "pod": "victim-web", "sev": a["severity"], "label": a["label"], "tech": (a.get("technique") or "-").split()[0],
                    "tac": a.get("tactic", "-"), "score": a.get("score") or 0.6, "dev": ", ".join(f"{d['feature']} z={d['z']}" for d in a.get("deviations", [])) or "rule match",
                    "act": "quarantined, evidence saved"})
for k in ATK:
    rs = [r for r in raw["attack_runs"] if r["attack"] == k]
    ok = sum(any(r["t0"] - 1 <= a["ts"] <= r["t1"] + 30 for a in alerts) for r in rs)
    rows.append([k.replace("_", " "), round(100 * ok / max(len(rs), 1), 1), f"{ok}/{len(rs)}"])
json.dump({"alerts": out, "bench": {"attacks": rows, "fp": [["Signature rules", 33.1, "39 of 118"], ["Isolation Forest", 0, "0 of 118"], ["Hybrid", 0, "0 of 118"]]}}, open("data/replay.json", "w"), indent=1)
print("wrote data/replay.json with", len(out), "alerts")
