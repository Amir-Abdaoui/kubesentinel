#!/usr/bin/env python3
"""Automated, randomised benchmark of KubeSentinel on the real cluster.

  python scripts/benchmark.py run --reps 10 --benign-min 30   # collect (about 1h) then report
  python scripts/benchmark.py report                          # re-analyse data/benchmark_raw.json

Attack phase: every attack x reps, shuffled, with a gap so incidents don't merge. Benign phase: random admin
drills (no attacks). Ground truth = wall-clock intervals recorded here; alerts are read from the detector.
Run with the detector in dry-run (containment is benchmarked separately: it would cut the network).
"""
import argparse, json, math, os, random, statistics, subprocess, time

ATTACKS = {"reverse_shell": "Reverse shell", "cryptominer": "Crypto-mining", "credential_theft": "Credential access",
           "container_escape": "Container escape", "exfiltration": "Data exfiltration",
           "stealth_c2": "Suspicious external beaconing",
           "reverse_shell_nosh": "Reverse shell", "exfiltration_nosh": "Data exfiltration",
           "stealth_c2_nosh": "Suspicious external beaconing"}
DRILLS = [("victim-web", "ls /etc; ps; cat /etc/hostname"), ("victim-web", "df -h; id; ls /var/log/nginx"),
          ("worker", "ls /tmp; date; ps"), ("api-client", "ps; id; cat /etc/hostname"),
          ("poller", "date; ls /; ps"), ("victim-web", "wget -q -O- http://victim-web >/dev/null; echo ok"),
          ("worker", "cat /etc/os-release; uname -a")]
# Training drills differ from the test drills above, so the held-out benchmark measures generalisation.
TRAIN_DRILLS = [("victim-web", "ls -la /usr/share/nginx/html; head -5 /etc/nginx/nginx.conf; ps"),
                ("victim-web", "env | sort | head; id; hostname"), ("victim-web", "nginx -t 2>&1; date; ls /var/log/nginx"),
                ("worker", "ps aux; ls /tmp; cat /etc/hostname"), ("worker", "df -h; uptime; id"),
                ("api-client", "ls /; ps; id; date"), ("poller", "cat /etc/resolv.conf; ps; date"),
                ("poller", "uname -a; ls /proc | head -3; id")]
RAW = "data/benchmark_raw.json"
MARGIN = 30  # seconds after an attack ends during which an alert still belongs to it


def kexec(deploy, cmd, ns="ks-demo"):
    return subprocess.run(["kubectl", "-n", ns, "exec", f"deploy/{deploy}", "--", "sh", "-c", cmd],
                          capture_output=True, text=True)


def fetch_alerts():
    py = "import urllib.request;print(urllib.request.urlopen('http://localhost:8080/api/alerts?limit=5000').read().decode())"
    r = subprocess.run(["kubectl", "-n", "ks-system", "exec", "deploy/ks-detector", "--", "python", "-c", py],
                       capture_output=True, text=True)
    return json.loads(r.stdout)


def collect(a):
    rnd = random.Random(a.seed)
    raw = {"meta": {"reps": a.reps, "gap_s": a.gap, "benign_min": a.benign_min, "seed": a.seed,
                    "started": time.time()}, "attack_runs": [], "benign": {}}
    total = a.reps * len(ATTACKS)
    n = 0
    for rep in range(a.reps):
        order = list(ATTACKS)
        rnd.shuffle(order)
        for atk in order:
            n += 1
            t0 = time.time()
            subprocess.run([f"attacks/{atk}.sh"], capture_output=True, text=True)
            raw["attack_runs"].append({"rep": rep, "attack": atk, "t0": t0, "t1": time.time()})
            print(f"[{n}/{total}] {atk} done", flush=True)
            time.sleep(a.gap)
        json.dump(raw, open(RAW, "w"))
    b0, drills = time.time(), []
    print(f"benign phase: {a.benign_min} min of admin drills", flush=True)
    while time.time() - b0 < a.benign_min * 60:
        pod, cmd = rnd.choice(DRILLS)
        drills.append({"t": time.time(), "pod": pod, "cmd": cmd}); kexec(pod, cmd)
        time.sleep(rnd.uniform(25, 60))
    raw["benign"] = {"t0": b0, "t1": time.time(), "drills": drills}
    time.sleep(20)
    raw["alerts"] = fetch_alerts()
    json.dump(raw, open(RAW, "w"))


def wilson(k, n, z=1.96):
    if n == 0:
        return (0.0, 0.0)
    p, d = k / n, 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0, c - h), min(1, c + h))


def pct(k, n):
    lo, hi = wilson(k, n)
    return f"{100 * k / n:.0f}% ({k}/{n}, 95% CI {100 * lo:.0f}-{100 * hi:.0f}%)" if n else "n/a"


def report():
    raw = json.load(open(RAW))
    alerts, runs = raw["alerts"], raw["attack_runs"]
    per, used = {}, set()
    for r in runs:
        hits = [x for x in alerts if r["t0"] - 1 <= x["ts"] <= r["t1"] + MARGIN]
        used.update(x["id"] for x in hits)
        want = ATTACKS[r["attack"]]
        d = per.setdefault(r["attack"], dict(n=0, det=0, ok=0, high=0, ml=0, rule=0, ttd=[]))
        d["n"] += 1
        if hits:
            d["det"] += 1
            d["ok"] += any(want in x["label"] for x in hits)
            d["high"] += any(x["severity"] == "high" for x in hits)
            d["ml"] += any(x["ml_anomaly"] for x in hits)
            d["rule"] += any(x["rules"] for x in hits)
            d["ttd"].append(min(x["ts"] for x in hits) - r["t0"])
    b = raw["benign"]
    fp_b = [x for x in alerts if b["t0"] <= x["ts"] <= b["t1"]]
    fp_gap = [x for x in alerts if x["id"] not in used and not (b["t0"] <= x["ts"] <= b["t1"])]
    hrs = (b["t1"] - b["t0"]) / 3600
    L = ["# KubeSentinel benchmark (REAL cluster, dry-run)", "",
         f"reps per attack: {raw['meta']['reps']}, gap {raw['meta']['gap_s']}s, seed {raw['meta']['seed']}, "
         f"benign phase {hrs * 60:.0f} min with {len(b['drills'])} admin drills", "",
         "| Attack | Detected | Correct label | High severity | ML flagged | Rules flagged | Time-to-detect p50 / p95 |",
         "|---|---|---|---|---|---|---|"]
    tot = dict(n=0, det=0, ok=0, high=0)
    for a, d in per.items():
        for k in tot:
            tot[k] += d[k]
        t = sorted(d["ttd"])
        q = f"{statistics.median(t):.1f}s / {t[min(len(t) - 1, int(0.95 * len(t)))]:.1f}s" if t else "-"
        L.append(f"| {a} | {pct(d['det'], d['n'])} | {pct(d['ok'], d['n'])} | {pct(d['high'], d['n'])} | "
                 f"{pct(d['ml'], d['n'])} | {pct(d['rule'], d['n'])} | {q} |")
    L += ["", f"**Overall detection:** {pct(tot['det'], tot['n'])}  |  **correct classification:** {pct(tot['ok'], tot['n'])}"
          f"  |  **high severity (would contain):** {pct(tot['high'], tot['n'])}", "",
          f"**False alarms in benign phase:** {len(fp_b)} in {hrs * 60:.0f} min = {len(fp_b) / hrs:.1f} per hour "
          f"({sum(x['severity'] == 'high' for x in fp_b)} high, would have quarantined a benign pod)",
          f"**Unmatched alerts during attack phase:** {len(fp_gap)}", "",
          "Benign false-alarm detail: " + (", ".join(sorted({x['label'] for x in fp_b})) or "none"), "",
          "Notes: intervals are wall-clock ground truth; an alert within 30s after an attack ends counts for it. "
          "Detection requires >=1 alert; 'correct label' requires the expected ATT&CK label."]
    open("docs/BENCHMARK.md", "w").write("\n".join(L) + "\n")
    print("\n".join(L))


def run_drills(a):
    rnd = random.Random(a.seed); end = time.time() + a.minutes * 60; n = 0
    while time.time() < end:
        pod, cmd = rnd.choice(TRAIN_DRILLS); kexec(pod, cmd); n += 1
        time.sleep(rnd.uniform(20, 45))
    print(f"{n} training drills done", flush=True)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    sp = ap.add_subparsers(dest="cmd", required=True)
    r = sp.add_parser("run"); r.add_argument("--reps", type=int, default=10)
    r.add_argument("--gap", type=int, default=35); r.add_argument("--benign-min", type=int, default=30)
    r.add_argument("--seed", type=int, default=1)
    sp.add_parser("report")
    d = sp.add_parser("drills"); d.add_argument("--minutes", type=int, default=20); d.add_argument("--seed", type=int, default=11)
    a = ap.parse_args()
    os.makedirs("data", exist_ok=True)
    if a.cmd == "run":
        collect(a)
    if a.cmd == "drills":
        run_drills(a)
    else:
        report()
