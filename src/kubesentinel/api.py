import hmac
import threading
import time
from collections import Counter

from flask import Flask, abort, jsonify, render_template, request

from .config import Config
from .features import WindowAggregator, from_falco, vectorize
from .mitre import classify
from .model import Detector
from .responder import Responder
from .rules import decide, rule_flags
from .store import Store

import os


def create_app(cfg=None, start_worker=True):
    cfg = cfg or Config.from_env()
    app = Flask(__name__)
    store, agg = Store(cfg.db_path), WindowAggregator()
    resp = Responder(cfg.response_mode, cfg.evidence_dir, cfg.namespaces, cfg.kill_after_evidence)
    state = {"det": Detector.load(cfg.model_path) if os.path.exists(cfg.model_path) else None,
             "started": time.time()}

    def auth():
        if cfg.api_token and not hmac.compare_digest(request.headers.get("X-KS-Token", ""), cfg.api_token):
            abort(401)

    recent = {}
    procs_of = lambda evs: {e.get("proc") for e in evs if e.get("type") == "exec"}
    ports_of = lambda evs: {e.get("dst_port") for e in evs if e.get("type") == "connect"}

    def process_window():
        n = 0
        for (ns, pod), evs in agg.snapshot(cfg.window_s).items():
            vec = vectorize(evs)
            store.add_window(ns, pod, vec)
            n += 1
            if cfg.mode == "learn":
                continue
            flags = rule_flags(vec)
            det = state["det"]
            score, ml = det.score(vec) if det else (None, False)
            fire, sev = decide(flags, ml, vec)
            if not fire:
                continue
            rank, label = {"medium": 1, "high": 2}[sev], classify(vec, procs_of(evs), ports_of(evs))["label"]
            prev = recent.get((ns, pod, label))
            if prev and time.time() - prev[0] < 30 and rank <= prev[1]:
                continue  # same incident already reported (overlapping windows)
            recent[(ns, pod, label)] = (time.time(), rank)
            first = min(e["time"] for e in evs)
            procs = {e.get("proc") for e in evs if e.get("type") == "exec"}
            ports = {e.get("dst_port") for e in evs if e.get("type") == "connect"}
            procs = {e.get("proc") for e in evs if e.get("type") == "exec"}
            ports = {e.get("dst_port") for e in evs if e.get("type") == "connect"}
            alert = {"ts": time.time(), "namespace": ns, "pod": pod, "severity": sev,
                     "score": None if score is None else round(score, 3),
                     "threshold": None if det is None else round(det.threshold, 3),
                     "ml_anomaly": ml, "rules": flags, "vector": vec,
                     "deviations": det.explain(vec) if det else [], **classify(vec, procs, ports),
                     "procs": sorted(map(str, procs))[:10], "ports": sorted(map(str, ports))[:10],
                     "time_to_detect_s": round(time.time() - first, 2), "actions": []}
            if sev == "high":
                alert["actions"] = resp.respond(ns, pod, alert)
                if "OK quarantined" in alert["actions"]:   # only when containment really happened
                    alert["time_to_contain_s"] = round(time.time() - first, 2)
            store.add_alert(alert)
        return n

    app.process_window = process_window
    app.state = state

    def ingest(ev):
        if ev and ev.get("pod"):
            ev.setdefault("time", time.time()); ev.setdefault("namespace", "default")
            agg.add(ev)

    @app.post("/falco")
    def falco():
        auth(); ingest(from_falco(request.get_json(force=True))); return "", 204

    @app.post("/ingest")
    def ingest_route():
        auth()
        body = request.get_json(force=True)
        for ev in (body if isinstance(body, list) else [body]):
            ingest(ev)
        return "", 204

    @app.get("/api/alerts")
    def alerts():
        return jsonify(store.alerts(int(request.args.get("limit", 200))))

    @app.get("/api/stats")
    def stats():
        al = store.alerts(1000)
        contain = [a["time_to_contain_s"] for a in al if "time_to_contain_s" in a]
        return jsonify({
            "windows_scanned": store.count_windows(), "alerts": len(al),
            "high": sum(a["severity"] == "high" for a in al),
            "mean_time_to_contain_s": round(sum(contain) / len(contain), 2) if contain else None,
            "by_technique": Counter(a["technique"] for a in al),
            "model_loaded": state["det"] is not None, "mode": cfg.mode,
            "response_mode": cfg.response_mode, "uptime_s": int(time.time() - state["started"])})

    @app.get("/healthz")
    def health():
        return jsonify(status="ok")

    @app.get("/metrics")
    def metrics():
        s = stats().json
        return (f"ks_windows_scanned {s['windows_scanned']}\nks_alerts_total {s['alerts']}\n"
                f"ks_alerts_high {s['high']}\n", 200, {"Content-Type": "text/plain"})

    @app.get("/")
    def dashboard():
        return render_template("dashboard.html")

    if start_worker:
        def loop():
            while True:
                time.sleep(max(cfg.window_s / 2, 1))
                try:
                    process_window()
                except Exception as exc:
                    app.logger.error("window error: %s", exc)
        threading.Thread(target=loop, daemon=True).start()
    return app
