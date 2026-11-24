import os, sys, time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from kubesentinel.api import create_app
from kubesentinel.config import Config
from kubesentinel.features import vectorize
from kubesentinel.model import Detector
from kubesentinel.simulator import BENIGN_W_TRAIN, dataset


def _app(tmp_path):
    cfg = Config(window_s=10, db_path=str(tmp_path / "a.db"), model_path=str(tmp_path / "m.joblib"),
                 evidence_dir=str(tmp_path))
    ev, _ = dataset(1500, 0, BENIGN_W_TRAIN, 1)
    Detector().fit([vectorize(e) for e in ev]).save(cfg.model_path)
    return create_app(cfg, start_worker=False)


def test_shell_with_external_connection_is_high_and_deduplicated(tmp_path):
    app, t = _app(tmp_path), time.time()
    base = {"time": t, "pod": "v", "namespace": "ks-demo"}
    evs = [{**base, "type": "exec", "proc": "sh"}] + \
          [{**base, "type": "connect", "dst_ip": "203.0.113.9", "dst_port": 4444}] * 3
    c = app.test_client()
    c.post("/ingest", json=evs)
    app.process_window(); app.process_window()        # overlapping evaluation of the same events
    alerts = c.get("/api/alerts").get_json()
    assert len(alerts) == 1                            # merged into one incident
    assert alerts[0]["severity"] == "high" and "shell_with_external_conn" in alerts[0]["rules"]


def test_sliding_window_drops_old_events():
    from kubesentinel.features import WindowAggregator
    a, now = WindowAggregator(), time.time()
    a.add({"time": now - 100, "pod": "p", "namespace": "n", "type": "exec"})
    a.add({"time": now - 1, "pod": "p", "namespace": "n", "type": "exec"})
    snap = a.snapshot(10, now)
    assert len(snap[("n", "p")]) == 1
