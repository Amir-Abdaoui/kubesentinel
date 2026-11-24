import os, sys, time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
import numpy as np
from kubesentinel.config import Config
from kubesentinel.api import create_app
from kubesentinel.features import vectorize, from_falco, FEATURES
from kubesentinel.model import Detector
from kubesentinel.simulator import ATTACKS, BENIGN, BENIGN_W_TRAIN, dataset, gen_events
from kubesentinel.responder import Responder


def test_vectorize_shape_and_counts():
    ev = [{"type": "exec", "proc": "sh"}, {"type": "connect", "dst_ip": "8.8.8.8", "dst_port": 4444},
          {"type": "open", "write": True, "file": "/etc/x"}, {"type": "alert", "priority": "Error"}]
    v = vectorize(ev)
    assert len(v) == len(FEATURES)
    d = dict(zip(FEATURES, v))
    assert d["n_shell"] == 1 and d["n_external_conn"] == 1 and d["n_write_sensitive"] == 1 and d["max_priority"] == 4


def test_falco_normalisation():
    p = {"rule": "KS Telemetry Connect", "output_fields": {"k8s.pod.name": "p", "k8s.ns.name": "ks-demo",
                                                           "fd.sip": "1.2.3.4", "fd.sport": 4444}}
    e = from_falco(p)
    assert e["type"] == "connect" and e["dst_ip"] == "1.2.3.4"
    assert from_falco({"rule": "x", "output_fields": {}}) is None


def test_model_flags_attacks_more_than_benign():
    ev, _ = dataset(1500, 0, BENIGN_W_TRAIN, 1)
    det = Detector().fit([vectorize(e) for e in ev])
    rng = np.random.default_rng(3)
    ben = [vectorize(gen_events(BENIGN["web"], "w", rng)) for _ in range(200)]
    atk = [vectorize(gen_events(ATTACKS["reverse_shell"], "a", rng, scale=1.0)) for _ in range(200)]
    assert det.score_many(atk)[1].mean() > 0.6
    assert det.score_many(ben)[1].mean() < 0.1


def test_end_to_end_alert_and_dryrun_response(tmp_path):
    cfg = Config(window_s=999, db_path=str(tmp_path / "t.db"), model_path=str(tmp_path / "m.joblib"),
                 evidence_dir=str(tmp_path))
    ev, _ = dataset(1500, 0, BENIGN_W_TRAIN, 1)
    Detector().fit([vectorize(e) for e in ev]).save(cfg.model_path)
    app = create_app(cfg, start_worker=False)
    c = app.test_client()
    rng = np.random.default_rng(1)
    r = c.post("/ingest", json=gen_events(ATTACKS["container_escape"], "victim", rng, scale=1.0))
    assert r.status_code == 204
    app.process_window()
    al = c.get("/api/alerts").get_json()
    assert al and al[0]["severity"] == "high" and "dry-run" in " ".join(al[0]["actions"])
    assert c.get("/api/stats").get_json()["high"] >= 1


def test_auth_and_namespace_guard(tmp_path):
    cfg = Config(db_path=str(tmp_path / "a.db"), api_token="s3cret", model_path="none")
    c = create_app(cfg, start_worker=False).test_client()
    assert c.post("/ingest", json={"pod": "x"}).status_code == 401
    assert c.post("/ingest", json={"pod": "x"}, headers={"X-KS-Token": "s3cret"}).status_code == 204
    out = Responder("enforce", str(tmp_path), ("ks-demo",)).respond("kube-system", "coredns", {})
    assert "allow-list" in out[0]
