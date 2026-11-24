import argparse
import json
import time
import urllib.request

import numpy as np

from .config import Config
from .features import vectorize


def train(args):
    cfg = Config.from_env()
    if args.source == "db":
        from .store import Store
        X = Store(cfg.db_path).windows()
        if len(X) < 200:
            raise SystemExit(f"only {len(X)} windows in DB; run in KS_MODE=learn longer (>=200)")
    elif args.source == "jsonl":
        X = [json.loads(l)["vec"] for l in open(args.path)]
    elif args.source == "jsonl":
        X = [json.loads(l)["vec"] for l in open(args.path)]
    else:
        from .simulator import BENIGN_W_TRAIN, dataset
        ev, _ = dataset(args.n, 0, BENIGN_W_TRAIN, 1)
        X = [vectorize(e) for e in ev]
    from .model import Detector
    Detector().fit(X).save(cfg.model_path)
    print(f"model trained on {len(X)} windows -> {cfg.model_path}")


def serve(args):
    from .api import create_app
    create_app().run(host="0.0.0.0", port=args.port)


def demo(args):
    """Stream simulated benign traffic + periodic attacks into a running server."""
    from .simulator import ATTACKS, BENIGN, gen_events
    rng = np.random.default_rng(5)
    attacks = list(ATTACKS)
    for r in range(args.rounds):
        evs = []
        for k, prof in BENIGN.items():
            if k != "admin_debug":
                evs += gen_events(prof, f"{k}-pod", rng)
        if r and r % 3 == 0:
            a = attacks[(r // 3 - 1) % len(attacks)]
            evs += gen_events(ATTACKS[a], f"victim-{a}", rng, scale=1.0)
            print(f"round {r}: injected attack -> {a}")
        req = urllib.request.Request(args.url + "/ingest", json.dumps(evs).encode(),
                                     {"Content-Type": "application/json", "X-KS-Token": args.token})
        urllib.request.urlopen(req)
        time.sleep(args.interval)


def main():
    ap = argparse.ArgumentParser("kubesentinel")
    sp = ap.add_subparsers(required=True)
    t = sp.add_parser("train"); t.add_argument("--source", choices=["sim", "db", "jsonl"], default="sim")
    t.add_argument("--path", default="data/baseline.jsonl")
    t.add_argument("--n", type=int, default=3000); t.set_defaults(f=train)
    s = sp.add_parser("serve"); s.add_argument("--port", type=int, default=8080); s.set_defaults(f=serve)
    d = sp.add_parser("demo"); d.add_argument("--url", default="http://localhost:8080")
    d.add_argument("--rounds", type=int, default=20); d.add_argument("--interval", type=float, default=5)
    d.add_argument("--token", default=""); d.set_defaults(f=demo)
    e = sp.add_parser("evaluate"); e.set_defaults(f=lambda a: __import__(
        "kubesentinel.evaluate", fromlist=["x"]).report())
    a = ap.parse_args(); a.f(a)


if __name__ == "__main__":
    main()
