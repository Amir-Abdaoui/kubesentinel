"""Honest evaluation on REAL benign telemetry: time-ordered split (train on the past, test on the future).
Usage: python scripts/eval_real.py [path]"""
import json
import sys
from collections import Counter

import numpy as np

sys.path.insert(0, "src")
from kubesentinel.features import FEATURES  # noqa: E402
from kubesentinel.model import Detector  # noqa: E402
from kubesentinel.rules import decide, rule_flags  # noqa: E402

path = sys.argv[1] if len(sys.argv) > 1 else "data/baseline.jsonl"
rows = sorted((json.loads(l) for l in open(path)), key=lambda r: r["ts"])
cut = int(len(rows) * 0.7)
train, test = rows[:cut], rows[cut:]
X_te = np.array([r["vec"] for r in test])
print(f"windows: total={len(rows)} train={len(train)} test={len(test)}")
print("windows per pod (test):", dict(Counter(r["pod"].rsplit("-", 2)[0] for r in test)))

det = Detector(fpr_target=0.02).fit([r["vec"] for r in train])
_, ml = det.score_many(X_te)
flags = [rule_flags(v) for v in X_te]
rules_p = np.array([len(f) >= 1 for f in flags])
hyb = np.array([decide(f, bool(m), v)[0] for f, m, v in zip(flags, ml, X_te)])
shell = X_te[:, FEATURES.index("n_shell")] >= 1


def row(name, p):
    adm = f"{p[shell].mean():.3f} ({int(p[shell].sum())}/{int(shell.sum())})" if shell.any() else "n/a"
    print(f"{name:<18} FPR all={p.mean():.3f} ({int(p.sum())}/{len(p)})   FPR admin-sessions={adm}")


print("\nFalse-positive rate on benign windows the model has NOT seen:")
row("Signature rules", rules_p)
row("Isolation Forest", np.array(ml))
row("Hybrid", hyb)
print(f"\nthreshold={det.threshold:.3f}  (calibrated to 2% FPR on the training windows)")
print("Caveat: loop workloads repeat nearly identically, so 'all' is optimistic; admin-session FPR is the honest number.")
