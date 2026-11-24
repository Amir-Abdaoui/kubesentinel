import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from .features import FEATURES


class Detector:
    """Isolation Forest over per-pod behaviour windows, with explainability."""

    def __init__(self, n_estimators=300, fpr_target=0.02, seed=42, z_guard=8.0):
        self.fpr_target, self.seed, self.z_guard = fpr_target, seed, z_guard
        self.iforest = IsolationForest(n_estimators=n_estimators, random_state=seed)
        self.mean = self.std = self.threshold = None

    def fit(self, X):
        X = np.asarray(X, float)
        self.mean = X.mean(0)
        self.zero_cols = X.max(axis=0) == 0   # features never observed in the baseline
        self.std = np.maximum(X.std(0), 0.5)  # avoid huge z on near-constant features
        self.iforest.fit(X)
        train_scores = -self.iforest.score_samples(X)
        self.threshold = float(np.quantile(train_scores, 1 - self.fpr_target))
        return self

    def _guard(self, X):
        """Out-of-support guard: Isolation Forest cannot split features that were constant in
        training (e.g. n_external_conn == 0 for every benign window), so flag extreme z-scores."""
        z = np.abs((X - self.mean) / self.std)
        never = ((X > 0) & getattr(self, "zero_cols", np.zeros(X.shape[1], bool))).any(axis=1)
        return (z.max(axis=1) >= self.z_guard) | never

    def score(self, vec):
        s, a = self.score_many([vec])
        return float(s[0]), bool(a[0])

    def score_many(self, X):
        X = np.asarray(X, float)
        s = -self.iforest.score_samples(X)
        return s, (s > self.threshold) | self._guard(X)

    def explain(self, vec, top=3):
        z = (np.asarray(vec) - self.mean) / self.std
        order = np.argsort(-np.abs(z))[:top]
        return [{"feature": FEATURES[i], "value": float(vec[i]),
                 "baseline_mean": round(float(self.mean[i]), 2), "z": round(float(z[i]), 1)}
                for i in order if abs(z[i]) >= 2]

    def save(self, path):
        joblib.dump(self, path)

    @staticmethod
    def load(path):
        return joblib.load(path)
