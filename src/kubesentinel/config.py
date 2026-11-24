import os
from dataclasses import dataclass


@dataclass
class Config:
    window_s: float = 30.0
    mode: str = "detect"            # detect | learn
    response_mode: str = "dry-run"  # off | dry-run | enforce
    kill_after_evidence: bool = False
    namespaces: tuple = ("ks-demo",)  # the ONLY namespaces the responder may touch
    db_path: str = "data/kubesentinel.db"
    model_path: str = "data/model.joblib"
    evidence_dir: str = "evidence"
    api_token: str = ""

    @classmethod
    def from_env(cls):
        e = os.environ.get
        return cls(
            window_s=float(e("KS_WINDOW_S", 30)),
            mode=e("KS_MODE", "detect"),
            response_mode=e("KS_RESPONSE", "dry-run"),
            kill_after_evidence=e("KS_KILL", "false").lower() == "true",
            namespaces=tuple(x for x in e("KS_NAMESPACES", "ks-demo").split(",") if x),
            db_path=e("KS_DB", "data/kubesentinel.db"),
            model_path=e("KS_MODEL", "data/model.joblib"),
            evidence_dir=e("KS_EVIDENCE", "evidence"),
            api_token=e("KS_API_TOKEN", ""),
        )
