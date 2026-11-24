"""Signature baseline (what a non-ML ruleset would do) + hybrid decision logic."""
from .features import FEATURES

IDX = {k: i for i, k in enumerate(FEATURES)}


def rule_flags(vec):
    g = lambda k: vec[IDX[k]]
    flags = []
    if g("n_shell") >= 1:
        flags.append("shell_spawned_in_container")
    if g("n_sensitive_open") >= 1:
        flags.append("sensitive_file_read")
    if g("n_shell") >= 1 and g("n_external_conn") >= 1:
        flags.append("shell_with_external_conn")
    if g("n_write_sensitive") >= 1:
        flags.append("write_to_sensitive_path")
    if g("max_priority") >= 3:
        flags.append("falco_warning_or_higher")
    if g("n_connect") > 100:
        flags.append("connection_flood")
    return flags


def decide(flags, ml_anomaly, vec):
    """Hybrid verdict -> (alert?, severity)."""
    alert = ml_anomaly or len(flags) >= 2 or "falco_warning_or_higher" in flags
    if not alert:
        return False, None
    if (vec[IDX["n_write_sensitive"]] > 0 or len(flags) >= 3 or (ml_anomaly and flags)
            or "shell_with_external_conn" in flags):
        return True, "high"
    return True, "medium"
