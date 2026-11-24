"""Signature baseline + hybrid decision logic."""
from .features import FEATURES

IDX = {k: i for i, k in enumerate(FEATURES)}
# Corroborated signals: any one of these justifies automatic containment.
STRONG = {"shell_with_external_conn", "write_to_sensitive_path", "sensitive_file_read",
          "falco_warning_or_higher", "external_burst", "connection_flood"}


def rule_flags(vec):
    g = lambda k: vec[IDX[k]]
    flags = []
    if g("n_shell") >= 1:
        flags.append("shell_spawned_in_container")           # weak: admins open shells too
    if g("n_sensitive_open") >= 1:
        flags.append("sensitive_file_read")
    if g("n_shell") >= 1 and g("n_external_conn") >= 1:
        flags.append("shell_with_external_conn")
    if g("n_external_conn") >= 4:
        flags.append("external_burst")
    if g("n_write_sensitive") >= 1:
        flags.append("write_to_sensitive_path")
    if g("max_priority") >= 3:
        flags.append("falco_warning_or_higher")
    if g("n_connect") > 100:
        flags.append("connection_flood")
    return flags


def decide(flags, ml_anomaly, vec):
    """Hybrid verdict -> (alert?, severity). high = auto-contain, medium = alert for a human."""
    strong = [f for f in flags if f in STRONG]
    if not (ml_anomaly or len(flags) >= 2 or strong):
        return False, None
    return True, ("high" if strong else "medium")
