import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from kubesentinel.features import FEATURES
from kubesentinel.rules import decide, rule_flags


def vec(**kw):
    return [float(kw.get(f, 0)) for f in FEATURES]


def test_admin_shell_alone_is_never_contained():
    v = vec(n_exec=5, n_unique_proc=5, n_shell=1)
    assert decide(rule_flags(v), True, v) == (True, "medium")      # alert a human, do not quarantine


def test_corroborated_signals_contain():
    for v in (vec(n_shell=1, n_external_conn=3), vec(n_external_conn=10), vec(n_write_sensitive=2),
              vec(n_sensitive_open=3)):
        assert decide(rule_flags(v), False, v) == (True, "high")


def test_benign_is_silent():
    v = vec(n_exec=3, n_unique_proc=2, n_connect=6, n_unique_dst=3)
    assert decide(rule_flags(v), False, v) == (False, None)
