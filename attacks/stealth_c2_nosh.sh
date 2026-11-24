#!/usr/bin/env bash
ATTACK=stealth_c2_nosh; . "$(dirname "$0")/_lib.sh"
echo "[attack:$ATTACK] pod=$POD t=$(date +%s)"
for i in $(seq 1 10); do kubectl -n "$NS" exec "$POD" -- nc -z -w1 "$ATTACKER" 8443 || true; sleep 1; done
