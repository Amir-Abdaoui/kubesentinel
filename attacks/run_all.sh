#!/usr/bin/env bash
# Runs every scenario with a gap so each lands in its own detection window.
cd "$(dirname "$0")"
for a in reverse_shell cryptominer credential_theft container_escape exfiltration stealth_c2; do
  ./$a.sh; sleep "${GAP:-25}"
done
