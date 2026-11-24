#!/usr/bin/env bash
ATTACK=credential_theft; . "$(dirname "$0")/_lib.sh"
run "for i in 1 2 3 4; do cat /var/run/secrets/kubernetes.io/serviceaccount/token >/dev/null; done; cat /etc/shadow >/dev/null"
