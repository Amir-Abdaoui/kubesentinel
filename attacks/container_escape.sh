#!/usr/bin/env bash
ATTACK=container_escape; . "$(dirname "$0")/_lib.sh"
run "echo test > /etc/ks-escape-test; cp /bin/sh /usr/bin/ks-payload; ls /proc/1/root >/dev/null"
