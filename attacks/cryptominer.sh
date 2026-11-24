#!/usr/bin/env bash
ATTACK=cryptominer; . "$(dirname "$0")/_lib.sh"
# Output redirected so the background process doesn't keep `kubectl exec` attached.
run "printf '#!/bin/sh\nsleep 15\n' > /tmp/xmrig; chmod +x /tmp/xmrig; (/tmp/xmrig >/dev/null 2>&1 &); for i in \$(seq 1 12); do nc -z -w1 $ATTACKER 3333; done"
