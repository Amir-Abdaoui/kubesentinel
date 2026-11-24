# LAB ONLY. Harmless simulations (TEST-NET IPs 203.0.113.0/24, 198.51.100.0/24 are non-routable).
NS=${NS:-ks-demo}
POD=${POD:-$(kubectl -n "$NS" get pod -l app=victim-web -o jsonpath='{.items[0].metadata.name}')}
run() { echo "[attack:$ATTACK] pod=$POD t=$(date +%s)"; kubectl -n "$NS" exec "$POD" -- sh -c "$1" || true; }
ATTACKER=${ATTACKER:-$(docker inspect -f "{{.NetworkSettings.Networks.kind.IPAddress}}" ks-attacker)}
