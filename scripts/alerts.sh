#!/usr/bin/env bash
# Prints one line per alert, read from inside the detector pod (no port-forward needed).
kubectl -n ks-system exec deploy/ks-detector -- python -c "
import json, urllib.request
F=['exec','uproc','shell','conn','udst','uport','ext','sens','wr','alerts','prio']
for a in reversed(json.load(urllib.request.urlopen('http://localhost:8080/api/alerts'))):
    print(a['severity'][:3], a['label'][:34].ljust(34), dict(zip(F,[int(x) for x in a['vector']])), 'ml' if a['ml_anomaly'] else '')
print(json.load(urllib.request.urlopen('http://localhost:8080/api/stats')))
"
