#!/usr/bin/env bash
# Dump the windows recorded in learn mode (read from inside the pod: no port-forward, no tar needed).
mkdir -p data
kubectl -n ks-system exec deploy/ks-detector -- python -c "
import sqlite3, json
for ts, ns, pod, vec in sqlite3.connect('/app/data/kubesentinel.db').execute('select ts,ns,pod,vec from windows order by ts'):
    print(json.dumps({'ts': ts, 'ns': ns, 'pod': pod, 'vec': json.loads(vec)}))
" > data/baseline.jsonl
wc -l data/baseline.jsonl
