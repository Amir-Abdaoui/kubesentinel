.PHONY: venv test train evaluate serve demo cluster calico build deploy falco kyverno attacks scan down
PY=PYTHONPATH=src .venv/bin/python
venv:      ; python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
test:      ; $(PY) -m pytest -q tests
train:     ; $(PY) -m kubesentinel train --source sim
evaluate:  ; $(PY) -m kubesentinel evaluate
serve:     ; KS_WINDOW_S=5 $(PY) -m kubesentinel serve          # http://localhost:8080
demo:      ; $(PY) -m kubesentinel demo --rounds 24 --interval 5  # run in a 2nd terminal

# ---------- real cluster ----------
cluster:   ; kind create cluster --name ks --config k8s/kind-config.yaml
calico:    ; kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.33.0/manifests/calico.yaml && kubectl -n kube-system rollout status ds/calico-node
build:     ; docker build -t kubesentinel:dev . && kind load docker-image kubesentinel:dev --name ks
deploy:    ; kubectl apply -f k8s/00-namespaces.yaml && \
             kubectl -n ks-system create secret generic ks-token --from-literal=token=$$(openssl rand -hex 24) --dry-run=client -o yaml | kubectl apply -f - && \
             kubectl apply -f k8s/10-victim-app.yaml -f k8s/20-quarantine-netpol.yaml && \
             kubectl apply -f k8s/30-detector.yaml
falco:     ; helm repo add falcosecurity https://falcosecurity.github.io/charts && helm repo update && \
             T=$$(kubectl -n ks-system get secret ks-token -o jsonpath='{.data.token}' | base64 -d) && \
             sed "s/__TOKEN__/$$T/" falco/values.yaml | helm upgrade --install falco falcosecurity/falco -n falco --create-namespace -f -
kyverno:   ; helm repo add kyverno https://kyverno.github.io/kyverno && helm upgrade --install kyverno kyverno/kyverno -n kyverno --create-namespace && kubectl apply -f k8s/40-kyverno-policies.yaml
attacks:   ; ./attacks/run_all.sh
dash:      ; while true; do kubectl -n ks-system port-forward svc/ks-detector 8099:8080; echo "reconnecting..."; sleep 1; done
scan:      ; checkov -d k8s --framework kubernetes ; trivy config k8s
down:      ; kind delete cluster --name ks
