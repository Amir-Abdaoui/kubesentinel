"""Automated containment: label -> NetworkPolicy isolates -> evidence snapshot -> (optional) kill.

Safety guards: namespace allow-list, cooldown, dry-run default, evidence hashed (SHA-256).
"""
import hashlib
import json
import os
import time


class Responder:
    def __init__(self, mode="dry-run", evidence_dir="evidence", namespaces=("ks-demo",),
                 kill=False, cooldown_s=120):
        self.mode, self.dir, self.namespaces = mode, evidence_dir, set(namespaces)
        self.kill, self.cooldown_s = kill, cooldown_s
        self._last = {}
        self._api = None

    def _core(self):
        if self._api is None:
            from kubernetes import client, config
            try:
                config.load_incluster_config()
            except Exception:
                config.load_kube_config()
            self._api = client.CoreV1Api()
        return self._api

    def respond(self, ns, pod, alert):
        actions = []
        if self.mode == "off":
            return actions
        if ns not in self.namespaces:
            return [f"skipped: namespace '{ns}' not in allow-list"]
        key = (ns, pod)
        if time.time() - self._last.get(key, 0) < self.cooldown_s:
            return ["skipped: cooldown"]
        self._last[key] = time.time()
        dry = self.mode != "enforce"
        tag = "[dry-run] " if dry else ""
        actions.append(f"{tag}label pod ks-quarantine=true (NetworkPolicy deny-all applies)")
        actions.append(f"{tag}snapshot evidence (logs, spec, events) + SHA-256 manifest")
        if self.kill:
            actions.append(f"{tag}delete pod (controller recreates a clean replica)")
        if dry:
            return actions
        try:
            api = self._core()
            api.patch_namespaced_pod(pod, ns, {"metadata": {"labels": {"ks-quarantine": "true"}}})
            actions.append("OK quarantined")
            actions.append("OK evidence -> " + self._evidence(api, ns, pod, alert))
            if self.kill:
                api.delete_namespaced_pod(pod, ns, grace_period_seconds=0)
                actions.append("OK pod deleted")
        except Exception as exc:  # never crash the detector because of a response failure
            actions.append(f"ERROR {type(exc).__name__}: {exc}")
        return actions

    def _evidence(self, api, ns, pod, alert):
        d = os.path.join(self.dir, f"{ns}_{pod}_{int(time.time())}")
        os.makedirs(d, exist_ok=True)
        files = {
            "alert.json": json.dumps(alert, indent=2, default=str),
            "pod_spec.json": json.dumps(api.read_namespaced_pod(pod, ns).to_dict(), indent=2, default=str),
            "events.json": json.dumps([e.to_dict() for e in api.list_namespaced_event(
                ns, field_selector=f"involvedObject.name={pod}").items], indent=2, default=str),
        }
        try:
            files["logs.txt"] = api.read_namespaced_pod_log(pod, ns, tail_lines=500)
        except Exception as exc:
            files["logs.txt"] = f"unavailable: {exc}"
        manifest = {}
        for name, body in files.items():
            with open(os.path.join(d, name), "w") as fh:
                fh.write(body)
            manifest[name] = hashlib.sha256(body.encode()).hexdigest()
        with open(os.path.join(d, "MANIFEST.sha256.json"), "w") as fh:
            json.dump(manifest, fh, indent=2)
        return d
