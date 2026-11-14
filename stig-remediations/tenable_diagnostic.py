"""One approved, reversible diagnostic assessment of the existing scoped scan.

No network action without --execute. No scan creation, credential mutation,
Windows changes or automatic launch retry. Private receipts survive interruption.
The separate evidence client retains its read-only scan-operation contract.
"""
import argparse
import copy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys

import tenable_client as T

DIAGNOSTICS = {19506, 10394, 10400, 10428, 21745, 24786, 26917,
               104410, 110385, 110723, 141118, 22964}
CHANGES = {
    # Live editor readback disables fast discovery with its parent ping setting.
    # Preserve both original values for restoration; neither proves reachability.
    "ping_the_remote_host": "no", "fast_network_discovery": "no", "portscan_range": "445",
    "ssh_netstat_scanner": "no", "wmi_netstat_scanner": "no",
    "snmp_scanner": "no", "only_portscan_if_enum_failed": "no",
    "silent_dependencies": "no", "audit_trail": "full",
    "log_live_hosts": "yes",
}
SAFETY = {
    "safe_checks": "yes", "host_tagging": "no",
    "syn_scanner": "yes", "tcp_scanner": "no", "udp_scanner": "no",
    "start_remote_registry": "no", "enable_admin_shares": "no",
    "start_server_service": "no", "never_send_win_creds_in_the_clear": "yes",
}
BASE_FIELDS = {"name", "text_targets", "scanner_id", "fast_network_discovery"}


def inputs(value):
    """Yield UI input metadata; callers choose fields before reading defaults."""
    if isinstance(value, dict):
        if isinstance(value.get("id"), str) and "default" in value:
            yield value
        for child in value.values():
            yield from inputs(child)
    elif isinstance(value, list):
        for child in value:
            yield from inputs(child)


def selected_defaults(value, allowed):
    result = {}
    for item in inputs(value):
        key = item["id"]
        if key in allowed:
            val = item["default"]
            T.require(key not in result or result[key] == val, "Conflicting editor defaults.")
            result[key] = val
    return result


def family_state(family):
    return {"status": family["status"],
            "enabled": sorted(k for k, v in family.get("individual", {}).items() if v == "enabled")}


def fingerprint(snapshot):
    value = copy.deepcopy(snapshot)
    value["plugins"] = {k: family_state(v) for k, v in snapshot["plugins"].items()}
    return hashlib.sha256(T.json_bytes(value)).hexdigest()


def patch(snapshot, assignments):
    T.require(set(assignments) == DIAGNOSTICS, "Diagnostic plugin mapping incomplete.")
    result = copy.deepcopy(snapshot)
    T.require(all(k in result["settings"] for k in CHANGES), "Missing original setting; cannot restore.")
    result["settings"].update(CHANGES)
    for plugin, family in assignments.items():
        T.require(family in result["plugins"], "Unknown plugin family.")
        f = result["plugins"][family]
        T.require(f["status"] in ("disabled", "mixed"), "Broad family enablement rejected.")
        f.update(status="mixed", mixedDefault="disabled", selectedStatus="disabled")
        f.setdefault("lock_state", "Unlocked")
        f.setdefault("individual", {})[str(plugin)] = "enabled"
    return result


def payload(snapshot, scope):
    settings = snapshot["settings"]
    T.require(settings["name"] == scope["scan_name"] and settings["text_targets"] == scope["target"],
              "Scan identity or target mismatch.")
    T.require(isinstance(settings.get("scanner_id"), str) and settings["scanner_id"], "Scanner must be explicit.")
    T.require(all(settings.get(k) == v for k, v in SAFETY.items()), "Unsafe prerequisite settings.")
    T.require(snapshot["schedule"].get("enabled") is False and not snapshot["schedule"].get("rrules"),
              "Scheduled scan rejected.")
    T.require(len(snapshot["credentials"]) == 1 and snapshot["credentials"][0]["auth_method"] == "Password",
              "Expected one existing Windows password credential.")
    T.require(len(snapshot["audits"]) == 1 and
              snapshot["audits"][0]["id"] == "21156_DISA_STIG_Microsoft_Windows_11_v2r11.audit",
              "Expected exactly the approved Windows audit.")
    # Credentials/audits are intentionally absent: do not re-send or replace secrets.
    return {"uuid": snapshot["uuid"], "settings": dict(settings),
            "plugins": copy.deepcopy(snapshot["plugins"])}


class Diagnostic:
    def __init__(self, client, batch):
        self.client = client
        self.batch = Path(batch)

    def get(self, suffix):
        T.require(suffix in ("", "/families/1", "/families/2", "/families/4", "/families/18", "/families/29"),
                  "Editor route outside diagnostic scope.")
        return T.decode(self.client._https("GET", "/editor/scan/" + self.client.scan + suffix, None))

    def snapshot(self):
        details = self.client.details()
        T.require(details["info"].get("status") in ("completed", "empty", "aborted", "canceled"),
                  "Existing scan is active or in an unsupported state.")
        e = self.get("")
        T.require(e.get("name") == "advanced" and e.get("title") == "Advanced Network Scan",
                  "Unsupported scan template.")
        settings = selected_defaults(e["settings"], set(CHANGES) | set(SAFETY) | BASE_FIELDS)
        scanners = [x for item in inputs(e["settings"]) if item["id"] == "scanner_id"
                    for x in item.get("options", []) if x.get("id") == settings.get("scanner_id")]
        T.require(len(scanners) == 1 and scanners[0].get("name") == self.client.scope["scanner_name"] and
                  scanners[0].get("status") == "on" and scanners[0].get("linked"), "Assigned scanner unavailable.")
        credentials = []
        for cat in e["credentials"]["data"]:
            for kind in cat.get("types", []):
                instances = kind.get("instances", [])
                T.require(not instances or kind.get("name") == "Windows", "Unexpected credential type configured.")
                if kind.get("name") == "Windows":
                    settings.update(selected_defaults(kind.get("settings", {}), set(SAFETY)))
                    for instance in instances:
                        vals = selected_defaults(instance, {"username", "domain", "auth_method"})
                        credentials.append(dict(vals, id=instance["id"], ad_hoc=instance.get("ad_hoc")))
        audits = []
        for cat in e["compliance"]["data"]:
            for audit in cat.get("audits", []):
                if audit.get("free") == 0:
                    # Only configured audit metadata; no unrelated audit material is retained.
                    variables = {a["id"]: a["default"] for a in inputs(audit)}
                    audits.append({"id": audit["id"], "variables": variables})
        plugins = {}
        for name, f in e["plugins"]["families"].items():
            T.require(f["status"] in ("disabled", "mixed"), "Unexpected broadly enabled family.")
            entry = {"id": f["id"], "status": f["status"]}
            if f["status"] == "mixed":
                rows = self.get("/families/" + str(f["id"]))["plugins"]
                entry.update(individual={str(x["id"]): x["status"] for x in rows},
                             mixedDefault="disabled", selectedStatus="disabled",
                             lock_state=f.get("lock_state", "Locked"))
            plugins[name] = entry
        schedule = [x for x in e["settings"]["basic"]["groups"] if x.get("name") == "schedule"]
        T.require(len(schedule) == 1, "Schedule metadata missing.")
        snap = {"uuid": e["uuid"], "settings": settings, "credentials": credentials,
                "audits": audits, "plugins": plugins,
                "schedule": {k: schedule[0].get(k) for k in ("enabled", "rrules", "starttime", "timezone")}}
        payload(snap, self.client.scope)
        return snap

    def prepare(self):
        original = self.snapshot()
        assignments = {}
        for family, f in original["plugins"].items():
            if f["id"] in (1, 2, 4, 18):
                for p in self.get("/families/" + str(f["id"]))["plugins"]:
                    if int(p["id"]) in DIAGNOSTICS:
                        T.require(int(p["id"]) not in assignments, "Duplicate plugin mapping.")
                        assignments[int(p["id"])] = family
        proposed = patch(original, assignments)
        payload(proposed, self.client.scope)
        enabled = {int(k) for f in original["plugins"].values() for k, v in f.get("individual", {}).items()
                   if v == "enabled"}
        T.require(enabled == {21156}, "Unexpected original plugin selection.")
        return T.save_evidence(self.batch / "prepared", {
            "original.private.json": T.json_bytes(original),
            "diagnostic.private.json": T.json_bytes(proposed),
            "binding.private.json": T.json_bytes({"scope_sha256": T.scope_digest(self.client.scope),
                                                  "original_sha256": fingerprint(original),
                                                  "diagnostic_sha256": fingerprint(proposed)})},
            {"purpose": "Exact single-scan diagnostic proposal and restoration snapshot; credential secrets excluded"})

    def prepared(self):
        root = self.batch / "prepared"
        manifest = T.decode(T.private_read(root / "manifest.json"))
        values = {}
        for name in ("original.private.json", "diagnostic.private.json", "binding.private.json"):
            raw = T.private_read(root / name)
            T.require(hashlib.sha256(raw).hexdigest() == manifest["files"][name], "Plan integrity mismatch.")
            values[name] = T.decode(raw)
        before, after, binding = (values[n] for n in ("original.private.json", "diagnostic.private.json", "binding.private.json"))
        T.require(binding == {"scope_sha256": T.scope_digest(self.client.scope),
                              "original_sha256": fingerprint(before), "diagnostic_sha256": fingerprint(after)},
                  "Prepared scope or state changed.")
        return before, after

    def record(self, name, data):
        return T.private_write(self.batch / name, T.json_bytes(dict(data, at_utc=datetime.now(timezone.utc).isoformat())))

    def update(self, desired, receipt):
        body = T.json_bytes(payload(desired, self.client.scope))
        self.record(receipt, {"operation": "PUT owned scan", "request_sha256": hashlib.sha256(body).hexdigest(),
                              "rule": "No automatic mutation retry; inspect current state if transport fails."})
        # Ignore mutation response bodies; inspect a fresh secret-free snapshot instead.
        self.client._https("PUT", "/scans/" + self.client.scan, body)
        observed = self.snapshot()
        T.save_evidence(self.batch / receipt.replace(".json", "-readback"),
                        {"snapshot.private.json": T.json_bytes(observed)}, {"purpose": "Mutation state verification"})
        T.require(fingerprint(observed) == fingerprint(desired), "Scan readback differs; do not launch.")
        return {"verified": True}

    def apply(self):
        before, after = self.prepared()
        T.require(fingerprint(self.snapshot()) == fingerprint(before), "Scan changed since preparation.")
        return self.update(after, "apply-attempt.private.json")

    def launch(self):
        _, after = self.prepared()
        T.require(fingerprint(self.snapshot()) == fingerprint(after), "Diagnostic state not verified.")
        history = self.client.history()
        self.record("launch-attempt.private.json", {"scope_sha256": T.scope_digest(self.client.scope),
                    "previous_history_ids": [x["id"] for x in history["history"]],
                    "rule": "Exactly one launch; this receipt forbids automatic retry, including on timeout."})
        response = T.decode(self.client._https("POST", "/scans/" + self.client.scan + "/launch", b"{}"))
        T.require(isinstance(response, dict) and isinstance(response.get("scan_uuid"), str),
                  "Launch response unsupported; inspect history, do not retry.")
        self.record("launch-response.private.json", {"scan_uuid": response["scan_uuid"]})
        return {"launch_submitted": True, "launch_count": 1}

    def restore(self):
        before, after = self.prepared()
        current = self.snapshot()
        if fingerprint(current) == fingerprint(before):
            return {"restored": True, "write_needed": False}
        # Only our documented fields/families may differ; preserve identity and safety.
        T.require(current["credentials"] == before["credentials"] and current["audits"] == before["audits"] and
                  current["schedule"] == before["schedule"], "Protected scan state changed; restoration requires review.")
        for k, v in current["settings"].items():
            T.require(k in CHANGES or v == before["settings"].get(k), "Unexpected non-diagnostic setting change.")
        T.require(set(current["plugins"]) == set(before["plugins"]), "Plugin families changed during diagnostic.")
        for name, family in current["plugins"].items():
            T.require(family_state(family) in (family_state(before["plugins"][name]),
                                               family_state(after["plugins"][name])),
                      "Unexpected plugin selection; restoration requires review.")
        result = self.update(before, "restore-attempt.private.json")
        return dict(result, restored=True)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("action", choices=("prepare", "apply", "launch", "restore"))
    p.add_argument("--connection", type=Path)
    p.add_argument("--batch", type=Path)
    p.add_argument("--execute", action="store_true")
    a = p.parse_args(argv)
    if not a.execute:
        print(json.dumps({"network_contacted": False, "requires": "explicit approval, private connection/batch, --execute"}))
        return 0
    try:
        T.require(a.connection is not None and a.batch is not None, "Private connection and batch required.")
        config = T.decode(T.private_read(a.connection))
        with T.private_directory(a.batch):
            pass
        obj = Diagnostic(T.Client(config["scope"], config["keys"]), a.batch)
        print(json.dumps(getattr(obj, a.action)()))
        return 0
    except T.Blocked as exc:
        print("Stopped: " + str(exc), file=sys.stderr)
    except Exception:
        print("Stopped: diagnostic state, transport or private storage failed; no remote body or credential printed.", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
