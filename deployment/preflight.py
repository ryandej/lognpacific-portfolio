"""Offline deployment readiness review. No Azure imports, CLI execution or writes.

Observations are operator assertions from a separately authorized read-only
preflight, not live facts established by this tool. No output authorizes deployment.
"""
import argparse
from datetime import datetime, timezone, timedelta
import json
from pathlib import Path
import re
import sys

SPEC = json.loads(Path(__file__).with_name("windows11-spec.json").read_text())
SCOPE_KEYS = ("subscription_id", "student_group", "network_group", "vnet", "subnet")
PERMISSIONS = ("vm_create", "nic_create", "disk_create", "deployment_write", "subnet_join")
CHECKS = ("policy_allows_spec", "windows_license_confirmed", "management_prerequisites_confirmed",
          "management_path_authorized", "nsg_path_reviewed", "shutdown_policy_resolved", "purge_policy_resolved")


def load_json(text):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON field")
            result[key] = value
        return result
    return json.loads(text, object_pairs_hook=unique)


def template():
    return dict(schema=1, captured_at=None,
                expected_scope={k: None for k in SCOPE_KEYS}, observed_scope={k: None for k in SCOPE_KEYS},
                expected_vm_fingerprint=None, existing_vms=[], resource_group_exists=None,
                region=None, image_urn=None, image_available=None, image_os_disk_gib=None,
                size=None, size_available=None, nonzonal_supported=None, compute_registered=None,
                trusted_launch_supported=None, subnet_capacity_available=None,
                family_free_vcpus=None, regional_free_vcpus=None,
                subnet_succeeded=None, subnet_has_delegations=None,
                permissions={k: None for k in PERMISSIONS}, checks={k: None for k in CHECKS},
                scanner_scope_authorized=None, scanner_path_verified=None)


def evaluate(obs, spec=None, now=None):
    spec = SPEC if spec is None else spec
    now = datetime.now(timezone.utc) if now is None else now
    blockers = []
    if not isinstance(obs, dict) or set(obs) != set(template()):
        raise ValueError("observation fields do not match the template")
    # The spec is deliberately pinned; alteration requires code/reviewer reconciliation.
    expected_spec = dict(schema=1, region="eastus2", image_urn="MicrosoftWindowsDesktop:windows-11:win11-25h2-pro:26200.9974.261109",
                         size="Standard_D2als_v6", vcpus=2, zone=None, os_disk_sku="StandardSSD_LRS",
                         os_disk_gib=128, data_disks=0, public_ip=False, nic_count=1,
                         subnet="existing-approved-subnet", additional_nic_nsg=False,
                         security_type="TrustedLaunch", secure_boot=True, vtpm=True, vm_limit=1)
    if spec != expected_spec or any(type(spec.get(k)) is not type(v) for k, v in expected_spec.items()):
        blockers.append("deployment specification differs from documented constraints")
    if type(obs["schema"]) is not int or obs["schema"] != 1:
        blockers.append("unsupported observation schema")
    try:
        stamp = obs["captured_at"]
        if not isinstance(stamp, str) or not stamp.endswith("Z"):
            raise ValueError()
        age = now - datetime.fromisoformat(stamp[:-1] + "+00:00")
        if not timedelta(0) <= age <= timedelta(minutes=30):
            blockers.append("preflight observations are stale or future-dated")
    except (TypeError, ValueError):
        blockers.append("valid UTC capture time required")
    for label in ("expected_scope", "observed_scope"):
        if not isinstance(obs[label], dict) or set(obs[label]) != set(SCOPE_KEYS):
            raise ValueError("scope fields do not match template")
    for key in SCOPE_KEYS:
        expected, actual = obs["expected_scope"][key], obs["observed_scope"][key]
        if not isinstance(expected, str) or not expected.strip() or expected != actual:
            blockers.append("assigned scope not confirmed: " + key)
    for key in ("resource_group_exists", "image_available", "size_available", "nonzonal_supported", "compute_registered", "subnet_succeeded", "trusted_launch_supported", "subnet_capacity_available"):
        if obs[key] is not True:
            blockers.append(key + " not confirmed")
    if obs["subnet_has_delegations"] is not False:
        blockers.append("subnet delegation compatibility unresolved")
    for key in ("region", "image_urn", "size"):
        if obs[key] != expected_spec[key]:
            blockers.append("observed " + key + " differs from proposal")
    for key in ("family_free_vcpus", "regional_free_vcpus"):
        if type(obs[key]) is not int or obs[key] < 2:
            blockers.append(key + " insufficient or unknown")
    disk = obs["image_os_disk_gib"]
    if type(disk) is not int or not 1 <= disk <= 128:
        blockers.append("image minimum OS disk size is unconfirmed or exceeds proposal")
    for group, required in (("permissions", PERMISSIONS), ("checks", CHECKS)):
        if not isinstance(obs[group], dict) or set(obs[group]) != set(required):
            raise ValueError(group + " fields do not match template")
        for key in required:
            if obs[group][key] is not True:
                blockers.append(key + " not confirmed")
    vms = obs["existing_vms"]
    if not isinstance(vms, list):
        raise ValueError("existing_vms must be a list")
    action = "create-proposal"
    if len(vms) > 1:
        blockers.append("multiple VMs: stop and resolve the single-VM violation")
        action = "stop"
    elif len(vms) == 1:
        action = "preserve-existing"
        vm = vms[0]
        if not isinstance(vm, dict) or set(vm) != {"identity_fingerprint", "conforms_to_spec"}:
            raise ValueError("existing VM fields do not match template")
        fingerprint = obs["expected_vm_fingerprint"]
        if not isinstance(fingerprint, str) or not re.fullmatch(r"[0-9a-f]{64}", fingerprint) or fingerprint != vm["identity_fingerprint"]:
            blockers.append("existing VM identity has not been confirmed")
        if vm["conforms_to_spec"] is not True:
            blockers.append("existing VM configuration requires review; do not replace it")
    elif obs["expected_vm_fingerprint"] is not None:
        action = "stop"
        blockers.append("preserved VM missing: recovery decision required; do not recreate")
    scanner = [k + " not confirmed" for k in ("scanner_scope_authorized", "scanner_path_verified") if obs[k] is not True]
    return dict(mode="offline-review", azure_operations=0, deploy=False, proposed_action=action,
                ready_for_deployment_review=not blockers and action == "create-proposal",
                preserve_existing_vm=action == "preserve-existing",
                blockers=blockers, baseline_dependencies=scanner,
                limitation="Operator-supplied observations are not independently authenticated. Recheck immediately before any separately authorized deployment; concurrent creation can invalidate this snapshot.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--template", action="store_true")
    parser.add_argument("--observations", type=Path)
    args = parser.parse_args()
    if args.template:
        print(json.dumps(template(), indent=2))
        return 0
    if args.observations is None:
        print(json.dumps({"deploy": False, "blockers": ["supply a private observation file; see README.md"]}))
        return 1
    try:
        result = evaluate(load_json(args.observations.read_text()))
    except (OSError, ValueError, TypeError, KeyError):
        print("Invalid preflight input; no Azure operation performed.", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2))
    return 1 if result["blockers"] else 0


if __name__ == "__main__":
    sys.exit(main())
