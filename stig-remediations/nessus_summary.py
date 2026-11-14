"""Offline, single-target .nessus v2 evidence extraction. No API or scan operations.

Outputs allowlisted metadata, not raw plugin output, credentials, or host identity.
An actual empty TVM export was rejected. Diagnostic and compliance exports
are supported without promoting claims or inferring missing rule revisions.
"""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import sys
import xml.etree.ElementTree as ET

CM = "{http://www.nessus.org/cm}"
MAX_BYTES = 16 * 1024 * 1024
CATALOG = json.loads(Path(__file__).with_name("catalog.json").read_text())
CONTROLS = {c["ControlId"]: c for c in CATALOG["Controls"] if c["Implementation"] == "prepared"}
DIAGNOSTICS = (10180, 10394, 10400, 10428, 19506, 21156, 21745, 24269,
               24786, 26917, 104410, 110385, 110723, 117885, 117887, 141118, 214001)
PROBLEM_PLUGINS = {10428, 21745, 24786, 26917, 104410, 110385, 110723, 117885, 214001}


class Invalid(ValueError):
    pass


def require(ok, message):
    if not ok:
        raise Invalid(message)


def read_private(path):
    """Bound the read and reject symlinks/non-regular files. Never writes."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode), "input must be a regular file")
        require(info.st_size <= MAX_BYTES, "export exceeds the supported size limit")
        data = stream.read(MAX_BYTES + 1)
    require(len(data) <= MAX_BYTES, "export exceeds the supported size limit")
    return data


def field(element, name):
    values = element.findall(name)
    require(len(values) <= 1, "duplicate XML field requires manual review")
    if not values:
        return ""
    require(not list(values[0]), "nested scalar XML field is unsupported")
    return (values[0].text or "").strip()


def summarize(data, target, origin="synthetic"):
    try:
        ip = ipaddress.ip_address(target)
    except ValueError:
        raise Invalid("one explicit target IP is required") from None
    require(ip.version == 4 and str(ip) == target, "one canonical IPv4 target is required")
    require(origin in ("synthetic", "authorized-live"), "invalid evidence origin")
    require(isinstance(data, bytes) and len(data) <= MAX_BYTES, "export exceeds the supported size limit")
    require(b"\x00" not in data and not re.search(br"<!\s*(?:DOCTYPE|ENTITY)", data, re.I),
            "DTD, entities and non-UTF-8 XML are unsupported")
    try:
        text = data.decode("utf-8-sig")
        require(not re.search(r'encoding\s*=\s*[\"\'](?!utf-8[\"\'])', text[:150], re.I),
                "only UTF-8 XML is supported")
        root = ET.fromstring(text)
    except (UnicodeError, ET.ParseError):
        raise Invalid("invalid UTF-8 .nessus XML") from None
    require(root.tag == "NessusClientData_v2", "unsupported export root")
    reports = root.findall("Report")
    require(len(reports) == 1 and len(list(root.iter("Report"))) == 1,
            "exactly one top-level report is required")
    hosts = reports[0].findall("ReportHost")
    require(1 <= len(hosts) <= 200 and len(list(root.iter("ReportHost"))) == len(hosts),
            "authorized host fragments required; empty or nested hosts are not a pass")
    items, first_properties, previous_items = [], None, set()
    for host in hosts:
        # TVM's observed export splits one host into 100-item fragments. Each
        # must independently identify the target; never resolve a hostname.
        require(host.get("name") == target, "report host does not match authorized target")
        require(len(host.findall("HostProperties")) <= 1, "duplicate host properties")
        properties = {}
        for tag in host.findall("HostProperties/tag"):
            key = tag.get("name")
            require(key and key not in properties and not list(tag), "duplicate or invalid host property")
            properties[key] = tag.text or ""
        require("host-ip" not in properties or properties["host-ip"] == target,
                "host identity fields disagree")
        if len(hosts) > 1:
            require(all(properties.get(k) for k in ("host-ip", "host-uuid", "HOST_START", "HOST_END")),
                    "fragment identity and scan window must be explicit")
            require(first_properties is None or properties == first_properties,
                    "host fragment identity, window or metadata differs")
        first_properties = properties
        fragment = host.findall("ReportItem")
        fingerprints = {ET.canonicalize(ET.tostring(i, encoding="unicode"), strip_text=True)
                        for i in fragment}
        require(not fingerprints.intersection(previous_items), "repeated export items across host fragments")
        previous_items.update(fingerprints)
        items.extend(fragment)
    require(len(items) <= 20000, "too many report items")
    found = {cid: [] for cid in CONTROLS}
    present, auth, unmapped, truncated = set(), set(), 0, False
    for item in items:
        pid = item.get("pluginID", "")
        require(bool(re.fullmatch(r"[0-9]{1,9}", pid)), "invalid plugin identifier")
        pid = int(pid)
        present.add(pid)
        output = field(item, "plugin_output")
        # Export truncation can affect compliance fields as well as plugin output.
        if any("***TRUNCATED***" in (n.text or "") for n in item.iter()):
            truncated = True
        if pid == 19506:
            auth.update(x.lower() for x in re.findall(
                r"(?im)^[ \t]*Credentialed checks[ \t]*:[ \t]*(yes|no)"
                r"(?:,[ \t]+as[ \t]+'[^'\r\n]+'[ \t]+via[ \t]+SMB)?[ \t]*$", output))
        if pid != 21156:
            continue
        name = field(item, CM + "compliance-check-name")
        match = re.match(r"^(WN11-[A-Z0-9]+-[0-9]{6})(?=\s|$)", name)
        if not match or match[1] not in found:
            unmapped += 1
            continue
        cid = match[1]
        audit = field(item, CM + "compliance-audit-file")
        rev = re.fullmatch(r"(?:[0-9]+_)?DISA_STIG_Microsoft_Windows_11_v([0-9]+)r([0-9]+)\.audit", audit, re.I)
        benchmark = "V" + rev[1] + "R" + rev[2] if rev else None
        actual = field(item, CM + "compliance-actual-value")
        info = field(item, CM + "compliance-info")
        reference = field(item, CM + "compliance-reference")
        rules = set(re.findall(r"\bSV-[0-9]+r[0-9]+_rule\b", info + "\n" + reference))
        # Rule revisions are often absent: do not fill them from our catalog.
        rule = next(iter(rules)) if len(rules) == 1 else None
        result = field(item, CM + "compliance-result")
        status = {"PASSED": "pass", "FAILED": "fail"}.get(result, "inconclusive")
        found[cid].append(dict(status=status, benchmark=benchmark, rule_id=rule,
                               mapping_compatible=benchmark == CATALOG["Benchmark"]["Label"] and rule == CONTROLS[cid]["RuleId"],
                               audit_sha256=hashlib.sha256(audit.encode()).hexdigest(),
                               actual_value_sha256=hashlib.sha256(actual.encode()).hexdigest(),
                               item_sha256=hashlib.sha256(ET.tostring(item)).hexdigest()))
    credentialed = next(iter(auth)) if len(auth) == 1 else "conflicting" if auth else "unknown"
    rows = []
    for cid, observations in found.items():
        row = dict(control=cid, status="not_assessed", observations=observations)
        if len(observations) == 1:
            row["status"] = observations[0]["status"]
        elif observations:
            row["status"] = "ambiguous"
        rows.append(row)
    return dict(schema=1, origin=origin, asset="ASSET-A", source_sha256=hashlib.sha256(data).hexdigest(),
                scope_checked=True, report_items=len(items), credentialed_checks=credentialed,
                diagnostic_plugins={str(p): p in present for p in DIAGNOSTICS},
                diagnostic_problem_present=bool(present & PROBLEM_PLUGINS),
                truncated=truncated, unmapped_compliance_items=unmapped, controls=rows,
                claim="unverified", missing=["scan/history identity and UTC window confirmation",
                "scanner, policy and authentication review", "audit/rule reconciliation",
                "original evidence and disclosure review"])


def compare(before, after):
    rows = []
    for a, b in zip(before["controls"], after["controls"]):
        require(a["control"] == b["control"], "control order mismatch")
        safe = all(s["credentialed_checks"] == "yes" and not s["truncated"] and
                   not s["diagnostic_problem_present"] for s in (before, after))
        safe = safe and all(len(r["observations"]) == 1 and r["observations"][0]["mapping_compatible"] for r in (a, b))
        if safe:
            safe = a["observations"][0]["audit_sha256"] == b["observations"][0]["audit_sha256"]
        transition = {("fail", "pass"): "fail-to-pass", ("pass", "pass"): "already-passing",
                      ("fail", "fail"): "still-failing", ("pass", "fail"): "regressed"}.get((a["status"], b["status"]), "not-comparable") if safe else "not-comparable"
        rows.append(dict(control=a["control"], reported_transition=transition))
    return dict(controls=rows, claim="unverified", limitations=[
        "Same input target enforced by CLI; IP reuse is not proof of same VM.",
        "Matching audit filenames do not prove identical audit content.",
        "Validate ordered scan histories, UTC timestamps, equivalent settings and audit digests independently.",
        "This extraction does not verify effective policy, remediation execution or external acceptance."])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("export", type=Path)
    parser.add_argument("--target", required=True, help="exact private target supplied by the operator")
    parser.add_argument("--origin", choices=("synthetic", "authorized-live"), default="synthetic")
    parser.add_argument("--followup", type=Path)
    args = parser.parse_args()
    try:
        result = summarize(read_private(args.export), args.target, args.origin)
        if args.followup:
            after = summarize(read_private(args.followup), args.target, args.origin)
            result = dict(baseline=result, followup=after, comparison=compare(result, after))
        print(json.dumps(result, indent=2))
        return 0
    except (Invalid, OSError, ValueError):
        # Do not print XML, paths, plugin outputs or parser exception details.
        print("Export rejected: unsupported, ambiguous or out-of-scope input; review privately.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
