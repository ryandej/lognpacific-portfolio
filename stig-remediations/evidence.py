"""Offline evidence ledger; not a Tenable export parser or proof of authenticity.

Standard library only. Reads explicitly supplied JSON; writes reports to stdout.
Never connects to a service, opens evidence attachments, or executes PowerShell.
"""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import sys

CATALOG = json.loads(Path(__file__).with_name("catalog.json").read_text())
CONTROLS = {c["ControlId"]: c for c in CATALOG["Controls"] if c["Implementation"] == "prepared"}
PINNED = CATALOG["Benchmark"]["Label"]


class Invalid(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise Invalid(message)


def keys(value, expected, where):
    require(isinstance(value, dict) and set(value) == set(expected.split()), where + ": unexpected or missing fields")


def utc(value):
    require(isinstance(value, str) and re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z", value), "timestamp must use complete UTC date/time with Z")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        raise Invalid("invalid UTC timestamp") from None


def load_json(text):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate JSON field")
            result[key] = value
        return result
    return json.loads(text, object_pairs_hook=unique)


def blank_scan():
    return dict(status="not_assessed", at=None, evidence=None, benchmark=None, rule_id=None)


def new_ledger(origin="synthetic", asset="ASSET-UNASSIGNED"):
    return {
        "schema": 1, "origin": origin, "asset": asset,
        "benchmark": {"label": None, "evidence": None}, "evidence": {},
        "controls": [dict(
            control=cid, baseline=blank_scan(), followup=blank_scan(),
            local=dict(status="not_run", at=None, evidence=None, value_exists=None, kind=None, value=None),
            remediation=dict(status="not_run", at=None, evidence=None, changed=None, exit_code=None),
            review=dict(status="pending", at=None, evidence=None), claim="unverified"
        ) for cid in CONTROLS],
    }


def map_identifier(identifier):
    matches = [c["ControlId"] for c in CONTROLS.values()
               if identifier in (c["ControlId"], c["VulnerabilityId"], c["RuleId"])]
    require(len(matches) == 1, "identifier is unknown, deferred, or ambiguous; manual review required")
    return matches[0]


def validate(data):
    """Reject malformed records and overstated claims; return missing validation gates."""
    keys(data, "schema origin asset benchmark evidence controls", "ledger")
    require(type(data["schema"]) is int and data["schema"] == 1, "unsupported schema")
    require(data["origin"] in ("synthetic", "authorized-live"), "invalid origin")
    require(isinstance(data["asset"], str) and re.fullmatch(r"ASSET-[A-Z0-9-]{1,40}", data["asset"]), "use a pseudonymous asset label")
    keys(data["benchmark"], "label evidence", "benchmark")
    require(isinstance(data["evidence"], dict), "evidence must be an object")
    for ref, ev in data["evidence"].items():
        require(re.fullmatch(r"EV-[A-Z0-9-]{1,40}", ref), "invalid evidence alias")
        keys(ev, "kind sha256 captured_at asset disclosure_reviewed", "evidence entry")
        require(ev["kind"] in ("benchmark", "baseline", "followup", "local", "remediation", "review"), "invalid evidence kind")
        require(isinstance(ev["sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", ev["sha256"]), "invalid evidence digest")
        utc(ev["captured_at"])
        require(ev["asset"] == data["asset"], "evidence asset mismatch")
        require(type(ev["disclosure_reviewed"]) is bool, "disclosure_reviewed must be boolean")

    def reference(ref, kind, at=None):
        require(isinstance(ref, str) and ref in data["evidence"], "missing evidence reference")
        ev = data["evidence"][ref]
        require(ev["kind"] == kind, "evidence kind mismatch")
        if at is not None:
            require(utc(ev["captured_at"]) >= utc(at), "evidence capture predates observation")
        return ev["disclosure_reviewed"]

    benchmark = data["benchmark"]["label"]
    if benchmark is None:
        require(data["benchmark"]["evidence"] is None, "benchmark label missing")
    else:
        require(isinstance(benchmark, str) and re.fullmatch(r"V[1-9][0-9]*R[1-9][0-9]*", benchmark), "invalid benchmark label")
        reference(data["benchmark"]["evidence"], "benchmark")
    require(isinstance(data["controls"], list) and len(data["controls"]) == len(CONTROLS), "include each of the ten controls exactly once")
    seen, result = set(), {}
    for row in data["controls"]:
        keys(row, "control baseline followup local remediation review claim", "control record")
        cid = row["control"]
        require(isinstance(cid, str) and cid in CONTROLS and cid not in seen, "unknown or duplicate control")
        seen.add(cid)
        control = CONTROLS[cid]
        reviewed = []
        for stage in ("baseline", "followup"):
            scan = row[stage]
            keys(scan, "status at evidence benchmark rule_id", stage)
            require(scan["status"] in ("not_assessed", "pass", "fail", "error", "not_applicable"), "invalid scan status")
            if scan["status"] == "not_assessed":
                require(all(scan[k] is None for k in ("at", "evidence", "benchmark", "rule_id")), "unassessed scan contains results")
            else:
                utc(scan["at"])
                reviewed.append(reference(scan["evidence"], stage, scan["at"]))
                require(isinstance(scan["benchmark"], str) and re.fullmatch(r"V[1-9][0-9]*R[1-9][0-9]*", scan["benchmark"]), "scan benchmark missing")
                require(isinstance(scan["rule_id"], str) and re.fullmatch(r"SV-[0-9]+r[0-9]+_rule", scan["rule_id"]), "scan rule ID missing")
        local = row["local"]
        keys(local, "status at evidence value_exists kind value", "local")
        require(local["status"] in ("not_run", "RegistryMatch", "RegistryMismatch", "Error"), "invalid local status")
        if local["status"] == "not_run":
            require(all(local[k] is None for k in ("at", "evidence", "value_exists", "kind", "value")), "unrun local check contains results")
        else:
            utc(local["at"])
            reviewed.append(reference(local["evidence"], "local", local["at"]))
            require(local["value_exists"] is None or type(local["value_exists"]) is bool, "invalid value_exists")
            require(local["kind"] in (None, "DWord", "QWord", "String", "ExpandString", "MultiString", "Binary", "Unknown"), "invalid registry kind")
            require(local["value"] is None or (type(local["value"]) is int and -2147483648 <= local["value"] <= 4294967295), "record only a bounded numeric registry value; keep other values private")
            if local["status"] != "Error":
                require(type(local["value_exists"]) is bool, "local existence was not observed")
                if local["value_exists"]:
                    require(local["kind"] is not None, "existing registry value lacks an observed type")
                    if local["kind"] == "DWord":
                        require(type(local["value"]) is int, "DWORD observation lacks its numeric value")
                matches = local["value_exists"] and local["kind"] == "DWord" and local["value"] == control["ExpectedValue"]
                require((local["status"] == "RegistryMatch") == matches, "local status contradicts registry observation")
                if not local["value_exists"]:
                    require(local["kind"] is None and local["value"] is None, "absent registry value has data")
        change = row["remediation"]
        keys(change, "status at evidence changed exit_code", "remediation")
        outcomes = {"Changed": True, "AlreadyMatches": False, "NotApplied": False, "Restored": True, "AlreadyRestored": False}
        require(change["status"] in (*outcomes, "Error", "not_run"), "invalid remediation status")
        if change["status"] == "not_run":
            require(all(change[k] is None for k in ("at", "evidence", "changed", "exit_code")), "unrun remediation contains results")
        else:
            utc(change["at"])
            reviewed.append(reference(change["evidence"], "remediation", change["at"]))
            require(change["changed"] is None or type(change["changed"]) is bool, "changed must be boolean or unknown")
            require(type(change["exit_code"]) is int, "exit code must be an integer")
            if change["status"] == "Error":
                require(change["exit_code"] == 2, "error must retain exit code 2; state may have changed")
            else:
                require(change["exit_code"] == 0 and change["changed"] is outcomes[change["status"]], "status/changed/exit code conflict")
        review = row["review"]
        keys(review, "status at evidence", "review")
        require(review["status"] in ("pending", "changes_requested", "reviewed"), "invalid review status")
        if review["status"] == "pending":
            require(review["at"] is None and review["evidence"] is None, "pending review contains an outcome")
        else:
            utc(review["at"])
            reviewed.append(reference(review["evidence"], "review", review["at"]))
        # Observed stages can be recorded independently, but claimed verification requires ordering.
        gates = []
        if data["origin"] != "authorized-live": gates.append("authorized live observations")
        if benchmark != PINNED: gates.append("benchmark reconciliation")
        if local["status"] != "RegistryMatch": gates.append("matching Windows registry observation")
        if change["status"] not in ("Changed", "AlreadyMatches"): gates.append("successful apply outcome")
        if local["at"] and change["at"] and utc(local["at"]) < utc(change["at"]): gates.append("local verification after apply")
        windows_gates = list(gates)
        for stage in ("baseline", "followup"):
            scan = row[stage]
            allowed = ("pass", "fail") if stage == "baseline" else ("pass",)
            if scan["status"] not in allowed: gates.append(stage + " assessment")
            if scan["benchmark"] != PINNED or scan["rule_id"] != control["RuleId"]: gates.append(stage + " mapping/revision reconciliation")
        times = [row[k]["at"] for k in ("baseline", "remediation", "local", "followup")]
        if not all(times) or any(utc(a) > utc(b) for a, b in zip(times, times[1:]) if a and b):
            gates.append("ordered baseline/apply/local/follow-up evidence")
        if review["status"] != "reviewed" or not row["followup"]["at"] or (review["at"] and utc(review["at"]) < utc(row["followup"]["at"])):
            gates.append("independent review after follow-up")
        if benchmark is not None:
            reviewed.append(reference(data["benchmark"]["evidence"], "benchmark"))
        if not reviewed or not all(reviewed): gates.append("disclosure review of referenced evidence metadata")
        require(row["claim"] in ("unverified", "windows_verified", "tenable_verified"), "invalid validation claim")
        if row["claim"] == "windows_verified": require(not windows_gates, "Windows verification claim lacks required evidence")
        if row["claim"] == "tenable_verified": require(not gates, "Tenable verification claim lacks required evidence")
        before, after = row["baseline"]["status"], row["followup"]["status"]
        comparable = all(row[s]["benchmark"] == PINNED and row[s]["rule_id"] == control["RuleId"] for s in ("baseline", "followup"))
        comparison = {("fail", "pass"): "fail-to-pass", ("pass", "pass"): "already-passing", ("fail", "fail"): "still-failing", ("pass", "fail"): "regressed"}.get((before, after), "unassessed") if comparable else "not-comparable"
        result[cid] = {"comparison": comparison, "missing": gates, "claim": row["claim"]}
    return result


def report(data, cid):
    results = validate(data)
    require(cid in results, "unknown control")
    row = next(r for r in data["controls"] if r["control"] == cid)
    c = CONTROLS[cid]
    lines = [f"# {cid}: {c['Title']}", "", f"Context: {data['origin']}; asset: {data['asset']}; recorded benchmark: {data['benchmark']['label'] or 'unrecorded'}.",
             f"Candidate mapping: {c['VulnerabilityId']} / {c['RuleId']} ({PINNED}).", "",
             "| Stage | Recorded outcome | UTC observation | Evidence alias |", "|---|---|---|---|"]
    for stage in ("baseline", "remediation", "local", "followup", "review"):
        lines.append(f"| {stage} | {row[stage]['status']} | {row[stage]['at'] or 'unrecorded'} | {row[stage]['evidence'] or 'none'} |")
    for stage in ("baseline", "followup"):
        lines.append(f"\nRecorded {stage} mapping: {row[stage]['benchmark'] or 'unrecorded'} / {row[stage]['rule_id'] or 'unrecorded'}.")
    lines.extend(["", f"Comparison: {results[cid]['comparison']}. Declared claim: {row['claim']}.", "",
                  "Remaining gates: " + ("; ".join(results[cid]["missing"]) or "none in this ledger's consistency model") + ".", "",
                  "This is a consistency report of operator-entered metadata, not independent authentication of results, publication approval, or external acceptance. Hashes identify bytes; attachments and original results require separate review."])
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init")
    init.add_argument("--origin", choices=("synthetic", "authorized-live"), default="synthetic")
    init.add_argument("--asset", default="ASSET-UNASSIGNED")
    mapping = sub.add_parser("map")
    mapping.add_argument("identifier")
    for verb in ("validate", "report"):
        cmd = sub.add_parser(verb)
        cmd.add_argument("ledger", type=Path)
        if verb == "report": cmd.add_argument("--control", required=True, choices=tuple(CONTROLS))
        else: cmd.add_argument("--require-verified", action="store_true")
    args = parser.parse_args()
    try:
        if args.command == "init":
            data = new_ledger(args.origin, args.asset)
            validate(data)
            print(json.dumps(data, indent=2))
        elif args.command == "map": print(map_identifier(args.identifier))
        else:
            data = load_json(args.ledger.read_text())
            result = validate(data)
            if args.command == "report": print(report(data, args.control), end="")
            else:
                print(json.dumps(result, indent=2))
                if args.require_verified and any(r["missing"] for r in result.values()): return 1
    except (Invalid, OSError, ValueError, TypeError, KeyError) as exc:
        # Never echo untrusted file content, paths, or JSON decoder excerpts.
        print("Invalid evidence: " + (str(exc) if isinstance(exc, Invalid) else "input could not be processed"), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
