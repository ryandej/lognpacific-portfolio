"""Build an original, offline Azure Workbook. No cloud or file writes on import.

Synthetic by default. Live generation requires one device ID, explicit UTC bounds
and an explicit workspace. The generated private artifact is not authorization.
"""
import argparse
from datetime import datetime, timedelta, timezone
import importlib.util
import json
from pathlib import Path
import re
import sys

HERE = Path(__file__).resolve().parent
DETECTOR = HERE.parent / "auth-sequence.kql"
SPEC = importlib.util.spec_from_file_location("workbook_fixture", HERE.parent / "kql_fixture.py")
FIXTURE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FIXTURE)
SCHEMA = "https://github.com/Microsoft/Application-Insights-Workbooks/blob/master/schema/workbook.json"
PANELS = {
    "coverage": ("Event coverage", "table", '''print
    RawRows=toscalar(Raw | count),
    DistinctRows=toscalar(Deduplicated | count),
    EligibleRows=toscalar(Scoped | count),
    CandidateSequences=toscalar(Candidates | count),
    UnknownActions=toscalar(Deduplicated | where ActionType !in ("LogonFailed", "LogonSuccess") | count),
    FirstEvent=toscalar(Raw | summarize min(Timestamp)),
    LastEvent=toscalar(Raw | summarize max(Timestamp))
| extend DuplicateRows=RawRows-DistinctRows, MissingKeyRows=DistinctRows-EligibleRows,
    NoTelemetry=(RawRows == 0), Threshold=Threshold, Window=Window'''),
    "timeline": ("Logons by minute", "timechart", '''Scoped
| summarize Failures=countif(ActionType == "LogonFailed"), Successes=countif(ActionType == "LogonSuccess") by bin(Timestamp, 1m)
| order by Timestamp asc'''),
    "sources": ("Logons by source", "categoricalbar", '''Scoped
| summarize Failures=countif(ActionType == "LogonFailed"), Successes=countif(ActionType == "LogonSuccess") by RemoteIP, LogonType
| order by Failures desc, RemoteIP asc
| project SourceLabel=strcat(RemoteIP, " | ", LogonType), Failures, Successes'''),
    "sequences": ("Matching logon sequences", "table", '''Candidates
| extend LookbackClipped=(SuccessAt - Window < Start), Evidence="Correlated logons; analyst decision required"
| project SuccessAt, DeviceId, DomainKey, UserKey, RemoteIP, LogonType, FailureCount,
    FirstFailure, LastFailure, SuccessReportId, LookbackClipped, Evidence
| order by SuccessAt asc'''),
    "events": ("Events in each sequence", "table", '''Candidates
| project DeviceId, UserKey, DomainKey, RemoteIP, LogonType, SuccessAt, SuccessReportId
| join kind=inner (Scoped | project DeviceId, UserKey, DomainKey, RemoteIP, LogonType,
    EventAt=Timestamp, EventReportId=ReportId, ActionType) on DeviceId, UserKey, DomainKey, RemoteIP, LogonType
| where EventAt >= SuccessAt - Window and EventAt <= SuccessAt
| project SuccessAt, SuccessReportId, EventAt, EventReportId, DeviceId, DomainKey, UserKey, RemoteIP, LogonType, ActionType
| order by SuccessAt asc, EventAt asc, EventReportId asc'''),
}


def utc(value):
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError("Use an explicit UTC timestamp ending in Z")
    at = datetime.fromisoformat(value[:-1] + "+00:00")
    return at.astimezone(timezone.utc)


def stamp(value):
    return value.isoformat().replace("+00:00", "Z")


def scope(mode, device_id, start, end, workspace):
    if mode not in ("synthetic", "live"):
        raise ValueError("Unknown source mode")
    if mode == "synthetic":
        if any(v is not None for v in (device_id, start, end)):
            raise ValueError("Synthetic fixtures have fixed device/time scope")
        _, _, devices, begin = FIXTURE.fixture()
        finish = begin + timedelta(minutes=30)
    else:
        if not isinstance(device_id, str) or not re.fullmatch(r"[0-9a-fA-F]{40}", device_id):
            raise ValueError("Live mode requires one confirmed 40-hex Defender DeviceId")
        begin, finish = utc(start), utc(end)
        if not timedelta(0) < finish - begin <= timedelta(days=1):
            raise ValueError("Live window must be ordered and at most 24 hours")
        if not workspace:
            raise ValueError("Live mode requires an explicit approved workspace")
        devices = [device_id]
    if workspace is not None and not re.fullmatch(
        r"/subscriptions/[0-9a-fA-F-]{36}/resourceGroups/[A-Za-z0-9_.()-]+/providers/Microsoft\.OperationalInsights/workspaces/[A-Za-z0-9-]+", workspace, re.IGNORECASE):
        raise ValueError("Expected one Log Analytics workspace resource ID")
    return devices, begin, finish


def fixture_table():
    rows, _, _, _ = FIXTURE.fixture()
    values = []
    for r in rows:
        values.append("datetime(" + stamp(r["Timestamp"]) + "), " + ", ".join(json.dumps(r[k]) for k in
                      ("DeviceId", "AccountName", "AccountDomain", "RemoteIP", "LogonType", "ReportId", "ActionType")))
    return "datatable(Timestamp:datetime, DeviceId:string, AccountName:string, AccountDomain:string, RemoteIP:string, LogonType:string, ReportId:long, ActionType:string) [\n" + ",\n".join(values) + "\n]"


def query_prefix(mode, devices, begin, finish, source=None):
    source = DETECTOR.read_text() if source is None else source
    FIXTURE.validate_settings(source)
    for old, new in {
        "let Start = datetime(null);": "let Start = datetime(" + stamp(begin) + ");",
        "let End = datetime(null);": "let End = datetime(" + stamp(finish) + ");",
        "let DeviceScope = dynamic([]);": "let DeviceScope = dynamic(" + json.dumps(devices) + ");",
        "DeviceLogonEvents": "Raw",
    }.items():
        if source.count(old) != 1:
            raise ValueError("Detector source drift; reconcile builder")
        source = source.replace(old, new)
    pre, marker, rest = source.partition("let Scoped = materialize(")
    declarations, separator, body = rest.rpartition("\nSuccesses\n")
    if not marker or not separator:
        raise ValueError("Detector boundary drift; reconcile builder")
    source_table = fixture_table() if mode == "synthetic" else "DeviceLogonEvents"
    raw = "let Raw = materialize(\n" + source_table + '''
| where Timestamp >= Start and Timestamp < End
| where DeviceId in (DeviceScope)
| where Timestamp {TimeRange}
| project Timestamp, DeviceId, AccountName, AccountDomain, RemoteIP, LogonType, ReportId, ActionType
);
// Raw rows retain duplicates and missing keys for the coverage panel.
let Deduplicated = Raw | extend AccountName=tolower(AccountName), AccountDomain=tolower(AccountDomain) | distinct *;
'''
    return "// " + mode.upper() + " DATA MODE. Scope is fixed by this artifact.\n" + pre + raw + marker + declarations + "\nlet Candidates = (Successes\n" + body.rstrip() + "\n);\n"


def build(mode="synthetic", device_id=None, start=None, end=None, workspace=None):
    devices, begin, finish = scope(mode, device_id, start, end, workspace)
    prefix = query_prefix(mode, devices, begin, finish)
    banner = ("Generated test events. "
              if mode == "synthetic" else "Scoped DeviceLogonEvents query. ")
    note = (banner + "Scope: " + str(len(devices)) + " device IDs, " + stamp(begin) + " to " + stamp(finish)
            + ". Review sequences with five failures in the ten minutes before a successful logon.")
    items = [{"type": 1, "name": "scope-and-meaning", "content": {"json": "# Authentication sequence investigation\n\n" + note}},
             {"type": 9, "name": "time-scope", "content": {"version": "KqlParameterItem/1.0", "style": "above", "parameters": [
                 {"id": "approved-time", "version": "KqlParameterItem/1.0", "name": "TimeRange", "label": "Display window",
                  # Native custom ranges serialize as a positive duration with a
                  # fixed endTime. Zero duration leaves the UI parameter unset.
                  "type": 4, "isRequired": True, "value": {"durationMs": int((finish - begin).total_seconds() * 1000), "endTime": stamp(finish)},
                  "typeSettings": {"selectableValues": [{"durationMs": 1800000}, {"durationMs": 3600000}, {"durationMs": 86400000}], "allowCustom": True}}]}}]
    for name, (title, visualization, query) in PANELS.items():
        content = {"version": "KqlItem/1.0", "title": title, "query": prefix + query,
                   "queryType": 0, "resourceType": "microsoft.operationalinsights/workspaces", "size": 0,
                   "visualization": visualization, "crossComponentResources": [workspace] if workspace else []}
        if name == "sources":
            # An unconfigured numeric bar chart can infer Failures as its x-axis,
            # leaving only Successes visible. Bind the category and both measures.
            content["chartSettings"] = {"xAxis": "SourceLabel", "yAxis": ["Failures", "Successes"], "showLegend": True}
        items.append({"type": 3, "name": name, "content": content})
    items.append({"type": 1, "name": "analyst-decisions", "content": {"json": "## Review a match\n\n"
        "1. Check coverage, duplicates, missing fields and the available lookback.\n"
        "2. Check the account, source and logon outcome. Consider stale credentials, retries and automation.\n"
        "3. Review related process and network events within the approved scope. Save query and event references.\n"
        "4. Record the finding and request approval for any response. This workbook runs queries only.\n\n"
        "The detector groups by device, domain, account, source IP and logon type. Distributed attempts may evade it. "
        "Missing fields and ingestion gaps reduce coverage. Confirm the source of the records. "
        "Overlapping sequences can repeat events in the context grid. "
        "Use the full ten-minute lookback. A shorter display interval can omit earlier failures."}})
    return {"version": "Notebook/1.0", "items": items, "fallbackResourceIds": [workspace] if workspace else [], "$schema": SCHEMA}


def render_query(item):
    """Resolve the only UI parameter to the full fixed scope for service tests."""
    query = item["content"]["query"]
    if query.count("{TimeRange}") != 1:
        raise ValueError("Unexpected workbook parameter")
    return query.replace("{TimeRange}", ">= Start and Timestamp < End")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("synthetic", "live"), default="synthetic")
    parser.add_argument("--device-id")
    parser.add_argument("--start")
    parser.add_argument("--end")
    parser.add_argument("--workspace-resource-id")
    parser.add_argument("--check", action="store_true", help="Compare committed synthetic artifact with deterministic generation")
    args = parser.parse_args()
    try:
        result = build(args.mode, args.device_id, args.start, args.end, args.workspace_resource_id)
        if args.check:
            if any((args.mode != "synthetic", args.device_id, args.start, args.end, args.workspace_resource_id)):
                raise ValueError("Check uses only default synthetic settings")
            if json.loads((HERE / "authentication-investigation.workbook.json").read_text()) != result:
                raise ValueError("Workbook artifact is stale")
            print("Workbook generation matches the synthetic artifact.")
        else:
            print(json.dumps(result, indent=2))
        return 0
    except (ValueError, OSError, TypeError):
        print("Workbook generation rejected: invalid scope or source drift.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
