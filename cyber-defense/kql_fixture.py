"""Render a synthetic KQL regression query to stdout; never submit it to a service.

Uses the actual detector body with a datatable in place of live telemetry.
Expected results are test assertions, not observed Defender results.
"""
from datetime import datetime, timedelta, timezone
import importlib.util
import inspect
import json
from pathlib import Path
import re


def fixture():
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    rows, expected = [], {}
    for case in ("positive", "below", "source", "late", "duplicates", "boundary", "outside-window", "unscoped"):
        device = "FIXTURE-" + case.upper()
        expected[device] = 1 if case in ("positive", "boundary") else 0
        count = 4 if case == "below" else 5
        for i in range(count):
            minute = i + 6 if case == "late" else 0 if case == "duplicates" else i
            rows.append(dict(Timestamp=start + timedelta(minutes=minute), DeviceId=device,
                             AccountName="analyst", AccountDomain="SYNTHETIC", RemoteIP="SOURCE-A",
                             LogonType="Network", ReportId=0 if case == "duplicates" else i,
                             ActionType="LogonFailed"))
        success = start + timedelta(minutes=10 if case in ("boundary", "outside-window") else 5,
                                    seconds=1 if case == "outside-window" else 0)
        rows.append(dict(Timestamp=success, DeviceId=device, AccountName="ANALYST", AccountDomain="synthetic",
                         RemoteIP="SOURCE-B" if case == "source" else "SOURCE-A", LogonType="Network",
                         ReportId=99, ActionType="LogonSuccess"))
    scope = [device for device in expected if device != "FIXTURE-UNSCOPED"]
    return rows, expected, scope, start


def validate_settings(source):
    """Fail closed on drift from model defaults; this is not a KQL parser.

    Recognize integer threshold and integer d/h/m/s window literals only.
    Other expressions require deliberate reconciliation before rendering.
    """
    spec = importlib.util.spec_from_file_location(
        "auth_sequence_reference", Path(__file__).with_name("auth_sequence.py"))
    model = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(model)
    parameters = inspect.signature(model.detect).parameters
    threshold = parameters["threshold"].default
    window = parameters["window"].default
    thresholds = re.findall(r"^let\s+Threshold\s*=\s*([0-9]+)\s*;$", source, re.M)
    windows = re.findall(r"^let\s+Window\s*=\s*([0-9]+)([dhms])\s*;$", source, re.M)
    declarations = re.findall(r"\blet\s+(Threshold|Window)\s*=", source)
    if (type(threshold) is not int or threshold < 1 or declarations.count("Threshold") != 1
            or len(thresholds) != 1 or int(thresholds[0]) != threshold):
        raise ValueError("Detector Threshold differs from the Python reference model default; reconcile the fixture renderer.")
    seconds = {"d": 86400, "h": 3600, "m": 60, "s": 1}
    if (not isinstance(window, timedelta) or window <= timedelta(0) or declarations.count("Window") != 1
            or len(windows) != 1 or timedelta(seconds=int(windows[0][0]) * seconds[windows[0][1]]) != window):
        raise ValueError("Detector Window differs from the Python reference model default; reconcile the fixture renderer.")


def render():
    rows, expected, scope, _ = fixture()
    source = Path(__file__).with_name("auth-sequence.kql").read_text()
    validate_settings(source)
    replacements = {
        "let Start = datetime(null);": "let Start = datetime(2026-01-01T00:00:00Z);",
        "let End = datetime(null);": "let End = datetime(2026-01-01T00:30:00Z);",
        "let DeviceScope = dynamic([]);": "let DeviceScope = dynamic(" + json.dumps(scope) + ");",
        "DeviceLogonEvents": "FixtureLogons",
    }
    for old, new in replacements.items():
        if source.count(old) != 1:
            raise ValueError("Detector source changed; reconcile the fixture renderer before use.")
        source = source.replace(old, new)
    declarations, separator, body = source.rpartition("\nSuccesses\n")
    if not separator:
        raise ValueError("Detector query boundary changed; reconcile the fixture renderer.")
    values = []
    for row in rows:
        at = row["Timestamp"].isoformat().replace("+00:00", "Z")
        values.append("datetime(" + at + "), " + ", ".join(json.dumps(row[k]) for k in
                      ("DeviceId", "AccountName", "AccountDomain", "RemoteIP", "LogonType", "ReportId", "ActionType")))
    expected_rows = ",\n".join(json.dumps(device) + ", " + str(count) for device, count in expected.items())
    return (
        "// SYNTHETIC ONLY. Expected outcomes are assertions; service execution is pending.\n"
        "let FixtureLogons = datatable(Timestamp:datetime, DeviceId:string, AccountName:string, AccountDomain:string, RemoteIP:string, LogonType:string, ReportId:long, ActionType:string) [\n"
        + ",\n".join(values) + "\n];\n" + declarations
        + "\nlet Actual = (Successes\n" + body.rstrip() + "\n| summarize ActualRows=count() by DeviceId);\n"
        + "let Expected = datatable(DeviceId:string, ExpectedRows:long) [\n" + expected_rows + "\n];\n"
        + "Expected | join kind=fullouter (Actual) on DeviceId\n"
        + "| extend Device=coalesce(DeviceId, DeviceId1), ActualRows=coalesce(ActualRows, tolong(0)), ExpectedRows=coalesce(ExpectedRows, tolong(0))\n"
        + "| project Device, ExpectedRows, ActualRows, Passed=(ActualRows == ExpectedRows)\n| order by Device asc\n"
    )


if __name__ == "__main__":
    print(render(), end="")
