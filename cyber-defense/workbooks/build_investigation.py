"""Build a workbook from the saved Windows investigation counts. No Azure calls."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
SUMMARY = HERE.parents[1] / "threat-hunting/module-1/investigation-summary.json"
ARTIFACT = HERE / "endpoint-investigation.workbook.json"
SCHEMA = "https://github.com/Microsoft/Application-Insights-Workbooks/blob/master/schema/workbook.json"
TABLES = {"DeviceEvents", "DeviceFileEvents", "DeviceNetworkEvents", "DeviceProcessEvents", "DeviceRegistryEvents"}


def count(value):
    if type(value) is not int or value < 0:
        raise ValueError("Expected a nonnegative integer count")
    return value


def validate(data):
    if data.get("data") != "Authorized historical training telemetry":
        raise ValueError("Expected the recorded investigation source")
    total = count(data["timeline_records"])
    sources = data["sources"]
    if len(sources) != len(TABLES) or {r["table"] for r in sources} != TABLES:
        raise ValueError("Unexpected or duplicated source table")
    expected = {r["table"]: count(r["records"]) for r in sources}
    if sum(expected.values()) != total:
        raise ValueError("Source counts do not match the timeline")
    bins = data["timeline_bins"]
    if len(bins) != 6 or data["focus_minutes"] != 90:
        raise ValueError("Expected the recorded 90-minute window")
    for i, row in enumerate(bins):
        if row["start_minute"] != i * 15 or row["end_minute"] != (i + 1) * 15:
            raise ValueError("Timeline bins are not contiguous")
    if sum(count(r["records"]) for r in bins) != total:
        raise ValueError("Timeline bins do not match the total")
    actions, seen = Counter(), set()
    for row in data["actions"]:
        key = (row["table"], row["action"])
        if key in seen or key[0] not in TABLES or not key[1].isascii() or not key[1].isalnum():
            raise ValueError("Invalid or duplicated action")
        seen.add(key)
        actions[key[0]] += count(row["records"])
    if dict(actions) != expected:
        raise ValueError("Action counts do not match source counts")
    queries = data["queries"]
    if len(queries) != 10 or len({r["query"] for r in queries}) != 10:
        raise ValueError("Expected ten distinct query receipts")
    for row in queries:
        count(row["returned_rows"])
        if row["complete_response"] is not True:
            raise ValueError("Incomplete query response")
    if next(r for r in queries if r["query"] == "09-timeline")["returned_rows"] != total:
        raise ValueError("Timeline receipt disagrees with the summary")


def table(columns, rows):
    fields = ", ".join(f"{name}:{kind}" for name, kind in columns)
    values = ",\n".join(", ".join(json.dumps(v) for v in row) for row in rows)
    return f"datatable({fields}) [\n{values}\n]"


def build(data=None):
    data = json.loads(SUMMARY.read_text()) if data is None else data
    validate(data)
    panels = [
        ("overview", "Investigation overview", "table",
         f'print TimelineRecords={data["timeline_records"]}, Sources={len(data["sources"])}, '
         f'Queries={len(data["queries"])}, FocusMinutes={data["focus_minutes"]}', None),
        ("sources", "Records by source", "categoricalbar",
         table([("Source", "string"), ("Records", "long")],
               [(r["table"], r["records"]) for r in data["sources"]]) + "\n| order by Records desc, Source asc",
         {"xAxis": "Source", "yAxis": ["Records"], "showLegend": False}),
        ("timeline", "Activity through the 90-minute window", "categoricalbar",
         table([("StartMinute", "long"), ("Interval", "string"), ("Records", "long")],
               [(r["start_minute"], f'{r["start_minute"]}–{r["end_minute"]} min', r["records"]) for r in data["timeline_bins"]])
         + "\n| order by StartMinute asc\n| project Interval, Records",
         {"xAxis": "Interval", "yAxis": ["Records"], "showLegend": False}),
        ("actions", "Recorded activity", "table",
         table([("Source", "string"), ("Action", "string"), ("Records", "long")],
               [(r["table"], r["action"], r["records"]) for r in data["actions"]])
         + "\n| order by Records desc, Source asc, Action asc", None),
        ("queries", "Query results", "table",
         table([("Query", "string"), ("ReturnedRows", "long")],
               [(r["query"], r["returned_rows"]) for r in data["queries"]]) + "\n| order by Query asc", None),
    ]
    items = [{"type": 1, "name": "introduction", "content": {"json":
        "# Windows endpoint investigation\n\n"
        "Recorded results from the Cyber Range investigation reviewed November 14, 2026. "
        "Ten KQL queries produced a 233-record timeline. Private identifiers are omitted. "
        "The charts use elapsed minutes from the start of the investigation window."}}]
    for name, title, visualization, query, chart in panels:
        content = {"version": "KqlItem/1.0", "title": title, "query": query,
                   "queryType": 0, "resourceType": "microsoft.operationalinsights/workspaces",
                   "size": 0, "visualization": visualization, "crossComponentResources": []}
        if chart:
            content["chartSettings"] = chart
        items.append({"type": 3, "name": name, "content": content})
    items.append({"type": 1, "name": "findings", "content": {"json":
        "## Investigation notes\n\n"
        "Account creation and a registry write had supporting events. Task and service commands "
        "still need confirmation of the resulting state. An alert linked another endpoint; "
        "further evidence is needed to establish movement.\n\n"
        "Query results can overlap. Earlier authentication activity was recovered in a separate, "
        "wider query. These panels display saved counts and remain unchanged when new telemetry arrives."}})
    return {"version": "Notebook/1.0", "items": items, "fallbackResourceIds": [], "$schema": SCHEMA}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Compare the saved workbook with the source counts")
    args = parser.parse_args()
    result = build()
    if args.check:
        if json.loads(ARTIFACT.read_text()) != result:
            raise SystemExit("Workbook differs from the recorded source")
        print(json.dumps({"matches_source": True, "source_sha256": hashlib.sha256(SUMMARY.read_bytes()).hexdigest(),
                          "panels": 5, "timeline_records": 233}))
    else:
        print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
