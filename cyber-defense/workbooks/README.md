# Windows endpoint investigation workbook

[Portfolio](../../README.md) · [Investigation report](../../threat-hunting/module-1/README.md) · [Workbook source](endpoint-investigation.workbook.json)

This workbook brings together the results of a Windows endpoint investigation in the Cyber Range. Ten KQL queries produced a timeline of 233 records across five Defender tables. The workbook shows when activity clustered, which sources contributed records, and which actions need follow-up.

The existing Azure workbook was updated on November 15, 2026 UTC. All five queries returned the expected results, and the saved source matched on readback. [Validation record](validation-results.json).

The values come from saved query responses collected on November 14, 2026 UTC. The queries and responses were checked against their original SHA-256 records. Names, addresses and command lines stay private. The chart uses minutes elapsed within the 90-minute investigation window.

![Windows endpoint investigation workbook showing recorded Cyber Range results](evidence/workbook-overview.png)

*Azure workbook overview and source chart. The timing, activity and query tables are below this view. [Source counts](../../threat-hunting/module-1/investigation-summary.json) · [Capture details](../../docs/visual-evidence.md).*

## What the panels show

| Panel | Use |
|---|---|
| Investigation overview | 233 timeline records, five source tables, ten queries and a 90-minute focus window. |
| Records by source | Compare 100 general device events, 57 registry events, 43 process events, 27 file events and six network events. |
| Activity over time | Locate the busiest interval: 93 records between minutes 15 and 30. |
| Recorded activity | Review event types, including process creation, file creation, registry changes and account activity. |
| Query results | Check the returned rows for each investigation query before drawing conclusions. |

Account creation and a registry write had supporting events. Task and service commands need confirmation of the resulting state. A shared alert linked another endpoint; further evidence is needed to establish movement.

These panels retain the saved investigation counts. New telemetry requires a new collection and review. Query results can overlap, and several records can describe one action. The focus window missed earlier authentication activity, which a separate authorized query recovered.

## Source and checks

[build_investigation.py](build_investigation.py) builds the workbook from the [investigation summary](../../threat-hunting/module-1/investigation-summary.json). It checks that source counts, activity counts and time bins reconcile to the timeline. It rejects duplicate entries, incomplete query receipts and inconsistent totals.

```bash
python3 -B cyber-defense/workbooks/build_investigation.py --check
python3 -B -m unittest discover -s tests -p test_investigation_workbook.py -v
```

The source includes saved aggregate values in KQL datatables. It contains no tenant or endpoint identifiers. Import it through Azure Workbooks' Advanced Editor in an approved workspace. Saving or replacing a cloud workbook requires authorization. The existing private deployment retains its resource binding outside Git.

## Authentication detector tests

The separate [authentication workbook](authentication-investigation.workbook.json) exercises the [KQL detector](../README.md) with generated test events. Those fixtures test duplicate handling, thresholds, time boundaries and empty results. Eight detector cases and all five original workbook queries passed in Log Analytics. The original deployed charts and time controls were also checked. [Recorded test results](validation-results.json).

Keep these fixtures when changing the detector. They provide repeatable checks. Actual authentication coverage and false positive rates still need an authorized telemetry study.

```bash
python3 -B cyber-defense/workbooks/build_workbook.py --check
python3 -B -m unittest discover -s tests -p test_workbook.py -v
```

For a private live-data copy, the authentication builder requires `--mode live`, one confirmed `--device-id`, `--workspace-resource-id`, and UTC `--start` and `--end` values no more than 24 hours apart. Its fixed scope filters remain in every query. Include the full ten-minute lookback when investigating a success near the window start. The detector correlates by source IP and logon type, so distributed attempts can evade its threshold.

## References

The workbook follows Microsoft's [source format](https://github.com/microsoft/Application-Insights-Workbooks/blob/master/schema/workbook.json) and [chart configuration](https://learn.microsoft.com/en-us/azure/azure-monitor/visualize/workbooks-chart-visualizations). The authentication test workbook uses Microsoft's [time parameters](https://learn.microsoft.com/en-us/azure/azure-monitor/visualize/workbooks-time) and [DeviceLogonEvents schema](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/devicelogonevents).

The source and builders are original. Private execution records use `EV-MODULE1-V17`, `EV-WORKBOOK-RUNTIME-V16`, `EV-WORKBOOK-V17` and `EV-WORKBOOK-RECORDED-V27`.
