# Project screenshots

[Portfolio](../README.md) · [Validation](local-validation.md)

Nine images show the selected projects. Each report explains its source and results. File sizes and SHA-256 hashes are listed in the [image manifest](visual-evidence.json).

| Image | Source |
|---|---|
| [STIG results](../stig-remediations/evidence/control-results.png) | Local evidence report built from ten authenticated Tenable comparisons and Windows recovery checks. [Assessment record](../vulnerability-management/assessment-summary.json). |
| [Assessment overview](../vulnerability-management/evidence/assessment-overview.png) | Local report showing all 258 compliance outcomes before and after remediation, including unresolved findings. |
| [Sentinel workbook](../cyber-defense/workbooks/evidence/workbook-overview.png) | Native Azure workbook capture showing the recorded investigation overview and source chart. Portal identity details were hidden for capture; values were unchanged. [Data](../threat-hunting/module-1/investigation-summary.json). |
| [Completed hunt](../threat-hunting/evidence/hunt-completion.png) | The owned hunt completion indicator: all 18 flags, all 1,750 points, completed on time. The original title and score were framed for capture; the page layout was then restored. |
| [Hartwell source coverage](../threat-hunting/evidence/hartwell-source-coverage.png) | Local analysis of saved KQL results: 52,979 records across seven sources. The first and last event times show where coverage began late. [Summary](../threat-hunting/investigation-summary.json). |
| [Hartwell analysis](../threat-hunting/evidence/hartwell-analysis-checks.png) | Local review of monitoring continuity, four encoding checks, 71 process records and 45 decoded commands. It includes the available network evidence limits. |
| [Endpoint response](evidence/endpoint-response.png) | Local report of observed onboarding, collection, isolation and recovery. [Execution record](endpoint-validation.md). |
| [Windows investigation](../threat-hunting/module-1/evidence/endpoint-investigation.png) | Local report of ten executed queries, 233 timeline records, five event sources and activity timing. [Summary](../threat-hunting/module-1/investigation-summary.json). |
| [Authentication detector tests](../cyber-defense/evidence/detection-tests.png) | Local summary of eight generated cases executed in Log Analytics. Expected and observed matches agree for every case. [Results and source hashes](../cyber-defense/detection-validation.json). |

The local reports use retained evidence. Private identifiers, credentials, command lines and challenge answers are excluded. Original captures and source records remain in private storage under `EV-PORTFOLIO-VISUALS-V22`, `EV-HARTWELL-REPORT-REFRESH`, `EV-TRACKER-PROJECT-REFRESH-20261115` and `EV-WORKBOOK-RECORDED-V27`. The November 15 presentation refresh is recorded under `EV-PORTFOLIO-PRESENTATION-20261115`; it preserves the original results.

Repository checks allow only the nine listed image paths and their reviewed hashes. They check PNG structure, metadata, dimensions and size. Each replacement also needs a visual privacy check. Other images and attachments remain ignored.
