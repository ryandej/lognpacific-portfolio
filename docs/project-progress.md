# Project status

[Portfolio](../README.md) · [Validation](local-validation.md) · [STIG results](windows-stig-validation.md)

Updated November 15, 2026 UTC. This page records completed work and the checks still outstanding.

## Engineering work

| Work | Completed | Still to check |
|---|---|---|
| Windows STIGs | Ten V2R11 findings changed from FAILED to PASSED. Preview, apply, repeat, rollback and reapply passed for each. The 33 reviewed source hashes match. | Broader feature behavior and persistence after reboot or policy refresh. |
| PowerShell tests | 340 mocked cases passed on Ubuntu and Windows; 32 files parsed on Windows. | Repeat only when the tested source or runtime changes. |
| Tenable tools | The scoped API client and parser processed the actual baseline and follow-up. Each export contained 258 compliance items and 16 diagnostics. | Audit-content digest was unavailable. Further formats need tests before support is added. |
| Assessment recovery | Original scan settings restored, temporary ingress removed and Remote Registry restored. Defender and management services remained healthy. | A future scan needs an authorized prerequisite window. |
| Defender response | Onboarding, central process telemetry, investigation collection, isolation and release verified on the owned VM. All 70 collection operations succeeded. | Ingestion of other event types and other network paths. [Details](endpoint-validation.md). |
| Windows investigation | Ten scoped queries executed on historical telemetry. The timeline has 233 records; an incident report and containment proposal are complete. | Task and service installation outcomes. The alert-linked endpoint needs further evidence before concluding movement. |
| Authentication detector | Python model checks and eight generated KQL cases passed in Log Analytics. | Live authentication coverage, false positives and alert deployment. |
| Hartwell Breach | All 18 flags, all 1,750 points, completed on time. [Report and screenshots](../threat-hunting/README.md). | Exact answers and restricted telemetry remain private. |
| Sentinel workbook | Five panels now display recorded Windows investigation results. Five aggregate queries passed in Log Analytics and the existing workbook was updated with matching readback. | New investigations need a fresh collection. [Workbook](../cyber-defense/workbooks/README.md). |
| Vulnerability program | One-endpoint assessment report, proposed policy, tabletop and remaining-work queue. All ten closures reconcile to the original evidence. | Policy adoption and wider deployment have not occurred. |
| Review | Earlier Claude reviews reported no blocking defects. The operator waived an additional review of later execution. | Record any future review by version and scope. |
| AI security systems | Future scope identified. | Implementation and evaluation. |

## Ten remediated controls

All expected values are DWORDs. The authenticated baseline and follow-up ran on November 13, 2026 UTC. Every control also passed Windows verification and recovery checks.

| Control | Expected value | Tenable baseline | Tenable follow-up |
|---|---|---|---|
| [WN11-CC-000010](../stig-remediations/WN11-CC-000010/report.md) | `NoLockScreenSlideshow = 1` | FAILED | PASSED |
| [WN11-CC-000100](../stig-remediations/WN11-CC-000100/report.md) | `DisableWebPnPDownload = 1` | FAILED | PASSED |
| [WN11-CC-000110](../stig-remediations/WN11-CC-000110/report.md) | `DisableHTTPPrinting = 1` | FAILED | PASSED |
| [WN11-CC-000180](../stig-remediations/WN11-CC-000180/report.md) | `NoAutoplayfornonVolume = 1` | FAILED | PASSED |
| [WN11-CC-000185](../stig-remediations/WN11-CC-000185/report.md) | `NoAutorun = 1` | FAILED | PASSED |
| [WN11-CC-000190](../stig-remediations/WN11-CC-000190/report.md) | `NoDriveTypeAutoRun = 255` | FAILED | PASSED |
| [WN11-CC-000295](../stig-remediations/WN11-CC-000295/report.md) | `DisableEnclosureDownload = 1` | FAILED | PASSED |
| [WN11-CC-000310](../stig-remediations/WN11-CC-000310/report.md) | `EnableUserControl = 0` | FAILED | PASSED |
| [WN11-CC-000315](../stig-remediations/WN11-CC-000315/report.md) | `AlwaysInstallElevated = 0` | FAILED | PASSED |
| [WN11-CC-000326](../stig-remediations/WN11-CC-000326/report.md) | `EnableScriptBlockLogging = 1` | FAILED | PASSED |

Four researched candidates remain deferred. [Research](../stig-remediations/research.md).

## Remaining work

The complete audit still contains 107 failures, 65 errors and eight warnings. Further remediation needs its own scope and approval. Preserve the existing VM and the original evidence. Lifecycle and licensing questions remain in the private project records.

Local tests, Windows observations, Tenable findings and review decisions each have their own records. Publication and later reuse require approval. Administrative records stay private.
