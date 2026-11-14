# Engineering results and validation status

[Portfolio](../README.md) · [Validation](local-validation.md) · [STIG results](windows-stig-validation.md)

**Engineering checkpoint:** November 14, 2026 UTC (November 13 local workday). This record describes the implemented work and observed validation; publication approval is tracked separately.

Ten Windows 11 STIG implementations have authenticated fail-to-pass evidence and completed apply, rollback and repeatability checks. The [technical validation report](windows-stig-validation.md) records scope, timing, residual findings and cleanup. The table below separates implemented work, observed results and remaining technical validation.

## Engineering deliverables

| Work | Observed status | Remaining validation |
|---|---|---|
| STIG implementations | Ten actual V2R11 failures remediated; ten follow-up passes. WhatIf, repeat application, real rollback, repeat restore and reapply passed for each. All 33 reviewed source hashes unchanged. | Broader feature behavior and persistence across reboot/policy refresh not established; these limits do not negate the observed ten-rule results. |
| Local and Windows tests | 203 shared Python plus 8 DISA/static tests passed. Retained 340 mocked cases passed in each of PowerShell 7.6.6 and native Windows 5.1.26100.9818; 32 Windows files parsed. | Do not equate mocked results with real state changes; actual execution is separately recorded. |
| Evidence tooling | Actual API compliance-host binding and three-fragment single-host exports reconciled with fail-closed checks; 45 client, 39 parser and 24 diagnostic tests included above. Private comparison ledger validates all ten. | Additional independent review waived, not performed. Disclosure permission remains separate. No audit-content digest supplied by the service. |
| VM and scan readiness | Same existing VM, exact private target and designated scanner. Authenticated SMB/registry assessment succeeded in two bounded prerequisite windows. Original scan settings restored; temporary ingress removed; Remote Registry restored; Defender and management services healthy. | Future assessments require authorized prerequisite windows. Preserve same VM and resolve lifecycle/licensing policy questions. |
| Endpoint operations | Defender onboarding verified locally and centrally; benign process ingestion observed. Investigation package succeeded with 70/70 collection operations. Isolation/release succeeded with observed HTTPS loss/recovery. | No complete ingestion or all-path isolation claim. Supported offboarding requires an administrator-issued package. See [endpoint validation](endpoint-validation.md). |
| Historical endpoint investigation | All ten scoped queries executed against the assigned historical dataset. Private captured values, timeline, containment proposal and report are evidence-linked. | Shared-alert second-endpoint association remains a lead, not proof of movement. Task/service command outcomes and source-handling exception are documented. No response was executed against the historical investigation endpoints. |
| Authentication sequence | Python reference tests passed; eight generated synthetic cases passed in an authorized Log Analytics service using the actual detector body. | Required columns observed in the authorized Log Analytics schema; own-VM authentication coverage was zero in the checked interval. Real event semantics, false-positive analysis and review remain; no deployed detection or response. |
| Completed training investigation | Authorized Log Analytics queries and platform completion preserved privately under `EV-HARTWELL-COMPLETE-20261113`. | Approved evidence sharing; separate from Module 1 or external acceptance. |
| Sentinel workbook | One approved five-panel synthetic workbook deployed; exact readback, native time control, both chart outcomes and empty-window behavior verified. 18 focused workbook tests passed. | Live detection effectiveness, performance and full JSON Schema validation remain unestablished. |
| Vulnerability program | One-asset lifecycle report, original policy/tabletop, reverified assessment summary and six metric tests. All ten closures reconciled to original evidence. | Governance is simulated; no organization-wide adoption or separate Windows Server/software exercise claimed. |
| Independent review | Operator reports prior Claude engineering reviews found no blocking defects; a current review packet is prepared. | An additional review of the later execution batch was waived. Neither that waiver nor a prepared packet constitutes a new independent review. |
| AI engineering | Scope proposed. | No implemented/evaluated AI security system claimed. |

## Ten implemented controls

All values are DWORDs. The November 12 missing-value observations remain preserved under `EV-WIN-INTEGRATION-20261112`; actual authenticated evidence on November 13 now establishes the baseline and follow-up below.

| Control | Required value | Tenable baseline | Final Windows verification | Tenable follow-up | Real rollback / repeat / previews |
|---|---|---|---|---|---|
| [WN11-CC-000010](../stig-remediations/WN11-CC-000010/report.md) | `NoLockScreenSlideshow = 1` | FAILED | RegistryMatch | PASSED | Passed |
| [WN11-CC-000100](../stig-remediations/WN11-CC-000100/report.md) | `DisableWebPnPDownload = 1` | FAILED | RegistryMatch | PASSED | Passed |
| [WN11-CC-000110](../stig-remediations/WN11-CC-000110/report.md) | `DisableHTTPPrinting = 1` | FAILED | RegistryMatch | PASSED | Passed |
| [WN11-CC-000180](../stig-remediations/WN11-CC-000180/report.md) | `NoAutoplayfornonVolume = 1` | FAILED | RegistryMatch | PASSED | Passed |
| [WN11-CC-000185](../stig-remediations/WN11-CC-000185/report.md) | `NoAutorun = 1` | FAILED | RegistryMatch | PASSED | Passed |
| [WN11-CC-000190](../stig-remediations/WN11-CC-000190/report.md) | `NoDriveTypeAutoRun = 255` | FAILED | RegistryMatch | PASSED | Passed |
| [WN11-CC-000295](../stig-remediations/WN11-CC-000295/report.md) | `DisableEnclosureDownload = 1` | FAILED | RegistryMatch | PASSED | Passed |
| [WN11-CC-000310](../stig-remediations/WN11-CC-000310/report.md) | `EnableUserControl = 0` | FAILED | RegistryMatch | PASSED | Passed |
| [WN11-CC-000315](../stig-remediations/WN11-CC-000315/report.md) | `AlwaysInstallElevated = 0` | FAILED | RegistryMatch | PASSED | Passed |
| [WN11-CC-000326](../stig-remediations/WN11-CC-000326/report.md) | `EnableScriptBlockLogging = 1` | FAILED | RegistryMatch | PASSED | Passed |

Four additional researched candidates remain deferred; see [research](../stig-remediations/research.md). Never weaken a passing setting to create a finding.

## Scope and remaining validation

1. The release includes original code and sanitized technical reports. Raw evidence and confidential source material stay in private storage; later disclosure or reuse requires permission.
2. Keep validation layers separate. The endpoint investigation used authorized historical telemetry through Log Analytics; its earlier Graph 403 remains an API-specific limit. The owned VM is now onboarded to Defender with observed benign process telemetry. The synthetic workbook is deployed, but no live detector, honeypot, additional control or AI security system is implied.
3. Preserve the existing VM and private evidence. Lifecycle and licensing questions remain recorded; do not create a replacement VM.

The audit still includes 107 other failures, 65 errors and 8 warnings; this work does not claim whole-machine compliance. Public release and later NCyTE reuse require permission, appropriate disclosure review, attribution and validation. Administrative participation and acceptance records remain private.
