# Windows 11 STIG validation — November 13, 2026 UTC

[Portfolio](../README.md) · [Project status](project-progress.md) · [Validation](local-validation.md)

Ten original remediation implementations produced authenticated **FAILED → PASSED** results against the same DISA Windows 11 V2R11 rules on the same authorized Windows 11 Pro 25H2 VM, build 26200. Each change also passed actual preview, repeat-application, rollback and reapply checks. This report describes those ten observed results and the residual findings; it does not claim whole-system compliance. Review provenance is recorded with the evidence below.

![Ten STIG controls with failed baselines, passing follow-ups and successful Windows checks](../stig-remediations/evidence/control-results.png)

*Screenshot of the local evidence report built from saved Tenable results and Windows execution records. Each control is listed below. [Image source and verification](visual-evidence.md).*

## Results

All values below are `REG_DWORD` in the 64-bit registry view. Each was absent before the change. Unlike that earlier registry observation, the baseline below is an actual authenticated Tenable finding.

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

## Execution and comparability

- Baseline: **12:14:59–12:22:13 UTC**, 434 seconds including orchestration. Follow-up: **12:38:50–12:45:15 UTC**, 385 seconds. Plugin 19506 reports 266 and 265 seconds of scanner-engine activity, respectively.
- Each run assessed one authorized host, returned 16 diagnostic items and 258 compliance findings, and reported credentialed checks **yes via SMB**. SMB login, registry access and credential-validation diagnostics were present. Each of the ten exported Rule IDs matches the pinned catalog and the corresponding follow-up result.
- Same VM continuity, scanner, audit selection, protected credential metadata, safety settings and diagnostic configuration were checked privately. Both runs used Nessus **10.12.6**, plugin feed **202611121400**. The configuration fingerprints match. The audit binary-content digest was not available; an audit filename hash is not a content or authenticity proof.
- Native Windows PowerShell **5.1.26100.9818**, 64-bit, ran the unchanged reviewed entrypoints. Preflight found no domain/Azure AD/workplace join, MDM account registration or local machine Registry.pol. These observations supported the authorized local change; they do not prove the permanent absence of all policy writers.
- For every control: verify prior absence; preview without mutation; apply with a new private snapshot; verify; repeat without mutation; preview restore without mutation; restore original absence; repeat restore without mutation; reapply using a separate snapshot; verify. All stages passed. The final reapplications completed by **12:35:16 UTC**, before the follow-up.
- All **33 source hashes** matched before and after execution. **154 Windows execution records**, including 20 snapshots, were transferred privately and independently hash-verified. Prior parser and mocked-harness evidence remains distinct from these actual registry operations.

## Effective behavior and cleanup

A new native Windows PowerShell child process executed a harmless marker. Immediate log queries returned no matching event. A later bounded read found one event **4104** matching that exact process, marker and time window. Native script-block logging is therefore observed; the earlier negative observations are retained. This does not establish PowerShell 7 logging coverage or behavior across future policy refreshes/reboots.

The other nine controls have actual registry and Tenable evidence; their every possible user-interface, device, printer or installer behavior was not separately exercised. No reboot or policy-refresh persistence claim is made.

Authenticated scanning needed temporary, exact scanner-source TCP445 ingress to this VM and Remote Registry in Manual/running state. Both prerequisite windows were closed: the added rules were removed and Remote Registry returned to its original Disabled/stopped state. The original saved scan configuration was restored and read back after each assessment. Defender remained active; the VM agent, RPC, Server, Event Log and RDP services/listener were healthy. Bastion was not reconnected solely for this checkpoint.

The original empty scan's unique root cause remains unproven: discovery settings and prerequisites changed across the diagnostic sequence. The successful bounded combination establishes a usable authenticated path without attributing a zero-host result to Remote Registry alone. Future scans need separately authorized prerequisite windows; cleanup intentionally removed that temporary access.

## Residual findings and evidence

The complete audit changed from 117 failed / 68 passed to 107 failed / 78 passed. **65 errors and 8 warnings remained unchanged**, outside these ten controls. This VM is not claimed fully STIG compliant, and those inconclusive findings were not converted to passes or silently dropped.

Private evidence aliases resolve in the authoritative private ledger:

| Alias | Evidence |
|---|---|
| `EV-TENABLE-BASELINE-20261113` | Original authenticated baseline XML, metadata, configuration and launch/export receipts. |
| `EV-STIG-WINDOWS-APPLY-20261113` | Original source manifest, per-control execution records, snapshots and 154-file checksum manifest. |
| `EV-TENABLE-FOLLOWUP-20261113` | Original authenticated follow-up XML, equivalent configuration and restoration proof. |
| `EV-STIG-CLEANUP-20261113` | Six exact prerequisite snapshot records, final health observations and delayed logging check. |
| `EV-STIG-COMPARISON-20261113` | Reconciled per-control ledger, original-export digests and review status at capture. |

The baseline export SHA-256 is `e6a28259be7e1674c75980605c02a36c62167ecfd7a2350d9a3368620d51978a`; the follow-up is `aa30ef0544b1b22097ee371d03f7eed1552041005b4b818d7ac4422df69e2d12`. Digests establish byte identity, not authenticity by themselves. Original exports, host identifiers, addresses, accounts, snapshots and raw event text are excluded from this repository.

The existing internal evidence schema validates all ten records as `windows_verified` and reports observed fail-to-pass comparisons. Its captured review fields remain pending, and it withholds its stronger reviewed claim. The subsequent operator waiver is recorded separately; it does not manufacture a review or alter the preserved schema or evidence. Exact native seven-digit UTC fractions remain in original records; the derived ledger truncates the seventh fractional digit to its supported microsecond precision. No source timestamp is overwritten.

See the [local validation record](local-validation.md), [Tenable runbook](../stig-remediations/tenable-readiness.md), [evidence semantics](../stig-remediations/evidence-workflow.md) and individual reports above. Reviewed source-file headers retain their original development checkpoint; current status is recorded here and in the reports without changing the tested source hashes.
