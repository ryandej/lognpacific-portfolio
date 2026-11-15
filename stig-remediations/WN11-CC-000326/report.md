# WN11-CC-000326: PowerShell script block logging must be enabled on Windows 11.

[Portfolio](../../README.md) · [Control index](../README.md#implemented-controls) · [Remediation](remediate.ps1) · [Verifier](verify.ps1) · [Tests](control.Tests.ps1)

**Status:** Authenticated Tenable V2R11 baseline **FAILED**, authorized remediation applied, native Windows verification **RegistryMatch**, and equivalent authenticated follow-up **PASSED** on November 13, 2026 UTC. Actual preview, repeatability, rollback and reapply checks passed. See [consolidated validation](../../docs/windows-stig-validation.md) for the comparison method, residual findings and review status.

![Authenticated Tenable before-and-after results including WN11-CC-000326](../evidence/control-results.png)

*The row for WN11-CC-000326 shows its failed baseline, passing follow-up and Windows checks. This screenshot comes from the local evidence report built from the saved scan results.*

## Authoritative definition

- DISA Windows 11 **V2R11**, September 30, 2026; retrieved November 12, 2026.
- Finding `V-253414`; rule `SV-253414r958422_rule`; severity `medium`.
- [Official DISA archive](https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Windows_11_V2R11_STIG.zip); [provenance and hashes](../research.md).
- Key: `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging`.
- Required value: `EnableScriptBlockLogging = 1` as `REG_DWORD`.
- Audit: check presence, exact DWORD type, and value. The verifier uses the 64-bit registry view; absence or another type is a mismatch.
- DISA policy guidance: Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Windows PowerShell >> "Turn on PowerShell Script Block Logging" to "Enabled".

## Implementation and impact

Enables Windows PowerShell script-block logging. Logging may capture sensitive script content and increase log volume. Confirm retention and disclosure rules; do not publish raw event logs. This does not establish PowerShell 7 logging coverage.

[Remediation](remediate.ps1) and the separate [read-only verifier](verify.ps1) use the original [shared registry module](../RegistryControl.psm1). [Control-specific tests](control.Tests.ps1) bind this exact rule and expected state to the native in-memory harness, including failure, idempotence, WhatIf, and rollback cases. All 34 control-specific mocked cases passed on Windows PowerShell 5.1.26100.9818; this does not test real registry writes or policy effects.

## Required validation

1. Confirm the approved Windows 11 VM, applicability, policy owner, and active Tenable rule/revision. Capture the actual baseline with UTC time; do not manufacture a failing setting.
2. Follow the [package prerequisites and one-control workflow](../README.md#one-control-workflow): review the dry run, obtain change approval, and use a new private snapshot outside the checkout. Unexpected non-DWORD values require manual review.
3. Observe local verification, repeat-run behavior, and the relevant feature. Coordinate any policy refresh, new session, or reboot separately; none runs automatically. For logging, use a new Windows PowerShell session and harmless script, with separately approved event inspection.
4. Obtain an authorized Tenable follow-up with matching revision and adequate coverage. Record actual outcomes, side effects, and independent-review findings.

Direct registry changes do not persist policy into GPO/MDM or satisfy the separate policy-management requirement. A registry match alone does not establish effective behavior or Tenable compliance.

## Recovery and evidence

With separate authorization, use `remediate.ps1 -Restore` and the original private snapshot; see [recovery details](../README.md#snapshots-and-recovery). Restore the prior DWORD or remove only a previously absent value. Empty keys remain. Wrong-host/control snapshots, malformed values, or unexpected drift are rejected. Failures retain the snapshot and require inspection; recovery is not automatic.

The original absence was captured in a private snapshot and actually restored during rollback validation, then the control was reapplied using a separate snapshot. Both snapshots remain private. The final expected value remains applied; additional independent review was waived, and publication permission remains separate. Keep raw exports, credentials, and tenant details out of Git.


## Observed execution — November 13, 2026 UTC

Asset alias `ASSET-A`: Windows 11 Pro 25H2 build 26200, native 64-bit Windows PowerShell 5.1.26100.9818. Baseline ended at **12:22:13 UTC**; final apply at **12:35:15.871490Z** and verification at **12:35:15.920878Z**; follow-up ended at **12:45:15 UTC**. Derived ledger times use microsecond precision; original native timestamps retain all seven fractional digits privately.

| Stage | Observed result |
|---|---|
| Before | Expected value absent; authenticated V2R11 rule `SV-253414r958422_rule` FAILED. |
| Apply preview | `NotApplied`, `Changed=false`; registry remained absent and no snapshot was created. |
| Apply and repeat | `Changed`, `Changed=true`, exit 0; verifier matched. Repeat returned `AlreadyMatches`, `Changed=false`, with the original snapshot unchanged. |
| Restore preview | `NotApplied`, `Changed=false`; expected registry value remained present. |
| Actual restore and repeat | `Restored`, `Changed=true`; verifier confirmed original absence. Repeat returned `AlreadyRestored`, `Changed=false`. |
| Final apply and verification | `Changed`, `Changed=true`, exit 0; verifier returned `RegistryMatch`, DWORD `1`, exit 0. |
| Equivalent Tenable follow-up | The same V2R11 Rule ID PASSED; successful credentialed checks and registry access recorded. |

Evidence aliases: `EV-TENABLE-BASELINE-20261113`, `EV-STIG-WINDOWS-APPLY-20261113`, `EV-TENABLE-FOLLOWUP-20261113`, and `EV-STIG-COMPARISON-20261113`. Private manifests bind the individual records and two snapshots to this control. The remediation source SHA-256 is `e14cf715b397a8a02943098500a89e09a2d4c96082972717675d1614d1746818`; the verifier is `c9be80a33b2e5d918ef0b5c30a7698d3f6865f888a239ff2ac9cebe2a68871ac`. The shared module SHA-256 is `0aa1837c62cad66f3546e59f6af59436f5c2e5ef96c163b3d5073b1c35dd977d`. All reviewed source files remained unchanged.

A new native Windows PowerShell child process ran a harmless marker. Immediate event queries were negative; a later bounded read found one matching event 4104 for that exact process, marker and time window. This supports effective native script-block logging. It does not establish PowerShell 7 logging coverage, complete log retention, or persistence across reboot/policy refresh. Raw script-block content remains private.

The complete audit contains unrelated failures, errors and warnings; see the [residual findings and evidence](../../docs/windows-stig-validation.md#residual-findings-and-evidence). This individual pass does not establish whole-system compliance or external acceptance.
