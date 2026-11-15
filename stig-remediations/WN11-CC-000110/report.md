# WN11-CC-000110: Printing over HTTP must be prevented.

[Portfolio](../../README.md) · [Control index](../README.md#implemented-controls) · [Remediation](remediate.ps1) · [Verifier](verify.ps1) · [Tests](control.Tests.ps1)

Tenable changed this V2R11 control from FAILED to PASSED on November 13, 2026 UTC. Windows verification matched the expected value. Preview, repeated application, rollback and reapply checks passed. [Full validation record](../../docs/windows-stig-validation.md).

![Authenticated Tenable before-and-after results including WN11-CC-000110](../evidence/control-results.png)

*The row for WN11-CC-000110 shows its failed baseline, passing follow-up and Windows checks. This screenshot comes from the local evidence report built from the saved scan results.*

## Authoritative definition

- DISA Windows 11 **V2R11**, September 30, 2026; retrieved November 12, 2026.
- Finding `V-253376`; rule `SV-253376r958478_rule`; severity `medium`.
- [Official DISA archive](https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Windows_11_V2R11_STIG.zip); [provenance and hashes](../research.md).
- Key: `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers`.
- Required value: `DisableHTTPPrinting = 1` as `REG_DWORD`.
- Audit: check presence, exact DWORD type, and value. The verifier uses the 64-bit registry view; absence or another type is a mismatch.
- DISA policy guidance: Configure the policy value for Computer Configuration >> Administrative Templates >> System >> Internet Communication Management >> Internet Communication settings >> "Turn off printing over HTTP" to "Enabled".

## Implementation and impact

Prevents HTTP printing; confirm no required lab workflow uses it. This does not stop the spooler or alter firewall rules; test any required printing separately.

[Remediation](remediate.ps1) and the separate [read-only verifier](verify.ps1) use the original [shared registry module](../RegistryControl.psm1). [Control-specific tests](control.Tests.ps1) bind this exact rule and expected state to the native in-memory harness, including failure, idempotence, WhatIf, and rollback cases. All 34 mocked cases for this control passed on Windows PowerShell 5.1.26100.9818. The Windows execution results are recorded below.

## Required validation

1. Confirm the approved Windows 11 VM, applicability, policy owner, and active Tenable rule/revision. Capture the actual baseline with UTC time; do not manufacture a failing setting.
2. Follow the [package prerequisites and one-control workflow](../README.md#one-control-workflow): review the dry run, obtain change approval, and use a new private snapshot outside the checkout. Unexpected non-DWORD values require manual review.
3. Observe local verification, repeat-run behavior, and the relevant feature. Coordinate any policy refresh, new session, or reboot separately; none runs automatically.
4. Obtain an authorized Tenable follow-up with matching revision and adequate coverage. Record actual outcomes, side effects, and independent-review findings.

Central enforcement requires Group Policy or approved MDM. Policy refresh can overwrite a local registry change. Feature behavior and Tenable results need separate checks.

## Recovery and evidence

With separate authorization, use `remediate.ps1 -Restore` and the original private snapshot; see [recovery details](../README.md#snapshots-and-recovery). Restore the prior DWORD or remove only a previously absent value. Empty keys remain. Wrong-host/control snapshots, malformed values, or unexpected drift are rejected. Failures retain the snapshot and require inspection; recovery is not automatic.

Rollback restored the original absence. Reapplication used a new snapshot and left the expected value in place. Both snapshots remain private. The operator waived an additional review; publication still requires approval.


## Observed execution on November 13, 2026 UTC

Asset alias `ASSET-A`: Windows 11 Pro 25H2 build 26200, native 64-bit Windows PowerShell 5.1.26100.9818. Baseline ended at **12:22:13 UTC**; final apply at **12:35:10.837978Z** and verification at **12:35:10.893189Z**; follow-up ended at **12:45:15 UTC**. Derived ledger times use microsecond precision; original native timestamps retain all seven fractional digits privately.

| Stage | Observed result |
|---|---|
| Before | Expected value absent; authenticated V2R11 rule `SV-253376r958478_rule` FAILED. |
| Apply preview | `NotApplied`, `Changed=false`; registry remained absent and no snapshot was created. |
| Apply and repeat | `Changed`, `Changed=true`, exit 0; verifier matched. Repeat returned `AlreadyMatches`, `Changed=false`, with the original snapshot unchanged. |
| Restore preview | `NotApplied`, `Changed=false`; expected registry value remained present. |
| Actual restore and repeat | `Restored`, `Changed=true`; verifier confirmed original absence. Repeat returned `AlreadyRestored`, `Changed=false`. |
| Final apply and verification | `Changed`, `Changed=true`, exit 0; verifier returned `RegistryMatch`, DWORD `1`, exit 0. |
| Equivalent Tenable follow-up | The same V2R11 Rule ID PASSED; successful credentialed checks and registry access recorded. |

Evidence aliases: `EV-TENABLE-BASELINE-20261113`, `EV-STIG-WINDOWS-APPLY-20261113`, `EV-TENABLE-FOLLOWUP-20261113`, and `EV-STIG-COMPARISON-20261113`. Private manifests bind the individual records and two snapshots to this control. The remediation source SHA-256 is `50b1fd10b8d4111d79f9b5fd952b28edff94dfe505c1c697031c9bda0a75449a`; the verifier is `e6cf966ed802985aa95d09ab3621f04784bba29378324718266f644d51e82fac`. The shared module SHA-256 is `0aa1837c62cad66f3546e59f6af59436f5c2e5ef96c163b3d5073b1c35dd977d`. All reviewed source files remained unchanged.

The stored value and Tenable check passed. Broader feature behavior, reboot persistence, policy refresh and central policy enforcement remain untested.

The remaining audit findings are listed in [residual findings and evidence](../../docs/windows-stig-validation.md#residual-findings-and-evidence). External acceptance is recorded separately.
