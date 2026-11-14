# WN11-CC-000315: The Windows Installer feature "Always install with elevated privileges" must be disabled.

[Portfolio](../../README.md) · [Control index](../README.md#implemented-controls) · [Remediation](remediate.ps1) · [Verifier](verify.ps1) · [Tests](control.Tests.ps1)

**Status:** Authenticated Tenable V2R11 baseline **FAILED**, authorized remediation applied, native Windows verification **RegistryMatch**, and equivalent authenticated follow-up **PASSED** on November 13, 2026 UTC. Actual preview, repeatability, rollback and reapply checks passed. See [consolidated validation](../../docs/windows-stig-validation.md) for the comparison method, residual findings and review status.

## Authoritative definition

- DISA Windows 11 **V2R11**, September 30, 2026; retrieved November 12, 2026.
- Finding `V-253411`; rule `SV-253411r1051054_rule`; severity `high`.
- [Official DISA archive](https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Windows_11_V2R11_STIG.zip); [provenance and hashes](../research.md).
- Key: `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer`.
- Required value: `AlwaysInstallElevated = 0` as `REG_DWORD`.
- Audit: check presence, exact DWORD type, and value. The verifier uses the 64-bit registry view; absence or another type is a mismatch.
- DISA policy guidance: Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Windows Installer >> "Always install with elevated privileges" to "Disabled".

## Implementation and impact

Disables the machine-side AlwaysInstallElevated policy. The DISA check targets HKLM; this package does not change HKCU or claim to assess all user policy state.

[Remediation](remediate.ps1) and the separate [read-only verifier](verify.ps1) use the original [shared registry module](../RegistryControl.psm1). [Control-specific tests](control.Tests.ps1) bind this exact rule and expected state to the native in-memory harness, including failure, idempotence, WhatIf, and rollback cases. All 34 control-specific mocked cases passed on Windows PowerShell 5.1.26100.9818; this does not test real registry writes or policy effects.

## Required validation

1. Confirm the approved Windows 11 VM, applicability, policy owner, and active Tenable rule/revision. Capture the actual baseline with UTC time; do not manufacture a failing setting.
2. Follow the [package prerequisites and one-control workflow](../README.md#one-control-workflow): review the dry run, obtain change approval, and use a new private snapshot outside the checkout. Unexpected non-DWORD values require manual review.
3. Observe local verification, repeat-run behavior, and the relevant feature. Coordinate any policy refresh, new session, or reboot separately; none runs automatically.
4. Obtain an authorized Tenable follow-up with matching revision and adequate coverage. Record actual outcomes, side effects, and independent-review findings.

Direct registry changes do not persist policy into GPO/MDM or satisfy the separate policy-management requirement. A registry match alone does not establish effective behavior or Tenable compliance.

## Recovery and evidence

With separate authorization, use `remediate.ps1 -Restore` and the original private snapshot; see [recovery details](../README.md#snapshots-and-recovery). Restore the prior DWORD or remove only a previously absent value. Empty keys remain. Wrong-host/control snapshots, malformed values, or unexpected drift are rejected. Failures retain the snapshot and require inspection; recovery is not automatic.

The original absence was captured in a private snapshot and actually restored during rollback validation, then the control was reapplied using a separate snapshot. Both snapshots remain private. The final expected value remains applied; additional independent review was waived, and publication permission remains separate. Keep raw exports, credentials, and tenant details out of Git.


## Observed execution — November 13, 2026 UTC

Asset alias `ASSET-A`: Windows 11 Pro 25H2 build 26200, native 64-bit Windows PowerShell 5.1.26100.9818. Baseline ended at **12:22:13 UTC**; final apply at **12:35:15.173651Z** and verification at **12:35:15.223065Z**; follow-up ended at **12:45:15 UTC**. Derived ledger times use microsecond precision; original native timestamps retain all seven fractional digits privately.

| Stage | Observed result |
|---|---|
| Before | Expected value absent; authenticated V2R11 rule `SV-253411r1051054_rule` FAILED. |
| Apply preview | `NotApplied`, `Changed=false`; registry remained absent and no snapshot was created. |
| Apply and repeat | `Changed`, `Changed=true`, exit 0; verifier matched. Repeat returned `AlreadyMatches`, `Changed=false`, with the original snapshot unchanged. |
| Restore preview | `NotApplied`, `Changed=false`; expected registry value remained present. |
| Actual restore and repeat | `Restored`, `Changed=true`; verifier confirmed original absence. Repeat returned `AlreadyRestored`, `Changed=false`. |
| Final apply and verification | `Changed`, `Changed=true`, exit 0; verifier returned `RegistryMatch`, DWORD `0`, exit 0. |
| Equivalent Tenable follow-up | The same V2R11 Rule ID PASSED; successful credentialed checks and registry access recorded. |

Evidence aliases: `EV-TENABLE-BASELINE-20261113`, `EV-STIG-WINDOWS-APPLY-20261113`, `EV-TENABLE-FOLLOWUP-20261113`, and `EV-STIG-COMPARISON-20261113`. Private manifests bind the individual records and two snapshots to this control. The remediation source SHA-256 is `7713a47417b8312f8aab87206b0b59ee7da599b7bbe0fa163c380a00b6b39bcc`; the verifier is `699f02804c2e760ec3ea4bd295264996e2c6aef649a5a4d3c76088a63a20e368`. The shared module SHA-256 is `0aa1837c62cad66f3546e59f6af59436f5c2e5ef96c163b3d5073b1c35dd977d`. All reviewed source files remained unchanged.

Registry and Tenable observations establish the stated check in this environment. Every related user-interface, device, printer or installer behavior was not separately exercised. Policy-refresh/reboot persistence and centrally managed GPO/MDM behavior remain untested.

The complete audit contains unrelated failures, errors and warnings; see the [residual findings and evidence](../../docs/windows-stig-validation.md#residual-findings-and-evidence). This individual pass does not establish whole-system compliance or external acceptance.
