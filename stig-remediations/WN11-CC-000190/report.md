# WN11-CC-000190: Autoplay must be disabled for all drives.

[Portfolio](../../README.md) · [Control index](../README.md#implemented-controls) · [Remediation](remediate.ps1) · [Verifier](verify.ps1) · [Tests](control.Tests.ps1)

I remediated this Windows 11 V2R11 finding with PowerShell. The authenticated Tenable baseline was FAILED and the follow-up was PASSED on November 13, 2026 UTC. Windows verification and rollback checks also passed. [Full validation record](../../docs/windows-stig-validation.md).

![Authenticated Tenable before-and-after results including WN11-CC-000190](../evidence/control-results.png)

*The row for WN11-CC-000190 shows its failed baseline, passing follow-up and Windows checks. This screenshot comes from the local evidence report built from the saved scan results.*

## Implementation and impact

Disables AutoPlay across all drive types; the required decimal value is 255. A value of 1 is not equivalent to the all-drive mask. Test with harmless media only if separately approved.

The [remediation](remediate.ps1) and separate [verifier](verify.ps1) use the [shared registry module](../RegistryControl.psm1). All 34 control-specific mocked cases passed on Windows PowerShell 5.1.26100.9818. They cover incorrect targets, write failures, repeat execution, previews and rollback.

## Observed execution on November 13, 2026 UTC

Asset alias `ASSET-A`: Windows 11 Pro 25H2 build 26200, native 64-bit Windows PowerShell 5.1.26100.9818. Baseline ended at **12:22:13 UTC**; final apply at **12:35:13.104080Z** and verification at **12:35:13.149744Z**; follow-up ended at **12:45:15 UTC**.

| Stage | Observed result |
|---|---|
| Before | Expected value absent; authenticated V2R11 rule `SV-253388r958804_rule` FAILED. |
| Apply preview | `NotApplied`, `Changed=false`; registry remained absent and no snapshot was created. |
| Apply and repeat | `Changed`, `Changed=true`, exit 0; verifier matched. Repeat returned `AlreadyMatches`, `Changed=false`, with the original snapshot unchanged. |
| Restore preview | `NotApplied`, `Changed=false`; expected registry value remained present. |
| Actual restore and repeat | `Restored`, `Changed=true`; verifier confirmed original absence. Repeat returned `AlreadyRestored`, `Changed=false`. |
| Final apply and verification | `Changed`, `Changed=true`, exit 0; verifier returned `RegistryMatch`, DWORD `255`, exit 0. |
| Equivalent Tenable follow-up | The same V2R11 Rule ID PASSED; successful credentialed checks and registry access recorded. |

Evidence aliases: `EV-TENABLE-BASELINE-20261113`, `EV-STIG-WINDOWS-APPLY-20261113`, `EV-TENABLE-FOLLOWUP-20261113`, and `EV-STIG-COMPARISON-20261113`. Private manifests bind the individual records and two snapshots to this control. The remediation source SHA-256 is `cf078cb57d809e6b785ee5f776b2b30c7b458dd4de7dd8c0136d1ea8e6b88813`; the verifier is `482a3ecc9532e5c6a6717fb25eb28aa8f024f98f35c6022b0a0927c4610cce94`. The shared module SHA-256 is `0aa1837c62cad66f3546e59f6af59436f5c2e5ef96c163b3d5073b1c35dd977d`. All reviewed source files remained unchanged.

The stored value and Tenable check passed. Broader feature behavior, reboot persistence, policy refresh and central policy enforcement remain untested.

The remaining audit findings are listed in [residual findings and evidence](../../docs/windows-stig-validation.md#residual-findings-and-evidence).

## Authoritative definition

- DISA Windows 11 **V2R11**, September 30, 2026; retrieved November 12, 2026.
- Finding `V-253388`; rule `SV-253388r958804_rule`; severity `high`.
- [Official DISA archive](https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Windows_11_V2R11_STIG.zip); [provenance and hashes](../research.md).
- Key: `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer`.
- Required value: `NoDriveTypeAutoRun = 255` as `REG_DWORD`.
- Audit: check presence, exact DWORD type, and value. The verifier uses the 64-bit registry view; absence or another type is a mismatch.
- DISA policy guidance: Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> AutoPlay Policies >> "Turn off AutoPlay" to "Enabled:All Drives".

## Recovery and reuse

Rollback restored the original absence. Reapplication used a new snapshot and left the expected value in place. Both snapshots remain private.

For an authorized reuse, follow the [one-control workflow](../README.md#one-control-workflow) and [snapshot recovery procedure](../README.md#snapshots-and-recovery). Confirm the target, benchmark and policy owner first. The restore path rejects wrong-host snapshots, malformed values and unexpected drift. It leaves empty keys in place.

Group Policy or MDM can overwrite local settings. Coordinate feature checks, policy refresh and reboot testing with the system owner.
