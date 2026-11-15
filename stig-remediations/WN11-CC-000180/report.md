# WN11-CC-000180: Autoplay must be turned off for non-volume devices.

[Portfolio](../../README.md) · [Control index](../README.md#implemented-controls) · [Remediation](remediate.ps1) · [Verifier](verify.ps1) · [Tests](control.Tests.ps1)

I remediated this Windows 11 V2R11 finding with PowerShell. The authenticated Tenable baseline was FAILED and the follow-up was PASSED on November 13, 2026 UTC. Windows verification and rollback checks also passed. [Full validation record](../../docs/windows-stig-validation.md).

![Authenticated Tenable before-and-after results including WN11-CC-000180](../evidence/control-results.png)

*The row for WN11-CC-000180 shows its failed baseline, passing follow-up and Windows checks. This screenshot comes from the local evidence report built from the saved scan results.*

## Implementation and impact

Disables automatic actions for non-volume devices. Manual device access remains a separate behavior to validate on the approved VM.

The [remediation](remediate.ps1) and separate [verifier](verify.ps1) use the [shared registry module](../RegistryControl.psm1). All 34 control-specific mocked cases passed on Windows PowerShell 5.1.26100.9818. They cover incorrect targets, write failures, repeat execution, previews and rollback.

## Observed execution on November 13, 2026 UTC

Asset alias `ASSET-A`: Windows 11 Pro 25H2 build 26200, native 64-bit Windows PowerShell 5.1.26100.9818. Baseline ended at **12:22:13 UTC**; final apply at **12:35:11.572897Z** and verification at **12:35:11.624351Z**; follow-up ended at **12:45:15 UTC**.

| Stage | Observed result |
|---|---|
| Before | Expected value absent; authenticated V2R11 rule `SV-253386r958804_rule` FAILED. |
| Apply preview | `NotApplied`, `Changed=false`; registry remained absent and no snapshot was created. |
| Apply and repeat | `Changed`, `Changed=true`, exit 0; verifier matched. Repeat returned `AlreadyMatches`, `Changed=false`, with the original snapshot unchanged. |
| Restore preview | `NotApplied`, `Changed=false`; expected registry value remained present. |
| Actual restore and repeat | `Restored`, `Changed=true`; verifier confirmed original absence. Repeat returned `AlreadyRestored`, `Changed=false`. |
| Final apply and verification | `Changed`, `Changed=true`, exit 0; verifier returned `RegistryMatch`, DWORD `1`, exit 0. |
| Equivalent Tenable follow-up | The same V2R11 Rule ID PASSED; successful credentialed checks and registry access recorded. |

Evidence aliases: `EV-TENABLE-BASELINE-20261113`, `EV-STIG-WINDOWS-APPLY-20261113`, `EV-TENABLE-FOLLOWUP-20261113`, and `EV-STIG-COMPARISON-20261113`. Private manifests bind the individual records and two snapshots to this control. The remediation source SHA-256 is `d26184354ff664e9909350e86804484a61470910a4a0c1afe2ba71ce6505d2d3`; the verifier is `55679feca04183c4b7156c21a11a7e7f79a2b831a54b7a3bcd19d7cf68a149ea`. The shared module SHA-256 is `0aa1837c62cad66f3546e59f6af59436f5c2e5ef96c163b3d5073b1c35dd977d`. All reviewed source files remained unchanged.

The stored value and Tenable check passed. Broader feature behavior, reboot persistence, policy refresh and central policy enforcement remain untested.

The remaining audit findings are listed in [residual findings and evidence](../../docs/windows-stig-validation.md#residual-findings-and-evidence).

## Authoritative definition

- DISA Windows 11 **V2R11**, September 30, 2026; retrieved November 12, 2026.
- Finding `V-253386`; rule `SV-253386r958804_rule`; severity `high`.
- [Official DISA archive](https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Windows_11_V2R11_STIG.zip); [provenance and hashes](../research.md).
- Key: `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer`.
- Required value: `NoAutoplayfornonVolume = 1` as `REG_DWORD`.
- Audit: check presence, exact DWORD type, and value. The verifier uses the 64-bit registry view; absence or another type is a mismatch.
- DISA policy guidance: Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> AutoPlay Policies >> "Disallow Autoplay for non-volume devices" to "Enabled".

## Recovery and reuse

Rollback restored the original absence. Reapplication used a new snapshot and left the expected value in place. Both snapshots remain private.

For an authorized reuse, follow the [one-control workflow](../README.md#one-control-workflow) and [snapshot recovery procedure](../README.md#snapshots-and-recovery). Confirm the target, benchmark and policy owner first. The restore path rejects wrong-host snapshots, malformed values and unexpected drift. It leaves empty keys in place.

Group Policy or MDM can overwrite local settings. Coordinate feature checks, policy refresh and reboot testing with the system owner.
