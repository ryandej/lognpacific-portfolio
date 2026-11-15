# Windows 11 candidate research

Research date: November 12, 2026. Source: DISA Windows 11 V2R11, dated September 30, 2026. Fourteen controls were checked against the archive. Ten were later implemented and verified through authenticated Tenable assessments. [Results](../docs/windows-stig-validation.md).

## Authoritative source and provenance

- [Official DISA archive](https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Windows_11_V2R11_STIG.zip)
- [DISA distribution catalog](https://www.cyber.mil/stigs/downloads)
- XCCDF member: `U_MS_Windows_11_V2R11_Manual_STIG/U_MS_Windows_11_STIG_V2R11_Manual-xccdf.xml`
- Archive SHA-256: `5a1337e899f113a2482debd3ef240a867fdd205423cbf134e8961de249260d54`
- XCCDF SHA-256: `97680465c4cf44a9be234292f8414f0fe8f4ca8ee8915a2e3f23d840684afde6`
- The archive was retrieved directly from DISA. The XML identifies version 2 and release 11, dated September 30, 2026. Hashes identify the bytes examined; they are not a DISA digital-signature verification.
- The Python suite compares the supplied archive/XML to hashes recorded from that same research copy. A pass confirms that the bytes match the research copy. Publisher signatures and independently authenticated checksums remain unverified.
- V2R11 is the pinned research basis. The completed assessments used V2R11, and all ten exported Rule IDs matched the catalog. Recheck the revision before future assessments. Do not substitute a similarly numbered SCAP package or an older course reference without comparing the specific rules.
- The public archive and extracted XML are held only in ignored `.cache/stig-research/`. No internal instructional document was copied. The source-alignment check accepts an explicitly supplied copy of this archive and performs no download.

## Shortlist

All entries use an HKLM DWORD registry check. Exact registry paths, vulnerability identifiers, rule revisions, values, and implemented-control policy guidance are in [catalog.json](catalog.json). Each implemented control links to its execution report and official identifiers.

| Control / finding | Required value | Disposition | Selection rationale / dependency |
|---|---|---|---|
| `WN11-CC-000005` / `V-253350` | `NoLockScreenCamera = 1` | Deferred | Deferred: confirm a physical or redirected camera; DISA marks camera-free systems not applicable. |
| `WN11-CC-000010` / `V-253352` | `NoLockScreenSlideshow = 1` | [Verified](WN11-CC-000010/report.md) | Restricts lock-screen slideshow presentation. |
| `WN11-CC-000035` / `V-253356` | `NoNameReleaseOnDemand = 1` | Deferred | Deferred: confirm NetBIOS/WINS dependencies and policy-template ownership. |
| `WN11-CC-000100` / `V-253374` | `DisableWebPnPDownload = 1` | [Verified](WN11-CC-000100/report.md) | Prevents HTTP print-driver downloads; confirm no required printer setup depends on them. |
| `WN11-CC-000110` / `V-253376` | `DisableHTTPPrinting = 1` | [Verified](WN11-CC-000110/report.md) | Prevents HTTP printing; confirm no required lab workflow uses it. |
| `WN11-CC-000180` / `V-253386` | `NoAutoplayfornonVolume = 1` | [Verified](WN11-CC-000180/report.md) | Disables automatic actions for non-volume devices. |
| `WN11-CC-000185` / `V-253387` | `NoAutorun = 1` | [Verified](WN11-CC-000185/report.md) | Prevents AutoRun commands from executing automatically. |
| `WN11-CC-000190` / `V-253388` | `NoDriveTypeAutoRun = 255` | [Verified](WN11-CC-000190/report.md) | Disables AutoPlay across all drive types; the required decimal value is 255. |
| `WN11-CC-000295` / `V-253407` | `DisableEnclosureDownload = 1` | [Verified](WN11-CC-000295/report.md) | Prevents automatic RSS enclosure downloads. |
| `WN11-CC-000305` / `V-253409` | `AllowIndexingEncryptedStoresOrItems = 0` | Deferred | Deferred: DISA distinguishes GPO and Intune paths; the management channel is unknown. |
| `WN11-CC-000310` / `V-253410` | `EnableUserControl = 0` | [Verified](WN11-CC-000310/report.md) | Removes user control of privileged Windows Installer options. |
| `WN11-CC-000315` / `V-253411` | `AlwaysInstallElevated = 0` | [Verified](WN11-CC-000315/report.md) | Disables the machine-side AlwaysInstallElevated policy. |
| `WN11-CC-000326` / `V-253414` | `EnableScriptBlockLogging = 1` | [Verified](WN11-CC-000326/report.md) | Enables Windows PowerShell script-block logging. |
| `WN11-CC-000330` / `V-253416` | `AllowBasic = 0` | Deferred | Deferred: establish WinRM authentication dependencies before disabling Basic. |

## Selection and enforcement limits

The prepared set changes individual presentation, printing, AutoPlay/AutoRun, RSS, Windows Installer, or Windows PowerShell logging values. It does not modify management ports, firewall rules, Defender configuration, authentication methods, or accounts. Compatibility still needs checking on each target. Printing dependencies, software-installation behavior, log volume, and sensitive log contents still require review.

DISA `WN11-CC-000063` separately requires policy enforcement through Group Policy or approved MDM. Direct registry writes are a controlled local implementation technique; they do not establish that management requirement or persist a policy into its owning GPO/MDM configuration. Determine the owner and approved enforcement approach before use. A policy refresh may overwrite a local change.

The camera control includes an explicit no-camera not-applicable condition. Encrypted-file indexing has different GPO and Intune paths in V2R11. Those dependencies keep both controls deferred. WinRM authentication and NetBIOS/WINS behavior require environment compatibility review.

The ten prepared controls require missing values to be treated as a finding under their registry checks. Verifiers also reject an incorrect registry type. Remediation stops on an unexpected non-DWORD value for manual review.

## Microsoft implementation references

- [Registry64 selection with RegistryKey.OpenBaseKey](https://learn.microsoft.com/en-us/dotnet/api/microsoft.win32.registrykey.openbasekey)
- [ShouldProcess, WhatIf, and confirmation](https://learn.microsoft.com/en-us/powershell/scripting/learn/deep-dives/everything-about-shouldprocess)
- [Win32_OperatingSystem properties](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-operatingsystem)
- [Windows lock-screen policy mappings](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-devicelock)
- [Windows Installer policy mappings](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-msi)
- [Windows PowerShell logging policy mappings](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-powershellexecutionpolicy)

Use Microsoft mappings to interpret the policy, then check the exact DISA requirement and active Tenable audit. All remediation, verification, and test code in this package is original. No third-party remediation script or instructor solution was imported.
