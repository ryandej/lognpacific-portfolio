# Validation record

[Portfolio](../README.md) · [Project status](project-progress.md) · [Windows results](windows-stig-validation.md)

The results below cover local tests, Windows execution, authenticated Tenable assessments and KQL service checks. Source hashes connect each run to the version tested.

## Reproduce local checks

```bash
python3 -B -m unittest discover -s tests -v
python3 -B stig-remediations/tests/test_static.py \
  --benchmark-archive .cache/stig-research/U_MS_Windows_11_V2R11_STIG.zip
python3 -B tools/check_repository.py
python3 -B cyber-defense/workbooks/build_investigation.py --check
python3 -B cyber-defense/workbooks/build_workbook.py --check
```

The DISA checks read the cached benchmark archive and compare it with the recorded hashes and definitions. Independent publisher-signature verification remains outstanding. These commands install nothing and perform no scans or host changes.

## Observed results

| Check | Result |
|---|---|
| Windows parser | All 32 PowerShell files parsed under native Windows PowerShell 5.1.26100.9818. |
| PowerShell behavior | All 340 mocked cases passed on Ubuntu PowerShell 7.6.6 and Windows PowerShell 5.1.26100.9818. |
| Source transfer | All 33 transferred source hashes matched. The nine files in the original Windows evidence checksum manifest also matched. |
| Initial Windows observations | Ten missing registry values, ten `RegistryMismatch` results, zero execution errors. These were collected before the authenticated baseline. |
| Windows changes | Preview, apply, repeat, restore preview, restore, repeat restore and reapply passed for all ten controls. All 154 retained records, including 20 snapshots, were hash-verified. |
| Feature behavior | A delayed event 4104 matched the new native PowerShell process and marker. Broader feature behavior and persistence after reboot or policy refresh remain untested. |
| Tenable | Same host, equivalent saved configuration and successful credentialed checks. Each assessment returned 258 compliance items and 16 diagnostics. All ten exact V2R11 rules changed from FAILED to PASSED. |
| Authentication detector | Eight generated cases passed in Log Analytics using the detector body. Required table columns were observed. Live detector performance remains untested. |
| Windows investigation | Ten queries executed on authorized historical telemetry. Twenty saved query and response hashes matched. The main timeline has 233 records. |
| Recorded investigation workbook | Five aggregate queries passed in Log Analytics. The existing workbook was updated and its source readback matched. |
| Authentication test workbook | All five queries passed their expected results. Rendered charts, full and empty time windows were checked in Azure. |
| Defender response | Onboarding and central process telemetry verified. All 70 collection operations succeeded. Isolation and release succeeded; a 30-sample HTTPS test showed interruption and recovery. |
| Hartwell evidence | Thirty-four retained files matched their hashes. The owned completion page showed all 18 flags, all 1,750 points and completion on time. |

The Windows integration record is `EV-WIN-INTEGRATION-20261112`. Parser execution was at 22:40:57 UTC, mocked cases finished at 22:41:02, and initial observations ran from 22:42:29 to 22:42:38. The later [STIG report](windows-stig-validation.md) records the authenticated assessment and recovery checks.

## Corrections found during validation

The PowerShell 5.1 transfer wrapper originally counted a nested JSON array as one file. A minimal diagnostic reproduced it. Direct `ConvertFrom-Json -InputObject` assignment preserved all 33 entries. File-count, allowlist, duplicate-path and hash checks remained in place. The reviewed STIG implementation was unchanged.

Actual Tenable responses exposed two parser assumptions. Compliance rows could omit the hostname while binding to the validated host ID, and one host's XML could span three `ReportHost` fragments. The tools now require exact same-response host binding and identical identity, time and property maps across fragments. They reject conflicting identity and duplicate items. Both populated exports returned all 274 items and the ten expected rule transitions.

The API also returned an opaque export ID. The client now validates it as a bounded path segment and preserves the receipt to prevent duplicate export requests. Tenable disabled fast discovery when ping was disabled; the configuration check stopped launch until that change was reconciled and tested. These details and the guard conditions are in the [Tenable runbook](../stig-remediations/tenable-readiness.md).

Original Windows timestamps retain seven fractional digits. The derived ledger uses microseconds and documents the precision conversion. Its review fields remain pending; the later operator waiver has a separate record. All ten records pass the existing schema checks as `windows_verified`.

The original authentication workbook needed an explicit chart category axis and both outcome series. Its time parameter needed a positive duration with a fixed end. Those corrections passed service and portal checks. The current portfolio workbook uses recorded investigation counts and has no time picker.

## PowerShell reproduction

Use the approved portable runtime by absolute path and keep its temporary caches in a private test directory:

```bash
XDG_CACHE_HOME="$private_test_dir/cache" \
XDG_CONFIG_HOME="$private_test_dir/config" \
XDG_DATA_HOME="$private_test_dir/data" \
"$approved_pwsh" -NoLogo -NoProfile -NonInteractive \
  -File stig-remediations/tests/Invoke-UnitTests.ps1
```

Set the runtime and private paths before running. Record version, UTC time, output, exit code and source hashes. The harness substitutes in-memory host, registry and snapshot functions. It does not invoke remediation entrypoints. See [test coverage](../stig-remediations/tests/validation.md).

Repeat the relevant tests when source, runtime or new failures justify it. Preserve completed evidence for unchanged code.

## Review and disclosure checks

The operator reported Claude approval of the earlier engineering package. Later execution and documentation have separate records, and an additional review was waived. A prepared review packet remains available. Review status applies to the version and scope examined.

[check_repository.py](../tools/check_repository.py) checks Git-visible candidates, local documentation links, selected disclosure patterns, KQL scope defaults and ignore protections. It allows eight image paths with matching hashes, bounded dimensions and valid PNG structure. Human visual review checks the image content. Free-form secrets, new credential formats, Git history and staged blobs need separate review.

The retained screenshots show actual application views or local reports built from saved evidence. They exclude private names, addresses, credentials, raw command lines and challenge answers. [Image sources and hashes](visual-evidence.md).

## Current local results

On November 15, 2026 UTC, all 222 shared Python tests and all eight DISA source checks passed. The shared suite includes nine checks for the recorded investigation workbook and 18 for the authentication test workbook. All five recorded-data queries also passed in Log Analytics.

The repository check covered 107 text files and eight reviewed images with zero findings. The reviewed PowerShell scripts, shared module and KQL files were unchanged. No Windows tests or vulnerability assessments were repeated for this update.
