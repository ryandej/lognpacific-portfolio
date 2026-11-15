# Local validation and reproduction

[Portfolio](../README.md) · [Project status](project-progress.md) · [Methodology](methodology.md)

All checks below run from the repository root using Python's standard library. These test commands do not contact Azure, Defender or Tenable, execute Windows remediation, or create live evidence. Synthetic fixtures use temporary files. Use `-B` to avoid bytecode files. The separate evidence client requires approved credentials and explicit execution before it can contact Tenable; its tests mock transport.

```bash
python3 -B stig-remediations/tests/test_static.py \
  --benchmark-archive .cache/stig-research/U_MS_Windows_11_V2R11_STIG.zip
python3 -B -m unittest discover -s tests -v
python3 -B tools/check_repository.py
git --no-optional-locks diff --check
git --no-optional-locks diff --cached --name-only
```

The first suite requires the already cached public DISA archive, supplied explicitly. It compares cached bytes with recorded hashes and definitions; it does not independently establish publisher authenticity. A missing archive is a dependency, not permission to download it. The second suite uses in-memory synthetic fixtures. The final Git command inspects staging without modifying it.

## Observed validation

Repository test checkpoint: November 14, 2026 UTC (November 13 local workday), with all 221 Python tests rerun for the Hartwell report refresh. Local tests performed no downloads, installations or Windows modifications. Separately authorized Windows remediation and Tenable assessments are recorded as distinct execution layers below.

| Layer | Actual result |
|---|---|
| DISA source-alignment/static suite | 8 passed, 0 failed, using the existing cached V2R11 archive. |
| Shared Python suites | 213 passed, 0 failed, including 39 synthetic export-parser cases, 45 mocked evidence-client cases and 24 diagnostic guard cases. The workbook contributes 18 tests, program metrics six, and reviewed-image disclosure guards ten. Total with the static suite: 221. |
| PowerShell on Ubuntu | Prior observed run on existing portable PowerShell 7.6.6: 340 mocked behavioral cases passed, exit 0, plus source/deferred/unknown-control assertions. Unchanged source was not rerun for the API-client follow-up. |
| Retained Windows parser evidence | 32 files, 0 errors on Windows PowerShell 5.1.26100.9818, 64-bit. |
| Retained Windows mocked tests | 340 passed, 0 failed; 34 per control. These were not rerun remotely in this batch. |
| Retained Windows read-only checks | Ten missing expected values, `RegistryMismatch`, exit 1; 0 execution errors. |
| Source/evidence integrity | All 33 current reviewed source hashes match the retained transfer manifest. All 9 files listed in the original private evidence checksum manifest match. |
| Actual Windows changes and recovery | Ten actual apply/WhatIf/repeat/restore/reapply sequences passed. Expected DWORDs remain applied. 154 execution records including 20 snapshots were transferred and hash-verified; all 33 source hashes remain unchanged. Native script-block logging was observed through a matching event 4104 after delayed collection. Other feature behavior and policy-refresh/reboot persistence remain untested. |
| Tenable baseline/follow-up | One authenticated baseline and one equivalent follow-up assessed the same host and 258 compliance findings each. All ten exact V2R11 rules changed FAILED → PASSED, with credentialed SMB and registry access. Original empty and diagnostic-only histories remain preserved. Both raw compliance exports passed integrity and actual-format extraction checks. Temporary scan settings and Windows prerequisites were restored after each run. See the [execution report](windows-stig-validation.md). |
| Private browser adapter | Repeated authorized page reads/navigation through one temporary official MCP/CLI connection. After a native-input and route-scope correction, 14 Python adapter cases and 15 Node guard cases passed; all 15 Node cases also passed on Windows. Native clicks were observed as trusted and delivered to the exact owned export controls, but no download was obtained. Temporary processes were stopped, preserving Chrome and loopback debugging. These separate adapter tests are not part of the 221 repository tests. |
| Coordination-workstation browser | Repeated authenticated course/hunt reads and navigation succeeded through one local official MCP/CLI session. It runs as the normal user, with no service/autostart or public debugging listener. Its URL target filter is a version-pinned private customization, not a browser-profile security boundary. |
| Repository disclosure/link/ignore checks | 103 Git-visible text files and seven exact reviewed PNGs checked for the Hartwell report refresh, zero findings. Image hashes, bounded dimensions/sizes, PNG structure/checksums and absence of metadata chunks were verified. Checks are not comprehensive secret detection or pixel-content review. |
| KQL service execution | Eight synthetic authentication-sequence cases passed in authorized Log Analytics using the actual detector body and datatables only. Separately scoped training-investigation queries also executed successfully. All five new workbook panels also passed synthetic service-result contracts. Ten investigation queries passed empty-scope execution against the authorized Log Analytics schema, with zero rows. An owned-VM authentication query returned zero events in its bounded interval. A later authorized query against the correct course workspace executed all ten queries on assigned historical data, with a 233-row focus timeline. The owned endpoint was subsequently onboarded and a benign process event was observed centrally. These distinct results do not establish live detector performance. The earlier narrow Graph request returned 403; the supported Log Analytics route used existing authorized data access. |
| Azure diagnostics | Bounded existing-VM/NIC/subnet and read-only guest observations collected. Shared NSG read denied; investigation stopped at that boundary. |

The retained Windows evidence alias is `EV-WIN-INTEGRATION-20261112`. Parser execution was at 22:40:57 UTC; mocked cases finished at 22:41:02; read-only observations ran at 22:42:29–22:42:38. Its original private directory and SHA-256 manifest remain unchanged. Source integrity links these observations to the current implementation; it does not prove policy effectiveness or publisher authenticity.

The prior PowerShell 5.1 transfer wrapper failure was reproduced as pipeline JSON array nesting: wrapping the piped deserialization yielded one nested array. Direct `ConvertFrom-Json -InputObject` assignment preserved the 33 entries. File-count, allowlist, duplicate/path checks and SHA-256 gates were retained. The successful source verification and execution followed that correction. This wrapper was a temporary transport artifact, not a change to the reviewed STIG source.

The operator reports independent Claude approval of the earlier engineering package and 77 prior Python tests. That review does not cover the latest parser/client corrections, actual Windows/Tenable results or reports. The original 33 reviewed artifacts are unchanged. The operator previously waived another independent review and now requests a prepared Claude review packet before publication. No new independent review is represented as completed. Disclosure approval is separate. API tests cover route/scope restrictions, private storage, hidden input, TLS origin, redirect/error handling, export-job binding and integrity. Diagnostic tests additionally cover exact plugin selection, protected settings, restoration conflicts and durable duplicate-launch protection. Three observed apply/launch/restore cycles now comprise the earlier diagnostic-only run and the later authenticated baseline/follow-up.

Populated compliance responses exposed two format assumptions: API compliance rows can omit hostname while binding to an IP-validated host ID, and one host's XML items can be split across repeated `ReportHost` fragments. The client now requires an exact same-response ID binding; the parser requires identical host identity/window/property maps across fragments and rejects repeated items or conflicting identity. Actual Rule IDs came from `compliance-reference`; plugin 19506 annotated successful credentialed checks with an SMB account clause. The parser recognizes that bounded form without retaining the account. Fifteen new regression methods cover these behaviors and rejection paths. Both actual populated exports now extract all 274 diagnostic/compliance items and the ten correct rule transitions.

The derived evidence ledger initially rejected native seven-digit timestamp fractions. Explicit, documented truncation to microseconds resolved its existing precision requirement without changing that schema or the original evidence. All ten records validate. Their captured review fields remain pending; the later operator waiver is recorded separately without changing the schema or original evidence. Initial script-block event checks were negative; a later exact process/marker/time query found the event. Both observations are retained.

During this batch, one static test initially found an ignored Python bytecode cache in the source directory. Removing that generated cache restored 8/8 static passes; no reviewed source or test was weakened. The first scan readback correctly blocked launch because Tenable disabled fast discovery together with its parent ping setting. Explicit handling and a regression case were added; immutable original and reconciled plans were retained. A read-only guest diagnostic initially returned no usable structured output. Its bounded retry succeeded with structured error capture, but absent authentication/block events and disabled firewall packet logging cannot prove absence of traffic. No Windows parser or behavioral test was rerun for these Python/documentation changes.

## Reproducing the local PowerShell tests

Use the existing approved portable runtime by absolute path. For a constrained execution environment, place transient .NET/PowerShell caches in a dedicated private temporary directory rather than changing system configuration:

```bash
XDG_CACHE_HOME="$private_test_dir/cache" \
XDG_CONFIG_HOME="$private_test_dir/config" \
XDG_DATA_HOME="$private_test_dir/data" \
"$approved_pwsh" -NoLogo -NoProfile -NonInteractive \
  -File stig-remediations/tests/Invoke-UnitTests.ps1
```

Set those paths deliberately to an existing approved runtime and an approved private test location. Record version, UTC time, stdout, stderr, exit code and source hashes. The harness installs no dependencies, replaces registry/host/snapshot boundaries with in-memory functions, and does not execute remediation entrypoints. Never run the apply scripts on the coordination workstation. See [coverage](../stig-remediations/tests/validation.md).

The Windows integration evidence already establishes PowerShell 5.1 parser and mocked behavior. Do not repeat it solely to update a timestamp. Repeat applicable tests if source/runtime changes or a real failure invalidates the evidence. Before any Windows change, independently establish the live baseline, scope, policy ownership and rollback approval.

## Quality-check limitations

[check_repository.py](../tools/check_repository.py) obtains candidates from read-only Git listing, refuses protected paths before opening them, checks local Markdown/HTML links, selected disclosure hazards, KQL empty defaults/scope, and hypothetical ignore paths. The only image exceptions are eight exact paths with matching [reviewed hashes and provenance](visual-evidence.json); unknown images, replaced bytes, metadata chunks and excess size fail validation. All eight images have been visually inspected; the automated checker does not read pixel meaning. It does not inspect ignored private directories or print matched secret values. It is not a complete secret detector or data-loss-prevention system; free-form sensitive details, new credential formats and misleading claims still require human review. It does not scan Git history or the contents of staged blobs; independently inspect the exact staged revision only after staging is authorized.

Public claims must distinguish authored source, static checks, Python runtime tests, PowerShell runtime tests, Windows observation, Tenable results and independent review. External acceptance is a separate decision with private administrative records; no local test or generated report awards it. There is no implemented or evaluated AI system in this package.

The evidence audit independently reparsed both original compliance exports, reconciled the same host identity and saved-configuration fingerprint, checked all ten exact Rule IDs, and verified 154 Windows evidence hashes, 33 unchanged source hashes and 110 execution-stage results. The four-file hunt completion bundle also matched its manifest. See the [program results](../vulnerability-management/README.md) and [workbook evidence](../cyber-defense/workbooks/validation-results.json). The later workbook deployment is recorded under `EV-WORKBOOK-V17`: five rendered synthetic panels, native full-range control, empty-data behavior and exact source readback. No live detection effectiveness is established.

The [endpoint validation](endpoint-validation.md) records actual onboarding, central process ingestion, forensic collection and bounded isolation/release. These later approved operations are separate from the retained STIG assessment and local tests.

## Hartwell case-report refresh

The [Hartwell report](../threat-hunting/README.md) now occupies the existing tracker-linked GitHub path. Preparing it rechecked 34 private hunt-evidence hashes and preserved the original results. A fresh capture of the owned completion indicator was taken through the existing browser connection; the page was restored afterward. Two additional screenshots show clearly labeled local analysis views of saved query results. The three hunt images are unchanged native PNG captures, totaling 236,413 bytes. No new telemetry queries, scans, host changes, or investigation-response actions were performed. The shortened KQL excerpts are documented adaptations, not newly executed service queries.

## Project report update — November 15, 2026 UTC

The Windows investigation report now includes a screenshot and a small summary of its saved results. All ten query files and their twenty saved query and response hashes matched the original execution records. The timeline contains 233 records across five tables. Its six time-bin counts sum to the same total.

The image is a native screenshot of a local report. It contains aggregate counts and findings; private identifiers, commands and answers are omitted. The portfolio now has eight reviewed images totaling 830,440 bytes. The existing image size and metadata checks remain in place.

After these changes, all 213 shared Python tests and eight DISA static checks passed. The reviewed PowerShell scripts, shared module and KQL queries were unchanged. No Windows actions, new assessments or telemetry queries were needed for this update.

The ten individual STIG reports and the consolidated results page display the existing control-results screenshot directly. Every project page linked from the activity and supporting-work records now includes a relevant reviewed image. The pages reuse the same eight image files, so this change adds no image storage.
