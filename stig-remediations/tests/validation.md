# Local validation record

Development environment: Ubuntu coordination workstation and the authorized Windows VM. Reconciled November 13, 2026 UTC using retained evidence and current local tests.

## Validation layers

| Layer | Status |
|---|---|
| Official DISA source retrieval and manual definition review | V2R11 archive and fourteen candidate definitions inspected; provenance recorded in research. |
| Python source-alignment and repository checks | Passed: 8 tests, including source comparisons for all 14 candidates and artifact checks for all 10 implementations. |
| PowerShell parser | Passed in the local harness; retained Windows evidence records 32 files and 0 errors under PowerShell 5.1.26100.9818. |
| Native PowerShell unit harness | Retained runs: 340 passed on Ubuntu PowerShell 7.6.6; 340 passed, 0 failed on Windows PowerShell 5.1.26100.9818. Unchanged sources were not rerun solely to update a timestamp. |
| Windows prerequisite and registry API checks | Ten actual apply/verify, repeat-run, WhatIf, restore/verify, repeat-restore and final-reapply sequences passed on Windows 11 Pro 25H2 build 26200. Original absence was restored during each rollback; expected DWORDs remain applied. |
| Effective GPO/MDM/feature behavior | Native Windows PowerShell script-block logging observed through a matching child-process event 4104 after delayed collection. Broader feature behavior and policy-refresh/reboot persistence remain untested. No central policy writer was identified in the bounded preflight. |
| Tenable baseline and follow-up compliance audit | All ten exact V2R11 rules FAILED in the authenticated baseline and PASSED in the equivalent follow-up. Other audit failures, errors and warnings remain. |
| Independent review | Operator reports Claude reviewed the original package and all six subsequent corrections, found no blocking defects, and independently reproduced all 8 Python tests. Exact reviewed artifact hashes were not supplied. The operator waived additional independent review of the latest tooling, live evidence and documentation; no new review is claimed. |

Observed command:

```bash
python3 stig-remediations/tests/test_static.py \
  --benchmark-archive .cache/stig-research/U_MS_Windows_11_V2R11_STIG.zip
```

The eight checks cover cached archive/XML hash consistency and revision; fourteen DISA identifier/path/type/value mappings; deferred applicability and management exceptions; ten control-specific entry points and expected cases; absence of deferred implementation directories; local documentation links; Git visibility; and exclusion of administrative framing. The suite uses Python's standard library and reads the already-downloaded public benchmark. It does not parse or execute PowerShell or independently authenticate the source archive; see [provenance](../research.md#authoritative-source-and-provenance).

The native harness defines **34 behavioral cases per prepared control (340 total)**, plus source-mapping assertions and deferred/unknown-control checks. Coverage includes missing/matching/wrong-type states, exact DWORD writes, no-op repeatability, WhatIf, target/OS/edition/architecture/elevation checks, snapshot failures and overwrite prevention, drift, write/read failures, rollback, malformed/cross-host/cross-value snapshots, and benchmark rejection. Four additional cases per control cover missing-directory apply previews, rejection during actual apply and restore previews, and retained path validation during previews. All 340 cases have observed passing results in both runtimes; the underlying operations were mocked.

## Independent-review follow-up

- Renamed local variables that shadowed PowerShell's automatic `$Matches` variable.
- Apply-only `-WhatIf` can preview before the private directory exists. Actual changes and all restore paths retain their directory/snapshot prerequisites; no directory is created automatically.
- Preserved exit codes and documented all `Status`/`Changed` outcomes, including previews and rollback.
- Clarified that matching the recorded cached archive hashes is not independent publisher-authenticity verification.
- Reran the Python suite after the follow-up: all 8 tests passed. Local whitespace checks and Python syntax parsing also passed. Status/Changed assertions were strengthened in the authored PowerShell cases.
- The previous runtime-unavailable checkpoint is superseded. An existing portable PowerShell 7.6.6 runtime and the Windows 5.1 evidence now establish mocked execution. The operator reports review of the prior corrections with no blocking defects; the operator subsequently waived another independent review.

In-memory unit coverage does not establish write adapters, actual policy effect, signing or snapshot ACL behavior. Separate actual Windows execution now exercises the write/snapshot/restore adapters for the ten selected controls, with a private SYSTEM/Administrators-only evidence directory. All 33 current source hashes match the retained transfer manifest; 154 new execution records, including 20 snapshots, were transferred and hash-verified. The original empty scan remains inconclusive; the later authenticated baseline and follow-up are distinct, preserved histories. See the [execution report](../../docs/windows-stig-validation.md) for timestamps, comparability, cleanup and limitations.

The later local package preserves the registry module, all remediation/verification/control-test scripts and PowerShell harness unchanged. Per-control reports distinguish the operator waiver of another review from the reported prior code review; neither is treated as an independent review of the live results. Its separate Python evidence, deployment, detection-model and quality checks are recorded in [local validation](../../docs/local-validation.md), including current runtime versions, evidence aliases, timestamps and the retained transfer-wrapper correction. Python tests remain separate from PowerShell execution.
