# Windows and Tenable evidence workflow

The ten controls are candidates. Neither a prepared script nor an audit item in a reference document establishes a failing baseline, a successful change, or external acceptance. Start from the actual authorized VM and the actual scan policy.

## Before scanning

Obtain the assigned scanner, permission to scan this VM's private IP, the permitted scan window, credentials through the approved secret store, and the exact Windows 11 STIG compliance policy. Confirm scanner-to-VM connectivity with the range administrator, including subnet/NIC NSGs, routing and Windows firewall. A private IP, peering, or successful RDP session does not establish scanner reachability.

Tenable documents that credentialed Windows checks require access to the relevant files and registry, commonly administrative access. Confirm the approved authentication method, required SMB/RPC/WMI access, administrative shares and Remote Registry behavior for the selected scanner and policy. Do not disable UAC, Defender or the firewall, change authentication filtering, or open broad inbound rules as a shortcut. Any required configuration change needs separate approval. [Tenable Windows credentialed checks](https://docs.tenable.com/nessus/Content/CredentialedChecksOnWindows.htm).

Record private evidence of successful authentication and completed compliance checks, not merely a completed network scan. Capture the audit filename/version, source and digest, selected policy, scanner/plugin versions, target identity, Windows edition/build, UTC window, result completeness and any errors. The `.audit` format's `version:"2"` is a format version, **not DISA V2R11**. [Tenable Windows audit-file reference](https://docs.tenable.com/nessus/compliance-checks-reference/Content/WindowsConfigurationAuditComplianceFileReference.htm).

Compare the actual audit's benchmark and each rule against [catalog.json](catalog.json). The implementations are pinned to DISA V2R11. Older source examples do not establish the live policy revision. If the selected audit is another revision, retain its actual identifiers, stop the candidate's validation claim, and review the check/fix differences. Do not rename a result to make it match.

## Offline ledger and mapping

[evidence.py](evidence.py) uses Python's standard library. It does not parse Tenable CSV, XML or `.nessus` exports. No specific export layout has been verified in our environment. A separate [documented-format extractor](tenable-readiness.md#offline-export-extraction) can assist with exact mappings, but has only synthetic test coverage and never populates this ledger automatically. A human must reconcile the minimum metadata against authorized private results and independently check the transcription. Preserve original exports outside Git.

Run from the repository root. Commands print to stdout and do not create files. If saving output, use a separately approved private store; do not put populated live ledgers in tracked paths.

```bash
python3 -B stig-remediations/evidence.py init --origin authorized-live --asset ASSET-A
python3 -B stig-remediations/evidence.py map WN11-CC-000010
python3 -B stig-remediations/evidence.py map V-253352
python3 -B stig-remediations/evidence.py validate /approved/private/ledger.json
python3 -B stig-remediations/evidence.py report /approved/private/ledger.json --control WN11-CC-000010
python3 -B stig-remediations/evidence.py validate /approved/private/ledger.json --require-verified
```

`init` creates ten **unassessed** records with no benchmark or evidence. The default context is `synthetic`; selecting `authorized-live` describes the intended source and does not create authorization. Mapping accepts an exact prepared control ID, vulnerability ID, or pinned rule ID; it does not guess from a title, plugin number, severity, or partial match. Deferred controls require manual review.

## Internal schema 1

The `init` output is the complete field template. Unknown fields are rejected to reduce accidental inclusion of raw output. Required structures:

| Field | Meaning and permitted values |
|---|---|
| `schema`, `origin`, `asset` | Schema `1`; `synthetic` or `authorized-live`; pseudonym such as `ASSET-A`. |
| `benchmark` | Actual `label` such as `V2R11`, with a benchmark evidence alias. Leave both null until observed. |
| `evidence` | Map of `EV-...` aliases to `kind`, SHA-256 digest, UTC `captured_at`, matching asset alias and boolean `disclosure_reviewed`. Kinds: benchmark, baseline, remediation, local, followup, review. |
| `controls` | Exactly ten unique prepared control records. Preserve records for unselected controls as unassessed. |
| `baseline`, `followup` | `status`: not_assessed, pass, fail, error, not_applicable; `at`, `evidence`, actual `benchmark`, exact `rule_id`. All other fields null when unassessed. |
| `local` | `status`: not_run, RegistryMatch, RegistryMismatch, Error; UTC `at`, evidence alias, `value_exists`, registry `kind`, numeric `value`. Keep arbitrary string/binary registry data private. |
| `remediation` | `status`: not_run, Changed, AlreadyMatches, NotApplied, Restored, AlreadyRestored, Error; UTC `at`, evidence alias, `changed`, `exit_code`. Preserve null uncertainty for an error where state is unknown. |
| `review` | pending, changes_requested, or reviewed, with UTC `at` and evidence of the independent review of this control's results. Code review alone is not review of live results. |
| `claim` | unverified, windows_verified, or tenable_verified. The tool rejects claims with missing supporting stages. |

Evidence aliases are resolvable references in a **private manifest**: map each to the approved store location, original capture, operator, tool/version, authorization reference and digest. Do not place those locations or identities in public reports. `disclosure_reviewed` covers the proposed metadata/derivative; it does not authorize publishing raw attachments. Hashes identify bytes but cannot prove authenticity, correct scope or truth. The tool does not open attachments or verify supplied digests against them.

Record each scan's actual rule revision independently. A different revision can be recorded but cannot receive a compatible comparison or final validation claim. All observation times must be UTC with `Z`; capture time must not predate the observation. Timestamps and metadata are operator assertions, not cryptographically attested events.

## Per-control execution and comparison

1. Confirm applicability, policy ownership, authorization, management recovery and the actual baseline. Record pass/fail/error/not-applicable as observed. Do not deliberately weaken a passing control to create a finding.
2. Complete the PowerShell parser and behavioral tests first. On the authorized Windows VM, record read-only verification, inspect the apply preview, then obtain the approved change scope. Keep the private backup directory, snapshot ACLs and recovery path ready. See [script usage and return values](README.md).
3. Apply only the selected, approved control and preserve its original snapshot. Record `Status`, `Changed` and exit code together. Exit 0 includes no-op, preview and restore outcomes; it does not alone prove remediation. Error exit 2 may follow a partial write. Investigate before retrying or restoring.
4. Run the separate verifier after the change. `RegistryMatch` means the expected value/type was observed; it does not prove effective policy behavior, all user state, or a Tenable pass. Capture relevant policy-refresh/sign-in requirements and side effects privately.
5. Run the authorized follow-up against the same VM and policy. Require successful credentialed checks and the exact control result. Record the actual outcome, even when it fails. Retain baseline and follow-up separately.
6. Obtain independent review of the live evidence and limitations. Append the generated comparison to the control's technical report only after disclosure review. Include policy effect, side effects, recovery readiness and deviations that the compact ledger cannot represent.

The comparison distinguishes fail-to-pass, already-passing, still-failing, regressed (pass-to-fail), unassessed and not-comparable. `windows_verified` represents only the technical observation supported by the recorded Windows registry/apply checks. It does not establish independent-review completion, disclosure approval, Tenable compliance, or formal program credit. Those require separate evidence and decisions; the schema and technical validation gates do not change this distinction. `tenable_verified` additionally requires compatible completed baseline/follow-up, passing follow-up, ordered evidence, independent result review and disclosure review. It is not an acceptance decision by an external reviewer or program.

`validate` exits 0 for internally consistent metadata, **even if validation gates remain missing**; inspect `missing`. `--require-verified` exits 1 if any of the ten candidates has missing gates. Exit 2 means invalid input. Reports print evidence aliases and stage outcomes, never raw results. This tool checks consistency, not automatic sanitization: human review remains mandatory.
