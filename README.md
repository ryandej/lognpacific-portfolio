# LOG(N) Pacific | AI Security Engineering

**Ryan DeJong — cybersecurity engineering portfolio**

Original PowerShell and Python automation, KQL investigations, and security validation developed in the LOG(N) Pacific Cyber Range. The work covers Windows hardening, vulnerability management, threat detection, and endpoint response using Tenable, Microsoft Defender for Endpoint, Microsoft Sentinel, and Azure.

Start with the [Windows hardening results](docs/windows-stig-validation.md), the [Sentinel investigation workbook](cyber-defense/workbooks/README.md), or the [threat investigation portfolio](threat-hunting/README.md). Each project links its implementation, observed results, and limitations.

## Selected projects

| Project | Engineering work | Observed result |
|---|---|---|
| [Windows 11 STIG automation](stig-remediations/README.md) | Ten PowerShell remediations for DISA Security Technical Implementation Guide controls, with separate verification, previews, snapshots, and guarded rollback. | **10 authenticated Tenable findings changed from FAILED to PASSED** against Windows 11 V2R11. Actual repeat application, rollback, and reapply checks passed for every control. |
| [Vulnerability management program](vulnerability-management/README.md) | A complete assessment cycle for one endpoint: asset scope, prioritization, remediation, equivalent reassessment, reporting, and a residual-work queue. | Reconciled **258 compliance items** before and after the changes. All ten selected failures closed; remaining failures, errors, and warnings stay visible. Governance exercises are labeled as simulations. |
| [Detection engineering and Sentinel workbook](cyber-defense/README.md) | Authentication-sequence KQL, a Python reference model, reproducible fixtures, and a five-panel investigation workbook. | Eight synthetic detector cases passed in Log Analytics. The deployed workbook's charts, event context, time controls, and empty-data behavior were verified using explicitly synthetic events. |
| [Threat hunting and incident reconstruction](threat-hunting/README.md) | HTTP-to-host investigation methods and ten scoped Defender queries covering access, execution, persistence, network activity, and timelines. | Queries executed against authorized historical telemetry; findings, a timeline, and a containment proposal were documented privately. Public artifacts preserve the methods without disclosing restricted answers or telemetry. |
| [Endpoint telemetry and response](docs/endpoint-validation.md) | Defender onboarding, telemetry checks, investigation-package collection, and controlled isolation/recovery on the owned endpoint. | Central process telemetry observed; **70/70 collection operations succeeded**; isolation and release succeeded with observed connectivity loss and recovery. |

All operational results come from authorized Cyber Range work. Synthetic detection tests, historical investigations, and actual Windows configuration changes are identified separately.

## Selected work in pictures

<table>
<tr>
<td width="50%" valign="top"><a href="stig-remediations/README.md"><img src="stig-remediations/evidence/control-results.png" alt="Sanitized evidence report showing ten authenticated STIG findings changed from FAILED to PASSED"></a><br><strong>Windows hardening:</strong> ten verified control transitions, with Windows checks and recovery validation. Screenshot of the local evidence report.</td>
<td width="50%" valign="top"><a href="cyber-defense/workbooks/README.md"><img src="cyber-defense/workbooks/evidence/workbook-overview.png" alt="Actual Azure workbook with synthetic authentication coverage, charts and candidate sequences"></a><br><strong>Sentinel workbook:</strong> actual deployed interface using explicitly synthetic events. Account and resource chrome excluded.</td>
</tr>
</table>

Each project includes its relevant image. See the [five-image evidence index](docs/visual-evidence.md) for the assessment overview, hunt completion and endpoint response, with provenance and limitations. The complete image set is about 0.49 MiB.

## Explore the implementation

| Component | What to inspect |
|---|---|
| PowerShell engineering | [Shared registry module](stig-remediations/RegistryControl.psm1), [example remediation](stig-remediations/WN11-CC-000010/remediate.ps1), [read-only verifier](stig-remediations/WN11-CC-000010/verify.ps1), and [control report](stig-remediations/WN11-CC-000010/report.md). |
| Tenable and evidence automation | [Scoped API client](stig-remediations/tenable_client.py), [export parser](stig-remediations/nessus_summary.py), and [before/after evidence workflow](stig-remediations/evidence-workflow.md). |
| Detection engineering | [KQL detector](cyber-defense/auth-sequence.kql), [Python reference model](cyber-defense/auth_sequence.py), and [workbook builder](cyber-defense/workbooks/build_workbook.py). |
| Investigation queries | [Query catalog](threat-hunting/module-1/README.md#query-index), including coverage checks and timeline reconstruction. |
| Deployment safeguards | [Pinned VM specification and offline preflight](deployment/README.md), including duplicate-VM prevention and preservation of the existing endpoint. |

## Validation

- **221 Python tests passed:** 213 shared tests and eight DISA source-alignment/static checks.
- **340 mocked PowerShell cases passed on each runtime:** Ubuntu PowerShell 7.6.6 and native Windows PowerShell 5.1.
- **32 PowerShell files parsed on Windows; 33 reviewed source hashes matched.**
- Actual Windows remediation and rollback, authenticated Tenable comparisons, and KQL service execution are recorded separately from local tests.

The [validation record](docs/local-validation.md) contains versions, reproduction steps, and evidence limits. Run the local Python suite and repository checks from the repository root:

```bash
python3 -B -m unittest discover -s tests -v
python3 -B tools/check_repository.py
```

These commands use the Python standard library and perform no live scans or Windows changes. DISA source checks additionally require the documented cached benchmark archive. Reviewed PowerShell source remains unchanged from its observed Windows execution.

## Evidence and scope

Reports connect technical claims to observed results, source hashes, and private evidence references. Ten selected STIG passes do not establish whole-system compliance; synthetic detector results do not establish production effectiveness. Original scan exports, forensic data, internal resource identifiers, credentials, and confidential source material remain outside Git.

AI assistance supported implementation, test design, and evidence reconciliation. The portfolio documents security engineering with human-authorized execution; it does not claim an implemented or evaluated AI security product. Independent review is recorded only for the versions and scope actually reviewed.

Use the [project status](docs/project-progress.md), [methodology](docs/methodology.md), and [engineering scope](docs/engineering-scope.md) for further detail. Live operations require authorization for the specified assets and actions. The LOG(N) Pacific and historical NCyTE projects retain separate repositories, histories, attribution, and validation.
