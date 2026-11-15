# Engineering scope

[Portfolio](../README.md) · [Project status](project-progress.md) · [Validation](local-validation.md)

This portfolio covers Windows hardening, vulnerability management, threat investigation, detection engineering and security automation. Work items need a defined scope, reproducible source and observed results.

## Deliverables

| Area | Deliverables | Validation |
|---|---|---|
| Windows STIGs | PowerShell remediations, separate verifiers, recovery, tests and control reports. | Applicable benchmark, failing baseline, Windows checks and comparable Tenable follow-up. |
| Vulnerability management | Assessment scope, prioritization, remediation plan, results and remaining findings. | Authentication, coverage, exact revisions and retained exports. |
| Threat detection | KQL, a reference model, test cases and investigation workbooks. | Query execution, data coverage, positive and negative cases, false positives and limitations. |
| Cyber Defense | Investigations, incident timelines and response plans. | Source events, collection limits and evidence of any authorized response. |
| Security automation | Tools for scoped collection, parsing, comparison and testing. | Repeatable execution, safe failure handling and tests of input boundaries. |
| AI security engineering | Future experiments with a defined threat model and evaluation. | Approved data, baseline, held-out cases, measured results and review. |

## Repository layout

- `stig-remediations/`: ten control packages, shared PowerShell, Tenable tools and evidence workflow.
- `threat-hunting/`: the Hartwell report and Windows investigation queries.
- `cyber-defense/`: authentication detector, reference model and workbooks.
- `vulnerability-management/`: assessment report, policy proposal, tabletop and metrics.
- `deployment/`: pinned VM specification and offline preflight.
- `tests/` and `tools/`: regression tests and repository checks.

Add directories when they hold useful work. Keep confidential source material, raw evidence and administrative records in approved private storage.

## Operating constraints

Use the same owned VM throughout the project. Preserve management access, Defender, telemetry and scanning capability. Shared infrastructure and other participants' devices require separate scope.

Obtain approval for cloud changes, scans, installations, identity changes, exposure and response actions. Check effective permissions before proceeding. An exposed honeypot would need a separate plan covering monitoring, duration, containment and recovery.

Keep credentials, raw logs, resource identifiers and confidential course material out of Git. Review each proposed publication. NCyTE remains a separate project with its own history, attribution and validation.

## Dependencies

| Area | Current position |
|---|---|
| VM and access | One Windows 11 VM on the assigned subnet, no public IP. Bastion and Run Command work. Shared NSG inspection was denied. Preserve the VM. |
| Assessment | Authenticated baseline and follow-up completed for the ten controls. Temporary scanning prerequisites were restored; another assessment needs an approved window. |
| Lifecycle | Shutdown, inactivity-purge and client-licensing questions remain with the range administrator. |
| Telemetry | Historical investigation queries succeeded. The owned endpoint is onboarded and a process event was observed centrally. Broader ingestion and live detector performance need testing. |
| Workbooks | The current workbook displays saved investigation counts. Authentication fixtures remain available for regression tests. |
| Further controls | Select from actual findings after reviewing applicability and dependencies. |
| AI experiments | No AI security system has been implemented or evaluated. Select a question and evaluation plan before development. |
| Review and publication | Record the reviewed version, findings and publication permission. Preserve operator waivers separately. |

See [methodology](methodology.md) for the execution and evidence workflow.
