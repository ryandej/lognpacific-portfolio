# Portfolio guide

[Portfolio](../README.md) · [Project status](project-progress.md) · [Validation](local-validation.md)

This repository contains selected work from my LOG(N) Pacific projects, prepared for public review. Each project page connects the problem, my implementation and the observed results to its code and supporting evidence.

## Where to start

| Interest | Project | What to look for |
|---|---|---|
| Security engineering | [Windows hardening](../stig-remediations/README.md) | Ten PowerShell implementations, target checks, separate verifiers and tested rollback. |
| Vulnerability management | [Assessment cycle](../vulnerability-management/README.md) | Authenticated baseline, prioritization, remediation and comparable follow-up results. |
| Detection engineering | [Authentication detector](../cyber-defense/README.md) | KQL logic, Python reference model, positive and negative test cases. |
| SOC analysis | [Sentinel workbook](../cyber-defense/workbooks/README.md) | Five panels built from recorded investigation results. |
| Threat hunting | [Hartwell Breach](../threat-hunting/README.md) | HTTP and host-event correlation, command analysis and incident scope. |
| Endpoint investigation | [Windows investigation](../threat-hunting/module-1/README.md) | Ten KQL queries, a combined timeline and evidence-based findings. |
| Incident response | [Defender exercise](endpoint-validation.md) | Onboarding, investigation collection, isolation and recovery. |

## Code and supporting material

- `stig-remediations/` holds the ten control packages, shared PowerShell module, Tenable API tools and evidence parser.
- `vulnerability-management/` holds assessment metrics, the program report and a policy tabletop.
- `threat-hunting/` holds the investigation reports and Windows KQL queries.
- `cyber-defense/` holds the authentication detector, reference model and workbook sources.
- `deployment/` holds the original VM specification and offline readiness checks.
- `tests/` and `tools/` hold Python regression tests and repository checks.

The [validation record](local-validation.md) identifies the tested versions and environments. The [methodology](methodology.md) covers execution, recovery and evidence handling. The [image index](visual-evidence.md) identifies application captures and locally produced summaries.

## Reading the results

The reports identify the tested asset or dataset, measured result and remaining technical questions. The authentication detector uses generated events for repeatable testing. The Sentinel investigation workbook uses saved results from historical Cyber Range telemetry. The vulnerability policy and stakeholder exercise are proposals.

Private source records support the published summaries. Credentials, raw telemetry, internal infrastructure details and restricted course material remain outside the repository.
