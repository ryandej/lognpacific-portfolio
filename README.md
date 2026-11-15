# LOG(N) Pacific | AI Security Engineering

Ryan DeJong · Cybersecurity portfolio

This repository presents a selected, public-facing collection of my security engineering work with LOG(N) Pacific. Its Cyber Range is an Azure-based environment for testing defenses and investigating threats. These projects show my PowerShell and Python automation, authenticated Tenable assessments, KQL investigations, and Microsoft Sentinel and Defender work.

Start with the [Windows hardening results](docs/windows-stig-validation.md), [Sentinel workbook](cyber-defense/workbooks/README.md), or [Hartwell Breach investigation](threat-hunting/README.md).

## Selected projects

| Project | What I did | Tools and skills |
|---|---|---|
| [Windows 11 STIG automation](stig-remediations/README.md) | Built ten remediations for DISA security configuration requirements. Authenticated assessments confirmed all ten fixes. Tested verification, repeat execution and rollback. | PowerShell, Tenable, Windows hardening, automated testing |
| [Vulnerability management](vulnerability-management/README.md) | Completed an assessment cycle on one endpoint, reconciled 258 compliance results and documented the ten fixes and remaining findings. | Tenable API, Python, prioritization, compliance reporting |
| [Sentinel investigation workbook](cyber-defense/workbooks/README.md) | Deployed five panels presenting 233 recorded investigation events, source coverage and activity timing. | Microsoft Sentinel, KQL, visualization |
| [Authentication detection](cyber-defense/README.md) | Built a detector for repeated failed logons followed by success. Verified eight generated test cases in Log Analytics. | KQL, Python, detection logic, regression testing |
| [Hartwell Breach investigation](threat-hunting/README.md) | Reconstructed a web-server intrusion across seven log sources, tracing execution, credential access and persistence. Completed all 18 hunt flags on time. | Threat hunting, Linux, HTTP analysis, incident reconstruction |
| [Windows endpoint investigation](threat-hunting/module-1/README.md) | Wrote and executed ten queries covering processes, files, network activity, registry changes and accounts. Built a timeline and response proposal. | Defender telemetry, KQL, event correlation |
| [Defender endpoint response](docs/endpoint-validation.md) | Verified onboarding and process telemetry, collected an investigation package, and tested endpoint isolation and recovery. | Microsoft Defender for Endpoint, API automation, containment |

## Work in pictures

[![Ten STIG findings changed from failed to passed](stig-remediations/evidence/control-results.png)](docs/windows-stig-validation.md)

*Windows hardening results, summarized from the saved Tenable assessments and Windows checks.*

[![Microsoft Sentinel workbook showing recorded Windows investigation results](cyber-defense/workbooks/evidence/workbook-overview.png)](cyber-defense/workbooks/README.md)

*Microsoft Sentinel workbook displaying the recorded investigation. [Image sources](docs/visual-evidence.md).*

## Source code

| Area | Source |
|---|---|
| PowerShell | [Shared registry module](stig-remediations/RegistryControl.psm1), [example remediation](stig-remediations/WN11-CC-000010/remediate.ps1), [verifier](stig-remediations/WN11-CC-000010/verify.ps1), [report](stig-remediations/WN11-CC-000010/report.md). |
| Tenable automation | [Scoped API client](stig-remediations/tenable_client.py), [export parser](stig-remediations/nessus_summary.py), [evidence workflow](stig-remediations/evidence-workflow.md). |
| Detection and workbooks | [KQL detector](cyber-defense/auth-sequence.kql), [Python model](cyber-defense/auth_sequence.py), [investigation workbook builder](cyber-defense/workbooks/build_investigation.py). |
| Investigations | [Ten-query catalog](threat-hunting/module-1/README.md#query-index). |
| Deployment checks | [VM specification and offline preflight](deployment/README.md). |

## Validation

The PowerShell test harness passed 340 cases on both Ubuntu and Windows. The ten remediations also passed Windows execution, rollback and authenticated Tenable checks.

The [validation record](docs/local-validation.md) lists the Python test results, versions and remaining checks. Run the local tests from the repository root:

```bash
python3 -B -m unittest discover -s tests -v
python3 -B tools/check_repository.py
```

These commands use the Python standard library. The separate DISA checks require the cached benchmark archive described in the validation record.

See the [portfolio guide](docs/engineering-scope.md), [project status](docs/project-progress.md) and [methodology](docs/methodology.md) for more detail.
