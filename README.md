# LOG(N) Pacific | AI Security Engineering

This portfolio presents my work as an AI Security Engineer at LOG(N) Pacific. Its technical focus is Cyber Defense, Vulnerability Management, Threat Detection, Security Automation, and original AI security engineering supported by actual implementation and evidence.

## Engineering objectives

- Develop original Windows 11 STIG remediations in PowerShell, with reproducible local checks and before/after Tenable compliance validation.
- Investigate authorized telemetry with Microsoft Defender, Microsoft Sentinel, and KQL; document findings, query behavior, and detection limitations.
- Build security automation with explicit scope, predictable failure handling, meaningful tests, and auditable results.
- Develop AI security experiments when their scope, data, and evaluation criteria are defined. Record observed performance, failure cases, and independent review.

## Project status

The repository currently contains documentation and operating guidance and is private. No remediation, detection pipeline, automation, AI system, or security-control outcome is established as implemented or validated by these files. The [project tracker](docs/project-progress.md) records planned work separately from tested, verified, and independently reviewed results.

## Technical work and documentation

| Area | Intended artifacts |
|---|---|
| Vulnerability Management | Original remediation and verification scripts, control-specific tests, Tenable comparisons, and technical reports. |
| Cyber Defense and Threat Detection | Original KQL, synthetic query tests where useful, investigation timelines, findings, and evidence-based response recommendations. |
| Security Automation | Scoped utilities or reusable components added when an actual workflow warrants them, with tests and documented failure behavior. |
| AI Security Engineering | Original implementations and reproducible evaluations using authorized or synthetic data; proposed studies are not reported as results. |

Keep implementations, tests, reports, and reviewed evidence together by work item. Add directories only when artifacts exist.

- [Engineering scope](docs/engineering-scope.md): intended deliverables, operating constraints, and unresolved dependencies.
- [Methodology](docs/methodology.md): STIG and hunting workflows, security validation, independent review, and evidence handling.
- [Project progress](docs/project-progress.md): implementation, test, validation, and review status.

## Methodology and evidence

Confirm authorization, establish a baseline, implement a scoped change or investigation, test it, and validate with the appropriate security platform. Reports must connect claims to observed results and state limitations. Codex supports approved development; Claude provides independent technical and security review. The human operator verifies results and approves Git activity.

Local tests, platform validation, and independent review are recorded separately. Training exercises and synthetic results retain their original context. Raw evidence stays in approved private storage; only cleared, sanitized derivatives may accompany reports.

## Operating boundaries

Use the same participant-owned VM throughout the project. Do not create a second VM or delete/recreate it as a routine transition. Shared service visibility does not authorize access to other participants' resources or data. Cloud operations, scans, configuration changes, and exposure exercises require explicit authorization.

Keep credentials, sensitive tenant information, raw telemetry, confidential instructional material, and instructor solutions out of Git. `Planning/` remains local-only and ignored. Publication requires LOG(N) permission and human disclosure review; private visibility does not authorize uploading confidential material.

## Separate project histories

Historical NCyTE work remains in its own repository and history. Approved original LOG(N) Pacific code and methods may later inform a separate NCyTE-aligned engineering project with new validation, dates, and attribution. Do not transfer confidential range evidence or represent this work as a historical NCyTE accomplishment.
