# Selected visual evidence

[Portfolio](../README.md) · [Validation](local-validation.md)

Five images illustrate the main projects. Together they occupy about **0.49 MiB**. Full technical records remain the source for interpreting results; a screenshot is not a substitute for assessment scope, authentication, source hashes or validation limits.

| Image | Origin and meaning |
|---|---|
| [STIG control results](../stig-remediations/evidence/control-results.png) | Screenshot of an original local evidence report: ten authenticated FAILED → PASSED comparisons, Windows checks and actual recovery validation. Built from the [assessment record](../vulnerability-management/assessment-summary.json); this is not the Tenable console. |
| [Assessment overview](../vulnerability-management/evidence/assessment-overview.png) | Screenshot of an original local report showing all 258 compliance outcomes before and after the changes. Remaining failures, errors and warnings stay visible. These are audit counts, not CVE counts or a risk-reduction percentage. |
| [Sentinel workbook](../cyber-defense/workbooks/evidence/workbook-overview.png) | Actual deployed Azure workbook showing coverage, authentication charts and candidate sequences. Its data is explicitly synthetic; the event-context panel is below the captured viewport. Portal identity chrome was excluded using temporary local presentation framing, then the original layout was restored. No workbook source or query result changed. |
| [Completed hunt](../threat-hunting/evidence/hunt-completion.png) | Actual owned completion indicator: 18/18 flags, 1,750/1,750 points, completed on time. Only the existing title and completion indicator were displayed for capture, with temporary spacing and contrast adjustments. The original page was restored. Questions, answers, raw events, topology and other participants are excluded. |
| [Endpoint response](evidence/endpoint-response.png) | Screenshot of an original local report summarizing observed onboarding, investigation collection and isolation/recovery. Based on the [execution record](endpoint-validation.md); this is not the Defender console. The limited ingestion and connectivity coverage remain explicit. |

The three local reports use already sanitized records. The two application captures preserve the actual displayed values. No image uses AI-generated pixels, invented findings or retouched result values. Original captures and rendering records remain private under `EV-PORTFOLIO-VISUALS-V22`.

The [image manifest](visual-evidence.json) records exact SHA-256 hashes, dimensions, sizes, sources and framing. Repository checks accept only these five paths and exact bytes, reject PNG metadata/extra chunks and enforce size limits. Other screenshots and source attachments remain ignored. These checks do not inspect pixel meaning; any replacement requires another visual disclosure review.
