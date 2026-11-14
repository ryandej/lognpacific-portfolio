# HTTP-to-host incident reconstruction

[Portfolio](../README.md) · [Investigations](README.md) · [Windows investigation](module-1/README.md)

This method was applied in an authorized, completed training investigation. The private evidence contains the actual query records, timeline and platform completion receipt. This public artifact presents the original analytical approach and its limitations without disclosing challenge answers, restricted event data or attack identifiers.

## Evidence chain

| Question | Method | Claim boundary |
|---|---|---|
| Was activity reconnaissance or exploitation? | Compare access-log timing, request characteristics and errors with the normal browsing pattern. Corroborate enriched HTTP records with the web server log. | Scanner-like traffic or a warning alone does not establish execution. |
| Did the server execute an attacker-supplied command? | Correlate the request interval with process creation, web-service parentage and the effective account. Retain source event identity and timestamp. | Separate a received request from a recorded child process and its outcome. |
| What did an encoded request represent? | Decode a private copy as data, validate the transformation order and compare with observed process commands. | Never execute decoded content; a plausible decoding is weaker than corroboration. |
| Did a defense-evasion attempt work? | Distinguish a stop-command invocation from its permission outcome and later evidence that the monitoring component remained active. | A process command line proves an attempt, not that a service stopped. |
| Was access made persistent? | Correlate scheduling/configuration activity with subsequent observed execution, and evaluate storage lifetime and collection gaps. | A staged artifact, installed mechanism and executed callback are different claims. |
| Was information transferred or movement observed? | Inspect the established request/response path, relevant process activity and available authentication/network evidence. | No indication in the available scope is not proof of universal absence. |

## Provenance and coverage

Use the event's original timestamp when ingestion is delayed or replayed. Record the query hash, authorized window, source table, row count, truncation and event identifiers. Read an entire authorized small result set before drawing negative conclusions; partition larger results rather than silently accepting a row cap.

The completed investigation combined seven event sources. Some normalized network destination fields were empty, and some supporting logs started later than the main activity. The report explicitly retained those gaps instead of claiming complete packet visibility. Findings were supported by multiple sources where available; correlation alone was not described as causation.

Keep every analytical transformation reproducible. Hash the original exports and derived records separately. Preserve incorrect hypotheses and their correction in private notes, while making the final report internally consistent. Detection coverage and external scoring/acceptance are separate evidence categories.

## Safe response planning

The private report contains a proposed containment and recovery plan, not an executed response. First preserve volatile evidence within approved scope, protect affected identities, and plan minimal containment that preserves required management. Validate persistence removal and restoration using observed state and follow-up monitoring; do not assume silence proves recovery.

The [Windows investigation query package](module-1/README.md) implements analogous evidence categories for Defender. It targets a different operating system and dataset and is not claimed to be the query set used in the completed web-server exercise. The [authentication workbook](../cyber-defense/workbooks/README.md) provides a separately tested correlation and triage example.
