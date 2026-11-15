# HTTP-to-host incident reconstruction

[Portfolio](../README.md) · [Investigations](README.md) · [Windows investigation](module-1/README.md)

I used this method in the completed Hartwell investigation. The private record contains the executed queries, timeline and completion receipt. The public report describes the analysis and its limits.

## Evidence chain

| Question | Method | Claim boundary |
|---|---|---|
| Was activity reconnaissance or exploitation? | Compare access-log timing, request characteristics and errors with the normal browsing pattern. Corroborate enriched HTTP records with the web server log. | Scanner-like traffic or a warning alone does not establish execution. |
| Did the server execute an attacker-supplied command? | Correlate the request interval with process creation, web-service parentage and the effective account. Retain source event identity and timestamp. | Separate a received request from a recorded child process and its outcome. |
| What did an encoded request represent? | Decode a private copy as data, validate the transformation order and compare with observed process commands. | Never execute decoded content; a plausible decoding is weaker than corroboration. |
| Did a defense-evasion attempt work? | Distinguish a stop-command invocation from its permission outcome and later evidence that the monitoring component remained active. | Check service state, command outcomes and later telemetry to determine whether a stop succeeded. |
| Was access made persistent? | Correlate scheduling/configuration activity with subsequent observed execution, and evaluate storage lifetime and collection gaps. | A staged artifact, installed mechanism and executed callback are different claims. |
| Was information transferred or movement observed? | Inspect the established request/response path, relevant process activity and available authentication/network evidence. | State the collection scope and gaps when reporting no observed movement. |

## Provenance and coverage

Use the event's original timestamp when ingestion is delayed or replayed. Record the query hash, authorized window, source table, row count, truncation and event identifiers. Read an entire authorized small result set before drawing negative conclusions; partition larger results so each response fits within the row limit.

The investigation combined seven sources. Some network destination fields were empty and supporting logs began late. Those gaps limited the conclusions. I used multiple sources where available to check each finding.

Keep every analytical transformation reproducible. Hash the original exports and derived records separately. Preserve incorrect hypotheses and their correction in private notes, while making the final report internally consistent. Detection coverage and external scoring/acceptance are separate evidence categories.

## Safe response planning

The private report proposes containment and recovery. Execution requires separate authorization. First preserve volatile evidence within approved scope, protect affected identities, and plan minimal containment that preserves required management. Validate persistence removal and restoration using observed state and follow-up monitoring; do not assume silence proves recovery.

The [Windows investigation](module-1/README.md) applies similar analysis to Defender telemetry from a separate dataset. Its [workbook](../cyber-defense/workbooks/README.md) presents the saved query results.
