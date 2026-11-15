# PHP2Shell: The Hartwell Breach

[Portfolio](../README.md) · [Windows investigation](module-1/README.md) · [Investigation method](investigation-method.md)

**Threat hunt report · Ryan DeJong · November 13, 2026**

[Scope](#scope-and-tools) · [Findings](#what-happened) · [Behavior mapping](#behavior-mapping) · [Recommended response](#recommended-response)

I investigated a compromised Linux web server running WordPress, following the activity from web reconnaissance through command execution, credential access, and persistence. The work used KQL against seven log sources in an authorized Cyber Range training dataset.

I connected HTTP requests to filesystem events, new web endpoints and web-server child processes. I also checked the outcome of monitoring-stop attempts and looked for movement to other systems.

**Outcome:** Reconstructed the intrusion from reconnaissance to persistence, corroborated webshell execution, and checked whether monitoring continued after the attacker tried to stop it. The completed hunt earned all 1,750 points across 18 flags and finished on time.

![Actual Hartwell hunt page showing the title, 1750 of 1750 points, 18 of 18 flags solved, and Completed on time](evidence/hunt-completion.png)

*The completed hunt shows all flags solved and completion on time. [Screenshot source](../docs/visual-evidence.md).*

## Scope and tools

| Item | Scope |
|---|---|
| Environment | One Linux/WordPress scenario host; historical training telemetry |
| Event window | October 23, 2026, 04:00–16:00 UTC, narrowed for individual questions |
| Query platform | Azure Log Analytics and Kusto Query Language (KQL) |
| Analysis | HTTP and host-event correlation, process ancestry, safe decoding, timeline reconstruction, and scope checks |
| Supporting tools | Python for checking transformations and evidence hashes |
| Response work | Recommendations only; no containment or recovery was performed on the scenario host |

### Check coverage before drawing conclusions

The scoped dataset contained 52,979 log records. Several records can describe one action.

| Source | Events | What it contributed |
|---|---:|---|
| Apache access | 2,895 | Request patterns, new URIs, and HTTP status codes |
| Apache error | 93 | PHP warnings and application-side context |
| Enriched HTTP | 458 | Request metadata and decoded command fields |
| Sysmon | 34,559 | Process creation, parent processes, and available network events |
| Linux audit | 9,786 | Filesystem activity and corroborating host evidence |
| Authentication | 382 | Available login and service-related context |
| Syslog | 4,806 | System and monitoring-related messages |

![Evidence review showing the seven source counts and their observed time coverage](evidence/hartwell-source-coverage.png)

*Screenshot of my local evidence review, built from the preserved KQL results. The bars show the first and last observed event for each source. Logging gaps can fall between them.*

Authentication and Syslog records started after the main command window. Some normalized network fields were empty. Those gaps mattered when assessing what I could reasonably rule out.

This is a shortened version of the coverage query. The time parameters are deliberately empty; they must be set for an authorized dataset before use. It omits the original query's `TimeGenerated` comparisons because those values do not establish ingestion time.

```kusto
let Begin = datetime(null);
let End = datetime(null);
union withsource=SourceTable
    HartwellApache_CL, HartwellApacheError_CL,
    HartwellHTTPEnriched_CL, HartwellSysmon_CL,
    HartwellAudit_CL, HartwellAuth_CL, HartwellSyslog_CL
| where isnotnull(Begin) and isnotnull(End)
| where OriginalTime between (Begin .. End)
| summarize Events=count(),
            FirstEvent=min(OriginalTime),
            LastEvent=max(OriginalTime) by SourceTable
| order by FirstEvent asc
```

## What happened

The sequence combines several sources. An apparent time offset between application errors and HTTP records remains unresolved.

| Stage | Evidence I followed | Conclusion |
|---|---|---|
| Reconnaissance | Repeated probes, request volume, and scanner-identifying user-agent records | The traffic included deliberate reconnaissance. |
| Exploitation and foothold | Upload-related request characteristics, PHP warnings, audit filesystem events, and a newly requested PHP endpoint | Multiple sources supported the transition from probing to a webshell. A warning alone did not prove the exploit mechanism. |
| Remote command execution | Apache-parented processes and enriched HTTP command metadata | The attacker obtained command execution in the web-service account's context. |
| Discovery and credential access | Host/network discovery commands, monitoring enumeration, configuration reads, and SQL query metadata | The attacker investigated the host and accessed application/database credential material. Exact returned contents were not collected. |
| Attempted monitoring disruption | Service-stop commands followed by continuing process, audit, and monitoring-related activity | Monitoring activity continued after the stop attempts. |
| Persistence and scope | Scheduling commands, a staged implant, HTTP responses, and scoped process/command checks | Commands to establish persistence were observed. The available command records did not establish lateral movement. |

### 1. Connect the web activity to execution

I started with access-log patterns, then used application errors and enriched HTTP records to narrow the suspicious requests. The important step was corroboration: Linux audit events supported a new file in the web root, later access logs showed requests to that endpoint, and Sysmon recorded child processes associated with the web server.

Together, those events supported successful command execution. The available evidence did not identify a specific CVE.

For process triage, I grouped executable and parent-process pairs before inspecting a smaller set of command records. This excerpt follows the same approach; the account and time bounds are withheld parameters. The shortened queries in this report were not rerun against the service.

```kusto
let Begin = datetime(null);
let End = datetime(null);
let WebAccount = "";
HartwellSysmon_CL
| where isnotnull(Begin) and isnotnull(End) and isnotempty(WebAccount)
| where OriginalTime between (Begin .. End)
| where toint(EventID) == 1 and User == WebAccount
| summarize ProcessEvents=count(),
            FirstSeen=min(OriginalTime),
            LastSeen=max(OriginalTime) by Image, ParentImage
| order by ProcessEvents desc
```

### 2. Verify the hidden command channel

Standard access logs did not provide the full command context. Enriched HTTP records exposed the additional request metadata needed to understand how the webshell was operated.

I compared four encoded command samples with their decoded equivalents. Reapplying the candidate transformations reproduced all four encoded values exactly; changing the order did not match. I then compared the decoded activity with host-process evidence. No decoded command was executed during the analysis.

All four samples matched the tested encoding order. Other encoded requests still need individual checks. The custom header, payload names and exact flag values remain private.

### 3. Follow discovery and credential access

Process records showed the attacker inspecting network configuration, neighboring systems, listening services, and the monitoring stack. Later activity accessed application configuration and queried user records in the database.

I retained the query structure and relevant table/column metadata without collecting password or hash values. Configuration and database reads lined up with webshell requests and responses. Response metadata supported data returning over the existing webshell channel, but the response bodies were not retrieved. Early HTTP errors were not counted as successful extraction, and I did not claim a confirmed number of stolen records.

### 4. Test whether the monitoring disruption worked

The attacker tried to stop monitoring services. A stop command in a process log only establishes an attempt, so I checked what happened afterward.

The follow-up window contained **608 Sysmon events** and **385 audit events**. Seven forwarder-related process events were included in the Sysmon count. That continued activity supported the conclusion that monitoring was not persistently silenced.

The available records did not include every command's exit code or output. The web-service account's limited privileges provided context, but continued telemetry was the observable basis for the outcome assessment. Short gaps in monitoring were not ruled out.

### 5. Assess persistence and incident scope

Scheduling commands and a staged implant showed an attempt to maintain access. The staging location is normally backed by volatile storage, making collection before restart a priority. Mount configuration, swap, implant contents and later scheduled execution were not inspected.

For lateral movement, I reviewed **71 web-account process-creation records** and **45 decoded webshell commands** in the narrowed window. The scoped checks found no remote-login tools, explicit remote database host options in the process records, or references to additional internal destinations in those reviewed commands.

![Evidence review showing monitoring continuation, four encoding checks, and the limits of the lateral-movement assessment](evidence/hartwell-analysis-checks.png)

*Screenshot of the local review of saved query results. The network evidence gaps are recorded below.*

I found no evidence of lateral movement in the reviewed records. Missing destination, port and initiation fields limited the network assessment.

## Behavior mapping

These ATT&CK mappings describe the observed behavior. The assessment column records whether an attempt or outcome was supported.

| Behavior | ATT&CK reference | Assessment |
|---|---|---|
| Webshell-based access | [T1505.003: Web Shell](https://attack.mitre.org/techniques/T1505/003/) | Corroborated by web, filesystem, and process records. |
| Access to credential-bearing configuration | [T1552.001: Credentials In Files](https://attack.mitre.org/techniques/T1552/001/) | File/query activity observed; secret values excluded from collection and publication. |
| Attempts to disable monitoring | [T1685: Disable or Modify Tools](https://attack.mitre.org/techniques/T1685/) | Attempt observed; subsequent monitoring activity remained visible. |
| Recurring execution mechanism | [T1053: Scheduled Task/Job](https://attack.mitre.org/techniques/T1053/) | Installation command observed; later scheduled execution was not verified. |
| Data returned through the command channel | [T1041: Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/) | Supported channel interpretation; response contents and total data loss were not independently established. |

## Recommended response

The response team should consider these actions after authorization:

1. Preserve volatile host evidence, relevant logs, and the web application state before restarting or rebuilding the server.
2. Contain the compromised web service while preserving an approved recovery path. Investigate and correct the entry point before returning it to service.
3. Rotate exposed application/database credentials and assess affected user accounts. Use the retained evidence to establish which data was exposed.
4. Remove the webshell and persistence, verify monitoring health, and validate recovery from a trusted state.
5. Expand the scope with usable network and authentication evidence. Review other assets only with explicit authorization.

Detection improvements would focus on web-server processes spawning shells, new executable content under the web root, monitoring-service stop attempts, and unexpected scheduled execution. Correlating those behaviors with HTTP activity is more useful than depending on one payload filename or attacker-controlled header.

## Lessons and evidence

Checking coverage first helped direct the investigation. I used host events to confirm execution and later telemetry to assess the monitoring-stop attempts. Missing network fields left part of the incident scope unresolved.

The [sanitized evidence summary](investigation-summary.json) records the counts used here. Private records retain the executed queries, source results, timestamps, and integrity manifests; **34 hunt evidence files were rechecked against their saved hashes** while preparing this report. The hashes confirm that the retained files are unchanged. Coverage still depends on the original collection.

Screenshots include one actual application capture and two clearly labeled local analysis views. No result values were invented or changed. Private addresses, credentials, exact challenge answers, raw commands, and participant scoreboard information are excluded. [Capture details and image hashes](../docs/visual-evidence.md).

For related work, see the [separate Windows investigation](module-1/README.md), [reusable investigation method](investigation-method.md), and [authentication detection and Sentinel workbook](../cyber-defense/README.md). Each has its own source data and results.
