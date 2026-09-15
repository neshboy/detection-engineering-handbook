# Part XVII — Sigma

Sigma is a generic, YAML-based format for describing log-based detection logic in a way that is
not tied to any single SIEM query language. The pitch is simple: write the detection once, in a
structure that captures *what pattern of events matters*, and let a backend converter turn that
into SPL, KQL, ES|QL/Lucene, AQL, or whatever your platform speaks. The reality is more nuanced,
and this chapter treats Sigma as what it actually is in a working detection program: a portable
authoring and sharing format with real translation limits, not a universal query language.

[CONCEPT] Think of Sigma the way you'd think of a recipe written in generic units ("one part
flour to one part butter") instead of a recipe hardcoded to one specific oven brand's temperature
dial. The generic version is easier to share, review, and store in version control. But someone
still has to know their own oven — the actual field names, log format, and quirks of the SIEM it's
being converted for — or the translated recipe burns the cake.

## Anatomy of a Sigma Rule

A Sigma rule is YAML with a fixed set of top-level keys. The ones that matter for day-to-day
detection engineering:

| Key | Purpose | Notes |
|---|---|---|
| `title` | Short human-readable name | Shows up in every alert queue; write it for the analyst reading it at 3am, not for the author. |
| `id` | Globally unique UUID | Required for dedup across rule repos; generate once, never reuse. |
| `status` | `stable`, `test`, `experimental`, `deprecated` | Governs whether it should even fire in production — a lot of public Sigma rules are `experimental` for good reason. |
| `description` | What behaviour this catches and why | This is where you explain intent, not just repeat the title. |
| `references` | Links/citations to the source behaviour (blog, ATT&CK, incident) | Traceability — where did this idea come from. |
| `author` | Who wrote/maintains it | Accountability when it needs tuning. |
| `date` / `modified` | Authoring and last-edit dates | Rule age is a real signal — old, untouched rules against a changed environment are a tuning debt item. |
| `tags` | ATT&CK technique IDs and other taxonomy | `attack.t1059.001`, `attack.execution`, etc. |
| `logsource` | Which log type/category/product this rule expects | The single most important key for translation correctness — see below. |
| `detection` | `selection`/`filter` blocks plus a `condition` string | The actual logic. |
| `fields` | Fields to surface in the alert | Not filtering logic — just what the analyst sees first. |
| `falsepositives` | Known legitimate activity that matches | Mandatory honesty field; "unknown" is a legitimate but weak answer. |
| `level` | `informational`, `low`, `medium`, `high`, `critical` | Triage priority, not a confidence score — a `high` rule can still have real false positives. |

### `logsource` — the field everyone under-thinks

`logsource` tells the backend converter which pipeline/index/table this rule targets, using
`category` (e.g. `process_creation`, `network_connection`, `dns_query`), `product` (e.g.
`windows`, `linux`, `aws`), and sometimes `service` (e.g. `sysmon`, `auditd`, `cloudtrail`). The
converter maps this to a target-specific source (an index name in Splunk, a table in Sentinel, a
data stream in Elastic) using a **pipeline config** — and this mapping is exactly where silent
breakage happens. If your Sysmon Event ID 1 data lands in a custom index with non-default field
names, the generic `process_creation` category conversion will produce syntactically valid SPL
that queries the wrong index or references fields that don't exist in yours.

[ENGINEERING] `logsource` is a *contract*, not a guarantee. Sigma assumes a normalized field
taxonomy (the Sigma "taxonomy" project, and increasingly OCSF-aligned fields) exists between the
rule author's assumptions and your actual parsed data. If your CIM/CEF/OCSF mapping is incomplete
— which it almost always is somewhere — the rule silently degrades instead of erroring. Nothing
tells you the field it needed doesn't exist; the query just returns zero results, or matches
against a field that happens to share a name but not the same content.

### `detection` — selection, filter, and condition

The `detection` block is a dictionary of named sub-blocks (conventionally `selection*` for what
you want to match and `filter*` for what to exclude) plus a mandatory `condition` string that
combines them with boolean logic.

```yaml
detection:
  selection_process:
    Image|endswith: '\powershell.exe'
  selection_encoded:
    CommandLine|contains:
      - '-enc '
      - '-EncodedCommand'
      - ' -e '
  filter_known_tool:
    CommandLine|contains: 'C:\Program Files\ApprovedTool\wrapper.ps1'
  condition: selection_process and selection_encoded and not filter_known_tool
```

Field modifiers (`|endswith`, `|contains`, `|startswith`, `|re`, `|cased`, `|all`, `|windash` and
others) control match semantics per field. `|all` requires every listed value to match rather than
any; `|windash` normalizes Windows command-line argument prefixes (`-`, `/`, `—`) so a rule
written for `-enc` also catches `/enc`. Getting these modifiers right is a large chunk of what
separates a rule that looks correct from one that actually fires correctly — a plain string match
where you meant `|contains` misses substrings entirely in some backends' default semantics.

## Example Rule 1 — Suspicious Encoded PowerShell Command

This is one of the most commonly published Sigma rules, and one of the most commonly
mis-deployed. Below is a **CONCEPTUAL SAMPLE**, illustrative of the structure — validate field
names against your own Sysmon/EDR schema before use.

```yaml
title: Suspicious Encoded PowerShell Command Line
id: 3b1a1f2e-7c9a-4e3b-9d5a-2f6c8a9b1d34
status: test
description: >
  Detects PowerShell invoked with -EncodedCommand (or common short forms) combined with
  execution-policy bypass flags, a pattern frequently used to obfuscate a base64-encoded
  payload and avoid literal string-matching on the decoded content.
references:
  - Microsoft Learn - about_PowerShell_exe (command-line switches)
author: Detection Engineering Handbook (sample)
date: 2026-01-01
tags:
  - attack.execution
  - attack.defense-evasion
  - attack.t1059.001
  - attack.t1027
logsource:
  category: process_creation
  product: windows
detection:
  selection_image:
    Image|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'
  selection_encoded:
    CommandLine|contains|windash:
      - '-enc'
      - '-EncodedCommand'
  selection_bypass:
    CommandLine|contains:
      - '-ExecutionPolicy Bypass'
      - '-exec bypass'
      - '-nop'
  filter_rmm_tool:
    ParentImage|endswith: '\ApprovedRMMAgent.exe'
  condition: selection_image and selection_encoded and selection_bypass and not filter_rmm_tool
falsepositives:
  - Legitimate admin scripts and some configuration-management tooling (DSC, some SCCM/Intune
    script deployment paths) use -EncodedCommand deliberately to avoid quoting issues.
  - Some commercial RMM and backup agents wrap PowerShell this way by design — must be
    filtered per environment, not assumed.
level: high
fields:
  - CommandLine
  - ParentImage
  - User
  - Hashes
```

[DETECTION ENGINEER] Note what this rule does *not* try to do: decode the base64 payload itself.
That's a separate enrichment step (many SIEMs support a lookup/eval function to base64-decode
`-EncodedCommand` arguments at search time) — Sigma's job here is the trigger condition, not the
full investigation pipeline.

[ANALYST] When this fires, the actual investigative value is in decoding the payload and checking
`ParentImage` — encoded PowerShell spawned from `winword.exe`, `excel.exe`, or `wscript.exe` is a
very different case than the same command run interactively by an admin from `explorer.exe`.

[THREAT HUNTER] Attackers who know this rule exists evade it trivially: string-concatenation
obfuscation (`'-e'+'nc'`), `$Env:...`-based reconstruction, `IEX (New-Object Net.WebClient)...`
without `-EncodedCommand` at all, or dropping to `cmd.exe /c` wrapping. Hunt separately for
PowerShell processes with unusually long command lines regardless of flags, and for
`ScriptBlockLogging` (Event ID 4104) content containing `-bxor`, `FromBase64String`, or
`[Convert]::` patterns that never touch the process command line at all.

## Example Rule 2 — Password Spray Pattern (Authentication Telemetry)

Password spray detection is fundamentally a statistics problem (many accounts, few attempts each,
same source) rather than a single-event match, so this rule leans on Sigma's `correlation`-style
aggregation support (`timeframe` + `condition` with a count comparison) rather than plain
selection matching. This is a **CONCEPTUAL SAMPLE** — exact field names depend heavily on whether
the source is Windows Security 4625, Entra ID sign-in logs, or an on-prem AD FS/RADIUS source.

```yaml
title: Possible Password Spray - Many Accounts, Single Source, Low Attempt Count Each
id: 8e2d4a6f-1b3c-4d5e-9f7a-6c8b0d2e4f19
status: experimental
description: >
  Detects a single source IP generating failed authentication attempts against a
  high number of distinct user accounts within a short window, each with a low
  per-account attempt count - the classic password-spray shape, distinct from
  brute force (many attempts, one account) or normal user mistyping.
references:
  - MITRE ATT&CK T1110.003
author: Detection Engineering Handbook (sample)
date: 2026-01-01
tags:
  - attack.credential-access
  - attack.t1110.003
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
    Status: '0xC000006A'   # bad password (not locked/disabled/expired)
  timeframe: 10m
  condition: selection | count(TargetUserName) by IpAddress > 15
falsepositives:
  - Misconfigured service account or scheduled task retrying a stale/rotated
    credential against many resources from one host (looks identical in shape).
  - NAT'd office egress IP or VPN concentrator aggregating many real users'
    normal failed logins behind one source address.
  - Password-expiry events after a mass credential rotation.
level: medium
fields:
  - IpAddress
  - TargetUserName
  - Status
```

[DETECTION ENGINEER] The `count(...) by ...` aggregation syntax shown here maps to Sigma's
correlation rule extension (rules of type `correlation` referencing a base detection rule), or,
depending on your Sigma tooling version, to a `count()`-style condition inline. Not every backend
converter supports every aggregation form identically — this is exactly the kind of construct
where "converts without error" and "produces the intended `by`-grouped, windowed count" are two
different claims, and the second one needs verification against real output, not assumption.

[HUNTER'S NOTE] The single biggest false-positive source for spray rules in real environments is
NAT. A source IP threshold that works cleanly on a home-user population falls apart the moment a
large branch office, VPN concentrator, or cloud NAT gateway is the observed source for hundreds of
real users. Always check whether `IpAddress` here is the true client address or a NAT/proxy
address before trusting the "single source" framing.

[ANALYST] Triage checklist for a spray alert: is the target account list random-looking (spray) or
does it cluster around a naming pattern like a distribution list or department (targeted spray
using an enumerated user list, e.g. from a prior recon/OSINT phase)? Did any attempt succeed
(pivot immediately to that account's subsequent activity — this is now a confirmed-compromise
investigation, not a spray alert)?

## Example Rule 3 — Filtering Structure Recap (Selection + Filter + Condition)

To make the `selection`/`filter`/`condition` interplay concrete, here's a minimal, deliberately
simple rule showing suspicious use of `rundll32.exe` with no DLL export named — a known
defense-evasion / masquerading pattern — and how a `filter` block removes a specific known-good
case without weakening the base selection:

```yaml
title: Rundll32 Execution With No Function Export Specified
id: 5f9a2c31-4e8d-4b1a-8c3e-7d1f9a2b5c60
status: test
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\rundll32.exe'
    CommandLine|re: '(?i)rundll32\.exe\s*$'
  filter_patchmgmt:
    ParentImage|endswith: '\PatchMgmtAgent.exe'
  condition: selection and not filter_patchmgmt
tags:
  - attack.defense-evasion
  - attack.t1218.011
level: medium
falsepositives:
  - Some legitimate installer/uninstaller chains invoke rundll32 with no visible
    arguments briefly before self-terminating; verify against your baseline.
```

**Detection Autopsy — the naive version of this rule, and why it broke**

*Original logic (what a first draft often looks like):* `Image|endswith: '\rundll32.exe'` alone,
with `condition: selection`, and no filter block at all, `level: high`.

*Why it looked reasonable:* `rundll32.exe` genuinely is abused constantly — it's a living-off-the-
land binary used to proxy-execute arbitrary DLL code, and any single hit on it feels worth a look.

*What broke in production:* `rundll32.exe` is also one of the highest-volume legitimate process
names on any Windows fleet — Control Panel applets, print spooler operations, various vendor
installers, and Windows Update components all shell out to it constantly with completely benign
arguments. Alerting on the bare image name alone produced dozens to hundreds of daily hits per
1,000 endpoints, essentially none actionable.

*Missing context:* the useful signal isn't that `rundll32.exe` ran — it's *how* it ran: no
arguments at all (a masquerading pattern where the actual malicious DLL is loaded via a different
mechanism and the process itself is a decoy), or a suspiciously-named/unsigned DLL path, or an
unusual parent process. The original rule captured none of that.

*Revised analytic:* narrow the selection with the empty-command-line regex shown above, tag it
`medium` instead of `high` to reflect the residual ambiguity, add a `filter` for the one
identified noisy legitimate parent in the environment, and pair it (in the SIEM's correlation
layer, not inside this single rule) with a `DllExport`/module-load telemetry check where available
to confirm what actually got loaded.

*How it was tested:* run the narrowed rule retroactively over 30 days of existing
`process_creation` data before enabling it live; count matches, manually triage a sample, confirm
the filtered parent process was the dominant remaining false-positive source, and only then move
`status` from `test` to `stable`.

*Result:* daily match volume dropped by roughly two orders of magnitude in the illustrative
walkthrough above (this specific number is scenario-dependent — the point is the *method*, not a
number to copy into your own environment).

## Translating Sigma to a Real Backend

Sigma rules are converted to a target query language with a rule-to-query compiler — historically
`sigmac`, now the `pySigma` library and its backend plugins (`pySigma-backend-splunk`,
`pySigma-backend-microsoft365defender`/Sentinel, `pySigma-backend-elasticsearch`, community QRadar
AQL backends, and others), fronted by the `sigma-cli` tool for most day-to-day conversion work.

```mermaid
flowchart TD
    A[Sigma rule YAML<br/>logsource + detection] --> B[pySigma parser]
    B --> C{Pipeline config<br/>field + logsource mapping}
    C -->|Splunk pipeline| D[SPL query]
    C -->|Sentinel pipeline| E[KQL query]
    C -->|Elastic pipeline| F[ES|QL / Lucene / EQL]
    C -->|QRadar pipeline| G[AQL query]
    D --> H[Manual validation against real index/schema]
    E --> H
    F --> H
    G --> H
    H --> I{Fields exist?<br/>Semantics match?<br/>Test data confirms hits?}
    I -->|No| J[Fix pipeline config / rewrite rule]
    I -->|Yes| K[Promote to production - status: stable]
```

**Splunk (SPL).** Conversion typically targets a CIM-compliant data model (`Endpoint.Processes`,
`Authentication`, `Network_Traffic`) or a specific index/sourcetype via a pipeline config. If your
Sysmon data is onboarded through a different TA/sourcetype than the pipeline assumes, field names
like `Image` vs `process_path` vs `process_name` will not line up, and the converted `tstats`/
`search` query will run cleanly and return nothing — no error, just silence.

**Microsoft Sentinel (KQL).** The Sentinel backend generally targets `DeviceProcessEvents`
(Defender for Endpoint schema) or `SecurityEvent`/`WindowsEvent` depending on which table your
environment actually ingests into and which pipeline config is selected. A rule converted assuming
Defender's advanced hunting schema will silently mismatch if your tenant only ingests classic
Windows Security events through AMA, because the field names (`InitiatingProcessCommandLine` vs
`CommandLine`) are genuinely different vocabularies for the same concept.

**Elastic (ES|QL/EQL/Lucene).** Elastic Common Schema (ECS) is the intended normalization target,
and Elastic's own detection rules already ship largely Sigma-aligned. The risk here is usually the
opposite direction of the others: an environment with partial ECS mapping (some indices ECS-
compliant, older Beats/Logstash pipelines still using legacy field names) means the same Sigma
rule produces correct hits against new data and silent misses against old data in the same index
pattern.

**IBM QRadar (AQL).** QRadar support is the least standardized of the four — fewer maintained
community backends, and QRadar's own DSM/QID normalization layer adds another translation step
before Sigma's own field mapping even applies. Treat any QRadar-targeted Sigma conversion as a
first draft requiring hand verification of QID mappings, not a ready-to-deploy rule, more
consistently than the other three backends.

| Backend | Primary target schema | Typical breakage point |
|---|---|---|
| Splunk | CIM data models or raw index/sourcetype | TA/sourcetype field-name mismatch; CIM tag not applied to the source |
| Sentinel | Defender advanced-hunting tables or `SecurityEvent`/`WindowsEvent` | Wrong table selected for actual ingestion path (AMA vs MDE sensor) |
| Elastic | ECS fields | Partial/legacy ECS mapping across old vs new data sources |
| QRadar | QID/DSM-normalized fields via AQL | Weak community backend maturity; DSM mapping errors upstream of Sigma |

**The warning that matters more than any of the above table rows:** a Sigma rule converting
without a syntax error is not evidence that it will match anything correct. The compiler's job
ends at producing valid query syntax against the field names the pipeline config *told it* to use
— it has no way to know whether those field names actually exist in your data, whether they hold
the values you expect, or whether your parser populates them at all for a given source. Every
converted rule needs to be run against real historical data with a known-true-positive test case
(or a deliberately generated one in a lab) before it goes anywhere near a production alert queue.
"It compiled" and "it detects the behaviour" are two separate, sequential validation steps, and
skipping the second one is how detection programs end up with a rule count that looks impressive
in a slide and a real detection coverage number that is much lower.

[SOC MANAGEMENT VIEW] Sigma's actual organizational value is portability and review-ability, not
runtime performance — a rule reviewed once in a common YAML format, with `falsepositives` and
`references` fields forcing the author to document intent, is easier to audit across a team and
easier to hand off than a pile of backend-specific saved searches with no shared documentation
convention. But budget real analyst/engineer time for the validation step above per rule per
backend; treating "converted" as a synonym for "deployed" is the most common way Sigma adoption
produces a false sense of coverage. Track conversion+validation as a distinct pipeline stage in
whatever governance process tracks rule lifecycle, with its own sign-off, not as a sub-step of
authoring.

## Engineering Reality

**Engineering Reality:** Sigma's field-name assumptions are only as good as your normalization
layer, and no organization's normalization layer is complete. The honest operating model is: Sigma
rules are a starting point per backend, pipeline configs need environment-specific overrides more
often than the "just works" narrative suggests, and every rule that matters enough to page someone
needs its own validated, backend-native version checked into your actual detection repo — not a
live re-conversion trusted blindly at alert time.

## Hunt Beyond the Rule

Sigma rules, by design, express point-in-time boolean match logic. A threat hunter's job starts
where the rule's `condition` stops:

- For the encoded-PowerShell rule: pull every PowerShell process creation (not just the ones
  matching the encoded-flag pattern) over a longer window and cluster by parent process and
  command-line length/entropy, to catch the obfuscation variants that dodge the literal flag
  match.
- For the password-spray rule: don't wait for the count threshold — trend failed-auth-by-source
  over time per source IP even below the alerting threshold, since a spray tuned to stay under a
  known detection threshold (e.g. 10 accounts instead of 15) is a realistic adversary adaptation
  once they've profiled your defenses.
- For the rundll32 rule: pivot from any confirmed hit to module-load / image-load telemetry (where
  available) to identify exactly which DLL got loaded, and hunt for the same DLL hash/path across
  other hosts regardless of which parent binary invoked it.

> **[SCREENSHOT PLACEHOLDER — CONTROLLED LAB]** — Sysmon process-creation log (Event ID 1) showing
> a `powershell.exe` process with an `-EncodedCommand` argument and its `ParentImage`, captured
> from a lab Windows host, illustrating the exact `CommandLine` and `ParentImage` field values the
> Example Rule 1 selection logic and analyst triage step above depend on.

## References

- MITRE ATT&CK, technique T1059.001 (PowerShell) and T1110.003 (Password Spraying)
- MITRE ATT&CK, technique T1218.011 (Signed Binary Proxy Execution: Rundll32)
- MITRE ATT&CK, technique T1027 (Obfuscated Files or Information)
- Sigma HQ project documentation (SigmaHQ/sigma on GitHub) — rule specification and pySigma backend list
- Microsoft Learn — `about_PowerShell_exe` command-line switches reference
