# Part XL — SIEM Migration

## The lie in "we're just moving platforms"

[CONCEPT] Every SIEM migration is sold internally as a lift-and-shift: same detections, same
coverage, new platform, ideally invisible to the SOC except for a login-page change. That framing
is wrong in a way that causes real coverage gaps, and it's wrong for a specific reason — a
detection rule on the old platform is not one thing, it's three things bolted together:

1. A **threat hypothesis** — the behaviour someone decided was worth alerting on.
2. **Query syntax** — the specific implementation of that hypothesis in QRadar AQL, Splunk SPL,
   Chronicle YARA-L, Sentinel KQL, or Elastic EQL/KQL.
3. **Platform-specific plumbing** — field names from that vendor's parser/CIM/schema, lookup
   tables, macros, correlation windows expressed in that engine's scheduling model, suppression
   logic, and whatever exceptions got bolted on over eighteen months of tuning tickets.

Migration projects fail when someone treats #2 as the whole rule and pipes it through a syntax
translator (official or improvised) without ever reconstructing #1. You get a query that runs
without error on the new platform and alerts on almost nothing, or alerts on everything, because
the translated syntax quietly dropped a join, a `bystring` grouping, a lookup-table exclusion, or
a "last 14 days" baseline that had no direct equivalent — and nobody go back and asked what the
rule was actually *for*.

[MANAGEMENT] This is the part of a migration that budgets and timelines consistently miss. Vendors
and integrators price "rule migration" as a mechanical conversion task — X rules, Y dollars per
rule, Z weeks. Extracting and validating the underlying logic for a few hundred rules, several
dozen of which nobody currently on the team wrote or fully understands, is not mechanical. It's
detection engineering work, done backwards, under time pressure, usually during a period when the
old platform is also being decommissioned out from under you.

**Engineering Reality:** the moment a syntax-translation tool ships a converted rule that
"compiles" on the new platform, someone on the project will mark that rule done. Whether it fires
on the right things, at the right rate, is a separate question that a migration project plan
often doesn't have a line item for. Build that line item in explicitly, or it won't happen.

## Why literal translation fails: a worked comparison

Take a moderately common QRadar rule: alert when a single source IP fails authentication against
five or more distinct usernames within 10 minutes, excluding known VPN concentrators and excluding
service accounts, and only where at least one of the usernames later succeeds (credential
stuffing / password spraying pattern with a hit).

```
-- CONCEPTUAL SAMPLE, illustrative QRadar-style AQL, not guaranteed to run unmodified
SELECT sourceip, UNIQUECOUNT(username) AS distinct_users, username, eventname
FROM events
WHERE eventname ILIKE '%authentication failure%'
  AND sourceip NOT IN (SELECT ip FROM reference_set('vpn_concentrators'))
  AND username NOT IN (SELECT user FROM reference_set('service_accounts'))
GROUP BY sourceip
HAVING UNIQUECOUNT(username) >= 5
LAST 10 MINUTES
```

A syntax-literal port to Sentinel KQL might look like this if someone just maps table/field names
across:

```kql
// CONCEPTUAL SAMPLE — naive literal translation, DO NOT USE AS-IS
SigninLogs
| where ResultType != "0"
| where IPAddress !in (VpnConcentrators)
| where UserPrincipalName !in (ServiceAccounts)
| summarize DistinctUsers = dcount(UserPrincipalName) by IPAddress, bin(TimeGenerated, 10m)
| where DistinctUsers >= 5
```

This *looks* like a correct port and it will run. But it silently dropped the "at least one
later succeeded" condition — which in the original rule was the single biggest false-positive
filter, because failed-auth bursts from misconfigured mobile devices, expired-password loops, and
scanners are extremely common and mostly harmless. Without the success-after-failure clause, this
Sentinel version will page the SOC constantly in week one, someone will disable it by day three,
and the org will have a documented gap in credential-stuffing detection with nobody aware of it
until an incident review asks "didn't we have a rule for this?"

This is the core teaching point of this chapter: **the extraction step has to happen before the
rewrite step, and it has to be written down, not held in someone's head.**

## The extraction framework

[DETECTION ENGINEER] Before touching new-platform syntax, pull every legacy rule apart into this
structure. It doesn't matter whether you do this in a spreadsheet, a wiki table, or YAML files
committed alongside the detection-as-code repo (the last option is the one that survives — see
Part XVI). What matters is that every field below gets an answer, and "unknown, ask the original
author" is written down explicitly rather than silently left blank.

| Field | What you're extracting | Why literal translation loses it |
|---|---|---|
| **Threat hypothesis** | One sentence: what adversary behaviour is this rule trying to catch? | Old rule names/comments are often stale ("Failed Logon Rule") and don't say why thresholds are what they are |
| **Required fields** | The minimum set of fields the logic actually needs (source identity, target identity, action, result, timestamp, at minimum) | New platform's parser may name/type/normalize these differently, or not populate them at all for some log sources |
| **Sequence** | Is this a single event, an ordered sequence (A then B then C), or an unordered set within a window? | Sequence logic (QRadar rule chaining, SPL `transaction`, Sentinel `join` with time bounds) has no common syntax across platforms — each engine expresses "A before B" differently |
| **Threshold / cardinality** | Count of events, count of distinct values (`dcount`/`UNIQUECOUNT`), or a rate | Distinct-count vs. raw-count is easy to flip by accident during translation and changes rule behaviour completely |
| **Time window** | Sliding vs. tumbling/bucketed window, and its length | QRadar/Splunk correlation windows and Sentinel's `bin()` bucketing are not equivalent — bucketing can miss a burst that spans a bucket boundary |
| **Entities** | What gets grouped by / what identifies "one occurrence" — host, user, source IP, session ID | Grouping key choice determines whether the alert reads as one incident or fragments into many (see the QRadar offense-grouping trap above) |
| **Exceptions / suppressions** | Reference lists, allow-lists, "except when X," known-noisy source exclusions | These live in reference sets, lookup tables, or macros that frequently do NOT get exported/migrated at all — they're the single most commonly lost piece of logic |
| **Positive confirmation logic** | Any "and it actually succeeded / had impact" clause (like the auth-success-after-failure example above) | These are exactly the tuning fixes added after a false-positive storm; they're invisible unless someone remembers the incident that caused them |
| **Current tuning state** | Is this rule currently enabled, disabled, in "log only" mode, muted for a known-noisy source? | Migrating a rule nobody currently trusts, without carrying that context, wastes tuning effort rebuilding trust in something that should probably be redesigned instead |

```mermaid
flowchart LR
    A[Legacy rule: QRadar AQL / SPL / YARA-L] --> B[Extraction pass]
    B --> C[Threat hypothesis]
    B --> D[Required fields]
    B --> E[Sequence & logic shape]
    B --> F[Threshold / cardinality]
    B --> G[Time window]
    B --> H[Entities / grouping key]
    B --> I[Exceptions & suppressions]
    C & D & E & F & G & H & I --> J[Platform-neutral detection spec\n(written down, versioned)]
    J --> K[Field-mapping check against\nnew platform's schema/parser]
    K --> L{Required fields present\nand reliably populated?}
    L -- no --> M[Flag as gap: cannot migrate as-is,\nneeds new telemetry source or redesign]
    L -- yes --> N[Rewrite native query in\ntarget query language]
    N --> O[Test against replayed/live traffic\non new platform]
    O --> P{Matches expected\nfire rate and cases?}
    P -- no --> Q[Tune: adjust threshold/window/\nexceptions on NEW platform's own terms]
    P -- yes --> R[Ship, monitor fire rate\nfor first tuning cycle]
    Q --> O
```

**Hunter's Note:** the extraction pass is also the best threat-hunting opportunity most teams get
in a decade. You're forced to re-read every detection rule your org has and ask "does this still
make sense." Half the value of a migration is deleting rules that encode a threat model from 2019,
not porting them forward.

## Worked example: Splunk → Elastic, a lateral movement rule

Take a Splunk SPL detection for suspicious use of PsExec-style remote service creation followed by
a new process on the target within a short window (a classic lateral-movement pairing: SMB/RPC
service install on the destination, then a child process spawned by the service host).

```spl
-- CONCEPTUAL SAMPLE, illustrative SPL, not guaranteed to run unmodified
index=wineventlog EventCode=7045 ServiceFileName="*\\PSEXESVC*"
| rename ComputerName as dest
| join dest [
    search index=sysmon EventCode=1 ParentImage="*\\services.exe"
    | rename ComputerName as dest
    | fields dest, Image, CommandLine, _time
  ]
| where (_time - _time) < 120
| stats count by dest, Image, CommandLine
```

**Extraction:**

- **Threat hypothesis:** remote service-based execution (PsExec / PsExec-alikes) followed by a
  process spawned under `services.exe`, consistent with lateral movement via SMB admin shares
  (maps to MITRE ATT&CK **T1021.002** — Remote Services: SMB/Windows Admin Shares, and **T1569.002**
  — System Services: Service Execution).
- **Required fields:** destination host, service file name (7045), parent image (services.exe),
  child image, command line, timestamps on both sides of the pair.
- **Sequence:** ordered — service creation event, then a process-creation event on the same host,
  within a bounded window. This is a **join**, not a simple aggregation, and that's exactly the
  part a naive translation is most likely to flatten into an unordered `OR`.
- **Threshold:** none — this fires on presence of the pair, not a count. (Worth flagging: no
  volume threshold means this rule is inherently higher-noise per event and depends entirely on
  the specificity of the service-name match.)
- **Time window:** 120 seconds between service install and child process — deliberately tight to
  catch the actual PsExec handoff rather than unrelated services.exe children hours later.
- **Entities:** grouped by destination host; the interesting output is the pairing of service name
  + resulting process, not a count of hosts.
- **Exceptions:** (check the original rule's comments/history — commonly, an allow-list for
  legitimate remote-admin tooling that also uses PSEXESVC-style naming, e.g. sanctioned RMM tools,
  or an exclusion for a specific patch-management service account.)
- **Missing-data risk:** Event ID 7045 requires the System log and Sysmon Event ID 1 requires
  Sysmon deployed and its config not filtering `services.exe` children — both need to be verified
  present on the *new* platform's ingested sources, not assumed identical to the old pipeline.

Rebuilt on Elastic (EQL, which is well suited to exactly this kind of ordered-sequence logic):

```eql
// CONCEPTUAL SAMPLE — illustrative EQL sequence, verify field names against your own ECS mapping
sequence by host.name with maxspan=2m
  [any where event.code == "7045" and file.name : "*PSEXESVC*"]
  [process where event.code == "1" and process.parent.name : "services.exe"
     and not user.name in ("svc-patchmgmt")]
```

Note what changed and what didn't: the *hypothesis*, *entities* (host), and *window* (2 minutes)
carried over unchanged because they were extracted, not guessed at from the SPL syntax. The
*mechanism* changed completely — Splunk's `join` became EQL's native `sequence`, which is a better
fit for ordered pairs than either platform's join primitive really is for the other. A literal
syntax mapper would have tried to force an Elastic `JOIN`-like construct (a much weaker, less
native fit) instead of recognizing that the underlying logic is a textbook sequence query.

**Detection Autopsy**

*Original logic:* the naive first-draft port of this rule (produced by a syntax-conversion tool
during an actual migration crunch) mapped the Splunk `join` to two separate Elastic rules — one
alerting on 7045 events matching the service name, one alerting on Sysmon EID 1 children of
`services.exe` — on the theory that "we'll correlate them in the SOAR layer later."

*Why it looked reasonable:* both halves individually "worked" — each fired on real events, each
passed its own unit test, and the migration tracker marked both rules green.

*What broke in production:* the service-creation half fired on every legitimate PsExec-based
patch deployment across roughly 40 servers a night, with no pairing logic to suppress it, because
the "later correlate in SOAR" step was never actually built. Analysts muted the rule inside nine
days.

*False positives:* massive — any legitimate remote administration using a PsExec-style service
name.

*False negatives:* also present — the Sysmon-only half, running alone, fired on `services.exe`
children from routine Windows service activity unrelated to remote execution at all, and was
muted even faster, meaning the *actual* lateral-movement pairing had zero coverage once both
halves were disabled.

*Missing context:* the pairing — the entire point of the original rule — never survived the port,
because nobody extracted "this is a sequence, not two independent conditions" before rewriting.

*Revised analytic:* the EQL `sequence` query above, rebuilt from the extraction table, restoring
the ordered pairing and the tight 2-minute window.

*How it was tested:* replayed a captured PsExec lateral-movement sequence from a lab (service
install + child process) through the Elastic pipeline, confirmed a single match; separately
generated 40+ nights of legitimate patch-deployment traffic with the same service name to confirm
it did not fire outside the paired window (i.e., service install with no qualifying child process
inside 2 minutes produces no alert).

*Result:* single correlated alert per genuine pairing, patch-management noise suppressed by the
window and account exclusion, coverage for the technique restored instead of quietly dropped.

## Field mapping is its own project, not a side effect of query rewriting

[ENGINEERING] Every SIEM has its own normalization layer — QRadar's QID/DSM mapping, Splunk's CIM
and source-typing, Chronicle's UDM, Sentinel/Microsoft's schema tables and (increasingly) ASIM,
Elastic's ECS. A field called `sourceip` in one platform is not guaranteed to be populated by the
same parsing logic, from the same raw log line, as `SourceIP` or `source.ip` on another. Concretely:

- A field might exist on both platforms but be populated by different parser logic — one extracts
  it from a structured JSON field, another regexes it out of free text, and edge cases (IPv6,
  proxied addresses, multi-value fields) land differently.
- A field might exist on the old platform only because of a custom property someone built with a
  regex against raw payload, which has no equivalent unless someone rebuilds that same extraction
  on the new platform's ingest pipeline.
- A field might not be collected at all on the new platform's connector/table for that log source
  yet — migrations often change *how* logs get to the SIEM (agent-based collection changing to
  cloud-native connectors, syslog forwarding changing to an API pull), and that can change field
  coverage even when the underlying source system didn't change.

**Engineering Reality:** run a field-coverage audit before rewriting a single query. For every
field in your extraction table's "required fields" column, confirm it is populated, at expected
volume, for the actual log sources in scope, on the new platform, using real ingested data — not
vendor documentation, which describes the schema's intent, not your specific parser's behaviour
against your specific log sources.

## Sequence and time-window logic across platforms

This is where migrations lose the most fidelity, because every platform expresses "ordered events
within a window" differently, and none of them map onto each other cleanly:

| Platform | Native mechanism for ordered/windowed logic | Key behaviour to check |
|---|---|---|
| QRadar | Rule chaining ("when an event matches rule X, then within N minutes an event matches rule Y") | Whether chaining preserves entity binding (same user/host) across the chain or just time-boxes it |
| Splunk | `transaction` command, or `join`/`stats` with time bucketing | `transaction` is sequence-aware but expensive at scale; `stats`-based approximations lose order |
| Chronicle | YARA-L multi-event rules with `match` variables across events | Whether variable binding correctly scopes to the same entity across event blocks |
| Sentinel | KQL `join` with time-bound filters, or `bin()`-bucketed `summarize` | `bin()` bucketing can split a real sequence across a bucket boundary and miss it — use explicit time-delta joins for anything window-sensitive |
| Elastic | EQL `sequence`, or correlation rules | `maxspan` is the direct window equivalent; `sequence by` sets the entity-binding key |

If the legacy rule's sequence logic doesn't map cleanly, don't force a bad fit — flag it in the
extraction spec as "requires native sequence support" and pick the platform's actual sequencing
primitive rather than approximating with aggregation, which is the single most common source of
migrated rules that quietly stop catching ordered attack chains while still technically "working."

## Testing a migrated rule before it goes live

[DETECTION ENGINEER] A migrated rule needs the same validation discipline as a newly authored one
(see the testing approaches in Part XVI), plus one extra check specific to migration: **fire-rate
parity**. Before cutover, run the new rule in shadow/log-only mode against live traffic for a
comparable time period as the old rule, and compare:

- Total fire count over the same window (old platform vs. new, same underlying log sources).
- Overlap: do the two rules fire on the *same* underlying events, identified by a stable key like
  event ID + timestamp + host, or are they catching different populations entirely?
- Any known true positives from the old platform's history (past incidents, red-team exercises)
  — replay or confirm the new rule would have caught them.

[THREAT HUNTER] Where you have historical incident data or red-team/purple-team exercise logs,
treat the migrated rule the same way you'd validate a brand-new hypothesis: hunt for the
technique manually on the new platform first, confirm the behaviour is visible in the new
telemetry at all, then confirm the rule catches what the manual hunt found. If the manual hunt
can't find the behaviour in the new platform's data, the rule migration was never the real
problem — the telemetry pipeline is.

> **[SCREENSHOT PLACEHOLDER — CONTROLLED LAB]** — side-by-side shadow-mode fire-count comparison
  from a real migration test, captured from a Sysmon process-creation log source ingested in
  parallel into both an old and new SIEM stack in a lab environment, illustrating the
  overlap/divergence check described above (same underlying events, different match counts).

## Governance during the migration window

[MANAGEMENT] For the period both platforms are live (and it will run longer than planned — dual
running always does), decide explicitly and document:

- **Coverage source of truth:** which platform is authoritative for each rule during cutover, so
  an incident isn't missed because both teams assumed the other platform "has it now."
- **Rule inventory reconciliation:** a signed-off mapping of every legacy rule to exactly one of:
  migrated-and-validated, migrated-and-tuning, intentionally retired (with the reason recorded),
  or deferred (with an owner and date). "We'll get to it after go-live" rules are the ones that
  quietly vanish.
- **Analyst dual-training cost:** SOC analysts working both platforms during overlap have measurably
  slower triage — budget for it in staffing, don't treat it as absorbable overhead.
- **Decommission trigger:** the condition that has to be true before the old platform is switched
  off (not a date — a coverage confirmation), because "the license renewal is due" is not a
  detection-engineering reason to lose coverage.

**SOC Management View:** the fastest way to turn a migration into a headline incident is to
decommission the old SIEM on a licensing deadline while a chunk of the rule inventory still sits
in "deferred." Track migration status as a coverage metric reported alongside normal detection
coverage metrics, not as a separate IT project status that only project management sees.

## Summary checklist

- Extract before you translate: hypothesis, required fields, sequence, threshold, window,
  entities, exceptions — written down, for every rule in scope.
- Treat reference sets/lookup tables/allow-lists as first-class migration artifacts; they are lost
  more often than the core query logic.
- Audit field population on the new platform against real ingested data before rewriting queries,
  not against vendor schema documentation.
- Match sequence/ordered logic to the new platform's native sequencing primitive; don't approximate
  order with aggregation.
- Validate with shadow-mode fire-rate comparison and, where available, replay of confirmed past
  true positives before cutover.
- Keep an explicit, owned rule-by-rule migration status inventory, and gate old-platform
  decommission on coverage confirmation, not on a license date.
