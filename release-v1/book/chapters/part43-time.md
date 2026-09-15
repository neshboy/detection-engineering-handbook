# Part XLIII — Time

Every detection in this book eventually reduces to a claim about ordering: X happened, then Y
happened within some window, therefore alert. That claim is built on timestamps, and timestamps
are the least-examined field in most pipelines. Analysts trust `@timestamp` the way they trust a
clock on a wall — right up until they build a correlation rule that silently drops half its true
positives because two log sources disagree about what time it is, or an alert fires eleven hours
late because a forwarder was backlogged, or a hunt returns nothing because the query window and the
event's actual timestamp are talking about two different clocks.

This chapter is not about NTP hygiene as an IT hygiene topic. It's about the specific, recurring
ways time gets misrepresented in security telemetry, and the specific ways that breaks detection
logic that otherwise looks correct on paper.

## 1. There is no single "time" in a SIEM event

[CONCEPT] A single log line, once it reaches your detection platform, usually carries at least
three distinct timestamps, and they are frequently not the same value:

| Timestamp | What it actually measures | Who sets it |
|---|---|---|
| **Event time** | When the thing happened, according to the clock on the system where it happened | Source host OS clock |
| **Collection/read time** | When a forwarder, agent, or API poll picked the event up | Forwarder/agent clock |
| **Ingestion time** | When the event landed in the SIEM's index/pipeline | SIEM ingest pipeline, often the indexer's own clock |
| **Processing time** | When enrichment, parsing, or a detection rule actually evaluated the event | Detection engine clock, at rule execution |

[ENGINEERING] **Engineering Reality**: most SIEM query languages default to filtering and sorting
on ingestion time, not event time, because that's the field the indexing tier actually controls and
indexes efficiently. Splunk's `_time` is populated from the parsed event timestamp *if parsing
succeeds*, but falls back to indexing time on parse failure — silently, with no alert that it
happened. Elastic's `@timestamp` is whatever the ingest pipeline sets it to, and a misconfigured
pipeline (or one lacking a `date` processor for a given source) will leave it as document-index
time. Sentinel's `TimeGenerated` is close to ingestion time for most connectors, not event time. If
you have never explicitly checked which timestamp field a given source populates and which one your
detection rules key off, assume you don't know, and go check — this is the single most common
silent bug in multi-source correlation.

[DETECTION ENGINEER] When you write `earliest=-1h index=win_security` or a KQL `where TimeGenerated
> ago(1h)`, you are almost always filtering on ingestion or collection time. If a source has a
9-minute forwarding delay and you're hunting for "events in the last 5 minutes," you will
systematically miss the newest 4 minutes of that source's *real* activity every single time you
run the query, and never notice, because the query returns results — just not the right ones.

## 2. UTC vs. local time: the boring bug that never stops recurring

[CONCEPT] Every log source should emit UTC. Not all of them do, and "should" carries no weight in
a live estate. Windows Event Log timestamps in the raw `.evtx` are stored as UTC (FileTime), but
the moment they're rendered — by `wevtutil`, by many forwarders' default templates, by an analyst
reading the Event Viewer GUI — they can be converted to the local time zone of whatever machine is
doing the rendering. Firewall and network appliance syslog is a coin flip: some vendors default to
local time with no time zone offset in the string at all, which means the string `2026-09-15
14:03:11` is meaningless without external knowledge of which time zone that appliance was configured
for at the time.

[ANALYST] The practical failure mode: an analyst pivots from a SIEM alert (displayed in UTC, or in
their configured browser time zone) to a raw firewall log or a cloud provider's native console
(displayed in the account's configured local time, or the analyst's local time, or the resource's
region time — three different defaults across three different consoles is normal), and lines the
events up by eye, off by however many hours the offset is. During an incident, this produces a
timeline that's subtly wrong — a lateral-movement step that appears to happen *before* the initial
access step it depended on, which either gets "corrected" by an analyst assuming the tooling must be
buggy, or worse, doesn't get questioned at all and ships in the incident report.

[DETECTION ENGINEER] Never trust a bare timestamp string without a timezone/offset. Normalize every
source to UTC at ingestion, and store the *original* source string and its declared/assumed offset
alongside the normalized field — you will need to explain a discrepancy to an analyst eventually,
and "we converted it, trust us" is not an answer to "why does this timeline look wrong."

**Hunter's Note**: if you're hunting historical activity and a source uses local time with no
offset, first confirm the actual configured time zone *at the time the events were generated*, not
today's setting — appliances get their time zone changed during migrations, and nobody updates the
runbook.

## 3. Daylight saving transitions: two days a year, disproportionate damage

[CONCEPT] Twice a year, in jurisdictions that observe DST, local clocks jump forward an hour
(losing an hour, no events exist for that hour in local time) or fall back an hour (gaining an
hour, meaning local-time timestamps for that hour are *ambiguous* — there were two 1:30 AMs that
day, and a bare local timestamp with no offset cannot tell you which one).

[DETECTION ENGINEER] This is a real, recurring detection engineering incident, not a theoretical
edge case:

- Any system still logging in local time (see section 2) has one day a year where a
  correlation window computed naively in local time either drops an hour of events entirely
  (spring-forward — the window "1:00–2:00" doesn't exist) or double-counts / mis-orders an hour
  (fall-back — two separate hours both claim to be "1:00–2:00").
- Scheduled jobs, including scheduled detection rule runs, threat intel feed pulls, and log rotation
  jobs, that are scheduled in local time will run at the wrong offset relative to UTC for one run,
  which can produce a coverage gap (a rule that runs "every hour on the hour" local time skips or
  doubles a run) or a duplicate-alert burst.
- Baselining logic (Part XXV) that computes "activity by hour of day" over a rolling window will
  have one week a year where the bucket boundaries shift by an hour relative to the rest of the
  year's data, subtly widening or narrowing the effective baseline window for that comparison.
- Correlation rules with fixed windows (e.g., "successful login within 10 minutes of failure burst")
  are not directly broken by DST *if* both events are timestamped consistently in UTC or with
  correct offsets — the actual elapsed wall-clock time between two UTC timestamps is unaffected by
  DST. The breakage happens specifically when a human, a report, or a downstream system reconstructs
  local time from UTC and gets the offset wrong for the transition day, or when the *source* system
  logs in local time without an offset and its underlying OS clock genuinely jumps.

[SOC MANAGEMENT VIEW] Put DST transition dates on the detection engineering calendar the same way
you'd calendar a major patch Tuesday. In the week before each transition: confirm every scheduled
detection job, retention job, and report generator is scheduled in UTC (not "local time, whatever
that resolves to that week"); confirm any source still logging local time is a known, documented
exception with an owner; and staff someone to specifically review alert volume and gaps on the
transition day itself, because a real attacker doesn't care what day it is and a detection outage on
a DST day is indistinguishable from a detection outage on any other day until someone looks.

## 4. Clock drift between sources

[CONCEPT] Every host, appliance, and cloud service has its own clock. NTP keeps these reasonably
synchronized *if it's configured, reachable, and actually working* — none of which is guaranteed.
Common real-world drift sources: a host that's had its NTP client silently failing for weeks
(firewall rule change blocked outbound UDP/123, nobody noticed because the symptom — a clock a few
minutes off — doesn't page anyone); a virtualized guest whose clock drifts because the hypervisor's
time-sync service is disabled or fighting with an in-guest NTP client; an appliance with a battery-
backed RTC that's years off because it's never been network-synced at all and was set by hand at
install; a cloud function or container whose clock is fine but whose *logging library* buffers and
timestamps events at flush time rather than event time.

[ENGINEERING] **Engineering Reality**: drift is rarely uniform across your estate. It clusters —
one subnet with a broken NTP relay, one appliance model with a known clock bug, one region's cloud
logging pipeline running a few seconds to a few minutes behind another region's. This means a fixed
global "add N seconds to compensate" fudge factor doesn't work; you need per-source drift tracking
if you're going to compensate for it algorithmically, and most teams don't build that, so drift
mostly just sits in the data uncorrected until it causes a visible problem.

[DETECTION ENGINEER] Clock drift breaks correlation two ways:

1. **False negatives** — a correlation rule with a tight window (say, 60 seconds between a proxy
   log entry and an EDR process-creation event that should be near-simultaneous) misses matches
   because one source's clock is 90 seconds ahead. The rule looks correct in testing (test
   environment, synced clocks) and quietly underperforms in production (real environment, one drifted
   appliance) with no error, just fewer detections than expected.
2. **False ordering** — a chain that depends on "A happened before B" (Part XXIII's failed-logon →
   successful-login → privilege-use → process → network chain is a direct example) can have its
   *apparent* order reversed if the source for A is running fast and the source for B is running
   slow, even though A really did happen first. A correlation engine that hard-requires strict
   timestamp ordering between stages will silently drop the entire chain.

**Detection Autopsy — the drift-broken lateral movement correlation**

*Original logic*: A correlation rule fires when a Sysmon Event ID 3 (network connection) from a
workstation to a peer workstation on SMB (445) is followed, within 30 seconds, by a Sysmon Event ID
1 (process creation) on that peer workstation for a process spawned by `services.exe` — a reasonable
proxy for PsExec-style lateral movement (T1021.002, T1570-adjacent tooling). The 30-second window
was chosen because in lab testing, the network connection and the resulting service creation and
process launch consistently landed 2-6 seconds apart.

*Why it looked reasonable*: the lab environment had all endpoints on the same hypervisor host with
host-time-sync enabled, so every clock was effectively identical. Thirty seconds looked like a
generous, safe margin — six times the observed lab latency.

*What broke in production*: two endpoint pools in the estate were built from a golden image that had
Windows Time service disabled as a side effect of a hardening template applied inconsistently
(intended to disable it only on domain controllers acting as authoritative time sources, mis-scoped
to a broader OU). Those endpoints drifted up to four minutes over a few weeks of uptime before their
next reboot resynced them. Real PsExec-based lateral movement into and out of that pool during the
drifted period produced network connections and process creations more than 30 seconds apart *by
timestamp*, even though the actual elapsed wall-clock time between the two events was still a few
seconds — the rule correctly measured a nonexistent 4-minute gap because it trusted each host's own
clock at face value.

*False positives*: none directly from this — the failure mode was silent underperformance, not
noise, which is arguably worse because nothing about it looked wrong. Alert volume on that
correlation stayed low and steady; it just wasn't catching what it was supposed to be catching in
that pool.

*False negatives*: confirmed during a red-team exercise. The operator used a PsExec-equivalent to
move into a host in the affected pool; the correlation rule did not fire; the activity was caught
instead by an unrelated, much noisier heuristic and only then did the timestamp gap get noticed.

*Missing context*: the rule had no visibility into either endpoint's clock health — no NTP-offset
telemetry, no "time since last sync" field, nothing that would have flagged that the 30-second
assumption no longer held for that pool.

*Revised analytic*: two changes. First, the correlation window was loosened from a fixed 30 seconds
to a per-pair adaptive window that also checks each host's last-known NTP sync status (pulled from
a scheduled `w32tm /query /status`-equivalent inventory sweep) and widens the window when either
host's reported clock offset exceeds a threshold. Second, and more durably, a separate low-priority
detection was added purely to catch clock drift itself: any endpoint reporting an NTP offset beyond
a threshold, or any endpoint whose Windows Time service is stopped when policy requires it running,
generates a health alert to the endpoint team — fixing the root cause instead of only compensating
for it in one correlation rule.

*How it was tested*: replayed the red-team PsExec sequence against a test host with its clock
deliberately skewed by increasing amounts (30s, 90s, 4 min, 10 min) to confirm the adaptive window
caught the chain up to the point where the offset itself should have already triggered the new
clock-health alert, and confirmed the clock-health alert fired before the lateral-movement window
would have needed to stretch unreasonably far.

*Result*: lateral movement detection restored for the affected pool; the clock-health alert
subsequently caught two more instances of the same disabled-Windows-Time-service misconfiguration
being reapplied by a later hardening template push, before it caused another detection gap.

## 5. Delayed event arrival: the window problem in full

[CONCEPT] Every log source has some latency between event time and the moment it's queryable in the
SIEM. That latency is never zero and is rarely constant. It's the sum of: local buffering on the
source, forwarder polling interval or batch size, network transit, queueing at an intermediate log
collector, ingestion pipeline backlog, parsing time, and indexing/commit time before the event
becomes searchable. Cloud audit logs are a well-known offender — many cloud providers document
that audit/activity logs can take anywhere from under a minute to upward of 15 minutes (occasionally
longer during provider-side incidents) to appear, and that latency is not guaranteed or SLA-backed
in most tiers.

[ANALYST] This matters directly for investigation completeness: if you pull "all activity in the
last 15 minutes" during an active incident to build a timeline, and one of your key sources
(commonly cloud control-plane/audit logs, or a source that batches and forwards every N minutes)
has 10+ minutes of ingestion latency, you can genuinely be looking at an incomplete picture and not
know it — the query succeeded, returned data, and looks complete. The absence of an expected event
in a live investigation is not evidence the event didn't happen; it may just not have arrived yet.

[DETECTION ENGINEER] This is the mechanism behind the chapter's headline failure mode: **a
correlation window based on ingestion time, applied across sources with different ingestion
delays, systematically misses or misorders true positives** — not occasionally, structurally,
every time the delay differential exceeds the window. Concretely: suppose stage A of a correlation
comes from a source with ~10 seconds of ingestion delay (endpoint EDR telemetry, typically fast),
and stage B comes from a source with ~5 minutes of ingestion delay (a cloud provider's audit log,
or a batch-exported SaaS log pulled every few minutes via API poll). A correlation rule that fires
"stage B within 60 seconds of stage A, by ingestion time" will almost never fire, because stage B
routinely arrives 4+ minutes after stage A *by ingestion time*, even when the two events happened
essentially simultaneously *by event time*. Any team that built and tested this rule against
same-day, already-fully-ingested historical data in a query tool will see it "work" in testing and
then quietly fail to fire in near-real-time production, because testing against backfilled data
eliminates the very latency differential that breaks it live.

```mermaid
sequenceDiagram
    participant Src as Real-world event (T0)
    participant EDR as Endpoint EDR agent
    participant SaaS as SaaS/cloud audit log
    participant SIEM as SIEM ingestion pipeline
    participant Rule as Correlation rule engine

    Src->>EDR: Process creation happens at T0
    EDR->>SIEM: Forwarded, ~10s ingestion delay
    Note over SIEM: EDR event visible at T0+10s

    Src->>SaaS: Related cloud API call also happens near T0
    SaaS->>SaaS: Provider-side audit log generation delay
    SaaS->>SIEM: Polled/exported, ~4-6 min ingestion delay
    Note over SIEM: Cloud event visible at T0+~5min

    Rule->>SIEM: Evaluate "cloud event within 60s of EDR event,\nby ingestion time" at T0+70s
    Note over Rule: Cloud event not yet ingested -> no match -> true positive missed

    SIEM->>Rule: Cloud event finally lands at T0+5min
    Note over Rule: Rule already evaluated and moved on;\nlate arrival never re-triggers the window
```

[DETECTION ENGINEER] Practical mitigations, roughly in order of how often teams actually need to
combine more than one:

- **Correlate on event time, not ingestion time**, whenever the source reliably populates a real
  event timestamp. This fixes ordering and elapsed-time calculations even when ingestion is
  delayed — the events will still be *found* late, but once found, they'll compare correctly.
- **Widen the window to cover the realistic maximum delay differential**, not the typical one.
  This trades false-negative risk for false-positive risk (a wider window catches more coincidental,
  unrelated pairs) — an explicit, documented tradeoff, not a default.
- **Re-evaluate windows on late arrival**, i.e., design the correlation engine to re-check whether a
  newly-ingested (but old-event-time) event completes a previously-unmatched partial chain, rather
  than only evaluating forward from each new event as it lands. This is an architecture choice, not
  a query tweak — most simple "rule runs every N minutes over the last N minutes" scheduled-search
  correlation setups cannot do this at all; it typically needs a stateful streaming correlation
  engine or an explicit "pending chains" store with its own expiry.
- **Track and alert on ingestion latency itself per source**, so a detection engineer finds out when
  a source's delay profile changes (a SaaS vendor changes their export interval, a forwarder starts
  backlogging) before it silently degrades every correlation rule that touches that source.

[THREAT HUNTER] When hunting rather than alerting, delayed arrival is less dangerous but still worth
respecting: if you're hunting "in the last hour" across multiple sources, explicitly check each
source's typical latency and either widen your query window past that latency or accept, in writing
in your hunt notes, that recent activity in slow sources may be underrepresented in your result set.
A hunt that concludes "no suspicious cloud API activity in the last 60 minutes" when the cloud audit
log source has a 10-minute typical delay has actually only checked the first 50 minutes.

## 6. A worked correlation query with time handled explicitly

[CONCEPT] The following is an illustrative KQL example (syntax patterns typical of Microsoft
Sentinel/Log Analytics; treat as illustrative, verify exact function names and table schema against
your own environment before use) showing the difference between naive ingestion-time correlation and
event-time correlation with an explicit late-arrival allowance.

**Naive version (ingestion-time join, breaks under differential delay):**

```kql
// CONCEPTUAL SAMPLE - illustrative only, not verified against a live tenant
let Window = 1m;
SecurityEvent
| where EventID == 4624
| project TimeGenerated, Account, Computer
| join kind=inner (
    CloudAppEvents
    | where ActionType == "risky sign-in equivalent"
    | project TimeGenerated, Account
) on Account
| where abs(datetime_diff('second', TimeGenerated, TimeGenerated1)) < 60
```

The join above compares `TimeGenerated` — ingestion time in most Sentinel connectors — across two
sources with materially different, and independently variable, ingestion latency. It will
underperform in exactly the way described in section 5.

**Event-time version with explicit late-arrival window:**

```kql
// CONCEPTUAL SAMPLE - illustrative only, not verified against a live tenant
let CorrelationWindow = 60s;
let MaxIngestLatency = 10m;  // documented worst-case for the slower source
let LookbackToCoverLatency = 15m;
SecurityEvent
| where TimeGenerated > ago(LookbackToCoverLatency)
| where EventID == 4624
| extend EventTime = TimeGenerated  // EDR/Windows source: event time ~= ingestion time
| project EventTime, Account, Computer
| join kind=inner (
    CloudAppEvents
    | where TimeGenerated > ago(LookbackToCoverLatency)
    | where ActionType == "risky sign-in equivalent"
    | extend EventTime = CreatedDateTime  // use the source's own event-time field, not TimeGenerated
    | project EventTime, Account
) on Account
| where abs(datetime_diff('second', EventTime, EventTime1)) < CorrelationWindow
```

The second version deliberately looks back further than the alert window (`LookbackToCoverLatency`
covers the slower source's documented worst-case ingest delay) and joins on each source's own
event-time field rather than the shared ingestion-time column, so a cloud event that lands five
minutes late by ingestion time still correctly matches an EDR event that happened at nearly the same
real-world moment. The tradeoff is that this rule, run on a fixed schedule, must run frequently
enough and look back far enough to catch chains where one side is still delayed — which increases
compute cost and duplicate-match handling complexity (deduplicate on a stable key, e.g., a hash of
account + both event IDs, so re-evaluating the same lookback window on the next run doesn't re-alert).

## 7. Tuning and testing time-aware detections

[DETECTION ENGINEER] Concrete things to check before shipping any correlation rule:

- For every source in the chain, confirm which field is event time, which is ingestion time, and
  document both explicitly in the rule's metadata/comments — not just in someone's memory.
- Measure actual observed ingestion latency per source over at least a week (not a guess, not the
  vendor's marketing SLA) and set lookback/window parameters against the observed p95 or p99, not
  the median.
- Test the rule against a synthetic event pair injected with a deliberately delayed second event
  (delay it artificially, or replay a real pair captured during a known-slow period) — not just
  against clean, simultaneous test data.
- Confirm the rule's dedup/idempotency behavior when the same lookback window is evaluated on two
  consecutive scheduled runs (this is where late-arrival-tolerant designs commonly double-alert if
  dedup wasn't built in).
- Add a per-source latency and clock-offset health check as its own low-noise detection (section 4's
  Detection Autopsy shows why this pays for itself independent of any single correlation rule).

[MANAGEMENT] **SOC Management View**: time-handling bugs are disproportionately expensive because
they're invisible in normal operating metrics. A correlation rule silently missing true positives
due to a delay differential looks, on a dashboard, identical to a correlation rule that's simply
not triggering because there's no bad activity — both show "low alert volume." Budget recurring time
for detection engineers to audit timestamp handling on existing high-value correlations (not just new
ones), particularly after any change to a data source's forwarding architecture, any SaaS vendor
export-interval change, or any DST transition. This is unglamorous maintenance work with no feature
to demo, which is exactly why it gets skipped and exactly why it should be explicitly staffed rather
than left to whoever notices a gap during an incident retrospective.

**Hunter's Note**: when a chain-based hunt across multiple sources comes back empty, before
concluding "nothing happened," check whether the slowest source in the chain has actually finished
arriving for the time period you're looking at. An empty result and a not-yet-fully-ingested result
look identical from the query output.

## Summary

Timestamps are not a neutral scaffolding underneath detection logic — they're an active part of it,
with their own failure modes: which clock, which time zone, which of three-plus timestamp fields,
how much drift, how much delay, and whether that delay is uniform across sources. Every correlation
rule and every threshold rule with a time window is implicitly making claims about all of these, and
most of those claims are never written down or tested. The fix isn't a single control — it's
treating time handling as a first-class, explicitly documented, explicitly tested part of every
multi-source detection, and building the boring, unglamorous health checks (NTP offset, ingestion
latency per source) that turn a silent detection gap into a visible engineering alert instead.
