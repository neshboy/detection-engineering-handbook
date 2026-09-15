# TERMINOLOGY.md — Canonical Glossary for the Detection Engineering Handbook

**Status:** Proposal 2 of 2 (independent draft), for reconciliation into a single canonical
glossary before Part I ships.
**Audience:** All chapter, detection, and hunt authors across all 40+ parts.
**Purpose:** One definition per term, used the same way everywhere in the book. If a chapter
needs to use a term in a way that conflicts with this file, that is a signal the definition
needs to be fixed here — in a discussion with the terminology owner — not silently redefined
in one chapter.

## How to use this file

- **Do not redefine these terms inline in a chapter.** Link back to this file
  (`see TERMINOLOGY.md § Alert`) instead of writing a competing one-liner. If your chapter's
  concept doesn't fit an existing entry, propose an addition here rather than inventing local
  vocabulary — with 150+ authors, a single term defined 40 slightly different ways is the
  single biggest cause of reader confusion and contradictory cross-references.
- **First use in a chapter:** spell out an abbreviation once (`true positive (TP)`), then use
  the abbreviation freely.
- **Capitalization:** terms are Title Case only when used as the formal glossary term itself
  (e.g., "this is a **Benign Positive**, not a False Positive"); ordinary prose use is
  lowercase ("the alert was a benign positive").
- **"See also"** cross-references terms that are easily confused with the entry, or that
  combine with it — read those together before writing a chapter that leans on either term.
- Terms are grouped by function, not alphabetically, because most confusion in this book comes
  from adjacent terms in the same pipeline stage (e.g., Alert vs. Incident vs. Case) rather
  than from unrelated terms that happen to share a letter. An alphabetical index is at the
  bottom.

---

## 1. The Data Layer: Before Any Detection Logic Runs

### Event

A single, immutable, timestamped record of something that happened, as captured by an
instrumented system, that exists whether or not any detection logic ever looks at it.

*Example:* A Windows Security log record for Event ID 4624 showing an interactive logon by
`jsmith` on `WIN-042` at `03:14:07 UTC` is one event, regardless of whether any rule ever
evaluates it.

**See also:** Telemetry, Signal.

### Telemetry

The aggregate stream of events, at whatever fidelity, completeness, and retention a program has
actually achieved, that is available to be queried — a statement about what data exists in the
pipeline, not about what can be detected with it.

*Example:* "We ingest Sysmon Event IDs 1, 3, 10, and 11 from 92% of Windows endpoints, retained
90 days" describes telemetry. It says nothing about whether any analytic uses that data
reliably.

**See also:** Telemetry Coverage, Detection Coverage, Visibility Debt, Log Source.

### Log Source

A single, named origin of telemetry with its own ingestion path, schema, retention policy, and
owner (e.g., "Windows Security event log via Sysmon," "Okta system log," "AWS CloudTrail,"
"Zeek `conn.log`") — the unit that telemetry coverage and schema drift are tracked against.

*Example:* "Azure AD Sign-In Logs" and "Azure AD Audit Logs" are two different log sources with
different schemas, even though both come from the same platform.

**See also:** Telemetry, Schema Drift.

### Signal

A property of an event or event sequence that correlates with the behavior a detection is
trying to identify, without itself being a verdict — the raw material a detection combines,
weighs, and thresholds against, not an alert in its own right.

*Example:* "PowerShell process launched with `-EncodedCommand`" is a signal. On its own it does
not say whether the invocation is malicious — legitimate configuration-management tooling
produces the same signal.

**See also:** Analytic, Correlation, Analytic Confidence, Noise (the legitimate activity that
also carries a given signal, and the reason no single signal is used unqualified).

---

## 2. From Idea to Deployed Capability

### Threat Hypothesis

A specific, falsifiable statement about an adversary behavior or technique that may be
occurring, or may currently be undetectable, written down *before* any query is run or any
rule is designed — the starting artifact for both a Hunt and an Analytic.

*Example:* "Attackers who gain access via a phished OAuth token are enumerating mailbox rules
before setting up mail forwarding, and we have no analytic covering the enumeration step."

**See also:** Hunt, Analytic, Use Case.

### Use Case

The business, risk, or compliance justification for building and maintaining detection
capability in a given area at all — a program-level grouping of one or more Analytics tied to a
named driver (a top threat, a regulatory control, a prior incident), owned and reviewed at the
program level rather than the rule level.

*Example:* "Detect credential theft from memory" is a use case; it may be satisfied by several
distinct analytics (LSASS access, DCSync abuse, Kerberos ticket forging), not by one rule.

**See also:** Analytic, Detection Rule, Detection Coverage.

### Analytic

The implementation-independent logical statement of what pattern in telemetry indicates a
targeted behavior — designed and validated as logic first, before being written in any
specific query language or deployed as a rule; one analytic may be implemented as several
platform-specific Detection Rules.

*Example:* "An account authenticates interactively to a host it has no 30-day history with,
followed within 10 minutes by execution of a known LOLBin" is an analytic. It exists
conceptually before anyone writes it in Sigma, KQL, or SPL.

**See also:** Detection Rule, Use Case, Signal, Correlation.

### Detection Rule

The literal, deployed, versioned piece of logic (a Sigma rule, a SIEM correlation search, a KQL
scheduled query, a YARA-L rule) that evaluates telemetry and produces alerts — the
implementation of an Analytic in a specific backend, with its own lifecycle (deployed, tuned,
deprecated) distinct from the analytic it implements.

*Example:* The Sysmon Event ID 10 (`ProcessAccess`) correlation search deployed in the SIEM,
with your environment's specific EDR/AV allow-list, is the detection rule that implements the
LSASS-access analytic above.

**See also:** Analytic, Detection, Detection-as-Code.

### Detection

The general term for the deployed, owned, and maintained capability that turns telemetry into
an alert for a specific adversary behavior — encompassing both the Analytic (the logic) and the
Detection Rule (the implementation that runs it), plus the ownership, testing, and review that
keep it correct over time; use "detection" for the capability as a whole and reach for
"analytic" or "detection rule" when the distinction between logic and implementation actually
matters to the sentence.

*Example:* "This detection has a documented false-positive rate, an owner, and a review date"
is a statement about the whole capability, not specifically about the query text.

**See also:** Analytic, Detection Rule, Use Case, Detection-as-Code, Detection Coverage.

### Hunt

A time-boxed, hypothesis-driven, human-led investigation into a behavior that has no reliable
standing detection yet (or may never get one), conducted to prove or disprove a Threat
Hypothesis and, where validated, produce evidence toward a new Analytic — distinct from a
Detection Rule in that it is not continuous, automated, or queue-driven.

*Example:* A hunter searches 30 days of DNS query logs for beacon-interval jitter patterns to
test the hypothesis that the current C2 detection would miss a jittered beacon; no standing
rule exists for this yet.

**See also:** Threat Hypothesis, Analytic, IOC-Based Hunt, Atomic Test.

### Detection-as-Code

The practice of managing detection logic — Analytics and the Detection Rules that implement
them — with the same engineering discipline as application software: version control, peer
review, automated true/false-positive testing, CI/CD deployment, and rollback, instead of
direct, unreviewed edits in a SIEM console.

*Example:* A Sigma rule change is submitted as a pull request, run against a stored
true-positive/false-positive test corpus by CI, peer-reviewed, and merged before the pipeline
deploys it to production.

**See also:** Detection Rule, Testing Debt (§6), Documentation Debt (§6).

---

## 3. The Alert Lifecycle and Triage Outcomes

### Alert

The specific, timestamped output instance produced when a deployed Detection Rule's conditions
are met against telemetry, entering an analyst's (or automated responder's) queue for
disposition — one detection rule produces many alert instances over its lifetime.

*Example:* The LSASS-access rule evaluates true against host `WIN-042` at `14:02 UTC`,
generating one alert instance in the SOC queue.

**See also:** Detection Rule, Triage, Disposition, Case.

### Triage

The initial analyst (or automated) process of examining an Alert's context — source, entity,
prior history, related alerts — to reach a Disposition, before any formal Case or Incident is
necessarily opened.

*Example:* An analyst pulls the parent process, the account's baseline, and the destination
host's criticality for a new alert within minutes of it firing, and closes it as a false
positive without opening a case.

**See also:** Alert, Disposition, Case.

### Disposition

The recorded outcome an analyst (or automated logic) assigns to a closed Alert — True Positive,
Benign Positive, False Positive, or Unable to Determine — which is the raw data every
quality metric (precision, recall, Analytic Confidence, tuning backlog) in this book is built
from; an alert without a disposition is not usable for any of those measurements.

*Example:* An alert closed with disposition `benign_positive`, reason code
`authorized_pentest`, feeds both the rule's confidence history and, if the reason code recurs,
a Tuning ticket.

**See also:** True Positive, Benign Positive, False Positive, Analytic Confidence, Tuning.

### Incident

A confirmed, or reasonably suspected and formally declared, security event — potentially built
from one or more Alerts plus non-alert reporting (a user report, a third-party notification) —
that is managed through a defined incident-response process because it represents actual or
credible likely adverse impact.

*Example:* Three separate alerts on one host within an hour (suspicious logon, LSASS access,
outbound connection matching a known C2 pattern) are correlated by an analyst and declared as a
single ransomware-precursor incident, handed to the IR team.

**See also:** Case, Alert, Escalation.

### Case

The working investigation container in a case-management system that groups one or more Alerts
(plus notes, evidence, and analyst actions) under a single owned investigation — a case may be
opened for a single ambiguous alert and closed as a false positive without ever becoming an
Incident; a Case is the *investigative unit*, an Incident is a *declared, impact-bearing
event*, and not every case escalates to one.

*Example:* An analyst opens a case for one alert, pulls in two related alerts discovered during
triage, and closes the case disposition as "false positive — known scanner" — no incident is
ever declared.

**See also:** Incident, Alert, Triage.

### True Positive (TP)

An alert Disposition indicating the detection rule's logic matched correctly *and* the matched
activity is genuinely malicious, unauthorized, or otherwise the exact thing the analytic was
built to catch.

*Example:* The encoded-PowerShell rule fires on an actual attacker's obfuscated
download-and-execute payload during a live intrusion.

**See also:** Benign Positive, False Positive, Disposition, Precision.

### Benign Positive (also: Benign True Positive, BTP)

An alert Disposition indicating the detection rule's logic matched *correctly* — the described
condition genuinely occurred, exactly as the rule specifies — but the underlying activity is
legitimate, authorized, or otherwise not a security problem in context; distinguished from a
False Positive by *where the correctness lives*: BTP means the logic is right and the activity
is benign, FP means the logic itself is defective.

*Example:* An authorized penetration tester runs a credential-dumping tool during a scoped,
approved engagement and trips the LSASS-access rule exactly as the rule is designed to catch —
the match is correct, the activity carries no risk.

**See also:** True Positive, False Positive, Precision, Tuning, Exception.

### False Positive (FP)

An alert Disposition indicating the detection rule's logic itself is defective for the case at
hand — it matched activity that does not represent the behavior the analytic claims to detect,
because the condition is too broad, mis-targeted, or coincidentally satisfied by unrelated
activity — as opposed to a Benign Positive, where the logic is correct and only the intent is
benign.

*Example:* A rule chaining "any 4672 (privileged logon) followed by any 4688 (process creation)
within 5 minutes" fires on essentially every routine admin login and scheduled task, because
the logic never actually discriminates attack activity from routine administration.

**See also:** Benign Positive, True Positive, Precision, Tuning, Suppression.

### False Negative (FN)

Malicious or policy-violating activity that met the criteria an analytic was intended to catch
but produced no alert, typically discovered after the fact via an incident post-mortem, red
team exercise, purple-team test, or hunt — the failure mode that alert-count and precision
metrics are structurally blind to, because a false negative produces no record at all.

*Example:* An attacker uses a LOLBin not on the rule's allow-listed set; the LSASS-access
analytic's logic never evaluates true, despite a real credential-theft attempt occurring.

**See also:** Recall, Testing Debt, Visibility Debt, Detection Debt.

---

## 4. Tuning and Noise Control

### Suppression

A configured mechanism that prevents an otherwise-matching Alert from reaching an analyst
queue — an allowlist entry, a maintenance-window rule, a deduplication window, a risk-score
floor — applied at or after the point the Detection Rule's logic already matched, without
altering that underlying logic.

*Example:* Alerts sourced from a known, scheduled vulnerability scanner's IP range are
suppressed for the duration of the weekly scan window; the rule still evaluates true underneath.

**See also:** Exception, Tuning, Allowlist.

### Exception

A documented, reviewed, and ideally time-bounded or owner-attributed carve-out written *into
the detection rule's own logic* to prevent it from matching a specific, known-benign case — as
opposed to Suppression, which filters an alert after the rule has already matched; an
undocumented exception is exactly what turns into Tuning Debt.

*Example:* The encoded-PowerShell rule's condition is amended with an explicit exclusion for a
named configuration-management agent's process path, recorded with a reviewer, date, and reason
in the rule's changelog — not filtered downstream, removed from the matching logic itself.

**See also:** Suppression, Tuning, Detection Debt.

### Tuning

The ongoing engineering process of adjusting a detection's thresholds, Exceptions, correlation
logic, or Suppression rules, driven by accumulated Disposition data (TP/BTP/FP rates), to
improve precision without silently opening a false-negative gap — tuning changes the rule;
Suppression changes what reaches the analyst without touching the rule.

*Example:* After three months of Benign Positives from an approved pentest subnet, the rule is
tuned with a permanent, documented exception for that subnet instead of every future alert
being manually dismissed one at a time.

**See also:** Exception, Suppression, Benign Positive, Tuning Debt.

### Alert Fatigue

The measurable degradation in analyst scrutiny and response speed that results from sustained
exposure to a high volume of low-value (mostly False Positive or repetitive Benign Positive)
alerts, which increases the risk that a genuine True Positive is triaged carelessly or
dismissed by pattern-matching against the usual noise.

*Example:* A rule that fires 200 times a day on a known-benign backup job desensitizes the
on-call analyst enough that a genuinely malicious use of the same pattern, on the 201st alert
that week, gets closed in ten seconds without real review.

**See also:** Tuning Debt, Precision, Disposition.

---

## 5. Coverage, Telemetry, and the Debt That Accrues Against Both

### Coverage

The umbrella term for "how much of the space of possible adversary behavior can this program
currently identify" — never use this word unqualified in this book; always specify which of
Telemetry Coverage or Detection Coverage is meant, because the two are routinely conflated and
that conflation is the single most common source of false confidence in coverage reporting.

**See also:** Telemetry Coverage, Detection Coverage, Visibility Debt.

### Telemetry Coverage (also called Log Coverage)

Whether data from a given source or technique surface exists in the pipeline at all, at some
retention and field fidelity — a statement about data presence, not detection capability.

*Example:* "We collect Windows Security event logs (4624, 4625, 4672, 4688) from all
domain-joined hosts" is a telemetry coverage statement. It says nothing about whether any rule
can reliably act on that data.

**See also:** Detection Coverage, Visibility Debt, Log Source.

### Detection Coverage

Whether a tested, tuned, owned Analytic exists that can reliably identify a specific adversary
behavior at a measured, acceptable false-positive rate, using telemetry that is actually
available — implies a working, validated detection, not merely a data source sitting in the
SIEM.

*Example:* "We can reliably detect an interactive/RDP logon with no 30-day account-host history
followed by LOLBin execution, with a validated false-positive rate against production data" is
a detection coverage statement.

**See also:** Telemetry Coverage, Use Case, Analytic Confidence.

### Visibility Debt

The accumulating gap between Telemetry Coverage and Detection Coverage: log sources ingested
with no corresponding tested Analytic — a form of Detection Debt that looks like progress on a
source-count dashboard while contributing nothing to actual detection capability.

*Example:* Onboarding a new cloud audit-log source increases the "sources ingested" count on a
coverage dashboard even though zero analytics use it yet — that gap is visibility debt, and it
is invisible on a dashboard that only counts sources.

**See also:** Telemetry Coverage, Detection Coverage, Detection Debt.

### Detection Debt

The umbrella term for the accumulated gap between what a detection stack *appears* to cover
(rule count, coverage spreadsheet, MITRE percentage) and what it *actually* covers correctly,
reliably, and at acceptable noise, given the current state of telemetry, tooling, and adversary
behavior — it fails silently by default (a broken detection produces zero alerts, which looks
identical to "the technique isn't happening"), which is what distinguishes it from ordinary
software technical debt. It has five commonly tracked sub-types: **Telemetry Debt** (assumed
fields/sources no longer flow as expected), **Parser Debt** (fields are null or mis-mapped
while ingest volume looks healthy), **Documentation Debt** (rationale/FP-notes/dependencies
were never recorded), **Testing Debt** (no scheduled re-verification against current
telemetry), and **Tuning Debt** (known false-positive sources identified but never fed back
into the rule).

*Example:* An EDR migration truncates a `CommandLine` field at a shorter length than the
previous agent; a rule matching against the untruncated field goes silent with zero errors and
zero new false positives — which reads as "clean" rather than "broken" until a red team exercise
finds the gap eighteen months later.

**See also:** Visibility Debt, Schema Drift, Testing Debt, Tuning Debt.

### Schema Drift

A change in a Log Source's field names, types, encoding, or value distribution — from a vendor
update, an agent migration, or an API version change — that silently invalidates a Detection
Rule's field references without producing any ingest error, because "zero matching events" is a
valid result for almost every query language.

*Example:* A cloud provider renames `src_ip` to `source.ip` between API versions; a rule
querying the old field name compiles, runs, and returns nothing, with no error raised anywhere.

**See also:** Log Source, Detection Debt, Testing Debt.

### Precision

The fraction of an analytic's alerts that were correct: `TP / (TP + FP)` (Benign Positives are
typically excluded from the FP term because the logic matched correctly; check your program's
convention and state it explicitly) — answers "when this fires, how often is it right," and
tells you nothing about what the analytic is missing.

*Example:* An analytic with 40 closed alerts, 30 true positives, 8 benign positives, and 2 false
positives has a precision of 30/32 ≈ 94% if benign positives are excluded from the denominator's
error term, as distinct from an unqualified TP/(TP+FP+BP) calculation — state which convention
a reported number uses.

**See also:** Recall, Analytic Confidence, Disposition.

### Recall

The fraction of actually-malicious activity that an analytic (or the program as a whole)
successfully alerted on, out of all such activity that occurred — in practice always measured
as "recall against intrusions we know about," a lower bound conditioned on the program's own
detection and hunting capability, not a true statistical recall, because the population of
undetected intrusions is by definition unmeasured directly.

*Example:* A red team exercise executes ten techniques; six trigger an alert. Measured recall
for that exercise is 60% — a sample-bound estimate, not a program-wide guarantee.

**See also:** False Negative, Precision, Testing Debt.

---

## 6. Correlation, Baselines, and Entities

### Correlation

Detection logic that produces a verdict from a combination of two or more individually
low-signal events, typically joined on a shared Entity Key within a bounded time window, where
no single constituent event would justify an alert on its own.

*Example:* A failed VPN authentication followed by a successful one from a new device, followed
by first-time access to a sensitive file share — each event unremarkable alone, correlated on
account and a bounded time window.

**See also:** Entity, Entity Key, Signal, Risk-Based Alerting.

### Baseline

A statistical or rule-based model of an Entity's expected behavior across a defined feature set
(login times, process names, destination countries, data volumes), built from historical
observation over an explicit time window with an explicit update/decay policy, against which
new observations are scored for deviation rather than matched against a fixed signature.

*Example:* A 30-day, per-account model of which hosts an account has authenticated to, used to
flag a first-time account-host pairing as elevated-confidence rather than matching a hardcoded
list of "bad" hosts.

**See also:** Entity, Correlation, Analytic Confidence.

### Entity

The specific real-world object (user account, host, process, session, service principal, IP
address, cloud resource) that telemetry, Correlation, and Baselines are anchored to, via a
stable identifier, so events from different sources can be recognized as pertaining to "the
same thing."

*Example:* A logon session GUID lets a 4624 logon event and a later 4688 process-creation event
be tied together as the same entity even though they are different event types from the same
log source.

**See also:** Entity Key, Correlation, Baseline.

### Entity Key

The specific field, or combination of fields, used to join events across sources or across time
as referring to the same Entity — the practical mechanism that makes Correlation and Baselining
possible, and the thing most likely to silently break a correlation when it changes format,
resets (e.g., a session ID that recycles), or isn't available at the same fidelity across every
source being joined.

*Example:* `AccountName + DomainName` may be a stable entity key for on-prem Windows logons but
needs to be resolved against a cloud identity's `object_id` before it can be joined to
Azure AD sign-in logs for the same user.

**See also:** Entity, Correlation.

### Enrichment

Additional context attached to an event, alert, or entity from a source outside the original
telemetry — asset criticality, user risk score, threat intel reputation, geolocation — used to
raise or lower Analytic Confidence without changing the core matching logic.

*Example:* A LOLBin-execution alert is enriched with the destination host's asset-criticality
tag; the same rule logic produces a higher-priority alert on a domain controller than on a
routine workstation.

**See also:** Analytic Confidence, Risk-Based Alerting.

### Risk-Based Alerting (RBA)

An alerting model in which individual weak Signals — each independently far below any
reasonable alerting threshold — contribute points to a running risk score for an Entity over a
time window, and an alert fires only when the accumulated score crosses a threshold, rather than
any single signal firing a standalone rule.

*Example:* An off-hours VPN login (+20), an unusual PowerShell script execution (+10), and
access to a sensitive share the account rarely touches (+15) sum to 45 for one account in one
session; an alert fires only because the combined score crossed the program's threshold, not
because any one signal did.

**See also:** Correlation, Entity, Analytic Confidence.

---

## 7. Confidence, Severity, and Priority — Three Different Axes

Authors routinely collapse these three into one number. Keep them separate: they answer
different questions and can move independently (a high-confidence alert on a low-value asset
may rank below a lower-confidence alert on a domain controller).

### Analytic Confidence

A measured — not assumed at authoring time — estimate of how likely a given Analytic's alert
instances represent genuinely malicious activity, derived from accumulated Disposition history
(TP/BTP/FP rates over a defined rolling window) and revised as more disposition data arrives;
answers "historically, how often is *this analytic* right," and is a property of the analytic,
not of any single alert instance.

*Example:* An analytic with a 92% true-positive rate over the last 90 days is auto-routed for
expedited triage; one with a 15% rate over the same window is routed to a lower-priority queue
pending Tuning, independent of what any single new alert instance "feels like."

**See also:** Precision, Severity, Priority, Disposition.

### Severity

An assessment of *how bad the underlying behavior would be if the alert is a true positive* —
a property of the technique/impact, largely independent of how confident you are that this
particular instance actually is one.

*Example:* "Domain Admin credential dumping" is high severity regardless of whether a given
alert instance turns out to be a real attacker or an authorized pentester — the potential
impact of the behavior, if real, doesn't change.

**See also:** Analytic Confidence, Priority.

### Priority

The operational ranking that determines which alerts an analyst works first — typically a
function combining Severity, Analytic Confidence, and Entity criticality (asset value, business
context), computed per alert instance rather than being a fixed property of the rule.

*Example:* A high-severity, high-confidence alert on a routine workstation may rank below a
medium-severity, medium-confidence alert on a domain controller, if the queue's priority
function weights entity criticality heavily.

**See also:** Severity, Analytic Confidence, Entity.

---

## 8. Testing, Validation, and Response Process

### Atomic Test

A small, scoped, single-technique adversary emulation action (e.g., one Atomic Red Team test
mapped to one MITRE ATT&CK technique) executed repeatably in a controlled environment, used to
generate a known-true-positive Ground Truth for a specific Analytic and re-run on a schedule or
after any environment change to catch Testing Debt before an incident does.

*Example:* A scheduled monthly re-execution of the `rundll32.exe` LOLBin-execution atomic test
against the current EDR agent, verifying the expected alert still fires on the expected fields.

**See also:** Detection Debt, Recall, Detection-as-Code.

### IOC (Indicator of Compromise) vs. IOA (Indicator of Attack)

An **IOC** is a static, known-bad artifact (a file hash, a malicious domain, a compromised
credential) that indicates a specific, previously identified malicious instance — it stops
working the moment the artifact changes. An **IOA** is a behavior-based indicator of intent or
technique (e.g., "process injection into a browser followed by outbound beaconing") that
survives artifact changes because it targets the underlying action, not a fingerprint of one
occurrence of it.

*Example:* A known-bad C2 domain is an IOC; "DNS queries with high subdomain entropy at a fixed
interval regardless of domain" is an IOA.

**See also:** Signal, Behaviour-Based Detection.

### Dwell Time

The elapsed time between an adversary gaining a foothold in an environment and that presence
being detected (by any means — a rule, a hunt, an external notification) — the metric that
Detection Coverage, Visibility Debt, and Recall all ultimately exist to reduce.

*Example:* A retrospective hunt against 90 days of retained logs, triggered by a new IOC
disclosure, finds an intrusion that had been present for 40 days before any alert fired — that
40 days is dwell time the standing detection stack failed to close.

**See also:** Recall, Detection Coverage, Hunt.

### Escalation

The formal act of moving an Alert or Case to a higher-severity handling track — most commonly,
declaring it (or a set of related ones) an Incident — with an associated change in response
process, stakeholders notified, and urgency.

*Example:* An analyst escalates a case from routine SOC triage to the incident-response team
after confirming lateral movement across three hosts.

**See also:** Incident, Case, Priority.

### Playbook vs. Runbook

A **playbook** is the decision logic for *how to respond* to a category of alert or incident
(what to check, in what order, what determines escalation) — the "what to decide." A
**runbook** is the step-by-step, largely mechanical procedure for executing a specific action
(how to isolate a host, how to rotate a credential, how to query a specific data source) — the
"how to execute." A playbook may call several runbooks.

*Example:* The "suspected ransomware precursor" playbook tells an analyst when to isolate a
host; the "endpoint isolation" runbook tells them exactly which console, which button, and what
to verify afterward.

**See also:** Incident, Escalation.

---

## Alphabetical Index

Alert (§3) · Alert Fatigue (§4) · Analytic (§2) · Analytic Confidence (§7) · Atomic Test (§8) ·
Baseline (§6) · Benign Positive / Benign True Positive (§3) · Case (§3) · Coverage (§5) ·
Correlation (§6) · Detection (§2) · Detection-as-Code (§2) · Detection Coverage (§5) ·
Detection Debt (§5) · Detection Rule (§2) · Disposition (§3) · Dwell Time (§8) · Enrichment (§6)
· Entity (§6) · Entity Key (§6) · Escalation (§8) · Event (§1) · Exception (§4) · False Negative
(§3) · False Positive (§3) · Hunt (§2) · Incident (§3) · IOC vs. IOA (§8) · Log Source (§1) ·
Playbook vs. Runbook (§8) · Precision (§5) · Priority (§7) · Recall (§5) · Risk-Based Alerting
(§6) · Schema Drift (§5) · Severity (§7) · Signal (§1) · Suppression (§4) · Telemetry (§1) ·
Telemetry Coverage (§5) · Threat Hypothesis (§2) · Triage (§3) · True Positive (§3) · Tuning
(§4) · Use Case (§2) · Visibility Debt (§5).
