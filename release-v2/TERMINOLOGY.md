# TERMINOLOGY.md — Canonical Glossary for the Detection Engineering Handbook (V2)

**Status:** Final, merged from two independently drafted glossary proposals for adoption before Part 1 ships.
**Applies to:** all 48 parts, all 7 appendices, all detections, and all hunts.

## How to use this file

This glossary is binding vocabulary for the entire book. Where a term gets fuller narrative treatment elsewhere, this entry is the short, load-bearing definition that chapter must not contradict — cross-referenced below via **Compatible with**. If a chapter's usage and this glossary disagree, the glossary wins and the chapter gets corrected, not the reverse.

- **Do not redefine these terms inline in a chapter.** Link back to this file (`see TERMINOLOGY.md § Alert`) instead of writing a competing one-liner. If a chapter's concept doesn't fit an existing entry, propose an addition here rather than inventing local vocabulary — with dozens of authors, one term defined several slightly different ways is the single biggest cause of reader confusion and contradictory cross-references.
- **First use in a chapter:** spell out an abbreviation once (`true positive (TP)`), then use the abbreviation freely.
- **Capitalization:** terms are Title Case only when used as the formal glossary term itself ("this is a **Benign Positive**, not a **False Positive**"); ordinary prose use is lowercase ("the alert was a benign positive").
- **See also / Do not confuse with** flags the specific adjacent term this one is most often collapsed into by mistake, or that combines with it — read both entries together before writing a chapter that leans on either.
- Terms are grouped by pipeline stage, not alphabetically, because most real confusion in this book comes from adjacent terms in the same stage (Alert vs. Incident vs. Case) rather than unrelated terms sharing a letter. An alphabetical index is at the bottom.

---

## 1. The Data Layer: Before Any Detection Logic Runs

### Event

A single, immutable, timestamped record of something that happened, as captured by an instrumented system — it exists whether or not any detection logic ever evaluates it.

*Example:* A Windows Security log record for Event ID 4624 showing an interactive logon by `jsmith` on `WIN-042` at `03:14:07 UTC` is one event, regardless of whether any rule ever evaluates it.

**See also:** Telemetry, Signal.

### Telemetry

The aggregate stream of events, at whatever fidelity, completeness, and retention a program has actually achieved, available to be queried — a statement about what data exists in the pipeline, not about what can be detected with it.

*Example:* "We ingest Sysmon Event IDs 1, 3, 10, and 11 from 92% of Windows endpoints, retained 90 days" describes telemetry. It says nothing about whether any analytic uses that data reliably.

**Do not confuse with:** Event (one record within the stream) or Signal (an interpreted property of an event).
**Compatible with:** Part 3, Part 4.

### Log Source

A single, named origin of telemetry with its own ingestion path, schema, retention policy, and owner (e.g., "Windows Security event log via Sysmon," "Okta System Log," "AWS CloudTrail," "Zeek `conn.log`") — the unit that telemetry coverage and schema drift are tracked against.

*Example:* "Azure AD Sign-In Logs" and "Azure AD Audit Logs" are two different log sources with different schemas, even though both come from the same platform.

**See also:** Telemetry, Schema Drift.

### Signal

A property of an event or event sequence that correlates with the malicious behavior a detection targets — weak on its own, and combined with other signals to raise Analytic Confidence or feed a Risk Score. Not itself a verdict.

*Example:* The presence of `-EncodedCommand` on a PowerShell invocation is a signal for obfuscated execution; alone it is not evidence of compromise, since legitimate config-management tooling produces the same signal.

**Do not confuse with:** Event (the record a signal is a property of).
**See also:** Analytic, Correlation, Analytic Confidence, Noise (the legitimate activity that also carries a given signal — the reason no single signal is used unqualified).
**Compatible with:** Part 1 §"Signals, Noise, and Confidence"; Part 33 (Risk-Based Detection).

---

## 2. From Idea to Deployed Capability

### Threat Hypothesis

A specific, falsifiable statement about an adversary behavior — with a subject, a behavior, and an implied negation — written down *before* any query is run or any rule designed. Seeds either a Hunt or the design of a new Analytic.

*Example:* "A domain account with no prior administrative history on Host X should not authenticate interactively to Host X and then launch `rundll32.exe`." ("Let's look at logon events" is a topic, not a hypothesis — it has no pass/fail condition.)

**Compatible with:** Part 1 (detection lifecycle, stage 1); Part 34.

### Data Feasibility

The lifecycle check — performed before designing analytic logic — of whether the required telemetry actually exists, at the needed fidelity, from the needed hosts, for long enough retention. Skipping it is the most common reason a "detection" exists only on paper.

**Compatible with:** Part 1 (detection lifecycle, stage 2); Part 3, Part 4.

### Use Case

The business, risk, or compliance justification for detecting a given behavior area at all — a program-level grouping of one or more Analytics tied to a named driver (a top threat, a regulatory control, a prior incident), owned and reviewed at the program level rather than the rule level.

*Example:* "Detect credential theft from memory" is a use case; it may be satisfied by several distinct analytics (LSASS access, DCSync abuse, Kerberos ticket forging), not by one rule.

**Compatible with:** Part 1 §"Detection Rule vs. Analytic vs. Use Case vs. Hunt."

### Analytic

The implementation-independent logical statement of what pattern in telemetry indicates a targeted behavior — the design, validated as logic first, before being written in any specific query language or deployed as a rule. One analytic may be implemented as several platform-specific Detection Rules.

*Example:* "A process other than LSASS itself, not on an approved allowlist, opens a handle to `lsass.exe` with access rights sufficient for memory reading" is an analytic; the Sigma/KQL/SPL query that implements it in your specific SIEM is the Detection Rule.

**Do not confuse with:** Detection Rule (platform-specific implementation), Use Case (the business justification the analytic serves).
**Compatible with:** Part 1; Part 23 (Query Language Strategy).

### Detection Rule

The literal, deployed, versioned logic (a Sigma rule, a SIEM correlation search, a KQL scheduled query, a YARA-L rule) that evaluates live telemetry and produces alerts, implementing one or more Analytics — with its own lifecycle (deployed, tuned, deprecated) distinct from the analytic it implements.

*Example:* The Sysmon Event ID 10 (`ProcessAccess`) correlation search deployed in the SIEM, with your environment's specific EDR/AV allowlist, is the detection rule that implements the LSASS-access analytic above.

**Compatible with:** Part 1; Part 22 (Detection-as-Code).

### Detection

The general term for the deployed, owned, and maintained capability that turns telemetry into an alert for a specific adversary behavior — encompassing both the Analytic (the logic) and the Detection Rule (the implementation), plus the ownership, testing, and review that keep it correct over time. Use "detection" for the capability as a whole, and reach for "analytic" or "detection rule" when the distinction between logic and implementation matters to the sentence. It is only a synonym for "detection rule" in casual shorthand, which this book avoids.

*Example:* "This detection has a documented false-positive rate, an owner, and a review date" is a statement about the whole capability, not specifically about the query text.

**Compatible with:** Part 1; Part 41 (Detection Coverage).

### Detection-as-Code

Managing detection logic — Analytics and the Detection Rules that implement them — with the same engineering discipline as application software: version control, peer review, automated true/false-positive testing, CI/CD deployment, and rollback, instead of direct, unreviewed edits in a vendor console.

*Example:* Sigma rules stored in a git repository, linted, and replayed against a stored true-positive/false-positive test corpus by CI on every pull request before merge.

**Compatible with:** Part 1 §"Detection-as-Code"; Part 22.

### Hunt

A time-boxed, hypothesis-driven, human-led investigation into a behavior with no reliable standing detection (or one that may never get one), conducted to prove or disprove a Threat Hypothesis against real telemetry in the absence of a fired alert. Must end in either a documented negative finding (naming the coverage gap it exposed) or a new detection candidate — never in "nothing found, moving on" with no artifact left behind. Distinct from a Detection Rule in that it is manual and time-boxed, not automated and continuous.

*Example:* A hunter tests whether WMI-based lateral movement would evade the existing RDP-only lateral-movement rule, confirms it would, and files a new analytic candidate.

**Compatible with:** Part 34–36.

---

## 3. The Alert Lifecycle and Triage Outcomes

### Alert

The specific, timestamped output instance produced when a deployed Detection Rule's conditions are met against telemetry, entering an analyst's (or automated responder's) queue for disposition. An alert is a claim that something *might* be malicious, not a confirmed judgment — one detection rule produces many alert instances over its lifetime.

*Example:* A SIEM correlation search matches a process-access event and opens a queue item titled "Suspicious Process Access to LSASS Memory — HOST01," awaiting analyst disposition.

**Do not confuse with:** Detection (the capability that produced the alert), Incident (a confirmed event the alert may escalate into).
**Compatible with:** Part 37 (Detection Testing).

### Triage

The analyst (or automated) process of examining an Alert's context — source, entity, prior history, related alerts — to reach a Disposition, before any formal Case or Incident is necessarily opened.

*Example:* An analyst pulls the parent process, the account's baseline, and the destination host's criticality for a new alert within minutes of it firing, and closes it as a false positive without opening a case.

**See also:** Disposition, Case.

### Disposition

The recorded outcome an analyst (or automated logic) assigns to a closed Alert — True Positive, Benign Positive, False Positive, or Unable to Determine. Every quality metric in this book (precision, recall, Analytic Confidence, tuning backlog) is built from disposition data; an alert without a disposition is not usable for any of them.

*Example:* An alert closed with disposition `benign_positive`, reason code `authorized_pentest`, feeds both the rule's confidence history and, if the reason code recurs, a Tuning ticket.

**Compatible with:** Part 42 (Detection Quality).

### Case

The tracked unit of investigation — in a SOAR/ticketing system — that bundles one or more related Alerts, evidence, and analyst actions under a single owned working record, and which may resolve as benign, false positive, or escalate into a declared Incident. A case is the *investigative container*; an incident is a *declared, impact-bearing event*, and not every case escalates to one.

*Example:* Three correlated alerts on the same host within one hour are grouped into a single case for investigation; the case closes as benign before ever becoming an incident.

**Do not confuse with:** Incident.
**See also:** Alert, Triage.

### Incident

A confirmed, or reasonably suspected and formally declared, security event — potentially built from one or more Alerts plus non-alert reporting (a user report, a third-party notification) — managed through a defined incident-response process because it represents actual or credible likely adverse impact.

*Example:* Ransomware encryption is confirmed on twelve hosts; the IR team is activated and a formal incident timeline begins.

**Do not confuse with:** Case (the container investigators work in — an incident is a specific, more consequential outcome a case can escalate to), Alert (a single queue item, of which an incident may involve many).

### Escalation

The formal act of moving an Alert or Case to a higher-severity handling track — most commonly, tier-2/IR/threat-hunting review — with an associated change in stakeholders and urgency. Escalation is a workload/skill routing decision, and it does **not**, by itself, mean the alert or case has become a declared Incident; a case can be escalated to a senior analyst and still close as benign.

*Example:* An analyst dispositions an alert "unable to determine" and escalates it to tier-2 for deeper investigation; tier-2 later closes it as benign without ever declaring an incident.

**Do not confuse with:** Incident (a specific, declared outcome — escalation is a routing step that may or may not lead there).
**See also:** Case, Priority.

### True Positive (TP)

An alert Disposition indicating the detection rule's logic matched correctly *and* the matched activity is genuinely malicious, unauthorized, or otherwise the exact thing the analytic was built to catch.

*Example:* The LSASS-access rule fires because Mimikatz's `sekurlsa::logonpasswords` module actually ran on the host.

**See also:** Benign Positive, False Positive, Precision.

### Benign Positive (also: Benign True Positive, BTP)

An alert Disposition indicating the detection rule's logic matched **correctly** — the described condition genuinely occurred, exactly as the rule specifies — but the underlying activity is legitimate, authorized, or otherwise not a security problem in context. Distinguished from a False Positive by *where the correctness lives*: a benign positive means the logic is right and the activity is benign; a false positive means the logic itself is defective.

*Example:* An authorized penetration tester runs a credential-dumping tool during a scoped, approved engagement and trips the LSASS-access rule exactly as the rule is designed to catch — the match is correct; the activity carries no risk.

**Normalization note:** Some chapters use "benign true positive" and "benign-true-positive" as identical to this concept — treat them as synonyms; standardize new content on "Benign Positive."
**Do not confuse with:** False Positive, True Positive.
**See also:** Precision, Tuning, Exception.

### False Positive (FP)

An alert Disposition indicating the detection rule's logic itself is defective for the case at hand — it matched activity that does not represent the behavior the analytic claims to detect, because the condition is too broad, mis-targeted, or coincidentally satisfied by unrelated activity. Distinct from a Benign Positive, where the logic is correct and only the intent is benign.

*Example:* A rule chaining "any 4672 (privileged logon) followed by any 4688 (process creation) within 5 minutes" fires on essentially every routine admin login and scheduled task, because the logic never actually discriminates attack activity from routine administration.

**Do not confuse with:** Benign Positive.
**See also:** True Positive, Precision, Tuning, Suppression.
**Compatible with:** Part 38 (False Positive Engineering).

### False Negative (FN)

Malicious or policy-violating activity that met the criteria an analytic was intended to catch but produced no alert — typically discovered after the fact via an incident post-mortem, red-team exercise, or hunt. The failure mode alert-count and precision metrics are structurally blind to, because a false negative produces no record at all.

*Example:* An attacker uses a LOLBin not on the rule's allowlisted set; the LSASS-access analytic's logic never evaluates true, despite a real credential-theft attempt occurring.

**See also:** Recall, Testing Debt, Visibility Debt, Detection Debt.
**Compatible with:** Part 39 (False Negative Engineering); Part 42 §"Recall."

---

## 4. Tuning and Noise Control

### Suppression

Any mechanism — allowlist, maintenance window, known-benign-source exclusion, deduplication window, risk-score gating — that prevents an otherwise-matching alert condition from ever reaching an analyst, **without altering the underlying detection logic itself**.

*Example:* Alerts from a known vulnerability scanner's IP range are filtered before reaching the queue via an allowlist rule; the rule still evaluates true underneath.

**Do not confuse with:** Tuning (changes the detection's own logic).
**See also:** Exception.
**Compatible with:** Part 42 §"Suppression rate."

### Exception

One specific, named, and time-bounded carve-out from a detection's normal behavior — scoped to a particular entity or pattern, with a documented justification and a review/expiry date — written into the detection rule's own logic (as opposed to Suppression, which filters an alert after the rule already matched). This is the accountable unit that suppressions should be tracked as individually, not as an anonymous filter list; an undocumented exception is exactly what turns into Tuning Debt.

*Example:* "Exception EX-0417: exclude service account `SVC-BKUP01` from the off-hours-logon rule; justification: nightly backup job; review date 2026-12-31."

**Compatible with:** Part 42 §"Suppression rate" (exclusions need the same last-reviewed-date discipline as detection rules themselves); Part 43 (Detection Debt).

### Tuning

A deliberate, logged change to a detection rule's logic, thresholds, or exclusions, made in response to observed false-positive or false-negative patterns from accumulated Disposition data, recorded with a reason and a date. Tuning changes what the rule matches; Suppression changes what reaches the analyst without touching the rule.

*Example:* Adding a `filter_known_tools` block excluding `ProcessHacker.exe` and `Taskmgr.exe` from the LSASS-access rule after a month of false positives.

**Do not confuse with:** Suppression.
**Compatible with:** Part 42 §"Tuning frequency"; Part 43 §"Tuning Debt."

### Alert Fatigue

The measurable degradation in analyst scrutiny and response speed from sustained exposure to a high volume of low-value (mostly False Positive or repetitive Benign Positive) alerts, which increases the risk that a genuine True Positive is triaged carelessly or dismissed by pattern-matching against the usual noise.

*Example:* A rule that fires 200 times a day on a known-benign backup job desensitizes the on-call analyst enough that a genuinely malicious use of the same pattern, on the 201st alert that week, gets closed in ten seconds without real review.

**See also:** Tuning Debt, Precision, Disposition.

---

## 5. Coverage, Telemetry, and the Debt That Accrues Against Both

### Coverage

The dangerously ambiguous umbrella claim that some part of the environment is "monitored" or "defended." **Bare "coverage" is an incomplete sentence in this book** — always qualify it as Telemetry Coverage, Detection Coverage, or a named tier on the six-tier scale below.

*Example:* Do not write "we have coverage for lateral movement." Write "RELIABLE DETECTION coverage for T1021.001 on the Windows fleet; TELEMETRY ONLY for T1021.006 (WinRM)."

**Compatible with:** Part 41.

### Telemetry Coverage (also called Log Coverage)

Whether data from a given source or technique surface exists in the pipeline at all, at some retention and field fidelity — a statement about data presence, not detection capability.

*Example:* "We collect Windows Security event logs (4624, 4625, 4672, 4688) from all domain-joined hosts" is a telemetry coverage statement. It says nothing about whether any rule can reliably act on that data.

**See also:** Detection Coverage, Visibility Debt, Log Source.
**Compatible with:** Part 3, Part 4.

### Detection Coverage

Whether a tested, tuned, owned Analytic exists that can reliably identify a specific adversary behavior, at an acceptable false-positive rate, using telemetry that is actually available. Implies a working, validated detection, not merely a data source sitting in the SIEM.

*Example:* "We can reliably detect an interactive/RDP logon with no 30-day account-host history followed by LOLBin execution, with a validated false-positive rate against production data" is a detection coverage statement.

**Standard expression — six-tier scale.** Report detection coverage as a distribution across these six tiers, never as a single aggregate percentage:

1. **NO VISIBILITY** — no telemetry exists; a collection gap, not a detection gap.
2. **TELEMETRY ONLY** — logged, no analytic built against it; a detection-backlog item (= Visibility Debt).
3. **PARTIAL DETECTION** — a rule exists with known evasion paths.
4. **RELIABLE DETECTION** — acceptable false-positive rate, but a single telemetry source.
5. **MULTI-SOURCE DETECTION** — two or more independent sources would catch it.
6. **TESTED / RECENTLY VALIDATED** — proven via Adversary Emulation within a defined recency window (e.g., 90 days).

**See also:** Telemetry Coverage, Use Case, Analytic Confidence.
**Compatible with:** Part 1 §"Detection Coverage vs. Log Coverage"; Part 41 (full six-tier matrix structure).

### Visibility Debt

The accumulating, named gap between Telemetry Coverage and Detection Coverage: log sources you collect but have not yet built, tested, or validated any analytic against. A form of Detection Debt that looks like progress on a source-count dashboard while contributing nothing to actual detection capability.

*Example:* Onboarding a new cloud audit-log source increases the "sources ingested" count on a coverage dashboard even though zero analytics use it yet — that gap is visibility debt, invisible on a dashboard that only counts sources.

**See also:** Telemetry Coverage, Detection Coverage, Detection Debt.

### Detection Drift

The gradual divergence between what a rule was designed to catch and what it actually catches now, caused by changes in adversary tradecraft, the environment, or both. No single clean metric exists for it — only proxies (declining alert volume with no environmental explanation, false negatives later traced to a rule that should have fired).

**Do not confuse with:** Schema Drift (a data-format change; detection drift is a behavioral/relevance change, which schema drift can be one cause of but is not the only cause).
**Compatible with:** Part 42 §"Detection drift"; Part 43.

### Schema Drift

A change in a Log Source's field names, types, encoding, or value distribution — from a vendor update, an agent migration, or an API version change — that silently invalidates a Detection Rule's field references without producing any ingest error, because "zero matching events" is a valid result for almost every query language.

*Example:* A cloud provider renames `src_ip` to `source.ip` between API versions; a rule querying the old field name compiles, runs, and returns nothing, with no error raised anywhere.

**See also:** Log Source, Detection Debt, Testing Debt.
**Compatible with:** Part 5 (Parsers); Part 37 (Detection Testing).

### Detection Debt

The umbrella term for the accumulated gap between what a detection stack *appears* to cover (rule count, coverage spreadsheet, MITRE percentage) and what it *actually* covers correctly, reliably, and at acceptable noise right now. It fails silently by default — a broken detection produces zero alerts, which looks identical to "the technique isn't happening" — which is what distinguishes it from ordinary software technical debt. Five commonly tracked sub-types:

- **Telemetry debt** — assumed fields/sources stop flowing as assumed.
- **Parser debt** — fields are null or mis-mapped while ingest volume looks healthy.
- **Documentation debt** — rationale, false-positive notes, and dependencies were never recorded.
- **Testing debt** — no scheduled re-verification against current telemetry or environment changes.
- **Tuning debt** — known false-positive sources identified repeatedly but never fed back into the rule.

*Example:* An EDR migration truncates a `CommandLine` field to a shorter length than the previous agent; a rule matching against the untruncated field goes silent with zero errors and zero new false positives — reading as "clean" rather than "broken" until a red-team exercise finds the gap eighteen months later, having simultaneously accrued telemetry, testing, and documentation debt.

**Compatible with:** Part 43.

### Rule Failure Rate

The fraction of deployed rules that are, at a given time, silently broken — syntax errors, schema-mismatched field references, or scheduled searches failing without alerting on their own failure. A pipeline-health metric, not a detection-quality one.

**Compatible with:** Part 42 §"Rule failure rate."

### Precision

The fraction of an analytic's alerts that were correct: `TP / (TP + FP)`. Benign Positives are typically excluded from the FP term, since the logic matched correctly — check and state your program's convention explicitly, since an unqualified `TP / (TP + FP + BP)` calculation yields a different, lower number. Answers "when this fires, how often is it right"; says nothing about what the analytic is missing.

*Example:* An analytic with 40 closed alerts — 30 true positives, 8 benign positives, 2 false positives — has a precision of 30/32 ≈ 94% if benign positives are excluded from the error term.

**See also:** Recall, Analytic Confidence, Disposition.
**Compatible with:** Part 42.

### Recall

The fraction of actually-malicious activity an analytic (or the program as a whole) successfully alerted on, out of all such activity that occurred — measurable only against known Ground Truth, and in practice always really "recall against intrusions we know about," a lower bound conditioned on the program's own detection and hunting capability, not a true statistical recall.

*Example:* A red-team exercise executes ten techniques; six trigger an alert. Measured recall for that exercise is 60% — a sample-bound estimate, not a program-wide guarantee.

**Do not confuse with:** Ground Truth (the unresolved problem underneath this and every other quality metric).
**See also:** False Negative, Precision, Testing Debt.
**Compatible with:** Part 42.

### Ground Truth

The (never fully available) knowledge of which events were actually malicious and which were not. Every Recall figure this book reports is really "recall against the intrusions we know about" — a lower bound biased by the strength of your own hunting and IR program, not a true statistical recall.

**Compatible with:** Part 42 §"Ground truth."

---

## 6. Correlation, Baselines, and Entities

### Correlation

Detection logic that produces a verdict from a combination of two or more individually low-signal events, typically joined on a shared Entity Key within a bounded Correlation Window, where no single constituent event would justify an alert on its own.

*Example:* A failed VPN authentication, followed by a successful one from a new device, followed by first-time access to a sensitive file share — each event unremarkable alone, joined on account identity within a 30-minute window.

**See also:** Entity, Entity Key, Correlation Window, Signal, Risk-Based Alerting.
**Compatible with:** Part 30.

### Correlation Window

The bounded span of time within which two or more events must occur, relative to each other, to be considered part of the same correlated chain.

*Example:* A logon event and a subsequent LOLBin execution must occur within 10 minutes of each other on the same host to satisfy the correlation condition.

**Compatible with:** Part 30.

### Baseline

A statistical or rule-based model of "expected" values for a given Entity (user, host, role, peer group, service account, application, network segment, time, geo) over a defined feature set, built from historical observation over a stated time window with an explicit update/decay policy, against which new observations are scored for deviation rather than matched against a fixed signature.

*Example:* A per-user 30-day rolling model of typical logon hours and source ASNs, scored as a "seen before / never seen before" boolean at query time.

**Compatible with:** Part 31.

### Entity

The identifiable "thing" being tracked, baselined, or risk-scored across telemetry sources — a user, host, service account, cloud identity/principal, session, or peer group — resolved across sources via an Entity Key.

*Example:* A Sysmon `ProcessGuid` is the entity key that ties a single process's creation event to its own subsequent network connections and child processes.

**Compatible with:** Part 30 §"Entity keys"; Part 31.

### Entity Key / Entity Resolution

An entity key is the field, or combination of fields, used to assert that two events concern the same Entity. Entity resolution is the broader practice — and frequent failure point — of reliably mapping identifiers (IP, hostname, session ID, cloud principal) to a single consistent entity across sources that represent identity differently. This is the mechanism that makes Correlation and Baselining possible, and the thing most likely to silently break a correlation when it changes format, resets (a session ID that recycles), or isn't available at the same fidelity across every joined source.

*Example:* Joining a failed-logon event to a subsequent success by account + source IP, then joining that success to a process-creation event by logon session ID, because no single key survives across all three event types; `AccountName + DomainName` may be a stable key on-prem but needs to be resolved against a cloud identity's `object_id` before joining to Azure AD sign-in logs for the same user.

**Compatible with:** Part 30 §"Entity keys."

### Enrichment

Additional context attached to an event, alert, or entity from a source outside the original telemetry — asset criticality, user role, prior alert history, threat-intel reputation — applied inline in detection logic or at triage time, to raise or lower Analytic Confidence without changing the core matching logic, and to convert a technically-anomalous-but-ambiguous signal into something an analyst can act on without manual pivoting.

*Example:* Attaching asset-criticality tier and 30-day account-host baseline status to an alert automatically, rather than requiring the analyst to look both up by hand.

**Compatible with:** Part 34 (hunt methodology stage "Enrichment"); Part 42 §"Analyst handling time."

### Risk-Based Alerting (RBA) / Risk Score

An alerting model in which individual weak Signals — each independently far below any reasonable alerting threshold — contribute points to a running risk score for an Entity over a time window, and an alert fires only when the accumulated score crosses a threshold, rather than any single signal firing a standalone rule.

*Example:* An off-hours VPN login (+20), an unusual PowerShell script execution (+10), and access to a sensitive share the account rarely touches (+15) sum to 45 for one account in one session; an alert fires only because the combined score crossed the program's threshold, not because any one signal did.

**Compatible with:** Part 33.

---

## 7. Confidence, Severity, and Priority — Three Different Axes

Authors routinely collapse these three into one number. Keep them separate: they answer different questions and can move independently — a high-severity, low-confidence alert and a low-severity, high-confidence alert require very different triage treatment, and a high-severity/high-confidence alert on a routine workstation may still rank below a lower one on a domain controller.

### Analytic Confidence

A measured — not assumed at authoring time — estimate of how likely a given Analytic's alert instances represent genuinely malicious activity, derived from accumulated Disposition history (TP/BTP/FP rates over a defined rolling window) and revised as more disposition data arrives. Answers "historically, how often is *this analytic* right"; a property of the analytic, not of any single alert instance, and a distinct axis from Detection Coverage (whether a technique is covered at all) and Severity (impact if true).

*Example:* A hard-coded Mimikatz command-line-string match carries higher analytic confidence than a generic "packed executable" YARA heuristic, and that confidence figure is revised monthly from real disposition data rather than fixed at rule-authoring time.

**Do not confuse with:** Severity, Coverage Level.
**Compatible with:** Part 33 §"Detection confidence."

### Severity

An assessment of how bad the underlying behavior would be *if* the alert is a true positive — a property of the technique/impact, largely independent of how confident you are that this particular instance actually is one.

*Example:* "Domain Admin credential dumping" is high severity regardless of whether a given alert instance turns out to be a real attacker or an authorized pentester — the potential impact of the behavior, if real, doesn't change.

**See also:** Analytic Confidence, Priority.

### Priority

The operational ranking that determines which alerts an analyst works first — typically a function combining Severity, Analytic Confidence, and Entity criticality (asset value, business context), computed per alert instance rather than being a fixed property of the rule.

*Example:* A high-severity, high-confidence alert on a routine workstation may rank below a medium-severity, medium-confidence alert on a domain controller, if the queue's priority function weights entity criticality heavily.

**See also:** Severity, Analytic Confidence, Entity, Escalation.

---

## 8. Testing, Validation, and Response Process

### Adversary Emulation / Atomic Test

Adversary emulation is the controlled, known-plan execution of a specific technique (via a red team, purple team, or a scoped tool like Atomic Red Team or Caldera) used to produce a "Last Validation" result for a detection or coverage-matrix row. An atomic test is the smallest such unit — one technique, executed the same way, repeatably — re-run on a schedule or after any environment change to catch Testing Debt before an incident does.

*Example:* Re-running the same Atomic Red Team T1055.012 test after an EDR migration to confirm the process-hollowing rule still fires against the new agent's telemetry.

**Compatible with:** Part 35–36; Part 41.

### MITRE ATT&CK Technique / Sub-technique

A technique (e.g., T1055) and its sub-techniques (e.g., T1055.012) are the standard external taxonomy this book uses to scope, tag, and report coverage. Sub-technique-level tracking is required wherever coverage is reported, since parent-technique-only coverage claims obscure which specific implementation paths are and are not detected.

*Example:* A rule tagged only `attack.t1055` with no sub-technique is not specific enough for a coverage matrix row.

**Compatible with:** Part 41; see also the MITRE ID formatting rules in `STYLE-GUIDE.md` §5.

### IOC vs. IOA vs. TTP

Three related but distinct terms for describing "what you match on," in increasing order of durability against attacker change:

- An **IOC (Indicator of Compromise)** is a specific, low-durability artifact — a hash, domain, IP, mutex name — that an attacker can trivially change; it stops working the moment the artifact changes.
- An **IOA (Indicator of Attack)** is a behavior-based indicator of intent or technique (e.g., "process injection into a browser followed by outbound beaconing") that survives artifact changes because it targets the underlying action, not a fingerprint of one occurrence of it.
- A **TTP (Tactic, Technique, Procedure)** is the broader ATT&CK-level framework for describing that same durable behavior at a standardized, cross-organization taxonomy level — the vocabulary IOAs and behavior-based/correlation-based detections are usually built and reported against.

Signature/IOC matching still has value for high-confidence hits on reused commodity infrastructure, but degrades to zero the moment the artifact changes — this is the core argument for building durable detection around IOAs and TTPs rather than IOC lists alone.

*Example:* A known-bad C2 domain is an IOC; "DNS queries with high subdomain entropy at a fixed interval regardless of domain" is an IOA; "T1071.004 (DNS)" is the TTP-level classification both the IOA and any specific IOC instance of it roll up to.

**See also:** Signal.
**Compatible with:** Part 1 §"Behaviour-Based vs. Signature-Based vs. Correlation-Based vs. Risk-Based Detection."

### Dwell Time

The elapsed time between an adversary gaining a foothold in an environment and that presence being detected, by any means — a rule, a hunt, an external notification. The outcome metric Detection Coverage, Visibility Debt, and Recall all ultimately exist to reduce, used as a program-level metric rather than a per-rule one.

*Example:* A retrospective hunt against 90 days of retained logs, triggered by a new IOC disclosure, finds an intrusion that had been present for 40 days before any alert fired — that 40 days is dwell time the standing detection stack failed to close.

**See also:** Recall, Detection Coverage, Hunt.

### Playbook vs. Runbook

A **playbook** is the decision logic for how to respond to a category of alert or incident (what to check, in what order, what determines escalation) — the "what to decide." A **runbook** is the step-by-step, largely mechanical procedure for executing a specific action (how to isolate a host, how to rotate a credential, how to query a specific data source) — the "how to execute." A playbook may call several runbooks.

*Example:* The "suspected ransomware precursor" playbook tells an analyst when to isolate a host; the "endpoint isolation" runbook tells them exactly which console, which button, and what to verify afterward.

**See also:** Incident, Escalation.

---

## Alphabetical Index

Adversary Emulation / Atomic Test (§8) · Alert (§3) · Alert Fatigue (§4) · Analytic (§2) · Analytic
Confidence (§7) · Baseline (§6) · Benign Positive / Benign True Positive (§3) · Case (§3) · Correlation
(§6) · Correlation Window (§6) · Coverage (§5) · Data Feasibility (§2) · Detection (§2) ·
Detection-as-Code (§2) · Detection Coverage (§5) · Detection Debt (§5) · Detection Drift (§5) ·
Detection Rule (§2) · Disposition (§3) · Dwell Time (§8) · Enrichment (§6) · Entity (§6) · Entity Key /
Entity Resolution (§6) · Escalation (§3) · Event (§1) · Exception (§4) · False Negative (§3) · False
Positive (§3) · Ground Truth (§5) · Hunt (§2) · Incident (§3) · IOC vs. IOA vs. TTP (§8) · Log Source
(§1) · MITRE ATT&CK Technique / Sub-technique (§8) · Playbook vs. Runbook (§8) · Precision (§5) ·
Priority (§7) · Recall (§5) · Risk-Based Alerting / Risk Score (§6) · Rule Failure Rate (§5) · Schema
Drift (§5) · Severity (§7) · Signal (§1) · Suppression (§4) · Telemetry (§1) · Telemetry Coverage (§5)
· Threat Hypothesis (§2) · Triage (§3) · True Positive (§3) · Tuning (§4) · Use Case (§2) · Visibility
Debt (§5).
