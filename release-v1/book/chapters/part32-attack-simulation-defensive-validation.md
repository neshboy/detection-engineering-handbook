# Part XXXII — Attack Simulation for Defensive Validation

## Scope and Authorization Boundary

Everything in this chapter assumes a written, authorized test scope: a defined environment you
(or your organization) own or have explicit written permission to test, a defined time window, a
named approver, and a rollback/communication plan. Atomic Red Team tests, purple team exercises,
breach-and-attack-simulation (BAS) platforms, and adversary emulation frameworks like MITRE Caldera
execute real (if often benign-payload) attacker techniques — process injection, credential access
API calls, lateral movement primitives, persistence mechanisms. Run against a system you don't own
or outside an approved scope, several of these techniques are indistinguishable from an actual
intrusion and, depending on jurisdiction, from a computer crime.

None of what follows is instruction for compromising third-party systems. It is instruction for
finding out whether your own detections work, in an environment where you have the authority to
find that out. If you're reading this to figure out how to test somebody else's network — stop; get
a signed authorization first, or don't do it.

[MANAGEMENT] The authorization boundary is not a formality to route around quickly. Legal and
compliance should sign off on scope before any technique executes, especially in regulated
environments (PCI, HIPAA, FedRAMP) where "we ran a credential-dumping simulation on the domain
controller" needs to be a pre-approved, documented activity — not something discovered in a
post-incident review of your own EDR logs.

## Why Validate Detections At All

A detection rule that has never been tested against the behaviour it claims to catch is a
hypothesis, not a control. Three things drift constantly and silently:

- **The environment drifts.** Endpoint agents get reconfigured, log sources get re-piped, field
  names change after a SIEM migration, EDR policies get "temporarily" loosened and never restored.
- **The adversary drifts.** Technique implementations change (a new LOLBIN, a new PowerShell
  obfuscation pattern, a new credential-dumping tool that doesn't touch LSASS the same way
  Mimikatz does).
- **The rule drifts from its own intent.** Someone tunes a rule to kill a false-positive storm and,
  six months later, nobody remembers the tuning also killed the true-positive path.

Attack simulation is how you catch all three before an incident does. It converts "we have a rule
for T1003" into "we ran a controlled LSASS-dump technique on a domain-joined test host on
2026-09-10 and the rule fired within 90 seconds, with this exact telemetry."

```mermaid
flowchart TD
    A[Define hypothesis: "we should detect X"] --> B[Select technique + ATT&CK ID]
    B --> C[Authorize scope: host, window, approver]
    C --> D[Execute controlled technique]
    D --> E{Telemetry generated?}
    E -- No --> F[Telemetry/pipeline gap: fix collection first]
    E -- Yes --> G{Detection fired?}
    G -- No --> H[Detection logic gap: tune or write rule]
    G -- Yes --> I{Fired with usable context, on time?}
    I -- No --> J[Alert quality gap: enrich, dedupe, speed up]
    I -- Yes --> K[Record result, timestamp, evidence]
    K --> L[Feed into coverage matrix / ATT&CK Navigator]
    F --> B
    H --> B
    J --> B
```

## Atomic Red Team-Style Controlled Testing

[CONCEPT] Atomic Red Team (Red Canary) is a library of small, single-technique test cases mapped
to MITRE ATT&CK — each "atomic test" executes one narrow behaviour (e.g., dumping LSASS with a
named tool, creating a scheduled task with a specific command pattern) and nothing else. The point
is isolation: if a detection fails, you know which technique failed, not "something in a 40-step
attack chain broke somewhere."

[DETECTION ENGINEER] The workflow is: pick an ATT&CK technique your coverage matrix claims to
cover, find (or write) the corresponding atomic test, run it on an instrumented test host, and
check whether the expected telemetry and the expected detection both fired. Atomic Red Team tests
are shell/PowerShell/bash snippets with declared prerequisites (tools that must be present,
privileges required) and declared cleanup steps — always run the cleanup step, or the test host
accumulates artifacts (scheduled tasks, registry keys, dropped binaries) that pollute your next
test run and your baseline.

**What atomic testing is reliable for:**
- Confirming a specific technique produces the expected raw event (does Sysmon actually log Event
  ID 10 with the access mask you assumed when LSASS is touched by this specific tool?).
- Confirming a rule's logic matches reality (field names, casing, exact command-line syntax).
- Regression testing after a SIEM/EDR upgrade, agent version bump, or parser change.

**What it does not validate:**
- Chained, multi-stage attacker behaviour — an atomic test is one technique, not a campaign. A
  detection that only fires on the full chain (e.g., correlation across five events) will look
  "broken" against a single atomic test and that's expected, not a failure.
- Evasive variants. Off-the-shelf atomic tests are public and well-known; a real adversary
  targeting your organization has almost certainly read the same GitHub repo you have and will
  vary the command line, the process ancestry, or the tool. A pass on the stock atomic test tells
  you the naive version is covered — nothing about obfuscated or renamed variants.
- Anything about detection *quality* under load — atomic tests run in a quiet lab don't tell you
  whether the rule survives 50,000 events/second of legitimate admin scripting noise in
  production.

**Hunter's Note:** Running the stock Atomic Red Team test for a technique and declaring victory
because the SIEM lit up is the single most common false sense of coverage in this industry. Always
ask: would this rule still fire if the attacker renamed the binary, changed one flag, or ran it
from a different parent process? If you don't know, you haven't validated the *technique*, you've
validated *one specific command line*.

## Purple Team Exercises

[CONCEPT] A purple team exercise is a collaborative session where an offensive operator (red)
executes techniques in real time while the detection/SOC team (blue) watches their own tooling live
and reports, in the moment, what did or didn't fire. Unlike a traditional red team engagement
(where blue is kept in the dark and success is measured by whether red got caught), the entire
point of purple teaming is transparency — the outcome is a coverage map, not a "gotcha."

A working purple team cadence looks like:

1. **Scoping meeting.** Pick 5-15 techniques (not the whole ATT&CK matrix in one session — depth
   over breadth). Prioritize by threat-intel relevance to your sector, gaps flagged in the last
   exercise, or techniques used in a recent real incident.
2. **Execution, technique by technique.** Red announces intent ("executing T1055 process
   injection via technique X now"), executes, blue confirms in real time whether telemetry arrived
   and whether a detection fired, and both sides capture timestamps.
3. **Immediate gap triage.** For anything that didn't fire: is it a telemetry gap (event never
   generated or never reached the SIEM), a logic gap (event arrived, rule didn't match), or a
   tuning gap (rule matched but was suppressed by a threshold/allowlist)?
4. **Written outcome, mapped to ATT&CK.** Update a coverage matrix (see table below) with pass/fail/
   partial per technique, owner for the fix, and a re-test date.

| Technique (ATT&CK) | Test executed | Telemetry arrived? | Detection fired? | Time to fire | Gap type | Owner |
|---|---|---|---|---|---|---|
| T1003.001 – LSASS Memory | Atomic test #1, comsvcs.dll MiniDump | Yes (Sysmon EID 10) | Yes | 47s | none | — |
| T1053.005 – Scheduled Task | Atomic test #3, schtasks /create | Yes (EID 4698) | No | n/a | logic gap: rule required admin-share path | Detection eng |
| T1071.001 – Web C2 | Custom beacon simulation | Partial (proxy log only, no TLS SNI) | No | n/a | telemetry gap: no SNI logging | Network eng |

[SOC Management View] Purple team exercises are cheap relative to their output and should run more
often than the yearly-audit cadence most programs default to. A half-day session covering ten
techniques with two analysts and one operator produces a coverage matrix that a compliance-driven
annual pen test rarely produces, because the pen test report tells you "we got domain admin" and
not "your T1053 rule required an admin-share path that real attackers rarely use." Budget for
purple teaming as a recurring line item, not a one-time project.

## Breach-and-Attack-Simulation (BAS) Platforms

[CONCEPT] BAS platforms (commercial and open-source, e.g., MITRE Caldera as a free adversary
emulation framework) automate what a purple team does manually: schedule technique execution
against agents deployed on test hosts, and report pass/fail against your detection stack on a
recurring basis — daily, weekly, or continuously.

**What BAS platforms genuinely add over ad hoc atomic testing:**
- Continuous, scheduled re-validation, so a detection that regresses after next Tuesday's EDR
  policy change gets flagged within a day, not at next year's purple team session.
- Broader technique libraries with less manual scripting overhead.
- Reporting dashboards that management can actually read.

**Real limitations, stated plainly:**
- Vendors tune their own agents to be recognizable/safe, which means some BAS execution patterns
  are themselves distinguishable from a real attacker's tooling — a detection that keys on "this
  exact BAS agent's process ancestry" can look like a pass in the tool's dashboard while providing
  zero real-world coverage.
- Continuous execution against production-adjacent hosts needs the same authorization discipline
  as any other test — "it's just the BAS tool, it runs every day" is not a substitute for scoped
  approval, especially for techniques that touch credential stores or make outbound network
  connections.
- Licensing cost and agent deployment overhead are real; a small team without dedicated capacity to
  triage daily BAS output will let failed runs pile up unreviewed, which is worse than not running
  it — it produces a false paper trail of "we test daily" with nobody looking at the results.

**Engineering Reality:** A BAS agent that has to run with elevated privileges to execute realistic
technique tests is itself an attractive target and a source of risk if compromised or
misconfigured — treat its credentials and deployment scope with the same rigor as any other
privileged automation, and make sure it is asset-inventoried, not a shadow agent nobody remembers
installing eighteen months later.

## Synthetic Telemetry Generation

[CONCEPT] Sometimes you want to test detection *logic* without executing any actual attacker
behaviour at all — you generate log events that look like what the technique would produce, and
feed them directly into the SIEM/detection pipeline. This is not simulation of the attack; it's
simulation of the *evidence* the attack would leave.

**When this is the right tool instead of Atomic Red Team / BAS:**
- Testing a new Sigma/KQL rule's syntax and field-matching logic before you have a safe way to
  generate the real event (e.g., you don't want to actually run a ransomware-adjacent mass-file-
  rename operation on a shared test host).
- Regression-testing a detection after a parser or schema change, where you need a known, exact
  input event to confirm the rule still matches the same fields after normalization changed.
- Load/performance testing a detection pipeline — replaying or generating high event volume to see
  if a correlation rule holds up, without needing volume of real attacker activity.
- Unit-testing detection-as-code pipelines in CI (see the Detection-as-Code chapter) where a fixed
  synthetic event fixture is exactly what you want — deterministic, versioned, no live host needed.

**The limitation, stated directly:** synthetic telemetry only proves the rule matches the event you
hand-crafted. It proves nothing about whether the real technique actually produces that event in
your environment, with your agent version, your logging policy, your parser. Treat synthetic
telemetry as a unit test for rule logic, and Atomic Red Team / BAS / purple teaming as the
integration test that confirms the real-world event matches your synthetic assumption. Skipping the
integration test and trusting only synthetic fixtures is how a rule ships "green" in CI and never
fires in production because the real Sysmon event has a field the fixture didn't.

```
CONCEPTUAL SAMPLE — synthetic Sysmon Event ID 10 fixture for a LSASS-access unit test
(illustrative JSON shape, not a captured event, not guaranteed to match your parser's exact schema)

{
  "EventID": 10,
  "SourceImage": "C:\\Windows\\System32\\rundll32.exe",
  "TargetImage": "C:\\Windows\\System32\\lsass.exe",
  "GrantedAccess": "0x1010",
  "CallTrace": "C:\\Windows\\SYSTEM32\\ntdll.dll+..."
}
```

## Historical Event Replay

[CONCEPT] Replay takes real, previously captured telemetry — from a documented past incident, a
public "attack range" dataset, or your own honeynet/lab capture — and feeds it back through the
current detection pipeline to check whether today's rules would catch yesterday's (real or
simulated) attack.

[THREAT HUNTER] Replay is the sharpest tool for answering "if this exact incident happened again
right now, would we catch it?" — because unlike an atomic test, the replayed data is a real,
complete artifact of an actual technique execution (or a faithfully captured lab attack), including
the surrounding noise, timing, and process ancestry that a scripted atomic test often lacks.

Two practical sourcing paths:
- **Your own captured incident/lab data.** If your honeynet or lab environment captured a real
  attacker session or a red-team engagement's full telemetry, replaying it — with data properly
  sanitized of any real secrets/credentials before it re-enters a shared environment — is higher
  fidelity than any public dataset because it matches your actual log schema already.
- **Public attack-range / research datasets.** Various research groups and vendors publish sample
  detection-engineering datasets (attack range logs, EVTX samples) for exactly this purpose. Verify
  license terms and confirm the schema before assuming it maps to yours.

**Engineering Reality:** replay is only as good as timestamp handling. Feeding old events into a
live pipeline with their original timestamps will often get silently dropped by time-based
ingestion windows, retention filters, or correlation rules that assume "now." Either replay through
a dedicated test index/pipeline that doesn't share retention/time assumptions with production, or
rewrite timestamps to "now" as part of the replay tooling — and document which you did, because it
changes what a passing/failing result actually means.

## Tabletop Exercises

[CONCEPT] A tabletop exercise is a facilitated, narrative walkthrough of an incident scenario with
no technical execution at all — a room (or call) with IR, detection engineering, SOC leadership,
legal, and sometimes executive stakeholders, working through "here's what happened at 2am, what do
we see, who do we call, what do we do" using a written scenario.

Tabletops validate a different layer than everything above: not "does the detection fire," but "if
it fires, does the organization respond correctly." A technically perfect detection that fires into
a queue nobody is trained to act on at 2am on a Saturday is not a working control. Run tabletops
against scenarios informed by the gaps found in purple team exercises and BAS results — "the
scheduled-task persistence technique we found undetected three months ago, what if that had been a
real ransomware precursor" is a far sharper tabletop scenario than a generic one.

[MANAGEMENT] Tabletops are also the venue where you validate that escalation paths, communication
plans, and legal/PR involvement actually work under time pressure — none of which any purely
technical simulation exercises above will ever test.

## Worked Example: Purple Team Validation of an LSASS Credential-Access Detection

**Hypothesis:** "Our EDR + SIEM combination detects LSASS memory access consistent with credential
dumping (T1003.001), on Windows Server 2022 domain controllers, within 5 minutes."

**Test setup:**
- Authorized, isolated test domain controller in the lab, not production.
- Sysmon (with a config that logs Event ID 10, process access, for LSASS as a target) plus EDR
  agent in its production policy configuration — deliberately using the *actual* production policy,
  not a permissive test policy, because the point is validating what production would really do.
- Atomic Red Team test for T1003.001 using the `comsvcs.dll` MiniDump technique (a well-known,
  publicly documented LOLBIN method — `rundll32.exe comsvcs.dll, MiniDump <lsass_pid> <path> full`).

**Illustrative Sigma rule under test** (labeled illustrative — verify exact field names/casing
against your own Sysmon config before use):

```yaml
title: Potential LSASS Memory Dump via comsvcs.dll
id: 5c3a2e10-part32-01
status: test
description: >
  Detects rundll32.exe invoking comsvcs.dll's MiniDump export, a documented
  LOLBIN technique for dumping LSASS process memory without dropping a
  separate credential-dumping tool.
references:
  - MITRE ATT&CK T1003.001
tags:
  - attack.t1003.001
  - attack.credential_access
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\rundll32.exe'
    CommandLine|contains|all:
      - 'comsvcs.dll'
      - 'MiniDump'
  filter_known_admin_tooling:
    ParentImage|endswith: '\backup_agent.exe'   # example legit caller — verify per environment
  condition: selection and not filter_known_admin_tooling
falsepositives:
  - Legitimate use of comsvcs.dll MiniDump by approved diagnostic/backup tooling (rare; verify per environment)
level: high
```

**Result of the run:** the atomic test executed cleanly; Sysmon logged the process-creation event
with the expected command line; the rule fired in the SIEM 62 seconds after execution, correctly
excluding nothing (no legitimate caller existed on this test host, so the filter branch was
unexercised — flagged as a follow-up to test the filter path separately with a synthetic event, per
the synthetic telemetry section above).

**Follow-up gap found during the same session:** the EDR agent's own built-in LSASS-protection
detection also fired, but on a different timeline (nearly instant, pre-execution block) — and the
two alerts landed in different queues with different severity labels, with no correlation rule
tying them together as the same underlying event. That's a real, common outcome of validation
exercises: the individual control worked, but the cross-tool alert correlation didn't, and that gap
would not have been found by running either tool's detection test in isolation.

## Detection Autopsy: The Atomic Test That "Passed" and Still Failed in Production

**Original rule logic:** a command-line detection for T1003.001 keyed narrowly on the exact string
pattern from the public Atomic Red Team test: `rundll32.exe comsvcs.dll, MiniDump` with a comma
and a space in that exact position, matched as a literal substring.

**Why it looked reasonable:** the atomic test passed cleanly in the lab. The command line
generated by the test matched the rule's literal string exactly, alert fired, box checked, coverage
matrix updated to "covered."

**What broke in production:** six weeks later, a real credential-dumping attempt on a different
host used the same LOLBIN technique but with the argument order and whitespace that `rundll32.exe`
itself accepts in several equally valid forms (no space after the comma, full vs. relative DLL
path, mixed case on `MiniDump`). None of these variants matched the literal substring. The rule had
been validated against exactly one command-line shape — the one the public atomic test happened to
produce — and nothing else.

**False positives:** none reported, which was itself a warning sign nobody read at the time — a
rule with zero false positives and zero true positives for six weeks is not "clean," it's
untested against reality.

**False negatives:** the real incident, caught only because the EDR agent's memory-access-based
detection (matching on the *behaviour* — a non-LSASS process opening a handle with dump-capable
access rights to `lsass.exe`) fired independently of the command-line rule.

**Missing context:** the rule author had validated command-line *pattern matching* but never asked
"what does `rundll32.exe`'s argument parser actually accept as valid syntax" or "what does
`GrantedAccess` on the Sysmon Event ID 10 record look like regardless of how the command line is
phrased."

**Revised analytic:** replaced the brittle command-line-literal match with a access-mask-based
detection on Sysmon Event ID 10 (`TargetImage` ending in `lsass.exe`, `GrantedAccess` containing
rights consistent with memory-read access such as `0x1010` or `0x1410`, filtered against a
maintained allowlist of known-legitimate `SourceImage` processes such as EDR/AV engines and backup
agents), with the original command-line rule kept as a secondary, lower-confidence signal rather
than the sole detection.

**How it was tested:** re-ran the original atomic test (still fired, now via the access-mask path),
then ran three additional atomic-test variants with altered argument spacing/casing/path forms, and
a synthetic-telemetry fixture representing a different LSASS-dumping tool entirely (not comsvcs.dll
at all) to confirm the access-mask logic generalized beyond the one LOLBIN.

**Result:** all four variants and the synthetic non-comsvcs case fired correctly post-revision;
zero literal-string-only detections remain in the ruleset for this technique as the sole layer.

## Screenshot / Evidence Placeholders

> **[SCREENSHOT PLACEHOLDER — CONTROLLED LAB]** — Sysmon process-creation log (Event ID 1) and
> process-access log (Event ID 10) captured on an isolated lab domain controller during an
> authorized Atomic Red Team T1003.001 run, showing the `rundll32.exe`/`comsvcs.dll` command line
> and the corresponding `GrantedAccess` value on the `lsass.exe` target — illustrating the exact
> fields the revised analytic in the Detection Autopsy above keys on.

> **[SCREENSHOT PLACEHOLDER — CONTROLLED LAB]** — SIEM alert timeline view from the worked-example
> purple team session, showing the EDR built-in LSASS-protection alert and the custom Sigma-rule
> alert for the same underlying event, timestamped separately, illustrating the cross-tool
> correlation gap described above.

## Coverage Matrix as a Living Artifact

[SOC Management View] Every technique validated through any method in this chapter should land in
one place — an ATT&CK Navigator layer or equivalent coverage matrix — with, at minimum: technique
ID, last validation date, validation method used (atomic/purple/BAS/replay/tabletop), and a
freshness expiry. A coverage claim more than a year old, in an environment where the EDR agent has
been upgraded twice since, is not a coverage claim — it's a guess with a date on it. Budget analyst
time for re-validation on a fixed cadence, not just after incidents.

| Validation method | Confirms | Does not confirm | Typical cadence |
|---|---|---|---|
| Atomic Red Team-style test | Single-technique telemetry + rule match | Chained behaviour, evasive variants | Per rule, on change |
| Purple team exercise | Real-time cross-technique coverage + response | Full incident-scale response, org-wide | Quarterly |
| BAS platform | Continuous regression across many techniques | Novel/custom evasion, human response process | Daily/weekly, automated |
| Synthetic telemetry | Rule logic/syntax correctness | Whether the real event actually looks like the fixture | Per rule change, in CI |
| Historical replay | Detection against a real, complete past dataset | Whether *current* attacker tooling still matches old artifact | Per major pipeline/rule change |
| Tabletop | Organizational response, escalation, communication | Any technical detection accuracy | Semi-annual |

Reminder: every method above is only meaningful inside an authorized scope, on systems you're
permitted to test, with cleanup steps run afterward and results recorded. Outside that boundary,
none of this is a validation exercise — it's just running attacker tooling, and the framing of this
entire chapter does not apply.
