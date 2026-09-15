# Detection Engineering Handbook — STYLE-GUIDE.md (V2)

**Status:** Draft for review (Proposal 1 of 2)
**Audience for this document:** every writer, technical reviewer, and editor working on V2.
**Purpose:** V1 (archived at `release-v1/`, read-only) was produced by 55 independent single-pass
agents with no shared style contract. The result is technically broad but structurally
inconsistent: the same recurring callout appears as a bolded run-in, an H2, an H3, and a
blockquote depending on which part you're in; content tags appear as `[TAG]` in one part and
`**[TAG]**` in the next; Event IDs are sometimes bare numbers and sometimes "Event ID 4624";
MITRE IDs sometimes carry technique names and sometimes don't. None of that is a judgment call —
it's drift from having no style contract at all. This document is that contract. It is normative:
"must" means a PR gets rejected if it doesn't comply; "should" means deviate only with a reason in
the PR description; "avoid" is a strong default that a reviewer can override with justification.

This guide governs prose voice, Markdown conventions, and the eight recurring callout boxes,
content-level tags, and evidence-classification system for figures. It does not cover technical
review standards (accuracy, false-positive analysis rigor, coverage claims) — that lives in a
separate REVIEW-STANDARDS.md, because voice/format consistency and technical correctness are
different failure modes and need different reviewers.

---

## 1. Voice and tone

### 1.1 The core rule

Write like a senior detection engineer explaining something to another senior detection engineer
on a call, not like a vendor blog post trying to rank for "XDR best practices 2026." The reader
already knows what a SOC is. They do not need to be sold on the importance of security. They need
the thing that actually happened, why it happened, and what to do about it.

Concretely:

- **State the claim, then the evidence.** Don't build up to it with scene-setting.
- **Name the failure mode, don't gesture at it.** "This breaks under X" beats "this can present
  challenges in certain scenarios."
- **Prefer the concrete number over the vague qualifier.** "Fires 40–200 times a day on a
  10,000-endpoint estate" beats "generates a significant volume of alerts."
- **Second person is fine for instructions, first person plural ("we") is fine for the book's own
  reasoning, but neither should be used to manufacture urgency.**
- **It is okay to say a control is boring, cheap, or already solved.** Not everything needs to
  sound like a breakthrough.

### 1.2 Banned filler — and the actual rule behind the ban

The list below is banned **only in its AI-marketing-pattern usage** — i.e., as a load-bearing
transition, hedge, or intensifier that could be deleted with no loss of meaning, or that signals
"content" rather than a claim. Mechanically grepping-and-blocking normal English is explicitly
wrong: several of these words have legitimate, specific uses that are fine to keep. The reviewer's
test is: **does this phrase carry information, or does it just sound like it does?**

| Banned pattern (as filler) | Why it's banned | Legitimate exception |
|---|---|---|
| "in today's rapidly evolving threat landscape" | Says nothing; every landscape is always evolving | None — always cut, replace with the actual specific change you mean |
| "it is crucial / critical that..." | Asserts importance instead of demonstrating it | Rewrite as the concrete consequence of not doing the thing |
| "robust posture / robust detection" | "Robust" as a vague virtue word attached to abstract nouns | "Robust" is fine describing a specific measurable property, e.g. "robust to clock skew up to 5 minutes" |
| "leveraging" | Nearly always means "using" | Keep if you mean something *is used as leverage* in a specific mechanical sense (rare) |
| "holistic" | Vague scope-inflation word | Cut; say what specific things are actually being combined |
| "seamlessly" | Unfalsifiable marketing adjective | Cut; if integration quality matters, describe the failure mode when it *isn't* seamless |
| "paramount" | Filler intensifier | Cut, or replace with the actual priority ranking |
| "delve" | AI-pattern verb-of-choice for "discuss/examine" | Use "look at," "cover," "walk through" |
| "in conclusion" | Section signposting the reader doesn't need in a technical book (headings already do this) | None in body prose; fine only inside a literal debate/thesis structure, which this book doesn't use |
| "it is important to note that" | Hedge that adds no information; if it's worth saying, say it directly | None — always cut, keep the sentence that follows |
| "landscape" (standalone, as in "security landscape") | Vague spatial metaphor standing in for a specific claim | Fine in literal geographic/network topology sense ("network landscape" describing actual segmentation) |
| "unlock / empower / elevate" (as verbs for tools enabling actions) | Marketing verbs, not engineering verbs | Use the literal verb: "lets you query," "gives you visibility into," "reduces the time to..." |
| "at the end of the day" | Filler transition | Cut |
| "game-changer / game-changing" | Unfalsifiable superlative | Cut, or state the measurable change |

If a draft uses one of these and a reviewer can delete it without the sentence losing meaning,
it's filler — cut it. If they can't, it's not the AI pattern the ban targets — leave it. Do not
add a global regex ban to a CI check for this reason: it will both miss the actual pattern (which
is about *rhetorical function*, not literal string) and false-positive on legitimate uses.

### 1.3 Worked GOOD vs. BAD examples

**Example 1 — opening a section**

> BAD: "In today's rapidly evolving threat landscape, it is crucial for organizations to maintain
> a robust detection posture around privileged authentication events."

> GOOD: "4672 (Special Privileges Assigned) fires on every logon that receives a sensitive
> privilege — Domain Admin, local admin via UAC elevation, service accounts with SeDebugPrivilege.
> On a typical 5,000-seat estate that's 2,000–6,000 events a day. Alerting on the raw event is
> useless; alerting on 4672 *without* a matching baseline entry is the actual detection."

**Example 2 — describing a limitation**

> BAD: "It is important to note that this approach may present certain challenges when leveraging
> cloud-native telemetry sources."

> GOOD: "This breaks in AWS: CloudTrail's `userIdentity.arn` doesn't survive an assumed-role chain
> the way a Windows SID does, so the same baseline-by-identity logic you'd write for 4624 needs a
> different join key — `sourceIdentity` if it's populated, which it isn't for every service."

**Example 3 — closing a section**

> BAD: "In conclusion, a holistic, seamless approach to detection engineering will empower SOC
> teams to elevate their security posture."

> GOOD: "None of this works without the baseline table being refreshed on a schedule shorter than
> your average attacker dwell time. A 30-day-stale baseline is worse than no baseline — it tells
> the analyst 'seen before' about a host that was decommissioned three weeks ago."

**Example 4 — a hedge that should just be a claim**

> BAD: "It is crucial to note that Sysmon configuration is paramount to the quality of detections
> that leverage its telemetry."

> GOOD: "A permissive Sysmon config drowns the SIEM in Event ID 3 noise from routine browser
> traffic. An overly restrictive one — cutting common paths to save volume — creates the exact
> blind spot a recon'd attacker will walk through. Test config changes against a baseline capture
> before pushing fleet-wide."

### 1.4 Sentence-level defaults

- Default to active voice. Passive is acceptable when the actor genuinely doesn't matter ("the
  event is logged to the Security channel").
- One claim per sentence where possible. If a sentence needs three commas and an em dash to hold
  together, it's probably two sentences.
- Numbers: use digits for Event IDs, ATT&CK IDs, port numbers, and any count ≥ 10; spell out
  small counts under 10 in prose ("three logon types," not "3 logon types") — except inside
  tables, where digits are always used for scanability.
- Contractions ("doesn't," "isn't," "won't") are fine and preferred — this book has a spoken-voice
  register, not a legal-document register.

---

## 2. Heading conventions

V1 used H1 for the part title and H2 for major sections consistently, but drifted between H2 and
H3 for subsections and for callouts across parts (some callouts are `##`, some are `###`, some are
bold run-in text with no heading at all — see §4). V2 locks this down:

| Level | Use for | Example |
|---|---|---|
| `#` (H1) | Part title only. One per file, first line of the file. | `# Part IV — Windows Detection Engineering` |
| `##` (H2) | Major numbered sections within a part (the part's table of contents entries). | `## 3. Kerberos authentication events` |
| `###` (H3) | Subsections within a major section — a specific event, a specific rule, a specific sub-topic. | `### 3.2 4769 — Kerberos Service Ticket Request` |
| `####` (H4) | Rare; only for structured sub-breakdowns inside an H3 that need their own anchor (e.g., "Fields," "False positive drivers," "Tuning" inside a single detection writeup). Do not nest deeper than H4. | `#### Fields that matter` |

Rules:

- **Callout boxes are never headings** (see §4) — they are bold run-in labels or blockquotes, at
  the same nesting level as the paragraph they belong to. A callout must not consume a heading
  level; it's an annotation on existing content, not a new section.
- Number H2 sections sequentially within the part (`## 1.`, `## 2.`, ...); do not number H3s
  independently of their parent — use `### 3.2` under `## 3`, not a restarted `### 1`.
- Every part must open with an unnumbered `## Why this part exists` section before numbering
  starts at `## 1.` — this was inconsistent in V1 (some parts had it, some went straight to `##
  1.`) and is now mandatory.
- Section titles are sentence case, not Title Case ("Kerberos authentication events," not
  "Kerberos Authentication Events"). Part titles use title case with an em dash, per the existing
  V1 convention (`# Part IV — Windows Detection Engineering`) — keep this exception, it's already
  baked into 50 part titles and rewriting them isn't worth the churn.

---

## 3. Code block conventions

Every fenced code block **must** carry a language tag — untagged fences are a lint failure. Use
these tags exactly (matching what V1 already used correctly in the majority of chapters; this
section formalizes it rather than changing it):

| Query language / artifact | Fence tag | Notes |
|---|---|---|
| Sigma rules | `` ```yaml `` | Sigma is YAML; do not invent a `sigma` tag, no renderer recognizes it. |
| Splunk SPL | `` ```spl `` | |
| Microsoft Sentinel / Defender KQL | `` ```kql `` | Same tag regardless of which product's KQL dialect — note the dialect in prose if it matters, not in the fence tag. |
| Google SecOps / Chronicle YARA-L | `` ```yaral `` | If the renderer's Pygments lexer doesn't support `yaral`, fall back to `` ```yaml `` only for YARA-L rules that are YAML-shaped; otherwise use ` ```text ` rather than mislabeling it. |
| Elastic EQL / KQL (Elastic dialect) | `` ```eql `` | Do not conflate with Sentinel KQL — always disambiguate in the prose line immediately above the block ("Elastic EQL:" / "Sentinel KQL:"). |
| Generic shell / command-line examples (attacker command lines, PowerShell one-liners) | `` ```powershell ``, `` ```bash ``, `` ```cmd `` | Pick the tag that matches the actual shell, not a generic `shell`. |
| Raw log excerpts (event fields, JSON log lines) | `` ```json `` or `` ```text `` | Use `json` only if it's actually valid JSON; a truncated/annotated excerpt should be `text` so a reader doesn't try to parse it as JSON and get confused by ellipses or inline comments. |
| Mermaid diagram source | `` ```mermaid `` | See §9 for what accompanies every Mermaid block. |
| Conceptual/illustrative code (field names invented for teaching, not copy-pasteable) | Same language tag as normal, **plus** a one-line label immediately above the fence reading `CONCEPTUAL SAMPLE — <one clause on what's illustrative about it>` | This is the one V1 convention that already worked well and should be kept exactly as-is (see part07, part01). |

Rules:

- A code block that is a real, runnable detection rule (the kind that ships in `book/detections/`)
  must not be labeled `CONCEPTUAL SAMPLE`. Reserve that label for teaching snippets embedded in
  prose that intentionally use invented field names or simplified logic.
- Every code block over ~15 lines should be preceded by one sentence stating what it does and
  followed by one sentence stating its main limitation (the false-positive driver, the coverage
  gap, or the field dependency). This is not optional — a bare wall of query syntax with no framing
  is one of the specific things a technical reviewer should reject.
- Inline code spans (`` `4624` ``, `` `ParentImage` ``) are for field names, single event IDs
  referenced mid-sentence, and file paths — not for full commands, which get a fenced block.

---

## 4. Callout boxes

V1 named eight recurring features in its planning but never gave them a stable Markdown shape —
`Detection Autopsy` alone appears as `**bold run-in**`, `## H2 heading`, `### H3 heading`, and
`> blockquote` across different parts, and several of the eight (Blind Spot, False Positive Trap,
Detection Test, SOC Management View, What Would Change My Mind) barely appear at all as
distinguishable boxes. Every callout below gets one exact template. **No part may invent its own
variant.** All eight use the same base shape — a blockquote opened with a bolded label — so they
are visually and structurally consistent with each other, distinguished only by label text and
(for two of them) an internal sub-structure.

General rule for all eight: they are blockquotes (`>`), not headings, and they sit inline in the
flow of a section — never as a jump-target the table of contents would list separately.

### 4.1 Detection Autopsy

Used when dissecting a real or realistic detection rule that shipped broken — the naive version,
why it failed, what replaced it. This is the highest-frequency callout in the book (appears in
nearly every technical part) and had the most drift in V1; this template is now mandatory for
every instance.

**Template:**

```markdown
> **Detection Autopsy — "<the naive rule in one clause, in quotes>"**
>
> **The rule:** <what it literally does, one or two sentences, plain description not code>.
>
> **Why it shipped:** <the reasonable-sounding logic that got this rule approved>.
>
> **How it failed:** <the specific false-positive or false-negative mechanism, with a concrete
> trigger scenario>.
>
> **The fix:** <what the corrected rule adds or changes, in one or two sentences>.
```

**Worked example:**

```markdown
> **Detection Autopsy — "alert on any process reading lsass.exe memory"**
>
> **The rule:** fire whenever Sysmon Event ID 10 (ProcessAccess) shows a `TargetImage` of
> `lsass.exe`, regardless of source process or access mask.
>
> **Why it shipped:** lsass memory access is the mechanism behind Mimikatz-style credential
> dumping, so on paper this looks like a direct technique-to-detection mapping.
>
> **How it failed:** every AV/EDR agent, Windows Defender, and several backup and monitoring
> agents legitimately open handles to lsass.exe as part of normal operation — often hundreds of
> times an hour per host. The rule alerted so often it was routed straight to a suppression rule
> within a week, silencing it for the one time it mattered.
>
> **The fix:** filter on the access mask (`GrantedAccess` values associated with memory-read
> rights, e.g. `0x1010` / `0x1410`) and exclude a maintained allowlist of known-good caller image
> paths, rather than alerting on the presence of the access event at all.
```

### 4.2 Hunter's Note

A short aside from the threat-hunting perspective embedded inside detection-focused content —
shorter than a full [THREAT HUNTER]-tagged paragraph (§10), used for a single tactical tip rather
than a full section.

**Template:**

```markdown
> **Hunter's Note:** <one to three sentences — a pivot, a field to check, or a hypothesis a hunter
> would chase that the detection rule above doesn't cover>.
```

**Worked example:**

```markdown
> **Hunter's Note:** Logon ID (`TargetLogonId` in 4624, referenced in 4672 and subsequent process
> events) is the join key that turns a pile of individual events into one session's story. If your
> hunt query isn't grouping by Logon ID, you're hunting on events, not sessions — and an attacker's
> activity almost always needs to be read as a session.
```

### 4.3 Engineering Reality

A blunt statement of an operational constraint that undercuts an otherwise-clean detection
story — the thing that makes the rule harder to run in production than it looks on paper.

**Template:**

```markdown
> **Engineering Reality:** <the operational constraint, stated as fact, plus its consequence for
> whoever has to run this in production>.
```

**Worked example:**

```markdown
> **Engineering Reality:** the absence of a source IP on Event 4776 is not a misconfiguration you
> can fix — NTLM authentication over that code path simply doesn't carry one. If your detection
> depends on source-IP enrichment for NTLM auth, you need a second telemetry source (network flow
> logs, DC-side packet capture, or a proxy/firewall log) joined on time and account, not a config
> change to the domain controller.
```

### 4.4 Blind Spot

States explicitly what a detection, telemetry source, or hunt does **not** cover — the coverage
gap an analyst or auditor needs to know exists. This callout was almost entirely absent from V1
(it existed as prose bullets under ad hoc headings like "Blind spots:") and is now a formal,
mandatory box wherever a detection's coverage is discussed.

**Template:**

```markdown
> **Blind Spot:** <what this detection/telemetry source cannot see, stated precisely — a log
> channel, a platform, an attacker behavior variant, or a timing window it misses>. <optional
> second sentence: what would need to change to close the gap>.
```

**Worked example:**

```markdown
> **Blind Spot:** this rule only covers the Security event log. System, Application, and
> PowerShell Operational channels have their own independent clear-log events and are cleared
> separately — an attacker who clears Security and forgets PowerShell Operational leaves evidence
> behind. Closing this gap means alerting on the clear-event in every forwarded channel, not just
> Security.
```

### 4.5 False Positive Trap

Names a specific, plausible-looking source of false positives that isn't obvious from reading the
rule logic alone — distinct from Detection Autopsy (which dissects a rule that already shipped and
broke) in that this callout is preventive, flagging a trap before the reader builds the rule.

**Template:**

```markdown
> **False Positive Trap:** <the legitimate activity that mimics the malicious pattern>, caused by
> <the specific tool, workflow, or platform behavior responsible>. <optional: how to distinguish
> it from the real thing>.
```

**Worked example:**

```markdown
> **False Positive Trap:** vulnerability scanners and EDR agents doing credentialed scanning
> generate the exact 4624 Type 3 + immediate 4634 pattern that a naive "rapid logon/logoff" lateral
> movement rule keys on, because a scan engine authenticates, runs a quick check, and disconnects —
> hundreds of times a night. Exclude known scanner service accounts and source hosts by identity,
> not by IP range, since scan infrastructure IPs rotate more often than the service account does.
```

### 4.6 Detection Test

A concrete validation step: how to actually verify a detection fires (and doesn't over-fire)
before trusting it in production — atomic test procedure, expected result, and what "it worked"
looks like in the SIEM. V1's `part30-detection-testing.md` covered this topic in prose but never
established a reusable inline box for individual detections; this is now the standard unit.

**Template:**

```markdown
> **Detection Test**
> - **Simulate:** <the exact tool/technique/command used to safely trigger the behavior, e.g. an
>   Atomic Red Team test ID, in a lab or controlled environment — never production>.
> - **Expect:** <the exact event(s)/field values that should appear>.
> - **Pass/fail:** <the specific query or check that confirms the alert fired correctly, and what
>   a false negative or false positive at this stage would look like>.
```

**Worked example:**

```markdown
> **Detection Test**
> - **Simulate:** run Atomic Red Team T1558.003 Test #1 (Rubeus `kerberoast`) against a
>   disposable lab service account with a weakly-configured SPN, from a non-DC lab host.
> - **Expect:** one or more 4769 events on the domain controller with `TicketEncryptionType =
>   0x17` (RC4) and `ServiceName` matching the test SPN, clustered in a single short burst from one
>   source workstation.
> - **Pass/fail:** the rule should fire within the SIEM's normal ingest latency window. If it
>   doesn't fire, check whether 4769 auditing for that DC is actually enabled (a common gap — see
>   the Engineering Reality box in §3.2) before assuming the rule logic is wrong.
```

### 4.7 SOC Management View

A callout aimed specifically at the [SOC MANAGEMENT] reader — staffing, SLA, escalation policy,
or budget implication of the detection or telemetry gap just discussed. Distinct from a
[SOC MANAGEMENT]-tagged paragraph (§10) in that this callout is a boxed aside inside
analyst/engineer-focused content, flagging one management-relevant consequence, not a full section
written for that audience.

**Template:**

```markdown
> **SOC Management View:** <the staffing, SLA, escalation, or resourcing implication>, stated as a
> decision or policy consequence, not just an observation.
```

**Worked example:**

```markdown
> **SOC Management View:** Event 1102 (Security log cleared) is one of the few Windows events
> where the correct SOC policy is "zero tuning, zero suppression, page someone" regardless of time
> of day. If this alert is routed through a normal ticket queue with SLA-based triage, that's a
> governance gap worth raising in the next detection-coverage review — by the time an SLA queue
> reaches it, the attacker covering their tracks has had hours of head start.
```

### 4.8 What Would Change My Mind

States the specific evidence that would falsify the claim, ranking, or recommendation just made —
an explicit epistemic-honesty checkpoint. This callout did not exist in V1 in any form; it is new
for V2 and should be used sparingly (see usage rule below), not on every page.

**Template:**

```markdown
> **What Would Change My Mind:** <the specific, checkable observation or dataset that would
> overturn the preceding claim>. <optional: why that evidence hasn't been seen (yet), i.e. it's a
> real open question, not a rhetorical hedge>.
```

**Worked example:**

```markdown
> **What Would Change My Mind:** the recommendation above to key lateral-movement baselining on
> Logon ID rather than PID assumes Logon ID doesn't recycle within your retention window. On a
> domain controller under extreme load with a short logon-ID counter reset (rare, but documented
> on some legacy DC builds), that assumption breaks. If you're running a build old enough for this
> to be a live concern, verify the Logon ID counter behavior in a controlled test before trusting
> this join key at scale.
```

**Usage rule:** this callout exists to mark genuine uncertainty, not to perform humility. Use it
only where the book is making a claim that (a) depends on an assumption that could plausibly be
wrong in some reader's environment, and (b) the failure mode is specific enough to name. If a
reviewer can't identify concrete evidence that would falsify the claim, the box is decorative —
cut it or make the claim more precise until the falsifying evidence is nameable.

### 4.9 Callout usage density

Not every section needs every callout. A reasonable density guideline: a single detection
writeup (one `###` subsection) typically carries 1 Detection Autopsy (if it has a known-bad naive
version worth dissecting), 0–1 Blind Spot, 0–1 False Positive Trap, and 1 Detection Test. Hunter's
Note, Engineering Reality, SOC Management View, and What Would Change My Mind are used
opportunistically where they add a genuinely distinct point — not as a checklist to fill per
section. A section with all eight callouts stacked back-to-back is over-boxed; fold the weaker
ones back into prose.

---

## 5. Windows Event ID notation

**Rule:** on **first mention within a given `###` subsection**, write the full form —
`Event ID 4624` — optionally followed by the event name in parentheses on true first use within
the part: `Event ID 4624 (An account was successfully logged on)`. On every subsequent mention
within that same subsection, the bare number is sufficient: `4624`.

This resolves V1's actual drift (grep across part04 shows 4624 written bare ~30 times and in full
form once, "Event ID 4624," at essentially one point in the whole chapter) — the intent was
clearly first-use-in-full, but it wasn't executed consistently. V2 makes it a mechanical rule tied
to a countable scope (the subsection, not the whole part) so a reviewer can check it: if a
subsection's first sentence mentioning a given ID doesn't say "Event ID," flag it.

Additional rules:

- Do not write "EID 4624" or "event 4624" (lowercase) — always either the bare number after
  first use, or the full capitalized "Event ID" on first use.
- When referring to a *range or family* of related IDs in prose, list them slash-separated with
  no repeated "Event ID": `4768/4769/4771/4776`. The first such list in a subsection should still
  be preceded by "Kerberos and NTLM authentication events" or equivalent context — don't open a
  paragraph cold with a bare number list.
- In tables, always use the bare number (no "Event ID" prefix) — the column header ("Event ID")
  already establishes it.
- In callout boxes (§4), treat the callout's own first mention as its own first-use scope if the
  callout is the first place that ID appears in the subsection — i.e., don't assume the reader
  carries context from prose into a blockquote; write "Event ID 4769" in the callout if it's the
  callout's first reference to it, even if 4769 was already spelled out earlier in the same
  subsection. This is a deliberate exception to strict first-use-only, because callouts are
  visually separated and often get read out of order (skimmed independently of surrounding prose).

---

## 6. MITRE ATT&CK ID formatting

**Rule:** always pair the ID with its technique (or sub-technique) name in parentheses on first
use within a `###` subsection: `T1558.003 (Kerberoasting)`. Subsequent mentions within that same
subsection may use the bare ID: `T1558.003`.

- Sub-technique IDs always include the parent technique number and the dot-suffix —
  `T1550.002`, never truncated to `T1550` when the sub-technique is what's actually meant.
- When listing several related techniques, slash-separate bare IDs after the first full mention,
  same pattern as Event IDs: "credential access via Kerberoasting (T1558.003) and AS-REP roasting
  (T1558.004)" on first use, then "T1558.003/T1558.004" afterward is acceptable only if both were
  already named in full earlier in the subsection.
- A `**MITRE:**` summary line (as already used in V1's per-detection metadata blocks) always
  lists full IDs with names, regardless of whether they were already spelled out in prose above —
  this line is often scanned independently of the surrounding text: `**MITRE:** T1070.001 (Clear
  Windows Event Logs).`
- Never use the pre-2020 flat numbering or drop the `T` prefix. Always `T1070`, never `1070`.
- Tactic names (e.g., "Credential Access," "Defense Evasion") are capitalized as proper nouns
  matching the ATT&CK matrix column headers, but do not get an ID of their own in this book's
  notation — only techniques and sub-techniques get IDs.

---

## 7. Content-level tags

Six tags mark which reader role a paragraph (or short run of paragraphs) is written for. V1
introduced these correctly in concept — part01 and part03 use them well — but drifted on the exact
Markdown shape (`[CONCEPT]` bare vs. `**[DETECTION ENGINEER]**` bolded) even within the same file.

**Format (locked):** `**[TAG]**` — bold, square brackets, all caps, at the start of the
paragraph's first line, followed by a space and then the paragraph text. Bold is mandatory (it's
what makes the tag scannable against surrounding unbolded prose); bare `[TAG]` without bold is not
acceptable even though V1 used it in places.

```markdown
**[ENGINEERING]** Sysmon is only as good as its config. A permissive config drowns the SIEM in
Event ID 3 noise from routine browser and update traffic...
```

### 7.1 The six tags and when to use each

| Tag | Use for | Typical content |
|---|---|---|
| `[CONCEPT]` | Foundational explanation any reader needs before the rest of the section makes sense — what a mechanism *is*, independent of role. | Definitions, how a protocol/log source actually works, why an ID exists. |
| `[ANALYST]` | What matters during live triage — the first three things to check, how to tell a true positive from noise fast, what "normal" looks like on triage. | Triage checklists, context-gathering steps, immediate next actions. |
| `[DETECTION ENGINEER]` | Rule-authoring and tuning judgment — field choice, join keys, thresholds, why one implementation is more durable than another. | Query logic decisions, tuning trade-offs, data-quality dependencies. |
| `[THREAT HUNTER]` | Hypothesis-driven exploration beyond a standing rule — what to pivot on, what a rule doesn't catch that's still worth looking for. | Pivot fields, hunting hypotheses, "if this rule is silent, check this instead." |
| `[ENGINEERING]` | Platform/pipeline-level concerns — log volume, retention, forwarding, config management, cost, and the operational cost of running this at scale. | Volume/retention math, config management, pipeline dependencies, "budget real engineering time for X." |
| `[SOC MANAGEMENT]` | Staffing, process, escalation, and organizational-policy implications for someone who runs a SOC rather than works a queue. | SLA policy, escalation paths, headcount/coverage trade-offs, what to put in a steering-committee update. |

### 7.2 Disambiguating the two easily-confused pairs

- **`[DETECTION ENGINEER]` vs. `[ENGINEERING]`:** `[DETECTION ENGINEER]` is about the *rule* — what
  fields, what logic, what threshold. `[ENGINEERING]` is about the *pipeline that gets the data to
  the rule* — whether the events exist, are retained, are forwarded, and at what volume/cost. A
  paragraph about choosing `ProcessGuid` over PID as a join key is `[DETECTION ENGINEER]`. A
  paragraph about whether your log forwarder can keep up with 4768 volume during a Kerberoasting
  spray is `[ENGINEERING]`.
- **`[ANALYST]` vs. `[THREAT HUNTER]`:** `[ANALYST]` responds to an alert that already fired.
  `[THREAT HUNTER]` goes looking without waiting for an alert, usually because they suspect a
  standing rule has a blind spot. If the paragraph starts from "an alert just fired, now what," it's
  `[ANALYST]`. If it starts from "assume no alert has fired, what would you go check," it's
  `[THREAT HUNTER]`.

### 7.3 Density and placement rules

- Tags are for paragraphs that genuinely shift audience — do not tag every paragraph in a section
  just to hit six tags. A section that naturally only has engineer- and analyst-relevant content
  doesn't need to manufacture a management paragraph.
- Do not use a tag as a heading replacement — a tagged paragraph is still a paragraph inside the
  section's normal prose flow, not a new subsection. If a role's perspective needs more than ~2
  paragraphs, consider whether it should be its own `###` subsection instead of a long tagged run.
- A tag applies to the paragraph it opens; if that reasoning continues into a second paragraph
  without a new tag, it's still understood to be the same audience — you don't need to re-tag
  every paragraph in a run, but don't let a single tag silently cover more than 2–3 paragraphs
  before either closing the thought or re-tagging.

---

## 8. Table conventions

- Header row always present; separator row uses plain `|---|---|` dashes — no alignment colons
  unless a column is genuinely numeric and benefits from right-alignment (rare in this book; most
  tables are descriptive, not numeric).
- First column of a reference table (Event ID tables, ATT&CK mapping tables, Logon Type tables) is
  always the bare ID/number with no prefix — see §5/§6.
- Keep cell content to one or two sentences max; if a cell needs a paragraph, the table is the
  wrong format — convert to a list or subsection.
- Every table that maps techniques to detections or events must include the bare MITRE ID in its
  own column (not embedded in a prose cell) so it's independently scannable/greppable.
- Tables illustrating invented/simplified data (not real captured output) must say so in the
  caption or an adjacent line, consistent with §9's evidence classes — e.g., a "typical command
  pattern" table gets `(CONCEPTUAL SAMPLE)` in its header or caption, exactly as V1's part07 command
  table already does correctly.

---

## 9. Figures, diagrams, and screenshots: evidence classification

Every visual reference — a Mermaid diagram, a screenshot placeholder, or (in V2) an actual
captured image — **must** declare which evidence class it belongs to. V1 already had two working
conventions (`[SCREENSHOT PLACEHOLDER — CONTROLLED LAB]` and `CONCEPTUAL SAMPLE`) but no formal
four-class system and no distinction between a controlled lab (built specifically to generate this
one artifact) and a real lab (a genuinely running environment, like the home-lab Proxmox/CT
environment, that happened to produce this evidence as a byproduct of normal operation). V2
formalizes four classes:

| Class | Meaning | When to use |
|---|---|---|
| **CONTROLLED LAB EXAMPLE** | Captured (or, until captured, specified for future capture) from a purpose-built lab environment set up specifically to generate this artifact — e.g., a disposable VM running one Atomic Red Team test. | Most detection-illustrating screenshots. This is the default for "here's what the real event looks like." |
| **REAL LAB EXAMPLE** | Captured from a genuinely operated environment (a real home-lab, real production-adjacent system) where the evidence is a byproduct of normal operation, not staged for the book. Carries more authenticity but also more redaction burden — real hostnames, real IPs, real account names must be sanitized before use. | Use when a real running environment already produced the exact evidence needed and staging a duplicate in a throwaway lab would add no value — and only after sanitization is confirmed complete. |
| **OFFICIAL REFERENCE** | Sourced from vendor/official documentation (Microsoft Learn, MITRE ATT&CK, a vendor's own schema reference) rather than captured by this book's authors. | Schema references, official field definitions, vendor architecture diagrams being cited rather than recreated. Must carry a full citation (see REFERENCES.md conventions) in addition to the evidence-class tag. |
| **CONCEPTUAL** | Illustrative only — invented field values, a simplified/idealized version of a real artifact, or a diagram of a concept with no corresponding real system. | Anything not claiming to be a real captured artifact: teaching diagrams, simplified schemas, invented example data. |

### 9.1 Figure caption format

Every figure (Mermaid diagram, screenshot, or embedded image) gets a caption in this exact shape,
as a blockquote immediately below the figure:

```markdown
> **Figure <part#>.<figure#> [<EVIDENCE CLASS>]** — <one or two sentences: what the figure shows
> and, for a screenshot, what fields/behavior it's meant to illustrate>.
```

**Worked examples, one per evidence class:**

```markdown
> **Figure 4.3 [CONTROLLED LAB EXAMPLE]** — Sysmon process-creation log (Event ID 1) captured from
> a disposable Windows 11 lab VM running Atomic Red Team T1059.001, showing the
> `powershell.exe`-as-child-of-`WINWORD.EXE` chain with `ParentCommandLine`, `Image`, `CommandLine`,
> and `IntegrityLevel` fields intact.
```

```markdown
> **Figure 3.7 [REAL LAB EXAMPLE]** — Pi-hole DNS query log from the author's operated home-lab
> network, showing a genuine high-entropy subdomain burst later confirmed as a misconfigured IoT
> device's telemetry check-in, not an actual DNS tunnel — included as an example of a real false
> positive an analyst would need to rule out. Hostnames and internal IPs redacted per lab
> sanitization policy.
```

```markdown
> **Figure 8.1 [OFFICIAL REFERENCE]** — Microsoft's Windows Logon Type reference table, reproduced
> from Microsoft Learn's Audit Logon documentation (see REFERENCES.md #WIN-AUDIT-LOGON) to
> establish the canonical Type-to-name mapping this chapter builds on.
```

```markdown
> **Figure 6.2 [CONCEPTUAL]** — Simplified process-tree diagram illustrating the
> parent/child/grandchild relationship a naive detection rule checks, with invented process names
> standing in for any real binary — not captured from a running system.
```

### 9.2 Placeholder notation until an image actually exists

Because V2's explicit goal (fixing V1 weakness #2/#3) is to actually render diagrams and capture
real screenshots, a figure reference in a draft that does not yet have its image asset is written
as:

```markdown
> **[FIGURE PLACEHOLDER — Figure <part#>.<figure#>, <EVIDENCE CLASS>]** — <same descriptive
> sentence(s) as the final caption will have>.
```

This is a **temporary, tracked state**, not a permanent fixture the way V1's 71 never-captured
screenshot placeholders were. Every `FIGURE PLACEHOLDER` must have a corresponding open tracking
entry in `VISUAL-INVENTORY.md` (or its V2 equivalent) with an owner and evidence class; a part is
not considered done while it still contains unresolved placeholders. This is the mechanical fix
for weakness #2 and #3 — a placeholder is now a to-do with an owner, not a permanent stand-in.

### 9.3 Mermaid diagrams specifically

- A Mermaid source block must be preceded by one sentence of context (what relationship/flow it
  diagrams) and followed immediately by its Figure caption per §9.1, using evidence class
  `CONCEPTUAL` unless the diagram is a direct transcription of an official reference architecture
  (in which case use `OFFICIAL REFERENCE` and cite the source).
- Because Mermaid source was never rendered in V1, every Mermaid block in V2 must actually be
  rendered to a checked-in image (SVG/PNG) as part of that part's completion criteria — the
  Mermaid source stays in the Markdown as the maintainable source of truth, but the rendered image
  is what ships, referenced via standard Markdown image syntax directly below the source block and
  above the caption.

---

## 10. Cross-cutting notes for reviewers

- **Voice review and technical review are separate passes.** A reviewer checking callout-box
  format and filler-phrase bans should not also be the sole technical accuracy reviewer for that
  unit — this guide exists partly to enable the separation-of-duties fix (V1 weakness #1); folding
  style review back into a single author-reviewer defeats that purpose.
- **When in doubt, match this guide over matching V1.** V1 is a reference for content and scope,
  not for format — its inconsistency is the documented reason this guide exists.
- **This guide is versioned with the book.** If a convention here turns out to be unworkable once
  real chapters are drafted against it (particularly the evidence-class captioning in §9, which is
  new and untested at scale), propose a change with a rationale rather than silently drifting from
  it — silent drift is exactly how V1 ended up with five different shapes for one callout box.
