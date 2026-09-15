# Detection Engineering Handbook — STYLE-GUIDE.md (V2)

**Status:** Final, merged from two independently drafted style-guide proposals for adoption before any V2 unit is authored or reviewed.
**Applies to:** every part, appendix, detection, hunt, and diagram in the V2 rebuild.
**Audience:** every writer, technical reviewer, and editor working on V2.

## Why this document exists

V1 (`release-v1/`, read-only) was produced by 55 independent single-pass agents with no shared style contract, and the drift is real and diagnosable, not hypothetical — confirmed by direct audit of `release-v1/book/chapters/part04-windows-detection-engineering.md` and others: the same recurring callout ("Engineering Reality," "Blind Spot," "Detection Autopsy") renders as a bolded run-in, an H2, an H3, and a blockquote depending on which part you're in; content tags appear as bare `[TAG]` in one part and `**[TAG]**` in the next; Windows Event IDs appear as bare numbers with no first-use expansion in roughly a 30:1 ratio in a given chapter; MITRE IDs sometimes carry the technique name and sometimes don't; no diagram among 89 Mermaid sources was ever rendered to an image, and none of 71 screenshot placeholders was ever captured.

None of this is a judgment call — it's drift from having no style contract at all. This document is that contract. **"Must"** means a PR gets rejected if it doesn't comply. **"Should"** means deviate only with a reason recorded in the PR description. **"Avoid"** is a strong default a reviewer can override with justification, and a documented override is a guide change, not silent drift — silent drift is exactly how V1 ended up with five shapes for one callout box.

This guide governs prose voice, Markdown conventions, the eight recurring callout boxes, content-level tags, and the evidence-classification system for figures. It does not cover technical review standards (accuracy, false-positive analysis rigor, coverage claims) — that is a separate concern with a separate reviewer, per the production model in `BOOK-INDEX.md`, because voice/format consistency and technical correctness are different failure modes.

---

## 1. Voice and Tone

### 1.1 The core rule

Write like a senior detection engineer explaining a decision to a peer who will have to maintain the rule at 3 AM — not like a vendor blog post trying to rank for "XDR best practices 2026." The reader already knows what a SOC is; they do not need to be sold on the importance of security. Every sentence should survive the question: **what does this actually tell me to do, check, or expect?** If it doesn't, cut it.

Concretely:

- **State the claim, then the evidence.** Don't build up to it with scene-setting.
- **Name the failure mode; don't gesture at it.** "This breaks under X" beats "this can present challenges in certain scenarios."
- **Prefer the concrete number over the vague qualifier.** "Fires 40–200 times a day on a 10,000-endpoint estate" beats "generates a significant volume of alerts."
- **Name the mechanism, the field, the command, the threshold** — not the adjective. Say what happens, not that something is important.
- **Prefer active voice with a named actor** ("the attacker," "the rule," "Sysmon," "the analyst") over passive constructions that hide who does what. Passive is acceptable only when the actor genuinely doesn't matter ("the event is logged to the Security channel").
- **Commit to a claim.** If evidence is thin, say so explicitly ("this is untested against real Kerberoasting traffic — treat the threshold as a starting point") rather than hedging with vague qualifiers.
- Second person ("you") is fine for procedural instructions; first person plural ("we") is fine for the book's own reasoning. Neither should be used to manufacture urgency or as a substitute for a real subject in an explanatory sentence.
- It is okay to say a control is boring, cheap, or already solved. Not everything needs to sound like a breakthrough.

### 1.2 Banned filler — and the actual rule behind the ban

The patterns below are banned **only in their AI-marketing-filler usage** — as a load-bearing transition, hedge, or intensifier that could be deleted with no loss of meaning, or that signals "content" rather than a claim. Mechanically grepping-and-blocking normal English is explicitly wrong: several of these words have legitimate, specific uses that are fine to keep. **The reviewer's test: does this phrase carry information, or does it just sound like it does?** If a reviewer can delete the phrase and the sentence loses nothing, it's filler — cut it. If they can't, it's not the pattern this ban targets — leave it. Do not add a global regex ban to a CI check for this reason: it will both miss the actual pattern (which is about rhetorical function, not literal string) and false-positive on legitimate uses.

| Banned pattern (as filler) | Why it's banned | Legitimate exception |
|---|---|---|
| "in today's rapidly evolving threat landscape" | Says nothing; every landscape is always evolving | None — always cut, replace with the specific change you mean |
| "it is crucial / critical / important / paramount that..." | Asserts importance instead of demonstrating it | Rewrite as the concrete consequence of not doing the thing |
| "robust posture / robust detection" | "Robust" as a vague virtue word attached to abstract nouns | Fine describing a specific measurable property: "robust to clock skew up to 5 minutes" |
| "leveraging" | Nearly always means "using" | Keep only if something is literally used as leverage in a specific mechanical sense (rare) |
| "holistic" | Vague scope-inflation word | Cut; say what specific things are actually being combined |
| "seamlessly" | Unfalsifiable marketing adjective | Cut; if integration quality matters, describe the failure mode when it *isn't* seamless |
| "delve into" | AI-pattern verb-of-choice for "discuss/examine" | Use "look at," "cover," "walk through" |
| "in conclusion" / "to summarize" as a section opener | Signposting the reader doesn't need — headings already do this | None in body prose; the book doesn't use a literal debate/thesis structure |
| "it is important to note that..." | Hedge that adds no information; if worth saying, say it directly | None — cut the phrase, keep the note only if something remains |
| "landscape" (standalone, as in "security landscape") | Vague spatial metaphor standing in for a specific claim | Fine in a literal geographic/network topology sense ("network landscape" describing real segmentation) |
| "unlock / empower / elevate" as verbs for tools enabling actions | Marketing verbs, not engineering verbs | Use the literal verb: "lets you query," "gives you visibility into," "reduces the time to..." |
| "at the end of the day" | Filler transition | Cut |
| "game-changer / game-changing / cutting-edge / best-in-class" | Unfalsifiable superlative | Cut, or state the measurable change |

A phrase is **not** banned just because it contains one of these words. Two tests:

- "Sysmon Event ID 1 is important because it's the only source that reliably captures the full command line before argument-splitting obfuscation kicks in" — `important` is load-bearing and explained. Keep it.
- "The threat landscape for this technique changed materially after the vendor patched X" — a specific, falsifiable claim, not the stock phrase. Keep it.

### 1.3 Worked GOOD vs. BAD examples

**Example 1 — opening a section**

> BAD: "In today's rapidly evolving threat landscape, it is crucial for organizations to maintain a robust detection posture around privileged authentication events."

> GOOD: "4672 (Special Privileges Assigned) fires on every logon that receives a sensitive privilege — Domain Admin, local admin via UAC elevation, service accounts with SeDebugPrivilege. On a typical 5,000-seat estate that's 2,000–6,000 events a day. Alerting on the raw event is useless; alerting on 4672 *without* a matching baseline entry is the actual detection."

**Example 2 — describing a limitation**

> BAD: "It is important to note that this approach may present certain challenges when leveraging cloud-native telemetry sources."

> GOOD: "This breaks in AWS: CloudTrail's `userIdentity.arn` doesn't survive an assumed-role chain the way a Windows SID does, so the same baseline-by-identity logic you'd write for 4624 needs a different join key — `sourceIdentity` if it's populated, which it isn't for every service."

**Example 3 — closing a section**

> BAD: "In conclusion, a holistic, seamless approach to detection engineering will empower SOC teams to elevate their security posture."

> GOOD: "None of this works without the baseline table being refreshed on a schedule shorter than your average attacker dwell time. A 30-day-stale baseline is worse than no baseline — it tells the analyst 'seen before' about a host that was decommissioned three weeks ago."

**Example 4 — a hedge that should just be a claim**

> BAD: "It is crucial to note that Sysmon configuration is paramount to the quality of detections that leverage its telemetry."

> GOOD: "A permissive Sysmon config drowns the SIEM in Event ID 3 noise from routine browser traffic. An overly restrictive one — cutting common paths to save volume — creates the exact blind spot a recon'd attacker will walk through. Test config changes against a baseline capture before pushing fleet-wide."

**Example 5 — false confidence vs. honest uncertainty**

> BAD: "This detection provides robust, comprehensive coverage of lateral movement techniques."

> GOOD: "This detection covers PsExec-style lateral movement via Event ID 7045 (service installation) and 4624 Type 3 logons. It does not cover WMI-based lateral movement (see Part 11) or living-off-the-land binaries that don't touch the SCM."

### 1.4 Sentence and paragraph mechanics

- Default to active voice; passive only when the actor genuinely doesn't matter.
- One claim per sentence where possible. If a sentence needs three commas and an em dash to hold together, it's probably two sentences. Prefer sentences under ~30 words; if a sentence has more than one comma-joined independent clause carrying technical content, split it.
- One idea per paragraph. A paragraph that introduces a detection, then its blind spot, then a correlation, then a MITRE mapping should be four short paragraphs or a callout box, not one block.
- Numbers: use digits for Event IDs, ATT&CK IDs, port numbers, and any count ≥ 10; spell out one through nine in prose ("three failed logons," not "3 failed logons") — except inside tables, where digits are always used for scanability, and except for counts that are themselves paired with an identifier or unit (Event ID 4625, a 5-minute window, T1078), which always use digits regardless of size.
- Contractions ("doesn't," "isn't," "won't") are fine and preferred — this book has a spoken-voice register, not a legal-document register.

---

## 2. Heading Level Conventions

V1 used H1 for the part title and H2 for major sections consistently, but drifted between H2, H3, bold run-in text, and blockquotes for subsections and callouts across parts. V2 locks this down:

| Level | Use for | Example |
|---|---|---|
| `#` (H1) | Part title only. One per file, first line of the file. | `# Part 8 — Windows Detection Engineering` |
| `##` (H2) | Major numbered sections within a part (the part's own table-of-contents entries). Number sequentially: `## 1. Title`, `## 2. Title`. | `## 3. Kerberos authentication events` |
| `###` (H3) | Subsections within a major section — a specific event, a specific rule, a specific sub-topic. This is the standard slot for a named Windows/EDR event walkthrough. Number as `### 3.2 Title` under `## 3`, never restarted as an independent `### 1`. | `### 3.2 4769 — Kerberos Service Ticket Request` |
| `####` (H4) | Rare; only for structured sub-breakdowns inside a long H3 that need their own anchor (e.g., "Fields," "False positive drivers," "Tuning" inside one detection writeup, when those aren't rendered as callout boxes). Do not nest deeper than H4. | `#### Fields that matter` |

Rules:

- **Callout boxes are never headings** (see §6) — they are blockquotes opened with a bold label, at the same nesting level as the paragraph they annotate. A callout must not consume a heading level, and a heading must never be used as a way to bold a single line of text — that's what an inline `**bold:**` label or a callout box is for.
- Never skip a level (no H2 directly to H4).
- Every part must open with an unnumbered `## Why this part exists` section before numbering starts at `## 1.` — inconsistent in V1 (some parts had it, some didn't), now mandatory for all 48 parts.
- Every H2 and H3 must be unique within its file — needed for stable anchor links from the index and cross-references.
- Section titles are sentence case, not Title Case ("Kerberos authentication events," not "Kerberos Authentication Events"). Part titles use title case with an em dash, per the existing convention (`# Part 8 — Windows Detection Engineering`) — keep this one exception; it's already baked into the part list and rewriting it isn't worth the churn.
- When an Event ID gets a dedicated `###` walkthrough, format the heading as `### 4624 — An account was successfully logged on` — numeral first, no "Event ID" prefix in the heading itself (the heading text is a label, not a sentence; see §5 for how to refer to the same event in prose).

---

## 3. Code Block Conventions

Every fenced code block **must** carry an explicit language tag — an untagged fence, or a tag for a language that isn't the one actually shown, is a lint failure.

| Language / platform | Fence tag | Notes |
|---|---|---|
| Sigma rules | `` ```yaml `` | Sigma is YAML; do not invent a `sigma` tag — no renderer highlights it. |
| Splunk SPL | `` ```spl `` | One pipe-clause per line for anything with 3+ pipes; align `\|` at the start of the continuation line. |
| Microsoft Sentinel / Defender KQL | `` ```kql `` | |
| Elastic KQL / Lucene (Kibana search bar) | `` ```kql `` | Same tag as Sentinel KQL is acceptable since most renderers have no distinct dialect mode — **always disambiguate in the sentence immediately above the block** ("The following Sentinel KQL query..." / "The following Elastic KQL query..."). Never conflate with Elastic EQL. |
| Elastic EQL | `` ```eql `` | Do not merge with `kql`. |
| Google SecOps / Chronicle YARA-L | `` ```yaral `` | If the renderer's lexer doesn't support `yaral`, fall back to `` ```yaml `` only for YARA-L rules that are YAML-shaped; otherwise use `` ```text `` rather than mislabeling it. |
| YARA | `` ```yara `` | |
| Suricata / Snort rules | `` ```suricata `` (fall back to `` ```text `` if the renderer lacks a Suricata mode) | |
| PowerShell | `` ```powershell `` | Never `ps1` as the fence tag. |
| Bash / shell (attacker or defender commands) | `` ```bash `` | Pick the tag matching the actual shell (`powershell`, `bash`, `cmd`) — never a generic `shell`. |
| Raw log excerpts, event XML/JSON not meant to be executed | `` ```json ``, `` ```xml ``, or `` ```text `` | Use `json`/`xml` only if it's actually valid; a truncated/annotated excerpt with ellipses or inline comments should be `text` so a reader doesn't try to parse it and get confused. |
| Mermaid diagram source | `` ```mermaid `` | See §9 — the fenced source stays in the file as the editable source of truth alongside its rendered image reference, never deleted once rendered. |
| Conceptual/illustrative code (invented field names, teaching-only logic) | Same language tag as normal, **plus** a one-line label immediately above the fence: `CONCEPTUAL SAMPLE — <one clause on what's illustrative about it>` | Keep this V1 convention exactly as-is — it already worked well (see V1 part01, part07). Reserve it for teaching snippets embedded in prose; never label a real, deployed detection rule this way. |

Additional rules:

- Every code block that is a real detection query must be preceded by one sentence stating what platform/version it targets and followed by one sentence stating its main limitation (the false-positive driver, the coverage gap, or the field dependency) — or a pointer to the Blind Spot/False Positive Trap box that says so. A bare wall of query syntax with no framing is grounds for reviewer rejection.
- Inline code (single backtick) is for field names, single event IDs used as identifiers mid-sentence, filenames, and command names — e.g., `` `TargetLogonId` ``, `` `rundll32.exe` `` — never a substitute for a fenced block when showing more than one line of logic.
- Comments inside query code explain *why*, not restate the syntax: `// exclude backup service account — see FP Trap below`, not `// this is a NOT clause`.

---

## 4. Windows Event ID Notation

**Rule: "Event ID 4624" on true first use in the chapter, "4624" on subsequent uses.** This mirrors how the term is actually spoken in a SOC and avoids the V1 pattern of bare numbers appearing with no introduction at all.

- First mention in a chapter: `Event ID 4624 (An account was successfully logged on)` — include the short official Microsoft event name in parentheses on the very first introduction *in the chapter*, not just the section, since readers may jump in mid-chapter via the index.
- Every subsequent mention within the same section: bare `4624` is acceptable — inline-coded only when used as a field-like token in a table or code comment, plain text otherwise.
- When a new `##`/`###` section starts and re-references an Event ID introduced much earlier in the chapter (more than ~2 pages back), re-anchor once with the short form: "the 4624 discussed above" or the full "Event ID 4624" — reviewer's call based on distance.
- Callouts get their own first-use exception: write the ID in full inside the callout even if already spelled out in surrounding prose, since callouts are often skimmed out of order.
- Never "Event 4624" (drop "ID"), never "EID 4624," never lowercase "event 4624." "EventCode" is Splunk's literal field name, not a term to use in prose — it's fine inside an SPL code block since that's the real field.
- Tables use the bare number only.
- Ranges: "Event IDs 4624 and 4625," not "Event ID 4624 and 4625" or "Event ID 4624/4625." A true contiguous range uses an en dash: "Event IDs 4728–4733."
- Sysmon Event IDs follow the same rule but always disambiguate from Windows Security IDs on first use per chapter: "Sysmon Event ID 1 (Process Create)," not bare "Event ID 1" — Windows Security also has low-numbered events that create ambiguity.

---

## 5. MITRE ATT&CK ID Formatting

- **First reference in a section:** technique ID + name — `T1558.003 (Kerberoasting)`.
- **Subsequent references in the same section:** bare ID is fine — `T1558.003`.
- Always uppercase `T`, no space between `T` and the digits, sub-technique separated by a period: `T1550.002`, never `T1550-002` or `T1550.2`. Sub-technique dot-suffixes are never truncated. Never drop the `T` prefix or use pre-2020 flat numbering.
- Tactic references use the `TA` prefix the same way: `TA0006 (Credential Access)` on first use.
- A standalone `**MITRE:**` summary line (in a detection file, a table cell, or a per-entry reference block) always spells out ID + name in full for every technique listed, **regardless of prior mentions elsewhere in the chapter** — this line is meant to be read in isolation (e.g., pulled into `MITRE-COVERAGE.md`), so it cannot rely on the reader having read the surrounding prose. Correct: `**MITRE:** T1558.003 (Kerberoasting), T1558.004 (AS-REP Roasting)`. Incorrect: naming only the first of two, or naming neither.
- Never invent or guess an ID. If a technique doesn't map cleanly, say so in prose rather than forcing a tenuous MITRE tag — false MITRE coverage is worse than an honest gap, and gaps are exactly what `MITRE-COVERAGE.md` needs to reflect accurately.
- Do not mix ATT&CK versions silently. If a technique was deprecated, merged, or renumbered, use the current ID and note the old one in a parenthetical only if the change is relevant to why an older detection references the retired ID.

---

## 6. Callout Boxes — Exact Templates

V1 named eight recurring features in planning but never gave them a stable Markdown shape — `Detection Autopsy` alone appears as bold run-in text, an H2, an H3, and a blockquote across different parts, and several of the eight (Blind Spot, False Positive Trap, Detection Test, SOC Management View, What Would Change My Mind) barely appear at all as distinguishable boxes. **Every callout below gets one exact template. No part may invent its own variant.**

All eight use the same base shape: a **blockquote** (`>`) opened with a bold label line, so they are visually and structurally consistent with each other and distinguished only by label text and (for two of them) internal sub-structure. They sit inline in the flow of a section — never as a jump-target the table of contents would list separately, and never nested one inside another.

**General template:**

```
> **[Label — optional short qualifier]**
> Body text, 1–5 sentences. Can include inline code and a short code block if needed.
```

If a box needs more than ~5 sentences, it isn't a callout — promote it to a real `###`/`####` subsection with prose.

### 6.1 Detection Autopsy

Dissects a real or realistic detection rule that shipped broken: the naive version, why it seemed reasonable, how it failed, what replaced it. The highest-frequency callout in the book and the one with the most V1 drift.

```
> **Detection Autopsy — "<the naive rule in one clause>"**
>
> **The rule:** <what it literally does, plain description not code>.
>
> **Why it shipped:** <the reasonable-sounding logic that got this rule approved>.
>
> **How it failed:** <the specific false-positive or false-negative mechanism, with a concrete trigger scenario>.
>
> **The fix:** <what the corrected rule adds or changes>.
```

Worked example:

```
> **Detection Autopsy — the naive Kerberoasting rule**
>
> **The rule:** Fires on any Event ID 4769 requesting an RC4 (0x17) encryption ticket.
>
> **Why it shipped:** RC4 tickets are the textbook Kerberoasting signal, and the query is a
> one-line filter — cheap to write, easy to explain in a design review.
>
> **How it failed:** Most AD environments still have legacy applications and printers that
> haven't been updated to support AES, so this fires on every one of them — dozens of daily
> false positives per domain controller, none of them an attacker.
>
> **The fix:** Restrict to service-account principals only, and add a per-source-host
> request-rate threshold (see the False Positive Trap box below).
```

### 6.2 Hunter's Note

A tactical, practitioner-voice aside from a threat hunter's perspective — a tip, a pivot, or a "this is what actually gets you unstuck" observation. Shorter and more informal than the other boxes, but still no filler.

```
> **Hunter's Note**
> The tip or pivot, stated as something you'd actually say out loud to a hunter sitting next to you.
```

Worked example:

```
> **Hunter's Note**
> Logon ID (`TargetLogonId` in 4624, referenced again in 4672 and in process-creation events via
> the token) is the cheapest pivot you have for stitching one session together across event
> types. Pull it first, before correlating on username or source IP — both are reused across
> sessions and will pull in noise the Logon ID won't.
```

### 6.3 Engineering Reality

A grounded statement about what actually happens in production — vendor defaults, licensing limits, operational tradeoffs — as opposed to what the spec or documentation implies. Every arrow in the telemetry chain can silently drop or mutate data; say so at each hop where it matters.

```
> **Engineering Reality**
> The gap between documented/expected behavior and what you'll actually hit in production, stated
> as a fact, plus the practical consequence.
```

Worked example:

```
> **Engineering Reality**
> If your build doesn't explicitly enable Script Block Logging via GPO — it is not on by default
> in any supported Windows version as of this writing — Event ID 4104 simply will not exist in
> your logs, and every detection in this section that depends on it will silently produce zero
> results rather than an error. Verify the GPO is applied before trusting an empty result set as
> "clean."
```

### 6.4 Blind Spot

A specific, named gap in what a detection or telemetry source can see — never a vague disclaimer.

```
> **Blind Spot**
> What this detection/source cannot see, stated specifically — the technique variant, the
> transport, or the condition that defeats it.
```

Worked example:

```
> **Blind Spot**
> Event ID 4624 tells you a logon succeeded; it does not tell you what the session did
> afterward. An attacker who authenticates cleanly with valid, stolen credentials and never
> triggers a process-creation or object-access event you're monitoring produces a 4624
> indistinguishable from a legitimate logon. You need session-activity correlation, not this
> event alone, to catch that case.
```

### 6.5 False Positive Trap

Names a specific, common legitimate activity that will trigger the detection, and what to do about it.

```
> **False Positive Trap**
> The specific legitimate behavior that triggers this detection. The fix: exclusion, threshold,
> or enrichment that resolves it — or an explicit statement that this is a tuning tradeoff with
> no clean fix.
```

Worked example:

```
> **False Positive Trap**
> Backup and vulnerability-scanning service accounts routinely authenticate against dozens of
> hosts in a short window using NTLM, which looks identical to the lateral-movement pattern this
> rule targets. Maintain an explicit allowlist of known scanner/backup service-account SIDs and
> exclude them at the query level — do not raise the host-count threshold to "fix" this, since
> that just raises the bar for a real attacker too.
```

### 6.6 Detection Test

A concrete, reproducible test procedure — usually a lab-safe attack-simulation command or tool invocation — used to validate the detection actually fires, plus the expected result.

```
> **Detection Test**
> **Setup:** lab prerequisites, one line.
> **Action:** `the exact command or tool invocation`
> **Expected result:** what should appear in the log/SIEM, specifically — event ID, field values.
```

Worked example:

```
> **Detection Test**
> **Setup:** Domain-joined Windows test host, Sysmon installed, no local admin rights required.
> **Action:** `Rubeus.exe kerberoast /outfile:hashes.txt`
> **Expected result:** One or more Event ID 4769 entries with `TicketEncryptionType` = `0x17`
> and a `ServiceName` matching a real SPN-registered service account, source `IpAddress`
> matching the test host.
```

### 6.7 SOC Management View

Aimed at the reader's decision-making at the manager/CISO level — cost, staffing, risk-acceptance, or metrics framing, not telemetry mechanics. This is the one box type explicitly allowed to discuss process/policy rather than detection logic.

```
> **SOC Management View**
> The management-level tradeoff, cost, staffing implication, or risk decision this technical
> content maps to, stated in terms a CISO would use in a budget or risk conversation.
```

Worked example:

```
> **SOC Management View**
> Event ID 1102 (audit log cleared) is one of the few Windows events where the correct SOC
> policy is "zero-tolerance page-out, no tuning, no exceptions" — it should never fire in a
> healthy environment, and every occurrence should generate a Tier 2 escalation regardless of
> source. If your team is routinely triaging 1102 as noise, that's a signal about scoping
> (someone has a legitimate reason to clear logs regularly) that needs a policy fix, not a
> detection-tuning fix.
```

### 6.8 What Would Change My Mind

An explicit falsifiability statement — what evidence, if observed, would change the stated conclusion or confidence level. Used to keep the handbook honest about the strength of its own claims, and to model intellectual honesty from Part 1 onward.

```
> **What Would Change My Mind**
> The specific observation, data point, or test result that would overturn or materially revise
> the claim just made — a concrete, checkable condition, not a vague "more research needed."
```

Worked example:

```
> **What Would Change My Mind**
> This detection assumes legitimate AS-REP requests without pre-authentication are rare enough
> to threshold on count alone. If a production audit showed more than 2% of accounts have "Do
> not require Kerberos preauthentication" set for a legitimate legacy-app reason, the
> count-based threshold would need to move to an allowlist-based approach instead, and this
> section's confidence rating would drop from High to Medium.
```

### 6.9 Callout usage density

A single detection writeup typically carries one Detection Autopsy, zero-to-one Blind Spot, zero-to-one False Positive Trap, and one Detection Test; the other four are used opportunistically. A section stacking all eight callouts is over-boxed — if every paragraph needs an annotation, the prose isn't doing its job.

---

## 7. Content-Level Tags

Format locked to `**[TAG]**` — bold, brackets, all caps, placed at the start of the paragraph or subsection it governs. V1's bare `[TAG]` variant is retired. Never a heading, never a footer note, never two tags on one paragraph (`[ANALYST] [DETECTION ENGINEER]` on the same paragraph is a sign the paragraph is doing two jobs — split it).

| Tag | Use for | Do not use for |
|---|---|---|
| `[CONCEPT]` | Foundational explanation of how a technology, protocol, or technique works, with no assumption the reader acts on it directly — the "what and why" a reader needs before anything else in the section makes sense. | Anything that gives a specific query, threshold, or command — that's a lower tag even if conceptually simple. |
| `[ANALYST]` | Triage-facing content: what an alert means, what to check first, how to tell true positive from false positive in the moment, escalation criteria. | Content about building or tuning the detection itself — that's `[DETECTION ENGINEER]`. |
| `[DETECTION ENGINEER]` | Rule logic, field selection, thresholds, exclusions, query syntax, platform-specific implementation detail, and the reasoning behind design tradeoffs. | Triage guidance for someone who didn't write the rule — that's `[ANALYST]`. |
| `[THREAT HUNTER]` | Hypothesis-driven exploration: pivots, exploratory queries, "what would this look like if the standing detection missed it," proactive search technique. | A named, deployable detection rule — even if a hunt becomes one, tag the finished rule `[DETECTION ENGINEER]` and keep the hunting narrative `[THREAT HUNTER]`. |
| `[ENGINEERING]` | Infrastructure/pipeline concerns: log-source onboarding, parsing, normalization, retention, pipeline cost/performance, SIEM architecture — the plumbing that has to exist before any detection or hunt can run. | Detection rule logic itself — `[ENGINEERING]` is about the platform the rule runs on, not the rule. |
| `[SOC MANAGEMENT]` | Staffing, process, metrics, budget, and risk-acceptance framing aimed at someone deciding how the SOC operates. Overlaps in spirit with the SOC Management View callout (§6.7) but can appear as ordinary tagged prose too. | Any content with a specific technical action embedded — if a management-tagged paragraph starts specifying a query, split it. |

Tagging guidance:

- Most `##` sections carry more than one tag across their subsections — a single section on Kerberoasting plausibly has a `[CONCEPT]` opening, `[DETECTION ENGINEER]` rule-building content, an `[ANALYST]` triage subsection, a `[THREAT HUNTER]` hunting angle, and a `[SOC MANAGEMENT]` callout. That's expected and good — it's how one topic serves the full audience range (SOC analyst through CISO) this handbook targets.
- `[CONCEPT]` is the only tag allowed to open a section before any other tag appears — every section needs grounding before it gets role-specific.
- The two pairs authors most often confuse: `[DETECTION ENGINEER]` (rule logic) vs. `[ENGINEERING]` (pipeline/volume/retention that the rule runs on top of); `[ANALYST]` (responding to a fired alert) vs. `[THREAT HUNTER]` (looking without a triggered alert). When in doubt, ask "is this about the plumbing, the rule, the response, or the search" and match to the tag whose column that falls under above.

---

## 8. Table Conventions

- Every data table gets a one-line lead-in sentence stating what decision it supports, not just "the following table shows..." — e.g., "The table below maps Windows Logon Type values to their typical legitimate and attacker-abuse patterns."
- Header row uses short noun phrases, capitalized like a title ("Typical Legitimate Source," not "typical legitimate source" or a full sentence).
- Left-align text columns; skip explicit `:---:` alignment markers unless a column is genuinely numeric and benefits from right-alignment.
- Cell content: fragments, not full sentences with terminal periods, unless a cell genuinely needs more than one sentence (rare — if so, reconsider whether it belongs in a table at all).
- Bare IDs in the first column. Field names, event IDs used as literal values, and command names inside cells use inline code ticks, same as in prose: `` `LogonType` ``, `` `taskeng.exe` ``.
- Never leave a cell blank — use an em dash "—" for "not applicable" so the omission is visibly deliberate.
- MITRE IDs get their own greppable column and must follow the §5 formatting rules inside the cell too — a table is not an exemption.
- Tables built from invented/illustrative data are marked `(CONCEPTUAL SAMPLE)` in the caption, same standard as code blocks in §3.

---

## 9. Figures, Diagrams, and Screenshots: Evidence Classification

V1 shipped 89 Mermaid diagrams never rendered to an image file and 71 screenshot placeholders never captured. V2's caption format exists specifically to make the **evidence class of every visual claim** explicit and auditable, so a reader (or a future review pass) can immediately tell a real captured screenshot from an aspirational placeholder from a conceptual sketch. Every figure — rendered diagram or screenshot, captured or still pending — uses this format, no exceptions.

### 9.1 Evidence classes (exactly four, always tagged)

| Tag | Meaning | Allowed for |
|---|---|---|
| `CONTROLLED LAB EXAMPLE` | Captured in a lab the author built specifically to generate this evidence (attack simulated, telemetry captured, screenshot/log taken from that run). | Screenshots, exported log excerpts, packet captures. |
| `REAL LAB EXAMPLE` | Captured from a real, pre-existing environment observing organic activity, or a simulated attack run against real infrastructure. Must be scrubbed of real secrets/PII before inclusion. | Screenshots, exported log excerpts. |
| `OFFICIAL REFERENCE` | Sourced from vendor documentation, a public standard, or another authoritative published source, reproduced or closely adapted with attribution. | Vendor console screenshots, official schema diagrams — must cite the source in `REFERENCES.md`. |
| `CONCEPTUAL` | An illustrative diagram with no claim of being captured from a real system — an architecture sketch, a data-flow diagram, a sequence diagram of expected behavior. | Mermaid diagrams, hand-drawn architecture figures. |

A figure with no real captured evidence behind it yet — the V1 default — is `CONCEPTUAL` if it's a diagram, or an explicit **pending placeholder** (§9.3) if it's meant to eventually be a screenshot. Never label an uncaptured, aspirational screenshot `CONTROLLED LAB EXAMPLE` "because it will be captured later" — the tag describes what evidence backs the figure *right now*. Screenshot filenames must additionally carry a `REAL-LAB-` or `SYNTH-UI-` prefix at the filesystem level (see the visuals naming convention referenced from `BOOK-INDEX.md`); `SYNTH-UI-` (a clearly labeled synthetic mockup) is permitted only when a real capture is genuinely infeasible and must be logged in `VISUAL-INVENTORY.md` with a reason.

### 9.2 Caption format — rendered figure (diagram or captured screenshot)

```
**Figure N.M — [Short descriptive title].** *[Evidence class tag].* One to two sentences: what
the figure shows and what it's evidence of, or — for CONCEPTUAL diagrams — what it illustrates
rather than proves. If OFFICIAL REFERENCE: source citation. If CONTROLLED/REAL LAB EXAMPLE: lab
context — host OS/version, tool used, capture date if relevant to tool-version drift.
```

Worked examples:

```
**Figure 2.2 — Kerberoasting request/response sequence.** *CONCEPTUAL.* Illustrates the expected
sequence of a Kerberoasting attempt against a service account with a weak password, from TGS
request through offline hash cracking. This is a sequence diagram of expected protocol behavior,
not a capture from a real attack run — see Figure 13.3 for a captured example from the
controlled lab.
```

```
**Figure 13.3 — Event ID 4769 entry for a Kerberoasting TGS request.** *CONTROLLED LAB EXAMPLE.*
Windows Security Event Log entry captured on a Windows Server 2022 domain controller in the
project's isolated AD lab, following a Rubeus-driven Kerberoasting run against a deliberately
weak-password service account (see the Detection Test box in §3). Captured 2026-09-02; field
layout may differ on non-English locales or older Server builds.
```

```
**Figure 9.1 — Sysmon event schema overview.** *OFFICIAL REFERENCE.* Reproduced/adapted from the
Microsoft Sysinternals Sysmon documentation (schema version noted in the source). See
REFERENCES.md entry [SYSMON-DOCS] for the full citation and retrieval date.
```

### 9.3 Pending placeholder format (only for figures not yet captured/rendered)

V2's goal is zero unresolved placeholders at release, but during drafting a unit may reference a figure that doesn't exist yet. Use this exact blockquote format so pending figures are grep-able, tracked in `VISUAL-INVENTORY.md`, and never mistaken for finished body text:

```
> **[FIGURE PENDING — target evidence class: <CONTROLLED LAB EXAMPLE | REAL LAB EXAMPLE |
> OFFICIAL REFERENCE | CONCEPTUAL>]** What the figure will show, one sentence. Why it isn't
> captured/rendered yet, one sentence. What claim in the surrounding text it would support.
```

A reviewer finding this block logs it in the tracked-placeholder list; it must be resolved (rendered image or captured screenshot swapped in, with the §9.2 caption format) before the unit ships — never left as permanent handbook content the way it was in V1.

---

## 10. Diagram Rendering Requirement

Because "diagrams were never rendered" is a named V1 defect, V2 treats a Mermaid code block as a draft, not a deliverable:

- Every `` ```mermaid `` block must be rendered to a static image (SVG preferred, PNG acceptable) and committed alongside the source, referenced via the §9.2 caption format with a real evidence-class tag (almost always `CONCEPTUAL` for a diagram, unless it's a literal reproduction of an `OFFICIAL REFERENCE` diagram).
- The Mermaid source stays in the file, directly above or below the rendered image reference — it is the editable source of truth, not dead weight to delete once rendered.
- A unit is not review-complete if it contains a `mermaid` fence with no paired rendered figure reference. This is enforced as a build check, not a manual convention (see `BOOK-INDEX.md` production model).

---

## 11. Review Checklist (for the independent reviewer, per unit)

This is the enforcement mechanism for everything above, and the direct fix for V1 defect #1 — every V2 unit gets an author and a separate reviewer, and **voice review and technical review are separate passes**; no reviewer should be the sole author-and-reviewer for both format and accuracy. Work from this list, not from vibes:

1. **Voice:** any banned filler pattern present without being rewritten? Any sentence that doesn't survive the "what does this tell me to do/check/expect" test?
2. **Headings:** correct level nesting, no heading used as a bold-line substitute, `## Why this part exists` present?
3. **Code blocks:** every fence tagged, every tag correct for the actual query language shown, framing sentences present for real detection queries?
4. **Event IDs:** "Event ID NNNN" on true first use, bare `NNNN` after, no "EID"/"Event NNNN" variants?
5. **MITRE IDs:** name present on first use per section and in every standalone `**MITRE:**` line, correct ID format, no invented mappings?
6. **Callouts:** correct label string, correct blockquote structure, body length in range, no box type nested in another, density not excessive (§6.9)?
7. **Tags:** every `##`/`###` subsection carries at least one `[TAG]`, no paragraph carries two?
8. **Tables:** lead-in sentence present, no blank cells, code-tick usage consistent with prose, MITRE/Event ID formatting followed inside cells?
9. **Figures:** every figure has a caption with an evidence-class tag; every pending figure uses the `[FIGURE PENDING]` blockquote and is logged in `VISUAL-INVENTORY.md`; every Mermaid block has (or is tracked toward) a paired rendered image?
10. **Depth check (V1 defect #4):** does this unit's technical depth match sibling units covering comparable scope? Flag thin sections rather than silently accepting breadth-only coverage.

Match this guide over matching V1's inconsistent precedent. Any deviation a reviewer approves gets recorded as a documented change to this file, not silent local drift.
