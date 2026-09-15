# The Detection Engineering Handbook — V2

**BOOK-INDEX.md — canonical part list and appendix list for the V2 rebuild.**
**Status:** Adopted architecture, synthesized from three independent architect proposals (Proposal 1, Proposal 2, Proposal 3). Supersedes `release-v1/BOOK-INDEX.md`.

## What this book is

A detection engineering handbook for SOC analysts, detection engineers, threat hunters, SIEM engineers, and SOC managers, organized so that each of those readers can find their depth without wading through the others'. The book has two structural layers running through every domain part: a **telemetry layer** (what the data is, what it actually captures, where it lies to you) and an **analytic layer** (what you build with that data — rules, correlations, scores, hunts). Domain parts state explicitly, in their opening scope paragraph, which layer they are and which neighboring part owns the layer they are *not* covering — this is the single biggest mechanical fix carried over from all three architecture proposals, aimed directly at V1's silent-duplication problem (the same concept, e.g. PowerShell logging or DNS tunnelling, explained slightly differently in two different parts with no cross-reference).

## Multi-level content model

Every part is written to serve multiple readers in the same pages rather than five separate books. Content is marked with one of six **content tags**, placed as a bold bracketed label at the start of the paragraph or subsection it governs (never as a heading, never doubled on one paragraph):

- `[CONCEPT]` — foundational "what and why," no assumption the reader acts on it directly.
- `[ANALYST]` — triage-facing: what an alert means, what to check first, escalation criteria.
- `[DETECTION ENGINEER]` — rule logic, field selection, thresholds, query syntax, design tradeoffs.
- `[THREAT HUNTER]` — hypothesis-driven exploration, pivots, "what would this look like if it wasn't caught."
- `[ENGINEERING]` — pipeline plumbing: onboarding, parsing, normalization, retention, cost, performance.
- `[SOC MANAGEMENT]` — staffing, process, metrics, budget, and risk-acceptance framing.

Layered on top of the tags are eight **recurring callout features**, each with one fixed Markdown template (defined in `STYLE-GUIDE.md`) so a reader can recognize and grep for them consistently across all 48 parts: **Detection Autopsy** (a naive rule dissected and rebuilt), **Hunter's Note** (a practitioner pivot/tip), **Engineering Reality** (documented behavior vs. what production actually does), **Blind Spot** (a named, specific visibility gap), **False Positive Trap** (a specific legitimate activity that triggers the rule, and the fix), **Detection Test** (a reproducible validation procedure), **SOC Management View** (the management/cost/staffing angle), and **What Would Change My Mind** (a falsifiability statement — what evidence would overturn this claim). Several weak "naive rule" patterns (PowerShell execution = malicious, five failed logins = brute force, foreign country = compromise, long DNS label = tunnel, curl in UA = attacker, unsigned process = malware, rare domain = malicious) are deliberately **seeded** in their natural source part as a Detection Autopsy teaser and **paid off once**, fully, in the Part 40 capstone — giving the book a narrative through-line V1 never had.

## Production model (cross-cutting, applies to every part/detection/hunt file)

Every chapter, detection, and hunt file carries mandatory YAML front matter: `author`, `reviewer` (a different person/agent, mandatory, technical-adversarial not copy-edit), `status` (draft → reviewed → tested → released), `last_validated`, and `depends_on` (the part/chapter IDs it assumes). Nothing ships to `released` without a reviewer sign-off recording at least one attempted technical objection. This operationalizes "separation of duties" as a blocking field rather than a policy statement — direct repair of V1's known weakness #1 (55 independent single-pass authors, no reviewer). Detections, hunts, diagrams, and screenshots carry permanent global IDs (`DET-####`, `HUNT-####`, `FIG-####`) independent of their position in the book, tracked in `DETECTION-INVENTORY.md`, `HUNT-INVENTORY.md`, and `VISUAL-INVENTORY.md`, so the next reorganization never breaks a cross-reference. A build check fails if a chapter cites a `FIG-####` with no rendered file present, or a query file with no matching detection ID in the ledger — converting V1's "89 diagrams, 0 rendered / 71 screenshots, 0 captured" from a promise into a gate.

---

## Part Table

*File path pattern:* `C:\Users\User\projects\detection-engineering-handbook\release-v2\chapters\partNN-slug.md`

### Section A — Foundations

| Part | Title | File Path | Scope | Recurring Features |
|---|---|---|---|---|
| 1 | Detection Engineering Foundations | `chapters\part01-detection-engineering-foundations.md` | Rule vs. analytic vs. use case vs. alert vs. detection vs. incident vs. hunt, worked example naming the same behavior at each layer; the four detection paradigms as a spectrum, not categories; the detection lifecycle; a terminology-level preview of detection-as-code and coverage that explicitly forward-references Parts 22 and 41 rather than re-explaining them. | What Would Change My Mind, SOC Management View |
| 2 | From Attack to Telemetry | `chapters\part02-from-attack-to-telemetry.md` | The book's visual spine: attacker action → OS/API call → artifact → log → collector → parser → normalisation → SIEM/lake → analytic, walked once abstractly and once with one concrete worked example traced end to end with a real rendered diagram at every hop. | Engineering Reality, Blind Spot |
| 3 | Telemetry Engineering I: Host & Identity Sources | `chapters\part03-telemetry-engineering-i-host-and-identity-sources.md` | Windows, Sysmon, PowerShell, EDR, Linux, auditd, SSH, and identity telemetry scored on visibility, blind spots, volume, quality, retention, cost, field completeness, and parser reliability. Deliberately deep on Linux/auditd/SSH and generic EDR — the only place in the book they get systematic treatment. | Blind Spot, Engineering Reality, SOC Management View |
| 4 | Telemetry Engineering II: Network, Application & AI Sources | `chapters\part04-telemetry-engineering-ii-network-application-and-ai-sources.md` | DNS, proxy, firewall, NDR/Zeek/NetFlow, email, cloud, web/WAF/API, database, and AI systems telemetry, same scoring model. Deliberately deep on proxy, firewall, NDR/NetFlow, and database — none of these get a dedicated deep-dive part later. | Blind Spot, Engineering Reality, SOC Management View |

### Section B — Data & Pipeline Foundations

| Part | Title | File Path | Scope | Recurring Features |
|---|---|---|---|---|
| 5 | Parsers | `chapters\part05-parsers.md` | How parser problems kill detections silently — field-mapping drift, encoding mismatches, truncation, partial ingestion, vendor log-format changes — plus a parser-health monitoring pattern and a real before/after break case study. | Engineering Reality, Blind Spot, Detection Test |
| 6 | Normalisation | `chapters\part06-normalisation.md` | ECS, OCSF, UDM, ASIM, and major vendor schemas, taught as a translation problem with one event mapped into all four; SIEM-migration cost folded in here as the natural consequence of normalisation choices. | Engineering Reality, SOC Management View |
| 7 | Time | `chapters\part07-time.md` | UTC vs. local, DST transitions, event vs. ingestion vs. processing time, clock drift, and pipeline delay, with a worked correlation-rule failure across a DST boundary; retention-window mechanics folded in as a time-and-cost subsection. | Engineering Reality, Detection Autopsy, Blind Spot |

### Section C — Windows, Identity & Endpoint Detection Engineering

| Part | Title | File Path | Scope | Recurring Features |
|---|---|---|---|---|
| 8 | Windows Detection Engineering | `chapters\part08-windows-detection-engineering.md` | Native Windows Security/System log architecture, ETW basics, key event IDs at field-by-field depth, what the native log does and doesn't capture before Sysmon exists. Telemetry layer — explicitly does not re-teach Sysmon (Part 9) or PowerShell logging (Part 10). | Detection Autopsy, Engineering Reality, Detection Test |
| 9 | Sysmon Detection Engineering | `chapters\part09-sysmon-detection-engineering.md` | Config-as-code, event ID coverage, filtering strategy, deployment at scale, and Sysmon's own blind spots/tamper surface. Telemetry layer — cross-referenced to, not duplicating, commercial EDR telemetry. | Engineering Reality, Blind Spot, Detection Test |
| 10 | PowerShell Detection Engineering | `chapters\part10-powershell-detection-engineering.md` | 4103/4104 logging, AMSI concepts and bypass surface (defensive framing only), execution policy as a non-control, encoding/obfuscation, download cradles, network correlation. Telemetry layer — owns all PowerShell detection logic exclusively; Part 11 is barred from re-covering it. | Detection Autopsy (seed), False Positive Trap |
| 11 | Endpoint Detection Engineering | `chapters\part11-endpoint-detection-engineering.md` | Analytic layer, explicitly cross-OS: process trees, LOLBins (LOLBAS + GTFOBins), credential access beyond Windows (LSASS, SAM, DPAPI, `/etc/shadow`, SSH keys, cloud instance-metadata theft), persistence across Windows services/tasks/registry *and* Linux cron/systemd/init, ransomware precursors, defence evasion, security-tool tampering. Flagship depth. | Detection Autopsy, Hunter's Note, False Positive Trap, Detection Test |
| 12 | Identity: Access & Authentication Detection | `chapters\part12-identity-access-and-authentication-detection.md` | Brute force, password spray, login-after-failure, MFA abuse/fatigue, account takeover, impossible travel, new device/country — IdP/SSO/sign-in-log-driven. | Detection Autopsy (seed), False Positive Trap, Detection Test |
| 13 | Identity: Directory, Privilege & Kerberos Detection | `chapters\part13-identity-directory-privilege-and-kerberos-detection.md` | Privilege changes, service-account misuse, Kerberoasting, AS-REP roasting, pass-the-hash/ticket, DCSync, LDAP enumeration, admin-group changes — AD/Kerberos-protocol-driven. | Detection Autopsy, Hunter's Note |

### Section D — Network & Application Domains

| Part | Title | File Path | Scope | Recurring Features |
|---|---|---|---|---|
| 14 | Network Detection Engineering | `chapters\part14-network-detection-engineering.md` | Port/horizontal/vertical scan, beaconing, C2, rare destinations, TLS signals, SMB/RDP/SSH abuse, Tor/proxy abuse, exfiltration. DNS tunnelling and domain-rarity scoring explicitly excluded, cross-referenced to Part 15. | Hunter's Note, Blind Spot, Detection Autopsy (seed) |
| 15 | DNS Detection Engineering | `chapters\part15-dns-detection-engineering.md` | Entropy scoring, rare/first-seen domains, NXDOMAIN patterns, DGA, TXT-record abuse, subdomain frequency, tunnelling, resolver context. Owns all DNS-tunnelling logic exclusively. | Detection Autopsy (seed), Hunter's Note, Detection Test |
| 16 | Web Detection Engineering | `chapters\part16-web-detection-engineering.md` | SQLi, XSS, traversal, LFI/RFI, command injection, RCE, SSRF, file upload abuse, web shells, admin-panel discovery, bot behaviour, credential stuffing, API abuse. | False Positive Trap, Detection Test, Detection Autopsy (seed) |
| 17 | Email Detection Engineering | `chapters\part17-email-detection-engineering.md` | Phishing, BEC, impersonation, header analysis, SPF/DKIM/DMARC failure semantics, URL/attachment analysis, QR-code phishing, OAuth consent-grant abuse, malicious inbox rules. | False Positive Trap, Hunter's Note |
| 18 | Cloud Identity & SaaS Detection Engineering | `chapters\part18-cloud-identity-and-saas-detection-engineering.md` | Entra ID, Okta, Google Workspace, M365, OAuth/app-consent abuse, cross-tenant/guest risk, conditional-access bypass — split from infrastructure so each can go deep instead of wide-and-shallow. | Detection Autopsy, False Positive Trap, Detection Test |
| 19 | Cloud Infrastructure Detection Engineering | `chapters\part19-cloud-infrastructure-detection-engineering.md` | AWS/Azure/GCP control-plane logging architecture and delivery-lag characteristics, IAM policy abuse, storage/network exposure, admin API actions, credential usage, mass access/exfiltration. | Engineering Reality, Blind Spot, SOC Management View |

### Section E — AI Security

| Part | Title | File Path | Scope | Recurring Features |
|---|---|---|---|---|
| 20 | AI Systems Telemetry & Audit-Trail Engineering | `chapters\part20-ai-systems-telemetry-and-audit-trail-engineering.md` | What to actually log for LLM/agent systems (prompts, tool calls, retrieval events, connector actions), a defensible audit-trail model, and privacy/data-minimisation tradeoffs. Telemetry layer, split out because "what should I even log, and what's the privacy exposure" is a distinct, high-stakes question. | Engineering Reality, Blind Spot, SOC Management View |
| 21 | AI Security Detection Engineering | `chapters\part21-ai-security-detection-engineering.md` | Analytic layer, built on Part 20: direct/indirect prompt injection, malicious file upload, RAG/KB poisoning, sensitive-data leakage, agent/tool/MCP abuse, AI API compromise, token-consumption anomalies, connector/browser-agent/code-agent abuse. | Detection Autopsy, What Would Change My Mind, Hunter's Note |

### Section F — Detection as Code & Query Languages

| Part | Title | File Path | Scope | Recurring Features |
|---|---|---|---|---|
| 22 | Detection as Code | `chapters\part22-detection-as-code.md` | Git-based rule repos, branching, PR review gates, metadata standards, lint/syntax validation, unit/regression tests, CI/CD, release/rollback, ownership, versioning. Reintroduces separation of duties (author ≠ reviewer ≠ merge-approver) as a structural CI-enforced requirement. | SOC Management View, Detection Test, Engineering Reality |
| 23 | Query Language Strategy | `chapters\part23-query-language-strategy.md` | Short bridging part. One canonical detection (a suspicious LSASS-access pattern) carried through the entire part, previewing how it will be expressed in each of the six languages that follow; Sigma-as-portable-authoring vs. native-query tradeoffs, translation loss, backend field-mapping gaps. | Engineering Reality, What Would Change My Mind |
| 24 | Sigma | `chapters\part24-sigma.md` | Syntax, correlation rules, testing, backend translation limits — implemented against the canonical detections carried from Part 23 and pulled from Parts 8–21. | Detection Test, Engineering Reality |
| 25 | KQL (Sentinel/Defender) | `chapters\part25-kql-sentinel-defender.md` | Syntax, joins, `summarize`, time-window functions, performance at scale. | Detection Test, False Positive Trap |
| 26 | Splunk SPL | `chapters\part26-splunk-spl.md` | Syntax, `stats`/`transaction`, search-time vs. index-time fields, subsearch cost. | Detection Test, Engineering Reality |
| 27 | QRadar AQL | `chapters\part27-qradar-aql.md` | Syntax, AQL's more limited correlation model, where it forces different detection design than KQL/SPL. | Engineering Reality, Blind Spot |
| 28 | YARA-L / Google SecOps | `chapters\part28-yara-l-google-secops.md` | Syntax, UDM-native detection design. | Engineering Reality, Detection Test |
| 29 | Elastic (EQL/KQL/ES\|QL) | `chapters\part29-elastic-eql-kql-esql.md` | Syntax across all three Elastic query surfaces and when to use which. | Detection Test, Engineering Reality |

### Section G — Advanced Analytic Techniques

| Part | Title | File Path | Scope | Recurring Features |
|---|---|---|---|---|
| 30 | Correlation Engineering | `chapters\part30-correlation-engineering.md` | Single- vs. multi-event rules, sequence logic, time windows, joins, entity resolution, and the failure modes: late/missing/duplicate events, ordering, clock skew (built directly on Part 7). | Engineering Reality, Detection Autopsy |
| 31 | Baselining | `chapters\part31-baselining.md` | User/host/role/peer-group/service-account/application/network/time/geo baselines; cold-start problem, travel, VPN, maintenance windows, role changes, seasonality. Placed before Threat Intelligence and Risk-Based Detection because both treat "rarity" as an input that only means something once a baseline exists. | False Positive Trap, Engineering Reality, Hunter's Note |
| 32 | Threat Intelligence in Detection | `chapters\part32-threat-intelligence-in-detection.md` | Reputation, confidence scoring, indicator age, first/last-seen, infrastructure role, prevalence, local context — organized around "IP bad ≠ incident." Moved here, immediately before Risk-Based Detection, because that part's own scope treats threat intel as a scoring input. | Detection Autopsy (seed), What Would Change My Mind |
| 33 | Risk-Based Detection | `chapters\part33-risk-based-detection.md` | Identity privilege weighting, asset importance, threat-intel confidence (Part 32), statistical rarity (Part 31), detection confidence, sequence/kill-chain completion scoring, and the honest failure modes of risk scores. Synthesis technique, placed last among its own dependencies. | SOC Management View, What Would Change My Mind, Detection Autopsy |

### Section H — Threat Hunting

| Part | Title | File Path | Scope | Recurring Features |
|---|---|---|---|---|
| 34 | Threat Hunting Fundamentals | `chapters\part34-threat-hunting-fundamentals.md` | Hypothesis formation, telemetry requirements, scoping, query construction, pivoting, enrichment, timeline building, conclusion, and converting a hunt into a detection candidate. Defines the Hunter's Note voice for the rest of the book. | Hunter's Note, What Would Change My Mind |
| 35 | Hunt Types | `chapters\part35-hunt-types.md` | IOC-based, TTP-based, anomaly-based, intel-led, incident-led, gap-driven, and retrospective hunts, each with a worked mini-example. | Hunter's Note, Detection Autopsy |
| 36 | Hunt to Detection | `chapters\part36-hunt-to-detection.md` | Pattern discovery → historical validation → feature selection → analytic authoring → test → deploy → monitor, closing the loop back into Part 22's detection-as-code pipeline. | Detection Test, Engineering Reality |

### Section I — Testing & Quality Engineering

| Part | Title | File Path | Scope | Recurring Features |
|---|---|---|---|---|
| 37 | Detection Testing | `chapters\part37-detection-testing.md` | Fires correctly, fires for the right reason, doesn't fire on normal activity, missing fields, duplicate events, parser failures, event delays, clock skew, schema change, case sensitivity, truncation, high volume, time-window boundaries — each with a concrete test-case pattern. Defines the Detection Test voice for the rest of the book. | Detection Test, Engineering Reality |
| 38 | False Positive Engineering | `chapters\part38-false-positive-engineering.md` | FP taxonomy, tuning workflow, suppression vs. rewriting, exception lists as technical debt, measuring FP rate honestly. | False Positive Trap, SOC Management View |
| 39 | False Negative Engineering | `chapters\part39-false-negative-engineering.md` | Missing telemetry, wrong assumptions baked into logic, overly specific matching, parser changes silently breaking extraction, data gaps, attacker variation, schema changes. | Blind Spot, Detection Autopsy |
| 40 | Detection Autopsy | `chapters\part40-detection-autopsy.md` | Capstone dissection: every naive rule seeded earlier (PowerShell execution = malicious, five failed logins = brute force, foreign country = compromise, long DNS label = tunnel, curl in UA = attacker, unsigned process = malware, rare domain = malicious) destroyed and rebuilt, cross-referenced back to its source part. Synthesis, not new material. | Detection Autopsy, What Would Change My Mind |
| 41 | Detection Coverage | `chapters\part41-detection-coverage.md` | ATT&CK coverage model that rejects fake all-green heatmaps: no telemetry → telemetry available → partial detection → detection → multi-source detection → tested → recently validated. Completes Part 1's deferred definition of "coverage." | SOC Management View, What Would Change My Mind |
| 42 | Detection Quality | `chapters\part42-detection-quality.md` | Precision/recall in SOC terms, TP/FP/FN in practice, alert-to-incident ratio, analyst handling time, coverage (Part 41) as a quality input, detection/testing age, suppression tracking, drift, rule-failure monitoring. | SOC Management View, Detection Test |
| 43 | Detection Debt | `chapters\part43-detection-debt.md` | Detection debt, telemetry debt, parser debt, testing debt, documentation debt, tuning debt — an inventory-and-payoff ledger, framed as accumulated Quality/Coverage erosion, not a metaphor. | SOC Management View, Engineering Reality, What Would Change My Mind |

### Section J — Applied Compromise Models

| Part | Title | File Path | Scope | Recurring Features |
|---|---|---|---|---|
| 44 | Adversary Behaviour for Defenders | `chapters\part44-adversary-behaviour-for-defenders.md` | Major ATT&CK stages from a pure detection perspective — behaviour, evidence, detection, hunting angle, visibility gap per stage. No offensive tutorial content. Bridge/synthesis chapter cross-referencing Parts 8–21 rather than reintroducing their detections. | Blind Spot, Hunter's Note, What Would Change My Mind |
| 45 | Ransomware Detection Model | `chapters\part45-ransomware-detection-model.md` | Kill-chain model weighted toward pre-encryption signals (initial access, discovery, credential access, lateral movement, backup/shadow-copy tampering); encryption-stage detection treated as the already-failed, last-resort case. | Detection Autopsy, SOC Management View |
| 46 | Identity Compromise Model | `chapters\part46-identity-compromise-model.md` | Credential → auth → privilege → discovery → lateral movement → data access, synthesizing Parts 12, 13, and 18. | Hunter's Note, Detection Autopsy |
| 47 | Web Compromise Model | `chapters\part47-web-compromise-model.md` | Request → app behaviour → child process → shell → download → network, synthesizing Parts 11 and 16. | Detection Autopsy, Hunter's Note |
| 48 | AI Compromise Model | `chapters\part48-ai-compromise-model.md` | Prompt/file → model → RAG → agent → tool → sensitive system → external destination, with a detection point at every stage, synthesizing Parts 20–21. Deliberately closes the book on the least mature domain. | What Would Change My Mind, Blind Spot |

**Total: 48 parts.**

---

## Appendix Table

*File path pattern:* `C:\Users\User\projects\detection-engineering-handbook\release-v2\appendices\aN-slug.md`

| Appendix | Title | File Path | Contents |
|---|---|---|---|
| A1 | Windows & Endpoint Telemetry Field Reference | `appendices\a1-windows-and-endpoint-telemetry-field-reference.md` | Windows Event ID reference (Security/System/Application), Sysmon event-type reference, Logon Type reference table, PowerShell logging (4103/4104/AMSI field) reference, Linux/auditd/SSH telemetry field reference. Companion field-level reference for Parts 3, 8–11. |
| A2 | Identity & Application Telemetry Field Reference | `appendices\a2-identity-and-application-telemetry-field-reference.md` | Identity/IdP/Kerberos telemetry field reference (Entra sign-in/audit logs, Okta System Log, Kerberos ticket fields, LDAP query fields), network/DNS/proxy/email field references (NetFlow/Zeek fields, DNS record types, SPF/DKIM/DMARC header fields). Companion reference for Parts 3–4, 12–17. |
| A3 | Cloud & AI Telemetry Field Reference | `appendices\a3-cloud-and-ai-telemetry-field-reference.md` | Cloud control-plane log references (CloudTrail, Azure Activity Log, GCP Cloud Audit Logs — event shape and delivery-lag notes), AI systems telemetry reference (prompt/tool-call/retrieval-event schema recommendations from Part 20). Companion reference for Parts 4, 18–20. |
| A4 | MITRE ATT&CK Mapping Quick Reference | `appendices\a4-mitre-attack-mapping-quick-reference.md` | Technique/sub-technique index cross-referenced to every detection ID in the book; the source table `MITRE-COVERAGE.md` is built from. |
| A5 | Query Language Quick Reference | `appendices\a5-query-language-quick-reference.md` | Side-by-side Sigma / KQL / SPL / AQL / YARA-L / Elastic EQL\|KQL\|ES\|QL syntax cheat sheet, anchored to the Part 23 canonical detection and the Rosetta-Stone detection set implemented across Parts 24–29. |
| A6 | Templates: Detection, Hunt, Review, Testing, Tuning & Change Request | `appendices\a6-templates-detection-hunt-review-testing-tuning-change-request.md` | Standard front-matter/body templates for a detection file, a hunt notebook, a peer-review sign-off (enforcing separation of duties), a detection test plan, a tuning/exception request, and a change-request record. |
| A7 | Coverage, Telemetry & QA Matrices and Checklists | `appendices\a7-coverage-telemetry-and-qa-matrices-and-checklists.md` | ATT&CK coverage matrix (six-tier state model from Part 41), telemetry-source matrix (cost/retention/reliability from Parts 3–4), QA/FP/FN review checklists (from Parts 37–39), and the visual-asset render/capture status matrix (tracks every diagram and screenshot against `VISUAL-INVENTORY.md` so none ships unresolved). |

**Total: 7 appendix bundles.**

---

## Key structural decisions and provenance

Each major deviation from V1 (and from the individual architect proposals it was drawn from) is recorded here so future editors know which choice was deliberate and why, rather than re-litigating settled ground.

1. **Ten-section grouping with continuous Part 1–48 numbering** (base structure — Proposal 3). Chosen over Proposal 1's Act-based Roman-numeral scheme and Proposal 2's ungrouped list because labeled sections make dependency order and reviewer/section-owner assignment visible at a glance — a precondition for the separation-of-duties fix, since you cannot assign the right reviewer to unlabeled, unordered content.
2. **Parsers, Normalisation, and Time moved to immediately follow the telemetry survey (Parts 5–7), not left at the end of the book** (Proposal 2 and Proposal 3 converged on this independently — strong signal it's correct). Every later part (Correlation, Testing, False Negative Engineering) references clock skew, schema drift, and parser failure as background knowledge; teaching them right after the telemetry survey removes a genuine forward-reference defect present in both V1 and the sponsor draft TOC.
3. **Telemetry Engineering split into two parts by domain family (Part 3: Host & Identity, Part 4: Network/Application/AI)** (Proposal 2). Twenty heterogeneous telemetry classes scored on eight dimensions in one part is the exact "single breadth-pass, thin depth" trap that produced V1 weakness #4 — splitting gives Linux/auditd/SSH, proxy, firewall, NDR/NetFlow, and database (none of which get a dedicated deep-dive part later) real page weight instead of a table row.
4. **Windows/Sysmon/PowerShell kept as three separate telemetry-layer parts, with Endpoint (Part 11) moved to sit immediately after PowerShell rather than after Identity** (Proposal 2's ordering argument, refining Proposal 1 and Proposal 3's split). Reading telemetry-then-analytics back to back while the material is fresh beats detouring through unrelated AD/Kerberos content first.
5. **Identity split into Access & Authentication (Part 12) vs. Directory, Privilege & Kerberos (Part 13)** (Proposal 3). Different telemetry sources (IdP sign-in logs vs. Windows Security/Kerberos/LDAP), different protocols, and different primary audiences — merging them forces a reader who only needs spray detection to wade through Kerberos ticket-encryption internals, and vice versa.
6. **Network (Part 14) and DNS (Part 15) each exclusively own DNS-tunnelling/domain-rarity logic** (converged across all three proposals) — stated as an explicit scope boundary to prevent the two parts from drifting into contradictory guidance, a defect risk the sponsor TOC invited by listing the same topics under both.
7. **Cloud split into Cloud Identity & SaaS (Part 18) vs. Cloud Infrastructure (Part 19)** (Proposal 1). A single Cloud part covering AWS+Azure+Entra+M365+GCP identity, IAM, logging, storage, network, and exfiltration cannot go deep on any of it without becoming a shallow checklist; the split matches how real teams are staffed (identity/SecOps analysts vs. cloud security engineers).
8. **AI split into Telemetry & Audit-Trail Engineering (Part 20) vs. Detection Engineering (Part 21)** (Proposal 3). Applies the same telemetry-vs-analytic-layer separation the book already uses everywhere else, consistently, to the domain readers understand least — "what should I even log, and what's the privacy exposure" is a distinct, high-stakes question deserving its own space.
9. **Query Language Strategy (Part 23) added as a short bridging part before the six language parts** (Proposal 1), carrying one canonical detection through Parts 23–29 so a reader can compare *semantics* across languages instead of learning six disconnected syntaxes — merged with Proposal 2's "Rosetta Stone" requirement (multiple canonical detections re-implemented file-for-file in every language part) as the mechanism that makes the comparison rigorous rather than anecdotal.
10. **Correlation → Baselining → Threat Intelligence → Risk-Based Detection reordered into an explicit dependency chain (Parts 30–33)** (Proposal 2 and Proposal 3 converged independently). Risk-Based Detection's own scope treats threat intel and rarity as scoring inputs; teaching the input after the technique that consumes it is a forward-reference bug in both V1 and the sponsor draft.
11. **Coverage (Part 41) placed before Quality (Part 42) and Debt (Part 43)** (Proposal 3, adopted by this synthesis). Quality's own metric set treats coverage as a measured input, and Debt is most coherently framed as accumulated Quality/Coverage erosion — so Debt comes last among the three, not second.
12. **Detection Autopsy (Part 40) is a capstone synthesis of teaser rules seeded in their natural source parts, not a from-scratch treatment** (converged across all three proposals). This gives the recurring feature narrative continuity a reader can track across the book, instead of one isolated takedown chapter that reads as invented-for-the-part.
13. **Mandatory per-file production front matter (`author`/`reviewer`/`status`/`depends_on`/`last_validated`) and permanent, position-independent global IDs for detections/hunts/figures** (Proposal 2). This is the single highest-leverage carryover: it converts "separation of duties" and "no diagram ever rendered" from aspirational V1 policy into a field a build script can check, and it means the next inevitable reorganization — like this one — never breaks a cross-reference the way position-scoped IDs would.
14. **48 total parts** — 3 more than Proposal 3's 45, from adding the Telemetry split (+1, decision 3), the Cloud split (+1, decision 7), and the Query Language Strategy bridge (+1, decision 9), all layered onto Proposal 3's own +2 over the sponsor draft (Identity split, AI split). Every addition is a named depth or continuity fix, not a rebalancing for its own sake.
