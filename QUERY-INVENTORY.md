# Query Inventory — Canonical Detection Across Query Languages

DET-23-01 ("Suspicious process access to lsass.exe," T1003.001) is the book's one canonical, cross-language detection. It is defined once in Part 23 (Query Language Strategy) and then re-implemented as a native artifact, in the same intent, across the six query-language parts (Parts 24–29). One row per implementation below.

**Total: 9 native implementations across 6 languages/backends (Parts 24–29), plus a consolidated restatement of 8 of them in Appendix A5.**

| Language / Backend | Part | Detection ID Used | File | Implementation Notes |
|---|---|---|---|---|
| Sigma | Part 24 | DET-23-01 | release-v2/chapters/part24-sigma.md | Filename-suffix `filter_known_tools` allowlist; Blind Spot added — a renamed credential-dumping tool (e.g., `svchost.exe`) bypasses the exclusion filter before `condition` ever evaluates. |
| KQL (Microsoft Sentinel/Defender) | Part 25 | DET-25-01 | release-v2/chapters/part25-kql-sentinel-defender.md | Queries `DeviceEvents`/`OpenProcessApiCall`; Engineering Reality box flags that `GrantedAccess` value *format* (hex vs. decimal) must be verified per DSM/connector, not just field presence. |
| Splunk SPL | Part 26 | DET-26-01 | release-v2/chapters/part26-splunk-spl.md | Lookup-table-based allowlist (`lsass_access_allowlist.csv`) rather than a hardcoded exclusion list; Blind Spot for process injection into an already-allowlisted binary. |
| QRadar AQL | Part 27 | DET-27-01 | release-v2/chapters/part27-qradar-aql.md | Implemented as three separately versioned QRadar objects (Building Block + Reference Set + Rule) rather than one deployed artifact — the one backend in the set that doesn't map 1:1 to a single file/rule. |
| YARA-L / UDM (Google SecOps) | Part 28 | DET-23-01 (ID reused, not renumbered) | release-v2/chapters/part28-yara-l-google-secops.md | Matches UDM `PROCESS_OPEN` events; broader default scope than the other backends since UDM has no confirmed `GrantedAccess`-equivalent field to filter on. |
| Elastic KQL | Part 29 | DET-29-01 | release-v2/chapters/part29-elastic-eql-kql-esql.md | Single-event filter form against an ECS-normalized index. |
| Elastic EQL (single-event) | Part 29 | DET-29-01 | release-v2/chapters/part29-elastic-eql-kql-esql.md | Single-event EQL query, equivalent in scope to the KQL filter form. |
| Elastic EQL (sequence extension) | Part 29 | DET-29-01 | release-v2/chapters/part29-elastic-eql-kql-esql.md | Extended beyond the canonical single-event form: LSASS access + an outbound network connection within 5 minutes, joined on `process.entity_id` — the one backend that also demonstrates a genuine correlation upgrade, not just a syntax port. |
| Elastic ES\|QL | Part 29 | DET-29-01 | release-v2/chapters/part29-elastic-eql-kql-esql.md | Single-event filter form using the newer ES\|QL pipe syntax. |

## Consolidated restatement — Appendix A5

Appendix A5 (Query Language Quick Reference) restates 8 of the 9 implementations above side by side in one file for at-a-glance comparison (it omits the Part 29 EQL sequence-extension variant, keeping only the single-event forms):

| Appendix A5 Section | Language | Detection ID | File |
|---|---|---|---|
| §7.1 | Sigma | DET-23-01 | release-v2/appendices/a5-query-language-quick-reference.md |
| §7.2 | Sentinel/Defender KQL | DET-25-01 | release-v2/appendices/a5-query-language-quick-reference.md |
| §7.3 | Splunk SPL | DET-26-01 | release-v2/appendices/a5-query-language-quick-reference.md |
| §7.4 | QRadar AQL/CRE | DET-27-01 | release-v2/appendices/a5-query-language-quick-reference.md |
| §7.5 | YARA-L/UDM | DET-23-01 | release-v2/appendices/a5-query-language-quick-reference.md |
| §7.6 | Elastic KQL | DET-29-01 | release-v2/appendices/a5-query-language-quick-reference.md |
| §7.7 | Elastic EQL | DET-29-01 | release-v2/appendices/a5-query-language-quick-reference.md |
| §7.8 | Elastic ES\|QL | DET-29-01 | release-v2/appendices/a5-query-language-quick-reference.md |

## Cross-book significance

Appendix A5's own review notes make the point of this exercise explicit: on 5 of 6 backends the canonical analytic deploys as a single artifact, but on QRadar it deploys as three separately versioned objects rolling up to one line of Detection Coverage — a translation-fidelity difference a reader migrating platforms would otherwise have no way to discover. A second, independently found translation gap: every implementation's exclusion/allowlist filters on the bare process-image name with no path or signing check (T1036.005 masquerading bypass), which the adversarial review flagged identically in Parts 24, 25/26 (via Part 23's own Blind Spot), 28, and Appendix A5 — the same real weakness surfaced independently in nearly every language port, which is exactly the translation-loss problem Part 23 was designed to make checkable.
