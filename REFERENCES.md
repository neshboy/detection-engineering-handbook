# References

Deduplicated references cited across the 55 completed units, grouped by publisher/source. Most units cite no external references at all (their `references` field is empty); citations that exist are either genuine third-party sources, this project's own governing documents (TERMINOLOGY.md / STYLE-GUIDE.md / BOOK-INDEX.md), this project's own captured lab evidence files, or cross-references to sibling parts.

## External / Third-Party Sources

### MITRE

- **CVE-2018-10561 / CVE-2018-10562** — GPON router authentication-bypass RCE (the real exploit path behind the honeynet's `/GponForm/diag_Form` evidence). Cited in: Part 4, Part 16 (implied via same CVE discussion), Part 26, Part 36, Part 40; Appendix A4.
- **MITRE ATLAS** (Adversarial Threat Landscape for Artificial-Intelligence Systems) — https://atlas.mitre.org. Cited in: Part 48.

### GTFOBins Project

- **GTFOBins** (Linux/Unix living-off-the-land binary abuse catalogue). Cited in: Part 11.

### LOLBAS Project

- **LOLBAS** (Living Off The Land Binaries, Scripts and Libraries — Windows equivalent of GTFOBins). Cited in: Part 11.

### OASIS

- **STIX 2.1** confidence field convention. Cited in: Part 32.

### NATO

- **Admiralty/NATO source-reliability and information-credibility system**. Cited in: Part 32.

### Microsoft

- Microsoft hybrid-identity documentation on the password-hash-synchronization expedited sync cycle. Cited in: Part 46.

### Independent Security Research

- Independent security research on the Entra ID password-hash-sync algorithm (deterministic function of on-prem NTLM hash + SID). Cited in: Part 46.

## Internal — Project Governing Documents

### TERMINOLOGY.md

Cited (by section or in whole) in: Part 2, Part 5, Part 15, Part 20, Part 25, Part 30, Part 31, Part 32, Part 34, Part 36, Part 37, Part 40, Part 42; Appendix A1, A2, A5, A6, A7.

### STYLE-GUIDE.md

Cited (by section or in whole) in: Part 15, Part 25, Part 30, Part 40, Part 42; Appendix A1, A5, A6, A7.

### BOOK-INDEX.md

Cited in: Part 15, Part 30; Appendix A6.

## Internal — Lab Evidence Files (`release-v2/lab/evidence/`)

- **ct100-pihole-sudo-invocations.txt** — cited in: Part 5, Part 22, Part 34, Part 38; Appendix A1.
- **ct100-pihole-dns-query-log.txt** — cited in: Part 38.
- **ct103-honeynet-correlated-attack-sessions.txt** — cited in: Part 30, Part 36, Part 47; Appendix A4, A6.
- **ct103-honeynet-http-events-exploit-probes.txt** — cited in: Part 36; Appendix A4.
- **ct103-honeynet-ssh-honeypot-credentials.txt** — cited in: Part 30, Part 36.
- **ct104-vulnscan-sudo-invocations.txt** — cited in: Part 22, Part 30, Part 34, Part 38; Appendix A1.
- **ct104-vulnscan-ssh-failed-logins-btmp.txt** — cited in: Part 24, Part 30, Part 34, Part 37, Part 38; Appendix A1.
- **ct104-vulnscan-web-systemd-state-changes.txt** — cited in: Part 34; Appendix A1.
- **ct108-honeynet-edge-ssh-protocol-scan.txt** — cited in: Part 36; Appendix A1.

(See LAB-EVIDENCE-MANIFEST.md for the full 11-file evidence set, including two files — `ct104-vulnscan-scan-findings-sample.txt` and one duplicate-purpose capture — that are used as source telemetry within chapters but not separately listed in any unit's formal `references` array.)

## Internal — Cross-References to Other Parts/Appendices

The following units carry explicit "see also" style references (beyond the standard `depends_on` front matter) pointing readers to sibling parts for deeper treatment of a concept this unit only touches on:

- **Part 2** → Part 1 (vocabulary), Parts 3–4 (telemetry sources), Part 5 (parsing), Part 6 (normalisation/schema), Part 7 (time), Part 10 (PowerShell depth), Part 11 (OS/API-call substitution), Parts 30/38/39 (analytic tuning, false-negative engineering), Part 35 (gap-driven hunting), Part 41 (coverage matrix).
- **Part 8** → Part 9 (Sysmon), Part 10 (PowerShell), Part 13 (Kerberos/Directory), Part 7 (Time), Part 31 (baseline methodology), Part 5 (Parsers), Appendix A1 (field reference).
- **Part 15** → Part 4 (DNS telemetry survey), Parts 5/6 (parser/normalisation), Part 33 (Risk-Based Alerting), Part 40 (naive-rule teardown).
- **Part 20** → Part 1 (Data Feasibility), Part 4 §8/§10 (MCP honeynet evidence), Part 8 (Logon ID pivot analogy), Parts 3/11 (file-hash triad precedent), Parts 12/13 (Entity Key join-path precedent), Part 14 (allowlist-enrichment FP pattern), Part 21 (analytic layer built on this schema), Part 31 (token-count baseline reference), Appendix A3 (full field schema).
- **Part 24** → Part 1 (Figure 1.3 real evidence reuse), Part 3 §7.4, Part 6, Part 9 §3.6, Part 22, Part 23, Part 30, Part 33, Part 37, Part 41/43.
- **Part 25** → Part 9 §3.6, Part 23 §1/§4, Part 24 §3/§4.1.
- **Part 26** → Part 1, Part 3 (DET-03-01), Part 5 §7, Part 9 §2/§3.6, Part 22, Part 23, Part 24, Part 25, Part 27.
- **Part 28** → Part 1, Part 3, Part 6, Part 9, Part 23.
- **Part 29** → Part 9, Part 12 (Figure 12.2 reuse), Part 22, Part 23; Appendix A5.
- **Part 30** → Part 7, Part 31, Part 33, Part 42.
- **Part 31** → Part 1, Part 3, Part 5, Part 7, Part 11, Part 12, Part 14, Part 24 (FIG-24-02), Part 30, Part 33, Part 40.
- **Part 32** → Part 15, Part 31, Part 33, Part 40, Part 41.
- **Part 36** → Part 12 §2 (DET-12-02), Part 22, Part 30, Parts 34–35, Part 37, Part 41, Part 43.
- **Part 37** → Part 5, Part 6, Part 7, Part 22.
- **Part 40** → cites DET-10-02 (Part 10), DET-11-01/02 (Part 11), DET-12-02/03/04 (Part 12), DET-15-05 (Part 15), DET-16-04 (Part 16) directly as revised worked examples.
- **Part 48** → Part 20, Part 21, Part 41.
- **Appendix A1** → Part 3, Part 8, Part 9, Part 10, Part 11, Part 13, Part 23.
- **Appendix A2** → Appendix A1, Part 12 (FIG-12-04 pending-figure cross-reference rather than duplication).
- **Appendix A4** → (evidence-only cross-references; see Lab Evidence Files above).
- **Appendix A5** → Part 22, Part 23, Part 24, Part 25, Part 26, Part 27, Part 28, Part 29; Appendix A4.
- **Appendix A6** → Part 1, Part 22, Part 32, Part 34, Part 36, Part 37, Part 38, Part 41, Part 43; Appendix A4, A7.
- **Appendix A7** → Part 3, Part 4, Part 37, Part 38, Part 39, Part 41, Part 42, Part 43; Appendix A1, A4, A6.
