# Hunt Inventory

One row per hunt defined across the 55 completed units of The Detection Engineering Handbook V2.

**Total: 68 hunts.**

| ID | Name | Part | File |
|---|---|---|---|
| HUNT-01-01 | Would a legacy-SSH-algorithm probe ever reach the failed-auth rule? (confirmed negative finding: preauth-rejected negotiation attempts never produce a Failed password event) | Part 1 | release-v2/chapters/part01-detection-engineering-foundations.md |
| HUNT-02-01 | Pipeline volume-consistency hunt — comparing EDR vs. Sysmon process-creation counts on the same host population to surface collector/parser gaps | Part 2 | release-v2/chapters/part02-from-attack-to-telemetry.md |
| HUNT-03-01 | Hunting legacy SSH protocol and algorithm negotiation attempts | Part 3 | release-v2/chapters/part03-telemetry-engineering-i-host-and-identity-sources.md |
| HUNT-04-01 | Hunting for agentic/MCP endpoint scanning (UA + source-ASN clustering pivot) | Part 4 | release-v2/chapters/part04-telemetry-engineering-ii-network-application-and-ai-sources.md |
| HUNT-04-02 | Pivoting across honeynet decoys for shared attacker infrastructure (cross-target source-IP recurrence) | Part 4 | release-v2/chapters/part04-telemetry-engineering-ii-network-application-and-ai-sources.md |
| HUNT-05-01 | Rules with anomalous zero-alert streaks | Part 5 | release-v2/chapters/part05-parsers.md |
| HUNT-06-01 | Fields that should be populated after a normalisation migration but aren't (100%-null field mapping gap) | Part 6 | release-v2/chapters/part06-normalisation.md |
| HUNT-07-01 | Event-time / ingestion-time skew as a tamper or infrastructure-failure signal | Part 7 | release-v2/chapters/part07-time.md |
| HUNT-08-01 | Novel explicit-credential pairings (Event ID 4648 SubjectUserName/TargetUserName/TargetServerName baseline hunt); cross-referenced (not redefined) in Appendix A1 | Part 8 | release-v2/chapters/part08-windows-detection-engineering.md |
| HUNT-09-01 | Sysmon coverage gaps as a tamper signal (Event ID 1 volume discontinuity vs. cross-channel SCM 7036/7040 corroboration) | Part 9 | release-v2/chapters/part09-sysmon-detection-engineering.md |
| HUNT-10-01 | Warning-level 4104 events not matched by existing keyword rules (nested/structural obfuscation hunt) | Part 10 | release-v2/chapters/part10-powershell-detection-engineering.md |
| HUNT-11-01 | Shell-process-parent sweep for undocumented GTFOBins abuse across the Linux fleet | Part 11 | release-v2/chapters/part11-endpoint-detection-engineering.md |
| HUNT-11-02 | Outbound requests to 169.254.169.254 (IMDS) from application processes with no documented metadata-service dependency | Part 11 | release-v2/chapters/part11-endpoint-detection-engineering.md |
| HUNT-12-01 | Low-and-slow credential reuse that never crosses a count threshold | Part 12 | release-v2/chapters/part12-identity-access-and-authentication-detection.md |
| HUNT-12-02 | Interactive sign-ins on accounts flagged non-interactive | Part 12 | release-v2/chapters/part12-identity-access-and-authentication-detection.md |
| HUNT-13-01 | SPN exposure and crackability audit | Part 13 | release-v2/chapters/part13-identity-directory-privilege-and-kerberos-detection.md |
| HUNT-13-02 | Over-permissioned replication rights audit | Part 13 | release-v2/chapters/part13-identity-directory-privilege-and-kerberos-detection.md |
| HUNT-14-01 | Low-and-slow beaconing under the standing threshold (24-hour sub-window review band) | Part 14 | release-v2/chapters/part14-network-detection-engineering.md |
| HUNT-14-02 | Residential-proxy abuse with no matching reputation-list hit | Part 14 | release-v2/chapters/part14-network-detection-engineering.md |
| HUNT-15-01 | Low-and-slow subdomain fan-out below the standing alert threshold | Part 15 | release-v2/chapters/part15-dns-detection-engineering.md |
| HUNT-15-02 | Resolver-bypass discovery: who isn't using the monitored resolver | Part 15 | release-v2/chapters/part15-dns-detection-engineering.md |
| HUNT-16-01 | Would DET-16-01's exploit-path rule alone have distinguished a probe from a possible compromise? (session-correlation candidate built on real attack_sessions data) | Part 16 | release-v2/chapters/part16-web-detection-engineering.md |
| HUNT-17-01 | Mid-thread payment-detail change audit | Part 17 | release-v2/chapters/part17-email-detection-engineering.md |
| HUNT-17-02 | API-created inbox rules with no prior sign-in history | Part 17 | release-v2/chapters/part17-email-detection-engineering.md |
| HUNT-18-01 | Dormant high-privilege OAuth apps (consented scope with no post-consent API usage after 30 days) | Part 18 | release-v2/chapters/part18-cloud-identity-and-saas-detection-engineering.md |
| HUNT-18-02 | Guest access reached through nested group membership rather than direct role assignment | Part 18 | release-v2/chapters/part18-cloud-identity-and-saas-detection-engineering.md |
| HUNT-19-01 | Anomalous AssumeRole source population (role ARN x source ASN x calling principal, 30-day never-seen-before) | Part 19 | release-v2/chapters/part19-cloud-infrastructure-detection-engineering.md |
| HUNT-19-02 | Dormant long-lived credential reactivation (90+ day unused IAM/service-account keys that suddenly get used) | Part 19 | release-v2/chapters/part19-cloud-infrastructure-detection-engineering.md |
| HUNT-20-01 | Does the audit pipeline actually log every connector type currently enabled, or only the ones present when it was built? | Part 20 | release-v2/chapters/part20-ai-systems-telemetry-and-audit-trail-engineering.md |
| HUNT-21-01 | Hunting for latent poisoned documents already in the RAG/KB corpus | Part 21 | release-v2/chapters/part21-ai-security-detection-engineering.md |
| HUNT-21-02 | Browser-agent sessions visiting never-before-seen external domains | Part 21 | release-v2/chapters/part21-ai-security-detection-engineering.md |
| HUNT-25-01 | LSASS OpenProcessApiCall access from non-allowlisted callers with no corroborating file/network event (fileless credential-theft gap) | Part 25 | release-v2/chapters/part25-kql-sentinel-defender.md |
| HUNT-26-01 | Recon sessions with unusually broad path diversity but no exploit-signature match (CT103 attack_sessions pipeline blind spot) | Part 26 | release-v2/chapters/part26-splunk-spl.md |
| HUNT-27-01 | Would DET-27-01's GrantedAccess value list miss a real access-rights variant? | Part 27 | release-v2/chapters/part27-qradar-aql.md |
| HUNT-28-01 | Field-population gaps behind a standing UDM rule (PROCESS_OPEN / target.process.file.full_path null-rate by ingestion label, filed as Visibility Debt) | Part 28 | release-v2/chapters/part28-yara-l-google-secops.md |
| HUNT-29-01 | Low-and-slow credential-stuffing pivot via ES\|QL wide-lookback STATS...BY aggregation | Part 29 | release-v2/chapters/part29-elastic-eql-kql-esql.md |
| HUNT-30-01 | Successful privileged logons with no antecedent failed-logon burst (catches stolen-credential/Pass-the-Hash logins) | Part 30 | release-v2/chapters/part30-correlation-engineering.md |
| HUNT-30-02 | Sessions where source_ip-based entity resolution over-merges (NAT/shared hosting) or under-merges (IP-rotating actor) | Part 30 | release-v2/chapters/part30-correlation-engineering.md |
| HUNT-31-01 | Peer-group divergence for accounts that pass their own self-baseline | Part 31 | release-v2/chapters/part31-baselining.md |
| HUNT-32-01 | TI-vintage mismatch as a dwell-time discovery hunt | Part 32 | release-v2/chapters/part32-threat-intelligence-in-detection.md |
| HUNT-33-01 | Entities with sustained near-threshold risk scores | Part 33 | release-v2/chapters/part33-risk-based-detection.md |
| HUNT-34-01 | Valid credentials, unusual remote administration — baseline-deviating interactive sudo session following clean SSH auth | Part 34 | release-v2/chapters/part34-threat-hunting-fundamentals.md |
| HUNT-35-01 | IOC-based hunt — reused default-credential string (support/support) across the honeynet's SSH decoy, rotating across a /24 | Part 35 | release-v2/chapters/part35-hunt-types.md |
| HUNT-35-02 | TTP-based hunt — protocol-confusion (TLS-on-plain-HTTP) probing against the decoy fleet | Part 35 | release-v2/chapters/part35-hunt-types.md |
| HUNT-35-03 | Anomaly-based hunt — internal device issuing repeated NXDOMAIN queries for an unrelated enterprise domain | Part 35 | release-v2/chapters/part35-hunt-types.md |
| HUNT-35-04 | Intel-led hunt — sweeping honeynet HTTP traffic for the disclosed GPON router RCE path (CVE-2018-10561/10562) | Part 35 | release-v2/chapters/part35-hunt-types.md |
| HUNT-35-05 | Incident-led hunt — scoping a honeynet-flagged possible_success session across recurrence | Part 35 | release-v2/chapters/part35-hunt-types.md |
| HUNT-35-06 | Gap-driven hunt — the failed-login rule that never sees a pre-auth protocol-negotiation reject (produced DET-35-01) | Part 35 | release-v2/chapters/part35-hunt-types.md |
| HUNT-35-07 | Retrospective hunt — dwell time against a gateway router with no retained telemetry to answer the question | Part 35 | release-v2/chapters/part35-hunt-types.md |
| HUNT-36-01 | Honeynet exploit-shaped-request-plus-follow-up pattern discovery (the worked hunt that generalizes into DET-36-01) | Part 36 | release-v2/chapters/part36-hunt-to-detection.md |
| HUNT-36-02 | SSH low-and-slow single-account/password credential-guessing campaign (documented negative finding, no new rule filed) | Part 36 | release-v2/chapters/part36-hunt-to-detection.md |
| HUNT-37-01 | Detections with no recorded test evidence (inventory-based hunt for untested/never-validated rules) | Part 37 | release-v2/chapters/part37-detection-testing.md |
| HUNT-38-01 | Stale exception audit | Part 38 | release-v2/chapters/part38-false-positive-engineering.md |
| HUNT-39-01 | Retroactive replay against newly disclosed indicators or techniques | Part 39 | release-v2/chapters/part39-false-negative-engineering.md |
| HUNT-39-02 | Distributed credential-stuffing campaigns that stay under every per-entity threshold | Part 39 | release-v2/chapters/part39-false-negative-engineering.md |
| HUNT-41-01 | Would the RC4-only Kerberoasting rule actually miss AES ticket requests? (confirmed finding; rewritten detection candidate requires a volume/rate discriminator) | Part 41 | release-v2/chapters/part41-detection-coverage.md |
| HUNT-42-01 | Detection-drift hunt — analytics whose alert volume dropped well below their trailing baseline with no matching change-log entry | Part 42 | release-v2/chapters/part42-detection-quality.md |
| HUNT-43-01 | Rules with anomalously low or zero alert volume and no negative-finding record | Part 43 | release-v2/chapters/part43-detection-debt.md |
| HUNT-44-01 | Backward pivot from a confirmed late-stage (Discovery/Lateral Movement) finding to check for a missing earlier-stage (Credential Access/Initial Access) detection | Part 44 | release-v2/chapters/part44-adversary-behaviour-for-defenders.md |
| HUNT-45-01 | Shadow-copy and snapshot enumeration without deletion | Part 45 | release-v2/chapters/part45-ransomware-detection-model.md |
| HUNT-45-02 | Fleet-wide backup-agent stop clustering | Part 45 | release-v2/chapters/part45-ransomware-detection-model.md |
| HUNT-46-01 | Full-chain dwell-time reconstruction from a single confirmed indicator | Part 46 | release-v2/chapters/part46-identity-compromise-model.md |
| HUNT-46-02 | Hybrid-seam coverage audit (asymmetric detection posture across on-prem/cloud planes) | Part 46 | release-v2/chapters/part46-identity-compromise-model.md |
| HUNT-46-03 | Sudoers exposure audit, the Linux analog to HUNT-13-01 | Part 46 | release-v2/chapters/part46-identity-compromise-model.md |
| HUNT-47-01 | Would this lab's honeynet decoys, if instrumented with real host and network telemetry, actually produce the confirmed_postexploit corroboration Part 16's state machine names? (negative finding on current CT103 build) | Part 47 | release-v2/chapters/part47-web-compromise-model.md |
| HUNT-48-01 | Sessions that complete the ordered compromise chain while staying under every individual stage's production alerting threshold | Part 48 | release-v2/chapters/part48-ai-compromise-model.md |
| A4-worked-case-study | Tagging a real honeynet session against ATT&CK using CT103's attack_sessions correlation output | Appendix A4 | release-v2/appendices/a4-mitre-attack-mapping-quick-reference.md |
| HUNT-A6-01 | Cross-target /24 scanning pattern in CT103 honeynet attack_sessions (feeds DET-A6-01) | Appendix A6 | release-v2/appendices/a6-templates-detection-hunt-review-testing-tuning-change-request.md |
