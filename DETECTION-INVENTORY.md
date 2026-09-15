# Detection Inventory

One row per detection defined across the 55 completed units of The Detection Engineering Handbook V2. IDs that recur across multiple parts (DET-23-01, and the Part 40 / Appendix A1 citations of detections owned by earlier parts) are listed once, under their originating/canonical part, with a note pointing to the part(s) that reimplement or cite them. Detections with no permanent ID in the source material (illustrative/unformalized examples) are listed with the placeholder label used by their unit.

**Total: 131 detections** (125 with permanent `DET-##-##` IDs, 6 illustrative/unformalized examples with no permanent ID assigned).

| ID | Name | Part | File | MITRE Techniques |
|---|---|---|---|---|
| DET-01-01 | Repeated failed SSH password authentication from one source (3+ failures, same account, same source, 5-minute window) | Part 1 | release-v2/chapters/part01-detection-engineering-foundations.md | T1110; T1110.001 |
| DET-02-01 | Sentinel KQL — encoded PowerShell launch via DeviceProcessEvents (`-enc`/`-EncodedCommand` substring + command-line length threshold) | Part 2 | release-v2/chapters/part02-from-attack-to-telemetry.md | T1059.001; T1059; T1027 |
| DET-03-01 | SSH failed-authentication burst detection, corrected for connection-count inflation (Splunk SPL) | Part 3 | release-v2/chapters/part03-telemetry-engineering-i-host-and-identity-sources.md | T1110; T1110.001 |
| DET-03-naive (unnumbered) | Naive failed-login-count rule: alert on N failed SSH logins from one source in an hour — Detection Autopsy "before" example, shown broken, superseded by DET-03-01 | Part 3 | release-v2/chapters/part03-telemetry-engineering-i-host-and-identity-sources.md | — |
| DET-04-01 | TLS-bypass exfiltration via proxy category allowlist (SPL) | Part 4 | release-v2/chapters/part04-telemetry-engineering-ii-network-application-and-ai-sources.md | T1567.002 |
| DET-04-02 | App-ID/port mismatch as a policy-evasion signal (KQL) | Part 4 | release-v2/chapters/part04-telemetry-engineering-ii-network-application-and-ai-sources.md | T1571 |
| DET-04-03 | Beaconing via connection periodicity (SPL, Zeek conn.log) | Part 4 | release-v2/chapters/part04-telemetry-engineering-ii-network-application-and-ai-sources.md | T1071.001 |
| DET-04-04 | Exploit-path POST against a known vulnerable endpoint (KQL) | Part 4 | release-v2/chapters/part04-telemetry-engineering-ii-network-application-and-ai-sources.md | T1190 |
| DET-04-05 | Bulk export via anomalous row-count SELECT (SPL, database audit log) | Part 4 | release-v2/chapters/part04-telemetry-engineering-ii-network-application-and-ai-sources.md | T1213 (directional mapping, explicitly flagged inexact) |
| DET-04-06 | Escalating exploit_attempt to possible_success (honeynet correlation rule) | Part 4 | release-v2/chapters/part04-telemetry-engineering-ii-network-application-and-ai-sources.md | T1595; T1046; T1083; T1190 |
| DET-05-01 | Sudo Escalation to Root Outside Approved Admin List (naive version, superseded by DET-05-02) | Part 5 | release-v2/chapters/part05-parsers.md | T1548.003 |
| DET-05-02 | Sudo Escalation to Root Outside Approved Admin List, Field-Resilient | Part 5 | release-v2/chapters/part05-parsers.md | T1548.003 |
| DET-05-03 | Per-field null-rate parser-health monitor for TargetUserName (Sentinel KQL scheduled query) | Part 5 | release-v2/chapters/part05-parsers.md | — |
| DET-06-01 | Web-recon / known-webshell-path probe from a source IP outside internal ranges (ECS/ASIM) | Part 6 | release-v2/chapters/part06-normalisation.md | T1190 |
| DET-07-01 | Host clock drift exceeding a 5-minute threshold | Part 7 | release-v2/chapters/part07-time.md | — |
| DET-07-02 | DST-safe failed-then-successful authentication correlation | Part 7 | release-v2/chapters/part07-time.md | — |
| DET-08-01 | Privileged RDP (Logon Type 10) from a new source correlated with 4672 SeDebugPrivilege and a suspicious 4688 PowerShell child process | Part 8 | release-v2/chapters/part08-windows-detection-engineering.md | T1021.001; T1078 |
| DET-08-02 | Privileged logon (4672) without a matching account/host baseline entry (also cross-referenced in Appendix A1) | Part 8 | release-v2/chapters/part08-windows-detection-engineering.md | T1078 |
| DET-08-03 | Any occurrence of Event ID 1102 (audit log cleared) on any host | Part 8 | release-v2/chapters/part08-windows-detection-engineering.md | T1070.001 |
| DET-09-01 | Suspicious process access to LSASS memory (Sysmon Event ID 10 / ProcessAccess) | Part 9 | release-v2/chapters/part09-sysmon-detection-engineering.md | T1003.001 |
| DET-09-02 | Unsigned or newly-observed kernel driver load (Sysmon Event ID 6 / Driver Loaded) | Part 9 | release-v2/chapters/part09-sysmon-detection-engineering.md | T1562.001 |
| DET-10-01 | PowerShell Download Cradle — Fetch Combined with Inline Execution (Sigma, Event ID 4104) | Part 10 | release-v2/chapters/part10-powershell-detection-engineering.md | T1105; T1027; T1027.010 |
| DET-10-02 | PowerShell Download Cradle Confirmed by Network Correlation (also cited/revised in Part 40) | Part 10 | release-v2/chapters/part10-powershell-detection-engineering.md | T1105; T1071.004 |
| DET-11-01 | WINWORD-to-PowerShell lineage (phishing macro handoff) (also cited in Part 40) | Part 11 | release-v2/chapters/part11-endpoint-detection-engineering.md | T1204.002; T1566.001; T1059.001 |
| DET-11-02 | LOLBin-to-shell lineage (GTFOBins shell-parent shape) (also cited in Part 40) | Part 11 | release-v2/chapters/part11-endpoint-detection-engineering.md | T1059.004; T1548.001 |
| DET-11-03 | Unexpected new systemd unit gated on ExecStart target | Part 11 | release-v2/chapters/part11-endpoint-detection-engineering.md | T1543.002 |
| DET-11-04 | LSASS Process Access with memory-read GrantedAccess mask | Part 11 | release-v2/chapters/part11-endpoint-detection-engineering.md | T1003.001 |
| DET-11-05 | Shadow-copy / backup deletion (vssadmin and equivalents) | Part 11 | release-v2/chapters/part11-endpoint-detection-engineering.md | T1490 |
| DET-11-06 | Security-tool service stop / auditd rule flush | Part 11 | release-v2/chapters/part11-endpoint-detection-engineering.md | T1562.001; T1562.006; T1070.001; T1070.002 |
| DET-12-01 | Password spray across the tenant | Part 12 | release-v2/chapters/part12-identity-access-and-authentication-detection.md | T1110.003; T1110.004 |
| DET-12-02 | Repeated-credential brute force against a single account (also cited in Part 40) | Part 12 | release-v2/chapters/part12-identity-access-and-authentication-detection.md | T1110; T1110.001 |
| DET-12-03 | Successful sign-in following a failure burst (also cited in Part 40) | Part 12 | release-v2/chapters/part12-identity-access-and-authentication-detection.md | T1110; T1078 |
| DET-12-04 | Geovelocity-based impossible travel (also cited in Part 40) | Part 12 | release-v2/chapters/part12-identity-access-and-authentication-detection.md | T1078; T1078.004 |
| DET-12-05 | Repeated MFA prompts in a short window (MFA fatigue / push bombing) | Part 12 | release-v2/chapters/part12-identity-access-and-authentication-detection.md | T1621; T1078 |
| DET-13-01 | Kerberoasting via requester fan-out, not ticket-encryption type | Part 13 | release-v2/chapters/part13-identity-directory-privilege-and-kerberos-detection.md | T1558.003 |
| DET-13-02 | AS-REP Roasting: TGT requests with no pre-authentication | Part 13 | release-v2/chapters/part13-identity-directory-privilege-and-kerberos-detection.md | T1558.004 |
| DET-13-03 | NTLM fallback from an AES-Kerberos-only account | Part 13 | release-v2/chapters/part13-identity-directory-privilege-and-kerberos-detection.md | T1550.002; T1550.003; T1558.001; T1558.002 |
| DET-13-04 | DCSync by a non-inventoried principal | Part 13 | release-v2/chapters/part13-identity-directory-privilege-and-kerberos-detection.md | T1003.006 |
| DET-13-05 | Unscheduled privileged-group membership change | Part 13 | release-v2/chapters/part13-identity-directory-privilege-and-kerberos-detection.md | T1098 |
| DET-14-01 | Vertical port scan — distinct destination ports per (source, destination) pair | Part 14 | release-v2/chapters/part14-network-detection-engineering.md | T1595.002; T1046 |
| DET-14-02 | Horizontal port scan — distinct destination hosts per (source, port) pair | Part 14 | release-v2/chapters/part14-network-detection-engineering.md | T1595.001; T1046 |
| DET-14-03 | Beaconing via connection-interval coefficient-of-variation scoring | Part 14 | release-v2/chapters/part14-network-detection-engineering.md | T1071.001; T1573; T1008 |
| DET-14-04 | SSH legacy protocol/algorithm negotiation-failure sweep detection | Part 14 | release-v2/chapters/part14-network-detection-engineering.md | T1595.002; T1046 |
| DET-14-05 | TLS ClientHello sent to a non-TLS port (protocol confusion) | Part 14 | release-v2/chapters/part14-network-detection-engineering.md | T1595.002; T1046 |
| DET-14-06 | Exfiltration via asymmetric byte ratio to a rare destination | Part 14 | release-v2/chapters/part14-network-detection-engineering.md | T1041; T1048.003 |
| DET-15-01 | First-seen apex domain outside the maintained baseline, joined to process context | Part 15 | release-v2/chapters/part15-dns-detection-engineering.md | T1071.004 |
| DET-15-02 | High-cardinality NXDOMAIN churn from a single source | Part 15 | release-v2/chapters/part15-dns-detection-engineering.md | T1568.002; T1071.004 |
| DET-15-03 | High-entropy apex-domain diversity per source | Part 15 | release-v2/chapters/part15-dns-detection-engineering.md | T1568.002 |
| DET-15-04 | Repeated TXT queries from a non-mail host against a single apex | Part 15 | release-v2/chapters/part15-dns-detection-engineering.md | T1071.004 |
| DET-15-05 | Composite DNS-tunnelling score: label shape, fan-out, and query-type skew (also cited in Part 40) | Part 15 | release-v2/chapters/part15-dns-detection-engineering.md | T1071.004; T1048.003 |
| DET-16-01 | Known-CVE exploit-path request against a web application or device endpoint (GPON router auth-bypass RCE worked example) | Part 16 | release-v2/chapters/part16-web-detection-engineering.md | T1190 |
| DET-16-04 | Web-server process spawning a shell or script interpreter (also cited/hardened in Part 40) | Part 16 | release-v2/chapters/part16-web-detection-engineering.md | T1505.003 |
| DET-16-08 | Sequential object-ID enumeration against a per-object API endpoint | Part 16 | release-v2/chapters/part16-web-detection-engineering.md | T1190 |
| unformalized-2.1 | SQLi request-log pattern match — illustrative Splunk SPL, no permanent DET-ID assigned | Part 16 | release-v2/chapters/part16-web-detection-engineering.md | T1190 |
| unformalized-2.2 | OS command-injection request-log pattern match — illustrative Sentinel KQL, no permanent DET-ID assigned | Part 16 | release-v2/chapters/part16-web-detection-engineering.md | T1059; T1059.003; T1059.004 |
| unformalized-5 | SSRF cloud-metadata/loopback outbound-fetch rule — illustrative Sigma, no permanent DET-ID assigned | Part 16 | release-v2/chapters/part16-web-detection-engineering.md | T1190; T1552.005 |
| DET-17-01 | Executive-impersonation via DMARC failure plus display-name match | Part 17 | release-v2/chapters/part17-email-detection-engineering.md | T1656 |
| DET-17-02 | Lookalike-domain first-contact to a finance recipient | Part 17 | release-v2/chapters/part17-email-detection-engineering.md | T1566; T1656 |
| DET-17-03 | High-risk OAuth consent grant burst | Part 17 | release-v2/chapters/part17-email-detection-engineering.md | T1528 |
| DET-17-04 | External auto-forwarding rule with evidence-hiding action | Part 17 | release-v2/chapters/part17-email-detection-engineering.md | T1114.003 |
| DET-18-01 | Suspicious OAuth app consent grant (illicit consent grant pattern) | Part 18 | release-v2/chapters/part18-cloud-identity-and-saas-detection-engineering.md | T1528; T1550.001 |
| DET-18-02 | Guest account granted a privileged directory role | Part 18 | release-v2/chapters/part18-cloud-identity-and-saas-detection-engineering.md | T1199; T1078.004 |
| DET-18-03 | Legacy authentication protocol success against a tenant with an intended block policy | Part 18 | release-v2/chapters/part18-cloud-identity-and-saas-detection-engineering.md | T1078.004 |
| DET-18-04 | Session/refresh token used from an inconsistent device or network fingerprint | Part 18 | release-v2/chapters/part18-cloud-identity-and-saas-detection-engineering.md | T1550.004 |
| DET-19-01 | IAM privilege escalation via policy attachment/creation (AWS CloudTrail) | Part 19 | release-v2/chapters/part19-cloud-infrastructure-detection-engineering.md | T1098.003 |
| DET-19-02 | Storage bucket/container exposed via public policy or ACL change | Part 19 | release-v2/chapters/part19-cloud-infrastructure-detection-engineering.md | T1530 |
| DET-19-03 | Security group ingress opened to 0.0.0.0/0 on, or spanning, a sensitive port | Part 19 | release-v2/chapters/part19-cloud-infrastructure-detection-engineering.md | T1562.007 |
| DET-19-04 | CloudTrail logging disabled, deleted, or silently narrowed | Part 19 | release-v2/chapters/part19-cloud-infrastructure-detection-engineering.md | T1562.008 |
| DET-19-05 | Snapshot/image sharing to an external, non-allowlisted account, or made fully public | Part 19 | release-v2/chapters/part19-cloud-infrastructure-detection-engineering.md | T1537 |
| DET-19-06 | Backdoor long-lived credential (CreateAccessKey) created on an already-compromised identity | Part 19 | release-v2/chapters/part19-cloud-infrastructure-detection-engineering.md | T1098.001 |
| DET-20-01 | Confidential-classified retrieval content reaching an unapproved external-destination tool call | Part 20 | release-v2/chapters/part20-ai-systems-telemetry-and-audit-trail-engineering.md | T1048 (loose/directional mapping, explicitly caveated) |
| DET-21-01 | Intent-divergence detection for indirect prompt injection | Part 21 | release-v2/chapters/part21-ai-security-detection-engineering.md | ATLAS-native (no clean ATT&CK technique); T1567 (case-level tag only) |
| DET-21-02 | Hidden-instruction extraction from uploaded files at ingestion | Part 21 | release-v2/chapters/part21-ai-security-detection-engineering.md | T1204.002 |
| DET-21-03 | Anomalous ingestion volume from a narrow source set (RAG/KB poisoning) | Part 21 | release-v2/chapters/part21-ai-security-detection-engineering.md | T1565.001 |
| DET-21-04 | Cross-tenant or cross-authorization output flagged by a PII classifier | Part 21 | release-v2/chapters/part21-ai-security-detection-engineering.md | T1567 (channel-dependent) |
| DET-21-05 | Session-level lethal-trifecta scoring for agent/tool/MCP abuse | Part 21 | release-v2/chapters/part21-ai-security-detection-engineering.md | ATLAS-native (no clean ATT&CK technique); T1567 (case-level) |
| DET-21-06 | Anomalous API key usage pattern (AI API compromise) | Part 21 | release-v2/chapters/part21-ai-security-detection-engineering.md | T1078 |
| DET-21-07 | Cost/token-volume spike per key or workflow | Part 21 | release-v2/chapters/part21-ai-security-detection-engineering.md | T1496 |
| DET-21-08 | Code-agent sandbox egress to a non-allowlisted destination | Part 21 | release-v2/chapters/part21-ai-security-detection-engineering.md | T1059; T1567 (case-level, if data leaves) |
| DET-22-01 | Sudo invocation of a command outside the host's established baseline | Part 22 | release-v2/chapters/part22-detection-as-code.md | T1548.003 |
| DET-23-01 | Suspicious process access to lsass.exe — canonical analytic, threaded through and reimplemented natively in Parts 24 (Sigma), 25 (KQL, as DET-25-01), 26 (SPL, as DET-26-01), 27 (AQL, as DET-27-01), 28 (YARA-L), 29 (EQL/KQL/ES\|QL, as DET-29-01), and Appendix A5 — see QUERY-INVENTORY.md | Part 23 | release-v2/chapters/part23-query-language-strategy.md | T1003.001 |
| DET-24-01 | SSH failed-authentication burst against a single account, expressed as a native Sigma correlation rule | Part 24 | release-v2/chapters/part24-sigma.md | T1110.001 |
| DET-25-01 | LSASS memory-access via DeviceEvents OpenProcessApiCall (KQL implementation of DET-23-01) | Part 25 | release-v2/chapters/part25-kql-sentinel-defender.md | T1003.001 |
| DET-25-02 | SSH failed-authentication burst, natively aggregated (KQL summarize/bin against Syslog) | Part 25 | release-v2/chapters/part25-kql-sentinel-defender.md | T1110.001 |
| DET-26-01 | LSASS memory-access via Sysmon Event ID 10, implemented in Splunk SPL (lookup-based allowlist) | Part 26 | release-v2/chapters/part26-splunk-spl.md | T1003.001 |
| DET-26-02 | SSH failed-authentication burst — DET-03-01 hardened with stats, explicit burst window, threshold | Part 26 | release-v2/chapters/part26-splunk-spl.md | T1110; T1110.001 |
| DET-26-03 | Recon-shaped HTTP request breadth via transaction (SPL equivalent of honeynet recon-stage classification) | Part 26 | release-v2/chapters/part26-splunk-spl.md | T1595 |
| DET-27-01 | Suspicious LSASS access, unapproved process (QRadar Building Block + Reference Set + Rule re-implementation of DET-23-01) | Part 27 | release-v2/chapters/part27-qradar-aql.md | T1003.001 |
| DET-27-02 | Repeated authentication failure against one account, one source (QRadar CRE threshold-test implementation of DET-01-01) | Part 27 | release-v2/chapters/part27-qradar-aql.md | — |
| DET-28-01 | SSH credential-guessing correlation against a honeynet SSH decoy (multi-event YARA-L, 24h window, count>=5) | Part 28 | release-v2/chapters/part28-yara-l-google-secops.md | T1110; T1110.001 |
| DET-29-01 | Suspicious process access to lsass.exe — Elastic KQL/EQL/ES\|QL re-implementations of DET-23-01 | Part 29 | release-v2/chapters/part29-elastic-eql-kql-esql.md | T1003.001 |
| DET-30-01 | Five-stage compromised-account chain: failed-logon burst → successful logon → privileged token (4672) → process create → network connection | Part 30 | release-v2/chapters/part30-correlation-engineering.md | T1110; T1078 |
| DET-30-02 | Grace-period re-check for late-arriving stage-5 (network connection) events against DET-30-01's partial-match state | Part 30 | release-v2/chapters/part30-correlation-engineering.md | — |
| DET-31-01 | Per-account SSH authentication-rate baseline (Splunk SPL, two-stage nightly build + hourly scoring) | Part 31 | release-v2/chapters/part31-baselining.md | T1110.001; T1078 |
| DET-31-02 | Service-account sudo behavioral-profile deviation (Sentinel KQL) | Part 31 | release-v2/chapters/part31-baselining.md | T1078.003; T1136.001 |
| DET-32-01 | Composite-gated alert on a threat-intelligence match against an internet-facing asset | Part 32 | release-v2/chapters/part32-threat-intelligence-in-detection.md | — |
| DET-32-02 | Indicator-age decay applied to a threat-intelligence match's composite score | Part 32 | release-v2/chapters/part32-threat-intelligence-in-detection.md | — |
| DET-33-01 | Kill-chain stage-weighted session risk score | Part 33 | release-v2/chapters/part33-risk-based-detection.md | T1595; T1046; T1083; T1190 |
| DET-34-01 | Interactive sudo session on an account with a zero-interactive-history baseline | Part 34 | release-v2/chapters/part34-threat-hunting-fundamentals.md | T1078; T1078.003; T1021.004; T1548.003 |
| DET-35-01 | SSH pre-authentication negotiation failure (atomic event) | Part 35 | release-v2/chapters/part35-hunt-types.md | T1595 |
| DET-36-01 | Exploit-shaped web request followed by non-duplicate follow-up activity from the same source | Part 36 | release-v2/chapters/part36-hunt-to-detection.md | T1190 |
| DET-37-01 | SSH failed-authentication burst from a single source (Sigma, count() by source.ip > 10 in 5m) | Part 37 | release-v2/chapters/part37-detection-testing.md | T1110.001; T1110.003 |
| DET-38-01 | Sudo invocation pivoting root to a service account (TTY-presence split for scripted vs. interactive sudo) | Part 38 | release-v2/chapters/part38-false-positive-engineering.md | T1548.003 |
| DET-38-02 | SSH failed-authentication burst against a small account set from a single source | Part 38 | release-v2/chapters/part38-false-positive-engineering.md | T1110.001 |
| DET-39-01 | Distributed credential-stuffing / brute-force detection aggregated by destination account and credential diversity (SPL, tstats) | Part 39 | release-v2/chapters/part39-false-negative-engineering.md | T1110.004; T1110.001 |
| DET-39-02 | Credential-stuffing detection re-aggregated by destination host to catch multi-account spread (KQL) | Part 39 | release-v2/chapters/part39-false-negative-engineering.md | T1110.004; T1110.001 |
| DET-40-01 | Curl/scripting-User-Agent + destination-rarity + exploit-path risk-scored composite (path_exploit_only vs. path_admin_generic split) — minted in Part 40 | Part 40 | release-v2/chapters/part40-detection-autopsy.md | T1595; T1595.002; T1190 |
| DET-40-02 | Rarity + indicator-age + infrastructure-role + local-context confidence composite, anticipating Part 32 — minted in Part 40 | Part 40 | release-v2/chapters/part40-detection-autopsy.md | T1071; T1583.001 |
| DET-41-01 | Coverage-row staleness alert (meta-detection on the coverage matrix's own last_validated/tier state; no attacker telemetry by design) | Part 41 | release-v2/chapters/part41-detection-coverage.md | — (no MITRE mapping by design) |
| DET-42-01 | Exception/suppression-ledger audit — flags ExceptionRegistry entries past review date or with a null/unparseable review date | Part 42 | release-v2/chapters/part42-detection-quality.md | N/A — program-hygiene analytic, not adversary behavior |
| DET-42-02 | Rule-failure canary — alerts on absence of a scheduled synthetic event in CanaryEvents_CL | Part 42 | release-v2/chapters/part42-detection-quality.md | N/A — pipeline-health analytic, not adversary behavior |
| DET-43-01 | SSH failed-password burst by source | Part 43 | release-v2/chapters/part43-detection-debt.md | T1110.001; T1110.003 |
| (illustrative, unnamed) | Crash-loop / repeated stop-start cycling on a production service unit (systemd) | Part 43 | release-v2/chapters/part43-detection-debt.md | — |
| (illustrative, unnamed) | Unexpected root activity against service-account-owned data (sudo/sqlite3 health-check pattern) | Part 43 | release-v2/chapters/part43-detection-debt.md | — |
| DET-44-01 | Multi-tactic session-progression correlation over honeynet-style tagged sessions | Part 44 | release-v2/chapters/part44-adversary-behaviour-for-defenders.md | T1595; T1046; T1083; T1190 |
| DET-45-01 | Volume Shadow Copy and Windows Backup deletion | Part 45 | release-v2/chapters/part45-ransomware-detection-model.md | T1490 |
| DET-45-02 | Backup or hypervisor management service stopped with no matching restart | Part 45 | release-v2/chapters/part45-ransomware-detection-model.md | T1489 |
| DET-45-03 | Composite ransomware kill-chain risk score | Part 45 | release-v2/chapters/part45-ransomware-detection-model.md | T1078; T1082; T1003; T1021; T1490 |
| DET-45-04 | Mass file-modification-rate detection (encryption stage) | Part 45 | release-v2/chapters/part45-ransomware-detection-model.md | T1486 |
| DET-46-01 | On-prem privileged password reset (Event ID 4724) followed by cloud sign-in for the same synced identity within the sync-lag window | Part 46 | release-v2/chapters/part46-identity-compromise-model.md | T1098; T1078.002; T1078.004 |
| DET-46-02 | Anomalous sudo invocation relative to per-account scripted/human baseline shape | Part 46 | release-v2/chapters/part46-identity-compromise-model.md | T1548.003; T1078.003 |
| DET-46-03 | On-prem privilege success (DCSync variant, Event ID 4662) correlated with a subsequent cloud privilege grant | Part 46 | release-v2/chapters/part46-identity-compromise-model.md | T1003.006; T1528; T1098 |
| DET-46-04 | Cross-surface discovery burst (on-prem enumeration + cloud directory reads, thresholded) | Part 46 | release-v2/chapters/part46-identity-compromise-model.md | T1087.002; T1087.004; T1069.002 |
| DET-46-05 | Identity fan-out across systems, tenants, or applications beyond baseline | Part 46 | release-v2/chapters/part46-identity-compromise-model.md | T1078; T1550.002; T1550.003; T1199 |
| DET-46-06 | Chain-weighted data-access alert with NoiseFloor-clamped effective threshold | Part 46 | release-v2/chapters/part46-identity-compromise-model.md | T1114; T1213; T1530 |
| DET-47-01 | Web-server-lineage shell followed by a LOLBin download, same host, bounded window | Part 47 | release-v2/chapters/part47-web-compromise-model.md | T1505.003; T1105; T1197 |
| DET-47-02 | New or rare outbound destination from a web-tier host, following a Suspicious-or-higher lineage event | Part 47 | release-v2/chapters/part47-web-compromise-model.md | T1071.001; T1041 |
| DET-48-01 | Ordered chain-completion scoring across the seven-stage AI compromise model | Part 48 | release-v2/chapters/part48-ai-compromise-model.md | T1078; T1567 |
| DET-A3-01 | Agent tool call using an assumed cloud role with no resolvable sourceIdentity (Sentinel KQL join against AWS CloudTrail) | Appendix A3 | release-v2/appendices/a3-cloud-and-ai-telemetry-field-reference.md | T1078.004 |
| a4-illustrative-t1190-http-probe | Exploit-shaped HTTP request against exposed web service — illustrative Sigma rule, not a deployed detection | Appendix A4 | release-v2/appendices/a4-mitre-attack-mapping-quick-reference.md | T1190 |
| DET-A6-01 | Coordinated multi-target scanning from a shared /24 against the honeynet decoy estate (draft) | Appendix A6 | release-v2/appendices/a6-templates-detection-hunt-review-testing-tuning-change-request.md | T1595; T1046; T1190 |
| DET-A7-01 | Illustrative Splunk SPL rule: repeated failed SSH password authentication from few accounts (count + distinct-account discriminator) | Appendix A7 | release-v2/appendices/a7-coverage-telemetry-and-qa-matrices-and-checklists.md | T1110; T1110.001 |

## Notes on cross-part reuse

- **DET-23-01** (Suspicious process access to lsass.exe) is the book's one canonical cross-language detection. It is defined once in Part 23 and then re-implemented, byte-for-byte equivalent in intent, as a native artifact in Sigma (Part 24), Sentinel/Defender KQL (Part 25, as DET-25-01), Splunk SPL (Part 26, as DET-26-01), QRadar AQL (Part 27, as DET-27-01), YARA-L/UDM (Part 28, reusing the ID DET-23-01), and Elastic EQL/KQL/ES\|QL (Part 29, as DET-29-01). Appendix A5 restates all of these side by side. See QUERY-INVENTORY.md for the per-language breakdown.
- **DET-08-02** and **HUNT-08-01** (Part 8) are cross-referenced, not redefined, in Appendix A1.
- **DET-10-02, DET-11-01, DET-11-02, DET-12-02, DET-12-03, DET-12-04, DET-15-05, DET-16-04** are cited and, in several cases, hardened with new Blind Spot/False Positive Trap callouts, in Part 40's capstone autopsy — Part 40 itself only mints DET-40-01 and DET-40-02 as new detections.
