# Hunt Inventory

Every named threat hunt built across the book, aggregated from the 55 authoring-pipeline unit summaries. 98 hunts total.

| ID | Name | Part/Appendix | File |
|---|---|---|---|
| part02-hunt-01 | Office application spawning a scripting interpreter (rarity-based, flag-independent) | Part II — How Attacks Become Data | `book/chapters/part02-how-attacks-become-data.md` |
| part03-01 | DNS Tunneling / C2 Beacon Hunt Across DNS + Zeek + NetFlow (with entropy/subdomain-count KQL sketch) | Part III — Telemetry Engineering | `book/chapters/part03-telemetry-engineering.md` |
| part04-03 | Privileged RemoteInteractive sessions from unbaselined sources with anomalous child processes (4624 Type 10 + 4672 + 4688 correlation) | Part IV — Windows Detection Engineering | `book/chapters/part04-windows-detection-engineering.md` |
| part05-h1 | Renamed-binary hunt via OriginalFileName mismatch (rundll32 example) | Part V — Sysmon as Detection Telemetry | `book/chapters/part05-sysmon-detection-telemetry.md` |
| part05-h2 | Known-good driver hash baseline vs Event ID 6 hash allowlist deviation (BYOVD) | Part V — Sysmon as Detection Telemetry | `book/chapters/part05-sysmon-detection-telemetry.md` |
| part05-h3 | Named pipe rarity/clustering hunt beyond known-bad pipe name lists | Part V — Sysmon as Detection Telemetry | `book/chapters/part05-sysmon-detection-telemetry.md` |
| part05-h4 | Baseline event-rate drop correlated with Sysmon/EDR service tamper (absence-of-evidence hunt) | Part V — Sysmon as Detection Telemetry | `book/chapters/part05-sysmon-detection-telemetry.md` |
| part06-hunt-01 | Rarity ranking of Office-app-to-PowerShell command lines across fleet | Part VI — Process Tree Detection | `book/chapters/part06-process-tree-detection.md` |
| part06-hunt-02 | Ancestry-chain anomaly hunting: depth outliers, signer discontinuity, parent PID/start-time mismatch, logon-type outliers | Part VI — Process Tree Detection | `book/chapters/part06-process-tree-detection.md` |
| part07-hunt-01 | PowerShell short-launch-string vs long-script-block-log variance hunt (catches obfuscation that defeats -enc flag matching) | Part VII — Command Line Detection | `book/chapters/part07-command-line-detection.md` |
| part07-hunt-02 | Office-parent to interpreter-child rarity hunt across 90-day baseline | Part VII — Command Line Detection | `book/chapters/part07-command-line-detection.md` |
| part07-hunt-03 | Script block log search for DownloadString/IEX/HttpClient regardless of process-creation command line content | Part VII — Command Line Detection | `book/chapters/part07-command-line-detection.md` |
| part08-h1 | Low-and-slow spray hunt (sub-window/multi-day shallow attempts) | Part VIII — Identity Detection Engineering | `book/chapters/part08-identity-detection-engineering.md` |
| part08-h2 | Quiet fatigue / abandoned MFA-burst hunt across multiple days | Part VIII — Identity Detection Engineering | `book/chapters/part08-identity-detection-engineering.md` |
| part08-h3 | Sub-threshold geographic drift hunt | Part VIII — Identity Detection Engineering | `book/chapters/part08-identity-detection-engineering.md` |
| part08-h4 | Slow-roll Kerberoasting hunt (per-SPN baseline + first-ever service-account interactive logon) | Part VIII — Identity Detection Engineering | `book/chapters/part08-identity-detection-engineering.md` |
| part08-h5 | Replication-rights exposure audit + retrospective 4662 sweep for DCSync | Part VIII — Identity Detection Engineering | `book/chapters/part08-identity-detection-engineering.md` |
| part09-hunt-01 | Slow/low-and-slow port scanning under naive count thresholds (7-day rolling distinct-port-per-source) | Part IX — Network Detection Engineering | `book/chapters/part09-network-detection-engineering.md` |
| part09-hunt-02 | SMB fan-out to second-host beacon chain from a confirmed initial-access host | Part IX — Network Detection Engineering | `book/chapters/part09-network-detection-engineering.md` |
| part09-hunt-03 | Cumulative slow/low exfiltration to a rare destination over a rolling multi-day window (SPL) | Part IX — Network Detection Engineering | `book/chapters/part09-network-detection-engineering.md` |
| part10-01 | Domain-first, time-correlation, infrastructure, and negative-space (NXDOMAIN-heavy host) pivots for DGA/tunnelling candidates | Part X — DNS Detection | `book/chapters/part10-dns-detection.md` |
| part11-h01 | Hunt for non-shelling web shells (pure PHP/JSP language-native eval/system, no child process) via new script files, entropy, and abnormal response timing under web-writable dirs | Part XI — Web Detection Engineering | `book/chapters/part11-web-detection-engineering.md` |
| part11-h02 | Low-and-slow admin-panel/discovery enumeration hunt via UA/JA3 fingerprint clustering across rotating source IPs instead of fixed-window 404 rate | Part XI — Web Detection Engineering | `book/chapters/part11-web-detection-engineering.md` |
| part11-h03 | Rotating-IP credential stuffing hunt at the account level (failed logins against breach-dump usernames from many single-attempt distinct sources) | Part XI — Web Detection Engineering | `book/chapters/part11-web-detection-engineering.md` |
| part11-h04 | DNS-rebinding SSRF hunt — compare initial validation-time DNS resolution vs fetch-time resolution for app-provided URLs | Part XI — Web Detection Engineering | `book/chapters/part11-web-detection-engineering.md` |
| part12-h1 | External-forwarding inbox rule creation correlated with preceding anomalous sign-in | Part XII — Email Detection Engineering | `book/chapters/part12-email-detection-engineering.md` |
| part12-h2 | Mass-mail campaign clustering by near-duplicate subject/attachment hash vs. sender's historical volume | Part XII — Email Detection Engineering | `book/chapters/part12-email-detection-engineering.md` |
| part12-h3 | Communication-graph anomaly: sender-recipient relationship baseline for BEC/vendor-compromise | Part XII — Email Detection Engineering | `book/chapters/part12-email-detection-engineering.md` |
| part13-h01 | Stale or Unused App Registrations with Broad OAuth Grants | Part XIII — Cloud Detection Engineering | `book/chapters/part13-cloud-detection-engineering.md` |
| part13-h02 | Week-over-week security group / NSG / firewall rule diff for silently widened rules | Part XIII — Cloud Detection Engineering | `book/chapters/part13-cloud-detection-engineering.md` |
| part13-h03 | Cross-account S3 CopyObject / replication to external-owned buckets | Part XIII — Cloud Detection Engineering | `book/chapters/part13-cloud-detection-engineering.md` |
| part13-h04 | IAM policy documents with wildcard Action/Resource created outside known IaC pipeline | Part XIII — Cloud Detection Engineering | `book/chapters/part13-cloud-detection-engineering.md` |
| part14-hunt-dll-write-precede | Hunt for DLL file-write staging events preceding sideload/hijack execution, shifting detection left to staging time | Part XIV — Endpoint Detection Engineering | `book/chapters/part14-endpoint-detection-engineering.md` |
| part14-hunt-edr-silence | Hunt for endpoint agent telemetry silence (heartbeat gaps) as a stealthier EDR tampering indicator than logged service-stop events | Part XIV — Endpoint Detection Engineering | `book/chapters/part14-endpoint-detection-engineering.md` |
| part14-hunt-lolbin-baseline | Per-host LOLBin frequency-outlier hunt against own history rather than fleet-wide rarity | Part XIV — Endpoint Detection Engineering | `book/chapters/part14-endpoint-detection-engineering.md` |
| part14-hunt-lsass-artifacts | Hunt for LSASS dump-file artifacts and LSA/PPL protection downgrades preceding a dump attempt | Part XIV — Endpoint Detection Engineering | `book/chapters/part14-endpoint-detection-engineering.md` |
| part14-hunt-rmm-network | Hunt network egress (DNS/TLS-SNI) for RMM vendor infrastructure even when the process binary is renamed to evade name-based detection | Part XIV — Endpoint Detection Engineering | `book/chapters/part14-endpoint-detection-engineering.md` |
| part14-hunt-throttled-encryption | Hunt for slow/throttled mass file-modify activity that evades short-window high-volume ransomware detonation thresholds | Part XIV — Endpoint Detection Engineering | `book/chapters/part14-endpoint-detection-engineering.md` |
| part14-hunt-unbacked-memory | Hunt for unbacked executable memory regions as a mechanism-agnostic process injection/hollowing indicator | Part XIV — Endpoint Detection Engineering | `book/chapters/part14-endpoint-detection-engineering.md` |
| part15-hunt-01 | RAG restricted-classification document leaked to non-entitled users (SPL-style join of retrieval log, doc ACL, group membership) | Part XV — AI Security Detection Engineering | `book/chapters/part15-ai-security-detection-engineering.md` |
| part17-hunt-01 | Cluster PowerShell process creations by parent process and command-line length/entropy to catch encoded-command obfuscation variants that dodge literal flag matching | Part XVII — Sigma | `book/chapters/part17-sigma.md` |
| part17-hunt-02 | Trend failed-authentication-by-source-IP over time below the alerting threshold to catch password sprays tuned to stay under a known detection threshold | Part XVII — Sigma | `book/chapters/part17-sigma.md` |
| part17-hunt-03 | Pivot from confirmed rundll32 masquerading hits to module/image-load telemetry to identify the loaded DLL and hunt the same hash/path across other hosts | Part XVII — Sigma | `book/chapters/part17-sigma.md` |
| part19-03 | Entity correlation across SigninLogs, DeviceLogonEvents, DeviceProcessEvents for a flagged account/time window | Part XIX — KQL | `book/chapters/part19-kql.md` |
| part19-04 | Hunt for Graph API-driven privileged operations following risky sign-in (bypassing AuditLogs-only content) | Part XIX — KQL | `book/chapters/part19-kql.md` |
| part20-hunt-01 | streamstats trailing-average rate-of-change hunt for failed logons per account | Part XX — Splunk SPL | `book/chapters/part20-splunk-spl.md` |
| appA3-01-placeholder | Password-spray candidate via UNIQUECOUNT(username) grouped by source/destination | Part XXI — QRadar AQL | `book/chapters/part21-qradar-aql.md` |
| part21-02-hunt-placeholder | Low-and-slow beacon candidate via UNIQUECOUNT(destinationip) with high flow count | Part XXI — QRadar AQL | `book/chapters/part21-qradar-aql.md` |
| part22-hunt-01 | Loosen stage 1/3 of the descendant-network sequence (drop parent-name list, add DNS/SMB egress) to find document-to-C2 chains missed by the base rule | Part XXII — Elastic | `book/chapters/part22-elastic.md` |
| part22-hunt-02 | Pivot to ProcessAccess (handle-open with PROCESS_VM_READ) events against lsass.exe to catch procdump/API-based LSASS dumping that leaves no interesting process command line | Part XXII — Elastic | `book/chapters/part22-elastic.md` |
| part23-hunt-01 | Partial chains stalling at token-use/process stage (low-and-slow dwell) | Part XXIII — Detection Correlation | `book/chapters/part23-detection-correlation.md` |
| part23-hunt-02 | Successful logon with no preceding failure burst (valid-account access without brute force) | Part XXIII — Detection Correlation | `book/chapters/part23-detection-correlation.md` |
| part23-hunt-03 | Suspicious process to external connection with no preceding auth anomaly (token theft / session hijack) | Part XXIII — Detection Correlation | `book/chapters/part23-detection-correlation.md` |
| part24-02 | Hunt for entities scoring consistently just under alert threshold across multiple consecutive windows (adversary pacing to evade risk-score cutoff) | Part XXIV — Risk-Based Alerting | `book/chapters/part24-risk-based-alerting.md` |
| part25-hunt-01 | First-time-on-this-host process execution (fleet-common but host-novel binaries with unusual parent) | Part XXV — Baselining | `book/chapters/part25-baselining.md` |
| part25-hunt-02 | Service accounts authenticating from general-purpose user-workstation subnets | Part XXV — Baselining | `book/chapters/part25-baselining.md` |
| part25-hunt-03 | Zero-variance login-time/location accounts (possible human-account-as-service-account or scripted attacker use) | Part XXV — Baselining | `book/chapters/part25-baselining.md` |
| part26-01 | Staged hunt for valid-credential access combined with unusual remote-administration methods (RDP/WinRM/SMB/WMI/RMM tooling), using identity, host-pair, and time-of-day baselines | Part XXVI — Threat Hunting | `book/chapters/part26-threat-hunting.md` |
| part27-01 | IOC-based hunt: leaked C2 IP sweep across proxy/firewall/DNS logs | Part XXVII — Hunt Types | `book/chapters/part27-hunt-types.md` |
| part27-02 | TTP-based hunt: LSASS memory access pattern independent of tool | Part XXVII — Hunt Types | `book/chapters/part27-hunt-types.md` |
| part27-03 | Anomaly-based hunt: rare parent-child process pairs | Part XXVII — Hunt Types | `book/chapters/part27-hunt-types.md` |
| part27-04 | Intelligence-led hunt: advisory-driven multi-layer actor hunt | Part XXVII — Hunt Types | `book/chapters/part27-hunt-types.md` |
| part27-05 | Incident-driven hunt: lateral movement scoping during active IR | Part XXVII — Hunt Types | `book/chapters/part27-hunt-types.md` |
| part27-06 | Detection-gap-driven hunt: manual coverage for unmanaged Linux servers | Part XXVII — Hunt Types | `book/chapters/part27-hunt-types.md` |
| part27-07 | Retrospective hunt: supply-chain compromise disclosure lookback | Part XXVII — Hunt Types | `book/chapters/part27-hunt-types.md` |
| part27-08 | Hypothesis-driven hunt: RDP trust-relationship lateral movement without new tooling | Part XXVII — Hunt Types | `book/chapters/part27-hunt-types.md` |
| HUNT-2026-014 | Kerberoasting hunt via rare-actor distinct-SPN TGS burst detection (worked notebook example) | Part XXVIII — Threat Hunt Notebook | `book/chapters/part28-threat-hunt-notebook.md` |
| part29-01 | Hunt for LSASS ProcessAccess with memory-read mask and dbghelp/dbgcore call trace | Part XXIX — From Hunt to Detection | `book/chapters/part29-from-hunt-to-detection.md` |
| part30-01-hunt | Slow-drip / long-dwell Kerberoasting SPN enumeration (residual gap hunt) | Part XXX — Detection Testing | `book/chapters/part30-detection-testing.md` |
| part32-hunt-01 | Hunt for LSASS-access technique variants beyond the stock Atomic Red Team comsvcs.dll command-line pattern (argument-order/casing/whitespace variants and non-comsvcs tools) | Part XXXII — Attack Simulation for Defensive Validation | `book/chapters/part32-attack-simulation-defensive-validation.md` |
| part33-hunt-01 | Fail-then-succeed authentication pattern without correlated credential rotation event | Part XXXIII — False Positive Engineering | `book/chapters/part33-false-positive-engineering.md` |
| part34-01 | Hunting LSASS credential-access technique variants (procdump, comsvcs.dll MiniDump, Task Manager dump, direct API handle duplication) to find command-line-based detection blind spots | Part XXXIV — False Negatives | `book/chapters/part34-false-negatives.md` |
| part36-hunt-01 | Hunt for WMI/COM-based Win32_ShadowCopy deletion outside known backup-software process trees, as a compensating lead for the PARTIAL DETECTION gap in the T1490 command-line rule | Part XXXVI — Detection Coverage Matrix | `book/chapters/part36-detection-coverage-matrix.md` |
| part39-h1 | Hunt against the 'detections changed in the last 30 days' list to find fresh post-change gaps | Part XXXIX — Change Management | `book/chapters/part39-change-management.md` |
| part40-hunt-01 | Manual re-hunt of a migrated detection's target behaviour on the new platform before trusting the migrated rule's fire rate | Part XL — SIEM Migration | `book/chapters/part40-siem-migration.md` |
| part41-01 | High failure-to-success authentication ratio from a single normalized source IP (low-and-slow credential stuffing) | Part XLI — Normalisation | `book/chapters/part41-normalisation.md` |
| part42-hunt-01 | Hunting your own detection surface for field-population drift (extract referenced field paths, measure non-null population rate, flag rename candidates via sibling-field check) | Part XLII — Parser Failure | `book/chapters/part42-parser-failure.md` |
| part43-02 | Hunting recent activity in a slow-ingesting source (e.g. cloud audit/SaaS logs) without underestimating the true lookback needed to cover ingestion latency | Part XLIII — Time | `book/chapters/part43-time.md` |
| part44-01 | Log Source Heartbeat Gap hunt (KQL illustrative) | Part XLIV — Data Retention | `book/chapters/part44-data-retention.md` |
| part44-02 | Retention-Boundary Straddle Hunt (process/runbook hunt, not a query) | Part XLIV — Data Retention | `book/chapters/part44-data-retention.md` |
| part45-hunt-ttp | Hunt for TTP-level pattern (scheduled-task persistence + beacon interval) independent of atomic indicator, to catch infrastructure rotation/variants missed by hash/IP matching alone | Part XLV — Threat Intelligence in Detection | `book/chapters/part45-threat-intelligence-in-detection.md` |
| part46-02 | Pre-encryption ransomware hunt: shadow-copy/backup deletion followed by mass file-write on same host within a short window (illustrative KQL) | Part XLVI — Adversary Tradecraft: A Defender View | `book/chapters/part46-adversary-tradecraft-defender-view.md` |
| part46-03 | Discovery rate-and-diversity anomaly hunt: accounts running unusually many distinct discovery commands against unusually many distinct hosts/shares in a short window vs. 90-day baseline | Part XLVI — Adversary Tradecraft: A Defender View | `book/chapters/part46-adversary-tradecraft-defender-view.md` |
| part47-hunt-01 | RMM tool inventory diff week-over-week | Part XLVII — Ransomware Detection Engineering | `part47-ransomware-detection-engineering.md` |
| part47-hunt-02 | LSASS dump artifact hunt (minidump magic bytes, archive-then-delete pattern) | Part XLVII — Ransomware Detection Engineering | `part47-ransomware-detection-engineering.md` |
| part47-hunt-03 | DC-side LDAP query volume/breadth spike hunt (SharpHound-style) | Part XLVII — Ransomware Detection Engineering | `part47-ransomware-detection-engineering.md` |
| part47-hunt-04 | Reverse fan-in lateral movement hunt (staging host receiving from many sources) | Part XLVII — Ransomware Detection Engineering | `part47-ransomware-detection-engineering.md` |
| part47-hunt-05 | Outbound flow anomaly hunt to cloud-storage ASNs from server-role hosts | Part XLVII — Ransomware Detection Engineering | `part47-ransomware-detection-engineering.md` |
| part47-hunt-06 | Shadow-copy count inventory diff and backup-agent service stoppage hunt | Part XLVII — Ransomware Detection Engineering | `part47-ransomware-detection-engineering.md` |
| part47-hunt-07 | Post-incident 72-hour backward timeline reconstruction hunt | Part XLVII — Ransomware Detection Engineering | `part47-ransomware-detection-engineering.md` |
| part48-h1 | Reverse-chain hunt from Stage 6 (data access) backward through the identity compromise model | Part XLVIII — Identity Compromise Detection Model | `book/chapters/part48-identity-compromise-detection-model.md` |
| part49-hunt-dns-gap | Hunt for outbound connections from web-worker ancestry with no preceding matching DNS query (IP-literal C2) | Part XLIX — Web Compromise Detection Model | `book/chapters/part49-web-compromise-detection-model.md` |
| part49-hunt-webshell-pattern | Hunt for repeated-request webshell interaction pattern under uploads/media paths with executable extensions | Part XLIX — Web Compromise Detection Model | `book/chapters/part49-web-compromise-detection-model.md` |
| part50-hunt-01 | Chain-score distribution review — manually review top 1-2% of weekly AI session chain scores even below alert threshold | Part L — AI System Compromise Detection Model | `book/chapters/part50-ai-system-compromise-detection-model.md` |
| part50-hunt-02 | Full-chain reconstruction walkthrough from a single stage-6 exfiltration alert back through tool call, retrieval, and poisoned source document | Part L — AI System Compromise Detection Model | `book/chapters/part50-ai-system-compromise-detection-model.md` |
| appA2-02 | Kerberoasting beyond the threshold alert (low-and-slow RC4 ticket requests, first-time-RC4 baselining) | Appendix A2 — MITRE ATT&CK Detection Mapping | `book/appendices/a2-mitre-detection-mapping.md` |
| appA3-02 | Password-spray hunt via AQL (single account, many destination IPs, high failure count, short window) | Appendix A3 — Query Language Quick Reference | `book/appendices/a3-query-language-quick-reference.md` |
| appA3-03 | Office-app-spawns-script-interpreter with encoded/long command line (KQL + SPL worked example) | Appendix A3 — Query Language Quick Reference | `book/appendices/a3-query-language-quick-reference.md` |
