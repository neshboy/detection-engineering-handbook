# Detection Inventory

Every detection built across the book, aggregated from the 55 authoring-pipeline unit summaries. 109 detections total.

| ID | Name | Part/Appendix | File | MITRE Techniques |
|---|---|---|---|---|
| part01-01 | Suspicious Remote Logon Followed by Privileged Execution (LOLBin correlation with 30-day account-host baseline) | Part I — Detection Engineering Foundations | `book/chapters/part01-detection-engineering-foundations.md` | T1078, T1218 |
| part02-01 | Suspicious PowerShell Launched from Office Application with Encoded Command | Part II — How Attacks Become Data | `book/chapters/part02-how-attacks-become-data.md` | T1059.001, T1566 |
| part03-02 | Suspicious PowerShell Download-and-Execute Pattern with Office Parent (revised from naive keyword rule, illustrative Sigma) | Part III — Telemetry Engineering | `book/chapters/part03-telemetry-engineering.md` | T1059.001, T1027, T1204.002 |
| part03-03 | Cloud Session Token Reuse From Inconsistent Device Fingerprint (illustrative conceptual Sigma-style sketch) | Part III — Telemetry Engineering | `book/chapters/part03-telemetry-engineering.md` | T1078.004, T1550.004, T1556 |
| part04-01 | Possible Kerberoasting - High Distinct SPN Service Ticket Request Volume (Sigma) | Part IV — Windows Detection Engineering | `book/chapters/part04-windows-detection-engineering.md` | T1558.003 |
| part04-02 | Kerberoasting distinct-SPN volume hunt (KQL companion query) | Part IV — Windows Detection Engineering | `book/chapters/part04-windows-detection-engineering.md` | T1558.003 |
| part05-01 | Rundll32 Execution From UNC or Temp Path | Part V — Sysmon as Detection Telemetry | `book/chapters/part05-sysmon-detection-telemetry.md` | T1218.011 |
| part05-02 | Suspicious LSASS Access By Unsigned Or Non-Allowlisted Process (Detection Autopsy revised analytic) | Part V — Sysmon as Detection Telemetry | `book/chapters/part05-sysmon-detection-telemetry.md` | T1003.001 |
| part05-03 | Registry Run Key / IFEO / Winlogon Persistence via Sysmon 13 (KQL) | Part V — Sysmon as Detection Telemetry | `book/chapters/part05-sysmon-detection-telemetry.md` | T1547.001 |
| part05-04 | Registry Hive Dump via reg.exe save | Part V — Sysmon as Detection Telemetry | `book/chapters/part05-sysmon-detection-telemetry.md` | T1003.002 |
| part06-01 | Office Application Spawning PowerShell with Encoded Command | Part VI — Process Tree Detection | `book/chapters/part06-process-tree-detection.md` | T1566.001, T1204.002, T1059.001 |
| part06-02 | w3wp.exe spawning cmd/powershell/script hosts (webshell post-exploitation) | Part VI — Process Tree Detection | `book/chapters/part06-process-tree-detection.md` | T1190, T1059.001, T1059.003 |
| part06-03 | Detection Autopsy: naive explorer.exe->powershell.exe -enc rule and its correlated revision | Part VI — Process Tree Detection | `book/chapters/part06-process-tree-detection.md` | T1059.001, T1134.004 |
| part07-01 | Encoded PowerShell Spawned From Office Application With Network Follow-Up | Part VII — Command Line Detection | `book/chapters/part07-command-line-detection.md` | T1059.001, T1027, T1566.001 |
| part08-01 | Possible Password Spraying Against Domain Controllers/IdP | Part VIII — Identity Detection Engineering | `book/chapters/part08-identity-detection-engineering.md` | T1110.003 |
| part08-02 | MFA Push Bombing (Fatigue) Burst Detection | Part VIII — Identity Detection Engineering | `book/chapters/part08-identity-detection-engineering.md` | T1621 |
| part08-03 | Impossible Travel via Sign-in Distance/Speed Calculation | Part VIII — Identity Detection Engineering | `book/chapters/part08-identity-detection-engineering.md` | T1078 |
| part08-04 | Possible Kerberoasting via Bulk RC4 TGS Requests | Part VIII — Identity Detection Engineering | `book/chapters/part08-identity-detection-engineering.md` | T1558.003 |
| part08-05 | DCSync from Non-DC Source (Replicating Directory Changes All) | Part VIII — Identity Detection Engineering | `book/chapters/part08-identity-detection-engineering.md` | T1003.006 |
| part09-01 | Horizontal Port Scan - Single Port Fan-Out Across Many Destinations | Part IX — Network Detection Engineering | `book/chapters/part09-network-detection-engineering.md` | T1046, T1595 |
| part09-02 | Vertical Port Scan - Single Source, Many Ports on One Target (KQL) | Part IX — Network Detection Engineering | `book/chapters/part09-network-detection-engineering.md` | T1046, T1595 |
| part09-03 | External TLS Session with Self-Signed Certificate to First-Seen Destination (KQL) | Part IX — Network Detection Engineering | `book/chapters/part09-network-detection-engineering.md` | T1573, T1071.001 |
| part09-04 | Single Host SMB Fan-Out to Multiple Internal Peers | Part IX — Network Detection Engineering | `book/chapters/part09-network-detection-engineering.md` | T1021.002, T1570 |
| part10-01 | DGA / DNS-Tunnelling Composite Score (entropy + rarity + NXDOMAIN ratio + subdomain-count + label-length consistency) | Part X — DNS Detection | `book/chapters/part10-dns-detection.md` | T1071.004, T1568.002, T1048.003 |
| part11-01 | Web Server Process Spawning Command Interpreter (Possible Web Shell) — Sigma rule, IIS/PHP-FPM/Apache worker parent spawning cmd.exe/powershell/sh/bash/whoami/net/certutil | Part XI — Web Detection Engineering | `book/chapters/part11-web-detection-engineering.md` | T1505.003, T1059, T1190 |
| part11-02 | SQLi indicator with response-based confirmation (KQL) — payload token match joined to latency/size deviation from route baseline, not payload-only | Part XI — Web Detection Engineering | `book/chapters/part11-web-detection-engineering.md` | T1190 |
| part11-03 | Web shell process-event to HTTP-request correlation (KQL) — joins DeviceProcessEvents shell spawn back to W3CIISLog request within 10 seconds | Part XI — Web Detection Engineering | `book/chapters/part11-web-detection-engineering.md` | T1505.003, T1071.001 |
| part11-04 | Credential stuffing: username diversity + failure rate by source (KQL) | Part XI — Web Detection Engineering | `book/chapters/part11-web-detection-engineering.md` | T1110.004 |
| part11-05 | SSRF: web-tier host connecting to cloud metadata IP (KQL, VMConnection/NetFlow) | Part XI — Web Detection Engineering | `book/chapters/part11-web-detection-engineering.md` | T1190, T1552 |
| part12-01 | Reply-To / From Domain Mismatch on External Inbound Mail | Part XII — Email Detection Engineering | `book/chapters/part12-email-detection-engineering.md` | T1566 |
| part12-02 | Newly Registered Lookalike Domain in Inbound Mail | Part XII — Email Detection Engineering | `book/chapters/part12-email-detection-engineering.md` | T1583.001, T1036.005 |
| part12-03 | Suspicious Inbox Rule Creation (BEC Persistence) | Part XII — Email Detection Engineering | `book/chapters/part12-email-detection-engineering.md` | T1114.003, T1564.008 |
| part12-04 | Inbound Mail Containing Embedded QR Code Image | Part XII — Email Detection Engineering | `book/chapters/part12-email-detection-engineering.md` | T1566.002 |
| part12-05 | High-Risk OAuth App Consent Grant | Part XII — Email Detection Engineering | `book/chapters/part12-email-detection-engineering.md` | T1528 |
| part13-01 | AWS Root Account Console Login | Part XIII — Cloud Detection Engineering | `book/chapters/part13-cloud-detection-engineering.md` | T1078.004 |
| part13-02 | IAM Access Key Created by Non-Automation Principal Followed by First Use From New Location | Part XIII — Cloud Detection Engineering | `book/chapters/part13-cloud-detection-engineering.md` | T1098.001 |
| part13-03 | Security Group Rule Opened to 0.0.0.0/0 on Sensitive Port | Part XIII — Cloud Detection Engineering | `book/chapters/part13-cloud-detection-engineering.md` | T1190 |
| part13-04 | Anomalous Volume of S3 GetObject Calls by Single Principal | Part XIII — Cloud Detection Engineering | `book/chapters/part13-cloud-detection-engineering.md` | T1530 |
| part14-01 | PowerShell execution with Base64-encoded command and suspicious parent process | Part XIV — Endpoint Detection Engineering | `book/chapters/part14-endpoint-detection-engineering.md` | T1059.001, T1027 |
| part14-02 | LSASS memory access via comsvcs.dll MiniDump export | Part XIV — Endpoint Detection Engineering | `book/chapters/part14-endpoint-detection-engineering.md` | T1003.001 |
| part14-03 | Non-standard process requesting high-privilege access to LSASS | Part XIV — Endpoint Detection Engineering | `book/chapters/part14-endpoint-detection-engineering.md` | T1003.001 |
| part14-04 | Volume shadow copy or backup catalog deletion | Part XIV — Endpoint Detection Engineering | `book/chapters/part14-endpoint-detection-engineering.md` | T1490 |
| part15-01 | Indirect Injection Leading to Unsolicited Tool Call | Part XV — AI Security Detection Engineering | `book/chapters/part15-ai-security-detection-engineering.md` | AML.T0051, T1567 |
| part15-02 | Model API Key Anomalous Usage Pattern (KQL-style) | Part XV — AI Security Detection Engineering | `book/chapters/part15-ai-security-detection-engineering.md` | T1552, T1078 |
| part15-03 | Agent Tool-Call Loop Detector | Part XV — AI Security Detection Engineering | `book/chapters/part15-ai-security-detection-engineering.md` | AML.T0053 |
| part16-01 | Rundll32 Executing DLL From User-Writable Path | Part XVI — Detection as Code | `book/chapters/part16-detection-as-code.md` | T1218.011 |
| part16-autopsy-impossible-travel | Detection Autopsy: tuned impossible-travel / novel-ASN MFA bypass detection (illustrative, referenced as part16-01-impossible-travel-mfa-bypass.yml in text) | Part XVI — Detection as Code | `book/chapters/part16-detection-as-code.md` | T1078, T1621 |
| part17-01 | Suspicious Encoded PowerShell Command Line | Part XVII — Sigma | `book/chapters/part17-sigma.md` | T1059.001, T1027 |
| part17-02 | Possible Password Spray - Many Accounts, Single Source, Low Attempt Count Each | Part XVII — Sigma | `book/chapters/part17-sigma.md` | T1110.003 |
| part17-03 | Rundll32 Execution With No Function Export Specified | Part XVII — Sigma | `book/chapters/part17-sigma.md` | T1218.011 |
| part18-01 | Suspicious LOLBin Network Egress (rundll32/regsvr32 launch followed by outbound connection from same process) | Part XVIII — YARA-L / Google SecOps | `book/chapters/part18-yaral-google-secops.md` | T1218.011, T1218.010, T1218 |
| part18-02 | Impossible Travel via UDM Login Events (same principal, distant source IPs, implausible gap) | Part XVIII — YARA-L / Google SecOps | `book/chapters/part18-yaral-google-secops.md` | T1078 |
| part19-01 | Impossible travel via successful sign-ins (speed/distance based) | Part XIX — KQL | `book/chapters/part19-kql.md` | T1078 |
| part19-02 | Risky sign-in followed by privileged directory operation within 30 minutes | Part XIX — KQL | `book/chapters/part19-kql.md` | T1078, T1098, T1136 |
| part20-01 | Distinct-host lateral movement via 4624 (dc()-based, revised from naive transaction) | Part XX — Splunk SPL | `book/chapters/part20-splunk-spl.md` | T1021.002, T1021 |
| part20-02 | Password spray detection via tstats/Authentication data model with risk scoring | Part XX — Splunk SPL | `book/chapters/part20-splunk-spl.md` | T1110.003, T1110 |
| part20-03 | Cloud storage exfil outlier detection via eventstats per-user baseline | Part XX — Splunk SPL | `book/chapters/part20-splunk-spl.md` | T1567.002, T1041 |
| part21-01 | Excessive distinct usernames per source against single destination (password spray) | Part XXI — QRadar AQL | `book/chapters/part21-qradar-aql.md` | T1110, T1110.003 |
| part21-02 | Low unique-destination, high event-count host (beaconing candidate) | Part XXI — QRadar AQL | `book/chapters/part21-qradar-aql.md` | T1071, T1105 |
| part22-01 | Suspicious document-process descendant network connection (EQL sequence) | Part XXII — Elastic | `book/chapters/part22-elastic.md` | T1566.001, T1059.001, T1059.005, T1071.001 |
| part22-02 | rundll32 comsvcs MiniDump followed by dump-file write (EQL sequence, maxspan) | Part XXII — Elastic | `book/chapters/part22-elastic.md` | T1003.001 |
| part23-01 | Failed Logon Burst Followed By Success, Token Use, and Suspicious Egress (multi-stage Sigma correlation) | Part XXIII — Detection Correlation | `book/chapters/part23-detection-correlation.md` | T1110, T1078, T1134, T1059, T1218, T1071 |
| part24-01 | Session-based composite risk scoring model (off-hours+travel, privilege+rarity, sensitive-data+rarity composites, IOC match, ATT&CK sequence chaining) | Part XXIV — Risk-Based Alerting | `book/chapters/part24-risk-based-alerting.md` | Discovery, Credential Access, Lateral Movement, Collection |
| part25-01 | Service Account Interactive Logon Outside Established Host Set | Part XXV — Baselining | `book/chapters/part25-baselining.md` | T1078, T1078.002, T1078.003 |
| part26-02 | Weighted anomaly-score analytic for interactive/network logons vs. identity, host-pair, and account-hour baselines (revised from Detection Autopsy) | Part XXVI — Threat Hunting | `book/chapters/part26-threat-hunting.md` | T1078, T1021.001, T1021.006 |
| part26-03 | First-ever-occurrence detection for RMM/remote-support tool binaries per host vs. approved-RMM baseline | Part XXVI — Threat Hunting | `book/chapters/part26-threat-hunting.md` | T1219 |
| part27-01 | IOC sweep for a leaked C2 IP | Part XXVII — Hunt Types | `book/chapters/part27-hunt-types.md` | — |
| part27-02 | LSASS access via undocumented tooling | Part XXVII — Hunt Types | `book/chapters/part27-hunt-types.md` | T1003.001 |
| part27-06 | Manual hunt for unmanaged Linux servers (authorized_keys modification) | Part XXVII — Hunt Types | `book/chapters/part27-hunt-types.md` | T1098.004 |
| part28-01 | Kerberoasting via Rare-Actor Distinct-SPN TGS Burst | Part XXVIII — Threat Hunt Notebook | `book/chapters/part28-threat-hunt-notebook.md` | T1558.003, T1087.002 |
| part29-01 | Suspicious LSASS Memory Access by Unsigned Non-Allowlisted Process | Part XXIX — From Hunt to Detection | `book/chapters/part29-from-hunt-to-detection.md` | T1003.001 |
| part30-01 | Kerberoasting - Excessive RC4 TGS Requests (revised aggregation analytic) | Part XXX — Detection Testing | `book/chapters/part30-detection-testing.md` | T1558.003 |
| part31-01 | Scheduled Task Created With Suspicious Action (illustrative Sigma, used as worked validation example) | Part XXXI — Safe Lab Validation | `book/chapters/part31-safe-lab-validation.md` | T1053.005 |
| part32-01 | Potential LSASS Memory Dump via comsvcs.dll (access-mask revised analytic) | Part XXXII — Attack Simulation for Defensive Validation | `book/chapters/part32-attack-simulation-defensive-validation.md` | T1003.001 |
| part33-01 | Multiple Failed Authentications Followed By Success (tuned service-account variant) | Part XXXIII — False Positive Engineering | `book/chapters/part33-false-positive-engineering.md` | T1110, T1078 |
| part34-01 | LSASS credential access coverage gap - process-access based detection replacing narrow ProcDump string match | Part XXXIV — False Negatives | `book/chapters/part34-false-negatives.md` | T1003.001 |
| part35-01 | Suspicious Process Access to LSASS Memory (credential dumping pattern) | Part XXXV — Detection Quality Metrics | `book/chapters/part35-detection-quality-metrics.md` | T1003, T1003.001 |
| part36-01 | Suspended-process-create followed by remote thread into mismatched image (process hollowing) | Part XXXVI — Detection Coverage Matrix | `book/chapters/part36-detection-coverage-matrix.md` | T1055.012 |
| part36-02 | Process access to lsass.exe from non-allowlisted signer with suspicious access mask | Part XXXVI — Detection Coverage Matrix | `book/chapters/part36-detection-coverage-matrix.md` | T1003.001 |
| part36-03 | Impossible-travel sign-in correlated with sensitive-role activity within 30 minutes | Part XXXVI — Detection Coverage Matrix | `book/chapters/part36-detection-coverage-matrix.md` | T1078.004 |
| part36-04 | Office application spawning script host/LOLBin child process | Part XXXVI — Detection Coverage Matrix | `book/chapters/part36-detection-coverage-matrix.md` | T1566.001 |
| part36-05 | RDP logon from non-allowlisted source or lateral RDP between non-admin-tier workstations | Part XXXVI — Detection Coverage Matrix | `book/chapters/part36-detection-coverage-matrix.md` | T1021.001 |
| part36-06 | New Run/RunOnce registry value written by process outside deployment allowlist | Part XXXVI — Detection Coverage Matrix | `book/chapters/part36-detection-coverage-matrix.md` | T1547.001 |
| part36-07 | High-entropy subdomain query volume per source host (DNS tunneling) | Part XXXVI — Detection Coverage Matrix | `book/chapters/part36-detection-coverage-matrix.md` | T1071.004 |
| part36-08 | Command-line match on shadow-copy-deletion / boot-recovery-disable utilities | Part XXXVI — Detection Coverage Matrix | `book/chapters/part36-detection-coverage-matrix.md` | T1490 |
| part37-01 | Suspicious Base64-Encoded PowerShell Command (illustrative Sigma, used as worked debt-lifecycle example) | Part XXXVII — Detection Debt | `book/chapters/part37-detection-debt.md` | T1059.001, T1027 |
| part38-01 | LSASS Memory Access by Non-EDR Process (illustrative Sigma-style metadata example) | Part XXXVIII — Detection Governance | `book/chapters/part38-detection-governance.md` | T1003.001 |
| part39-01 | Kerberoasting service-ticket-request tuning (evidence-linked exclusion vs broad SCCM hostname exclusion) | Part XXXIX — Change Management | `book/chapters/part39-change-management.md` | T1558.003 |
| part39-02 | PsExec-style remote service creation lateral movement detection (Detection Autopsy example) | Part XXXIX — Change Management | `book/chapters/part39-change-management.md` | T1569.002 |
| part40-01 | Credential stuffing / password spraying (auth-failure fan-out with success confirmation) | Part XL — SIEM Migration | `book/chapters/part40-siem-migration.md` | T1110.003, T1110.004 |
| part40-02 | PsExec-style lateral movement: remote service creation followed by child process under services.exe | Part XL — SIEM Migration | `book/chapters/part40-siem-migration.md` | T1021.002, T1569.002 |
| part42-01 | Break-Glass Domain Admin Interactive Logon Outside Change Window | Part XLII — Parser Failure | `book/chapters/part42-parser-failure.md` | T1078 |
| part42-02 | Kerberoasting via RC4 Service Ticket Request (Detection Autopsy - revised coalesced-field version) | Part XLII — Parser Failure | `book/chapters/part42-parser-failure.md` | T1558.003 |
| part43-01 | Lateral movement correlation (Sysmon Event ID 3 SMB connection to Sysmon Event ID 1 services.exe-spawned process) - Detection Autopsy example showing clock-drift-induced false negative | Part XLIII — Time | `book/chapters/part43-time.md` | T1021.002, T1078 |
| part44-01 | Log Source Heartbeat Gap (retention/pipeline-loss meta-detection) | Part XLIV — Data Retention | `book/chapters/part44-data-retention.md` | T1070, T1070.001 |
| part45-01 | Reputation Match Corroborated by Process Execution and Network Beacon | Part XLV — Threat Intelligence in Detection | `book/chapters/part45-threat-intelligence-in-detection.md` | T1071, T1105, T1053.005 |
| part46-01 | Suspicious Encoded PowerShell With Network-Capable Decoded Content (Detection Autopsy revision of naive '-enc' flag rule) | Part XLVI — Adversary Tradecraft: A Defender View | `book/chapters/part46-adversary-tradecraft-defender-view.md` | T1059.001, T1027 |
| part47-01 | Unapproved Remote Management Tool Execution | Part XLVII — Ransomware Detection Engineering | `part47-ransomware-detection-engineering.md` | T1219 |
| part47-02 | Suspicious LSASS Memory Access (Potential Credential Dumping) | Part XLVII — Ransomware Detection Engineering | `part47-ransomware-detection-engineering.md` | T1003.001 |
| part47-03 | Rclone Execution or Config Indicative of Mass Exfiltration | Part XLVII — Ransomware Detection Engineering | `part47-ransomware-detection-engineering.md` | T1567, T1048 |
| part47-04 | Volume Shadow Copy or Windows Backup Deletion (Pre-Encryption Indicator) | Part XLVII — Ransomware Detection Engineering | `part47-ransomware-detection-engineering.md` | T1490 |
| part47-05 | Canary File Modification (High-Confidence Active Encryption Indicator) | Part XLVII — Ransomware Detection Engineering | `part47-ransomware-detection-engineering.md` | T1486 |
| part48-01 | Identity Compromise Chain (composite correlation across 6 stages) | Part XLVIII — Identity Compromise Detection Model | `book/chapters/part48-identity-compromise-detection-model.md` | T1110.003, T1621, T1098, T1003.006, T1087.002, T1550.002 |
| part49-01 | Web Exploit-to-Compromise Correlation Chain | Part XLIX — Web Compromise Detection Model | `book/chapters/part49-web-compromise-detection-model.md` | T1190, T1505.003, T1059, T1106, T1219, T1105, T1071, T1573, T1568 |
| part50-01 | AI Compromise Chain Score — weighted cross-stage correlation over session/agent_run_id | Part L — AI System Compromise Detection Model | `book/chapters/part50-ai-system-compromise-detection-model.md` | AML.T0051, AML.T0053, T1213, T1567 |
| appA2-01 | Suspicious LSASS Memory Access (Non-Allowlisted Process, High-Risk Access Mask) | Appendix A2 — MITRE ATT&CK Detection Mapping | `book/appendices/a2-mitre-detection-mapping.md` | T1003, T1003.001 |
| appA3-01 | Suspicious LSASS Access by Non-Standard Process (Sigma + YARA-L cross-language example) | Appendix A3 — Query Language Quick Reference | `book/appendices/a3-query-language-quick-reference.md` | T1003.001 |
| appA4-01 | Kerberoasting via Rare-Actor Distinct-SPN TGS Burst | Appendix A4 — Templates | `book/appendices/a4-templates.md` | T1558.003, T1087.002 |
| appA5-01 | Suspicious Process Access to LSASS Memory (illustrative Sigma, worked QA-checklist example) | Appendix A5 — Matrices and Checklists | `book/appendices/a5-matrices-and-checklists.md` | T1003.001 |
