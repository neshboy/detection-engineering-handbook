# Telemetry Matrix

One deduplicated row per distinct telemetry source cited across the 55 completed units, with the parts that rely on it. Sources are normalized where different units named the same underlying channel with slightly different phrasing (e.g., "Sysmon Event ID 10 / ProcessAccess" vs. "Sysmon Event ID 10 (ProcessAccess)"); Windows Security Event Log sub-events are grouped by functional area but individually noted since each is a genuinely distinct signal.

| Telemetry Source | Relied On By |
|---|---|
| Sysmon Event ID 1 (Process Create) | Parts 2, 3, 8, 9, 10, 11, 23, 25, 26, 27, 29, 30, 40, 44, 45, 47; Appendix A1, A4, A5 |
| Sysmon Event ID 3 (Network Connection) | Parts 9, 10, 29, 30, 47 |
| Sysmon Event ID 6 (Driver Loaded) | Parts 9, 11; Appendix A1 |
| Sysmon Event ID 7 (Image Loaded) | Parts 9, 11; Appendix A1 |
| Sysmon Event ID 8 (CreateRemoteThread) | Parts 9, 11; Appendix A1, A4 |
| Sysmon Event ID 10 (ProcessAccess) | Parts 3, 9, 11, 23, 24, 25, 26, 27, 28, 29, 41; Appendix A1, A4, A5 |
| Sysmon Event ID 11 (FileCreate) | Parts 3, 9, 11, 40, 45; Appendix A1 |
| Sysmon Event ID 12/13 (RegistryEvent) | Part 9, 11; Appendix A1, A4 |
| Sysmon Event ID 15 (FileCreateStreamHash) | Part 9; Appendix A1 |
| Sysmon Event ID 16 (config state changed) | Part 9 |
| Sysmon Event ID 17/18 (PipeEvent) | Part 9; Appendix A1 |
| Sysmon Event ID 22 (DNSEvent) | Part 9; Appendix A1 |
| Sysmon Event ID 23 (FileDelete) | Part 9, 11; Appendix A1 |
| Sysmon config XML (versioned, git-tracked) | Part 9 |
| Sysmon for Linux | Part 16 |
| Windows Security Event Log — logon events (4624, 4625, 4648, 4672) | Parts 8, 12, 25, 26, 30, 41; Appendix A2, A4 |
| Windows Security Event Log — process creation (4688) | Parts 2, 3, 9, 11, 30, 40, 41; Appendix A1, A4 |
| Windows Security Event Log — Kerberos events (4768, 4769, 4771, 4776) | Parts 8, 13, 41; Appendix A2, A4 |
| Windows Security Event Log — account/group management (4720, 4724, 4728, 4732, 4735, 4738, 4756, 4697, 4698) | Parts 8, 11, 13, 46; Appendix A4 |
| Windows Security Event Log — directory-service access (4662) | Parts 13, 46 |
| Windows Security Event Log — audit-log-cleared (1102) | Parts 8, 11, 45; Appendix A4 |
| Windows System Event Log — Service Control Manager (7036, 7040, 7045) | Parts 8, 9, 11 |
| Windows Application Event Log | Appendix A1 |
| Event Tracing for Windows (ETW) | Part 8; Appendix A1 |
| Windows audit policy configuration (auditpol / Advanced Audit Policy GPO) | Part 8 |
| Windows Event Forwarding (WEF) / Winlogbeat / forwarding agents | Parts 2, 8 |
| PowerShell Module Logging (Event ID 4103) / Script Block Logging (Event ID 4104) | Parts 2, 3, 10, 40; Appendix A1, A4 |
| AMSI-correlated scanning-engine log (Defender/EDR verdict) | Parts 10; Appendix A1 |
| Prefetch / Amcache secondary artifacts | Part 2 |
| Microsoft Defender for Endpoint DeviceProcessEvents (Advanced Hunting) | Parts 2, 11, 25, 45 |
| Microsoft Defender for Endpoint DeviceFileEvents | Parts 25, 45 |
| Microsoft Defender for Endpoint DeviceLogonEvents | Part 25 |
| Microsoft Defender for Endpoint DeviceNetworkEvents | Parts 14, 25, 47 |
| Microsoft Defender for Endpoint DeviceEvents (OpenProcessApiCall) | Part 25; Appendix A5 |
| Sentinel/Log Analytics SecurityEvent / Event table (via AMA or legacy agent) | Part 25 |
| Sentinel Syslog table (via AMA syslog connector) | Part 25 |
| Linux sshd authentication log / auth.log / journald | Parts 1, 3, 7, 12, 24, 26, 31, 34, 37, 38, 40; Appendix A1, A2, A4, A7 |
| Linux btmp / wtmp (via `lastb`/`last`) | Parts 1, 3, 7, 12, 24, 26, 34, 37, 38, 40, 43; Appendix A1, A4, A7 |
| Linux sudo invocation log (journalctl / auth.log / syslog) | Parts 3, 5, 22, 31, 34, 38, 39, 43, 46; Appendix A1, A7 |
| Linux auditd (execve records, watch rules, CONFIG_CHANGE) | Parts 3, 11; Appendix A1 |
| systemd / journalctl unit-state transitions | Parts 3, 11, 34, 39, 43, 45; Appendix A1 |
| syslog CRON execution lines | Part 11 |
| Identity telemetry — on-prem AD + cloud IdP sign-in logs (general) | Part 3 |
| Entra ID (Azure AD) SigninLogs | Parts 12, 18, 46; Appendix A2 |
| Entra ID (Azure AD) AuditLogs | Parts 18, 46; Appendix A2 |
| Okta System Log | Parts 12, 18; Appendix A2 |
| Ping Identity log API | Part 12 |
| Duo admin API | Part 12 |
| Microsoft 365 Unified Audit Log (mailbox audit, inbox rules, forwarding) | Parts 17, 18 |
| Google Workspace admin console audit logs | Part 18 |
| OAuth application-consent audit events | Parts 17, 18 |
| Graph API directory-read audit events | Part 46 |
| HybridIdentityMap (on-prem SID/UPN ↔ cloud UPN entity-resolution join table) | Part 46 |
| Mail-flow / secure email gateway (SEG) logs | Part 17 |
| Message headers (SPF/DKIM/DMARC, Received chains, From/Reply-To) | Parts 17; Appendix A2 |
| Pi-hole / dnsmasq DNS query log | Parts 4, 9, 10, 15, 32, 35, 38, 39, 40; Appendix A2 |
| Sentinel DnsEvents (Azure Monitor DNS analytics) | Part 15 |
| Elastic dns.question.entropy / dns.question.registered_domain fields | Part 15 |
| Splunk normalized DNS index | Part 15 |
| DNS record types (A/AAAA/CNAME/MX/TXT/NS/SOA/PTR/SRV/NULL/CAA) | Appendix A2 |
| Domain-registration-age and threat-intelligence enrichment feeds | Part 15 |
| DHCP / network-inventory data (source-IP-to-device resolution) | Parts 1, 15, 33 |
| Proxy / SWG (secure web gateway) logs, TLS inspection | Parts 4; Appendix A2 |
| Firewall / NGFW session and connection logs | Parts 4, 14 |
| NDR / Zeek (conn.log, dns.log, http.log, ssl.log, files.log) | Parts 4, 6, 14; Appendix A2 |
| NetFlow / IPFIX flow records | Parts 4, 14; Appendix A2 |
| Suricata inline IDS (plaintext HTTP listener) | Part 14 |
| Splunk Network_Traffic data model (tstats) | Part 14 |
| Tor Project exit-node reputation list / commercial VPN IP reputation feeds | Part 14 |
| Apache / Nginx access logs (combined format) | Parts 4, 16; Appendix A2, A4 |
| Web application firewall (WAF) logs | Parts 16; Appendix A2, A4 |
| API gateway logs | Part 16 |
| Application logs (parsed request parameters) | Part 16 |
| Database telemetry — native audit logging | Parts 4 |
| Database activity monitoring (DAM) | Part 4 |
| AWS CloudTrail (management events) | Parts 4, 7, 11, 19; Appendix A3 |
| AWS CloudTrail (data events, S3/Lambda/DynamoDB) | Part 19 |
| Azure Activity Log (subscription-level control plane) | Parts 11, 19; Appendix A3 |
| Azure per-resource diagnostic settings (data-plane) | Part 19 |
| GCP Cloud Audit Logs — Admin Activity | Parts 11, 19; Appendix A3 |
| GCP Cloud Audit Logs — Data Access | Part 19 |
| Cloud provider Instance Metadata Service (IMDS, 169.254.169.254) network logs | Part 11 |
| AI Gateway audit schema (AiAuditEvents / AIGatewayEvents — prompt, retrieval, tool_call, output events) | Parts 20, 21, 48 |
| AIToolCallEvents / MCP connector-and-tool-call telemetry | Parts 20, 21, 48 |
| ai_ingestion file-scan index (extracted rendered vs. hidden document text) | Part 21 |
| rag_ingestion / kb_ingest index (per-document contributor/source identity) | Part 21 |
| ai_api_gateway api_auth index (API key auth log) | Part 21 |
| AIUsageEvents / AIUsageBaseline (token/cost usage) | Part 21 |
| Code-agent sandbox network-egress log | Part 21 |
| Custom AI systems audit-trail schema per Part 20 (cloud/AI cross-reference) | Appendix A3 |
| Receiving sensitive-system's own audit log (database/mailbox/CRM record-level) | Part 48 (named as generally unjoined — a documented gap) |
| Model-provider/agent-framework reasoning trace | Part 48 (named as generally unavailable in current tooling — a documented gap) |
| WinRM operational log | Part 41 (named as an absent/NO VISIBILITY example) |
| Egress/TLS proxy log | Part 41 (named as an absent/NO VISIBILITY example) |
| EDR behavioral / process-access telemetry (generic, vendor-neutral) | Parts 3, 8, 11, 13, 41, 44, 47 |
| EDR agent-health / tamper telemetry | Part 44 |
| CT100 'pihole' — Pi-hole/dnsmasq DNS query log (real evidence file) | Parts 4, 9, 10, 15, 32, 35, 38, 39, 40; Appendix A2 |
| CT100 'pihole' — sudo invocation log (real evidence file) | Parts 3, 22, 34, 39, 46; Appendix A1, A7 |
| CT104 'vulnscan' — sudo invocation log (real evidence file) | Parts 3, 22, 31, 34, 39, 46; Appendix A1, A7 |
| CT104 'vulnscan' — SSH failed-login btmp capture (real evidence file) | Parts 1, 3, 7, 12, 24, 26, 30, 33, 34, 37, 40, 43; Appendix A1, A4, A7 |
| CT104 'vulnscan' — systemd/journalctl service-state changes (real evidence file) | Parts 3, 11, 34, 39, 43, 45; Appendix A1 |
| CT104 vulnerability-scanner platform scan-findings log | Part 35 |
| CT103 honeynet — ssh_events table | Parts 12, 21, 28, 30, 32, 35, 36, 39, 41; Appendix A6, A7 |
| CT103 honeynet — http_events table | Parts 4, 6, 16, 21, 26, 32, 35, 36, 39, 41 |
| CT103 honeynet — attack_sessions correlation table | Parts 1, 3, 4, 14, 16, 30, 32, 33, 35, 36, 39, 41, 44, 45, 47; Appendix A4, A6 |
| CT103 honeynet — network_events table | Part 41 |
| CT108 'honeynet-edge' — sshd/systemd journal (legacy protocol/algorithm scan) | Parts 1, 3, 35, 39, 43, 44; Appendix A1 |
| CT113 'aeronex-legacy' — Apache access.log (scanner-probe capture) | Parts 4, 16, 21, 35, 44 |
| Coverage-matrix database / ticketing backend (technique_id, tier, last_validated, owner) | Part 41 |
| ExceptionRegistry (Sentinel workspace watchlist) | Part 42 |
| CanaryEvents_CL (synthetic scheduled-event table) | Part 42 |
| Disposition data (TP/BP/FP/UTD outcomes underlying all quality metrics) | Part 42 |
| Adversary Emulation / Atomic Test results | Part 42 |
| Threat-intelligence indicator feeds (Sentinel ThreatIntelligenceIndicator, Splunk TI lookups, STIX 2.1 confidence) | Part 32 |
| Sentinel CommonSecurityLog | Part 32 |
