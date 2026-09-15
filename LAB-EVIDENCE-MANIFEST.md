# Lab Evidence Manifest

## Captured Evidence Files (`release-v2/lab/evidence/`)

The 11 real evidence files captured from the author's home lab (Proxmox hosts CT100/CT103/CT104/CT108/CT113), used throughout the book as REAL LAB EXAMPLE figures and Detection Test fixtures.

| File | Telemetry Type | Source Host | Classification |
|---|---|---|---|
| ct100-pihole-dns-query-log.txt | Pi-hole/dnsmasq DNS query log | CT100 'pihole' | REAL |
| ct100-pihole-sudo-invocations.txt | Linux sudo invocation log (auth.log) | CT100 'pihole' | REAL |
| ct103-honeynet-correlated-attack-sessions.txt | Honeynet attack_sessions correlation table (MITRE-tagged, status pipeline) | CT103 honeynet (hp-platform) | REAL |
| ct103-honeynet-http-events-exploit-probes.txt | Honeynet HTTP decoy listener events (exploit-path probes) | CT103 honeynet (hp-platform) | REAL |
| ct103-honeynet-ssh-honeypot-credentials.txt | Honeynet SSH decoy credential-attempt log (ssh_events table) | CT103 honeynet (hp-platform) | REAL |
| ct104-vulnscan-scan-findings-sample.txt | Vulnerability-scanner platform scan-findings log | CT104 'vulnscan' | REAL |
| ct104-vulnscan-ssh-failed-logins-btmp.txt | SSH failed-login capture via `lastb` against /var/log/btmp | CT104 'vulnscan' | REAL |
| ct104-vulnscan-sudo-invocations.txt | Linux sudo invocation log (journalctl/auth.log) | CT104 'vulnscan' | REAL |
| ct104-vulnscan-web-systemd-state-changes.txt | systemd unit state-transition journal (vulnscan-web.service) | CT104 'vulnscan' | REAL |
| ct108-honeynet-edge-ssh-protocol-scan.txt | sshd/systemd journal — legacy SSH protocol/algorithm negotiation failures | CT108 'honeynet-edge' | REAL |
| ct113-aeronex-legacy-apache-scanner-probes.txt | Apache access.log — scanner-probe capture (aeronex-legacy decoy) | CT113 'aeronex-legacy' | REAL |

**Total: 11 real evidence files. 0 CONTROLLED LAB EXAMPLE files currently captured** (every CONTROLLED LAB EXAMPLE figure/screenshot in the book is explicitly marked pending — see below — because the home lab is Linux/network/honeynet-only with no Windows host, AD domain, cloud tenant, or commercial SIEM/EDR/DAM/WAF product currently deployed).

## Screenshot Placeholders (status: pending capture)

35 screenshot placeholders are named across the book's 55 units. None has a captured image on disk as of 2026-09-15; each is explicitly marked `[FIGURE PENDING]` in its source chapter rather than fabricated.

| Description | Part | Target Evidence Class | Status |
|---|---|---|---|
| Windows Event Viewer capture of Event ID 4104 (Creating Scriptblock text) decoded script block, encoded-PowerShell worked example | Part 2 | CONTROLLED LAB EXAMPLE | pending capture |
| Cloud-console UI screenshot of the data-event/data-plane logging opt-in screen (AWS CloudTrail S3 data-events selector or Azure diagnostic-settings pane) | Part 4 | OFFICIAL REFERENCE | pending capture |
| WAF/CDN vendor console screenshot showing a blocked request's matched rule ID, anomaly/risk score, bot-classification verdict | Part 4 | OFFICIAL REFERENCE | pending capture |
| DAM (database activity monitoring) vendor console screenshot showing a captured statement resolved to end-user identity/session context | Part 4 | OFFICIAL REFERENCE | pending capture |
| Parser-health dashboard: per-field null-rate trend lines showing a visible step-change at a field-mapping shift | Part 5 | CONTROLLED LAB EXAMPLE | pending capture |
| Side-by-side of `auditpol /get /category:*` output vs. the Advanced Audit Policy GPO console for the same host (subcategory drift) | Part 8 | CONTROLLED LAB EXAMPLE | pending capture |
| Windows Event Viewer 4688 entry with the command-line GPO disabled vs. enabled, showing the missing CommandLine field | Part 8 | CONTROLLED LAB EXAMPLE | pending capture |
| Windows Event Viewer/SIEM view of a linked Sysmon Event ID 11 / Event ID 23 pair joined via ProcessGuid to the originating Event ID 1 | Part 9 | CONTROLLED LAB EXAMPLE | pending capture |
| Windows Event Viewer capture of Event ID 4104 for a download-cradle script block plus accompanying process-creation/network-connection events | Part 10 | CONTROLLED LAB EXAMPLE | pending capture |
| Sysmon Event ID 10 (Process Access) entry showing TargetImage lsass.exe and a memory-read GrantedAccess value from a lab-run credential-dumping tool | Part 11 | CONTROLLED LAB EXAMPLE | pending capture |
| Entra ID sign-in log detail blade showing the §1 field layout (FIG-12-04) | Part 12 | OFFICIAL REFERENCE | pending capture |
| Captured Event ID 4769 entry showing a service ticket with no corresponding upstream 4768 in the same logon session | Part 13 | CONTROLLED LAB EXAMPLE | pending capture |
| Captured Event ID 4662 entry showing the DS-Replication-Get-Changes-All GUID requested by a non-domain-controller principal | Part 13 | CONTROLLED LAB EXAMPLE | pending capture |
| Packet-capture/NDR screenshot of SMB session fan-out from one compromised workstation to multiple peer hosts | Part 14 | CONTROLLED LAB EXAMPLE | pending capture |
| Connection-graph visualization contrasting normal RDP jump-host star pattern vs. anomalous peer-to-peer lateral-movement pattern | Part 14 | CONTROLLED LAB EXAMPLE | pending capture |
| Captured mailbox-audit log entry showing New-InboxRule with an external ForwardTo and a DeleteMessage flag, plus preceding sign-in event | Part 17 | CONTROLLED LAB EXAMPLE | pending capture |
| Vendor-console screenshot of an OAuth application-consent prompt showing exact permission-scope disclosure language for a Mail.ReadWrite request | Part 17 | OFFICIAL REFERENCE | pending capture |
| Entra ID enterprise-application permissions blade showing requested-scope detail at consent time | Part 18 | OFFICIAL REFERENCE | pending capture |
| CloudTrail console or SIEM-rendered event view of the PutBucketPolicy call from the §3.1 Detection Test | Part 19 | CONTROLLED LAB EXAMPLE | pending capture |
| AI ingestion gateway file-scan output showing extracted hidden text and an injection-keyword flag from a test document | Part 21 | CONTROLLED LAB EXAMPLE | pending capture |
| AI API usage dashboard showing a request-rate spike from one API key across 4+ source ASNs within one hour | Part 21 | CONTROLLED LAB EXAMPLE | pending capture |
| DET-25-01 query result grid from the Defender Advanced Hunting portal against an OpenProcessApiCall/lsass.exe match | Part 25 | REAL/CONTROLLED LAB EXAMPLE | pending capture |
| Splunk search-results table showing DET-26-02's hardened stats query run against real ingested sshd syslog data | Part 26 | REAL LAB EXAMPLE | pending capture |
| QRadar Offenses tab showing a fired "R: Suspicious LSASS Access — Unapproved Process" Offense, magnitude score, contributing events | Part 27 | CONTROLLED LAB EXAMPLE | pending capture |
| Google SecOps detection/case queue entry showing DET-28-01's outcome fields (risk_score, distinct_usernames_tried) | Part 28 | CONTROLLED LAB EXAMPLE | pending capture |
| Kibana Discover screenshot showing HUNT-29-01's ES\|QL query results against honeynet SSH decoy telemetry | Part 29 | CONTROLLED LAB EXAMPLE | pending capture |
| SIEM correlation-rule alert view showing all five stages of the DET-30-01 chain fired against one real entity | Part 30 | CONTROLLED LAB EXAMPLE | pending capture |
| Per-entity baseline scorecard (observed value, learned baseline range, deviation score, model staleness) | Part 31 | REAL LAB EXAMPLE | pending capture |
| Honeynet platform's own analyst-facing session view for a possible_success-status session | Part 33 | REAL LAB EXAMPLE | pending capture |
| SIEM hunting-workbench timeline visualization for the SSH success / flagged sudo session / systemd state-change chain | Part 34 | CONTROLLED LAB EXAMPLE | pending capture |
| EDR or Sysmon tamper-protection alert firing after a controlled, lab-safe attempt to stop the sensor service | Part 44 | CONTROLLED LAB EXAMPLE | pending capture |
| Captured Sysmon Event ID 1 / Defender DeviceProcessEvents entry for `vssadmin.exe delete shadows /all /quiet` | Part 45 | CONTROLLED LAB EXAMPLE | pending capture |
| Defender DeviceFileEvents query-results capture showing FileEventCount/DistinctFolders crossing DET-45-04's thresholds | Part 45 | CONTROLLED LAB EXAMPLE | pending capture |

## Reconciliation notes

- The 11 captured evidence files above are the *only* real evidence on disk; every REAL LAB EXAMPLE figure in VISUAL-INVENTORY.md traces back to one of these 11 files (several files are cited by more than one part — see REFERENCES.md's "Internal — Lab Evidence Files" section for the per-file citation list).
- Part 46's Figure FIG-46-04 is tracked as a pending figure within VISUAL-INVENTORY.md's figure table (not duplicated here) since its source unit filed it under `figures`, not `screenshot_placeholders`.
- No screenshot placeholder in this manifest has ever been backed by a fabricated or invented vendor UI; every one is honestly labeled `[FIGURE PENDING]` with its target evidence class stated, consistent with the book-wide rule established in STYLE-GUIDE.md §9.
