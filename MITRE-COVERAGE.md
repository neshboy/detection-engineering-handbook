# MITRE ATT&CK Coverage

One row per distinct MITRE ATT&CK technique (or tactic, marked `TA####`) referenced anywhere across the 55 completed units, with every part that covers it. Compiled from each unit's `mitre_techniques` field plus detection-level MITRE tags.

| Technique | Name | Covered By |
|---|---|---|
| T1003 | OS Credential Dumping (general) | Parts 44, 45 |
| T1003.001 | OS Credential Dumping: LSASS Memory | Parts 3, 9, 11, 23, 24, 25, 26, 27, 28, 29, 41, 45; Appendix A1, A5 |
| T1003.002 | OS Credential Dumping: Security Account Manager | Part 11 |
| T1003.006 | OS Credential Dumping: DCSync | Parts 13, 46 |
| T1003.008 | OS Credential Dumping: /etc/passwd and /etc/shadow | Part 11 |
| T1005 | Data from Local System | Parts 4, 16, 44 |
| T1008 | Fallback Channels | Part 14 |
| T1018 | Remote System Discovery | Part 45 |
| T1021 | Remote Services (general) | Parts 44, 45 |
| T1021.001 | Remote Services: RDP | Parts 8, 14, 41, 45; Appendix A4 |
| T1021.002 | Remote Services: SMB/Windows Admin Shares | Parts 8, 14, 45 |
| T1021.004 | Remote Services: SSH | Part 34; Appendix A4 |
| T1021.006 | Remote Services: Windows Remote Management | Parts 41, 45 |
| T1027 | Obfuscated Files or Information | Parts 2, 10; Appendix A1, A4 |
| T1027.010 | Obfuscated Files or Information: Command Obfuscation | Parts 10; Appendix A1 |
| T1030 | Data Transfer Size Limits | Part 14 |
| T1036 | Masquerading (general) | Part 44 |
| T1036.001 | Masquerading: Match Legitimate Name or Location | Part 40 |
| T1036.005 | Masquerading: Match Legitimate Name or Location (binary) | Appendix A5 |
| T1037.004 | Boot or Logon Initialization Scripts: RC Scripts | Part 11 |
| T1041 | Exfiltration Over C2 Channel | Parts 14, 44, 47 |
| T1046 | Network Service Discovery | Parts 1, 3, 4, 14, 32, 33, 35, 41, 44; Appendix A6 |
| T1048 | Exfiltration Over Alternative Protocol | Parts 20, 44 |
| T1048.003 | Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol | Parts 14, 15, 47 |
| T1053 | Scheduled Task/Job (general) | Part 44 |
| T1053.003 | Scheduled Task/Job: Cron | Part 11 |
| T1053.005 | Scheduled Task/Job: Scheduled Task | Parts 8, 11; Appendix A1, A4 |
| T1055 | Process Injection | Parts 3, 9, 11; Appendix A1, A4 |
| T1055.004 | Process Injection: Asynchronous Procedure Call | Part 11 |
| T1055.012 | Process Injection: Process Hollowing | Parts 11, 41 |
| T1059 | Command and Scripting Interpreter (general) | Parts 16, 21, 28, 44; Appendix A1 |
| T1059.001 | Command and Scripting Interpreter: PowerShell | Parts 2, 11, 40; Appendix A4 |
| T1059.003 | Command and Scripting Interpreter: Windows Command Shell | Part 16; Appendix A4 |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | Parts 11, 16 |
| T1068 | Exploitation for Privilege Escalation | Part 44 |
| T1069.001 | Permission Groups Discovery: Local Groups | Parts 8; Appendix A1 |
| T1069.002 | Permission Groups Discovery: Domain Groups | Parts 13, 46 |
| T1069.003 | Permission Groups Discovery: Cloud Groups | Part 19 |
| T1070 | Indicator Removal (general) | Part 44 |
| T1070.001 | Indicator Removal: Clear Windows Event Logs | Parts 8, 11; Appendix A1, A4 |
| T1070.002 | Indicator Removal: Clear Linux or Mac System Logs | Parts 3, 11 |
| T1070.004 | Indicator Removal: File Deletion | Parts 9; Appendix A1 |
| T1070.006 | Indicator Removal: Timestomp | Part 7 |
| T1071 | Application Layer Protocol (general) | Parts 9, 28, 40; Appendix A1 |
| T1071.001 | Application Layer Protocol: Web Protocols | Parts 4, 14, 47 |
| T1071.004 | Application Layer Protocol: DNS | Parts 9, 10, 15, 28, 39, 40, 41, 47; Appendix A1, A4 |
| T1082 | System Information Discovery | Part 45 |
| T1083 | File and Directory Discovery | Parts 1, 3, 4, 14, 32, 33, 35, 41, 44; Appendix A4, A6 |
| T1087 | Account Discovery (general) | Parts 44, 45; Appendix A4 |
| T1087.002 | Account Discovery: Domain Account | Parts 13, 46 |
| T1087.004 | Account Discovery: Cloud Account | Part 46 |
| T1090 | Proxy (general) | Parts 14, 44 |
| T1090.003 | Proxy: Multi-hop Proxy | Part 14 |
| T1098 | Account Manipulation | Parts 8, 13, 44, 46; Appendix A1, A4 |
| T1098.001 | Account Manipulation: Additional Cloud Credentials | Parts 19, 41 |
| T1098.003 | Account Manipulation: Additional Cloud Roles | Part 19 |
| T1105 | Ingress Tool Transfer | Parts 9, 10, 11, 47; Appendix A1, A4 |
| T1110 | Brute Force (general) | Parts 1, 3, 12, 14, 26, 28, 30, 40, 44, 45; Appendix A7 |
| T1110.001 | Brute Force: Password Guessing | Parts 1, 3, 12, 24, 25, 26, 28, 29, 31, 35, 36, 37, 38, 39, 40, 43; Appendix A4, A7 |
| T1110.003 | Brute Force: Password Spraying | Parts 12, 37, 38, 41, 43, 45; Appendix A4, A7 |
| T1110.004 | Brute Force: Credential Stuffing | Parts 3, 12, 16, 28, 29, 39, 45; Appendix A7 |
| T1114 | Email Collection (general) | Parts 44, 46 |
| T1114.003 | Email Collection: Email Forwarding Rule | Part 17 |
| T1127.001 | Trusted Developer Utilities Proxy Execution | Part 11 |
| T1133 | External Remote Services | Parts 44, 45; Appendix A4 |
| T1135 | Network Share Discovery | Part 11 |
| T1136 | Create Account (general) | Parts 8; Appendix A1, A4 |
| T1136.001 | Create Account: Local Account | Part 31; Appendix A1 |
| T1136.002 | Create Account: Domain Account | Appendix A1 |
| T1140 | Deobfuscate/Decode Files or Information | Part 11 |
| T1190 | Exploit Public-Facing Application | Parts 1, 3, 4, 6, 16, 32, 33, 35, 36, 41, 44, 45; Appendix A4, A6 |
| T1197 | BITS Jobs | Parts 11, 41 |
| T1199 | Trusted Relationship | Parts 18, 46 |
| T1201 | Password Policy Discovery | Part 13 |
| T1204 | User Execution (general) | Part 44 |
| T1204.002 | User Execution: Malicious File | Parts 11, 21; Appendix A4 |
| T1213 | Data from Information Repositories | Parts 4, 44, 46 |
| T1218 | System Binary Proxy Execution (general) | Parts 11, 40 |
| T1218.005 | System Binary Proxy Execution: Mshta | Part 11 |
| T1218.010 | System Binary Proxy Execution: Regsvr32 | Part 11 |
| T1218.011 | System Binary Proxy Execution: Rundll32 | Part 11; Appendix A4 |
| T1482 | Domain Trust Discovery | Part 13 |
| T1485 | Data Destruction | Part 44 |
| T1486 | Data Encrypted for Impact | Parts 44, 45; Appendix A4 |
| T1489 | Service Stop | Parts 11, 44, 45 |
| T1490 | Inhibit System Recovery | Parts 11, 44, 45 |
| T1496 | Resource Hijacking | Part 21 |
| T1498 | Network Denial of Service | Part 44 |
| T1505.003 | Server Software Component: Web Shell | Parts 16, 40, 47 |
| T1528 | Steal Application Access Token | Parts 17, 18, 46 |
| T1530 | Data from Cloud Storage Object | Parts 19, 46 |
| T1537 | Transfer Data to Cloud Account | Part 19 |
| T1539 | Steal Web Session Cookie | Part 16 |
| T1543 | Create or Modify System Process (general) | Part 44 |
| T1543.002 | Create or Modify System Process: Systemd Service | Part 11 |
| T1543.003 | Create or Modify System Process: Windows Service | Parts 8, 11; Appendix A1 |
| T1546.003 | Event Triggered Execution: WMI Event Subscription | Part 9 |
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys | Parts 9, 11; Appendix A1, A4 |
| T1548 | Abuse Elevation Control Mechanism (general) | Part 44 |
| T1548.001 | Abuse Elevation Control Mechanism: Setuid/Setgid | Parts 5, 11 |
| T1548.002 | Abuse Elevation Control Mechanism: Bypass User Account Control | Appendix A4 |
| T1548.003 | Abuse Elevation Control Mechanism: Sudo and Sudo Caching | Parts 3, 5, 22, 34, 38, 39, 46 |
| T1548.005 | Abuse Elevation Control Mechanism: Temporary Elevated Cloud Access | Part 19 |
| T1550.001 | Use Alternate Authentication Material: Application Access Token | Part 18 |
| T1550.002 | Use Alternate Authentication Material: Pass the Hash | Parts 13, 30, 46; Appendix A4 |
| T1550.003 | Use Alternate Authentication Material: Pass the Ticket | Parts 13, 46 |
| T1550.004 | Use Alternate Authentication Material: Web Session Cookie | Part 18 |
| T1552 | Unsecured Credentials (general) | Part 45 |
| T1552.004 | Unsecured Credentials: Private Keys | Part 11 |
| T1552.005 | Unsecured Credentials: Cloud Instance Metadata API | Parts 11, 16, 19 |
| T1558 | Steal or Forge Kerberos Tickets (general) | Parts 44, 45 |
| T1558.001 | Steal or Forge Kerberos Tickets: Golden Ticket | Part 13 |
| T1558.002 | Steal or Forge Kerberos Tickets: Silver Ticket | Part 13 |
| T1558.003 | Steal or Forge Kerberos Tickets: Kerberoasting | Parts 8, 13, 41, 45; Appendix A4 |
| T1558.004 | Steal or Forge Kerberos Tickets: AS-REP Roasting | Parts 8, 13; Appendix A4 |
| T1562 | Impair Defenses (general) | Parts 44, 45 |
| T1562.001 | Impair Defenses: Disable or Modify Tools | Parts 3, 9, 10, 11, 45; Appendix A1, A4 |
| T1562.002 | Impair Defenses: Disable Windows Event Logging | Parts 8; Appendix A1 |
| T1562.006 | Impair Defenses: Indicator Blocking | Part 11 |
| T1562.007 | Impair Defenses: Disable or Modify Cloud Firewall | Part 19 |
| T1562.008 | Impair Defenses: Disable Cloud Logs | Part 19 |
| T1564.004 | Hide Artifacts: NTFS File Attributes | Parts 9; Appendix A1 |
| T1565.001 | Data Manipulation: Stored Data Manipulation | Part 21 |
| T1566 | Phishing (general) | Parts 17, 44, 45 |
| T1566.001 | Phishing: Spearphishing Attachment | Parts 11, 45; Appendix A4 |
| T1566.002 | Phishing: Spearphishing Link | Part 17; Appendix A4 |
| T1567 | Exfiltration Over Web Service | Parts 21, 44, 48 |
| T1567.002 | Exfiltration to Cloud Storage | Parts 4, 41 |
| T1568.002 | Dynamic Resolution: Domain Generation Algorithms | Part 15 |
| T1570 | Lateral Tool Transfer | Part 45 |
| T1571 | Non-Standard Port | Part 4 |
| T1572 | Protocol Tunneling | Part 44 |
| T1573 | Encrypted Channel | Part 14 |
| T1574.002 | Hijack Execution Flow: DLL Side-Loading | Parts 9; Appendix A1 |
| T1574.006 | Hijack Execution Flow: Dynamic Linker Hijacking | Part 11 |
| T1580 | Cloud Infrastructure Discovery | Part 19 |
| T1583.001 | Acquire Infrastructure: Domains | Part 40 |
| T1595 | Active Scanning (general) | Parts 1, 3, 4, 14, 32, 33, 35, 40, 41, 44; Appendix A4, A6 |
| T1595.001 | Active Scanning: Scanning IP Blocks | Part 14 |
| T1595.002 | Active Scanning: Vulnerability Scanning | Parts 3, 14, 39, 40 |
| T1595.003 | Active Scanning: Wordlist Scanning | Parts 4, 16 |
| T1621 | Multi-Factor Authentication Request Generation | Part 12 |
| T1656 | Impersonation | Part 17 |
| T1078 | Valid Accounts (general) | Parts 8, 12, 13, 18, 30, 31, 34, 40, 44, 46, 48; Appendix A4 |
| T1078.002 | Valid Accounts: Domain Accounts | Parts 13, 46 |
| T1078.003 | Valid Accounts: Local Accounts | Parts 31, 34, 46 |
| T1078.004 | Valid Accounts: Cloud Accounts | Parts 12, 18, 19, 40, 41; Appendix A3 |
| TA0002 | Execution (tactic) | Parts 2, 11 |
| TA0003 | Persistence (tactic) | Part 11 |
| TA0004 | Privilege Escalation (tactic) | Part 3 |
| TA0005 | Defense Evasion (tactic) | Parts 2, 3, 11 |
| TA0006 | Credential Access (tactic) | Parts 11, 28 |
| TA0043 | Reconnaissance (tactic) | Parts 3, 35 |
