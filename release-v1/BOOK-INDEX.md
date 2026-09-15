# The Detection Engineering Handbook

**Threat Hunting, Telemetry, Adversary Behaviour and Detection at Scale**

Status: DRAFT — first breadth pass in progress. See `BUILD-MANIFEST.md` for build status per part.

## How this book is organized

Every part follows the same underlying chain:

Adversary Behaviour → OS/Application Activity → Artifact → Telemetry → Collector → Parser → Schema → Detection Logic → Correlation → Alert → Investigation → Threat Hunt → Validation → Tuning → Detection Improvement

Where useful, content is layered by audience:

- `[CONCEPT]` — plain explanation
- `[ANALYST]` — what an investigator looks for
- `[DETECTION ENGINEER]` — how the detection is built
- `[THREAT HUNTER]` — how to hunt beyond the alert
- `[ENGINEERING]` — telemetry, schema, pipeline detail
- `[MANAGEMENT]` — coverage, cost, governance, risk

Recurring features: **Detection Autopsy** (a weak rule dissected), **Hunter's Note** (a short practitioner observation), **Engineering Reality** (a pipeline/data-quality truth), **SOC Management View** (cost/coverage/governance).

## Part index

| # | Part | File |
|---|------|------|
| I | Detection Engineering Foundations | `book/chapters/part01-detection-engineering-foundations.md` |
| II | How Attacks Become Data | `book/chapters/part02-how-attacks-become-data.md` |
| III | Telemetry Engineering | `book/chapters/part03-telemetry-engineering.md` |
| IV | Windows Detection Engineering | `book/chapters/part04-windows-detection-engineering.md` |
| V | Sysmon as Detection Telemetry | `book/chapters/part05-sysmon-detection-telemetry.md` |
| VI | Process Tree Detection | `book/chapters/part06-process-tree-detection.md` |
| VII | Command Line Detection | `book/chapters/part07-command-line-detection.md` |
| VIII | Identity Detection Engineering | `book/chapters/part08-identity-detection-engineering.md` |
| IX | Network Detection Engineering | `book/chapters/part09-network-detection-engineering.md` |
| X | DNS Detection | `book/chapters/part10-dns-detection.md` |
| XI | Web Detection Engineering | `book/chapters/part11-web-detection-engineering.md` |
| XII | Email Detection Engineering | `book/chapters/part12-email-detection-engineering.md` |
| XIII | Cloud Detection Engineering | `book/chapters/part13-cloud-detection-engineering.md` |
| XIV | Endpoint Detection Engineering | `book/chapters/part14-endpoint-detection-engineering.md` |
| XV | AI Security Detection Engineering | `book/chapters/part15-ai-security-detection-engineering.md` |
| XVI | Detection as Code | `book/chapters/part16-detection-as-code.md` |
| XVII | Sigma | `book/chapters/part17-sigma.md` |
| XVIII | YARA-L / Google SecOps | `book/chapters/part18-yaral-google-secops.md` |
| XIX | KQL | `book/chapters/part19-kql.md` |
| XX | Splunk SPL | `book/chapters/part20-splunk-spl.md` |
| XXI | QRadar AQL | `book/chapters/part21-qradar-aql.md` |
| XXII | Elastic | `book/chapters/part22-elastic.md` |
| XXIII | Detection Correlation | `book/chapters/part23-detection-correlation.md` |
| XXIV | Risk-Based Alerting | `book/chapters/part24-risk-based-alerting.md` |
| XXV | Baselining | `book/chapters/part25-baselining.md` |
| XXVI | Threat Hunting | `book/chapters/part26-threat-hunting.md` |
| XXVII | Hunt Types | `book/chapters/part27-hunt-types.md` |
| XXVIII | Threat Hunt Notebook | `book/chapters/part28-threat-hunt-notebook.md` |
| XXIX | From Hunt to Detection | `book/chapters/part29-from-hunt-to-detection.md` |
| XXX | Detection Testing | `book/chapters/part30-detection-testing.md` |
| XXXI | Safe Lab Validation | `book/chapters/part31-safe-lab-validation.md` |
| XXXII | Attack Simulation for Defensive Validation | `book/chapters/part32-attack-simulation-defensive-validation.md` |
| XXXIII | False Positive Engineering | `book/chapters/part33-false-positive-engineering.md` |
| XXXIV | False Negatives | `book/chapters/part34-false-negatives.md` |
| XXXV | Detection Quality Metrics | `book/chapters/part35-detection-quality-metrics.md` |
| XXXVI | Detection Coverage Matrix | `book/chapters/part36-detection-coverage-matrix.md` |
| XXXVII | Detection Debt | `book/chapters/part37-detection-debt.md` |
| XXXVIII | Detection Governance | `book/chapters/part38-detection-governance.md` |
| XXXIX | Change Management | `book/chapters/part39-change-management.md` |
| XL | SIEM Migration | `book/chapters/part40-siem-migration.md` |
| XLI | Normalisation | `book/chapters/part41-normalisation.md` |
| XLII | Parser Failure | `book/chapters/part42-parser-failure.md` |
| XLIII | Time | `book/chapters/part43-time.md` |
| XLIV | Data Retention | `book/chapters/part44-data-retention.md` |
| XLV | Threat Intelligence in Detection | `book/chapters/part45-threat-intelligence-in-detection.md` |
| XLVI | Adversary Tradecraft — Defender View | `book/chapters/part46-adversary-tradecraft-defender-view.md` |
| XLVII | Ransomware Detection Engineering | `book/chapters/part47-ransomware-detection-engineering.md` |
| XLVIII | Identity Compromise Detection Model | `book/chapters/part48-identity-compromise-detection-model.md` |
| XLIX | Web Compromise Detection Model | `book/chapters/part49-web-compromise-detection-model.md` |
| L | AI System Compromise Detection Model | `book/chapters/part50-ai-system-compromise-detection-model.md` |

## Appendices

| Bundle | Contents | File |
|---|---|---|
| A1 | Windows Event ID / Sysmon / Logon Type / PowerShell / Linux / Identity / Network / DNS / Proxy / Email / Cloud / AI telemetry references | `book/appendices/a1-telemetry-field-references.md` |
| A2 | MITRE ATT&CK detection mapping quick reference | `book/appendices/a2-mitre-detection-mapping.md` |
| A3 | Sigma / KQL / SPL / AQL / YARA-L quick references | `book/appendices/a3-query-language-quick-reference.md` |
| A4 | Detection template, hunt template, review/testing/tuning templates, change request template | `book/appendices/a4-templates.md` |
| A5 | Coverage matrix, telemetry matrix, QA/FP/FN checklists | `book/appendices/a5-matrices-and-checklists.md` |

## Other index files

- `REFERENCES.md` — authoritative sources cited across the book
- `DETECTION-INVENTORY.md` — every named detection, its ID, and where it lives
- `HUNT-INVENTORY.md` — every named hunt and where it lives
- `TELEMETRY-MATRIX.md` — telemetry source → what it provides → which parts use it
- `MITRE-COVERAGE.md` — ATT&CK technique → part/detection coverage
- `VISUAL-INVENTORY.md` — every diagram/screenshot, its type (REAL LAB / CONTROLLED LAB / OFFICIAL REFERENCE / CONCEPTUAL), and location
- `BUILD-MANIFEST.md` — build status per part/appendix
