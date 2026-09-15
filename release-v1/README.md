# Detection Engineering Handbook — working repository

Source repository for *The Detection Engineering Handbook: Threat Hunting, Telemetry,
Adversary Behaviour and Detection at Scale*.

Start at [BOOK-INDEX.md](BOOK-INDEX.md).

## Layout

```
book/
  chapters/     one file per Part (I-L)
  appendices/   reference appendices (A1-A5)
  detections/   standalone detection-as-code write-ups referenced by chapters
  hunts/        standalone threat hunt notebooks referenced by chapters
  queries/      Sigma/KQL/SPL/AQL/YARA-L query files referenced by chapters
  lab/evidence/ raw controlled-lab evidence (logs, command output) behind screenshots
  assets/
    screenshots/  labelled REAL LAB / CONTROLLED LAB / OFFICIAL REFERENCE / CONCEPTUAL
    diagrams/     Mermaid source + rendered SVG/PNG
    timelines/    correlation timelines
    charts/       matplotlib-generated charts
  references/   per-topic source notes backing REFERENCES.md
  qa/           QA pass notes
build/          PDF/DOCX build tooling and output
```

Every screenshot and diagram is labelled with its evidence class:
`REAL LAB`, `CONTROLLED LAB`, `OFFICIAL REFERENCE`, or `CONCEPTUAL`. No product
interface is ever fabricated.
