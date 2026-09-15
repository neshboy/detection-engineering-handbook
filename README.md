# The Detection Engineering Handbook

**Telemetry, Analytics, and Detection Engineering Practice — From Raw Events to Tested, Maintained Coverage**

📄 **[Download the full PDF](./Detection_Engineering_Handbook.pdf)** — 532 pages, ~328,600 words across 48 parts and 7 appendices.

Part of the **NESHBOY SOC Professional Library**, alongside [SIGNAL TO ACTION: The Complete SOC Playbook Handbook](https://github.com/neshboy/soc-playbook-handbook).

This is a detection engineering handbook for SOC analysts, detection engineers, threat hunters, SIEM engineers, and SOC managers, built around two structural layers that run through every domain part: a **telemetry layer** (what the data actually captures, and where it lies to you) and an **analytic layer** (what you build with that data — rules, correlations, scores, hunts). It covers telemetry engineering across Windows, Sysmon, PowerShell, Linux/auditd, network, DNS, web, email, cloud, and AI systems; the analytic layer across identity, endpoint, network, and AI security; detection-as-code and six query languages (Sigma, KQL, SPL, AQL, YARA-L, Elastic EQL/KQL/ES|QL); correlation engineering, baselining, threat intelligence, and risk-based detection; threat hunting methodology; detection testing, false-positive/false-negative engineering, coverage, quality, and detection debt; and four applied compromise models (ransomware, identity, web, AI) that synthesize the domain parts into end-to-end attack chains.

## Reading the book

- **[Detection_Engineering_Handbook.pdf](./Detection_Engineering_Handbook.pdf)** — the assembled, print-ready book. Start here.
- **[release-v2/BOOK-INDEX.md](./release-v2/BOOK-INDEX.md)** — the full part/appendix table with per-unit scope, if you'd rather browse the Markdown source chapter by chapter.
- **[STYLE-GUIDE.md](./STYLE-GUIDE.md)** — the voice, formatting, and figure-evidence-classification contract every part follows: six content tags (`[CONCEPT]`, `[ANALYST]`, `[DETECTION ENGINEER]`, `[THREAT HUNTER]`, `[ENGINEERING]`, `[SOC MANAGEMENT]`) and eight recurring callouts (Detection Autopsy, Hunter's Note, Engineering Reality, Blind Spot, False Positive Trap, Detection Test, SOC Management View, What Would Change My Mind).
- **[TERMINOLOGY.md](./TERMINOLOGY.md)** — the canonical, binding definitions (rule vs. analytic vs. detection vs. incident vs. hunt, disposition outcomes, the six-tier coverage scale) that the rest of the book assumes without re-explaining.

## What's synthetic vs. real

Every detection, query, case study, and log excerpt in this book is written to be technically accurate and realistic without fabricating evidence. Where the book cites real telemetry, it comes from the author's own operated home lab (a honeynet and several monitored hosts) and is explicitly labeled `REAL LAB EXAMPLE`, sanitized before use. Everywhere else, figures are labeled `CONCEPTUAL` (an illustrative diagram or field breakdown, not a capture) or `OFFICIAL REFERENCE` (cited vendor/standards documentation). Diagrams are original Mermaid flowcharts. This book contains **no fabricated screenshots of any commercial security product** — where a real vendor-console capture would normally anchor a claim (Entra ID sign-in blades, QRadar Offenses, an EDR console) and none was available from the author's lab, the text says so explicitly with a `[FIGURE PENDING]` note rather than inventing one. See `VISUAL-INVENTORY.md` for the full figure-by-figure evidence-class ledger.

## How it was built

- `release-v2/build/build_book.js` — parses `BOOK-INDEX.md`'s part/appendix tables, assembles all 55 chapter/appendix files into one HTML document (stripping YAML front matter, resolving image paths, colorizing the six content tags), and prints it to PDF via headless Chrome.
- `release-v2/build/render_mermaid.py` — renders every embedded ` ```mermaid ` source block under `release-v2/chapters/` and `release-v2/appendices/` to SVG and inserts the image reference back into the chapter.
- `release-v2/build/render_field_diagram.py` — renders CONCEPTUAL field/value-card diagrams (Pillow-based, numbered callouts) for the figures that would otherwise need a real vendor screenshot the lab can't produce.
- `release-v2/build/add_watermark.py` — applies the diagonal `neshboy` watermark to every page.
- `BUILD-MANIFEST.md` — status of all 55 planned parts/appendices through the author → technical-reviewer → adversarial-reviewer → editor pipeline.
- `VISUAL-INVENTORY.md` — every figure and screenshot placeholder, with its evidence class and render status.
- `DETECTION-INVENTORY.md`, `HUNT-INVENTORY.md`, `MITRE-COVERAGE.md`, `QUERY-INVENTORY.md`, `TELEMETRY-MATRIX.md` — cross-cutting ledgers tracking every detection ID, hunt ID, ATT&CK mapping, query, and telemetry source in the book.

## Rebuilding it yourself

```
cd release-v2/build
npm install
node build_book.js
"C:\Program Files\Google\Chrome\Application\chrome.exe" --headless=new --disable-gpu --no-sandbox --no-pdf-header-footer ^
  --print-to-pdf="..\_build\Detection_Engineering_Handbook.pdf" "..\_build\book.html"
python add_watermark.py
```

## Repository layout

- `release-v2/` — the current book (V1 is archived, read-only, at `release-v1/`).
  - `chapters/`, `appendices/` — the 48 parts + 7 appendices, Markdown source of record.
  - `assets/diagrams/`, `assets/screenshots/` — rendered figures (SVG diagrams, CONCEPTUAL field-diagram PNGs).
  - `build/` — the build/render/watermark tooling above.
- `BUILD-MANIFEST.md`, `STYLE-GUIDE.md`, `TERMINOLOGY.md`, and the `*-INVENTORY.md` / `*-MATRIX.md` ledgers — cross-cutting project documentation at the repo root.
