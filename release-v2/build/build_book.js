const fs = require("fs");
const path = require("path");
const { marked } = require("marked");

const REPO_ROOT = "C:/Users/User/projects/detection-engineering-handbook";
const BOOK_ROOT = path.join(REPO_ROOT, "release-v2");
const INDEX_PATH = path.join(BOOK_ROOT, "BOOK-INDEX.md");
const OUT_HTML = path.join(BOOK_ROOT, "_build", "book.html");

marked.setOptions({ mangle: false, headerIds: true, gfm: true });

function readFile(p) {
  return fs.readFileSync(p, "utf-8");
}

// BOOK-INDEX.md is two big Markdown tables (Part Table, Appendix Table) grouped by
// "### Section X — Name" subheadings, not a flat link list like the SOC Playbook's index.
// Parse both shapes into the same ordered entry stream build_book expects.
function parseIndex() {
  const lines = readFile(INDEX_PATH).split("\n");
  const entries = [];
  for (const raw of lines) {
    const line = raw.trim();

    if (line === "## Part Table") {
      entries.push({ type: "part", text: "Chapters" });
      continue;
    }
    if (line === "## Appendix Table") {
      entries.push({ type: "part", text: "Appendices" });
      continue;
    }
    const sectionMatch = line.match(/^### (Section .+)$/);
    if (sectionMatch) {
      entries.push({ type: "section", text: sectionMatch[1].trim() });
      continue;
    }

    if (line.startsWith("|")) {
      // Markdown escapes a literal "|" inside a table cell as "\|" (e.g. the Part 29 title
      // "Elastic (EQL/KQL/ES\|QL)"). A naive split("|") treats that as a column boundary and
      // shifts every later cell in the row - protect it first, split, then restore.
      const PIPE_TOKEN = "@@ESCAPED_PIPE@@";
      const protectedLine = line.split(String.fromCharCode(92,124)).join(PIPE_TOKEN);
      const cells = protectedLine
        .split("|")
        .slice(1, -1)
        .map((c) => c.trim().split(PIPE_TOKEN).join("|"));
      if (cells.length < 3) continue;
      const id = cells[0];
      if (!/^[0-9]+$/.test(id) && !/^A[0-9]+$/.test(id)) continue; // header/separator row
      const title = cells[1];
      const pathMatch = cells[2].match(/`([^`]+)`/);
      if (!pathMatch) continue;
      const target = "release-v2/" + pathMatch[1].replace(/\\/g, "/");
      const label = /^A[0-9]+$/.test(id) ? `Appendix ${id} — ${title}` : `Part ${id} — ${title}`;
      entries.push({ type: "chapter", text: label, target });
      continue;
    }
    // everything else (prose, "Total: 48 parts.", blank lines, "---") is not TOC-worthy.
  }
  return entries;
}

function stripFrontMatter(md) {
  return md.replace(/^---\r?\n[\s\S]*?\r?\n---\r?\n/, "");
}

function fixImagePaths(html, sourceFileDir) {
  return html.replace(/src="([^"]+)"/g, (m, p1) => {
    if (/^[A-Za-z]:\//.test(p1)) return `src="file:///${p1}"`;
    if (/^https?:\/\//.test(p1)) return m;
    const abs = path.resolve(sourceFileDir, p1).replace(/\\/g, "/");
    return `src="file:///${abs}"`;
  });
}

const TAG_COLORS = {
  CONCEPT: "tag-concept",
  ANALYST: "tag-analyst",
  "DETECTION ENGINEER": "tag-detection-engineer",
  "THREAT HUNTER": "tag-threat-hunter",
  ENGINEERING: "tag-engineering",
  "SOC MANAGEMENT": "tag-soc-management",
};

function colorizeContentTags(html) {
  const alternation = Object.keys(TAG_COLORS)
    .sort((a, b) => b.length - a.length)
    .join("|");
  const re = new RegExp(`<strong>\\[(${alternation})\\]<\\/strong>`, "g");
  return html.replace(re, (m, tag) => `<span class="content-tag ${TAG_COLORS[tag]}">[${tag}]</span>`);
}

function slugAnchor(s, seen) {
  let base = s
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/(^-|-$)/g, "");
  let anchor = base;
  let n = 2;
  while (seen.has(anchor)) {
    anchor = base + "-" + n;
    n++;
  }
  seen.add(anchor);
  return anchor;
}

function inlineMd(s) {
  return marked.parseInline(s);
}

function buildTOC(entries, anchors) {
  let toc = '<nav class="toc"><h1>Table of Contents</h1><ul class="toc-list">';
  entries.forEach((e, i) => {
    const anchor = anchors[i];
    if (e.type === "part") {
      toc += `</ul><li class="toc-part">${inlineMd(e.text)}</li><ul class="toc-list">`;
    } else if (e.type === "section") {
      toc += `<li class="toc-section"><a href="#${anchor}">${inlineMd(e.text)}</a></li>`;
    } else if (e.type === "chapter") {
      toc += `<li class="toc-chapter"><a href="#${anchor}">${inlineMd(e.text)}</a></li>`;
    }
  });
  toc += "</ul></nav>";
  return toc;
}

function escapeHtml(s) {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function main() {
  const entries = parseIndex();
  const seenAnchors = new Set();
  const anchors = entries.map((e) => slugAnchor(e.text, seenAnchors));

  let missing = [];
  let body = "";
  entries.forEach((e, i) => {
    const anchor = anchors[i];
    if (e.type === "part") {
      body += `<section class="part-divider" id="${anchor}"><h1>${inlineMd(e.text)}</h1></section>\n`;
    } else if (e.type === "section") {
      body += `<h2 class="section-heading" id="${anchor}">${inlineMd(e.text)}</h2>\n`;
    } else if (e.type === "chapter") {
      const fullPath = path.join(REPO_ROOT, e.target.replace(/\//g, path.sep));
      if (!fs.existsSync(fullPath)) {
        missing.push(e.target);
        body += `<section class="chapter" id="${anchor}"><p><em>MISSING FILE: ${escapeHtml(e.target)}</em></p></section>\n`;
        return;
      }
      let md = stripFrontMatter(readFile(fullPath));
      let html = marked.parse(md);
      html = fixImagePaths(html, path.dirname(fullPath));
      html = colorizeContentTags(html);
      body += `<section class="chapter" id="${anchor}">${html}</section>\n`;
    }
  });

  const toc = buildTOC(entries, anchors);

  const css = `
  :root {
    --blue: #2a78d6; --orange: #eb6834; --aqua: #1baf7a; --yellow: #eda100;
    --magenta: #e87ba4; --green: #008300; --violet: #4a3aa7; --red: #e34948;
    --ink: #0b0b0b; --ink-secondary: #52514e; --ink-muted: #898781;
    --gridline: #e1e0d9; --baseline: #c3c2b7;
    --blue-tint: #cde2fb; --orange-tint: #f9d9c4; --aqua-tint: #bdeedb; --yellow-tint: #fce8bf; --violet-tint: #e3ddf7; --magenta-tint: #fadce8; --green-tint: #cdeccd;
  }
  @page { size: A4; margin: 22mm 18mm 24mm 18mm; }
  * { box-sizing: border-box; }
  body { font-family: "Segoe UI", Calibri, Arial, sans-serif; color: var(--ink); line-height: 1.5; font-size: 10.5pt; }
  .cover { margin-top: 85mm; text-align: center; page-break-after: always; }
  .cover .kicker { font-size: 11pt; letter-spacing: 2pt; color: var(--ink-muted); text-transform: uppercase; margin-bottom: 8pt; }
  .cover h1 { font-size: 27pt; margin-bottom: 10pt; letter-spacing: 0.3pt; color: var(--blue); }
  .cover .accent-rule { width: 120pt; height: 3pt; background: linear-gradient(90deg, var(--blue), var(--aqua), var(--violet)); margin: 0 auto 16pt auto; border-radius: 2pt; }
  .cover h2 { font-size: 13pt; font-weight: 400; color: var(--ink-secondary); margin-top: 0; max-width: 72%; margin-left: auto; margin-right: auto; }
  .cover .meta { margin-top: 40pt; font-size: 9pt; color: var(--ink-muted); }
  .toc { page-break-after: always; }
  .toc h1 { font-size: 20pt; border-bottom: 2pt solid var(--blue); padding-bottom: 6pt; color: var(--ink); }
  .toc-list { list-style: none; padding-left: 0; }
  .toc-part { font-weight: 700; font-size: 14pt; margin-top: 16pt; color: var(--violet); text-transform: uppercase; letter-spacing: 0.5pt; }
  .toc-section { font-weight: 700; font-size: 12pt; margin-top: 10pt; margin-left: 6pt; color: var(--blue); }
  .toc-chapter { font-size: 9.5pt; margin-top: 2pt; margin-left: 18pt; color: var(--ink-secondary); }
  .toc a { text-decoration: none; color: inherit; }
  .part-divider { page-break-before: always; page-break-after: always; margin-top: 100mm; text-align: center; }
  .part-divider h1 { font-size: 26pt; border-top: 3pt solid var(--violet); border-bottom: 3pt solid var(--violet); padding: 14pt 0; text-align: center; color: var(--ink); text-transform: uppercase; letter-spacing: 1pt; }
  h2.section-heading { page-break-before: always; font-size: 16pt; border-bottom: 2pt solid var(--orange); padding-bottom: 4pt; margin-top: 0; color: var(--ink); }
  section.chapter { page-break-before: always; }
  section.chapter h1 { font-size: 17pt; margin-top: 0; color: var(--ink); border-bottom: 1.5pt solid var(--blue-tint); padding-bottom: 6pt; }
  section.chapter h2 { font-size: 13pt; margin-top: 16pt; color: var(--blue); }
  section.chapter h3 { font-size: 11pt; margin-top: 12pt; color: var(--ink); }
  section.chapter h4 { font-size: 10pt; margin-top: 10pt; color: var(--ink-secondary); }
  section.chapter img { max-width: 92%; max-height: 215mm; width: auto; height: auto; display: block; margin: 10pt auto; page-break-inside: avoid; }
  section.chapter table { border-collapse: collapse; width: 100%; font-size: 8.5pt; margin: 8pt 0; page-break-inside: avoid; }
  section.chapter th, section.chapter td { border: 0.5pt solid var(--baseline); padding: 3pt 5pt; text-align: left; vertical-align: top; }
  section.chapter th { background: var(--blue-tint); color: var(--ink); border-bottom: 1.5pt solid var(--blue); }
  section.chapter pre { background: #f4f4f4; border: 0.5pt solid var(--baseline); border-left: 3pt solid var(--violet); padding: 6pt; font-size: 7.8pt; overflow-wrap: break-word; white-space: pre-wrap; page-break-inside: avoid; }
  section.chapter code { font-family: Consolas, "Courier New", monospace; font-size: 8.3pt; background: var(--violet-tint); padding: 0 2pt; color: var(--ink); }
  section.chapter pre code { background: none; padding: 0; }
  section.chapter blockquote { border-left: 3pt solid var(--yellow); margin-left: 0; padding-left: 10pt; color: var(--ink-secondary); font-style: italic; background: var(--yellow-tint); padding: 6pt 10pt; border-radius: 0 3pt 3pt 0; page-break-inside: avoid; }
  section.chapter strong { color: var(--ink); }
  section.chapter hr { border: none; border-top: 1pt solid var(--gridline); margin: 12pt 0; }
  .content-tag { display: inline-block; font-weight: 700; font-size: 7.5pt; letter-spacing: 0.3pt; padding: 1.5pt 6pt; border-radius: 3pt; margin-right: 3pt; }
  .tag-concept { background: var(--gridline); color: var(--ink-secondary); border: 0.5pt solid var(--baseline); }
  .tag-analyst { background: var(--aqua-tint); color: #0d6b49; border: 0.5pt solid var(--aqua); }
  .tag-detection-engineer { background: var(--blue-tint); color: #164a8a; border: 0.5pt solid var(--blue); }
  .tag-threat-hunter { background: var(--magenta-tint); color: #99245c; border: 0.5pt solid var(--magenta); }
  .tag-engineering { background: var(--violet-tint); color: #2e2470; border: 0.5pt solid var(--violet); }
  .tag-soc-management { background: var(--orange-tint); color: #93401d; border: 0.5pt solid var(--orange); }
  `;

  const now = new Date();
  const dateStr = now.toISOString().slice(0, 10);

  const html = `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>The Detection Engineering Handbook</title>
<style>${css}</style>
</head>
<body>
<section class="cover">
  <div class="kicker">NESHBOY SOC Professional Library</div>
  <h1>THE DETECTION ENGINEERING HANDBOOK</h1>
  <div class="accent-rule"></div>
  <h2>Telemetry, Analytics, and Detection Engineering Practice — From Raw Events to Tested, Maintained Coverage</h2>
  <div class="meta">Build date: ${dateStr}</div>
</section>
${toc}
${body}
</body>
</html>`;

  fs.mkdirSync(path.dirname(OUT_HTML), { recursive: true });
  fs.writeFileSync(OUT_HTML, html, "utf-8");

  console.log("Entries:", entries.length, "| chapters:", entries.filter((e) => e.type === "chapter").length);
  console.log("Missing files:", missing.length);
  if (missing.length) console.log(missing.join("\n"));
  console.log("Wrote", OUT_HTML, "(", (html.length / 1024 / 1024).toFixed(2), "MB )");
}

main();
