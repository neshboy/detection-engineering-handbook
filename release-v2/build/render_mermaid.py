import os
import re
import subprocess
import glob

ROOT = r"C:\Users\User\projects\detection-engineering-handbook\release-v2"
CHAPTER_GLOBS = [
    os.path.join(ROOT, "chapters", "*.md"),
    os.path.join(ROOT, "appendices", "*.md"),
]
DIAGRAM_DIR = os.path.join(ROOT, "assets", "diagrams")
os.makedirs(DIAGRAM_DIR, exist_ok=True)

MERMAID_RE = re.compile(r"```mermaid\r?\n(.*?)```", re.DOTALL)
# Matches an existing rendered image (or a previous failure marker) that already
# immediately follows a mermaid fence, allowing the blank lines this script (and
# hand-authored figures) normally leave between the fence and the image.
NEXT_IMG_RE = re.compile(r"(?:\r?\n)*!\[[^\]]*\]\(([^)]+)\)")
NEXT_FAILURE_RE = re.compile(r"(?:\r?\n)*<!-- RENDER FAILED[^>]*-->")
MMDC_CMD = ["npx", "-y", "@mermaid-js/mermaid-cli"]

def slug_for(path):
    base = os.path.splitext(os.path.basename(path))[0]
    return base

def render_one(mmd_text, out_svg):
    tmp_mmd = out_svg + ".mmd"
    with open(tmp_mmd, "w", encoding="utf-8") as f:
        f.write(mmd_text)
    cmd = MMDC_CMD + ["-i", tmp_mmd, "-o", out_svg, "-b", "white"]
    result = subprocess.run(cmd, capture_output=True, text=True, shell=True, timeout=90)
    ok = os.path.exists(out_svg) and os.path.getsize(out_svg) > 0
    try:
        os.remove(tmp_mmd)
    except OSError:
        pass
    return ok, result.stdout, result.stderr

def process_file(path):
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()

    matches = list(MERMAID_RE.finditer(content))
    if not matches:
        return 0, 0

    slug = slug_for(path)
    rendered = 0
    failed = 0
    new_content = content
    offset = 0

    for i, m in enumerate(matches, start=1):
        mmd_text = m.group(1)
        fig_name = f"{slug}-fig{i:02d}"
        rel_path = f"../assets/diagrams/{fig_name}.svg"

        insert_at = m.end() + offset

        # Idempotency: if an image already immediately follows this mermaid
        # fence (a prior run of this script, or a hand-placed captioned
        # figure), re-render into that existing file in place instead of
        # inserting a second, duplicate image reference. If a previous
        # RENDER FAILED marker is there instead, consume it and retry fresh.
        existing_img = NEXT_IMG_RE.match(new_content, insert_at)
        existing_failure = None if existing_img else NEXT_FAILURE_RE.match(new_content, insert_at)

        if existing_img:
            out_svg = os.path.normpath(os.path.join(os.path.dirname(path), existing_img.group(1)))
            ok, out, err = render_one(mmd_text, out_svg)
            if ok:
                rendered += 1
            else:
                failed += 1
            continue

        if existing_failure:
            removed_len = existing_failure.end() - insert_at
            new_content = new_content[:insert_at] + new_content[existing_failure.end():]
            offset -= removed_len

        out_svg = os.path.join(DIAGRAM_DIR, fig_name + ".svg")
        ok, out, err = render_one(mmd_text, out_svg)
        if ok:
            rendered += 1
            img_line = f"\n\n![{fig_name}]({rel_path})\n"
        else:
            failed += 1
            img_line = f"\n\n<!-- RENDER FAILED for {fig_name}: {err.strip()[:300]} -->\n"

        insert_at = m.end() + offset
        new_content = new_content[:insert_at] + img_line + new_content[insert_at:]
        offset += len(img_line)

    new_content = new_content.replace("Rendered image pending.", "Rendered above.")
    new_content = new_content.replace("Rendered image pending", "Rendered above")

    with open(path, "w", encoding="utf-8") as f:
        f.write(new_content)

    return rendered, failed

def main():
    files = []
    for g in CHAPTER_GLOBS:
        files.extend(sorted(glob.glob(g)))

    total_rendered = 0
    total_failed = 0
    file_results = []
    for path in files:
        rendered, failed = process_file(path)
        if rendered or failed:
            file_results.append((os.path.basename(path), rendered, failed))
            print(f"{os.path.basename(path)}: rendered={rendered} failed={failed}", flush=True)
        total_rendered += rendered
        total_failed += failed

    print(f"\n=== TOTAL: rendered={total_rendered} failed={total_failed} across {len(file_results)} files ===")

if __name__ == "__main__":
    main()
