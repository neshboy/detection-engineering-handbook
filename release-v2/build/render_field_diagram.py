import json
import sys
import os
import textwrap
from PIL import Image, ImageDraw, ImageFont

FONT_DIR = r"C:\Windows\Fonts"
SANS_BOLD = os.path.join(FONT_DIR, "segoeuib.ttf")
SANS = os.path.join(FONT_DIR, "segoeui.ttf")
MONO = os.path.join(FONT_DIR, "consola.ttf")
MONO_BOLD = os.path.join(FONT_DIR, "consolab.ttf")

INK = (30, 34, 40)
MUTED = (110, 118, 128)
LINE = (215, 219, 224)
ACCENT = (0, 90, 160)
CALLOUT_BG = (0, 90, 160)
CARD_BG = (250, 250, 251)
BG = (255, 255, 255)
WARN_BG = (255, 244, 214)
WARN_INK = (140, 100, 10)

PAD = 40
CARD_PAD = 22
ROW_GAP = 10
WIDTH = 1040
LABEL_COL_W = 34  # chars
VALUE_COL_W = 42  # chars
LABEL_X_OFFSET = 28  # room for callout circle


def font(path, size):
    try:
        return ImageFont.truetype(path, size)
    except OSError:
        return ImageFont.load_default()


def wrap_or_self(text, width):
    lines = textwrap.wrap(str(text), width=width)
    return lines if lines else [""]


def render(spec, out_path):
    title = spec["title"]
    event_type = spec.get("event_type", "")
    fields = spec["fields"]
    callouts = spec.get("callouts", [])
    note = spec.get(
        "note",
        "Illustrative field breakdown, not a captured screenshot. No product interface is depicted.",
    )

    f_title = font(SANS_BOLD, 26)
    f_sub = font(SANS, 16)
    f_label = font(MONO_BOLD, 15)
    f_value = font(MONO, 15)
    f_callout_num = font(SANS_BOLD, 13)
    f_callout_text = font(SANS, 15)
    f_stamp = font(SANS_BOLD, 14)
    f_section = font(SANS_BOLD, 16)
    f_note = font(SANS, 13)

    dummy = Image.new("RGB", (10, 10))
    d0 = ImageDraw.Draw(dummy)

    def tw(text, f):
        return d0.textbbox((0, 0), text, font=f)[2]

    label_x = PAD + CARD_PAD + LABEL_X_OFFSET
    value_x = PAD + CARD_PAD + LABEL_X_OFFSET + (LABEL_COL_W * 8) + 24

    row_specs = []  # (label_lines, value_lines, callout_num_or_None)
    callout_by_label = {c["field_label"]: c["number"] for c in callouts if "field_label" in c}
    for field in fields:
        label = field["label"]
        value = str(field["value"])
        label_lines = wrap_or_self(label, LABEL_COL_W)
        value_lines = wrap_or_self(value, VALUE_COL_W)
        num = callout_by_label.get(label)
        n_lines = max(len(label_lines), len(value_lines))
        row_h = 22 * n_lines + ROW_GAP
        row_specs.append((label_lines, value_lines, num, row_h))

    title_lines = wrap_or_self(title, 58)
    sub_lines = wrap_or_self(event_type, 90) if event_type else []
    callout_lines = []
    for c in callouts:
        wrapped = textwrap.wrap(f"{c['number']}  {c['explanation']}", width=95)
        callout_lines.extend(wrapped if wrapped else [""])
    note_lines = textwrap.wrap(note, width=118)

    header_h = 40 + 34 * len(title_lines) + 22 * len(sub_lines) + 26
    card_h = CARD_PAD * 2 + sum(r[3] for r in row_specs)
    callout_h = (30 + 22 * len(callout_lines)) if callout_lines else 0
    footer_h = 20 + 18 * len(note_lines) + 20
    height = header_h + card_h + callout_h + footer_h + PAD * 2

    img = Image.new("RGB", (WIDTH, height), BG)
    d = ImageDraw.Draw(img)

    y = PAD
    d.rectangle([0, 0, WIDTH, 8], fill=ACCENT)

    stamp_text = "CONCEPTUAL"
    sw = tw(stamp_text, f_stamp) + 20
    d.rectangle([WIDTH - PAD - sw, y, WIDTH - PAD, y + 28], fill=WARN_BG, outline=WARN_INK)
    d.text((WIDTH - PAD - sw + 10, y + 5), stamp_text, font=f_stamp, fill=WARN_INK)

    y += 40
    title_right_limit = WIDTH - PAD - sw - 20
    for line in title_lines:
        d.text((PAD, y), line, font=f_title, fill=INK)
        y += 34
    for line in sub_lines:
        d.text((PAD, y), line, font=f_sub, fill=MUTED)
        y += 22
    y += 6
    d.line([(PAD, y), (WIDTH - PAD, y)], fill=LINE, width=1)
    y += 20

    card_top = y
    d.rectangle([PAD, card_top, WIDTH - PAD, card_top + card_h], fill=CARD_BG, outline=LINE)
    ry = card_top + CARD_PAD

    for label_lines, value_lines, num, row_h in row_specs:
        row_top = ry
        if num:
            r = 10
            cx, cy = label_x - LABEL_X_OFFSET, row_top + 2
            d.ellipse([cx, cy, cx + r * 2, cy + r * 2], fill=CALLOUT_BG)
            d.text((cx + r - 4, cy + 1), str(num), font=f_callout_num, fill=(255, 255, 255))
        ly = row_top
        for line in label_lines:
            d.text((label_x, ly), line, font=f_label, fill=INK)
            ly += 22
        vy = row_top
        for line in value_lines:
            d.text((value_x, vy), line, font=f_value, fill=(40, 60, 90))
            vy += 22
        ry += row_h

    y = card_top + card_h + 18

    if callout_lines:
        d.text((PAD, y), "Field notes", font=f_section, fill=INK)
        y += 26
        for line in callout_lines:
            d.text((PAD, y), line, font=f_callout_text, fill=(60, 66, 74))
            y += 22
        y += 8

    d.line([(PAD, y), (WIDTH - PAD, y)], fill=LINE, width=1)
    y += 12
    for line in note_lines:
        d.text((PAD, y), line, font=f_note, fill=MUTED)
        y += 18

    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    img.save(out_path, "PNG")
    return out_path


def main():
    if len(sys.argv) != 3:
        print("Usage: render_field_diagram.py <spec.json> <out.png>", file=sys.stderr)
        sys.exit(1)
    with open(sys.argv[1], "r", encoding="utf-8") as f:
        spec = json.load(f)
    out = render(spec, sys.argv[2])
    print(out)


if __name__ == "__main__":
    main()
