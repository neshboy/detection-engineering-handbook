import fitz
import sys

WATERMARK_TEXT = "neshboy"


def add_watermark(in_path, out_path, text=WATERMARK_TEXT):
    doc = fitz.open(in_path)
    for page in doc:
        rect = page.rect
        cx, cy = rect.width / 2, rect.height / 2
        fontsize = rect.width / (len(text) * 0.62)
        text_len = fitz.get_text_length(text, fontname="hebo", fontsize=fontsize)

        mat = fitz.Matrix(1, 1).prerotate(45)
        origin = fitz.Point(cx - text_len / 2, cy + fontsize / 2)

        shape = page.new_shape()
        shape.insert_text(
            origin,
            text,
            fontname="hebo",
            fontsize=fontsize,
            color=(0.63, 0.63, 0.60),
            fill_opacity=0.16,
            morph=(fitz.Point(cx, cy), mat),
            render_mode=0,
        )
        shape.commit()

    doc.save(out_path)
    print("Watermarked", doc.page_count, "pages ->", out_path)


if __name__ == "__main__":
    in_path = sys.argv[1] if len(sys.argv) > 1 else r"C:\Users\User\projects\detection-engineering-handbook\release-v2\_build\Detection_Engineering_Handbook.pdf"
    out_path = sys.argv[2] if len(sys.argv) > 2 else r"C:\Users\User\projects\detection-engineering-handbook\release-v2\_build\Detection_Engineering_Handbook_watermarked.pdf"
    add_watermark(in_path, out_path)
