"""Gera icon.png (256px) e icon.ico (multi-resolução). Requer Pillow (roda no container de build)."""

import sys
from pathlib import Path

from PIL import Image, ImageDraw

SIZE = 1024
BLUE = (36, 87, 214, 255)
WHITE = (255, 255, 255, 255)
RED = (230, 57, 70, 255)


def draw() -> Image.Image:
    img = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.rounded_rectangle((40, 40, SIZE - 40, SIZE - 40), radius=210, fill=BLUE)
    # Lupa: anel + cabo.
    cx, cy, r, w = 440, 430, 230, 70
    d.ellipse((cx - r, cy - r, cx + r, cy + r), outline=WHITE, width=w)
    d.line((cx + 165, cy + 165, 820, 820), fill=WHITE, width=110)
    # Sinal de bloqueio dentro da lente.
    d.ellipse((cx - 110, cy - 110, cx + 110, cy + 110), outline=RED, width=40)
    d.line((cx - 75, cy + 75, cx + 75, cy - 75), fill=RED, width=40)
    return img


def main(out_dir: str) -> None:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    img = draw()
    img.resize((256, 256), Image.LANCZOS).save(out / "icon.png")
    img.save(out / "icon.ico", sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "build/icon")
