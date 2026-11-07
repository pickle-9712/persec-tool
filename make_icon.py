"""Draws icon.ico: a dark rounded tile with lines of 'text', two of them redacted."""
from pathlib import Path

from PIL import Image, ImageDraw

S = 1024  # draw big, downscale for crisp small sizes
img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
d = ImageDraw.Draw(img)
d.rounded_rectangle((40, 40, S - 40, S - 40), radius=210, fill=(32, 34, 44, 255))

lines = [  # (y, x0, x1, redacted?)
    (270, 190, 830, False),
    (420, 190, 470, False), (420, 520, 830, True),
    (570, 190, 600, True), (570, 650, 830, False),
    (720, 190, 690, False),
]
for y, x0, x1, red in lines:
    if red:
        d.rounded_rectangle((x0, y - 52, x1, y + 52), radius=26, fill=(150, 152, 160, 255))
    else:
        d.rounded_rectangle((x0, y - 22, x1, y + 22), radius=22, fill=(235, 236, 242, 255))

out = Path(__file__).resolve().parent / "icon.ico"
img.save(out, sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
img.resize((256, 256), Image.LANCZOS).save(out.with_suffix(".png"))
print(out)
