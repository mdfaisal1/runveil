"""Generate the Runveil terminal demo GIF from the real dashboard scan result.

Renders a dark, cyan-accented terminal that progressively reveals an `rv scan`
run ending in the 3-of-297 (98% noise reduced) headline. Pure Pillow; no network.

Usage: python scripts/make_demo_gif.py [output.gif]
"""
import sys
from PIL import Image, ImageDraw, ImageFont

OUT = sys.argv[1] if len(sys.argv) > 1 else "website/demo.gif"

# ---- palette (matches the website) ----
BG = (7, 11, 20)
BAR = (14, 22, 38)
WHITE = (232, 238, 252)
DIM = (120, 144, 176)
CYAN = (56, 189, 248)
GREEN = (52, 211, 153)
YELLOW = (251, 191, 36)
RED = (248, 113, 113)
DOT_R, DOT_Y, DOT_G = (255, 95, 86), (255, 189, 46), (39, 201, 63)

FONT = r"C:\Windows\Fonts\consola.ttf"
FONTB = r"C:\Windows\Fonts\consolab.ttf"
SIZE = 19
font = ImageFont.truetype(FONT, SIZE)
fontb = ImageFont.truetype(FONTB, SIZE)

PAD = 24
BAR_H = 40
LH = 28
W = 920

# Each line: list of (text, color, bold) segments. None = blank line.
L = lambda *segs: list(segs)
S = lambda t, c=WHITE, b=False: (t, c, b)

LINES = [
    L(S("$ ", CYAN, True), S("rv scan ./package-lock.json --fail-on high", WHITE)),
    L(S("-> resolving 968 packages from lockfile...", DIM)),
    L(S("-> querying OSV vulnerability database...", DIM)),
    L(S("!  65 vulnerabilities found across dependencies", YELLOW)),
    L(S("-> building dependency & call graph...", DIM)),
    L(S("-> classifying reachable vs dormant...", DIM)),
    None,
    L(S("REACHABLE FINDINGS ", CYAN, True), S("(3 of 65)", DIM)),
    L(S("  * @angular/compiler  ", WHITE), S("HIGH  ", RED, True), S("XSS in i18n attribute bindings", DIM)),
    L(S("  * @angular/core      ", WHITE), S("HIGH  ", RED, True), S("XSS in i18n attribute bindings", DIM)),
    L(S("  * @angular/core      ", WHITE), S("HIGH  ", RED, True), S("i18n Cross-Site Scripting", DIM)),
    None,
    L(S("+ 62 dormant (dev-only) CVEs hidden", GREEN), S("  - never on an executed path", DIM)),
    L(S("= 3 reachable of 65 total  ", CYAN, True), S("- 95% noise reduced", GREEN, True)),
    L(S("x policy: max reachable HIGH >= high  ->  exit 3", RED)),
]

TITLE = "package-lock.json  -  rv scan"
H = BAR_H + PAD * 2 + LH * len(LINES)


def draw(visible, type_text=None):
    """visible: number of fully shown lines. type_text: (idx, n_chars) partial."""
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    # title bar
    d.rectangle([0, 0, W, BAR_H], fill=BAR)
    for i, col in enumerate((DOT_R, DOT_Y, DOT_G)):
        cx = PAD + i * 22
        d.ellipse([cx, BAR_H // 2 - 6, cx + 12, BAR_H // 2 + 6], fill=col)
    d.text((PAD + 78, BAR_H // 2 - SIZE // 2), TITLE, font=font, fill=DIM)

    y = BAR_H + PAD
    for idx in range(len(LINES)):
        if idx > visible:
            break
        line = LINES[idx]
        if line is not None:
            x = PAD
            partial = type_text and type_text[0] == idx
            budget = type_text[1] if partial else None
            for (text, color, bold) in line:
                if budget is not None:
                    if budget <= 0:
                        break
                    text = text[:budget]
                    budget -= len(text)
                d.text((x, y), text, font=(fontb if bold else font), fill=color)
                x += d.textlength(text, font=(fontb if bold else font))
            # cursor on the line currently being revealed
            if partial:
                d.rectangle([x + 1, y + 2, x + 10, y + SIZE], fill=CYAN)
        y += LH
    return img


frames, durations = [], []

# 1) type the command line char-by-char
cmd_len = sum(len(t) for t, _, _ in LINES[0])
for n in range(2, cmd_len + 1, 2):
    frames.append(draw(0, type_text=(0, n)))
    durations.append(40)
frames.append(draw(0)); durations.append(350)

# 2) reveal the remaining lines one at a time
PAUSE = {3: 500, 7: 250, 11: 350, 12: 400, 13: 250}  # ms after specific lines
for i in range(1, len(LINES)):
    frames.append(draw(i))
    durations.append(PAUSE.get(i, 220))

# 3) hold the final frame
frames.append(draw(len(LINES) - 1)); durations.append(3200)

frames[0].save(
    OUT, save_all=True, append_images=frames[1:], duration=durations,
    loop=0, optimize=True, disposal=2,
)
# Preview still of the final frame (same code path → trustworthy verification).
frames[-1].save(OUT.rsplit(".", 1)[0] + "_preview.png")
print(f"wrote {OUT}  ({len(frames)} frames)")
