#!/usr/bin/env python3
"""Da-Goat v2 pixel-art generator — Octopath-style Goat Knight Dark Lord.

Design spec: "Da-Goat v2 — Octopath-Style Goat Knight Dark Lord"
Deterministic, palette-audited. Native 64x64 sprites (figure ~56 px, realistic
proportions), selective warm-ink outline (light cores protected), top-left key
light + segmented cool rim light on convex right edges (HD-2D signature).
128 px sprite outputs = strict 2x nearest.
Round-1 previews only until the founder locks a variant.

Iteration 6 incorporates the three-lens critique panel (readability / style /
identity): obsidian horns, 3-row meme shades with bridge notch, dark nose
block, fur teardrop ears, dark six-pack lines, bold steel shield chevron,
cape flared past the shield with swallowtail + teal lining, split hooves,
segmented rim light.
"""
import sys
from pathlib import Path
from PIL import Image

# ------------------------------------------------------------ palette v2
# "Obsidian Rebel" — sprite subset (24 colors, cap 28).
PAL = {
    'K': (0x24, 0x1C, 0x26),  # warm near-black ink outline
    # blackened-steel plate + obsidian horn (shadows cool violet)
    'a': (0x14, 0x10, 0x20),  # plate darkest / horn shadow
    'b': (0x22, 0x1C, 0x30),  # plate dark / horn body
    'c': (0x32, 0x2B, 0x42),  # plate mid
    'd': (0x45, 0x3D, 0x58),  # plate lit
    'r': (0x7D, 0x82, 0xA8),  # cool rim light / horn ridge sheen
    'q': (0xB8, 0xBE, 0xDC),  # specular glint
    # black cloth (cape outer / FF15 underlayer)
    'u': (0x1C, 0x18, 0x22),  # cloth darkest
    'U': (0x2A, 0x25, 0x34),  # cloth fold
    # steel blade / shield trim
    'w': (0xE8, 0xEC, 0xF4),  # steel hi
    'x': (0xB9, 0xC2, 0xD4),  # steel mid
    'y': (0x88, 0x92, 0xAC),  # steel shade
    'z': (0x5A, 0x60, 0x7C),  # steel dark
    # cream fur (the light-value anchor)
    'f': (0xFF, 0xF4, 0xDC),  # fur hi
    'F': (0xEF, 0xD9, 0xB0),  # fur mid
    'e': (0xC9, 0xA8, 0x7C),  # fur shade
    'E': (0x96, 0x75, 0x4E),  # fur dark
    # snout / inner ear
    'n': (0xE0, 0xA4, 0x92),  # pink mid
    'N': (0xB0, 0x74, 0x68),  # pink shade
    # ivory hoof
    'h': (0xE8, 0xDC, 0xC4),  # hoof hi
    'H': (0xBF, 0xAE, 0x8C),  # hoof body
    'i': (0x8A, 0x7A, 0x5E),  # hoof shade
    # sunglasses (the meme)
    's': (0x10, 0x0C, 0x14),  # frame/lens black
    # brand teal — cape inner lining flash only
    't': (0x2E, 0x8C, 0x80),  # teal lining
    'T': (0x17, 0x50, 0x48),  # teal lining dark
}
SPRITE_CAP = 28
BG = {'meadow': (0xBF, 0xE3, 0xA8), 'sky': (0xBE, 0xE3, 0xF0)}
DARK = set('abcuU')            # materials that receive the cool rim light
# rim light only on convex forms, not as continuous piping
RIM_BANDS = ((21, 24), (29, 32), (41, 45), (50, 53))
# light cores the selective outline must never eat
PROTECT = set('wxqhHtr')

ASSETS = Path(__file__).resolve().parents[1] / 'desktop' / 'src' / 'assets' / 'da-goat'
PREVIEW = ASSETS / 'preview-v2'


class Sprite:
    def __init__(self, w=64, h=64):
        self.w, self.h = w, h
        self.g = [[None] * w for _ in range(h)]

    def px(self, x, y, c):
        if 0 <= x < self.w and 0 <= y < self.h:
            self.g[y][x] = c

    def run(self, y, x0, x1, c):
        for x in range(x0, x1 + 1):
            self.px(x, y, c)

    def vrun(self, x, y0, y1, c):
        for y in range(y0, y1 + 1):
            self.px(x, y, c)

    def rect(self, x0, y0, x1, y1, c):
        for y in range(y0, y1 + 1):
            self.run(y, x0, x1, c)

    def outline(self):
        """Selective ink outline: silhouette-edge pixels become 'K' unless
        they are protected light cores (steel, hoof ivory, teal, rim)."""
        edge = []
        for y in range(self.h):
            for x in range(self.w):
                c = self.g[y][x]
                if c is None or c in PROTECT:
                    continue
                for dx, dy in ((1, 0), (-1, 0), (0, 1), (0, -1)):
                    nx, ny = x + dx, y + dy
                    if nx < 0 or ny < 0 or nx >= self.w or ny >= self.h \
                            or self.g[ny][nx] is None:
                        edge.append((x, y))
                        break
        for x, y in edge:
            self.g[y][x] = 'K'

    def rim_right(self):
        """HD-2D rim: dark pixels just inside a right-facing ink edge,
        only on convex bands (pauldron, elbow, thigh, calf)."""
        for y0, y1 in RIM_BANDS:
            for y in range(y0, y1 + 1):
                for x in range(self.w):
                    if self.g[y][x] not in DARK:
                        continue
                    if x + 1 < self.w and self.g[y][x + 1] == 'K' and \
                            (x + 2 >= self.w or self.g[y][x + 2] is None):
                        self.g[y][x] = 'r'

    def key_left(self):
        """Top-left key light: dark pixels just inside a left-facing ink
        edge step one ramp up, so the cape/shield silhouette reads."""
        lighten = {'a': 'b', 'b': 'c', 'c': 'd', 'u': 'U'}
        for y in range(self.h):
            for x in range(self.w):
                c = self.g[y][x]
                if c not in lighten:
                    continue
                if x - 1 >= 0 and self.g[y][x - 1] == 'K' and \
                        (x - 2 < 0 or self.g[y][x - 2] is None):
                    self.g[y][x] = lighten[c]

    def silhouette(self):
        s = Sprite(self.w, self.h)
        for y in range(self.h):
            for x in range(self.w):
                if self.g[y][x] is not None:
                    s.g[y][x] = 'K'
        return s

    def used_colors(self):
        return {c for row in self.g for c in row if c is not None}

    def to_image(self, scale=1, bg=None):
        base = (0, 0, 0, 0) if bg is None else tuple(bg) + (255,)
        img = Image.new('RGBA', (self.w, self.h), base)
        for y in range(self.h):
            for x in range(self.w):
                c = self.g[y][x]
                if c is not None:
                    img.putpixel((x, y), PAL[c] + (255,))
        if scale != 1:
            img = img.resize((self.w * scale, self.h * scale), Image.NEAREST)
        return img


def save(sp, name, final=False):
    outdir = ASSETS if final else PREVIEW
    outdir.mkdir(parents=True, exist_ok=True)
    bad = sp.used_colors() - set(PAL)
    if bad:
        raise SystemExit(f'palette audit FAILED for {name}: unknown keys {bad}')
    if len(sp.used_colors()) > SPRITE_CAP:
        raise SystemExit(f'palette audit FAILED for {name}: '
                         f'{len(sp.used_colors())} colors > cap {SPRITE_CAP}')
    sp.to_image(1).save(outdir / f'{name}_64.png')
    sp.to_image(2).save(outdir / f'{name}_128.png')
    for bgn, bgc in BG.items():
        sp.to_image(1, bg=bgc).save(outdir / f'{name}_{bgn}_64.png')
        if final:
            sp.to_image(2, bg=bgc).save(outdir / f'{name}_{bgn}_128.png')
    if not final:
        sp.to_image(8).save(outdir / f'{name}_x8.png')       # inspection only
        sp.silhouette().to_image(4).save(outdir / f'{name}_silhouette.png')


# ================================================================ components
# Figure: 3/4 right, ground y=59, body centre ~x30, head y11-20 (+goatee).

def cape_flowing(s):
    """Black cape swinging left PAST the shield edge, ending in a
    swallowtail; teal lining flashes on the tails."""
    for yy in range(22, 50):
        if yy < 24:
            x0, x1 = 19, 28
        elif yy < 26:
            x0, x1 = 16, 27
        elif yy < 28:
            x0, x1 = 14, 27
        elif yy < 36:
            x0, x1 = 12, 26
        elif yy < 45:
            x0, x1 = 10, 26
        else:
            x0, x1 = 9, 26
        s.run(yy, x0, x1, 'u')
    # swallowtail: two tails with a background notch between them
    for yy, (l0, l1), (r0, r1) in [
            (50, (9, 15), (20, 26)), (51, (10, 15), (20, 26)),
            (52, (10, 14), (21, 25))]:
        s.run(yy, l0, l1, 'u')
        s.run(yy, r0, r1, 'u')
    # fold light
    s.vrun(12, 30, 42, 'U')
    s.vrun(11, 38, 47, 'U')
    s.vrun(18, 24, 28, 'U')
    # teal inner lining: flash along the tails' lower edge
    s.run(53, 10, 14, 't')
    s.run(53, 21, 25, 'T')
    s.run(52, 10, 11, 'T')


def cape_closed(s):
    """Cape wrapped tight — narrow monolith with a small swallowtail."""
    for yy in range(22, 50):
        x0 = 17 if 26 <= yy <= 48 else 18
        s.run(yy, x0, 27, 'u')
    for yy, (l0, l1), (r0, r1) in [
            (50, (17, 21), (24, 27)), (51, (17, 20), (24, 27)),
            (52, (18, 20), (25, 27))]:
        s.run(yy, l0, l1, 'u')
        s.run(yy, r0, r1, 'u')
    s.vrun(19, 26, 48, 'U')
    s.vrun(23, 24, 46, 'U')
    s.run(53, 18, 20, 't')
    s.run(53, 25, 27, 'T')


def legs(s):
    """Black plate legs, wide stance, split ivory hooves, knee lights."""
    # fauld / hip skirt + tassets
    s.rect(24, 39, 36, 41, 'b')
    s.run(39, 25, 33, 'c')
    s.run(40, 25, 31, 'c')
    s.rect(21, 39, 23, 42, 'b')           # far tasset
    s.rect(37, 39, 38, 42, 'c')           # near tasset (lit)
    # deep shadow between the legs
    s.vrun(29, 42, 55, 'a')
    # far leg (viewer-left)
    s.rect(23, 42, 28, 47, 'b')           # cuisse
    s.run(42, 23, 26, 'c')
    s.px(24, 44, 'd'); s.px(25, 44, 'd')  # knee catch-light
    s.rect(23, 48, 28, 49, 'u')           # knee-gap cloth
    s.rect(23, 50, 28, 55, 'b')           # greave
    s.vrun(23, 50, 55, 'c')
    s.run(56, 22, 28, 'a')                # boot rim
    # far hoof — ivory, cloven
    s.run(57, 23, 27, 'H')
    s.run(58, 22, 27, 'H')
    s.run(59, 22, 27, 'i')
    s.px(25, 58, 'K'); s.px(25, 59, 'K')
    # near leg (viewer-right, lit)
    s.rect(30, 42, 37, 47, 'c')           # cuisse
    s.vrun(30, 42, 47, 'd')
    s.vrun(31, 42, 45, 'd')
    s.run(42, 30, 35, 'd')
    s.rect(30, 48, 37, 49, 'u')           # knee-gap cloth
    s.rect(30, 50, 37, 55, 'c')           # greave
    s.vrun(30, 50, 55, 'd')
    s.vrun(31, 50, 54, 'd')
    s.px(33, 51, 'q')                     # shin glint
    s.run(56, 30, 37, 'a')                # boot rim
    # near hoof — ivory, cloven (gap x28-29 separates the boots)
    s.run(57, 31, 36, 'H')
    s.run(58, 30, 37, 'H')
    s.px(31, 57, 'h')
    s.run(59, 30, 37, 'i')
    s.px(33, 58, 'K'); s.px(33, 59, 'K')


def torso(s):
    """Open cuirass: black plate frame + cream-fur chest, six-pack that
    survives 1x (dark separators, shaded right column)."""
    # black cloth collar under the head
    s.rect(26, 21, 34, 22, 'u')
    # cuirass side plates (slight waist taper)
    s.rect(23, 25, 25, 32, 'b')
    s.vrun(23, 25, 32, 'c')
    s.rect(24, 33, 25, 36, 'b')
    s.rect(35, 25, 38, 32, 'b')
    s.vrun(38, 27, 32, 'a')
    s.rect(35, 33, 37, 36, 'b')
    # chest fur — pecs
    s.rect(26, 23, 34, 29, 'F')
    s.run(23, 26, 31, 'f')
    s.run(24, 26, 30, 'f')
    s.run(25, 26, 28, 'f')
    s.run(27, 27, 33, 'e')                # pec split line
    s.px(30, 27, 'F')
    s.run(29, 26, 34, 'E')                # under-pec shadow (dark, reads 1x)
    # abs — 2x3 grid, right column falls into shade
    s.rect(26, 30, 29, 36, 'F')           # left (lit) column
    s.rect(31, 30, 34, 36, 'e')           # right (shaded) column
    s.vrun(30, 30, 36, 'E')               # centre line
    s.run(32, 26, 34, 'E')                # row separators
    s.run(34, 26, 34, 'E')
    for by in (30, 33):                   # top-lit highlights, left cells only
        s.run(by, 27, 29, 'f')
    s.vrun(26, 30, 36, 'e')               # side shading
    s.vrun(34, 30, 36, 'E')
    s.run(36, 27, 33, 'E')                # abs meet the belt in shadow
    # belt
    s.rect(24, 37, 37, 38, 'a')
    s.run(37, 24, 30, 'b')
    s.rect(30, 37, 31, 38, 'y')           # steel buckle


def pauldron_far(s):
    """Far (viewer-left) pauldron — behind the shield top."""
    s.rect(18, 22, 26, 26, 'b')
    s.run(21, 19, 25, 'c')
    s.run(22, 18, 26, 'c')
    s.px(19, 21, 'd')


def pauldron_near(s):
    """Near (viewer-right) pauldron — chunky, lit."""
    s.rect(33, 21, 42, 26, 'c')
    s.run(20, 34, 40, 'd')
    s.run(21, 33, 42, 'd')
    s.run(22, 33, 35, 'd')
    s.px(36, 20, 'q')                     # specular
    s.run(26, 34, 42, 'b')
    s.px(43, 23, 'c'); s.px(43, 24, 'b')


def arm_sword_shouldered(s):
    """Near arm bent up; giant 5px blade resting over the near shoulder."""
    s.rect(39, 26, 41, 31, 'c')
    s.vrun(39, 26, 31, 'd')
    s.rect(39, 31, 41, 32, 'U')
    s.rect(41, 27, 43, 30, 'c')
    s.vrun(41, 27, 30, 'd')
    # fur fist gripping the hilt above the pauldron edge
    s.rect(42, 24, 44, 26, 'e')
    s.px(42, 24, 'F')
    s.px(41, 26, 'b')                     # pommel behind fist
    s.px(44, 23, 'b'); s.px(45, 23, 'b')  # grip to the guard
    # crossguard (diagonal, steel)
    s.run(24, 43, 46, 'z')
    s.run(23, 43, 47, 'z')
    s.run(22, 44, 48, 'x')
    # giant blade — 5px-thick 45-degree slab
    for k in range(14):
        xx, yy = 45 + k, 21 - k
        s.px(xx, yy - 1, 'w')
        s.px(xx, yy, 'x')
        s.px(xx, yy + 1, 'x')
        s.px(xx, yy + 2, 'x')
        s.px(xx, yy + 3, 'z')
    s.px(59, 5, 'w'); s.px(59, 6, 'x')    # squared tip
    s.px(59, 7, 'x'); s.px(59, 8, 'z')
    s.px(50, 17, 'q'); s.px(54, 13, 'q')  # fuller glints


def arm_sword_planted(s):
    """Dread-sovereign stance: fists stacked on the pommel, giant blade
    with a dark fuller planted tip-down in front, wide guard."""
    s.run(26, 38, 41, 'd')
    s.rect(38, 27, 40, 28, 'c')
    s.rect(40, 27, 43, 28, 'c')
    # pommel + stacked fur fists + grip
    s.rect(42, 24, 44, 25, 'y')           # pommel cap
    s.rect(41, 26, 45, 28, 'e')           # fists
    s.px(41, 26, 'F'); s.px(42, 26, 'F')
    s.rect(42, 29, 43, 30, 'b')           # grip
    # wide crossguard with dropped quillon ends
    s.run(32, 38, 48, 'z')
    s.run(31, 39, 47, 'x')
    s.px(38, 33, 'z'); s.px(48, 33, 'z')
    # blade straight down: lit left edge, dark fuller centre line
    for yy in range(33, 55):
        s.px(40, yy, 'x')
        s.px(41, yy, 'w')
        s.px(42, yy, 'y')                 # fuller
        s.px(43, yy, 'x')
        s.px(44, yy, 'z')
    s.run(55, 41, 43, 'x')
    s.px(42, 56, 'x')
    s.px(42, 57, 'z')                     # tip meets the ground


def arm_sword_side(s):
    """Blade held at mid-torso height, clean 45-degree slab down-right —
    reads as a held weapon, not a tail."""
    # arm down, forearm raised out to a mid-height fist
    s.rect(38, 26, 41, 32, 'c')
    s.vrun(38, 26, 32, 'd')
    s.rect(38, 32, 41, 33, 'U')           # elbow cloth
    s.rect(39, 33, 42, 36, 'c')           # forearm angled out
    s.vrun(39, 33, 36, 'd')
    # fur fist at mid-torso
    s.rect(40, 36, 42, 38, 'e')
    s.px(40, 36, 'F')
    # grip + perpendicular crossguard T
    s.px(42, 39, 'b'); s.px(43, 39, 'b')
    s.run(40, 41, 46, 'z')
    s.run(41, 42, 47, 'x')
    # blade — clean 45-degree, 4px stack, tip above the ground line
    for k in range(12):
        xx, yy = 45 + k, 42 + k
        s.px(xx, yy - 1, 'w')
        s.px(xx, yy, 'x')
        s.px(xx, yy + 1, 'x')
        s.px(xx, yy + 2, 'z')
    s.px(57, 53, 'w'); s.px(57, 54, 'x')  # tip
    s.px(57, 55, 'z')
    s.px(49, 47, 'q')


def shield(s):
    """Giant heater shield: modeled face (lit wedge, shaded foot), bold
    2px steel horn-chevron, rim-lit inner edge, own ink border."""
    rows = [
        (30, 14, 24), (31, 13, 25), (32, 13, 25), (33, 13, 25), (34, 13, 25),
        (35, 13, 25), (36, 13, 25), (37, 13, 25), (38, 13, 25), (39, 13, 25),
        (40, 13, 25), (41, 13, 25), (42, 14, 24), (43, 14, 24), (44, 15, 23),
        (45, 15, 23), (46, 16, 22), (47, 16, 22), (48, 17, 21), (49, 17, 21),
        (50, 18, 20), (51, 19, 19),
    ]
    for yy, x0, x1 in rows:
        s.run(yy, x0, x1, 'c')
    # form: shaded foot + darker lower-right, lit upper-left wedge
    for yy, x0, x1 in rows:
        if yy >= 44:
            s.run(yy, x0, x1, 'b')
    s.rect(14, 32, 18, 35, 'd')
    s.run(36, 14, 16, 'd')
    # own ink border (separates shield from cape and torso)
    for yy, x0, x1 in rows:
        s.px(x0, yy, 'K')
        s.px(x1, yy, 'K')
    s.run(30, 14, 24, 'K')
    # steel top rim (value-graded) + inner-edge rim light
    s.run(31, 15, 19, 'z')
    s.run(31, 20, 23, 'y')
    s.vrun(24, 33, 40, 'r')
    # bold 2px steel horn-chevron with bright apex
    s.px(14, 32, 'w'); s.px(24, 32, 'w')  # flared tips
    s.run(33, 15, 16, 'x'); s.run(33, 22, 23, 'x')
    s.run(34, 15, 16, 'x'); s.run(34, 22, 23, 'x')
    s.run(35, 16, 17, 'x'); s.run(35, 21, 22, 'x')
    s.run(36, 17, 18, 'x'); s.run(36, 20, 21, 'x')
    s.run(37, 18, 20, 'x')
    s.px(19, 38, 'w')                     # apex highlight
    s.px(19, 39, 'y')
    s.px(15, 32, 'q')                     # boss glint


def head(s):
    """Compact goat head, 3/4 right: 3-row meme shades with bridge notch,
    dark nose block, fur teardrop ears, stern jaw, long goatee."""
    # skull
    s.run(11, 28, 34, 'F')
    s.run(12, 27, 35, 'F')
    s.run(13, 26, 36, 'F')
    # crown lit
    s.run(11, 28, 31, 'f')
    s.run(12, 27, 30, 'f')
    s.run(13, 26, 28, 'f')
    # ears — fur teardrops drooping at 45 degrees
    s.run(13, 23, 25, 'F')
    s.run(14, 22, 24, 'F')
    s.run(15, 21, 23, 'e')
    s.px(21, 16, 'E'); s.px(22, 16, 'E')
    s.vrun(25, 13, 15, 'e')               # ear/skull contact shade
    # thick 3-row shades: bridge notch splits two lenses, temple into ear
    s.run(14, 27, 36, 's')
    s.px(31, 14, 'F')                     # bridge notch
    s.run(15, 26, 37, 's')
    s.run(16, 27, 36, 's')
    s.px(29, 15, 'q')                     # glint on the LEFT lens
    s.px(25, 14, 's'); s.px(26, 14, 's')  # temple arm terminates in the ear
    # face + muzzle with dark nose block
    s.rect(27, 17, 36, 18, 'F')
    s.vrun(27, 17, 18, 'e')
    s.px(37, 17, 'F')
    s.px(38, 17, 'b'); s.px(39, 17, 'b')  # nose block
    s.px(38, 18, 'b'); s.px(39, 18, 'a')
    s.run(19, 33, 37, 'e')                # hard-set mouth line
    # jaw with shaded termination row
    s.run(19, 28, 32, 'F')
    s.run(20, 28, 36, 'e')
    s.px(31, 20, 'F'); s.px(32, 20, 'F')  # chin catch-light
    # long dark-lord goatee (breaks the bottom contour over the collar)
    s.rect(31, 21, 34, 22, 'e')
    s.px(34, 21, 'E')
    s.rect(32, 23, 33, 23, 'E')
    s.px(32, 24, 'E')
    # right-side face shadow
    s.vrun(36, 17, 18, 'E')


def horns_warlord(s):
    """Massive OBSIDIAN crescent sweeping back-left, thick and solid;
    the far horn is a dark band along its top."""
    # far horn — darkest band above the near horn's top edge
    s.run(7, 28, 31, 'a')
    s.run(6, 21, 27, 'a')
    s.run(5, 15, 22, 'a')
    s.px(14, 5, 'a'); s.px(13, 5, 'a')
    # near horn — thick solid mass, root on the crown
    s.run(10, 27, 32, 'a')                # root contact shadow
    s.run(9, 24, 31, 'b')
    s.run(8, 19, 30, 'b')
    s.run(7, 15, 27, 'b')
    s.run(6, 13, 20, 'b')
    s.px(12, 7, 'a'); s.px(13, 7, 'b')    # dropped tip
    s.px(12, 8, 'a')
    # cool ridge sheen along the top edge (segments, not piping)
    s.run(9, 25, 27, 'r')
    s.run(8, 20, 22, 'r')
    s.run(7, 16, 18, 'r')
    s.px(14, 6, 'r')
    s.px(30, 9, 'q')                      # base glint


def horns_sovereign(s):
    """Wide-spread OBSIDIAN demon horns, thick bases, curving out-then-up."""
    # far horn — sweeps up-LEFT, darkest
    s.run(10, 26, 29, 'a')
    s.run(9, 24, 28, 'a')
    s.run(8, 23, 26, 'a')
    s.run(7, 22, 24, 'a')
    s.run(6, 21, 23, 'a')
    s.run(5, 20, 21, 'a')
    s.run(4, 19, 20, 'a')
    s.px(19, 3, 'a')
    # near horn — thick base on the crown, curving up-RIGHT
    s.run(10, 31, 35, 'a')                # root contact shadow
    s.run(9, 31, 36, 'b')
    s.run(8, 32, 37, 'b')
    s.run(7, 34, 38, 'b')
    s.run(6, 35, 39, 'b')
    s.run(5, 36, 40, 'b')
    s.run(4, 38, 40, 'b')
    s.run(3, 39, 40, 'b')
    s.px(40, 2, 'b')
    # cool ridge sheen along the inner curve
    s.run(9, 32, 34, 'r')
    s.px(35, 8, 'r'); s.px(36, 7, 'r')
    s.px(37, 6, 'r'); s.px(38, 5, 'r')
    s.px(39, 4, 'q')                      # tip glint
    s.px(33, 9, 'q')


def horns_ibex(s):
    """Tall OBSIDIAN ibex arc, thick continuous shaft, open 4-5px loop,
    tip curling down-forward; dark far horn behind."""
    # far horn — darkest band hugging the arc's top
    s.run(3, 25, 29, 'a')
    s.run(4, 27, 30, 'a')
    s.px(24, 3, 'a'); s.px(23, 3, 'a')
    # near horn — thick C-arc
    s.run(10, 29, 33, 'a')                # root contact shadow
    s.run(9, 29, 34, 'b')
    s.run(8, 29, 34, 'b')
    s.run(7, 28, 33, 'b')
    s.run(6, 25, 31, 'b')
    s.run(5, 21, 28, 'b')
    s.run(4, 19, 26, 'b')
    s.run(5, 19, 20, 'b')                 # arc turns down at the back
    s.run(6, 18, 20, 'b')
    s.run(7, 18, 20, 'a')
    s.run(8, 19, 21, 'a')
    s.run(9, 20, 22, 'a')                 # curl tip, forward
    # cool ridge sheen segments
    s.run(4, 20, 23, 'r')
    s.run(5, 24, 26, 'r')
    s.px(31, 7, 'r'); s.px(32, 8, 'r')
    s.px(21, 9, 'q')                      # tip glint
    # open air stays at x21-27 / y6-8 inside the arc


# ================================================================ variants
def build(horns, sword, cape):
    s = Sprite()
    cape(s)
    legs(s)
    torso(s)
    pauldron_far(s)
    shield(s)
    pauldron_near(s)
    sword(s)
    head(s)
    horns(s)
    s.outline()
    s.rim_right()
    s.key_left()
    return s


VARIANTS = {
    'variant_warlord':   (horns_warlord,   arm_sword_shouldered, cape_flowing),
    'variant_sovereign': (horns_sovereign, arm_sword_planted,    cape_flowing),
    'variant_ibex':      (horns_ibex,      arm_sword_side,       cape_closed),
}


def main(which='variants'):
    if which in ('variants', 'all'):
        for name, (h, sw, cp) in VARIANTS.items():
            sp = build(h, sw, cp)
            save(sp, name)
            print(f'{name}: {len(sp.used_colors())} colors OK')
    else:
        raise SystemExit(f'unknown target {which!r} (Round 1: "variants")')


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else 'variants')
