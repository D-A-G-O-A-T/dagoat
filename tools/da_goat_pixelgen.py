#!/usr/bin/env python3
"""Da-Goat pixel-art generator — deterministic, palette-audited.

Design spec: "Da-Goat — Main Playable Character Design"
Philosophy:  "Cozy Valor — a design philosophy"

Native 64x64, hard edges, no AA, selective 1px warm-ink outline,
top-left light, hue-shifted ramps. 128px = strict 2x nearest.
"""
import sys
from pathlib import Path
from PIL import Image

# ---------------------------------------------------------------- palette
PAL = {
    'K': (0x3B, 0x2C, 0x20),  # warm ink outline
    'f': (0xFF, 0xF3, 0xE0),  # fur hi
    'F': (0xF2, 0xDD, 0xB8),  # fur mid
    'd': (0xD4, 0xB4, 0x8C),  # fur shade
    'D': (0xA8, 0x82, 0x5C),  # fur dark
    'p': (0xE8, 0xA8, 0xA0),  # pink mid
    'P': (0xC4, 0x7C, 0x78),  # pink shade
    'H': (0xE8, 0xD5, 0xA8),  # horn hi
    'n': (0xC9, 0xAE, 0x7E),  # horn mid
    'N': (0x8F, 0x73, 0x50),  # horn shade
    'y': (0xFF, 0xE6, 0x99),  # bronze glint
    'b': (0xE8, 0xB3, 0x4B),  # bronze light
    'B': (0xC4, 0x86, 0x3A),  # bronze mid
    's': (0x96, 0x60, 0x2E),  # bronze shade
    'S': (0x6B, 0x42, 0x26),  # bronze dark
    'w': (0xFF, 0xFF, 0xFF),  # steel hi
    'W': (0xC8, 0xD4, 0xDC),  # steel mid
    'x': (0x8C, 0x9C, 0xAC),  # steel shade
    'u': (0x7F, 0xD4, 0xC0),  # teal hi
    't': (0x3F, 0xA8, 0x94),  # teal mid
    'T': (0x2A, 0x7A, 0x6E),  # teal shade
    'U': (0x1C, 0x54, 0x50),  # teal dark
    'g': (0x1E, 0x1A, 0x24),  # sunglasses black
    'G': (0x6E, 0x7A, 0x94),  # lens glint
}
BG = {'meadow': (0xBF, 0xE3, 0xA8), 'sky': (0xBE, 0xE3, 0xF0)}

ASSETS = Path(__file__).resolve().parents[1] / 'desktop' / 'src' / 'assets' / 'da-goat'
PREVIEW = ASSETS / 'preview'


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

    def mirror_left_onto_right(self, cx):
        for y in range(self.h):
            for x in range(cx):
                m = 2 * cx - x
                if m < self.w:
                    self.g[y][m] = self.g[y][x]

    def outline(self):
        edge = []
        for y in range(self.h):
            for x in range(self.w):
                if self.g[y][x] is None:
                    continue
                for dx, dy in ((1, 0), (-1, 0), (0, 1), (0, -1)):
                    nx, ny = x + dx, y + dy
                    if nx < 0 or ny < 0 or nx >= self.w or ny >= self.h \
                            or self.g[ny][nx] is None:
                        edge.append((x, y))
                        break
        for x, y in edge:
            self.g[y][x] = 'K'

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
    audit = sp.used_colors() - set(PAL)
    if audit:
        raise SystemExit(f'palette audit FAILED for {name}: {audit}')
    sp.to_image(1).save(outdir / f'{name}_64.png')
    sp.to_image(2).save(outdir / f'{name}_128.png')
    for bgn, bgc in BG.items():
        sp.to_image(1, bg=bgc).save(outdir / f'{name}_{bgn}_64.png')
        if final:
            sp.to_image(2, bg=bgc).save(outdir / f'{name}_{bgn}_128.png')
    if not final:
        sp.to_image(8).save(outdir / f'{name}_x8.png')       # inspection only
        sp.silhouette().to_image(4).save(outdir / f'{name}_silhouette.png')


# ---------------------------------------------------------------- head (3/4 right)
def head_34(s, brow='idle', mouth='smile'):
    # skull (sits directly on shoulders, no visible neck)
    s.run(9, 24, 35, 'F')
    s.run(10, 22, 37, 'F')
    s.run(11, 21, 38, 'F')
    for yy in range(12, 20):
        s.run(yy, 20, 39, 'F')
    s.run(20, 21, 38, 'F')
    s.run(21, 22, 36, 'F')
    # lit crown (top-left light)
    s.run(10, 23, 30, 'f')
    s.run(11, 22, 28, 'f')
    s.run(12, 21, 26, 'f')
    s.run(13, 21, 24, 'f')
    # shadow side (right of skull, above/below glasses)
    s.vrun(38, 10, 12, 'd'); s.vrun(39, 12, 12, 'd')
    s.run(20, 34, 38, 'd')
    # far horn (behind, shadow) — chunky crescent
    s.run(4, 18, 20, 'N')
    s.run(5, 15, 20, 'N')
    s.run(6, 14, 21, 'N')
    s.run(7, 16, 23, 'N')
    s.run(8, 20, 25, 'N')
    # near horn: solid crescent, tip swept back-left
    s.run(4, 26, 30, 'n')
    s.run(5, 25, 31, 'n'); s.run(5, 25, 26, 'H')
    s.run(6, 24, 33, 'n'); s.run(6, 24, 25, 'H')
    s.run(7, 27, 35, 'n'); s.run(7, 34, 35, 'N')
    s.run(8, 30, 36, 'n'); s.run(8, 34, 36, 'N')
    # far ear (left, droopy, shadow side)
    s.run(13, 14, 19, 'd')
    s.run(14, 12, 19, 'd')
    s.run(15, 11, 19, 'd')
    s.run(16, 12, 18, 'd')
    s.run(17, 14, 18, 'D')
    s.run(15, 13, 16, 'P')
    # near ear (right, droopy out)
    s.run(15, 40, 44, 'F')
    s.run(16, 40, 47, 'F')
    s.run(17, 41, 47, 'F')
    s.run(18, 43, 46, 'd')
    s.run(16, 42, 45, 'p')
    s.run(17, 43, 46, 'p')
    # muzzle (protrudes right)
    s.run(18, 35, 44, 'f')
    s.run(19, 34, 45, 'f')
    s.run(20, 34, 45, 'f')
    s.run(21, 34, 44, 'F')
    s.run(22, 35, 42, 'F')
    s.run(20, 42, 43, 'P')                                   # nostril
    if mouth == 'smile':
        s.run(21, 37, 42, 'K'); s.px(43, 20, 'K')
        s.run(22, 37, 41, 'd')
    else:  # firm
        s.run(21, 37, 43, 'K')
        s.run(22, 37, 41, 'd')
    # jaw fill down to chest (short neck)
    s.run(22, 25, 34, 'F')
    s.run(23, 26, 35, 'F')
    s.run(24, 27, 35, 'F')
    s.run(25, 28, 34, 'd')
    # chin beard
    s.run(23, 30, 35, 'd')
    s.run(24, 30, 34, 'D')
    s.run(25, 31, 33, 'D')
    # sunglasses: thick frames, band y13-17
    s.run(13, 21, 39, 'g')
    s.run(17, 22, 38, 'g')
    s.vrun(21, 13, 17, 'g'); s.vrun(39, 13, 17, 'g')
    s.rect(22, 14, 28, 16, 'g')                              # far lens
    s.rect(31, 14, 38, 16, 'g')                              # near lens
    s.run(14, 29, 30, 'g')                                   # bridge
    s.run(15, 29, 30, 'F'); s.run(16, 29, 30, 'F')
    s.run(14, 22, 23, 'G'); s.run(14, 31, 33, 'G')           # glints
    s.run(14, 40, 41, 'g')                                   # arm to near ear
    # brows above frames
    if brow == 'determined':
        s.run(12, 23, 26, 'K'); s.px(27, 12, 'K')
        s.run(12, 33, 36, 'K'); s.px(32, 12, 'K')
    else:
        s.run(12, 23, 25, 'd'); s.run(12, 33, 35, 'd')


# ---------------------------------------------------------------- body parts
def cape(s):
    # deep-teal cape so the mid-teal shield pops in front of it
    for y in range(26, 57):
        x0 = 13 - (y - 26) // 3
        x1 = 23 - (y - 26) // 4
        if x1 < x0 + 2:
            x1 = x0 + 2
        s.run(y, x0, x1, 'T')
        s.px(x0, y, 't')                                     # lit left edge
        s.px(x1, y, 'U')                                     # shaded right edge
    for y in range(52, 57):                                  # hem shade
        x0 = 13 - (y - 26) // 3
        x1 = 23 - (y - 26) // 4
        s.run(y, max(x0 + 1, x0), max(x1 - 1, x0 + 1), 'U')


def sword_shoulder(s):
    for i in range(10):                                      # blade up-right
        x, y = 52 + i, 19 - i
        s.px(x, y, 'W'); s.px(x, y - 1, 'w'); s.px(x + 1, y, 'x')
    s.px(62, 8, 'W')
    s.rect(46, 20, 52, 21, 'B'); s.run(20, 46, 48, 'b')      # cross-guard
    s.vrun(48, 22, 26, 'S'); s.vrun(49, 22, 26, 'S')         # grip
    s.run(27, 48, 49, 'b')                                   # pommel
    s.rect(46, 22, 50, 25, 'd')                              # fist wraps grip
    s.px(46, 22, 'F'); s.px(47, 22, 'F')


def sword_side(s):
    s.rect(44, 39, 50, 40, 'B'); s.run(39, 44, 46, 'b')      # guard
    s.vrun(46, 36, 38, 'S'); s.vrun(47, 36, 38, 'S')         # grip
    s.run(35, 46, 47, 'b')                                   # pommel
    for yy in range(41, 56):
        s.px(46, yy, 'w'); s.px(47, yy, 'W'); s.px(48, yy, 'x')
    s.px(47, 56, 'W')                                        # tip


def far_arm(s, pose):
    if pose == 'shoulder':
        s.rect(42, 28, 46, 33, 'd')                          # upper arm
        s.rect(44, 25, 48, 30, 'd')                          # forearm rising to fist
    else:
        s.rect(42, 28, 45, 35, 'd')                          # upper arm
        s.rect(44, 33, 48, 38, 'd')                          # forearm down
        s.rect(45, 36, 48, 39, 'd')                          # hand


def legs_idle(s):
    # near leg (lit) / far leg (shade), clear gap x31-32
    s.rect(24, 45, 30, 49, 'F'); s.vrun(24, 45, 49, 'f'); s.vrun(30, 45, 49, 'd')
    s.rect(33, 45, 38, 49, 'd')
    s.rect(24, 50, 30, 55, 'B'); s.vrun(24, 50, 55, 'b')     # near greave
    s.run(50, 24, 27, 'b')
    s.rect(33, 50, 38, 55, 'B'); s.vrun(38, 50, 55, 's')     # far greave
    s.vrun(30, 50, 55, 's')
    s.rect(23, 56, 30, 58, 'n'); s.run(58, 23, 30, 'N')      # near hoof
    s.rect(33, 56, 39, 58, 'n'); s.run(58, 33, 39, 'N')      # far hoof


def torso(s, variant):
    # chest plate: broad shoulders tapering to waist
    chest_rows = [(26, 20, 42), (27, 20, 42), (28, 21, 42), (29, 21, 41),
                  (30, 21, 41), (31, 22, 40), (32, 22, 40), (33, 23, 39)]
    for yy, x0, x1 in chest_rows:
        s.run(yy, x0, x1, 'B')
    s.run(26, 20, 42, 'b')
    s.run(27, 21, 30, 'b'); s.run(27, 22, 24, 'y')
    s.run(32, 24, 29, 's'); s.run(32, 33, 38, 's')           # pec scallop
    s.vrun(31, 31, 33, 's'); s.vrun(30, 31, 33, 's')
    if variant == 'sculpted':
        s.rect(24, 34, 38, 41, 'B')
        s.run(34, 24, 27, 'b')
        s.vrun(31, 34, 41, 's')
        s.run(36, 26, 36, 's'); s.run(39, 26, 36, 's')
        for cy in (34, 37, 40):
            s.px(28, cy, 'b'); s.px(34, cy, 'b')
        s.vrun(25, 34, 41, 's'); s.vrun(37, 34, 41, 's')
    else:
        s.rect(24, 34, 38, 41, 'F')
        s.run(34, 24, 27, 'f'); s.run(35, 24, 25, 'f')
        s.vrun(31, 34, 41, 'd')                              # linea alba
        s.run(36, 26, 36, 'd'); s.run(39, 26, 36, 'd')       # ab separators
        for cy in (34, 37, 40):
            s.px(28, cy, 'f'); s.px(34, cy, 'f')             # cell highlights
        s.vrun(25, 34, 41, 'D'); s.vrun(37, 34, 41, 'D')     # obliques
    # belt
    s.rect(24, 42, 38, 44, 'S')
    s.run(42, 24, 38, 'B')
    s.rect(29, 42, 33, 44, 'b'); s.px(30, 42, 'y')           # buckle


def sash(s):
    for i in range(16):
        yy = 27 + i
        x = 37 - (i * 12) // 15
        s.run(yy, x - 2, x, 't')
        s.px(x, yy, 'T')
    s.px(35, 27, 'u'); s.px(34, 28, 'u')


def collar(s):
    # teal cloth mantle across the chest top, knotted at the near shoulder
    s.run(26, 21, 41, 't')
    s.run(27, 21, 41, 't')
    s.run(27, 33, 41, 'T')
    s.px(22, 26, 'u'); s.px(23, 26, 'u')
    s.rect(36, 28, 38, 29, 't')                              # knot
    s.px(38, 30, 'T'); s.px(37, 31, 'T')                     # tail


def pauldrons(s):
    # near (left)
    s.run(24, 16, 21, 'b')
    s.run(25, 14, 23, 'b'); s.px(16, 25, 'y')
    s.rect(13, 26, 23, 28, 'B')
    s.run(26, 14, 17, 'b')
    s.run(29, 14, 23, 's')
    s.run(30, 15, 22, 's')
    s.run(31, 16, 21, 'S')
    s.vrun(23, 26, 30, 'S')                                  # separation from chest
    # far (right)
    s.run(24, 41, 45, 'B')
    s.run(25, 40, 46, 'B'); s.run(25, 41, 42, 'b')
    s.rect(40, 26, 47, 28, 'B')
    s.run(29, 40, 46, 's')
    s.run(30, 41, 45, 's')
    s.run(31, 42, 44, 'S')
    s.vrun(40, 26, 30, 'S')                                  # separation from chest
    # far arm-pit shade under pauldron
    s.run(31, 41, 44, 'd')


def near_arm(s):
    # upper arm swings free of the tapered waist
    s.rect(15, 31, 20, 38, 'F')
    s.vrun(15, 31, 37, 'f')
    s.vrun(19, 32, 38, 'd'); s.vrun(20, 32, 38, 'd')


def shield(s):
    widths = [6, 6, 6, 6, 6, 6, 6, 5, 5, 5, 4, 4, 4, 3, 3, 2, 2, 1, 1, 0, 0, 0]
    cx, top = 13, 34
    for i, hw in enumerate(widths):
        s.run(top + i, cx - hw, cx + hw, 't')
    for i, hw in enumerate(widths):                          # bronze rim ring
        yy = top + i
        s.px(cx - hw, yy, 'B')
        s.px(cx + hw, yy, 'S')
        if i > 15:
            s.px(cx - hw, yy, 'S')
    s.run(top, cx - 6, cx + 6, 'b')                          # top rim lit
    s.run(top + 1, cx - 5, cx - 1, 'u')
    s.run(top + 2, cx - 5, cx - 2, 'u')
    for i in range(12, 19):                                  # lower field shade
        s.run(top + i, cx, cx + widths[i] - 1, 'T')
    # emblem: sun disc + goat-horn curves (abstract, no letters)
    s.run(top + 5, cx - 1, cx + 1, 'y')
    s.run(top + 6, cx - 2, cx + 2, 'b'); s.px(cx - 1, top + 6, 'y')
    s.run(top + 7, cx - 1, cx + 1, 'b')
    s.px(cx - 3, top + 4, 'b'); s.px(cx - 4, top + 5, 'b'); s.px(cx - 4, top + 6, 'b')
    s.px(cx + 3, top + 4, 'b'); s.px(cx + 4, top + 5, 'b'); s.px(cx + 4, top + 6, 'b')


# ---------------------------------------------------------------- portrait (front bust)
def build_portrait(expr='happy'):
    """expr: 'happy' | 'sleepy' | 'determined' — sunglasses always on."""
    s = Sprite()
    ear_dy = {'happy': 0, 'sleepy': 5, 'determined': -2}[expr]

    # ---- symmetric half (left of cx=31), mirrored later
    # horn: solid crescent rising out of the crown
    s.run(2, 14, 17, 'n')
    s.run(3, 12, 18, 'n'); s.run(3, 12, 13, 'H')
    s.run(4, 11, 19, 'n'); s.run(4, 11, 12, 'H')
    s.run(5, 11, 20, 'n'); s.run(5, 18, 20, 'N')
    s.run(6, 13, 23, 'n'); s.run(6, 20, 23, 'N')
    s.run(7, 17, 26, 'N')
    # skull
    s.run(8, 20, 31, 'F')
    s.run(9, 17, 31, 'F')
    s.run(10, 15, 31, 'F')
    s.run(11, 14, 31, 'F')
    for yy in range(12, 34):
        s.run(yy, 12, 31, 'F')
    s.run(34, 13, 31, 'F')
    s.run(35, 14, 31, 'F')
    s.run(36, 15, 31, 'F')
    s.run(37, 17, 31, 'F')
    # lit crown
    s.run(9, 18, 26, 'f')
    s.run(10, 16, 24, 'f')
    s.run(11, 15, 22, 'f')
    s.run(12, 13, 20, 'f')
    # ear (thick, droopy), expression-shifted
    s.run(13 + ear_dy, 5, 11, 'F')
    s.run(14 + ear_dy, 3, 11, 'F')
    s.run(15 + ear_dy, 2, 11, 'F')
    s.run(16 + ear_dy, 2, 11, 'F')
    s.run(17 + ear_dy, 3, 11, 'F')
    s.run(18 + ear_dy, 5, 11, 'd')
    s.run(15 + ear_dy, 4, 9, 'p')
    s.run(16 + ear_dy, 3, 9, 'p')
    s.run(17 + ear_dy, 5, 9, 'P')
    # muzzle
    s.run(30, 22, 31, 'f')
    s.run(31, 21, 31, 'f')
    for yy in range(32, 40):
        s.run(yy, 20, 31, 'f')
    s.run(40, 21, 31, 'f')
    s.run(41, 22, 31, 'F')
    s.run(42, 24, 31, 'F')
    s.run(35, 25, 26, 'P')                                   # nostril
    # neck block first, beard layered over it (V-taper at center)
    s.rect(25, 43, 31, 47, 'F')
    s.rect(24, 48, 31, 52, 'F')
    s.run(52, 24, 31, 'd')
    s.run(43, 27, 31, 'd')
    s.run(44, 28, 31, 'd')
    s.run(45, 28, 31, 'D')
    s.run(46, 29, 31, 'D')
    s.run(47, 30, 31, 'D')
    # shoulders / pauldron (drawn after neck so armor overlays)
    s.run(50, 8, 18, 'b')
    s.run(51, 5, 20, 'b')
    for yy in range(52, 64):
        s.run(yy, 3, 20, 'B')
    s.run(52, 4, 12, 'b')
    for yy in range(60, 64):
        s.run(yy, 3, 20, 's')
    # chest + teal collar
    s.run(53, 21, 31, 't')
    s.run(54, 21, 31, 't')
    s.run(55, 21, 31, 'T')
    for yy in range(56, 64):
        s.run(yy, 21, 31, 'B')
    for yy in range(61, 64):
        s.run(yy, 21, 31, 's')

    s.mirror_left_onto_right(31)

    # ---- asymmetric corrections after mirror
    # keep light source top-left: damp mirrored crown highlight
    s.run(9, 40, 44, 'F')
    s.run(10, 40, 46, 'F'); s.run(11, 42, 47, 'F'); s.run(12, 44, 49, 'F')
    s.vrun(49, 13, 33, 'd'); s.vrun(50, 14, 32, 'd')         # right skull shade
    s.vrun(48, 14, 33, 'd')
    s.run(48, 32, 38, 'd'); s.run(49, 32, 38, 'd')           # neck shade right
    # sunglasses: one thick meme visor band, no bridge gap
    s.rect(13, 20, 49, 28, 'g')
    s.run(21, 15, 18, 'G'); s.run(22, 15, 16, 'G')           # glints (left of each lens)
    s.run(21, 35, 38, 'G'); s.run(22, 35, 36, 'G')
    # brows + mouth by expression
    if expr == 'determined':
        s.run(17, 14, 18, 'K'); s.run(18, 17, 21, 'K')       # brows slant in-down
        s.run(17, 44, 48, 'K'); s.run(18, 41, 45, 'K')
        s.run(39, 27, 35, 'K')                               # firm mouth
        s.px(26, 40, 'K'); s.px(36, 40, 'K')                 # set jaw corners
    elif expr == 'sleepy':
        s.run(18, 15, 20, 'D'); s.run(18, 42, 47, 'D')
        s.run(39, 28, 34, 'K')                               # small flat mouth
        s.px(41, 33, 'p'); s.px(42, 34, 'p')                 # sleep-drool sparkle
    else:  # happy
        s.run(39, 26, 36, 'K')                               # big smile
        s.px(25, 38, 'K'); s.px(37, 38, 'K')
        s.run(40, 28, 34, 'P')                               # open-mouth warmth
        s.run(31, 14, 17, 'p'); s.run(31, 45, 48, 'p')       # blush
    s.outline()
    return s


# ---------------------------------------------------------------- run key pose (side)
def build_run():
    """side view facing right, contact frame: front hoof planted, back hoof toe-off."""
    s = Sprite()
    # shield strapped on the back (drawn first, behind everything)
    widths = [6, 6, 6, 6, 6, 6, 6, 5, 5, 5, 4, 4, 4, 3, 3, 2, 2, 1, 1, 0, 0, 0]
    for i, hw in enumerate(widths):
        yy = 23 + i
        s.run(yy, 17 - hw, 17 + hw, 't')
        s.px(17 - hw, yy, 'B'); s.px(17 + hw, yy, 'S')
        if i > 15:
            s.px(17 - hw, yy, 'S')
    s.run(23, 11, 23, 'b')
    s.run(24, 12, 16, 'u'); s.run(25, 12, 15, 'u')
    for i in range(12, 19):
        s.run(23 + i, 17, 17 + widths[i] - 1, 'T')
    # far arm: forward swing, peeking in front of chest
    s.rect(41, 29, 44, 33, 'd')
    # back leg: extended back, toe-off
    s.run(41, 24, 32, 'd')
    s.run(42, 22, 30, 'd')
    s.run(43, 21, 28, 'd')
    s.run(44, 20, 26, 'd')
    for i in range(6):                                       # greave angled back-down
        yy = 45 + i
        s.run(yy, 17 - i, 25 - i, 'B')
    s.run(46, 17, 20, 'b')
    s.rect(12, 50, 18, 53, 'n'); s.run(53, 12, 18, 'N')      # hoof in air
    # torso (leaning forward)
    s.run(23, 27, 41, 't')                                   # collar
    s.run(24, 27, 41, 't'); s.run(24, 36, 41, 'T')
    s.rect(27, 25, 41, 32, 'B')
    s.run(25, 27, 41, 'b')
    s.run(26, 27, 33, 'b')
    s.rect(28, 33, 40, 38, 'F')                              # midriff
    s.run(33, 28, 31, 'f')
    s.vrun(34, 33, 38, 'd')                                  # linea
    s.run(35, 30, 38, 'd'); s.run(37, 30, 38, 'd')           # ab lines
    s.vrun(29, 33, 38, 'D')
    s.rect(28, 39, 40, 41, 'S'); s.run(39, 28, 40, 'B')      # belt
    s.rect(33, 39, 36, 41, 'b')
    # bronze strap across chest (holds the back-shield)
    for i in range(7):
        s.px(41 - i * 2, 25 + i, 's'); s.px(40 - i * 2, 25 + i, 's')
    # front leg: extended forward, planted
    s.run(41, 31, 39, 'F')
    s.run(42, 32, 40, 'F')
    s.run(43, 33, 41, 'F')
    s.run(44, 34, 41, 'F')
    for i in range(7):                                       # greave angled forward
        yy = 45 + i
        s.run(yy, 35 + i // 2, 43 + i // 2, 'B')
    s.run(45, 35, 38, 'b'); s.run(46, 35, 37, 'b')
    s.rect(40, 52, 47, 57, 'n')                              # planted hoof
    s.run(57, 40, 47, 'N'); s.run(56, 45, 47, 'N')
    # neck fill under jaw, then head (profile right), slightly ahead of torso = lean
    s.rect(33, 20, 38, 23, 'F')
    head_side(s)
    # near arm: swings back, holds sword low behind
    s.rect(33, 22, 41, 27, 'B')                              # pauldron
    s.run(22, 34, 40, 'b')
    s.rect(30, 27, 35, 32, 'F')                              # upper arm back
    s.rect(25, 30, 32, 34, 'F')                              # forearm
    s.rect(22, 32, 26, 36, 'F')                              # fist
    s.run(31, 24, 27, 'f')
    # sword: grip in fist, blade down-back (3px so a steel core survives outlining)
    s.px(23, 35, 'S'); s.px(22, 36, 'S')                     # grip
    s.rect(18, 36, 23, 37, 'B'); s.px(18, 36, 'b')           # guard
    for i in range(10):                                      # blade
        xc, y = 17 - i, 38 + i
        s.run(y, xc - 1, xc + 1, 'W')
        s.px(xc - 1, y, 'w')
    s.px(6, 48, 'W')                                         # tip
    s.outline()
    return s


def head_side(s):
    # skull profile
    s.run(6, 29, 38, 'F')
    s.run(7, 27, 40, 'F')
    for yy in range(8, 19):
        s.run(yy, 26, 42, 'F')
    s.run(19, 28, 42, 'F')
    s.run(20, 30, 42, 'F')
    s.run(7, 28, 34, 'f')
    s.run(8, 27, 33, 'f')
    s.run(9, 26, 31, 'f')
    # horn: single thick crescent swept back
    s.run(2, 26, 29, 'n')
    s.run(3, 24, 30, 'n'); s.run(3, 24, 25, 'H')
    s.run(4, 23, 32, 'n'); s.run(4, 23, 24, 'H')
    s.run(5, 25, 35, 'n'); s.run(5, 33, 35, 'N')
    s.run(6, 30, 38, 'N')
    # ear: flying back (motion)
    s.run(8, 20, 26, 'F')
    s.run(9, 17, 26, 'F')
    s.run(10, 16, 25, 'd')
    s.run(11, 18, 24, 'd')
    s.run(9, 19, 23, 'p')
    # muzzle wedge
    s.run(12, 40, 46, 'f')
    s.run(13, 40, 48, 'f')
    s.run(14, 40, 50, 'f')
    s.run(15, 39, 51, 'f')
    s.run(16, 39, 51, 'f')
    s.run(17, 39, 50, 'F')
    s.run(18, 40, 48, 'F')
    s.run(19, 41, 46, 'F')
    s.run(15, 49, 50, 'P')                                   # nostril
    s.run(17, 43, 49, 'K'); s.px(50, 16, 'K')                # smile
    s.run(18, 43, 47, 'd')
    # beard under chin
    s.run(20, 36, 40, 'd')
    s.run(21, 36, 39, 'D')
    s.run(22, 37, 38, 'D')
    # visor: side lens + temple arm to ear
    s.rect(36, 10, 46, 15, 'g')
    s.run(11, 26, 36, 'g'); s.run(12, 26, 30, 'g')
    s.run(11, 37, 40, 'G')                                   # glint
    s.run(12, 37, 38, 'G')
    # brow
    s.run(9, 36, 40, 'd')


# ---------------------------------------------------------------- poses
def build_idle(variant):
    """variant: 'cape' (A1) | 'sash' (A2) | 'sculpted' (A3) | 'hero' (A4)"""
    s = Sprite()
    if variant in ('cape', 'sculpted'):
        cape(s)
    far_arm(s, 'shoulder' if variant != 'sash' else 'side')
    if variant == 'sash':
        sword_side(s)
    else:
        sword_shoulder(s)
    legs_idle(s)
    torso(s, 'sculpted' if variant == 'sculpted' else 'open')
    if variant == 'sash':
        sash(s)
    if variant == 'hero':
        collar(s)
    pauldrons(s)
    near_arm(s)
    shield(s)
    head_34(s)
    s.outline()
    return s


def main():
    stage = sys.argv[1] if len(sys.argv) > 1 else 'a'
    if stage in ('a', 'all'):
        for v in ('cape', 'sash', 'sculpted', 'hero'):
            sp = build_idle(v)
            save(sp, f'variant_{v}')
            print(f'variant_{v}: {len(sp.used_colors())} colors')
    if stage in ('b', 'd', 'all'):
        for e in ('happy', 'sleepy', 'determined'):
            sp = build_portrait(e)
            save(sp, f'portrait_{e}')
            print(f'portrait_{e}: {len(sp.used_colors())} colors')
    if stage in ('c', 'all'):
        sp = build_run()
        save(sp, 'run')
        print(f'run: {len(sp.used_colors())} colors')
    if stage in ('final', 'all'):
        finals = {
            'da_goat_idle': build_idle('hero'),
            'da_goat_run': build_run(),
            'da_goat_portrait_happy': build_portrait('happy'),
            'da_goat_portrait_sleepy': build_portrait('sleepy'),
            'da_goat_portrait_determined': build_portrait('determined'),
        }
        for name, sp in finals.items():
            save(sp, name, final=True)
            print(f'{name}: {len(sp.used_colors())} colors')
        # presentation sheet — uniform 2x scale, flat pastel meadow, no text
        W, H = 496, 344
        sheet = Image.new('RGBA', (W, H), BG['meadow'] + (255,))
        spots = [('da_goat_idle', 108, 40), ('da_goat_run', 260, 40),
                 ('da_goat_portrait_happy', 32, 192),
                 ('da_goat_portrait_sleepy', 184, 192),
                 ('da_goat_portrait_determined', 336, 192)]
        for name, x, y in spots:
            img = finals[name].to_image(2)
            sheet.alpha_composite(img, (x, y))
        sheet.save(ASSETS / 'da_goat_sheet.png')
        print('sheet: da_goat_sheet.png')
    print('done ->', PREVIEW)


if __name__ == '__main__':
    main()
