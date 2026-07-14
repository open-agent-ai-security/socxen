#!/usr/bin/env -S uv run --quiet --script
# /// script
# requires-python = ">=3.10"
# dependencies = ["Pillow"]
# ///
# Copyright 2026 Exabeam, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Render the doc diagram figures: every *.html in the given directories becomes a
<name>-light.png / <name>-dark.png pair (2x for retina), margin-trimmed and optimized.

Headless Chrome stamps the theme via the page's #light / #dark URL hash. Each theme renders
to a temporary file first and only replaces the committed PNG after the trim succeeds, so a
blank or failed render can never clobber a checked-in figure. Optimization uses oxipng
(lossless) or pngquant (near-lossless) when one is on PATH, else Pillow's optimizer.

Usage:
    scripts/render_diagram.py docs/diagram security/redteam/diagram
    CHROME=/path/to/chrome scripts/render_diagram.py --window-size 1200x3200 docs/diagram
"""
import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

from PIL import Image, ImageChops

PAD = 40


def find_chrome() -> str:
    candidates = [
        os.environ.get("CHROME"),
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        shutil.which("google-chrome"),
        shutil.which("chromium"),
    ]
    for c in candidates:
        if c and Path(c).exists():
            return c
    sys.exit("chrome not found — set CHROME=/path/to/chrome")


def render(chrome: str, html: Path, theme: str, size: str, out: Path) -> None:
    subprocess.run(
        [chrome, "--headless=new", "--disable-gpu", "--hide-scrollbars",
         "--force-device-scale-factor=2", f"--window-size={size.replace('x', ',')}",
         f"--screenshot={out}", f"file://{html.resolve()}#{theme}"],
        check=True, capture_output=True,
    )


def trim(path: Path) -> None:
    im = Image.open(path).convert("RGB")
    bg = Image.new("RGB", im.size, im.getpixel((2, 2)))
    bbox = ImageChops.difference(im, bg).getbbox()
    if bbox is None:
        sys.exit(f"{path}: render came out blank — committed figure left untouched")
    l, t, r, b = bbox
    im.crop((max(0, l - PAD), max(0, t - PAD),
             min(im.width, r + PAD), min(im.height, b + PAD))).save(path)


def optimize(path: Path) -> None:
    if shutil.which("oxipng"):
        subprocess.run(["oxipng", "-o", "max", "--strip", "safe", "-q", str(path)], check=True)
    elif shutil.which("pngquant"):
        subprocess.run(["pngquant", "--quality=90-100", "--speed=1", "--strip",
                        "--skip-if-larger", "--force", "--output", str(path), str(path)],
                       check=False)  # non-zero on --skip-if-larger is fine
    else:
        im = Image.open(path)
        im.save(path, optimize=True)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("dirs", nargs="+", type=Path, help="directories containing diagram *.html sources")
    ap.add_argument("--window-size", default="1200x3200",
                    help="render window WxH; excess background is trimmed (default: %(default)s)")
    args = ap.parse_args()

    chrome = find_chrome()
    for d in args.dirs:
        htmls = sorted(d.glob("*.html"))
        if not htmls:
            sys.exit(f"{d}: no *.html sources found")
        for html in htmls:
            for theme in ("light", "dark"):
                target = html.with_name(f"{html.stem}-{theme}.png")
                tmp = target.with_suffix(".png.tmp.png")
                try:
                    render(chrome, html, theme, args.window_size, tmp)
                    trim(tmp)
                    optimize(tmp)
                    tmp.replace(target)
                finally:
                    tmp.unlink(missing_ok=True)
                w, h = Image.open(target).size
                print(f"{target}  {w}x{h}  {target.stat().st_size // 1024} KB")


if __name__ == "__main__":
    main()
