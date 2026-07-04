<!--
  Copyright 2026 Exabeam, Inc.
  SPDX-License-Identifier: Apache-2.0
-->

# Red-team harness figure

The architecture diagram embedded at the top of [`../METHODOLOGY.md`](../METHODOLOGY.md).

| File | Role |
|---|---|
| `harness.html` | **Source of truth.** Self-contained HTML/CSS (no external assets). Edit this. |
| `harness-light.png` / `harness-dark.png` | Rendered figures. GitHub swaps them by the reader's theme via a `<picture>` element in `METHODOLOGY.md`. **Generated — do not hand-edit.** |

Keep the diagram in sync with the harness: when `run.py`, the attack classes, or the tool policy
change, edit `harness.html` and regenerate both PNGs.

## Regenerate

Renders both themes with headless Chrome (2× for retina), then trims the margins. No dependency beyond
Chrome and Pillow — the same tools already on a maintainer's machine.

```sh
CHROME="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"   # or `google-chrome` on Linux
cd security/redteam/diagram

for theme in light dark; do
  "$CHROME" --headless=new --disable-gpu --hide-scrollbars --force-device-scale-factor=2 \
    --window-size=1060,3000 --screenshot="harness-$theme.png" "file://$PWD/harness.html#$theme"
done

python3 - <<'PY'
from PIL import Image, ImageChops
for t in ("light", "dark"):
    im = Image.open(f"harness-{t}.png").convert("RGB")
    bg = Image.new("RGB", im.size, im.getpixel((2, 2)))
    l, top, r, b = ImageChops.difference(im, bg).getbbox()
    pad = 40
    im.crop((max(0, l - pad), max(0, top - pad),
             min(im.width, r + pad), min(im.height, b + pad))).save(f"harness-{t}.png")
    print(f"harness-{t}.png ->", Image.open(f"harness-{t}.png").size)
PY
```

The theme is stamped via the URL hash (`harness.html#light` / `#dark`); the page defaults to light when
opened directly in a browser. If the page ever grows taller than the render window, bump the `3000` in
`--window-size`.
