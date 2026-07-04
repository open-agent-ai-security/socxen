<!--
  Copyright 2026 Exabeam, Inc.
  SPDX-License-Identifier: Apache-2.0
-->

# Guardrail bridge figure

The runtime-architecture diagram embedded in [`../security-guardrails.md`](../security-guardrails.md):
how the local bridge MCP proxies to the real Exabeam MCP and hooks input (`canonicalize`) and output
(`neutralize_output`) for safety, with `observra` recording a metadata-only audit trail.

| File | Role |
|---|---|
| `guardrails.html` | **Source of truth.** Self-contained HTML/CSS (no external assets). Edit this. |
| `guardrails-light.png` / `guardrails-dark.png` | Rendered figures; GitHub swaps them by the reader's theme via a `<picture>` element in the doc. **Generated — do not hand-edit.** |

Keep it in sync with the code: when the hooks in `connector/exabeam-mcp-bridge.py` — or `canonicalize.py`
/ `neutralize_output.py` / `observra_logging.py` — change, edit `guardrails.html` and regenerate.

## Regenerate

Renders every `*.html` in this folder to a light + dark PNG (2× for retina), then trims margins. Needs
only headless Chrome and Pillow.

```sh
CHROME="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"   # or `google-chrome` on Linux
cd docs/diagram

for html in *.html; do
  base="${html%.html}"
  for theme in light dark; do
    "$CHROME" --headless=new --disable-gpu --hide-scrollbars --force-device-scale-factor=2 \
      --window-size=1200,1400 --screenshot="$base-$theme.png" "file://$PWD/$html#$theme"
  done
done

python3 - <<'PY'
from PIL import Image, ImageChops
from pathlib import Path
for p in sorted(Path().glob("*-light.png")) + sorted(Path().glob("*-dark.png")):
    im = Image.open(p).convert("RGB")
    bg = Image.new("RGB", im.size, im.getpixel((2, 2)))
    l, t, r, b = ImageChops.difference(im, bg).getbbox()
    pad = 40
    im.crop((max(0, l - pad), max(0, t - pad),
             min(im.width, r + pad), min(im.height, b + pad))).save(p)
    print(p, "->", Image.open(p).size)
PY
```

The theme is stamped via the URL hash (`guardrails.html#light` / `#dark`); the page defaults to light
when opened directly. If a page grows taller than the render window, bump the `1400` in `--window-size`.
