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

One shared script renders every `*.html` in a diagram folder to a light + dark PNG (2× for retina),
trims the margins, and optimizes the PNGs. Needs headless Chrome; `uv` supplies Pillow.

```sh
scripts/render_diagram.py security/redteam/diagram        # from the repo root
```

The theme is stamped via the URL hash (`harness.html#light` / `#dark`); the page defaults to light when
opened directly in a browser. If the page ever grows taller than the render window, bump the script's
`--window-size` — excess background is trimmed away, so taller-than-needed is harmless.
