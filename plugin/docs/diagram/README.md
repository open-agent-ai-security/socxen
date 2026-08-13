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

One shared script renders every `*.html` in a diagram folder to a light + dark PNG (2× for retina),
trims the margins, and optimizes the PNGs. Needs headless Chrome; `uv` supplies Pillow.

```sh
scripts/render_diagram.py plugin/docs/diagram        # from the repo root
```

The theme is stamped via the URL hash (`guardrails.html#light` / `#dark`); the page defaults to light
when opened directly. If a page grows taller than the render window, bump the script's
`--window-size` — excess background is trimmed away, so taller-than-needed is harmless.
