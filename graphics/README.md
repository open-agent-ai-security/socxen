# socxen graphics

Brand and site assets for socxen. Same convention as [praxen/graphics](https://github.com/open-agent-ai-security/praxen/tree/main/graphics)
so the sister sites stay one family.

> **Placeholder status.** Every socxen-specific asset here was drawn as vector shapes to mock up the site
> and is meant to be **replaced by art-department artwork in the same poses and file names**: the lion mark,
> the wordmark (uses live `<text>`, not outlined paths — a font dependency the real masters must not have),
> and the hero mascot. The community and Exabeam logos are the real ones, copied verbatim from praxen.

**Convention**
- **`graphics/brand/`** — the brand source set: SVG masters referenced directly by the site (nav, footer, docs top bar).
  Named by the background the asset sits on: `-dark-background` = light art for dark backgrounds, `-light-background` = dark ink for light.
- **`graphics/`** — other masters (the mascot, the social card) and the sponsor logo.
- **`graphics/web/`** — raster copies for the surfaces that need them (favicons). Social/OG cards stay PNG for scraper compatibility.

## The mascot: Leo

A lion — the SOC's hunter — in the community's black hoodie, holding a crosshair loupe up to a planted alert.
Accent is **lion gold** (`#e6a23c` / `#f2bd5c` / `#c4841c` in `assets/socxen-theme.css`) where Praxen is
orange, Observra blue, and the community violet. The signal-teal (`#2fbf9f`) in the loupe is the theme's
second hue. `leo-hunting.svg` is cropped tight (viewBox) so it fills the hero like Praxy does.

| File | Form | Used by |
|---|---|---|
| `brand/socxen-mark.svg` | lion head mark, gold | source for the favicon and wordmark |
| `brand/socxen-favicon.svg` | mark on a gold tile | master for `web/favicon-{32,180,256}.png` |
| `brand/socxen-wordmark-dark-background.svg` | mark + "socxen" | landing nav + footer, docs top bar |
| `brand/socxen-wordmark-light-background.svg` | same, dark ink | available |
| `brand/community-logo-{dark,light}-background.svg` | parent-org logo | footer "Part of the…" |
| `leo-hunting.svg` | hero mascot | landing hero (referenced directly as SVG) |
| `socxen-social.png` | 1280×640 OG / Twitter card | `<meta property="og:image">` |
| `exabeam-logo-white.svg` | sponsor logo | footer sponsor band |
| `web/favicon-*.png` | 32 / 180 / 256 | `<link rel="icon">`, apple-touch-icon |

## Regenerating the rasters

Favicons and the social card are rendered with headless Chrome from the SVG masters (no ImageMagick in the
build environment); `sips` resizes:

```sh
CH="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
"$CH" --headless=new --hide-scrollbars --window-size=256,256 --default-background-color=00000000 \
  --screenshot=graphics/web/favicon-256.png "file://$PWD/<wrapper.html showing brand/socxen-favicon.svg at 256px>"
for sz in 180 32; do sips -z $sz $sz graphics/web/favicon-256.png --out graphics/web/favicon-$sz.png; done
```
