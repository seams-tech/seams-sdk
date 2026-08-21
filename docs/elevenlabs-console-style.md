# ElevenLabs Console Style

Last reconciled: August 21, 2026 (extracted from the live app and applied to
`apps/seams-console`)

## Scope

The Seams Console chrome is modelled on the ElevenLabs app. This document
records what that system actually is, how it maps onto our tokens and classes,
where we deliberately diverge, and how to re-derive any of it rather than
guessing from a screenshot.

It covers chrome only — palette, type scale, elevation, and the anatomy of
tables, dialogs, controls, the rail and the toast host. It says nothing about
what the Console _shows_; product decisions live in the refactor docs.

## Re-extracting the reference

None of this needs an account. The app ships its design system in public
static assets, and the sign-in page loads the whole set:

```js
[...document.querySelectorAll('link[rel=stylesheet], script[src]')].map((n) => n.href || n.src);
```

- **Tokens** live in one CSS chunk under `https://elevenlabs.io/app_assets/_next/static/chunks/*.css`
  (~930KB; one file carries every `:root` block). Pull the `:root` and `.dark`
  blocks and read the custom properties directly.
- **Component anatomy** lives in the JS chunks at the same path. They are
  compiled JSX, so the Tailwind class strings survive verbatim. Grep for
  `cva("` to recover the variant tables for Button, Badge and Input, and for
  `displayName="Table"` / `"DialogFooter"` to find the primitives.
- **Live measurement** is only needed to confirm which variant a real page
  uses. That does require signing in, and entering credentials is not something
  an agent should do — ask the account holder to sign in to a browser you can
  drive, then read computed styles.

Prefer re-extraction to inference. Several values below are counter-intuitive
enough that they would never be guessed correctly.

## The reference system

### Palette

The single most load-bearing idea: **hairlines, quiet fills and hover states
are translucent ink, not solid greys**. One value then works on white, on the
rail tint, and on a raised card.

| Role           | Reference        | Value               |
| -------------- | ---------------- | ------------------- |
| border         | `gray-alpha-150` | `rgba(0,0,0,0.075)` |
| quiet fill     | `gray-alpha-50`  | `rgba(0,0,0,0.02)`  |
| hover          | `gray-alpha-100` | `rgba(0,0,0,0.043)` |
| secondary text | `darken-500`     | `rgba(0,0,0,0.53)`  |
| muted text     | `darken-450`     | `rgba(0,0,0,0.44)`  |
| foreground     | —                | `#0f0f10`           |
| background     | —                | `#ffffff`           |
| rail           | `gray-50`        | `#fafafa`           |

The grey ramp underneath is fully achromatic (`0 0% N%`), and the alpha ladder
runs 2% / 3.2% / 4.3% / 7.5% / 10% / 16% / 44% / 53%.

### Type

Inter for the app, a proprietary face for display headings. Line heights and
tracking are part of the scale, not an afterthought — the large sizes carry
_negative_ tracking and the small sizes carry positive.

| Step | Size / line-height | Tracking   |
| ---- | ------------------ | ---------- |
| 2xs  | 10 / 16            | +0.0025em  |
| xs   | 12 / 16            | +0.0025em  |
| xm   | 13 / 20            | 0          |
| sm   | 14 / 20            | 0          |
| base | 16 / 24            | 0          |
| lg   | 18 / 26            | −0.0025em  |
| xl   | 20 / 28            | −0.005em   |
| 2xl  | 24 / 30            | −0.00625em |

Weight never carries hierarchy on its own. Nothing in the chrome is bold:
page title 24/400, dialog title 20/500, section label 16/500, body 14/400,
stat figure 18/500.

### Elevation

A hairline ring plus four decaying blurs, never one long drop shadow. This is
why raised surfaces read lifted instead of sitting in a grey halo:

```
0 0 0 1px rgba(0,0,0,.06), 0 1px 1px -.5px rgba(0,0,0,.06),
0 3px 3px -1.5px rgba(0,0,0,.06), 0 6px 6px -3px rgba(0,0,0,.06),
0 12px 12px -6px rgba(0,0,0,.04)          /* + 0 24px 24px -12px for the md step */
```

### Radii and control sizes

Radii: 6 / 8 / 10 / 12 / 16 / 24. Controls collapse onto a small number of
steps rather than being sized per-site:

| Step | Height | Padding | Radius | Text |
| ---- | ------ | ------- | ------ | ---- |
| 2xs  | 24     | 6       | 6      | 12   |
| xs   | 28     | 8       | 8      | 13   |
| sm   | 32     | 10      | 8      | 13   |
| md   | 36     | 12      | 10     | 14   |
| lg   | 40     | 16      | 12     | 14   |

Buttons carry **no shadow**. Primary is an ink fill with white text; outline is
white with an alpha border; ghost is transparent with an alpha hover.

### Tables

The part that most changes how a console reads:

- The table sits in a framed box — `1px` alpha hairline, `8px` radius, **no
  fill and no shadow** — so the grid reads as one object.
- Column labels are **13px sentence-case medium at full foreground ink**, in a
  40px row with 16px side padding. They are ordinary text, not the small
  uppercase letterspaced captions a spreadsheet uses.
- Cells are 14px with 16px side padding; rows separate with the same hairline.
- Widths are explicit per column with a table-level `min-width`, so a narrow
  viewport scrolls the table rather than crushing every column.

### Dialogs

- 512px wide, **24px corner**, 20px internal gap, 20px padding (32px on the
  larger picker dialogs), `shadow-natural-md`, no border.
- Scrim is **pale, not dark**: `gray-150 / 30%` plus a `2.5px` blur. The page
  stays legible behind the sheet; the sheet reads raised rather than spotlit.
- Title 20/500 at −0.5px tracking; description 14px secondary; footer actions
  right-aligned with a 10px gap.
- A full-bleed footnote strip (`-m-5 p-5 mt-0`, tinted, top hairline) is the
  house pattern for a caveat attached to a dialog.

### Rail

256px expanded. Rows are 32px tall with a 10px radius, inset 12px from the
edge, 4px apart, 14px medium **secondary** text that goes to full ink only when
active or hovered. Row actions (the `+`) are absolutely positioned and hidden
until the rail is hovered or focused. Width animates over 150ms; labels fade
and translate rather than unmounting.

### Toasts

A dark, faintly translucent slab over the white page — not a light card:

| Part                | Value                                                                                                          |
| ------------------- | -------------------------------------------------------------------------------------------------------------- |
| surface             | `rgba(33,33,33,0.85)` + blur                                                                                   |
| title / description | `#fafafa` / `rgba(255,255,255,0.71)`                                                                           |
| dots                | success `#8ab895`, error `#c5857f`, warning `#cfaa77`, info `#83a8cf`, default `#a1a5ab`, each with a 15% halo |
| shadow              | inset highlight + inset hairline + outer ring + two drop layers                                                |

### Motion

75ms for controls, 150ms for the rail, 200ms for dialogs and toasts.

## How it maps onto the Console

Everything lives in `apps/seams-console/src/core/dashboard/styles.css`, scoped
by class. Tokens are declared on `:root`.

| Reference idea         | Ours                                                                                                                                      |
| ---------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| alpha ladder           | `--dashboard-alpha-50` … `--dashboard-alpha-500`                                                                                          |
| border / hairline      | `--dashboard-border`, `--dashboard-line`                                                                                                  |
| secondary / muted text | `--dashboard-graphite`, `--dashboard-ash`                                                                                                 |
| radius ladder          | `--dashboard-radius-sm` … `--dashboard-radius-3xl`                                                                                        |
| stacked elevation      | `--dashboard-shadow-sm`, `--dashboard-shadow-md`                                                                                          |
| motion steps           | `--dashboard-motion-fast` / `-item` / `-sidebar`                                                                                          |
| shell metrics          | `--dashboard-sidebar-width`, `--dashboard-topbar-height`                                                                                  |
| framed table           | `.dashboard-data-table`                                                                                                                   |
| column label           | `.dashboard-data-table__header-cell`                                                                                                      |
| pill badge             | `.dashboard-data-table__badge`, `.dashboard-data-table__status`                                                                           |
| control step           | `.dashboard-pagination-button`, `.dashboard-input`, `.dashboard-search-control`, `.dashboard-select-control`, `.dashboard-policy-segment` |
| dialog sheet           | `.dashboard-modal`                                                                                                                        |
| dialog scrim           | `.dashboard-overlay-layer--modal-open`                                                                                                    |
| page title             | `.dashboard-main__title`                                                                                                                  |
| section label          | `.dashboard-view__section h2`                                                                                                             |
| stat strip             | `.dashboard-kpi-card__*`, `.dashboard-observability-summary__*`                                                                           |
| rail row               | `.dashboard-nav-item`, `.dashboard-nav-label`                                                                                             |
| command palette        | `.dashboard-command-palette`                                                                                                              |
| toast host             | `.dashboard-toaster`, `.dashboard-toast`                                                                                                  |

## Deliberate divergences

- **Typeface.** We keep Hanken Grotesk. The reference uses Inter plus a
  proprietary display face; switching would decouple the Console from the
  marketing site for no gain the user can name.
- **Warmth.** Our alpha ladder is mixed from `rgb(28,24,23)` rather than pure
  black, so it keeps a trace of the marketing site's warmth. Over white it
  resolves within a point of neutral, so the mechanic is unchanged.
- **Accent.** Seams green (`--dashboard-accent`) stays. It is a product accent
  and never plain chrome.
- **Stat strips** are static figures. The reference makes them selectable tabs
  that drive the chart below; that is behaviour we have not adopted.

## Gotchas

These cost real debugging time. They are not obvious from the CSS.

- **Tokens must be on `:root`, not on the shell.** The command palette portals
  to `<body>` to escape the top bar's `backdrop-filter` containing block. Any
  token scoped to `.dashboard-shell` resolves to nothing out there, and
  `background: var(--dashboard-surface)` silently renders transparent.
- **`backdrop-filter` creates a containing block** for `position: fixed`
  descendants. A translucent top bar will capture any fixed overlay rendered
  inside it — this is why ⌘K is portalled.
- **`text-overflow: ellipsis` cannot reach a bare text child of a grid
  container.** It becomes an anonymous grid item. Truncating cells must be
  `display: block`.
- **A badge in a grid cell stretches** unless it is given `width: fit-content`
  and `justify-self: start`.
- **sonner writes its theme variables inline** on the toast list element, so
  `--normal-bg` and friends cannot be overridden from a stylesheet. Set the
  surface on the toast element directly, and pass `--width` as a prop.
- **sonner renders nothing until a toast exists.** An absent
  `[data-sonner-toaster]` in the DOM does not mean the host failed to mount.
- **Cascade order beats longhand-versus-shorthand intuition.** A `padding-top`
  declared earlier in the file loses to a `padding` shorthand declared later on
  the same selector.
- **Applying `justify-content` while a width transitions causes a visible
  jump.** Interpolate padding instead; the rail wordmark flicked right on
  collapse until this changed.

## Verifying a change

The Console is served by its own Vite server on `localhost:3601` under
`/dashboard-static/`, proxied by Caddy at `https://localhost/dashboard/*`. It
needs the API env the launcher provides, or it falls back to
`window.location.origin` and every Console call lands on the marketing site:

```
VITE_CONSOLE_BASE_URL=https://localhost:9444 VITE_RELAYER_URL=https://localhost:9444 \
VITE_WALLET_ORIGIN=https://localhost:8443 pnpm -C apps/seams-console dev
```

For visual work, drive it headlessly and assert computed styles rather than
eyeballing screenshots — sizes in a 2× capture are easy to misread. Check for
horizontal overflow at 1680 / 1440 / 1180 / 980 / 760 before calling a layout
change done.

Note that `apps/seams-console/src` is **not** Prettier-clean at HEAD. Format
only the files you edited; a tree-wide `prettier --write` reformats ~18
untouched files and buries the real diff.
