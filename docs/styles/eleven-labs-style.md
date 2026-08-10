# ElevenLabs-inspired interface style

This document defines the visual direction for the Seams frontend application and console. The style takes cues from ElevenLabs: white paper, black ink, warm stone neutrals, sparse color, compact typography, strong alignment, and low-chrome layouts. It remains a Seams design through its product colors, gradient artwork, diagrams, and transaction-signing surfaces.

Use this guide when creating or revising UI in `apps/seams-site`. The SDK theming contract remains documented separately in [`apps/docs/src/getting-started/theming.md`](../../apps/docs/src/getting-started/theming.md).

## Design principles

1. **Paper is the canvas.** Most pages use white as the page and primary surface. Warm neutral fills separate supporting regions without making every region look like a card.
2. **Ink carries hierarchy.** Black and graphite establish emphasis. Muted taupe text supports labels and metadata.
3. **Color has a job.** Green identifies Seams product concepts and success. Amber and red communicate status. Blue is reserved for the SDK Paper theme and selected technical details.
4. **Space creates groups.** Prefer padding, gaps, and aligned edges before adding a separator or container.
5. **Borders stay quiet.** Hairlines establish structure. Stronger borders appear on focus, selection, and controls that need a visible boundary.
6. **Chrome recedes.** Navigation, filters, and tables should feel light enough that content and decisions remain dominant.
7. **Motion confirms state.** Use short color and opacity transitions. Layout motion should remain smooth, interruptible, and free of bounce.

## Sources of truth

| Area                                                                  | Source                                                                                                                               |
| --------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| Marketing palette, typography, content rail, cards, and section rules | [`apps/seams-site/src/styles/h2.css`](../../apps/seams-site/src/styles/h2.css)                                                       |
| Site semantic aliases and global typography                           | [`apps/seams-site/src/app.css`](../../apps/seams-site/src/app.css)                                                                   |
| Navigation structure and light appearance                             | [`apps/seams-site/src/components/Navbar/Navbar.css`](../../apps/seams-site/src/components/Navbar/Navbar.css)                         |
| Console palette, shell, forms, tables, and responsive behavior        | [`apps/seams-site/src/pages/dashboard/styles.css`](../../apps/seams-site/src/pages/dashboard/styles.css)                             |
| SDK Paper theme and other demo presets                                | [`apps/seams-site/src/context/app-themes.ts`](../../apps/seams-site/src/context/app-themes.ts)                                       |
| SDK geometry presets                                                  | [`packages/sdk-web/src/react/components/theme/design-tokens.ts`](../../packages/sdk-web/src/react/components/theme/design-tokens.ts) |
| ElevenLabs-inspired gradient assets                                   | [`apps/seams-site/src/public/gradients/README.md`](../../apps/seams-site/src/public/gradients/README.md)                             |

Prefer the variables and component patterns already defined in these files. Add a semantic token only when no existing role describes the value.

## Shared visual foundation

### Core palette

The marketing app and console share a pinned light paper palette.

| Role                       | Marketing token   | Console token                               | Reference value       |
| -------------------------- | ----------------- | ------------------------------------------- | --------------------- |
| Canvas and primary surface | `--h2-bg`         | `--dashboard-bg`, `--dashboard-surface`     | `#ffffff`             |
| Quiet surface              | `--h2-taupe`      | `--dashboard-surface-soft`                  | `#f5f3f1`             |
| Structural hairline        | `--h2-line`       | `--dashboard-line`                          | `#f2f0ed` / `#eeece8` |
| Component outline          | `--h2-stone`      | `--dashboard-border`                        | `#ebe8e4`             |
| Strong or active outline   | `--h2-ash`        | `--dashboard-active-border`                 | `#a59f97`             |
| Primary text               | `--h2-ink`        | `--dashboard-ink`                           | `#0a0a0a`             |
| Secondary text             | `--h2-graphite`   | `--dashboard-graphite`                      | `#44403b`             |
| Tertiary text              | `--h2-smoke`      | `--dashboard-ink-soft`                      | `#777169`             |
| Muted labels               | `--h2-ash`        | `--dashboard-ash`                           | `#a59f97`             |
| Seams accent and success   | `--h2-green`      | `--dashboard-accent`, `--dashboard-success` | `#157f5f`             |
| Soft success surface       | `--h2-green-soft` | `--dashboard-success-soft`                  | `#e4f0eb`             |
| Warning                    | `--h2-amber`      | `--dashboard-warning`                       | `#b45309`             |
| Danger                     | `--h2-red`        | `--dashboard-danger`                        | `#b91c1c`             |

The SDK Paper preset uses the same white and warm-neutral foundation with a blue accent:

- Primary and focus: `#6f9fd8`
- Strong technical highlight: `#4a6fa5`
- Primary action: `#000000`
- Secondary action: white with `#dcd6cd` border
- Error: `#ff4704`

The two accent systems serve different contexts. Use green for marketing and console product meaning. Use the Paper preset's blue inside embedded wallet and signing demonstrations where the preset already provides it.

### Applying color

- Fill the single primary action with ink or the established product color. Keep adjacent secondary actions white or neutral.
- Use `--h2-green` and `--dashboard-accent` for product concepts, selected technical details, and success. Plain navigation chrome remains neutral.
- Use status colors with a soft companion surface. Avoid large saturated blocks.
- Use semantic variables in component CSS. Raw hex values are appropriate only for a deliberately pinned palette or a new token definition.
- Check foreground and background contrast in the rendered state. Reserve muted text for supporting information; required instructions use higher contrast.
- Keep the marketing page and console light and theme-independent. SDK-owned surfaces may support light and dark appearances through their theme boundary.

### Gradient artwork

Gradients provide editorial color and brand texture. They work best as bounded artwork:

- Use the supplied blurred, grainy gradient images for cover cards, diagrams, small badges, and empty-state accents.
- Keep the source crop varied across repeated cards.
- Add a low-opacity inset outline when a pale gradient meets a white surface.
- Preserve a matte, subtly textured finish. Avoid visible fabric threads, lens flares, interface mockups, and text baked into background assets.
- Do not stretch the current 1024 px sources into full-bleed hero backgrounds; their intended rendered size is approximately 340 px wide.

## Frontend application guide

This section covers the public marketing and product pages under the `h2` styles.

### Page composition

- Use a centered content rail with `--h2-col-max: 1120px`.
- At desktop widths, place `1px` structural borders on both sides of the rail. Remove those borders at `1160px` and below.
- Use `.h2-shell` for the content inset: `36px` on desktop and `22px` at `760px` and below.
- Use generous vertical sections. The established default is `86px`; the snug variant uses `64px 0 14px`.
- Align headings, body copy, cards, and navigation to the same rail edges. Small optical exceptions should remain local to icons or artwork.
- Let full-width background treatments and rules bleed outward while text and controls stay inside the content inset.

### Marketing hierarchy

- Lead with a type-first hero. The simple hero uses a maximum headline width of `688px` and body copy near `504px`.
- Use split section headers for editorial rhythm: a `7fr / 5fr` headline-to-copy grid with a restrained gap. Collapse the split to one column at `900px`.
- Use one- or two-column product panels for primary stories and three-column grids for compact use cases. Collapse multi-column marketing grids when their contents stop fitting, currently around `900–980px`.
- Group related items with space and a shared surface. Add dividers only when rows need scanning support or a section boundary needs to span the viewport.

### Typography

The primary family is Hanken Grotesk with the existing system sans-serif fallback. Use the system monospace stack for technical labels, identifiers, and code.

- Display headlines use weight `300–400`, line-height near `1.04–1.1`, and slightly negative letter spacing.
- Section headlines use responsive `clamp()` sizes and `text-wrap: balance` where a short heading may wrap.
- Body copy generally uses `14–15.5px`, line-height `1.48–1.6`, and a bounded measure.
- Card titles use medium or semibold weight. Supporting copy uses smoke text and a comfortable line-height.
- Kicker labels use monospace, uppercase transformation, `0.12–0.14em` letter spacing, and muted color. Keep the source copy in natural case when practical and apply capitalization through CSS.
- Use tabular numerals for changing counts, balances, prices, and timestamps.
- Keep meaningful identifiers reachable when truncation is necessary. Allow long addresses and hashes to wrap where the layout can support it.

### Navigation

- Keep the desktop navbar flat and aligned to the page rail.
- Use a translucent white surface with an `8px` backdrop blur and a single bottom hairline.
- Keep the navbar shell square against the viewport. Pills belong to triggers, actions, and small navigation controls.
- Use compact plain-text labels and quiet hover fills.
- Dropdowns may use a shadow because they float above the page. Static navbar chrome should not.

### Buttons and controls

- Public marketing CTAs use full pills. The standard height is `36px`; the large variant is `40px`.
- Primary CTAs use black with white text and a `#262626` hover state.
- Outline CTAs use a white face and stone border, with a taupe hover fill.
- Keep labels short, sentence case, and action-led.
- Use exact transitions for background, border, and color, typically `150ms`.
- Do not move controls vertically on hover. State changes come from color, border, icon, or shadow.

### Cards and product visuals

- Use `22px` for large marketing panels and `14px` for image covers or inner canvases.
- Use warm neutral fills for large panels. A border is optional when surface contrast already defines the edge.
- Use `13–16px` radii for product mockups and contained application windows.
- Keep paired cards visually balanced through equal padding and bottom-aligned visual regions.
- Use inset outlines on images and gradient covers. Reserve drop shadows for visibly elevated mock windows or overlays.

## Console guide

The console extends the paper style into a denser operational interface. It stays light so the transition from marketing, login, and day-to-day administration feels continuous.

### Shell and navigation

- Use a two-column desktop shell: a `264px` sidebar and a flexible content region.
- The collapsed desktop rail is `60px`. Icons remain anchored while labels fade and clip during the width transition.
- The top bar is at least `56px` high and uses a single bottom border.
- At `1160px` and below, stack the top bar, sidebar, and main content. The sidebar receives a bottom border and a bounded height.
- At `980px` and below, reduce main padding to `16px`, stack filter controls, and simplify the top bar.
- Navigation rows use quiet fills for hover and active states. Active primary navigation has no accent edge or shadow.
- Use `1.6px` icon strokes with regular navigation text. Keep one outline icon family across the console.

### Main content

- Use `22px 24px 42px` main padding on desktop and a `14px` base content gap.
- Page titles use approximately `1.75rem`, semibold weight, and slight negative letter spacing.
- Prefer open sections with clear headings over nesting every group inside a bordered card.
- Use compact toolbars and filter rows above the content they control. Let them wrap or stack before labels and actions become cramped.
- Keep overlays in a dedicated layer over the main grid cell. Modal backdrops use restrained tint and blur.

### Tables and data density

Console tables follow the clearest ElevenLabs-derived pattern in the codebase:

- Keep the outer table borderless, radius-free, transparent, and free of shadow.
- Use sentence-case, medium-weight headers in muted ink.
- Separate the header and rows with horizontal hairlines. Avoid vertical cell borders.
- Use `10px 12px` header padding and `14px 12px` cell padding as the default density.
- Use a quiet taupe row hover.
- Align values by meaning: labels to the start, comparable numbers to the end, and compact actions consistently.
- Use `overflow-wrap` for IDs and structured values. Truncate only when the complete value remains available through a detail view or accessible tooltip.
- Use tabular numerals for balances, metrics, dates, durations, and changing counts.
- Give empty states a short explanation and a clear next action. A small gradient disc may add visual identity without turning the empty state into an illustration panel.

### Forms and actions

- Keep form widths intentional. The login form uses a maximum width of `384px`; dense filters use flexible grid tracks that collapse to one column.
- Use visible labels. Placeholders demonstrate format or expected content.
- Primary actions carry the strongest fill. Secondary and tertiary actions use neutral faces, borders, or text treatment.
- Focus states need a visible ring or stronger border using the established focus color.
- Error text states the issue and the recovery step. Destructive confirmation buttons repeat the consequence.
- Inputs should remain at least `16px` on mobile to avoid browser zoom.

### Panels, metrics, and status

- Default console panels use a `1px` neutral outline, `12–16px` radius, and white surface.
- Prefer borderless plain sections for large operational views where headings and spacing already establish grouping.
- Connected overview grids may use one outer border with shared internal dividers. Remove doubled borders where cells meet.
- Status banners combine a semantic border, soft background, and readable ink derived from the same status family.
- Reserve strong shadows for menus, command palettes, and modals that visibly float above the shell.

## Layout rules

### Grouping and alignment

- Space within a group should be visibly tighter than space between groups. A useful target is an inter-group gap at least twice the intra-group gap.
- Choose a small number of shared alignment edges per page. Misaligned card text, headings, and toolbars create more noise than a missing decoration.
- Keep controls visually distinct from static content through shape, border, fill, or consistent placement.
- Put primary information near the top and leading edge. Place supporting metadata beneath or after it.
- Use logical CSS properties for new direction-sensitive spacing and positioning.

### Responsive behavior

Use the current breakpoints as evidence of where the established layouts stop fitting:

| Width              | Current behavior                                                                                       |
| ------------------ | ------------------------------------------------------------------------------------------------------ |
| Above `1160px`     | Marketing side rails are visible; console uses a sidebar column and may collapse to an icon rail.      |
| `1160px` and below | Marketing side rails and decorative ticks disappear; console stacks its sidebar above the main region. |
| `980px` and below  | Dense console grids and toolbars simplify; main padding becomes `16px`.                                |
| `900px` and below  | Marketing split headers, product grids, workflow rows, and console login split become one column.      |
| `760px` and below  | Marketing shell padding becomes `22px`.                                                                |

New components should break at the width where their content becomes cramped. Avoid adding a new breakpoint when an established one fits the same layout transition.

### Reading order and overflow

- Keep DOM order aligned with visual order when grids collapse.
- Allow labels and descriptive copy to wrap. Use fixed widths only for stable chrome such as the desktop sidebar.
- Keep critical actions in normal flow or stable chrome where resizing cannot clip them.
- Use `overflow-x: clip` only for decorative full-bleed rules. Data surfaces that genuinely overflow need an explicit scrolling or responsive strategy.

## Border design

Borders communicate structure in this style. Each border should have one clear reason to exist.

### Border hierarchy

| Level                    | Typical color                   | Use                                                                  |
| ------------------------ | ------------------------------- | -------------------------------------------------------------------- |
| Structural hairline      | `#f2f0ed` or `#eeece8`          | Page rails, section rules, table rows, large grid divisions          |
| Component outline        | `#ebe8e4`                       | Inputs, secondary buttons, panels, dropdown rows, contained diagrams |
| Strong or active outline | `#d6d1cb` to `#a59f97`          | Hover, focus support, selection, active controls                     |
| Semantic outline         | Mixed from green, amber, or red | Status and validation states only                                    |

### Approved patterns

- **Bordered content rail:** one hairline on each side at wide desktop sizes.
- **Full-bleed section rule:** a single horizontal hairline extending beyond the content rail. Decorative corner ticks may mark the rail intersection.
- **Quiet component outline:** one neutral `1px` border around a control or compact panel.
- **Connected grid:** one outer border plus shared internal dividers, with adjacent edges deduplicated.
- **Borderless data table:** horizontal row dividers provide rhythm; the table has no outer box or vertical cell borders.
- **Image outline:** a low-opacity `1px` inset outline preserves the edge of pale artwork.
- **Focus ring:** a visible outline or ring outside the resting border. Focus must remain distinguishable from hover.

### Radius scale

| Radius    | Use                                                                          |
| --------- | ---------------------------------------------------------------------------- |
| `0`       | Page rails, flat navbar shell, tables, connected grid cells                  |
| `6–10px`  | Compact controls, nav rows, inputs, small chips with rectangular geometry    |
| `12–16px` | Console panels, dropdowns, product windows, inner canvases                   |
| `22px`    | Large marketing cards and feature panels                                     |
| `9999px`  | Marketing CTAs, search fields, avatars, status pills, compact round controls |

For nested rounded surfaces, keep corners concentric: the outer radius should equal the inner radius plus the surrounding padding. The SDK's `square` preset remains the default ElevenLabs-inspired geometry for embedded components: `16px` cards, `10px` controls and fields, and `44px` control heights.

### Patterns to avoid

- Repeated boxes around every section.
- Borders between every table cell.
- One-sided accent borders on rounded cards.
- Decorative colored borders on neutral navigation chrome.
- A heavy border and a strong shadow on the same static surface.
- Equal radii on nested surfaces with visible padding.
- Borders used solely to simulate elevation.

## Elevation and motion

- Static content usually sits directly on the paper canvas or a quiet taupe surface.
- Use shadows for actual elevation: dropdowns, command palettes, modals, and floating product mockups.
- Use specific transition properties. Avoid `transition: all`.
- Use approximately `140–160ms` for hover and focus color changes.
- Use the console's `220–280ms` timing for sidebar and label layout transitions.
- Keep animations interruptible. Use opacity, clipping, and small fixed transforms for state changes.
- Avoid bounce and hover lift effects.
- Honor `prefers-reduced-motion` for nonessential movement.

## Interface copy

- Use sentence case for headings, buttons, settings, table headers, and navigation labels.
- Start action labels with a specific verb: “Create project,” “Save policy,” or “Copy ID.”
- Use the same term throughout a flow. Avoid alternating between synonyms for the same object or action.
- Keep errors calm and actionable. State what failed and how to recover.
- Write empty states as orientation plus a next step.
- Use descriptive link text that remains understandable outside its surrounding paragraph.

## Implementation checklist

Before shipping a new or revised surface, confirm:

- The component consumes existing semantic tokens.
- The primary action is visually singular.
- The layout aligns to the established rail or console grid.
- Space establishes grouping before borders are introduced.
- Every border has a structural, interactive, or semantic role.
- Nested radii are concentric.
- Marketing artwork uses gradients as bounded editorial accents.
- Console tables remain borderless at the outer edge and use horizontal row rules.
- Text wraps at narrow widths and long identifiers have an intentional overflow behavior.
- Focus is visible, contrast is sufficient, and status does not depend on color alone.
- Motion uses explicit properties and respects reduced-motion preferences.
- The result has been checked at wide desktop, `1160px`, `980px`, `900px`, and a narrow mobile width relevant to the component.
