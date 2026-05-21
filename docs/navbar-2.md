# Navbar 2 Plan

## Goal

Update the frontpage navbar in `examples/seams-site` so it uses a simplified `Products`
dropdown with Guides, Tools, and Use cases, an AccessGrid-style `Pricing` dropdown with
three pricing tiles, and the AccessGrid desktop dropdown mechanics from
`https://accessgrid.com/guides` while keeping the Seams color palette and theme tokens.

The target implementation should feel like a single continuous surface: the top nav,
dropdown shell, active dropdown content, and footer CTA should transition through one
shared container instead of opening separate independent panels.

## Source Research

AccessGrid uses a small state controller and lets CSS do the visual work:

- Desktop header source: `header[data-controller="website-nav"]`
- Desktop trigger targets: `developersTrigger`, `pricingTrigger`
- Shared dropdown target: `popup`
- Content targets: `developersContent`, `pricingContent`
- Controller source: `https://accessgrid.com/assets/controllers/website_nav_controller-5f8872c274cdd09c5e8deda7438f1298af1878ca340330e7de6fb80a440198aa.js`
- Page source: `https://accessgrid.com/guides`

The controller only tracks the active content id. On trigger hover it sets
`popup.dataset.active = true`, sets the active content element dataset to `true`, and
sets every inactive content element dataset to `false`. The CSS uses the same mounted
popup shell for every menu, then slides each content pane horizontally through that shell.

Desktop measurements from Chromium at a 1418px CSS viewport:

- Header: fixed, centered, `top: 26px`, `min-width: 586px`, rendered size `586 x 52`.
- Nav surface: `padding: 6px 8px 6px 20px`, `border-radius: 16px`,
  `background: rgba(247, 247, 248, 0.9)`, `backdrop-filter: blur(4px)`.
- Nav shadow: `0 1px 1px rgba(38,38,43,.10)`, `0 0 0 1px rgba(38,38,43,.04)`,
  `0 2px 12px -4px rgba(38,38,43,.16)`.
- Trigger buttons: `height: 40px`, `padding: 8px 8px 8px 12px`, `border-radius: 10px`,
  `font-size: 13px`, `line-height: 24px`, `font-weight: 500`, `letter-spacing: -0.13px`,
  `gap: 8px`.
- Trigger hover and active background: AccessGrid gray `#eeeef0`; map this to a subtle
  `color-mix` using `--navbar-surface2` and the existing Seams border token.
- Popup outer: absolute below nav with `top: calc(100% - 8px)`, `padding-top: 24px`,
  `width: 100%`, transform origin top, inactive `opacity: 0`, `scale: .9`,
  `pointer-events: none`; active `opacity: 1`, `scale: 1`, `pointer-events: auto`.
- Popup outer transition: `all 300ms cubic-bezier(0, 0, 0.2, 1)`.
- Popup card: `border-radius: 16px`, translucent surface, `backdrop-filter: blur(12px)`,
  `overflow: hidden`.
- Popup card shadow: `0 24px 40px -20px rgba(38,38,43,.30)`,
  `0 10px 24px rgba(38,38,43,.06)`, `0 1px 1px rgba(38,38,43,.16)`,
  `0 0 0 1px rgba(38,38,43,.05)`, `0 8px 14px -10px rgba(38,38,43,.40)`.
- Popup inner padding: 4px around the top grid, then a footer strip.
- Top grid shell: `578 x 490`, `border-radius: 12px`, `overflow: hidden`,
  `background: white`, inner divider background `#eeeef0`, `gap: 2px`.
- Content pane transition: `all 250ms cubic-bezier(0.5, 1, 0.89, 1)`.
- Content pane active state: `opacity: 1`, `translateX(0)`, `pointer-events: auto`.
- Content pane inactive to the right: `opacity: 0`, `translateX(80px)`.
- Content pane inactive to the left: `opacity: 0`, `translateX(-80px)`.
- At 125ms during Developers to Pricing switch, the old pane was about
  `opacity: .286`, `translateX(-57px)`, and the new pane was about `opacity: .714`,
  `translateX(23px)`. This is the interaction signature to match.
- Footer CTA panes use the same 250ms opacity and horizontal transform as the top pane.
- Desktop popup has no arrow/notch; the 24px top padding makes the popup visually attach
  to the nav while allowing hover movement between trigger and dropdown.

Mobile AccessGrid notes:

- Mobile header is separate under `md:hidden`.
- It uses `data-open` and `data-submenu` on the header.
- Open/close height is measured with `ResizeObserver`.
- Main menu and submenu panes transition with
  `270ms cubic-bezier(0.33, 1, 0.68, 1)`.
- Bottom CTA area height switches over `270ms`, with submenu footer opacity using `500ms`.

## Current Seams Navbar

Primary files:

- `examples/seams-site/src/components/Navbar/NavbarStatic.tsx`
- `examples/seams-site/src/components/Navbar/Navbar.css`
- Frontpage entry: `examples/seams-site/src/pages/home/page.tsx`

Current shape:

- `DropdownId = 'products' | 'about'`
- Desktop order is `Products`, `Pricing`, `Documentation`, `About Us`
- Products uses a simplified AccessGrid-style three-tile panel.
- Pricing uses an AccessGrid-style three-tile panel.
- About uses the same popup shell with its own section-list pane.
- Mobile menu has products, pricing, and about submenus.

Required shape:

- `DropdownId = 'products' | 'about'`
- One simplified `Products` dropdown containing exactly `Guides`, `Tools`, and
  `Use cases`.
- One `Pricing` dropdown containing exactly `Embedded Wallets`,
  `Access Passes with account recovery`, and `Biometric Authentication`.
- Desktop order: `Products`, `Pricing`, `Documentation`, `About Us`.
- Mobile order: `Products`, `Pricing`, `Documentation`, `About Us`, then CTA row.
- Pricing should sit beside Products and use the same dropdown shell.

## Interaction Design

Implement desktop as one persistent popup shell with content panes:

```ts
type DropdownId = 'products' | 'about';

type DropdownPanePosition = 'left' | 'active' | 'right';

type DropdownContentPane = {
  id: DropdownId;
  label: string;
  layout: 'product-tiles' | 'sections';
  footer: DropdownFooterCta;
};
```

The active dropdown state should only decide:

- whether the shared popup shell is open
- which content pane is active
- which inactive panes sit left or right for the slide direction

Keep hover intent simple:

- Open on trigger `mouseenter` and focus.
- Keep open when pointer enters the popup.
- Close on popup leave, outside pointer down, Escape, and route click.
- Use a short close grace of about `120ms` if needed for local ergonomics. AccessGrid has
  no close delay, because the popup starts above its card with a 24px bridge region.
- Remove the current notch math: delete `dropdownSurfaceLeft`, `dropdownNotchLeft`,
  `getDropdownMaxWidthPx`, and the CSS pseudo-elements for the notch.

The “meld” effect depends on two rules:

1. The dropdown shell never remounts when switching menus.
2. The old and new content panes occupy the same grid cell and cross-slide through the
   same clipped card.

## Desktop Layout Spec

Map the AccessGrid structure into `NavbarStatic.tsx`:

```tsx
<nav className="navbar-static" aria-label="Primary">
  <div className="navbar-static__shell">
    <div className="navbar-static__nav-row">...</div>
    <div className="navbar-static__access-popup" data-open={openDropdown ? 'true' : 'false'}>
      <div className="navbar-static__access-card">
        <div className="navbar-static__access-grid-shell">{dropdownPanes.map(renderPane)}</div>
        <div className="navbar-static__access-footer-shell">{dropdownPanes.map(renderFooter)}</div>
      </div>
    </div>
  </div>
</nav>
```

Use CSS grid stacking:

```css
.navbar-static__access-grid-shell,
.navbar-static__access-footer-shell {
  display: grid;
}

.navbar-static__access-pane,
.navbar-static__access-footer {
  grid-area: 1 / 1;
}
```

Desktop shell styling:

- Keep `position: fixed` on `.navbar-static`.
- Change desktop shell width from the current broad `min(1420px, calc(100vw - 2rem))`
  to a content-fit AccessGrid shell. Use `width: max-content` and `min-width` based on
  our labels, with responsive caps:
  - `min-width: 640px` for desktop.
  - `max-width: calc(100vw - 2rem)`.
- Use one row with left logo, center links, and right actions. Keep the current Seams logo
  and color tokens.
- Port AccessGrid surface proportions:
  - desktop `top: 26px`
  - shell/nav row radius `16px`
  - nav row padding `6px 8px 6px 20px`
  - trigger height `40px`
  - trigger radius `10px`
  - trigger gap `8px`
  - trigger font `13px / 24px`, weight `500`
- Keep current CTA labels and auth behavior unless product asks otherwise.

Desktop popup styling:

- `.navbar-static__access-popup`
  - `position: absolute`
  - `top: calc(100% - 8px)`
  - `left: 0`
  - `width: 100%`
  - `padding-top: 24px`
  - `opacity: 0`
  - `transform: scale(.9)`
  - `transform-origin: top center`
  - `pointer-events: none`
  - `transition: opacity 300ms cubic-bezier(0,0,.2,1), transform 300ms cubic-bezier(0,0,.2,1)`
- `.navbar-static__access-popup.is-open`
  - `opacity: 1`
  - `transform: scale(1)`
  - `pointer-events: auto`
- `.navbar-static__access-card`
  - `border-radius: 16px`
  - `overflow: hidden`
  - `background` from Seams `--navbar-surface` tokens with `.90` alpha
  - `backdrop-filter: blur(12px)`
  - AccessGrid shadow geometry using Seams shadow colors
- `.navbar-static__access-grid-shell`
  - `margin: 4px`
  - `border-radius: 12px`
  - `overflow: hidden`
  - `background` from `--navbar-border` or `--navbar-surface2` to create 2px dividers
  - fixed desktop height near `490px`, with content-specific rows allowed only if all
    panes keep the same outer height.
- `.navbar-static__access-pane`
  - transition `opacity 250ms cubic-bezier(.5,1,.89,1), transform 250ms cubic-bezier(.5,1,.89,1)`
  - active: `opacity: 1`, `transform: translateX(0)`, `pointer-events: auto`
  - before active: `opacity: 0`, `transform: translateX(-80px)`, `pointer-events: none`
  - after active: `opacity: 0`, `transform: translateX(80px)`, `pointer-events: none`

## Dropdown Content

Products should include exactly three entries inside one AccessGrid-style panel:

- Left large tile: “Guides”, spanning two rows.
- Right top tile: “Tools”.
- Right bottom tile: “Use cases”.

Avoid small independent cards. Use AccessGrid-like large tiles separated by 2px dividers,
with title and description in the upper-left and subtle line-art visuals clipped into the
remaining tile space.

Pricing should include exactly three entries in the AccessGrid pricing reference layout:

- Left top tile: “Embedded Wallets”.
- Left bottom tile: “Access Passes with account recovery”.
- Right large tile: “Biometric Authentication”, spanning two rows.

Use the same shared popup shell, pane transition, clipped line-art style, and footer strip
as Products.

Footer CTA panes:

- Products footer:
  - icon: documentation or wallet icon
  - title: “Developer documentation”
  - copy: “Build embedded wallets and policy-controlled signing flows.”
  - button: “Read docs”
  - link: `/docs/getting-started/overview`
- About footer:
  - icon: company or contact icon
  - title: “Talk to the Seams team”
  - copy: “Plan a wallet integration or review a security-sensitive flow.”
  - button: “Contact sales”
  - link: `/contact/`

About dropdown can use the same shell with a smaller content set. Keep the shell width
constant during desktop switching so the surface never resizes while crossing between
Products and About. If About feels sparse, add “Company”, “Blog”, and “Support” tiles plus
the contact footer.

## TypeScript State Cleanup

Apply the repo TypeScript rules while changing nav state:

- Replace `DropdownId = 'products' | 'solutions' | 'about'` with
  `DropdownId = 'products' | 'about'`.
- Delete `solutionSections` and any product/solution list config that is no longer needed.
- Model product content as a branch-specific tile layout:

```ts
type ProductDropdownPane = {
  id: 'products';
  layout: 'product-tiles';
  tiles: ProductDropdownTile[];
  sections?: never;
};
```

- Model pane position with a discriminated helper return instead of booleans:

```ts
type PaneVisualState = { kind: 'active' } | { kind: 'before' } | { kind: 'after' };
```

- Use an exhaustive `switch` to map `PaneVisualState` to class names.
- Keep route strings inside typed config objects.
- Avoid broad object spreads when constructing dropdown pane data.
- Remove obsolete state:
  - `leavingDropdown`
  - `switchTimerRef`
  - `dropdownSurfaceLeft`
  - `dropdownNotchLeft`
  - `getDropdownMaxWidthPx`
  - `ABOUT_DROPDOWN_MAX_WIDTH_PX`
  - `DEFAULT_DROPDOWN_MAX_WIDTH_PX`
- Keep core inputs narrow: functions that render panes should accept a `DropdownContentPane`
  and an already-derived `PaneVisualState`.

## Mobile Plan

Keep the current mobile menu implementation style, then align it with the new IA:

- Remove `isMobileSolutionsOpen`.
- Products submenu contains only Guides, Tools, and Use cases.
- Add a Pricing submenu immediately after Products with Embedded Wallets, Access Passes
  with account recovery, and Biometric Authentication.
- Keep Documentation and About below Pricing.
- Consider AccessGrid’s measured-height pattern only if the current mobile display jumps:
  - use `ResizeObserver`
  - animate menu height over `270ms cubic-bezier(.33,1,.68,1)`
  - animate submenu content translate/opacity over the same duration

Since the user request centers on the desktop dropdown style, preserve current mobile
layout unless visual testing shows obvious mismatch after the IA change.

## CSS Migration Steps

1. Replace dropdown surface CSS.
   - Remove `.navbar-static__dropdown-surface::before` and `::after`.
   - Remove notch variables.
   - Add AccessGrid-style popup, card, grid shell, pane, footer shell, and footer pane
     classes.

2. Replace content card CSS.
   - De-emphasize current card gradients.
   - Use large tile layout with 2px dividers, clipped illustrations, 12px inner radius,
     and no nested card chrome.

3. Tune nav row CSS.
   - Use AccessGrid spacing and radius.
   - Keep Seams `--navbar-*` variables for surfaces, text, focus, border, and primary.
   - Keep the current theme toggle and dashboard auth behavior.

4. Add reduced motion support.
   - For `.navbar-static__access-popup`, panes, footers, chevrons, and mobile menu, set
     transitions to `none !important` under `prefers-reduced-motion: reduce`.

5. Remove obsolete CSS selectors.
   - Delete old dropdown view/card/all classes only after TSX no longer references them.
   - Keep mobile selectors that still map to active JSX.

## Implementation Steps

1. Update `NavbarStatic.tsx` types.
   - Merge dropdown IDs.
   - Add `ProductDropdownPane`, `SectionDropdownPane`, `DropdownFooterCta`, and
     `PaneVisualState`.
   - Add an `assertNever` helper if this file does not already have one.

2. Simplify Products content.
   - Replace product and solution sections with three `ProductDropdownTile` entries:
     Guides, Tools, and Use cases.
   - Delete the `Solutions` trigger.
   - Keep `Pricing` immediately after the Products trigger.

3. Add Pricing content.
   - Add a `PricingDropdownPane` branch with three `PricingDropdownTile` entries.
   - Place Pricing in `dropdownPanes` between Products and About.
   - Use the same dropdown trigger renderer as Products.

4. Replace desktop dropdown rendering.
   - Render one popup after the nav row.
   - Stack all panes in the same grid area.
   - Stack all footer CTAs in the same grid area.
   - Derive before/active/after visual state from pane order and `openDropdown`.

5. Replace desktop dropdown state.
   - Use `openDropdown: DropdownId | null`.
   - Keep timers only for open/close grace.
   - Delete content switch timers and notch positioning effects.
   - Keep keyboard controls: Enter/Space/ArrowDown opens and focuses first item, Escape
     closes and returns focus to trigger, Home/End/Arrow keys cycle menu items.

6. Update mobile menu.
   - Remove Solutions button and submenu.
   - Products submenu includes Guides, Tools, and Use cases.
   - Pricing submenu appears immediately after Products.

7. Update CSS.
   - Port measurements and transitions from the research section.
   - Map AccessGrid gray surfaces to existing Seams theme variables.
   - Verify dark and light theme tokens produce enough contrast.

8. Clean up.
   - Run `rg "solutions|navbar-static__dropdown-|navbar-dropdown-notch|leavingDropdown|dropdownSurfaceLeft|dropdownNotchLeft"` in the navbar files.
   - Delete stale classes and state after replacements.

## Validation

Risk is medium because this changes shared frontpage navigation, desktop hover behavior,
mobile IA, and keyboard navigation.

Run the cheapest checks that catch likely regressions:

1. Static/type check for the site package:
   - `pnpm --filter @seams/site typecheck` if available.
   - If the package has no typecheck script, run its nearest build or lint script.

2. Local browser verification:
   - Start the site dev server from `examples/seams-site`.
   - Open `/` at desktop width around `1418 x 900`.
   - Hover Products, then move to Pricing, Documentation, About, and back.
   - Confirm the dropdown shell stays mounted and content cross-slides through the same
     clipped card.
   - Confirm Products to About switch uses `250ms cubic-bezier(.5,1,.89,1)` and the
     inactive pane lands at `translateX(80px)` or `translateX(-80px)`.
   - Confirm moving from trigger to popup does not close the menu.
   - Confirm Escape closes the popup and focus returns to the trigger.

3. Mobile browser verification:
   - Test around `390 x 844`.
   - Open menu, open Products, confirm Guides, Tools, and Use cases are reachable.
   - Open Pricing, confirm all three pricing entries are reachable.
   - Confirm the CTA row and theme toggle remain usable.

4. Visual acceptance:
   - Desktop nav should be compact and centered like AccessGrid.
   - Dropdown should be the same width as the nav shell.
   - Dropdown card should have one rounded outer surface, one rounded inner clipped grid,
     2px dividers, and a footer CTA strip.
   - No triangle notch should remain.
   - No separate Products and Solutions triggers should remain.

## Follow-Up Constraints

- Keep this as a breaking cleanup. Delete obsolete Solutions dropdown state and CSS.
- Keep compatibility logic out of the navbar core.
- Keep comments brief and only around the pane-state or focus logic if needed.
- Use the current Seams palette and theme variables. Only borrow AccessGrid geometry,
  layout, and motion.
