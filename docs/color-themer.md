# Color Themer Plan

Last updated: 2026-02-16

## Short Answer

Yes. A light/dark color palette system is already mostly supported by the current architecture.

The site already uses:

- Controlled theme state (`light` / `dark`) via `data-w3a-theme` and `useSiteTheme`.
- SDK theme tokens (`--w3a-colors-*`) generated from palette-driven design tokens.
- Alias variables (`--fe-*`) in `examples/tatchi-site/src/app.css`.

The missing piece is standardizing all page/component colors onto a single palette contract and removing local ad-hoc color mixes/hardcoded values.

## Current State Review

### What is solid already

- Theme mode propagation is centralized and working:
  - `examples/tatchi-site/src/hooks/useSiteTheme.ts`
  - `examples/tatchi-site/src/App.tsx`
- SDK provides palette-derived theme tokens and supports per-theme token overrides:
  - `client/src/theme/palette.json`
  - `client/src/theme/base-styles.js`
  - `client/src/react/components/theme/ThemeProvider.tsx`
  - `client/src/react/components/theme/design-tokens.ts`
- Site styles already consume many semantic variables (`--w3a-colors-*`, `--fe-*`).

### Gaps to address

- High volume of direct color literals and local blends in site CSS, especially:
  - `examples/tatchi-site/src/layout.css`
  - `examples/tatchi-site/src/components/Navbar/Navbar.css`
  - `examples/tatchi-site/src/components/Footer.css`
- Many component-local `html[data-w3a-theme="light|dark"]` overrides duplicate logic instead of using shared semantic tokens.
- Token naming drift exists:
  - `--w3a-colors-background` is used in `examples/tatchi-site/src/layout.css:7`, while canonical token is `--w3a-colors-colorBackground`.
- Some non-canonical token names are used with fallbacks (`surface1`) in icon components.

## Target Architecture

Use a 3-layer color system:

1. Palette primitives (raw ramps):
   - Existing source of truth: `client/src/theme/palette.json`.
2. Semantic theme tokens (light/dark role mapping):
   - Existing contract: `tokens.colors.*` -> `--w3a-colors-*`.
3. Site component aliases:
   - New site-level semantic aliases (`--site-*`) mapped from `--w3a-colors-*` / `--fe-*`.
   - Components consume `--site-*` first, not raw hex/rgba.

## API Surface (Current vs Proposed)

### Current state

- React path: configurable today via `TatchiPasskeyProvider` `theme` props (including token overrides through Theme props).
- Core `TatchiPasskey` config path: not configurable today for palette/token overrides.
  - `TatchiConfigsInput` currently has no `appearance`/`palette` field.

### Recommended API shape

Use both surfaces, with one shared model:

1. Framework-agnostic source (`TatchiConfigsInput.appearance`) for SDK-wide defaults.
2. React override surface (`TatchiPasskeyProvider theme={...}`) for host-level control.

Type sketch:

```ts
type ThemeName = 'light' | 'dark';

type ThemeTokenOverrides = {
  light?: {
    colors?: Record<string, string>;
  };
  dark?: {
    colors?: Record<string, string>;
  };
};

interface AppearanceConfigInput {
  theme?: ThemeName;                 // initial mode (optional)
  palette?: 'default';               // optional named palette (legacy palettes removed)
  tokens?: ThemeTokenOverrides;      // semantic token overrides
}

interface TatchiConfigsInput {
  // existing fields...
  appearance?: AppearanceConfigInput;
}
```

React usage sketch:

```tsx
<TatchiPasskeyProvider
  config={{
    ...config,
    appearance: {
      theme: 'dark',
      palette: 'default',
      tokens: {
        dark: { colors: { primary: 'oklch(0.62 0.176 255)' } },
        light: { colors: { primary: 'oklch(0.56 0.158 255)' } },
      },
    },
  }}
  theme={{
    theme,
    setTheme,
    // optional React-level override, same semantic keys
    tokens: {
      dark: { colors: { borderPrimary: 'oklch(0.35 0.018 240)' } },
    },
  }}
>
  {children}
</TatchiPasskeyProvider>
```

### Precedence rules

Final theme/token resolution should be deterministic:

1. Explicit React prop override (`TatchiPasskeyProvider theme.tokens`).
2. SDK config defaults (`TatchiConfigsInput.appearance.tokens`).
3. Built-in SDK theme tokens (`LIGHT_THEME` / `DARK_THEME`).

Theme mode precedence:

1. Runtime explicit setter (`setTheme(...)`).
2. Controlled React prop (`theme.theme`).
3. `config.appearance.theme`.
4. Existing fallback behavior (`localStorage`/document/system as currently implemented per app).

## Extensibility Policy

This plan intentionally limits extensibility to **color themes/tokens only**.

Allowed:

- `appearance.theme` mode selection.
- `appearance.palette` selection (`default` only).
- `appearance.tokens` semantic token overrides.
- React-level token overrides via `TatchiPasskeyProvider theme.tokens`.

Not allowed (out of scope):

- Custom confirmation UI component replacement in wallet runtime.
- Arbitrary custom Lit element/module injection for confirm flows.
- Provider interfaces that let integrators replace secure confirm event/render behavior.

Rationale:

- Theme/token overrides preserve UI branding flexibility while keeping confirmation flow security semantics in SDK-owned code paths.
- Custom confirm component injection increases attack surface in wallet-origin runtime and is not required for the color-theming objective.

## Implementation Plan

### Phase 0: API Decision and Contract

- Adopt `appearance` in `TatchiConfigsInput` as the framework-agnostic color API.
- Keep `TatchiPasskeyProvider theme` as the React control surface and merge point.
- Lock semantic token keys for overrides (must match `tokens.colors.*` keys).

Files to update in implementation:

- `client/src/core/types/tatchi.ts`
- `client/src/core/config/defaultConfigs.ts`
- `client/src/react/context/TatchiPasskeyProvider.tsx`
- `client/src/react/types.ts`

Deliverable:

- Approved API schema and precedence behavior.

### Phase 1: Define Site Palette Contract

- Create a site token contract doc section in this file:
  - Core roles: `canvas`, `surface`, `surface-muted`, `text-primary`, `text-secondary`, `border`, `focus`, `brand`, `brand-hover`, `danger`, `success`.
  - Component roles: navbar, footer, marketing, forms, carousel.
- Decide which colors are allowed to remain literal (e.g., syntax-highlighting brand accents if intentionally fixed).

Deliverable:

- Agreed token naming and allowed exceptions list.

### Phase 2: Wire API Through Core + React

- Add `appearance` support in core config merge:
  - `client/src/core/types/tatchi.ts`
  - `client/src/core/config/defaultConfigs.ts`
- Initialize `TatchiPasskey.theme` from `config.appearance.theme` when provided:
  - `client/src/core/TatchiPasskey/index.ts`
- Thread appearance tokens to React theme boundary:
  - `client/src/react/context/TatchiPasskeyProvider.tsx`
  - `client/src/react/components/theme/ThemeProvider.tsx` (if merge helpers are needed)
- Add site theme override source:
  - `examples/tatchi-site/src/theme/siteThemeOverrides.ts` (new)
- Consume in site app:
  - `examples/tatchi-site/src/App.tsx`

Deliverable:

- Both light and dark palettes are configurable from `TatchiConfigsInput` and overridable in React.

### Phase 3: Add Site Alias Layer

- Add stable `--site-*` aliases in `examples/tatchi-site/src/app.css` under the theme boundary:
  - Map from `--w3a-colors-*` / `--fe-*`.
- Include compatibility aliases for known drift during migration:
  - Map `--w3a-colors-background` -> `--w3a-colors-colorBackground` (temporary shim).

Deliverable:

- Components can consume `--site-*` without caring about SDK token naming details.

### Phase 4: Migrate High-Impact CSS First

Migration order:

1. `examples/tatchi-site/src/layout.css`
2. `examples/tatchi-site/src/components/Navbar/Navbar.css`
3. `examples/tatchi-site/src/components/Footer.css`
4. `examples/tatchi-site/src/styles/contact-page.css`
5. `examples/tatchi-site/src/components/Carousel/CarouselStyles.css`

Rules during migration:

- Replace literal colors with `--site-*` tokens where possible.
- Collapse repeated `html[data-w3a-theme]` branches into token reassignment blocks.
- Keep visual intent, but move math/blends into token definitions instead of leaf selectors.

Deliverable:

- Main UI surfaces consume semantic palette tokens with minimal per-component theme branching.

### Phase 5: Cleanup + Guardrails

- Remove temporary compatibility aliases after migration.
- Normalize non-canonical usages:
  - `--w3a-colors-background` -> `--w3a-colors-colorBackground`
  - `surface1` fallback strategy (replace or formalize).
- Add a lint/check script to flag new hardcoded colors in site CSS except allowlisted locations.

Deliverable:

- Theme consistency is enforced and regressions are caught early.

### Phase 6: Validation

- Functional checks:
  - Theme toggle works across Home, Pricing, Company, Contact, Dashboard.
  - Theme persists across reloads and route transitions.
- Visual checks:
  - Compare before/after screenshots in both light and dark.
  - Verify gradients, borders, and focus rings still read correctly.
- Accessibility checks:
  - Validate contrast for primary text, secondary text, buttons, and form controls.
  - Verify focus-visible indicators in both modes.

Deliverable:

- Signed-off light/dark palette behavior with no major visual regressions.

## Validation Evidence (2026-02-16)

- Automated validation spec:
  - `tests/e2e/theme.colorThemer.validation.test.ts`
- Command:
  - `pnpm -C tests exec playwright test e2e/theme.colorThemer.validation.test.ts --reporter=line`
- Verified by test:
  - Functional: theme toggle + persistence across SPA transitions and reloads on `/`, `/pricing`, `/company`, `/contact`, `/dashboard/wallets-list`.
  - Visual: full-page screenshots captured for all listed routes in both dark/light and attached to Playwright test artifacts.
  - Accessibility:
    - Contrast checks for semantic tokens and concrete controls (pricing CTA, contact input).
    - Keyboard `:focus-visible` indicator checks for navbar theme toggle and contact first-name input.
  - Update:
    - Dark brand tokens were tightened to enforce strict `4.5:1` for `--site-text-button` on `--site-brand` (`primary: oklch(0.52 0.138 255)`, `primaryHover: oklch(0.56 0.158 255)`).
    - Strict rerun completed successfully: `pnpm -C tests exec playwright test e2e/theme.colorThemer.validation.test.ts --reporter=line` (`2 passed`).

## Phased TODO Checklist

### Phase 0: API contract and type plumbing

- [x] Add `appearance` to `TatchiConfigsInput` in `client/src/core/types/tatchi.ts`.
- [x] Add resolved `appearance` shape to `TatchiConfigs` in `client/src/core/types/tatchi.ts`.
- [x] Add default `appearance` values in `client/src/core/config/defaultConfigs.ts`.
- [x] Merge `appearance` overrides in `buildConfigsFromEnv` in `client/src/core/config/defaultConfigs.ts`.
- [x] Update React-facing provider types in `client/src/react/types.ts` if needed for API parity.
- [x] Add/update unit tests for config merge behavior and fallback precedence.
- [x] Add/update docs note that extensibility is limited to theme/tokens (no custom confirm component injection).
- [x] Phase 0 exit: `appearance.theme`, `appearance.palette`, and `appearance.tokens` are accepted by config types and merged deterministically.

### Phase 1: Theme runtime wiring

- [x] Initialize `TatchiPasskey.theme` from `config.appearance.theme` in `client/src/core/TatchiPasskey/index.ts`.
- [x] Keep `setTheme()` behavior unchanged and verify it still propagates to wallet/iframe flows.
- [x] Thread `appearance.tokens` into React theme boundary merge path via `client/src/react/context/TatchiPasskeyProvider.tsx`.
- [x] Add a single site-level override module: `examples/tatchi-site/src/theme/siteThemeOverrides.ts`.
- [x] Consume that module in `examples/tatchi-site/src/App.tsx` through provider props.
- [x] Add tests proving precedence: React `theme.tokens` > `config.appearance.tokens` > SDK base tokens.
- [x] Phase 1 exit: the same palette override works from config and React, with documented precedence.

### Phase 2: Site semantic alias layer

- [x] Define `--site-*` aliases in `examples/tatchi-site/src/app.css`.
- [x] Map `--site-*` aliases to `--w3a-colors-*` / `--fe-*` variables.
- [x] Add temporary compatibility alias for `--w3a-colors-background` -> `--w3a-colors-colorBackground`.
- [x] Define token naming for component domains: navbar, footer, marketing, forms, carousel.
- [x] Phase 2 exit: all new site styling can be authored only with `--site-*` tokens.

### Phase 3: High-impact CSS migration

- [x] Migrate `examples/tatchi-site/src/layout.css` from literals/component-local theme branches to `--site-*`.
- [x] Migrate `examples/tatchi-site/src/components/Navbar/Navbar.css` to `--site-*`.
- [x] Migrate `examples/tatchi-site/src/components/Footer.css` to `--site-*`.
- [x] Migrate `examples/tatchi-site/src/styles/contact-page.css` to `--site-*`.
- [x] Migrate `examples/tatchi-site/src/components/Carousel/CarouselStyles.css` to `--site-*`.
- [x] Normalize known token drift and non-canonical usages (`background`, `surface1` fallbacks).
- [x] Phase 3 exit: primary pages no longer depend on raw hex/rgba except approved exceptions.

### Phase 4: Cleanup and enforcement

- [x] Remove temporary compatibility aliases once no callsites remain.
- [x] Add lint/check script to flag new hardcoded colors in site CSS.
- [x] Add allowlist for intentional literal color uses (for example, syntax-highlight accents).
- [x] Add CI hook for the lint/check script.
- [x] Phase 4 exit: PRs introducing non-allowlisted literals fail checks.

### Phase 5: Validation and sign-off

- [x] Run functional verification for theme toggle and persistence on Home/Pricing/Company/Contact/Dashboard.
- [x] Run visual diff checks (light/dark) for migrated files.
- [x] Run accessibility contrast checks for text, controls, and focus states.
- [x] Capture before/after screenshots for sign-off.
- [x] Phase 5 exit: no significant visual regression and accessibility checks pass.

## Success Criteria

- All major site surfaces derive from one palette override source.
- No new raw hex/rgba colors are introduced outside allowlisted exceptions.
- Theme mode changes require editing tokens, not per-component light/dark overrides.
- Existing user-facing visual identity is preserved or improved with fewer code paths.

## Risks and Mitigations

- Risk: Visual drift in complex gradient-heavy sections.
  - Mitigation: Migrate section-by-section with screenshot diffs.
- Risk: Breaking embedded SDK component theming.
  - Mitigation: Keep `--w3a-colors-*` contract intact; only layer aliases on top.
- Risk: Incomplete migration leaves mixed token models.
  - Mitigation: Add lint/check and block merges on new hardcoded colors.
