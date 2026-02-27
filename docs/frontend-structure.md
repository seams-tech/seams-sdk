# Frontend Structure Plan

## Scope

This plan applies to `examples/tatchi-site/src`.

Goals:
- Organize by ownership and usage, not by file type.
- Keep route-specific code inside `pages/`.
- Keep journey-based behavior in `flows/`.
- Keep reusable UI in `components/`.
- Keep app-level context + theme ownership in `context/`.
- Keep cross-cutting non-UI utilities in `shared/`.
- Remove legacy/duplicate placements during the migration (no compatibility layer).

## Target Structure

```text
src/
  app/
    App.tsx
    main.tsx
    router/

  pages/
    home/
      page.tsx
      sections/
      styles.css
    pricing/
      page.tsx
      styles.css
    company/
      page.tsx
    contact/
      page.tsx
      styles.css
    dashboard/
      page.tsx
      routes/
        api-keys/page.tsx
        app-settings/page.tsx
        export-keys/page.tsx
        gas-smart-wallets/page.tsx
        policy-engine/page.tsx
        wallets-search/page.tsx
        wallets-list/page.tsx
        webhooks/page.tsx
      layout/
      components/
      styles.css

  flows/
    demo/
    auth/
    recovery/

  components/
    Navbar/
    Footer/
    Carousel/
    icons/

  context/
    AuthMenuControl.tsx
    ProfileMenuControl.tsx
    app-themes.ts
    siteThemeOverrides.ts

  shared/
    hooks/
    utils/
    types/

  assets/
  content/   (docs content lives in `examples/tatchi-docs/src`)
  styles/
    globals.css
```

## Ownership Rules

- `pages/*`: Route entry + route-local sections/components/styles only.
- `flows/*`: Journey-based modules used by one or more pages (state, business logic, flow UI).
- `components/*`: Reusable presentational UI shared across pages/flows.
- `context/*`: App-level context providers and theme configuration shared by multiple owners.
- `shared/hooks|utils|types`: Generic cross-cutting code with no page/flow ownership.
- Styles should be colocated with the owner (`page`/`flow`/`component`) unless truly global.

## Migration Plan

1. Create the base directories (`app`, `pages`, `flows`, `components`, `context`, `shared`).
2. Move all route entries from `src/pages/*.tsx` into `src/pages/<route>/page.tsx`.
3. Merge dashboard split:
   - Move `src/components/dashboard/*` into `src/pages/dashboard/{components,layout}`.
   - Keep dashboard route pages under `src/pages/dashboard/routes/*`.
   - Preserve route slugs exactly as-is: `wallets-list`, `wallets-search`, `gas-smart-wallets`.
4. Move homepage-only sections (`HomeHero`, `ProductCards`, `SecurityProofStrip`, `CredibilityBands`, `FinalCTA`) into `src/pages/home/sections/`.
5. Keep reusable UI in `src/components`:
   - `Navbar/*`, `Footer.*`, `Carousel/*`, `icons/*`, and generic primitives.
6. Extract large demo flow files into `src/flows/demo/*`:
   - Split `DemoPage.tsx` by domain concerns (state/actions/view helpers).
   - Keep page-level composition in `pages/home`.
7. Move app-level context + theme files:
   - `src/contexts/*` -> `src/context/*`.
   - `src/theme/*` -> `src/context/*`.
8. Move generic hooks/utils/types:
   - `src/hooks/*` -> `src/shared/hooks/*` where generic.
   - `src/utils/*` -> `src/shared/utils/*`.
   - `src/types.ts` -> `src/shared/types/index.ts`; keep `src/shared/types/raw.d.ts` for `*?raw`.
9. Reduce global CSS imports in `app.css` by moving ownership styles to colocated files.
10. Remove dead directories/files (`src/docs`, `.DS_Store`, obsolete CSS/imports).
11. Update imports and aliases, then run typecheck/build and fix remaining paths.

## TODO

- [x] Move `App.tsx` and `main.tsx` under `src/app/` and update entry imports.
- [x] Convert top-level route files to `src/pages/<route>/page.tsx`.
- [x] Unify dashboard into `src/pages/dashboard/` (remove `src/components/dashboard`).
- [x] Preserve existing dashboard route slugs (`wallets-list`, `wallets-search`, `gas-smart-wallets`).
- [x] Move home-only sections into `src/pages/home/sections/`.
- [x] Keep only truly reusable UI in `src/components/`.
- [x] Create folder skeleton for `app`, `pages`, `flows`, `components`, `context`, `shared`.
- [x] Create `src/context/`, move `src/contexts/*` and `src/theme/*` into it.
- [x] Create `src/flows/demo/` and split `DemoPage.tsx`.
  Status: `src/flows/demo/` created, demo flow files moved, EVM/RPC helper logic extracted to `src/flows/demo/demoEvmHelpers.ts`, major view sections extracted (`sections/NearGreetingSection.tsx`, `sections/ThresholdSignerSection.tsx`, `sections/SigningSessionSection.tsx`), and `DemoPage.tsx` orchestration split into flow hooks (`hooks/useDemoNearActions.tsx`, `hooks/useDemoSigningSession.ts`, `hooks/useDemoThresholdSigners.tsx`). `useDemoThresholdSigners.tsx` is now composition-only over focused flow hooks (`hooks/useDemoEip1559FeeCaps.ts`, `hooks/useDemoThresholdAccountState.ts`, `hooks/useDemoEvmGreetings.ts`, `hooks/useDemoTempoFeeTokenActions.tsx`, `hooks/useDemoTempoSigningActions.tsx`, `hooks/useDemoArcSigningActions.tsx`).
- [x] Move generic hooks into `src/shared/hooks/`.
- [x] Move generic utils into `src/shared/utils/`.
- [x] Move shared types into `src/shared/types/` (including `raw.d.ts` for `*?raw`).
- [x] Colocate page/flow/component CSS and trim `app.css` imports.
- [x] Delete `src/docs` (source of truth is `examples/tatchi-docs/src`).
- [x] Delete `.DS_Store` files under `src/`.
- [x] Run `pnpm -C examples/tatchi-site exec tsc --noEmit` and fix import/type errors.
- [x] Run `pnpm -C examples/tatchi-site build` and fix build-path issues.
- [x] Re-run touched docs/unit Playwright specs after path + flow refactors and align mocks with current demo request shape.
- [x] Add focused unit coverage for extracted threshold action hooks (`tests/unit/demoThresholdHooks.actions.unit.test.ts`), including success + failure/cancellation paths and cancellation classification semantics.
- [x] Remove duplicated broadcast failure-reporting blocks from extracted threshold action hooks via shared helper (`hooks/reportTempoBroadcastFailure.ts`).

## Next Steps

1. Continue keeping docs/unit harnesses aligned with current demo request shape (`kind: 'eip1559'` for Tempo + Arc, differentiated by chain id / RPC) as flow internals evolve.
2. Re-run on each refactor slice:
   - `pnpm -C examples/tatchi-site exec tsc --noEmit`
   - `pnpm -C examples/tatchi-site build`
   - `pnpm -C tests exec playwright test ./unit/demoThresholdHooks.actions.unit.test.ts --reporter=line`
   - `pnpm -C tests exec playwright test ./unit/passkeyLoginMenu.thresholdProvision.unit.test.ts --reporter=line`
   - `pnpm -C tests exec playwright test ./e2e/docs.thresholdRegisterAndSigning.integration.test.ts ./e2e/docs.thresholdSigningActions.smoke.test.ts --reporter=line`

## Done Criteria

- No code remains in deprecated legacy locations.
- Each file has a single clear owner (`pages`, `flows`, `components`, `context`, or `shared`).
- No duplicate component/function copies exist after moves.
- Typecheck and build pass for `examples/tatchi-site`.
