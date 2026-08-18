# Refactor 106: Docs App Refresh

Date created: August 12, 2026

Status: Implemented

## Goal

Turn `apps/docs` into a trustworthy developer product that belongs to the same
visual system as `apps/seams-site`.

The refreshed docs must:

1. present examples that compile against the current public SDK;
2. give a new integrator one short, verified path from installation to a signed
   operation;
3. use the frontend's typography, brand assets, semantic colors, surfaces,
   radii, focus treatment, and interaction language;
4. organize content around developer tasks, with protocol detail available as
   a deeper layer;
5. remain readable and operable in the light Paper appearance, keyboard
   navigation, mobile widths, and 200% zoom;
6. add narrow CI gates that catch broken links, stale examples, build failures,
   and major visual regressions.

The first milestone restores the operating path. Theme work and broader content
follow after the primary examples are correct and demonstrated once.

## Current State

`apps/docs` is a VitePress application with 45 Markdown pages, local search, a
responsive sidebar, page outlines, and Mermaid rendering. Its production build
and theme TypeScript check currently pass.

The app is functional, though it does not yet operate as a reliable SDK guide
or as a visual extension of the frontend.

### Correctness gaps

The flagship examples already disagree with the current public API:

- `apps/docs/src/getting-started/create-wallet.md` calls
  `registerPasskey('alice.testnet', options)`. The current
  `RegistrationCapability.registerPasskey` accepts an optional options object;
  passing a NEAR account id was removed.
- The same example reads `nearAccountId` and `transactionId` directly from a
  successful `RegistrationResult`. The current discriminated result union
  exposes `walletId`, `kind`, and branch-specific capabilities or provisioning
  state.
- The NEAR transaction and NEP-413 examples in
  `apps/docs/src/getting-started/sign-with-policy.md` omit the required
  `walletSession` input.
- Markdown fences are rendered and highlighted, but runnable TypeScript and
  TSX examples are not compiled against `@seams/wallet`.

These failures make the shortest integration path unusable. Fix them before
expanding coverage or adding visual polish.

### Theme and brand gaps

The docs apply Hanken Grotesk only to article headings. VitePress continues to
render body copy and interface chrome in Inter, while `apps/seams-site` uses
Hanken Grotesk throughout.

The remaining visual treatment is mostly stock VitePress:

- the header uses the text label `Seams.xyz` instead of the current v9
  wordmark;
- the docs do not use the frontend's semantic surface levels, brand tokens,
  gradients, radii, shadows, or compact floating navigation treatment;
- search, sidebar, tables, code blocks, page navigation, and callouts do not
  read as one component family with the frontend;
- the docs load Hanken Grotesk from Google Fonts while the frontend self-hosts
  the same family through `@fontsource/hanken-grotesk`;
- navigation and article headings use pervasive title case, while the frontend
  has moved toward sentence case.

The retired purple Mermaid theme contained a confirmed contrast failure. Its
node text/background pair measured approximately `1.16:1` in the rendered
architecture page.

### Information architecture gaps

The docs root contains one short paragraph and two links. It has no
installation command, quickstart, product paths, capability summary, or direct
connection to the frontend's product language.

The sidebar is one global array. Getting Started and almost every Concepts
group are expanded together, so the first screen exposes most of the 45-page
taxonomy. The structure follows internal concepts more closely than developer
tasks.

The frontend documentation menu promises:

- guides;
- SDK references for auth, sessions, wallet UI, and policy;
- use cases;
- architecture.

The current docs are primarily conceptual. There is no complete public API
reference for the exported package entrypoints, no production checklist, and
little troubleshooting or error-recovery guidance.

### Content and delivery gaps

The current content baseline is:

- 45 Markdown pages;
- 116 code fences;
- 11 Mermaid blocks;
- no page-specific `description` frontmatter;
- no content images or screenshots;
- only two custom-container markers;
- several overview and concept pages below 150 words.

`apps/docs` defines `type-check` and `build` scripts. The root `type-check`
script omits `type-check:docs`, and the primary repository validation workflow
runs the root command without a separate docs build. A docs-only regression can
therefore miss the normal CI path.

## Product and Design Source of Truth

Use `apps/seams-site` as the visual and product-language source of truth.

Relevant sources include:

- `apps/seams-site/src/app.css` for typography, spacing, radii, motion, and
  semantic site aliases;
- `apps/seams-site/src/context/app-themes.ts` and
  `apps/seams-site/src/context/siteThemeOverrides.ts` for the light Paper color
  roles;
- `apps/seams-site/src/context/seamsBranding.ts` and
  `apps/seams-site/src/public/seams-v9/` for current marks and wordmarks;
- `apps/seams-site/src/components/Navbar/` for navigation proportions, surface
  treatment, and focus behavior;
- `apps/seams-site/src/components/Footer.*` for footer hierarchy;
- `apps/seams-site/src/pages/shared/styles.css` for article-adjacent cards,
  page width, labels, and actions.

Map these primitives into VitePress-specific semantic roles inside the docs
theme. Keep the mapping local to `apps/docs` in this refactor. A new shared
brand package would add more machinery than the current two consumers require.
Create a shared package only after repeated synchronization work demonstrates
a real need.

Retain VitePress and extend its default layout through supported slots,
components, configuration, and CSS. Preserve its search, skip link, page
outline, keyboard behavior, and responsive layout. Avoid copying the React
navbar implementation or creating a parallel router inside the docs app.

## Target Information Architecture

### Start here

- Overview
- Install and configure
- Create a wallet
- Sign your first transaction
- Add recovery
- Delegate or rotate authority

### Guides

- Authentication
  - Passkeys
  - Email OTP
  - VoiceID
- Embedded wallets
- Policies and mandates
- Wallet sessions and signing lanes
- Delegated agents
- Linked devices
- Recovery, export, and rotation
- Theming

### SDK reference

- `@seams/wallet`
- `@seams/wallet/react`
- `@seams/wallet/advanced`
- `@seams/wallet/threshold`
- `@seams/wallet/runtime`
- Configuration
- Registration and auth
- Wallet and signing capabilities
- Sessions and capability references
- Events and progress
- Result and error unions
- Theme tokens and UI exports

Reference pages should document supported public exports only. Internal source
paths, compatibility shapes, and deprecated symbols stay out of the public
site.

### Concepts and security

- Architecture
- Custody model
- Auth planes
- Policy model
- Sessions
- Threshold signing
- Router A/B
- Streaming Yao A/B
- Key derivation and address invariants
- Glossary

### Deploy and operate

- Hosted integration
- Router and signer deployment
- Origin and iframe boundaries
- CSP and request authentication
- Environment variables
- Production checklist
- Observability and audit
- Troubleshooting

### Use cases

- Ecommerce agents
- iPhone access passes
- Shipping agent credentials
- Embedded device credentials

Use path-specific sidebars. The docs root opens directly into the Start here sidebar.
Each content route displays its own section and expands the current group.
Advanced protocol material remains collapsed until the reader enters that
section.

## Page Patterns

### Guide page

Every guide should use this order when the subject supports it:

1. outcome;
2. prerequisites;
3. minimal implementation;
4. expected result;
5. recoverable failures;
6. security, custody, or policy implications;
7. next step.

Runnable examples must be complete enough to compile. Partial examples receive
an explicit label and state which values or helpers the application supplies.

### Reference page

Reference pages should include:

- import path;
- supported public symbols;
- narrow input type or branch-specific input union;
- result union and exhaustive branch behavior;
- lifecycle preconditions;
- recoverable failures;
- one minimal example;
- links to related guides and concepts.

### Concept page

Concept pages should progress from a plain-language summary to invariants,
boundaries, diagrams, and deeper protocol material. A reader should understand
why the concept matters before encountering implementation detail.

### Troubleshooting entry

Each entry names:

- the observable symptom;
- the likely boundary or lifecycle state;
- how to inspect it;
- the supported recovery action;
- links to relevant error codes and configuration.

## Visual Direction

### Typography

- Self-host Hanken Grotesk as WOFF2 through the same package used by the
  frontend.
- Apply it to body copy, headings, navigation, search, buttons, and form
  controls.
- Keep the existing monospace stack for code unless the frontend establishes a
  separate code face.
- Use a small semantic type scale with body copy near 16px and line-height near
  1.5–1.6.
- Cap article measure near 65–72 characters.
- Use balanced wrapping for short headings and natural wrapping for prose.
- Adopt sentence case for headings, navigation, buttons, and pager labels.

### Color and surfaces

- Map frontend canvas, surface, muted surface, strong surface, primary text,
  secondary text, border, focus, brand, success, warning, and danger roles to
  VitePress variables.
- Use the frontend's light Paper appearance throughout the docs shell.
- Use brand color for links, active navigation, focus treatment, and the single
  primary action on a surface.
- Keep secondary actions neutral.
- Use space and surface changes for grouping; retain borders where they convey
  structure, selection, focus, or table boundaries.
- Measure every text/background pair in the rendered light appearance.

### Navigation and shell

- Use the current v9 monochrome wordmark and light mark.
- Give desktop navigation the frontend's compact floating-surface character
  while preserving VitePress's semantic navigation and mobile menu behavior.
- Keep search prominent and reachable by keyboard shortcut.
- Make the active section clear through text weight, color, and a surface cue.
- Add a product-aligned footer with links to the main site, dashboard, pricing,
  support, GitHub, and the major docs sections.

### Content components

Create a small docs-specific component set only where Markdown and existing
VitePress elements cannot express the design cleanly:

- docs-root orientation;
- task/path card;
- installation command with copy action;
- capability or package grid;
- diagram figure with caption and accessible summary;
- product footer.

Style existing VitePress code blocks, custom containers, tables, search,
outline, sidebar, and pagers. Do not wrap each stock element in a new Vue
component.

### Motion

- Use short color, opacity, and surface transitions for interactive state.
- Avoid `transition: all`.
- Keep high-frequency documentation interactions immediate.
- Honor `prefers-reduced-motion`.
- Preserve visible static cues for every animated state.

## Implementation Plan

Checklist markers: `[ ]` open, `[~]` partial, `[x]` complete.

### Phase 0 — Restore the primary operating path

- [x] Inventory all TypeScript and TSX fences under `apps/docs/src`.
- [x] Classify each fence as runnable, partial, pseudocode, protocol text, or
      generated data.
- [x] Fix the passkey registration guide to use the current options-only
      `registerPasskey` path or the explicit `registerWallet` path when named
      account provisioning is required.
- [x] Handle `RegistrationResult` through its `success` and `kind` branches;
      remove reads of retired result fields.
- [x] Add the required `walletSession` and precise account/chain references to
      signing examples.
- [x] Reconcile registration, unlock, signing, recovery, export, device-link,
      and delegation examples with existing public type fixtures and
      `apps/seams-site` flows.
- [x] Move runnable examples into compile fixtures under the top-level `tests/`
      workspace and render the same source in docs, or add a small extraction
      check that compiles fenced sources without duplicating example bodies.
- [x] Add one focused behavioral smoke test for the shortest wallet path.
- [x] Delete examples that exist only for retired API behavior.

Validation:

- all runnable examples compile against the workspace `@seams/wallet`;
- the focused wallet smoke passes;
- `pnpm -C apps/docs type-check`;
- `pnpm -C apps/docs build`.

Exit criterion: a new integrator can copy the installation, registration, and
first-signing examples without encountering a type error or retired API.

### Phase 1 — Establish the Seams docs theme

- [x] Replace remote Google Font loading with self-hosted Hanken Grotesk WOFF2
      assets and load only used weights/styles.
- [x] Add a concise VitePress semantic-token map derived from the frontend
      roles.
- [x] Replace legacy docs marks with current v9 theme-aware wordmark and favicon
      assets.
- [x] Apply frontend typography to the complete docs shell.
- [x] Restyle the navbar, search, sidebar, page outline, article content, code
      blocks, copy controls, custom containers, tables, and pagers.
- [x] Add the product footer through a VitePress layout slot.
- [x] Add visible `:focus-visible` treatment that survives Paper surfaces and
      forced-colors mode.
- [x] Keep all hit targets at least 24×24 CSS pixels and aim for 40×40 for
      standalone desktop controls.
- [x] Use logical layout properties for direction-dependent spacing.

Validation:

- compare the docs shell with `apps/seams-site` at 390px, 768px, and 1440px;
- verify the light Paper appearance;
- traverse all header, search, sidebar, outline, copy, and pager controls with
  the keyboard;
- verify no page-level horizontal scrolling at 320px;
- verify 200% zoom and text reflow;
- measure focus indicators and text contrast.

Exit criterion: the docs and frontend clearly belong to the same product while
retaining VitePress's proven documentation behavior.

### Phase 2 — Rebuild navigation and the docs root

- [x] Convert the global sidebar array to path-specific sidebars.
- [x] Implement the target top-level sections in this plan.
- [x] Move access-pass, shipping-agent, and embedded-device pages from Getting
      Started into Use cases.
- [x] Keep the initial Start here sequence limited to installation, wallet
      creation, signing, recovery, and delegation/rotation.
- [x] Put protocol detail under Concepts and security or Advanced protocol.
- [x] Serve `apps/docs/src/index.md` as the practical Start here guide at `docs.seams.sh`, with no separate marketing front page. Include installation, complete setup, the first-signing path, and direct links to reference, deployment, use cases, and troubleshooting.
- [x] Add consistent previous, next, and related-content relationships.
- [x] Update all visible navigation and headings to sentence case.

Validation:

- complete the docs-root-to-first-signing path at desktop and mobile widths;
- confirm every page is reachable from one intended section;
- confirm no page appears in an unrelated sidebar;
- verify search and deep links after all route moves;
- add redirects only at the request/deployment boundary for already published
  URLs, then remove obsolete content paths.

Exit criterion: the primary path is obvious from the docs root, and the
sidebar exposes only the context needed for the current task.

### Phase 3 — Complete guide and reference coverage

- [x] Rewrite Start here pages using the guide pattern.
- [x] Add public package-entrypoint reference pages for `.`, `/react`,
      `/advanced`, `/threshold`, and `/runtime`.
- [x] Document configuration as precise branches rather than one broad options
      bag.
- [x] Document registration, auth, signing, session, recovery, device, export,
      and theme result unions with exhaustive states.
- [x] Add event/progress and recoverable-error references.
- [x] Add hosted integration, origin/CSP, request-authentication, environment,
      production-checklist, and troubleshooting pages.
- [x] Reconcile use-case language with the current frontend product pages.
- [x] Give every page a unique description and a plain-language opening.
- [x] Add prerequisites and expected output to every runnable guide.
- [x] Remove short index pages that merely repeat sidebar links; replace them
      with useful orientation or let the sidebar own navigation.

Validation:

- verify every public package export is intentionally documented or explicitly
  outside the supported surface;
- compile all runnable examples;
- run a terminology pass against current domain types and intended-behaviour
  contracts;
- inspect search results for primary product and SDK terms.

Exit criterion: the docs fulfill the frontend's promise of guides, SDK
reference, use cases, and architecture coverage.

### Phase 4 — Repair diagrams and accessibility

- [x] Give Mermaid a complete light Paper token set. Node fill, node text,
      edge, label, note, and border colors must be designed as pairs.
- [x] Replace broad `any` usage in the Mermaid theme integration with the
      available Mermaid types or a narrow local interface.
- [x] Give each diagram a figure caption and accessible text summary.
- [x] Keep the original source reachable when it adds implementation value.
- [x] Make wide diagrams readable through responsive layout or contained
      horizontal scrolling with an obvious affordance.
- [x] Add `scroll-margin-top` to anchored headings.
- [x] Verify one page-level `h1`, coherent heading levels, one visible `main`,
      and descriptive link names on every page pattern.
- [x] Verify the mobile menu, search dialog, copy confirmation, and theme
      switch announce their name, role, and state.
- [x] Verify reduced motion, forced colors, 200% zoom, and 320px reflow.

Validation:

- all diagram text/background pairs meet WCAG AA for their rendered text size;
- keyboard-only navigation completes the main docs flow;
- automated accessibility checks pass on the docs root, a guide, a
  reference page, and a diagram-heavy concept page;
- manual screen-reader checks cover navigation, search, code copy, headings,
  tables, and diagrams.

Exit criterion: diagrams and interactive documentation controls remain usable
across supported input and display modes.

### Phase 5 — Metadata, search, and durable gates

- [x] Add page descriptions, canonical origin configuration, social metadata,
      sitemap configuration, and `lastUpdated` support.
- [x] Add a branded 404 page with search and common destinations.
- [x] Add search aliases for wallet session, signing lane, passkey, Router A/B,
      ECDSA, Yao, recovery, export, and delegated agents where the visible page
      terminology differs from likely queries.
- [x] Add docs type-check and production build to the normal repository CI
      path.
- [x] Add internal-link validation.
- [x] Add the runnable-snippet compile gate from Phase 0.
- [x] Add a small browser smoke covering the docs root, guide, reference, local
      search, mobile navigation, and the pinned light appearance.
- [x] Add visual snapshots for the docs root and one representative article
      at desktop/mobile sizes in the light Paper appearance.
- [x] Document the update requirement for public SDK signature, result-union,
      configuration, and route changes.

Validation:

- `pnpm check` with the docs checks included;
- production docs build;
- link validation;
- snippet compilation;
- focused docs browser smoke;
- reviewed visual snapshots.

Exit criterion: public API or theme drift produces a focused failure in the
same change set that caused it.

## Delivery Sequence

Land the work as reviewable, independently valuable changes:

1. example correctness and snippet validation;
2. theme foundation, brand assets, and docs shell;
3. docs root and path-specific navigation;
4. guide migration and public SDK reference;
5. deployment, troubleshooting, and use-case coverage;
6. diagrams, accessibility, metadata, and final CI gates.

Keep production API fixes separate from documentation corrections. If an
example exposes a real SDK regression, classify and repair that regression in
its own change. Delete stale documentation that describes retired behavior;
do not add a compatibility path to make an old example valid.

## Non-goals

- Replacing VitePress.
- Copying the frontend React navbar, router, or component tree into the docs.
- Creating a general design-system package before a demonstrated third
  consumer or repeated synchronization cost.
- Generating reference pages for internal or unsupported exports.
- Publishing internal protocol, secret material, deployment credentials, or
  private control-plane details.
- Adding versioned documentation before the SDK has a concrete multi-version
  support policy.
- Preserving obsolete URLs inside core navigation or content. Redirects belong
  at the deployment boundary where published links require them.
- Adding source-text guards for prose style or page structure. Prefer compiled
  examples, link checks, behavior tests, and visual/accessibility validation.

## Completion Criteria

Refactor 106 is complete when:

- the installation-to-first-signing path is current, copyable, and tested;
- every runnable TypeScript/TSX example compiles against the workspace SDK;
- the docs use the current Seams typography, wordmark, light Paper colors,
  surfaces, and interaction language;
- the docs root and path-specific navigation expose Start here, Guides, SDK
  reference, Concepts and security, Deploy and operate, and Use cases;
- public package entrypoints and major recoverable result unions are covered;
- diagrams meet contrast and accessibility requirements;
- mobile, keyboard, screen-reader, reduced-motion, forced-color, and 200% zoom
  checks pass for representative pages;
- page metadata, internal links, docs build, snippet compilation, and browser
  smoke checks run in CI;
- obsolete examples, legacy assets, duplicate navigation paths, and retired
  content are removed.
