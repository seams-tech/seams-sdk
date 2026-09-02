# Refactor 116: Lit Component Consolidation — Measured-Surface Motion

Date created: September 2, 2026

Status: planning. Phase 0 landed on `dev` (`ebbee5947`, `81da06b7a`,
`00e911025`, `110fa381b`, `73358e2d2`, `1f096fe52`, `2d84f9eb4`); Phases 1–3
are open.

## Decision

Inside a measured wallet-iframe modal, content announces its size and the
parent moves the box. Nothing inside the modal animates its own layout height,
reads its own viewport to size itself, or trusts a single frame of the box.
Every Lit component that can change the height of that modal goes through one
seam, the surface-motion choreographer in
`packages/wallet/src/core/signingEngine/uiConfirm/ui/confirm-surface-resize.ts`,
and every violation of the rules below fails a browser test that runs the real
parent router, the real cross-origin frame, and the real confirmer.

## Goal

Remove the whole class of "interior moves instantly, box eases after it"
defects, not the four instances of it that Refactor 108's compact modal has
already produced:

1. the tree tweened its own height while the parent eased toward every
   intermediate measurement, so the box trailed and clipped the card;
2. the tree's collapse-to-zero step inherited a resolved height from closed
   `<details>` content and tweened _down_ from it, so nodes opened at full size;
3. the args block was capped in `vh`, which inside a content-sized iframe is a
   feedback loop (each ease grows the cap, the cap grows the content, the
   content grows the box);
4. the parent forced a layout at the destination geometry before its ease
   started, and the cross-origin frame received that size for one frame,
   which the child read as arrival.

Each was invisible to the suite that existed at the time, and the last was
invisible to every same-process harness. The consolidation is as much about
where the proof lives as about where the code lives.

## Current State

What Phase 0 already put in place:

- `TxTree` hands every open/close to its host through `lit-tree-resize-begin`
  (`lit-events.ts`) and only runs its own CSS transition when nobody claims the
  motion. Its collapse step is transition-free (`anim-h-hold`).
- `confirm-surface-resize.ts` (attached by `confirm-ui.ts` for every
  `wallet_iframe` binding) claims the motion when the box hugs the host: it pins
  the host to the target size through a constructable stylesheet, locks
  document overflow, feeds the body height from the iframe viewport each frame,
  refuses to land on a box that jumped straight to the target
  (`LANDING_CONFIRM_FRAMES`), and settles on stall.
- `tx-confirmer.css` pins the `vh` caps of `.file-content`, the scrollable tree
  root, and `.action-content` to rem values under
  `data-w3a-confirm-surface='wallet-iframe'`.
- `client/overlay/overlay-controller.ts` eases once per measurement over
  `SURFACE_RESIZE_DURATION_MS` (180ms) from the box's current visual rectangle,
  and pins the iframe to the origin size (`pinDialogIframe`) while the
  destination geometry is written and read.
- `tests/wallet-iframe/confirmSurface.treeGrowth.integration.test.ts` samples
  both sides per painted frame across the real boundary;
  `tests/lit-components/confirm-surface-resize.test.ts` covers the
  choreographer with a scripted box, including the destination blip.

Components inside foreground surfaces that still own some motion of their own:

| Component                                                                         | Motion                                           | Measured modal?                     | Disposition                           |
| --------------------------------------------------------------------------------- | ------------------------------------------------ | ----------------------------------- | ------------------------------------- |
| `TxTree` folder / file bodies                                                     | height (now host-driven)                         | yes                                 | done                                  |
| `TxTree` bytes ↔ decoded toggle                                                   | instant re-render                                | yes                                 | Phase 1                               |
| `TxTree` `.file-content` drag handle (`resize: vertical`)                         | continuous input                                 | yes                                 | Phase 1: disabled in the surface      |
| `tx-confirm-content` / `viewer-modal` error banner, OTP prompt, loading → content | instant re-render                                | yes                                 | Phase 1                               |
| `Drawer` sheet translate and height sync                                          | transform + height                               | no: standalone full-viewport box    | out of scope                          |
| `seams-auth-menu-surface` height spring                                           | height (parent tracks 1:1, `is-resize-animated`) | no: anchored menu, its own contract | out of scope                          |
| `ExportPrivateKey` viewer, `RecoveryCodeBackup` viewer                            | opacity / transform                              | mixed                               | audit only (Phase 2 invariance check) |

## Required Invariants

1. **One owner of motion.** The parent's ease is the only size animation of a
   measured modal. Content announces a target and then fills the box the
   parent has made, frame by frame.
2. **One measurement per change.** The host pins itself to the destination so
   the reporter posts it once. A stream of intermediate sizes makes the box
   chase a moving target.
3. **Intrinsic content height.** No `vh`/`dvh`/`svh`/`vw` and no viewport
   media queries under `data-w3a-confirm-surface='wallet-iframe'`. The
   viewport there is an output of the content, never an input to it.
4. **Never trust one frame of the box.** The child lands only on a size it has
   watched the box ease into, or one the box has held for several frames. The
   parent never lays the iframe out at a destination its ease has not reached.
5. **Prove it across the real boundary.** Same-process harnesses cannot see
   the destination blip. Sampling must happen after layout (ResizeObserver),
   never from a competing animation-frame callback, which reads one step stale.

## Target Architecture

### The seam

`confirm-surface-resize.ts` becomes the single entry for interior size changes,
with a component-facing helper:

```ts
announceSurfaceResize(target: EventTarget, {
  deltaCssPx: number,           // signed: +grow, -shrink
  setHeightCssPx(px): void,     // clamp the changing element to [0, |delta|]
  finish(): void,               // commit the final DOM state
}): boolean;                    // false → nobody hugs the box; animate locally
```

It dispatches `lit-surface-resize-begin` (the tree-specific
`lit-tree-resize-begin` is renamed; the detail shape is unchanged). The
choreographer is the only listener that may claim it. Components never touch
the host, the reporter, or the viewport.

### Component contract

A component that changes the modal's height:

1. lays out the new content but keeps the changing element clamped at its
   previous height (`overflow: hidden`, height driven by a CSS variable on the
   component, never an inline style — the wallet origin ships
   `style-src-attr 'none'`);
2. calls `announceSurfaceResize` with the delta and the two callbacks;
3. if it returns `false`, runs its own transition exactly as today;
4. never uses `vh`, `vw`, or height media queries in the surface, and never
   adds a `transition` on `height`, `max-height`, or `block-size` that is not
   gated on the unclaimed path.

### Parent contract

`overlay-controller.ts` keeps exactly this behaviour and nothing more: one ease
per accepted measurement, from the current visual rectangle, with the iframe
pinned to the origin until the ease owns the box; instant application under
`prefers-reduced-motion`. It never forwards its viewport to the child and
never retargets on its own.

## Implementation Phases

### Phase 0 — land the mechanism (done)

- [x] Host-driven tree growth, transition-free collapse, intrinsic caps,
      landing confirmation, origin pin, 180ms ease, cross-boundary guard.

### Phase 1 — one seam, all mutators

- [ ] Rename `lit-tree-resize-begin` → `lit-surface-resize-begin` in
      `lit-events.ts`; add `announceSurfaceResize` to
      `confirm-surface-resize.ts`; make `TxTree` call it instead of building
      the detail itself.
- [ ] Route the bytes ↔ decoded toggle in `TxTree` through the seam: measure the
      `.file-content-shell` before and after `updateComplete`, clamp it with a
      CSS variable, announce the delta.
- [ ] Route `tx-confirm-content` / `viewer-modal` discrete swaps (error banner,
      OTP prompt, loading → content) through the seam at the confirmer level.
- [ ] Set `resize: none` on `.file-content` under the wallet-iframe surface and
      keep the rem cap plus inner scroll; a box that eases 180ms behind the
      pointer cannot follow a drag.
- [ ] Audit `RecoveryCodeBackup` and `ExportPrivateKey` viewers for height
      transitions or viewport units inside measured boxes; fix or document.

### Phase 2 — invariants as failing tests

- [ ] Extend `confirmSurface.treeGrowth.integration.test.ts` with a
      viewport-invariance check: with no pin active, resize the parent box to
      two heights and assert the host's natural height is identical (catches
      any `vh` cap or height media query without enumerating selectors).
- [ ] Add a no-streaming assertion to the same test: during any toggle the
      child posts exactly one measurement.
- [ ] Add the bytes-toggle and error-banner paths to the same test once routed.
- [ ] Add a parent unit test to `tests/unit/overlayController.test.ts`: right
      after a measured→measured `apply()`, the iframe's rectangle still equals
      the origin; after the animation finishes it equals the destination.
- [ ] Keep `tests/lit-components/confirm-surface-resize.test.ts` as the
      scripted-box suite (blip, instant parent, stall, unclaimed path).

### Phase 3 — canaries for what tests cannot enumerate

- [ ] Streaming detector in `surface-measurement-reporter.ts`, dev builds only:
      more than three measurements within 100ms with no announced motion in
      flight logs a warning naming the surface. It is the symptom of every
      variant of this defect.
- [ ] Built-in trace: expose the per-frame sampler used during the R108
      investigation as `window.__w3aSurfaceMotion.trace()` in dev builds so the
      next investigation starts with numbers.
- [ ] Blip counter on the choreographer (frames held at target that then
      reversed), asserted zero by the headless guard once the origin pin is in
      the built dist.

## Boundary Contract

Unchanged wire: `SURFACE_MEASUREMENT` / `measured_v1` in
`walletIframe/shared/messages.ts`. What changes is the _semantics_ the child
promises: a measurement is a destination, posted once per change, never a
frame of an animation. The parent may rely on that to ease once. No new
message types and no parent viewport in the child.

## CI Gate

`validate-repository.yml` runs a curated list of unit tests today and neither
the wallet-iframe nor the lit-components suites. Add
`wallet-iframe/confirmSurface.treeGrowth.integration.test.ts` and
`lit-components/confirm-surface-resize.test.ts` to that curated step after
`build:prod`; both take under ten seconds. The guard is only a fence if it
runs on every change.

## Non-Goals

- The standalone (full-viewport) drawer, the anchored auth menu, and the
  export iframe keep their own motion contracts; their boxes do not hug.
- No change to the parent's geometry union, viewport fallback, or measurement
  wire format.
- No attempt to make the parent's ease follow continuous input (drag);
  continuous inputs are removed from the surface instead.

## Completion Criteria

- Every interior height change in a measured modal goes through
  `announceSurfaceResize`; `grep -rn "transition[^;]*height"` in the modal
  stylesheets finds only the unclaimed-path rules.
- The cross-boundary guard asserts one measurement per toggle, a card that
  never exceeds its box, landing only after intermediate sizes, and
  viewport-invariant content height, and runs in `validate-repository.yml`.
- A manual expand of the "Calling …" row in the live demo shows a single
  180ms motion with the buttons riding the box's bottom edge, on macOS overlay
  scrollbars and on classic scrollbars alike.
