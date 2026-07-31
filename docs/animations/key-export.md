# Key export tile-ripple animation

## Goal

Replace the `Decrypting…` text in the Exported Keys viewer with a dense field of small colored tiles. A continuous wave moves across the tiles while key material is being prepared, then the field dissolves into the masked key when the real key arrives.

The effect should communicate hidden computation becoming visible. It should feel fluid and precise, without flashing, bounce, or layout movement.

## Visual behavior

### Loading

- Render a four-row field of small rounded tiles in the existing Private Key field instead of `Decrypting…`.
- Vary tile opacity and scale in staggered phases to create a soft horizontal ripple with several shades of the theme's accent color.
- Run the ripple with CSS transforms and opacity so it updates at the display refresh rate without JavaScript-driven visual steps.
- Keep the current Copy button disabled throughout loading and settling.
- Preserve the field's current two-line clamp and drawer dimensions at narrow widths.

The tiles are cosmetic. Their motion must not derive from partial key material or imply measurable decryption progress.

### Settling

When the viewer receives the ready payload:

1. Keep the ripple running as the tile field begins fading.
2. Crossfade the complete masked key into view.
3. Complete the transition approximately 360 ms after the ready payload arrives.

The final target masks exactly the middle 24 key characters. The remaining leading and trailing characters are split evenly and settle to their real values, while the protected middle settles to `x` characters. The key prefix remains visible and is excluded from the split. The animation must never render the unmasked middle or place it in per-character DOM attributes. Copy continues to use the complete private key already supplied to the viewer.

Layer the complete masked target over the tile field during settling. Keep the tile structure stable until the crossfade completes.

Once the crossfade completes, enable Copy and leave the final masked value static. The animation must run once for a loading-to-ready transition and must not replay on unrelated Lit updates, theme changes, or copy-state updates.

### Other key formats

The tile field is encoding-neutral and can represent secp256k1 and Ed25519 preparation without suggesting that either key format is already available. A viewer mounted directly with ready key material retains the static rendering.

### Errors and cancellation

- If preparation fails, stop and clear the animation before rendering the existing error state.
- If the drawer closes, cancel its animation frame and release all animation state.
- If a new loading session replaces the current one, reset the ripple before starting the new animation.

## Motion and accessibility

- Animate the tiles with CSS opacity and transforms at the display refresh rate. JavaScript owns only the 360 ms presentation-state transition after the ready payload arrives.
- Keep the animated tile container `aria-hidden="true"`. Expose one stable screen-reader status such as `Decrypting private key` while loading and `Private key ready` after settling.
- Under `prefers-reduced-motion: reduce`, show a stable key-shaped masked placeholder during loading and switch immediately to the final masked value when ready.
- Pause visual updates while the document is hidden. Resume from elapsed time without extending or replaying a completed settle.
- Use existing text and muted color tokens. Motion is the only emphasis.

## Component state

Represent the presentation lifecycle as a discriminated union local to the viewer:

```ts
type PrivateKeyRevealState =
  | {
      kind: 'rippling';
      entryKey: string;
    }
  | {
      kind: 'settling';
      entryKey: string;
      maskedTarget: string;
      startedAtMs: number;
    }
  | { kind: 'settled'; entryKey: string };
```

Use a stable entry identity derived from the entry index and scheme. Keep transition logic explicit and exhaustive:

- `loading + export entry` starts or continues `rippling`.
- `rippling + ready private key` starts `settling` toward the masked display string.
- `settling + crossfade complete` becomes `settled` and enables Copy.
- error, disconnect, entry replacement, or a return to loading resets the state.

Do not infer animation state from CSS classes or diagnostics. Normalize the display scaffold once, then pass the narrow state required by each renderer.

## Implementation plan

1. In `packages/sdk-web/src/core/signingEngine/uiConfirm/ui/lit-components/ExportPrivateKey/viewer.ts`, reuse the masking calculation for both static rendering and the settle target.
2. Start the rippling state for each loading key row. Detect the existing `loading: true` to `loading: false` transition after the ready `keys` payload has arrived, then begin settling. Ready-on-mount entries stay static.
3. Render a fixed tile grid whose phase classes create the ripple without inline styles. Keep animation output inaccessible to assistive technology and add a stable status label for the row.
4. Use one animation-frame owner only to finish the settling lifecycle and enable Copy. Cancel it on completion, error, reset, and `disconnectedCallback`.
5. In `packages/sdk-web/src/core/signingEngine/uiConfirm/ui/lit-components/css/export-viewer.css`, define the tile grid, phase offsets, ripple motion, crossfade, and reduced-motion treatment using existing theme tokens.
6. Leave `iframe-host.ts`, `iframe-export-bootstrap-script.ts`, worker messages, and export-domain payloads unchanged unless an implementation test demonstrates an ordering gap. The current session upsert already sends the ready `keys` payload and clears `loading` on the same mounted viewer.

## Verification

Add one focused Lit component test under `tests/lit-components/` covering the behavioral invariant:

- Loading renders the tile ripple and no `Decrypting…` text.
- Copy is disabled while tiles ripple and while they settle.
- A ready update settles to the existing masked representation, never exposes the protected middle in rendered text or attributes, and enables Copy only after the crossfade completes.
- An already-ready initial render remains static.
- An error or disconnect cancels the scheduled animation.
- Reduced motion skips settling and renders the final masked representation immediately.

Use browser clock control if deterministic transition timing is needed. The CSS ripple itself does not mutate application state.

Run the narrow component test first, then the existing strict-CSP element test because this component loads external CSS inside the export iframe:

```sh
pnpm test:lit-components -- <new-key-export-animation-test>
pnpm test:lit-components -- tests/lit-components/coep.strict.all-elements.test.ts
pnpm check
```

## Acceptance criteria

- No visible `Decrypting…` placeholder remains in a Private Key row.
- Loading shows a dense, smoothly animated field of colored tiles.
- Ready key material triggers one synchronized crossfade lasting approximately 360 ms.
- The rendered final value and copied value retain their current security behavior.
- Copy cannot run before the synchronized crossfade completes.
- The drawer does not resize or shift during the transition.
- Reduced-motion, error, replacement, and disconnect paths leave no running animation.
- No protocol, persistence, worker, or export-domain compatibility path is introduced for this presentation change.
