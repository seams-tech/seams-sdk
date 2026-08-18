# Key export slot-reveal animation

## Goal

Replace the `Decrypting…` text in the Exported Keys viewer with a restrained, slot-machine-style key reveal. Each character occupies a fixed monospace slot. The slots cycle independently while key material is being prepared, then decelerate and settle from left to right when the real key arrives.

The effect should communicate hidden computation becoming visible. It should feel precise and mechanical, without casino styling, glow, flashing, bounce, or layout movement.

## Visual behavior

### Loading

- Render a key-shaped row in the existing Private Key field instead of `Decrypting…`.
- Give every character its own fixed-width slot so changing glyphs never move adjacent content.
- For a secp256k1 export, show a stable `0x` visual anchor followed by 64 slots cycling through lowercase hexadecimal characters.
- Cycle slots at slightly different phases. The row should resemble many small reels running together rather than one string changing as a block.
- Keep the current Copy button disabled throughout loading and settling.
- Preserve the field's current two-line clamp and drawer dimensions at narrow widths.

The loading glyphs are cosmetic random data. They must never be derived from partial key material, and their motion must not imply measurable decryption progress.

### Settling

When the viewer receives the ready payload, stop the slots in a short left-to-right wave:

1. The first slot begins decelerating immediately.
2. Following slots begin at a small stagger, with several nearby slots allowed to overlap.
3. Each slot makes two or three slower glyph changes before landing.
4. Settled slots remain still while later slots continue cycling.
5. The complete wave lasts approximately 900–1,300 ms.

The final target is the same masked value the viewer renders today: the visible prefix and suffix settle to their real characters, while the protected middle settles to `x` characters. This change must preserve the current key-display policy. It must not briefly render the unmasked middle or place it in per-character DOM attributes. Copy continues to use the complete private key already supplied to the viewer.

Once the last slot lands, enable Copy and leave the final masked value static. The animation must run once for a loading-to-ready transition and must not replay on unrelated Lit updates, theme changes, or copy-state updates.

### Other key formats

Model the reel alphabet and display scaffold by export scheme:

- `secp256k1`: stable visual `0x` prefix and lowercase `0–9a–f` reels.
- `ed25519`: preserve the stable `ed25519:` prefix when present and use the key's supported encoded-character alphabet for the remaining reels.

The currently staged loading flow is secp256k1. Keep the implementation scheme-aware so a future staged Ed25519 payload can use the same component without pretending that a base-encoded key is hexadecimal. A viewer mounted directly with ready key material should retain the current static rendering; this task replaces the visible loading transition.

### Errors and cancellation

- If preparation fails, stop and clear the animation before rendering the existing error state.
- If the drawer closes, cancel its animation frame and release all animation state.
- If a new loading session replaces the current one, reset every slot before starting the new animation.

## Motion and accessibility

- Drive the reels from one `requestAnimationFrame` loop. Give each slot an independent change deadline and hold loading glyphs for 90–150 ms. During settling, lengthen those holds gradually toward 180–240 ms. This keeps the field active without flashing the complete key scaffold on every update. Fade each final glyph into place over 96 ms so the staggered landing remains legible.
- Keep the animated glyph container `aria-hidden="true"`. Expose one stable screen-reader status such as `Decrypting private key` while loading and `Private key ready` after settling. Frequent glyph updates must not enter a live region.
- Under `prefers-reduced-motion: reduce`, show a stable key-shaped masked placeholder during loading and switch immediately to the final masked value when ready.
- Pause visual updates while the document is hidden. Resume from elapsed time without extending or replaying a completed settle.
- Use existing text and muted color tokens. Motion is the only emphasis.

## Component state

Represent the presentation lifecycle as a discriminated union local to the viewer:

```ts
type ReelSlot = {
  glyph: string;
  nextChangeAtMs: number;
};

type PrivateKeyRevealState =
  | {
      kind: 'spinning';
      entryKey: string;
      prefix: string;
      alphabet: string;
      slots: ReelSlot[];
    }
  | {
      kind: 'settling';
      entryKey: string;
      prefix: string;
      alphabet: string;
      slots: ReelSlot[];
      targetSlots: string[];
      lockedSlots: number;
      startedAtMs: number;
    }
  | { kind: 'settled'; entryKey: string };
```

Use a stable entry identity derived from the entry index and scheme. Keep transition logic explicit and exhaustive:

- `loading + export entry` starts or continues `spinning`.
- `spinning + ready private key` starts `settling` toward the masked display string.
- `settling + final slot landed` becomes `settled` and enables Copy.
- error, disconnect, entry replacement, or a return to loading resets the state.

Do not infer animation state from CSS classes or diagnostics. Normalize the display scaffold once, then pass the narrow state required by each renderer.

## Implementation plan

1. In `packages/wallet/src/core/signingEngine/uiConfirm/ui/lit-components/ExportPrivateKey/viewer.ts`, extract the existing masking calculation into a standalone function that returns a plain display string. Reuse that result for both static rendering and the settle target.
2. Add standalone helpers for scheme-specific reel alphabets, loading scaffolds, cosmetic glyph selection, stagger timing, and exhaustive state transitions. Keep animation lifecycle methods on the element small and avoid nested function declarations.
3. Start the spinning state for each loading key row. Detect the existing `loading: true` to `loading: false` transition after the ready `keys` payload has arrived, then begin settling. Ready-on-mount entries stay static.
4. Schedule all reel updates through a single animation-frame owner on `ExportPrivateKeyViewer`. Request a Lit update only when one or more visible glyphs change. Cancel the frame on completion, error, reset, and `disconnectedCallback`.
5. Render one fixed-width span per visual slot, with the stable prefix outside the moving slot group. Keep animation output inaccessible to assistive technology and add a stable status label for the row.
6. In `packages/wallet/src/core/signingEngine/uiConfirm/ui/lit-components/css/export-viewer.css`, add the slot layout, settled/unsettled opacity treatment, and reduced-motion rules. Use the existing monospace font and theme tokens.
7. Leave `iframe-host.ts`, `iframe-export-bootstrap-script.ts`, worker messages, and export-domain payloads unchanged unless an implementation test demonstrates an ordering gap. The current session upsert already sends the ready `keys` payload and clears `loading` on the same mounted viewer.

## Verification

Add one focused Lit component test under `tests/lit-components/` covering the behavioral invariant:

- Loading renders key-shaped reels and no `Decrypting…` text.
- Copy is disabled while reels spin and while they settle.
- A ready update settles to the existing masked representation, never exposes the protected middle in rendered text or attributes, and enables Copy only after the final slot lands.
- An already-ready initial render remains static.
- An error or disconnect cancels the scheduled animation.
- Reduced motion skips settling and renders the final masked representation immediately.

Use deterministic time and glyph selection in the test through injected helper inputs or browser clock control. Do not make production randomness deterministic solely for test convenience.

Run the narrow component test first, then the existing strict-CSP element test because this component loads external CSS inside the export iframe:

```sh
pnpm test:lit-components -- <new-key-export-animation-test>
pnpm test:lit-components -- tests/lit-components/coep.strict.all-elements.test.ts
pnpm check
```

## Acceptance criteria

- No visible `Decrypting…` placeholder remains in a Private Key row.
- Loading looks like fixed character reels cycling independently.
- Ready key material triggers a single left-to-right slot settle lasting about one second.
- The rendered final value and copied value retain their current security behavior.
- Copy cannot run before the last slot settles.
- The drawer does not resize or shift during the transition.
- Reduced-motion, error, replacement, and disconnect paths leave no running animation.
- No protocol, persistence, worker, or export-domain compatibility path is introduced for this presentation change.
