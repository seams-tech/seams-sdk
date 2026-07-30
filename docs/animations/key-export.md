# Key export slot-reveal animation

## Goal

Replace the `Decrypting…` text in the Exported Keys viewer with a restrained, slot-machine-style key reveal. Each character occupies a fixed monospace slot. The slots cycle independently while key material is being prepared, then decelerate and settle from left to right when the real key arrives.

The effect should communicate hidden computation becoming visible. It should feel precise and mechanical, without casino styling, glow, flashing, bounce, or layout movement.

## Visual behavior

### Loading

- Render a key-shaped row in the existing Private Key field.
- Give every character its own fixed-width slot so changing glyphs never move adjacent content.
- For a secp256k1 export, show a stable `0x` anchor followed by 64 lowercase hexadecimal slots.
- Cycle the slots independently at a restrained 12–18 updates per second.
- Keep Copy disabled throughout loading and settling.
- Preserve the field's two-line clamp and drawer dimensions at narrow widths.

The loading glyphs are cosmetic random data. They are never derived from partial key material and do not imply measurable decryption progress.

### Settling

When the viewer receives the ready payload, stop the slots in a short left-to-right wave:

1. The first slot begins decelerating immediately.
2. Following slots begin at a small stagger, with nearby slots overlapping.
3. Each slot makes several slower glyph changes before landing.
4. Settled slots remain still while later slots continue cycling.
5. The complete wave lasts approximately 900–1,300 ms.

The target is the same masked value the viewer renders today: the visible prefix and suffix settle to their real characters, while the protected middle settles to `x`. The animation must never briefly render the unmasked middle or place it in per-character DOM attributes. Copy continues to use the complete private key already supplied to the viewer.

Enable Copy after the last slot lands. The reveal runs once for a loading-to-ready transition and does not replay on theme, copy-state, or unrelated Lit updates.

### Key formats

- `secp256k1`: stable `0x` prefix and lowercase `0–9a–f` reels.
- `ed25519`: stable `ed25519:` prefix when present and base58 reels.

The currently staged loading flow is secp256k1. A viewer mounted directly with ready material retains its static rendering.

### Errors and cleanup

- Stop and clear the animation before rendering an error state.
- Cancel the animation frame when the drawer disconnects.
- Reset all slots when a new loading entry replaces the current one.

## Motion and accessibility

- Drive every reel from one `requestAnimationFrame` owner.
- Keep animated glyphs `aria-hidden="true"` and expose one stable screen-reader status for loading and readiness.
- Under `prefers-reduced-motion: reduce`, show a stable masked scaffold and switch immediately to the final masked value.
- Let hidden documents pause naturally, then resume from elapsed time without replaying completed work.
- Use existing typography and color tokens. Motion is the only emphasis.

## Component state

Represent the presentation lifecycle as a discriminated union local to the viewer:

```ts
type PrivateKeyRevealState =
  | { kind: 'spinning'; entryKey: string; slots: string[] }
  | {
      kind: 'settling';
      entryKey: string;
      slots: string[];
      targetSlots: string[];
      startedAtMs: number;
    }
  | { kind: 'settled'; entryKey: string };
```

Use a stable identity derived from entry index and scheme. Keep transitions explicit:

- `loading + export entry` starts or continues `spinning`.
- `spinning + ready private key` starts `settling` toward the masked display string.
- `settling + final slot landed` becomes `settled` and enables Copy.
- Error, disconnect, replacement, or a return to loading resets the state.

## Implementation

1. Extract private-key masking into a standalone display function reused by static and animated rendering.
2. Add scheme-specific reel definitions and standalone timing/state helpers.
3. Detect the existing loading-to-ready transition in `ExportPrivateKeyViewer`; keep worker messages and domain payloads unchanged.
4. Run all entries from one animation frame and request a Lit update only when visible glyph state changes.
5. Render fixed-width glyph spans with an inaccessible animation layer and stable assistive status.
6. Add slot and reduced-motion rules to `export-viewer.css` using current theme tokens.
7. Add focused Lit component coverage for normal motion, reduced motion, errors, masking, Copy gating, and ready-on-mount behavior.

## Acceptance criteria

- A Private Key loading row contains no visible `Decrypting…` placeholder.
- Loading appears as fixed character reels cycling independently.
- Ready material triggers one left-to-right settle lasting about one second.
- The final masked display and full copied value retain their current security behavior.
- Copy cannot run before the final slot settles.
- The drawer does not resize or shift during the transition.
- Reduced-motion, error, replacement, and disconnect paths leave no running animation.
- No protocol, persistence, worker, or compatibility path is introduced.
