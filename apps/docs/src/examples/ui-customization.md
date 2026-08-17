---
title: UI customization
description: Apply the same colors and shape presets to React components and wallet-iframe surfaces.
---

# UI customization

Seams exposes one theme vocabulary for app-owned React components and
wallet-iframe surfaces. Start with a small token override, then add a shape
preset when your product needs a different control geometry.

## Apply one theme

Use `Theme` for React-owned components and `setAppearance` for wallet-iframe
surfaces. Both receive the same colors and complete shape preset.

<<< ./theming.tsx

Set `appearance` in the provider config for the initial theme. Use
`setAppearance` when the person switches themes at runtime.

Send the full shape record to `setAppearance` as well. Appearance updates
merge key by key, so a complete preset avoids stale values when switching from
rounded controls back to square controls.

## Expected result

React-owned account and auth components read the `Theme` tokens. The auth menu,
transaction confirmer, and export viewer read the iframe appearance. Driving
both from the same preset keeps a theme switch visually consistent.

## Recoverable failures

- Missing token keys use the SDK defaults. Start from `SHAPE_PRESETS.square` or
  `SHAPE_PRESETS.rounded` when changing geometry.
- Render `Theme` above every React component that should receive the tokens;
  components outside that boundary keep their own styles.

Read the full [theming guide](/guides/theming) for token names, CSS variables,
runtime switching, and iframe details.
