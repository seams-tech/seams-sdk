---
title: Theme wallet surfaces
description: Apply the same color and shape tokens to React components and wallet-origin surfaces.
---

# Theme wallet surfaces

Seams renders UI in your React app and in the protected wallet iframe. Reuse
the same color and shape values so auth, signing, and export screens match your
product.

## Apply one theme

This example applies the same colors and rounded shape to an app-owned auth
menu and the wallet-iframe surfaces.

<<< ../examples/theming.tsx

`Theme` scopes token overrides to components rendered by your React app. Call
`applyWalletTheme` after creating the `SeamsWeb` client so the wallet-origin
auth menu, transaction confirmer, and export viewer receive the same values.

## Set the initial appearance

Set the initial value with `SeamsConfigsInput.appearance`. Use
`setAppearance` when a theme picker or system-mode change happens at runtime;
updates merge into the current appearance.

## Change shape safely

`SHAPE_PRESETS` keeps card radii, control sizes, and field treatment consistent.
Spread the complete preset when updating the iframe so a previous shape cannot
leave stale values behind.

## Token names

Colors become `--w3a-colors-<key>` and shape values become
`--w3a-shape-<key>`. Common color roles include `colorBackground`,
`textPrimary`, `textSecondary`, `buttonBackground`, status colors, and
transaction highlights. Wallet-iframe appearance accepts additional color
keys, so a component-specific role can pass through without an SDK release.

See the [theming guide](/guides/theming) for accessibility checks and the
[React reference](/reference/react#appearance) for exported token types.
