---
title: Theming wallet surfaces
description: Apply one semantic color and shape system to app-owned React components and wallet-origin iframe surfaces.
---

# Theming wallet surfaces

Start with [UI customization](/examples/ui-customization). Seams renders UI in
two places: React components on the application origin and protected surfaces
on the wallet origin. Give both the same semantic palette and shape vocabulary.

## Apply a theme

- Use `Theme` and its tokens for app-owned React components.
- Set `appearance` during SDK configuration, or call `setAppearance`, for the
  auth menu, confirmer, and export viewer inside the wallet iframe.
- Start from `LIGHT_TOKENS`, `DARK_TOKENS`, and one `SHAPE_PRESETS` branch.
- Override semantic roles as a complete light/dark pair.
- Check text contrast, visible focus, status meaning, and forced-color behavior
  after every palette change.

See the detailed token table and code in the [theming
reference](/getting-started/theming).
