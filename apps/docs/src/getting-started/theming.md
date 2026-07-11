---
title: Theming
---

# Theming

Every wallet surface the SDK renders — the auth menu, account menus, and the
transaction confirmer inside the wallet iframe — reads its appearance from one
token vocabulary: **colors** (what things are painted) and **shape** (how
components are drawn: radii, control sizes, field treatment). Tokens become
CSS custom properties, so a theme is just data.

There are two delivery channels, one per rendering context:

| Surface | Rendered by | Themed via |
| --- | --- | --- |
| Auth menu, profile/account components | Your app (React) | `<Theme>` provider tokens |
| Tx confirmer drawer/modal, export viewer | Wallet iframe (isolated origin) | `appearance` config / `seams.setAppearance()` |

Both channels accept the same color and shape records, so one preset object
can drive the whole product.

## Quick Start

Wrap the SDK components in `Theme` and pass token overrides for the active
mode:

```tsx
import { Theme } from '@seams/sdk/react';

<Theme
  theme="light"
  tokens={{
    light: {
      colors: {
        colorBackground: '#ffffff',
        textPrimary: '#000000',
        buttonBackground: '#000000',
      },
    },
  }}
>
  <SeamsAuthMenu />
</Theme>
```

Then push the same tokens into the wallet iframe so embedded surfaces (the
signing confirmer, key export viewer) match:

```ts
seams.setAppearance({
  theme: {
    id: 'my-theme',
    mode: 'light',
    colors: {
      colorBackground: '#ffffff',
      textPrimary: '#000000',
      buttonBackground: '#000000',
    },
  },
  palette: 'default',
});
```

Appearance can also be set once at init via `SeamsConfigsInput.appearance`;
`setAppearance` is for runtime switching (theme pickers, dark-mode toggles).
Updates merge over the previous appearance, keyed per mode.

## Color Tokens

Every key in the `colors` record is emitted as `--w3a-colors-<key>`. The core
vocabulary:

| Group | Tokens | Notes |
| --- | --- | --- |
| Canvas | `colorBackground`, `surface`, `surface2`–`surface4`, `txDetailsBackground` | Card background and the muted surface ladder. |
| Text | `textPrimary`, `textSecondary`, `textMuted`, `textButton` | `textButton` is the label color on filled buttons. |
| Primary button | `buttonBackground`, `buttonHoverBackground` | The single filled CTA. |
| Secondary button | `secondaryButtonBackground`, `secondaryButtonHoverBackground`, `secondaryButtonBorder`, `secondaryButtonText` | Social/SSO and secondary actions. Use a bordered-surface look for a quiet hierarchy, or a fill for a branded one. |
| Borders | `borderPrimary`, `borderSecondary`, `borderHover` | Hairlines carry structure; keep them visible against the canvas. |
| Status | `success`, `warning`, `error`, `info`, `focus` | `focus` drives input focus states. |
| Tx highlights | `highlightReceiver`, `highlightMethodName`, `highlightAmount`, `highlightRow`, `highlightHalo` | Colors inside the confirmer's transaction tree. For a restrained look, set method names and amounts to `textPrimary` and let only the receiver carry an accent. |

Unknown keys are passed through as vars, so component-specific tokens (e.g.
`lastUsedBadgeBackground`) work without SDK changes.

## Shape Presets

Shape controls geometry: corner radii, control heights, and whether text
fields are bordered surfaces or tinted pills. Two presets ship with the SDK:

- **`square`** (default) — compact rectangles: 16px cards, 10px buttons and
  fields, 44px controls, bordered-white inputs. Nothing to configure.
- **`rounded`** — the soft pill look: 3rem cards, 2rem pill buttons, 52–54px
  controls, tinted pill inputs.

```tsx
import { Theme, SHAPE_PRESETS } from '@seams/sdk/react';

<Theme
  theme="light"
  tokens={{ light: { colors: myColors, shape: SHAPE_PRESETS.rounded } }}
>
  <SeamsAuthMenu />
</Theme>
```

And for the iframe surfaces:

```ts
seams.setAppearance({
  theme: {
    id: 'my-theme',
    mode: 'light',
    colors: myColors,
    shape: { ...SHAPE_PRESETS.rounded },
  },
});
```

::: tip Always send the full shape record
Appearance updates merge key-by-key. Spreading the whole preset guarantees a
switch from `rounded` back to `square` overwrites every key instead of
leaving stale pill values behind.
:::

### Shape Tokens

Each key is emitted as `--w3a-shape-<key>`. When a key (or the whole record)
is omitted, component CSS falls back to the `square` values.

| Token | Applies to | `square` | `rounded` |
| --- | --- | --- | --- |
| `card` | Auth card, modal, drawer sheet corners | `16px` | `3rem` |
| `control` | Buttons | `10px` | `2rem` |
| `field` | Text inputs | `10px` | `2rem` |
| `box` | Data readouts (tx tree, identity panels) | `10px` | `1.5rem` |
| `item` | List rows, labels, small tooltips | `8px` | `1rem` |
| `controlHeight` | Primary buttons (secondary actions derive −4px) | `44px` | `52px` |
| `fieldHeight` | Text inputs | `44px` | `54px` |
| `fieldBackground` | Input face | `var(--w3a-colors-surface)` | `var(--w3a-colors-surface2)` |
| `fieldBorder` | Input border | `var(--w3a-colors-borderPrimary)` | softened `borderPrimary` |

Values may reference other CSS variables, which is how the field treatment
stays theme-reactive.

### Custom Geometry

Presets are just token bundles — override individual keys for a brand-exact
spec:

```ts
import { SHAPE_PRESETS, type ShapeTokens } from '@seams/sdk/react';

const brandShape: ShapeTokens = {
  ...SHAPE_PRESETS.square,
  card: '24px',
  control: '6px',
  field: '6px',
};
```

Prefer starting from a preset over hand-assembling all nine keys: the preset
keeps radii, sizes, and field treatment coherent as a set.

## Keeping Both Channels In Sync

Drive both channels from one preset object so a theme switch re-skins the
React card and the iframe confirmer together:

```tsx
const preset = {
  id: 'paper',
  mode: 'light' as const,
  colors: PAPER_COLORS,
  shape: SHAPE_PRESETS.square,
};

// React surfaces
<Theme theme={preset.mode} tokens={{ [preset.mode]: { colors: preset.colors, shape: preset.shape } }}>
  {children}
</Theme>

// Iframe surfaces — re-run whenever the preset changes
React.useEffect(() => {
  seams.setAppearance({
    theme: {
      id: preset.id,
      mode: preset.mode,
      colors: preset.colors,
      shape: { ...preset.shape },
    },
  });
}, [seams, preset]);
```

## CSS Variable Reference

How token groups map to custom properties:

| Token group | CSS variable pattern | Example |
| --- | --- | --- |
| `colors` | `--w3a-colors-<key>` | `tokens.colors.primary` → `--w3a-colors-primary` |
| `shape` | `--w3a-shape-<key>` | `tokens.shape.card` → `--w3a-shape-card` |
| `spacing` | `--w3a-spacing-<key>` | `tokens.spacing.md` → `--w3a-spacing-md` |
| `borderRadius` | `--w3a-border-radius-<key>` | `tokens.borderRadius.lg` → `--w3a-border-radius-lg` |
| `shadows` | `--w3a-shadows-<key>` | `tokens.shadows.sm` → `--w3a-shadows-sm` |

On the React side the variables are set inline on the `Theme` boundary
element; inside the wallet iframe they're injected as `!important` overrides
scoped to the active mode, so app-provided tokens win over the SDK's
defaults.
