import { SHAPE_PRESETS } from '@seams/wallet/react';
import type { SeamsConfigsInput, ThemeProps, WalletShapeId } from '@seams/wallet/react';

type SdkAppearance = NonNullable<SeamsConfigsInput['appearance']>;

/* Contained drop shadows — the SDK default shadows.lg overflows the demo cell
   and clips; these keep the card lift within bounds. */
const CONTAINED_SHADOW_LIGHT =
  '0 2px 6px -2px rgba(15, 23, 42, 0.12), 0 12px 28px -16px rgba(15, 23, 42, 0.28)';
const CONTAINED_SHADOW_DARK =
  '0 2px 6px -2px rgba(0, 0, 0, 0.5), 0 14px 30px -16px rgba(0, 0, 0, 0.7)';

export const ROSE_PINE_DARK_COLORS: Record<string, string> = {
  primary: '#c4a7e7',
  primaryHover: '#9ccfd8',
  secondary: '#31748f',
  secondaryHover: '#ebbcba',
  accent: '#f6c177',

  textPrimary: '#e0def4',
  textSecondary: '#908caa',
  textMuted: '#6e6a86',
  textButton: '#191724',

  buttonBackground: '#c4a7e7',
  buttonHoverBackground: '#9ccfd8',
  secondaryButtonBackground: '#ebbcba',
  secondaryButtonHoverBackground: '#f6c177',
  secondaryButtonBorder: 'transparent',
  secondaryButtonText: '#191724',

  colorBackground: '#191724',
  surface: '#1f1d2e',
  surface2: '#26233a',
  txDetailsBackground: '#26233a',
  surface3: '#312f44',
  surface4: '#403d52',

  hover: '#26233a',
  active: '#403d52',
  focus: '#9ccfd8',

  success: '#31748f',
  warning: '#f6c177',
  error: '#eb6f92',
  info: '#9ccfd8',

  borderPrimary: '#524f67',
  borderSecondary: '#403d52',
  borderHover: '#6e6a86',

  gradientPrimary: 'linear-gradient(120deg, #1f1d2e 0%, #c4a7e7 100%)',
  gradientSecondary: 'linear-gradient(120deg, #191724 0%, #31748f 100%)',
  gradientTertiary: 'linear-gradient(120deg, #191724 0%, #26233a 100%)',

  highlightPrimary: '#c4a7e7',
  // Dark-mode tx row highlight: use a deeper Rose Pine purple shade.
  highlightRow: '#403d52',
  highlightHalo: '#e2d1f5',
  highlightReceiver: '#9ccfd8',
  highlightMethodName: '#c4a7e7',
  highlightAmount: '#f6c177',
};

export const ROSE_PINE_LIGHT_COLORS: Record<string, string> = {
  primary: '#907aa9',
  primaryHover: '#56949f',
  secondary: '#286983',
  secondaryHover: '#d7827e',
  accent: '#ea9d34',

  textPrimary: '#575279',
  textSecondary: '#797593',
  textMuted: '#9893a5',
  textButton: '#fffaf3',

  buttonBackground: '#907aa9',
  buttonHoverBackground: '#56949f',
  secondaryButtonBackground: '#ebbcba',
  secondaryButtonHoverBackground: '#e6a7a4',
  secondaryButtonBorder: 'transparent',
  secondaryButtonText: '#575279',

  colorBackground: '#faf4ed',
  surface: '#fffaf3',
  // lighter than Rose Pine's stock overlay so the seg track / readout
  // surfaces stay airy on the cream card
  surface2: '#f7f0e6',
  txDetailsBackground: '#fffaf3',
  surface3: '#eee6dc',
  surface4: '#e5dcd2',

  hover: '#f2e9de',
  active: '#dfdad9',
  focus: '#56949f',

  success: '#286983',
  warning: '#ea9d34',
  error: '#b4637a',
  info: '#56949f',

  borderPrimary: '#cecacd',
  borderSecondary: '#dfdad9',
  borderHover: '#9893a5',

  gradientPrimary: 'linear-gradient(120deg, #fffaf3 0%, #f2e9de 100%)',
  gradientSecondary: 'linear-gradient(120deg, #faf4ed 0%, #907aa9 100%)',
  gradientTertiary: 'linear-gradient(120deg, #faf4ed 0%, #fffaf3 100%)',

  highlightPrimary: '#907aa9',
  // Light-mode tx row highlight: use a soft Rose Pine purple tint.
  highlightRow: 'rgba(144, 122, 169, 0.24)',
  // Lighter Rose Pine iris for halo ring in light mode.
  highlightHalo: '#d7b9ea',
  highlightReceiver: '#56949f',
  highlightMethodName: '#907aa9',
  highlightAmount: '#ea9d34',
};

// ============================================================================
// Live-demo theme presets (fed to the SeamsAuthMenu via the SDK Theme provider)
// ============================================================================

// "Paper" — the ElevenLabs style: eggshell paper, ink buttons, warm
// taupe/stone neutrals, and soft blue accents for focused details.
export const PAPER_LIGHT_COLORS: Record<string, string> = {
  primary: '#2f9a76',
  primaryHover: '#157f5f',
  secondary: '#44403b',
  secondaryHover: '#000000',
  accent: '#2f9a76',

  textPrimary: '#000000',
  textSecondary: '#777169',
  textMuted: '#a59f97',
  textButton: '#fdfcfc',

  buttonBackground: '#000000',
  buttonHoverBackground: '#262626',
  // quiet bordered-white secondary (Google SSO): one black CTA per card,
  // like the ElevenLabs button hierarchy
  secondaryButtonBackground: '#ffffff',
  secondaryButtonHoverBackground: '#f5f3f1',
  secondaryButtonBorder: '#dcd6cd',
  secondaryButtonText: '#000000',

  // white menu card; the reference's eggshell #fdfcfc read too warm here
  colorBackground: '#ffffff',
  surface: '#ffffff',
  // chip behind the passkey halo icon: same subtle grey as the tx-details
  // box so the two read as one family
  passkeyHaloBackground: '#f8f8f7',
  surface2: '#f5f3f1',
  surface3: '#ebe8e4',
  surface4: '#e1ddd7',
  txDetailsBackground: '#f8f8f7',

  hover: '#f5f3f1',
  active: '#ebe8e4',
  focus: '#000000',

  success: '#157f5f',
  warning: '#b45309',
  error: '#ff4704',
  info: '#2f9a76',

  borderPrimary: '#ebe8e4',
  borderSecondary: '#e5e5e5',
  borderHover: '#d6d1cb',

  highlightPrimary: '#2f9a76',
  highlightRow: 'rgba(47, 154, 118, 0.12)',
  highlightHalo: '#c3e5d7',
  // one accent in the tx tree: the receiver/contract address. Method names
  // and amounts read in ink (ElevenLabs accent discipline).
  highlightReceiver: '#157f5f',
  highlightMethodName: '#000000',
  highlightAmount: '#000000',
};

// "Carbon" — the SDK's stock dark slate ramp (hue-240 oklch tokens from
// theme/palette.json, resolved to sRGB). Every control is a slate slab; the
// primary CTA leads by sitting one step lighter on the ramp rather than by
// inverting to white.
export const CARBON_DARK_COLORS: Record<string, string> = {
  primary: '#5cacff',
  primaryHover: '#499fff',
  secondary: '#876cca',
  secondaryHover: '#9b78de',
  accent: '#00cb9b',

  textPrimary: '#f4f5f6',
  textSecondary: '#8b959d',
  textMuted: '#626e76',
  textButton: '#f4f5f6',

  // slate600 — the lit step the reference card uses for its active segment;
  // one rung above the slabs, so the CTA leads without leaving the ramp
  buttonBackground: '#3c4a54',
  buttonHoverBackground: '#4c5c68',
  // secondary (Google SSO) rides the same slate slab as the other
  // non-primary actions, so only the CTA sits lifted
  secondaryButtonBackground: '#252f37',
  secondaryButtonHoverBackground: '#303c45',
  secondaryButtonBorder: '#3e4952',
  secondaryButtonText: '#f4f5f6',

  colorBackground: '#12171a',
  // surface backs the slate slabs: secondary buttons, Scan-and-Link, and
  // the square-shape input field
  surface: '#252f37',
  // chip behind the passkey halo icon: one step down from the slabs
  passkeyHaloBackground: '#1a2329',
  // surface2 is the shared hover step: the Scan-and-Link button takes it
  // directly, the SSO button via secondaryButtonHoverBackground. Both must
  // resolve to the same value or the two slabs light up differently.
  surface2: '#303c45',
  surface3: '#10171c',
  surface4: '#0a1116',
  txDetailsBackground: '#1a2329',

  hover: '#303c45',
  active: '#323c43',
  focus: '#5cacff',

  success: '#00cb9b',
  warning: '#cea700',
  error: '#ff7a80',
  info: '#5cacff',

  borderPrimary: '#323c43',
  borderSecondary: '#303c45',
  borderHover: '#3e4952',

  highlightPrimary: '#5cacff',
  highlightRow: 'rgba(92, 172, 255, 0.12)',
  highlightHalo: '#9ecdff',
  // one accent in the tx tree, mirroring Paper: receiver in blue, method
  // names and amounts in off-white ink
  highlightReceiver: '#5cacff',
  highlightMethodName: '#f4f5f6',
  highlightAmount: '#f4f5f6',
};

// "Greenhouse" — the Ironclad palette (ironcladapp.com, from their own color
// presets): navy ink on layered creams with the Ironclad green pair
// (#308970 brand / #00ca88 logo) doing the accent work.
const GREENHOUSE_LIGHT_COLORS: Record<string, string> = {
  primary: '#308970',
  primaryHover: '#27735e',
  secondary: '#1c212b',
  secondaryHover: '#308970',
  accent: '#00ca88',

  textPrimary: '#1c212b',
  textSecondary: '#555555',
  textMuted: '#adb9c4',
  textButton: '#ffffff',

  buttonBackground: '#308970',
  secondaryButtonBackground: '#308970',
  secondaryButtonHoverBackground: '#27735e',
  secondaryButtonBorder: 'transparent',
  secondaryButtonText: '#ffffff',
  buttonHoverBackground: '#27735e',

  colorBackground: '#ffffff',
  surface: '#f5f5f3',
  surface2: '#f2f1ee',
  surface3: '#e9e5df',
  surface4: '#dcd6cd',

  hover: '#f2f1ee',
  active: '#e9e5df',
  focus: '#308970',

  success: '#308970',
  warning: '#b45309',
  error: '#cf2e2e',
  info: '#3860be',

  borderPrimary: '#e3ded6',
  borderSecondary: '#edeae5',
  borderHover: '#c9c2b6',

  highlightPrimary: '#00ca88',
  highlightRow: 'rgba(0, 202, 136, 0.12)',
  highlightHalo: '#7bdcb5',
  highlightReceiver: '#308970',
  highlightMethodName: '#1c212b',
  highlightAmount: '#308970',
};

// "Pastel Dark" — the Pastel Rainbow palette on charcoal (Outlander-dashboard
// style): plum-charcoal layers, mint carrying the CTAs with dark ink, and the
// remaining pastels as status/highlight tones (pastels are light, so they
// read directly on dark surfaces).
const PASTEL_DARK_COLORS: Record<string, string> = {
  primary: '#C9E4DE',
  primaryHover: '#b1d6cd',
  secondary: '#b5b0bd',
  secondaryHover: '#f4f1ea',
  accent: '#DBCDF0',

  textPrimary: '#f4f1ea',
  textSecondary: '#b5b0bd',
  textMuted: '#847f8e',
  textButton: '#1e1d22',

  buttonBackground: '#C9E4DE',
  buttonHoverBackground: '#b1d6cd',
  // lavender pastel secondary (Google SSO) button
  secondaryButtonBackground: '#DBCDF0',
  secondaryButtonHoverBackground: '#cfbfe9',
  secondaryButtonBorder: 'transparent',
  secondaryButtonText: '#1e1d22',

  colorBackground: '#1e1d22',
  surface: '#26252b',
  surface2: '#2e2d34',
  surface3: '#38363f',
  surface4: '#423f4a',
  txDetailsBackground: '#2e2d34',

  hover: '#2e2d34',
  active: '#38363f',
  focus: '#C6DEF1',

  success: '#C9E4DE',
  warning: '#F7D9C4',
  error: '#F2C6DE',
  info: '#C6DEF1',

  borderPrimary: '#3a3841',
  borderSecondary: '#302e37',
  borderHover: '#4c4956',

  highlightPrimary: '#C6DEF1',
  highlightRow: 'rgba(198, 222, 241, 0.12)',
  highlightHalo: '#8fb9de',
  highlightReceiver: '#C6DEF1',
  highlightMethodName: '#f4f1ea',
  highlightAmount: '#F2C6DE',
};

// "Pastel" — the Pastel Rainbow palette (kdesign.co #09): paper cream,
// mint #C9E4DE, baby blue #C6DEF1, lavender #DBCDF0, and pink #F2C6DE.
// Pastels can't carry white text, so the primary button is baby blue with plum
// ink, and the semantic tones are deepened from their pastel.
const PASTEL_LIGHT_COLORS: Record<string, string> = {
  // deepened from the baby blue: primary also colors text (active seg label,
  // links), where #C6DEF1 fails contrast; the button itself stays pastel via
  // buttonBackground
  primary: '#6f9fd8',
  primaryHover: '#5a8cc7',
  secondary: '#55505e',
  secondaryHover: '#2f2a38',
  accent: '#DBCDF0',

  textPrimary: '#2f2a38',
  textSecondary: '#6f6a7a',
  textMuted: '#a8a2b3',
  textButton: '#2f2a38',

  buttonBackground: '#C6DEF1',
  buttonHoverBackground: '#aed0ec',
  // lavender secondary (Google SSO) button, the palette's second accent
  secondaryButtonBackground: '#DBCDF0',
  secondaryButtonHoverBackground: '#cfbfe9',
  secondaryButtonBorder: 'transparent',

  // subtle near-white cream menu card with lightly warmer controls and chrome
  colorBackground: '#fffefd',
  surface: '#fffdf9',
  // light-grey chip behind the passkey halo icon (surface ≈ modal bg here);
  // kept a touch warmer/darker than the modal bg so the chip stays visible
  passkeyHaloBackground: '#efeadf',
  surface2: '#fffaf3',
  surface3: '#F2C6DE',
  surface4: '#DBCDF0',
  txDetailsBackground: '#fffaf3',

  hover: '#fffbf6',
  active: '#fff8ee',
  focus: '#8fb9de',

  success: '#4f9e83',
  lastUsedBadgeBackground: '#F2C6DE',
  lastUsedBadgeText: '#2f2a38',
  warning: '#e6c891',
  error: '#d4547a',
  info: '#6f9fd8',

  borderPrimary: '#f4eedf',
  borderSecondary: '#faf4e9',
  borderHover: '#eadfcb',

  highlightPrimary: '#8fb9de',
  highlightRow: 'rgba(198, 222, 241, 0.28)',
  highlightHalo: '#C6DEF1',
  highlightReceiver: '#6f9fd8',
  highlightMethodName: '#2f2a38',
  highlightAmount: '#d4547a',
};

export type DemoThemeId =
  | 'paper'
  | 'carbon'
  | 'rose-pine-dark'
  | 'rose-pine-light'
  | 'greenhouse'
  | 'pastel'
  | 'pastel-dark';

export interface DemoThemePreset {
  id: DemoThemeId;
  label: string;
  /** Theme mode the SDK resolves against (picks light/dark tokens + data attr). */
  mode: 'light' | 'dark';
  /** Swatch shown in the theme switcher (the card background). */
  swatch: string;
  /** The active mode's color token map (source of truth for both consumers below). */
  colors: Record<string, string>;
  /** Component geometry: 'square' (EL-style rects, default) or 'rounded' (soft pills). */
  shape?: WalletShapeId;
}

export const DEMO_THEME_PRESETS: DemoThemePreset[] = [
  { id: 'paper', label: 'Paper', mode: 'light', swatch: '#fdfcfc', colors: PAPER_LIGHT_COLORS },
  {
    id: 'carbon',
    label: 'Carbon',
    mode: 'dark',
    swatch: '#12171a',
    colors: CARBON_DARK_COLORS,
  },
  {
    id: 'rose-pine-dark',
    label: 'Rose Pine Dark',
    mode: 'dark',
    swatch: '#c4a7e7',
    colors: ROSE_PINE_DARK_COLORS,
  },
  {
    id: 'rose-pine-light',
    label: 'Rose Pine Light',
    mode: 'light',
    swatch: '#faf4ed',
    colors: ROSE_PINE_LIGHT_COLORS,
  },
  {
    id: 'greenhouse',
    label: 'Greenhouse',
    mode: 'light',
    swatch: '#308970',
    colors: GREENHOUSE_LIGHT_COLORS,
  },
  {
    id: 'pastel',
    label: 'Pastel',
    mode: 'light',
    // lavender reads most distinctly "pastel" next to the other swatches
    swatch: '#DBCDF0',
    colors: PASTEL_LIGHT_COLORS,
  },
  {
    id: 'pastel-dark',
    label: 'Pastel Dark',
    mode: 'dark',
    swatch: '#1e1d22',
    colors: PASTEL_DARK_COLORS,
  },
];

/* Shape is orthogonal to the color preset: the demo's corners toggle passes
   it in; a preset's own shape (if any) is the fallback. */
function resolveDemoShape(preset: DemoThemePreset, shape?: WalletShapeId): WalletShapeId {
  return shape ?? preset.shape ?? 'square';
}

/** Build the React `<Theme tokens={...}>` value for a preset (includes a contained shadow). */
export function demoReactTokens(
  preset: DemoThemePreset,
  shapeId?: WalletShapeId,
): ThemeProps['tokens'] {
  const shadows = { lg: preset.mode === 'dark' ? CONTAINED_SHADOW_DARK : CONTAINED_SHADOW_LIGHT };
  const shape = SHAPE_PRESETS[resolveDemoShape(preset, shapeId)];
  return preset.mode === 'dark'
    ? { dark: { colors: preset.colors, shadows, shape } }
    : { light: { colors: preset.colors, shadows, shape } };
}

/** Build the wallet-iframe appearance (colors + shape) for a preset — fed to seams.setAppearance. */
export function demoIframeAppearance(
  preset: DemoThemePreset,
  shapeId?: WalletShapeId,
): SdkAppearance {
  return {
    theme: {
      id: preset.id,
      mode: preset.mode,
      colors: preset.colors,
      /* always send the full shape record so switching rounded → square
         overwrites every key (the host merges appearance updates) */
      shape: { ...SHAPE_PRESETS[resolveDemoShape(preset, shapeId)] },
    },
    palette: 'default',
  };
}

export const PAPER_THEME_TOKENS: ThemeProps['tokens'] = {
  light: {
    colors: PAPER_LIGHT_COLORS,
  },
};

export function paperReactTokens(shapeId?: WalletShapeId): ThemeProps['tokens'] {
  return {
    light: {
      colors: PAPER_LIGHT_COLORS,
      shadows: { lg: CONTAINED_SHADOW_LIGHT },
      shape: SHAPE_PRESETS[resolveDemoShape(DEMO_THEME_PRESETS[0], shapeId)],
    },
  };
}

export function paperIframeAppearance(shapeId?: WalletShapeId): SdkAppearance {
  return demoIframeAppearance(DEMO_THEME_PRESETS[0], shapeId);
}
