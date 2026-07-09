import type { ThemeProps, SeamsConfigsInput } from '@seams/sdk/react';

export type AppThemePreset = 'rose-pine-dark' | 'rose-pine-light';

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
  surface2: '#f2e9de',
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

export const ROSE_PINE_DARK_TOKENS: ThemeProps['tokens'] = {
  dark: { colors: ROSE_PINE_DARK_COLORS },
};

export const ROSE_PINE_LIGHT_TOKENS: ThemeProps['tokens'] = {
  light: { colors: ROSE_PINE_LIGHT_COLORS },
};

export const APP_THEME_TOKEN_PRESETS: Record<AppThemePreset, ThemeProps['tokens']> = {
  'rose-pine-dark': ROSE_PINE_DARK_TOKENS,
  'rose-pine-light': ROSE_PINE_LIGHT_TOKENS,
};

// ============================================================================
// Live-demo theme presets (fed to the SeamsAuthMenu via the SDK Theme provider)
// ============================================================================

// "Paper" — the ElevenLabs style: eggshell paper, ink buttons, warm
// taupe/stone neutrals, and soft blue accents for focused details.
const PAPER_LIGHT_COLORS: Record<string, string> = {
  primary: '#6f9fd8',
  primaryHover: '#5a8cc7',
  secondary: '#44403b',
  secondaryHover: '#000000',
  accent: '#6f9fd8',

  textPrimary: '#000000',
  textSecondary: '#777169',
  textMuted: '#a59f97',
  textButton: '#fdfcfc',

  buttonBackground: '#000000',
  buttonHoverBackground: '#262626',
  // black secondary accent (Google SSO) button
  secondaryButtonBackground: '#000000',
  secondaryButtonHoverBackground: '#262626',
  secondaryButtonBorder: 'transparent',
  secondaryButtonText: '#fdfcfc',

  // white menu card; the reference's eggshell #fdfcfc read too warm here
  colorBackground: '#ffffff',
  surface: '#ffffff',
  surface2: '#f5f3f1',
  surface3: '#ebe8e4',
  surface4: '#e1ddd7',
  txDetailsBackground: '#f5f3f1',

  hover: '#f5f3f1',
  active: '#ebe8e4',
  focus: '#6f9fd8',

  success: '#157f5f',
  warning: '#b45309',
  error: '#ff4704',
  info: '#6f9fd8',

  borderPrimary: '#ebe8e4',
  borderSecondary: '#e5e5e5',
  borderHover: '#d6d1cb',

  highlightPrimary: '#6f9fd8',
  highlightRow: 'rgba(111, 159, 216, 0.12)',
  highlightHalo: '#c7dcf4',
  highlightReceiver: '#6f9fd8',
  highlightMethodName: '#6f9fd8',
  highlightAmount: '#6f9fd8',
};

// "Midnight" — deep navy surfaces with a soft mint accent.
const MIDNIGHT_DARK_COLORS: Record<string, string> = {
  primary: '#b4e8c0',
  primaryHover: '#9fdcaf',
  secondary: '#7fb890',
  secondaryHover: '#b4e8c0',
  accent: '#b4e8c0',

  textPrimary: '#f3faf6',
  textSecondary: '#c4d2ce',
  textMuted: '#7d898a',
  textButton: '#141820',

  buttonBackground: '#b4e8c0',
  buttonHoverBackground: '#9fdcaf',
  secondaryButtonBackground: '#23352f',
  secondaryButtonHoverBackground: '#2c453d',
  secondaryButtonBorder: '#3d564e',
  secondaryButtonText: '#b4e8c0',

  colorBackground: '#141820',
  surface: '#181e28',
  surface2: '#202735',
  surface3: '#293241',
  surface4: '#34404f',
  txDetailsBackground: '#202735',

  hover: '#202735',
  active: '#293241',
  focus: '#b4e8c0',

  success: '#b4e8c0',
  warning: '#f0d994',
  error: '#ff8f8f',
  info: '#9fdcaf',

  borderPrimary: '#2c3440',
  borderSecondary: '#242c38',
  borderHover: '#465361',

  gradientPrimary: 'linear-gradient(120deg, #141820 0%, #b4e8c0 100%)',
  gradientSecondary: 'linear-gradient(120deg, #141820 0%, #23352f 100%)',
  gradientTertiary: 'linear-gradient(120deg, #141820 0%, #202735 100%)',

  highlightPrimary: '#b4e8c0',
  highlightRow: 'rgba(180, 232, 192, 0.14)',
  highlightHalo: '#d1f4da',
  highlightReceiver: '#b4e8c0',
  highlightMethodName: '#f3faf6',
  highlightAmount: '#b4e8c0',
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

  // subtle near-white paper cream menu card with deeper cream controls and chrome
  colorBackground: '#fffefd',
  surface: '#fffaf5',
  surface2: '#fff7ee',
  surface3: '#F2C6DE',
  surface4: '#DBCDF0',
  txDetailsBackground: '#fff7ee',

  hover: '#fff8f1',
  active: '#fff3e8',
  focus: '#8fb9de',

  success: '#4f9e83',
  lastUsedBadgeBackground: '#F2C6DE',
  lastUsedBadgeText: '#2f2a38',
  warning: '#e6c891',
  error: '#d4547a',
  info: '#6f9fd8',

  borderPrimary: '#f0ead9',
  borderSecondary: '#f6f0e3',
  borderHover: '#e5dac0',

  highlightPrimary: '#8fb9de',
  highlightRow: 'rgba(198, 222, 241, 0.28)',
  highlightHalo: '#C6DEF1',
  highlightReceiver: '#6f9fd8',
  highlightMethodName: '#2f2a38',
  highlightAmount: '#d4547a',
};

export type DemoThemeId =
  | 'paper'
  | 'midnight'
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
}

export const DEMO_THEME_PRESETS: DemoThemePreset[] = [
  { id: 'paper', label: 'Paper', mode: 'light', swatch: '#fdfcfc', colors: PAPER_LIGHT_COLORS },
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
  {
    id: 'midnight',
    label: 'Midnight',
    mode: 'dark',
    swatch: '#141820',
    colors: MIDNIGHT_DARK_COLORS,
  },
];

/** Build the React `<Theme tokens={...}>` value for a preset (includes a contained shadow). */
export function demoReactTokens(preset: DemoThemePreset): ThemeProps['tokens'] {
  const shadows = { lg: preset.mode === 'dark' ? CONTAINED_SHADOW_DARK : CONTAINED_SHADOW_LIGHT };
  return preset.mode === 'dark'
    ? { dark: { colors: preset.colors, shadows } }
    : { light: { colors: preset.colors, shadows } };
}

/** Build the wallet-iframe appearance (colors only) for a preset — fed to seams.setAppearance. */
export function demoIframeAppearance(preset: DemoThemePreset): SdkAppearance {
  return {
    theme: {
      id: preset.id,
      mode: preset.mode,
      colors: preset.colors,
    },
    palette: 'default',
  };
}
