import type { ThemeProps, SeamsConfigsInput } from '@seams/sdk/react';

export type AppThemePreset = 'rose-pine-dark' | 'rose-pine-light';

type AppearanceTokens = NonNullable<NonNullable<SeamsConfigsInput['appearance']>['tokens']>;

/* Contained drop shadows — the SDK default shadows.lg overflows the demo cell
   and clips; these keep the card lift within bounds. */
const CONTAINED_SHADOW_LIGHT =
  '0 2px 6px -2px rgba(15, 23, 42, 0.12), 0 12px 28px -16px rgba(15, 23, 42, 0.28)';
const CONTAINED_SHADOW_DARK =
  '0 2px 6px -2px rgba(0, 0, 0, 0.5), 0 14px 30px -16px rgba(0, 0, 0, 0.7)';

const ROSE_PINE_DARK_COLORS: Record<string, string> = {
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

const ROSE_PINE_LIGHT_COLORS: Record<string, string> = {
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

export const ROSE_PINE_DARK_TOKENS: AppearanceTokens = {
  dark: { colors: ROSE_PINE_DARK_COLORS },
};

export const ROSE_PINE_LIGHT_TOKENS: AppearanceTokens = {
  light: { colors: ROSE_PINE_LIGHT_COLORS },
};

export const APP_THEME_TOKEN_PRESETS: Record<AppThemePreset, ThemeProps['tokens']> = {
  'rose-pine-dark': ROSE_PINE_DARK_TOKENS,
  'rose-pine-light': ROSE_PINE_LIGHT_TOKENS,
};

// ============================================================================
// Live-demo theme presets (fed to the PasskeyAuthMenu via the SDK Theme provider)
// ============================================================================

// Warm paper — matches the /home2 page. Ink primary keeps the Register toggle
// neutral; green is reserved for accents/focus.
const PAPER_LIGHT_COLORS: Record<string, string> = {
  primary: '#0a0a0a',
  primaryHover: '#262626',
  secondary: '#44403b',
  secondaryHover: '#0a0a0a',
  accent: '#157f5f',

  textPrimary: '#0a0a0a',
  textSecondary: '#57534e',
  textMuted: '#a59f97',
  textButton: '#ffffff',

  buttonBackground: '#0a0a0a',
  buttonHoverBackground: '#262626',

  colorBackground: '#fdfcfc',
  surface: '#ffffff',
  surface2: '#f0eeeb',
  surface3: '#ebe8e4',
  surface4: '#e2ded9',

  hover: '#f5f3f1',
  active: '#ebe8e4',
  focus: '#157f5f',

  success: '#157f5f',
  warning: '#b45309',
  error: '#b91c1c',
  info: '#157f5f',

  borderPrimary: '#e7e3de',
  borderSecondary: '#efece8',
  borderHover: '#cbc5bd',

  highlightPrimary: '#157f5f',
  highlightRow: 'rgba(21, 127, 95, 0.14)',
  highlightHalo: '#8fd3bd',
  highlightReceiver: '#157f5f',
  highlightMethodName: '#0a0a0a',
  highlightAmount: '#157f5f',
};

// Neutral charcoal dark.
const CHARCOAL_DARK_COLORS: Record<string, string> = {
  primary: '#a78bfa',
  primaryHover: '#c4b5fd',
  secondary: '#cbd5e1',
  secondaryHover: '#f1f5f9',
  accent: '#a78bfa',

  textPrimary: '#f4f4f5',
  textSecondary: '#b4b0bd',
  textMuted: '#77737f',
  textButton: '#0a0a0a',

  buttonBackground: '#f4f4f5',
  buttonHoverBackground: '#e4e4e7',

  colorBackground: '#17171c',
  surface: '#1e1e26',
  surface2: '#26262f',
  surface3: '#2f2f3a',
  surface4: '#383844',

  hover: '#26262f',
  active: '#2f2f3a',
  focus: '#a78bfa',

  success: '#4ade80',
  warning: '#fbbf24',
  error: '#f87171',
  info: '#a78bfa',

  borderPrimary: '#2f2f3a',
  borderSecondary: '#26262f',
  borderHover: '#454552',

  highlightPrimary: '#a78bfa',
  highlightRow: '#2f2f3a',
  highlightHalo: '#c4b5fd',
  highlightReceiver: '#a78bfa',
  highlightMethodName: '#e0def4',
  highlightAmount: '#fbbf24',
};

// Classic Solarized (dark).
const SOLARIZED_DARK_COLORS: Record<string, string> = {
  primary: '#2aa198',
  primaryHover: '#35b1a7',
  secondary: '#268bd2',
  secondaryHover: '#3a9bde',
  accent: '#2aa198',

  textPrimary: '#93a1a1',
  textSecondary: '#839496',
  textMuted: '#586e75',
  textButton: '#002b36',

  buttonBackground: '#2aa198',
  buttonHoverBackground: '#35b1a7',

  colorBackground: '#002b36',
  surface: '#073642',
  surface2: '#0a3f4c',
  surface3: '#0e4753',
  surface4: '#14515e',

  hover: '#073642',
  active: '#0a3f4c',
  focus: '#2aa198',

  success: '#859900',
  warning: '#b58900',
  error: '#dc322f',
  info: '#268bd2',

  borderPrimary: '#0e4753',
  borderSecondary: '#0a3f4c',
  borderHover: '#14515e',

  highlightPrimary: '#2aa198',
  highlightRow: '#0e4753',
  highlightHalo: '#2aa198',
  highlightReceiver: '#268bd2',
  highlightMethodName: '#93a1a1',
  highlightAmount: '#b58900',
};

export type DemoThemeId = 'light' | 'dark' | 'solarized' | 'rose-pine' | 'rose-pine-dark';

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
  { id: 'light', label: 'Light', mode: 'light', swatch: '#fdfcfc', colors: PAPER_LIGHT_COLORS },
  { id: 'dark', label: 'Dark', mode: 'dark', swatch: '#17171c', colors: CHARCOAL_DARK_COLORS },
  {
    id: 'solarized',
    label: 'Solarized',
    mode: 'dark',
    swatch: '#002b36',
    colors: SOLARIZED_DARK_COLORS,
  },
  {
    id: 'rose-pine',
    label: 'Rosé Pine',
    mode: 'light',
    swatch: '#faf4ed',
    colors: ROSE_PINE_LIGHT_COLORS,
  },
  {
    id: 'rose-pine-dark',
    label: 'Rosé Pine Dark',
    mode: 'dark',
    swatch: '#191724',
    colors: ROSE_PINE_DARK_COLORS,
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
export function demoIframeAppearance(preset: DemoThemePreset): AppearanceTokensAppearance {
  return preset.mode === 'dark'
    ? { theme: 'dark', tokens: { dark: { colors: preset.colors } } }
    : { theme: 'light', tokens: { light: { colors: preset.colors } } };
}

type AppearanceTokensAppearance = {
  theme: 'light' | 'dark';
  tokens: AppearanceTokens;
};
