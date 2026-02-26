import type { ThemeProps, TatchiConfigsInput } from '@tatchi-xyz/sdk/react';

export type AppThemePreset = 'rose-pine-dark' | 'rose-pine-light';

type AppearanceTokens = NonNullable<NonNullable<TatchiConfigsInput['appearance']>['tokens']>;

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
  textButton: '#faf4ed',

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
