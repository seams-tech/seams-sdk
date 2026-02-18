import type { ThemeProps, TatchiConfigsInput } from '@tatchi-xyz/sdk/react';

export type AppThemePreset = 'solarized-dark' | 'solarized-light';

type AppearanceTokens = NonNullable<NonNullable<TatchiConfigsInput['appearance']>['tokens']>;

const SOLARIZED_DARK_COLORS: Record<string, string> = {
  primary: '#268bd2',
  primaryHover: '#2aa198',
  secondary: '#6c71c4',
  secondaryHover: '#d33682',
  accent: '#859900',

  textPrimary: '#93a1a1',
  textSecondary: '#839496',
  textMuted: '#657b83',
  textButton: '#fdf6e3',

  buttonBackground: '#268bd2',
  buttonHoverBackground: '#2aa198',

  colorBackground: '#002b36',
  surface: '#073642',
  surface2: '#0b3b48',
  surface3: '#0f4452',
  surface4: '#134d5d',

  hover: '#0b3b48',
  active: '#114654',
  focus: '#2aa198',

  success: '#859900',
  warning: '#b58900',
  error: '#dc322f',
  info: '#268bd2',

  borderPrimary: '#586e75',
  borderSecondary: '#657b83',
  borderHover: '#839496',

  gradientPrimary: 'linear-gradient(120deg, #073642 0%, #268bd2 100%)',
  gradientSecondary: 'linear-gradient(120deg, #002b36 0%, #2aa198 100%)',
  gradientTertiary: 'linear-gradient(120deg, #002b36 0%, #073642 100%)',

  highlightReceiverId: '#2aa198',
  highlightMethodName: '#268bd2',
  highlightAmount: '#b58900',
};

const SOLARIZED_LIGHT_COLORS: Record<string, string> = {
  primary: '#268bd2',
  primaryHover: '#2aa198',
  secondary: '#6c71c4',
  secondaryHover: '#d33682',
  accent: '#859900',

  textPrimary: '#586e75',
  textSecondary: '#657b83',
  textMuted: '#839496',
  textButton: '#fdf6e3',

  buttonBackground: '#268bd2',
  buttonHoverBackground: '#2aa198',

  colorBackground: '#fdf6e3',
  surface: '#eee8d5',
  surface2: '#e7e1cf',
  surface3: '#ddd6c1',
  surface4: '#d3cbb4',

  hover: '#eee8d5',
  active: '#e7e1cf',
  focus: '#2aa198',

  success: '#859900',
  warning: '#b58900',
  error: '#dc322f',
  info: '#268bd2',

  borderPrimary: '#93a1a1',
  borderSecondary: '#839496',
  borderHover: '#657b83',

  gradientPrimary: 'linear-gradient(120deg, #fdf6e3 0%, #eee8d5 100%)',
  gradientSecondary: 'linear-gradient(120deg, #eee8d5 0%, #d3cbb4 100%)',
  gradientTertiary: 'linear-gradient(120deg, #eee8d5 0%, #fdf6e3 100%)',

  highlightReceiverId: '#2aa198',
  highlightMethodName: '#268bd2',
  highlightAmount: '#b58900',
};

export const SOLARIZED_DARK_TOKENS: AppearanceTokens = {
  dark: { colors: SOLARIZED_DARK_COLORS },
};

export const SOLARIZED_LIGHT_TOKENS: AppearanceTokens = {
  light: { colors: SOLARIZED_LIGHT_COLORS },
};

export const APP_THEME_TOKEN_PRESETS: Record<AppThemePreset, ThemeProps['tokens']> = {
  'solarized-dark': SOLARIZED_DARK_TOKENS,
  'solarized-light': SOLARIZED_LIGHT_TOKENS,
};
