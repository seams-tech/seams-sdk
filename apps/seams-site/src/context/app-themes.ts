import { SHAPE_PRESETS } from '@seams/sdk/react';
import type { SeamsConfigsInput, ThemeProps, WalletShapeId } from '@seams/sdk/react';

type SdkAppearance = NonNullable<SeamsConfigsInput['appearance']>;

const CONTAINED_SHADOW =
  '0 2px 6px -2px rgba(15, 23, 42, 0.12), 0 12px 28px -16px rgba(15, 23, 42, 0.28)';

export const PAPER_LIGHT_COLORS: Record<string, string> = {
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
  secondaryButtonBackground: '#ffffff',
  secondaryButtonHoverBackground: '#f5f3f1',
  secondaryButtonBorder: '#dcd6cd',
  secondaryButtonText: '#000000',

  colorBackground: '#ffffff',
  surface: '#ffffff',
  passkeyHaloBackground: '#f8f8f7',
  surface2: '#f5f3f1',
  surface3: '#ebe8e4',
  surface4: '#e1ddd7',
  txDetailsBackground: '#f8f8f7',

  hover: '#f5f3f1',
  active: '#ebe8e4',
  focus: '#157f5f',

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
  highlightReceiver: '#4a6fa5',
  highlightMethodName: '#000000',
  highlightAmount: '#000000',
};

export const PAPER_THEME_TOKENS: ThemeProps['tokens'] = {
  light: {
    colors: PAPER_LIGHT_COLORS,
  },
};

function resolveShape(shapeId?: WalletShapeId): WalletShapeId {
  return shapeId ?? 'square';
}

export function paperReactTokens(shapeId?: WalletShapeId): ThemeProps['tokens'] {
  return {
    light: {
      colors: PAPER_LIGHT_COLORS,
      shadows: { lg: CONTAINED_SHADOW },
      shape: SHAPE_PRESETS[resolveShape(shapeId)],
    },
  };
}

export function paperIframeAppearance(shapeId?: WalletShapeId): SdkAppearance {
  return {
    theme: {
      id: 'paper',
      mode: 'light',
      colors: PAPER_LIGHT_COLORS,
      shape: { ...SHAPE_PRESETS[resolveShape(shapeId)] },
    },
    palette: 'default',
  };
}
