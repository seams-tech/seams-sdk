import type { SeamsConfigsInput, ThemeProps } from '@seams/wallet/react';
import { PAPER_LIGHT_COLORS, PAPER_THEME_TOKENS } from './app-themes';

export const SITE_APPEARANCE: NonNullable<SeamsConfigsInput['appearance']> = {
  theme: {
    id: 'paper',
    mode: 'light',
    colors: PAPER_LIGHT_COLORS,
  },
  palette: 'default',
};

export const SITE_THEME_TOKEN_OVERRIDES: ThemeProps['tokens'] = PAPER_THEME_TOKENS;
