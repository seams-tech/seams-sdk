import type { ThemeProps, TatchiConfigsInput } from '@tatchi-xyz/sdk/react';
import { SOLARIZED_DARK_TOKENS, SOLARIZED_LIGHT_TOKENS } from './app-themes';

const SOLARIZED_LIGHT_DARK_TOKENS = {
  ...SOLARIZED_LIGHT_TOKENS,
  ...SOLARIZED_DARK_TOKENS,
};

export const SITE_APPEARANCE: NonNullable<TatchiConfigsInput['appearance']> = {
  // Used as the initial SDK theme when the React host is not controlling it.
  theme: 'dark',
  // Use standard palette; Solarized comes from explicit token overrides.
  palette: 'default',
  // SDK-level semantic token overrides.
  tokens: SOLARIZED_LIGHT_DARK_TOKENS,
};

export const SITE_THEME_TOKEN_OVERRIDES: ThemeProps['tokens'] = {
  // Host-level React overrides (highest precedence).
  ...SOLARIZED_LIGHT_DARK_TOKENS,
};
