import type { ThemeProps, TatchiConfigsInput } from '@tatchi-xyz/sdk/react';
import { ROSE_PINE_DARK_TOKENS, ROSE_PINE_LIGHT_TOKENS } from './app-themes';

const ROSE_PINE_LIGHT_DARK_TOKENS = {
  ...ROSE_PINE_LIGHT_TOKENS,
  ...ROSE_PINE_DARK_TOKENS,
};

export const SITE_APPEARANCE: NonNullable<TatchiConfigsInput['appearance']> = {
  // Used as the initial SDK theme when the React host is not controlling it.
  theme: 'dark',
  // Use standard palette; Rose Pine comes from explicit token overrides.
  palette: 'default',
  // SDK-level semantic token overrides.
  tokens: ROSE_PINE_LIGHT_DARK_TOKENS,
};

export const SITE_THEME_TOKEN_OVERRIDES: ThemeProps['tokens'] = {
  // Host-level React overrides (highest precedence).
  ...ROSE_PINE_LIGHT_DARK_TOKENS,
};
