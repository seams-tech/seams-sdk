import React from 'react';
import { DARK_TOKENS, LIGHT_TOKENS, type DesignTokens } from '../theme/design-tokens';
import { createCSSVariables } from '../theme/utils';

export type PasskeyAuthMenuThemeName = 'light' | 'dark';
export type PasskeyAuthMenuThemeMode = PasskeyAuthMenuThemeName | 'auto';

export interface PasskeyAuthMenuThemeScopeProps {
  tag?: keyof React.JSX.IntrinsicElements;
  className?: string;
  style?: React.CSSProperties;
  dataAttr?: string;
  theme?: PasskeyAuthMenuThemeMode;
  tokens?: DesignTokens;
  children?: React.ReactNode;
}

function getSystemPrefersDark(): boolean {
  if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') return false;
  return window.matchMedia('(prefers-color-scheme: dark)').matches;
}

function resolveThemeName(mode?: PasskeyAuthMenuThemeMode): PasskeyAuthMenuThemeName {
  if (mode === 'dark' || mode === 'light') return mode;
  return getSystemPrefersDark() ? 'dark' : 'light';
}

function tokensForThemeName(name: PasskeyAuthMenuThemeName): DesignTokens {
  return name === 'dark' ? DARK_TOKENS : LIGHT_TOKENS;
}

/**
 * Minimal theme scope used by PasskeyAuthMenu shell/skeleton.
 *
 * This intentionally does NOT import SDK context or user-preference syncing,
 * keeping SSR-safe entrypoints lightweight and free of browser-only deps.
 */
export const PasskeyAuthMenuThemeScope: React.FC<PasskeyAuthMenuThemeScopeProps> = ({
  tag = 'div',
  className = 'w3a-theme-provider',
  style,
  dataAttr = 'data-w3a-theme',
  theme,
  tokens,
  children,
}) => {
  const themeName = resolveThemeName(theme);
  const resolvedTokens = React.useMemo(
    () => tokens ?? tokensForThemeName(themeName),
    [themeName, tokens],
  );
  const vars = React.useMemo(() => createCSSVariables(resolvedTokens, '--w3a'), [resolvedTokens]);
  const passkeyAuthMenuVars = React.useMemo(
    () => ({
      ['--w3a-passkey-auth-menu2-seg-active-bg' as any]:
        themeName === 'dark'
          ? `color-mix(in srgb, ${resolvedTokens.colors.surface3} 86%, ${resolvedTokens.colors.primary} 14%)`
          : `color-mix(in srgb, ${resolvedTokens.colors.surface2} 88%, ${resolvedTokens.colors.primary} 12%)`,
      ['--w3a-passkey-auth-menu2-seg-register-active-text' as any]:
        themeName === 'dark' ? resolvedTokens.colors.textPrimary : resolvedTokens.colors.primary,
      ['--w3a-passkey-auth-menu2-seg-register-active-text-hover' as any]:
        themeName === 'dark' ? resolvedTokens.colors.primary : resolvedTokens.colors.primaryHover,
    }),
    [
      themeName,
      resolvedTokens.colors.primary,
      resolvedTokens.colors.primaryHover,
      resolvedTokens.colors.surface2,
      resolvedTokens.colors.surface3,
      resolvedTokens.colors.textPrimary,
    ],
  );
  const Comp: any = tag;
  const attrs: any = { [dataAttr]: themeName };
  return (
    <Comp className={className} style={{ ...vars, ...passkeyAuthMenuVars, ...style }} {...attrs}>
      {children}
    </Comp>
  );
};

export default PasskeyAuthMenuThemeScope;
