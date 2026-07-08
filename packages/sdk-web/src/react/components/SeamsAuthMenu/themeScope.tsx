import React from 'react';
import { DARK_TOKENS, LIGHT_TOKENS, type DesignTokens } from '../theme/design-tokens';
import { createCSSVariables } from '../theme/utils';

export type SeamsAuthMenuThemeName = 'light' | 'dark';
export type SeamsAuthMenuThemeMode = SeamsAuthMenuThemeName | 'auto';

export interface SeamsAuthMenuThemeScopeProps {
  tag?: keyof React.JSX.IntrinsicElements;
  className?: string;
  style?: React.CSSProperties;
  dataAttr?: string;
  theme?: SeamsAuthMenuThemeMode;
  tokens?: DesignTokens;
  children?: React.ReactNode;
}

function getSystemPrefersDark(): boolean {
  if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') return false;
  return window.matchMedia('(prefers-color-scheme: dark)').matches;
}

function resolveThemeName(mode?: SeamsAuthMenuThemeMode): SeamsAuthMenuThemeName {
  if (mode === 'dark' || mode === 'light') return mode;
  return getSystemPrefersDark() ? 'dark' : 'light';
}

function tokensForThemeName(name: SeamsAuthMenuThemeName): DesignTokens {
  return name === 'dark' ? DARK_TOKENS : LIGHT_TOKENS;
}

/**
 * Minimal theme scope used by SeamsAuthMenu shell/skeleton.
 *
 * This intentionally does NOT import SDK context or user-preference syncing,
 * keeping SSR-safe entrypoints lightweight and free of browser-only deps.
 */
export const SeamsAuthMenuThemeScope: React.FC<SeamsAuthMenuThemeScopeProps> = ({
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
  const Comp: any = tag;
  const attrs: any = { [dataAttr]: themeName };
  return (
    <Comp className={className} style={{ ...vars, ...style }} {...attrs}>
      {children}
    </Comp>
  );
};

export default SeamsAuthMenuThemeScope;
