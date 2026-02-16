import React from 'react';
import { TatchiContextProvider } from '.';
import { LIGHT_TOKENS, Theme } from '../components/theme';
import type { ThemeOverrides, ThemeProps, ThemeName } from '../components/theme';
import { usePreconnectWalletAssets } from '../hooks/usePreconnectWalletAssets';
import { useWalletIframeZIndex } from '../hooks/useWalletIframeZIndex';
import type { TatchiContextProviderProps } from '../types';
import { deepMerge } from '../components/theme/utils';

export type TatchiPasskeyProviderThemeProps = Omit<ThemeProps, 'children'> & {
  setTheme?: (theme: ThemeName) => void;
};

export interface TatchiPasskeyProviderProps {
  /** TatchiContextProvider configuration */
  config: TatchiContextProviderProps['config'];
  /** Theme props for the boundary (defaults to provider+scope).
   * Token precedence:
   * 1) `theme.tokens` (React override)
   * 2) `config.appearance.tokens` (SDK config default)
   * 3) built-in SDK theme tokens
   */
  theme?: TatchiPasskeyProviderThemeProps;
  /**
   * Optional z-index override for the wallet iframe overlay.
   * Sets the CSS variable --w3a-wallet-overlay-z on the document root.
   *
   * Defaults and layering:
   * - Wallet iframe overlay: `var(--w3a-wallet-overlay-z, 2147483646)`
   * - Linked Devices modal + QR scanner: `overlayZ - 2` / `overlayZ - 1`
   *   (always below the wallet overlay so tx confirmer wins)
   * - ProfileSettingsMenu/PasskeyAuthMenu: small local z-indexes only (1–3),
   *   no fullscreen overlay z-index.
   */
  walletOverlayZIndex?: number;
  /**
   * When true, pre-warm iframe + workers on idle after mount.
   * Defaults to false (lazy by default).
   */
  eager?: boolean;
  children: React.ReactNode;
}

function resolvePaletteOverrides(
  config: TatchiPasskeyProviderProps['config'],
): ThemeOverrides | undefined {
  if (config.appearance?.palette !== 'cream') return undefined;
  return { light: LIGHT_TOKENS };
}

function resolveConfigTokenOverrides(
  config: TatchiPasskeyProviderProps['config'],
): ThemeOverrides | undefined {
  const lightColors = config.appearance?.tokens?.light?.colors;
  const darkColors = config.appearance?.tokens?.dark?.colors;
  if (!lightColors && !darkColors) return undefined;
  return {
    ...(lightColors ? { light: { colors: lightColors } } : {}),
    ...(darkColors ? { dark: { colors: darkColors } } : {}),
  };
}

function mergeThemeOverrideLayers(
  layers: Array<ThemeOverrides | undefined>,
): ThemeOverrides | undefined {
  let hasLayer = false;
  let merged: ThemeOverrides = {};
  for (const layer of layers) {
    if (!layer) continue;
    hasLayer = true;
    if (layer.light) {
      merged = { ...merged, light: deepMerge(merged.light ?? {}, layer.light) };
    }
    if (layer.dark) {
      merged = { ...merged, dark: deepMerge(merged.dark ?? {}, layer.dark) };
    }
  }
  return hasLayer ? merged : undefined;
}

/**
 * TatchiPasskeyProvider — ergonomic composition of Theme + PasskeyProvider.
 * Renders a theming boundary (Theme) and provides Passkey context.
 */
export const TatchiPasskeyProvider: React.FC<TatchiPasskeyProviderProps> = ({
  config,
  theme,
  walletOverlayZIndex,
  eager,
  children
}) => {
  // Internal: opportunistically add preconnect/prefetch hints for wallet + relayer
  usePreconnectWalletAssets(config);

  // Optionally override the wallet iframe overlay z-index via CSS variable
  useWalletIframeZIndex(walletOverlayZIndex);

  const {
    theme: controlledTheme,
    setTheme,
    tokens: reactTokenOverrides,
    ...themeOverrides
  } = theme || ({} as any);
  const paletteOverrides = React.useMemo(() => resolvePaletteOverrides(config), [config]);
  const configTokenOverrides = React.useMemo(() => resolveConfigTokenOverrides(config), [config]);
  const mergedTokens = React.useMemo<ThemeProps['tokens']>(() => {
    if (!paletteOverrides && !configTokenOverrides && !reactTokenOverrides) return undefined;
    return (base) => {
      const resolvedReactTokens = typeof reactTokenOverrides === 'function'
        ? reactTokenOverrides(base)
        : reactTokenOverrides;
      return mergeThemeOverrideLayers([
        paletteOverrides,
        configTokenOverrides,
        resolvedReactTokens,
      ]) || {};
    };
  }, [paletteOverrides, configTokenOverrides, reactTokenOverrides]);

  const themeProps: ThemeProps = {
    theme: controlledTheme,
    setTheme,
    tokens: mergedTokens,
    ...(themeOverrides as Omit<ThemeProps, 'children' | 'theme'>),
  };
  return (
    <TatchiContextProvider config={config} eager={eager} theme={controlledTheme ? { theme: controlledTheme, setTheme } : undefined}>
      <Theme {...themeProps}>{children}</Theme>
    </TatchiContextProvider>
  );
};

export default TatchiPasskeyProvider;
