import React from 'react';
import { TatchiContextProvider } from '.';
import { DARK_TOKENS, LIGHT_TOKENS, Theme } from '../components/theme';
import type { ThemeOverrides, ThemeProps, ThemeName } from '../components/theme';
import { usePreconnectWalletAssets } from '../hooks/usePreconnectWalletAssets';
import { useWalletIframeZIndex } from '../hooks/useWalletIframeZIndex';
import type { TatchiContextProviderProps } from '../types';
import { deepMerge } from '../components/theme/utils';
import { createCspStylesheetManager, getDefaultCspNonce } from '../../core/WalletIframe/shared/csp-stylesheet';

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

const APP_LIT_THEME_OVERRIDE_STYLE_ID = 'w3a-lit-theme-token-overrides-app';
const APP_LIT_THEME_OVERRIDE_RULE_ID = 'w3a-lit-theme-overrides-app';
const APP_LIT_HOST_SELECTORS = [
  'w3a-tx-tree',
  'w3a-drawer',
  'w3a-modal-tx-confirmer',
  'w3a-drawer-tx-confirmer',
  'w3a-tx-confirm-content',
  'w3a-halo-border',
  'w3a-passkey-halo-loading',
  'w3a-export-key-viewer',
] as const;
const APP_LIT_DARK_SELECTOR = APP_LIT_HOST_SELECTORS.join(',\n');
const APP_LIT_LIGHT_SELECTOR = APP_LIT_HOST_SELECTORS
  .map((selector) => `:root[data-w3a-theme="light"] ${selector}`)
  .join(',\n');
let appLitThemeOverrideStyleManager: ReturnType<typeof createCspStylesheetManager> | null = null;

function getAppLitThemeOverrideStyleManager(): ReturnType<typeof createCspStylesheetManager> {
  if (!appLitThemeOverrideStyleManager) {
    appLitThemeOverrideStyleManager = createCspStylesheetManager({
      doc: document,
      baseCss: '',
      dynamicStyleDataAttr: 'data-w3a-lit-theme-overrides-app',
      nonce: () => getDefaultCspNonce(),
    });
  }
  return appLitThemeOverrideStyleManager;
}

function toStringRecord(value: unknown): Record<string, string> {
  if (!value || typeof value !== 'object') return {};
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    if (typeof v === 'string') out[k] = v;
  }
  return out;
}

function sanitizeTokenName(name: string): string | null {
  const trimmed = name.trim();
  if (!trimmed) return null;
  return /^[A-Za-z][A-Za-z0-9_-]*$/.test(trimmed) ? trimmed : null;
}

function sanitizeTokenValue(value: string): string | null {
  const trimmed = value.trim();
  if (!trimmed) return null;
  if (trimmed.length > 1024) return null;
  if (/[{};\n\r]/.test(trimmed)) return null;
  return trimmed;
}

function serializeColorOverrides(colors: Record<string, string>): string[] {
  const lines: string[] = [];
  for (const [rawName, rawValue] of Object.entries(colors)) {
    const tokenName = sanitizeTokenName(rawName);
    if (!tokenName) continue;
    const tokenValue = sanitizeTokenValue(rawValue);
    if (!tokenValue) continue;
    lines.push(`  --w3a-colors-${tokenName}: ${tokenValue} !important;`);
  }
  return lines;
}

function extractThemeColorOverrides(overrides?: ThemeOverrides): {
  light: { colors: Record<string, string> };
  dark: { colors: Record<string, string> };
} {
  return {
    light: { colors: toStringRecord(overrides?.light?.colors) },
    dark: { colors: toStringRecord(overrides?.dark?.colors) },
  };
}

function upsertAppLitThemeOverrides(args: {
  lightColors: Record<string, string>;
  darkColors: Record<string, string>;
}): void {
  const darkLines = serializeColorOverrides(args.darkColors);
  const lightLines = serializeColorOverrides(args.lightColors);
  const cssBlocks: string[] = [];
  if (darkLines.length > 0) {
    cssBlocks.push(`${APP_LIT_DARK_SELECTOR} {\n${darkLines.join('\n')}\n}`);
  }
  if (lightLines.length > 0) {
    cssBlocks.push(`${APP_LIT_LIGHT_SELECTOR} {\n${lightLines.join('\n')}\n}`);
  }
  const cssText = cssBlocks.join('\n\n').trim();
  if (!cssText) {
    getAppLitThemeOverrideStyleManager().deleteDynamicRule(APP_LIT_THEME_OVERRIDE_RULE_ID);
    // Cleanup legacy inline style node from older SDK versions, if present.
    document.getElementById(APP_LIT_THEME_OVERRIDE_STYLE_ID)?.remove();
    return;
  }
  getAppLitThemeOverrideStyleManager().setDynamicRule(APP_LIT_THEME_OVERRIDE_RULE_ID, cssText);
  // Cleanup legacy inline style node from older SDK versions, if present.
  document.getElementById(APP_LIT_THEME_OVERRIDE_STYLE_ID)?.remove();
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
  const configTokenOverrides = React.useMemo(() => resolveConfigTokenOverrides(config), [config]);
  const resolvedReactTokenOverrides = React.useMemo<ThemeOverrides | undefined>(() => {
    if (!reactTokenOverrides) return undefined;
    return typeof reactTokenOverrides === 'function'
      ? reactTokenOverrides({ light: LIGHT_TOKENS, dark: DARK_TOKENS })
      : reactTokenOverrides;
  }, [reactTokenOverrides]);
  const mergedTokenOverrides = React.useMemo<ThemeOverrides | undefined>(
    () => mergeThemeOverrideLayers([configTokenOverrides, resolvedReactTokenOverrides]),
    [configTokenOverrides, resolvedReactTokenOverrides],
  );
  const mergedTokens = React.useMemo<ThemeProps['tokens']>(() => {
    if (!mergedTokenOverrides) return undefined;
    return mergedTokenOverrides;
  }, [mergedTokenOverrides]);

  const mergedThemeColorOverrides = React.useMemo(
    () => extractThemeColorOverrides(mergedTokenOverrides),
    [mergedTokenOverrides],
  );
  const providerConfig = React.useMemo<TatchiPasskeyProviderProps['config']>(() => {
    const lightColors = mergedThemeColorOverrides.light.colors;
    const darkColors = mergedThemeColorOverrides.dark.colors;
    const hasLight = Object.keys(lightColors).length > 0;
    const hasDark = Object.keys(darkColors).length > 0;
    if (!hasLight && !hasDark) return config;
    return {
      ...config,
      appearance: {
        ...(config.appearance || {}),
        tokens: {
          light: { colors: lightColors },
          dark: { colors: darkColors },
        },
      },
    };
  }, [config, mergedThemeColorOverrides.dark.colors, mergedThemeColorOverrides.light.colors]);

  const rootTheme = controlledTheme || config.appearance?.theme;
  React.useEffect(() => {
    if (rootTheme === 'light' || rootTheme === 'dark') {
      try { document.documentElement.setAttribute('data-w3a-theme', rootTheme); } catch {}
    }
  }, [rootTheme]);

  React.useEffect(() => {
    try {
      upsertAppLitThemeOverrides({
        darkColors: mergedThemeColorOverrides.dark.colors,
        lightColors: mergedThemeColorOverrides.light.colors,
      });
    } catch {}
  }, [mergedThemeColorOverrides.dark.colors, mergedThemeColorOverrides.light.colors]);

  const themeProps: ThemeProps = {
    theme: controlledTheme,
    setTheme,
    tokens: mergedTokens,
    ...(themeOverrides as Omit<ThemeProps, 'children' | 'theme'>),
  };
  return (
    <TatchiContextProvider config={providerConfig} eager={eager} theme={controlledTheme ? { theme: controlledTheme, setTheme } : undefined}>
      <Theme {...themeProps}>{children}</Theme>
    </TatchiContextProvider>
  );
};

export default TatchiPasskeyProvider;
