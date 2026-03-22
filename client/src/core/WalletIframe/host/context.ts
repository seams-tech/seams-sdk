import { MinimalNearClient } from '../../rpcClients/near/NearClient';
import { TatchiPasskey } from '../../TatchiPasskey';
import { __setWalletIframeHostMode } from '../host-mode';
import type { TatchiConfigsInput } from '../../types/tatchi';
import type { PMSetConfigPayload } from '../shared/messages';
import { isString } from '@shared/utils/validation';
import { setEmbeddedBase } from '../../walletRuntimePaths';
import { cloneChainConfig, resolvePrimaryNearRpcUrl } from '../../config/chains';
import {
  assertWalletHostConfigsNoNestedIframeWallet,
  sanitizeWalletHostConfigs,
} from './config-guards';
import { createCspStylesheetManager, getDefaultCspNonce } from '../shared/csp-stylesheet';

const W3A_LIT_THEME_OVERRIDE_STYLE_ID = 'w3a-lit-theme-token-overrides';
const W3A_LIT_THEME_OVERRIDE_RULE_ID = 'w3a-lit-theme-overrides';
const W3A_LIT_HOST_SELECTORS = [
  'w3a-tx-tree',
  'w3a-drawer',
  'w3a-modal-tx-confirmer',
  'w3a-drawer-tx-confirmer',
  'w3a-tx-confirm-content',
  'w3a-halo-border',
  'w3a-passkey-halo-loading',
  'w3a-export-key-viewer',
] as const;
const W3A_LIT_DARK_SELECTOR = W3A_LIT_HOST_SELECTORS.join(',\n');
const W3A_LIT_LIGHT_SELECTOR = W3A_LIT_HOST_SELECTORS.map(
  (selector) => `:root[data-w3a-theme="light"] ${selector}`,
).join(',\n');
let litThemeOverrideStyleManager: ReturnType<typeof createCspStylesheetManager> | null = null;

function getLitThemeOverrideStyleManager(): ReturnType<typeof createCspStylesheetManager> {
  if (!litThemeOverrideStyleManager) {
    litThemeOverrideStyleManager = createCspStylesheetManager({
      doc: document,
      baseCss: '',
      dynamicStyleDataAttr: 'data-w3a-lit-theme-overrides',
      nonce: () => getDefaultCspNonce(),
    });
  }
  return litThemeOverrideStyleManager;
}

function toStringRecord(value: unknown): Record<string, string> {
  if (!value || typeof value !== 'object') return {};
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    if (typeof v === 'string') out[k] = v;
  }
  return out;
}

function coerceThemeName(value: unknown): 'light' | 'dark' | undefined {
  return value === 'light' || value === 'dark' ? value : undefined;
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
    // Use !important so app-provided token overrides keep precedence even if
    // generated w3a-components.css is loaded/reloaded later.
    lines.push(`  --w3a-colors-${tokenName}: ${tokenValue} !important;`);
  }
  return lines;
}

function upsertLitThemeOverrideStyle(args: {
  darkColors: Record<string, string>;
  lightColors: Record<string, string>;
}): void {
  const { darkColors, lightColors } = args;
  const darkLines = serializeColorOverrides(darkColors);
  const lightLines = serializeColorOverrides(lightColors);
  const cssBlocks: string[] = [];

  if (darkLines.length > 0) {
    cssBlocks.push(`${W3A_LIT_DARK_SELECTOR} {\n${darkLines.join('\n')}\n}`);
  }
  if (lightLines.length > 0) {
    cssBlocks.push(`${W3A_LIT_LIGHT_SELECTOR} {\n${lightLines.join('\n')}\n}`);
  }

  const cssText = cssBlocks.join('\n\n').trim();
  if (!cssText) {
    getLitThemeOverrideStyleManager().deleteDynamicRule(W3A_LIT_THEME_OVERRIDE_RULE_ID);
    // Cleanup stale inline style node, if present.
    document.getElementById(W3A_LIT_THEME_OVERRIDE_STYLE_ID)?.remove();
    return;
  }
  getLitThemeOverrideStyleManager().setDynamicRule(W3A_LIT_THEME_OVERRIDE_RULE_ID, cssText);
  // Cleanup stale inline style node, if present.
  document.getElementById(W3A_LIT_THEME_OVERRIDE_STYLE_ID)?.remove();
}

export interface HostContext {
  parentOrigin: string | null;
  port: MessagePort | null;
  walletConfigs: TatchiConfigsInput | null;
  nearClient: MinimalNearClient | null;
  tatchiPasskey: TatchiPasskey | null;
  prefsUnsubscribe?: (() => void) | null;
  onWindowMessage?: (e: MessageEvent) => void;
}

export function createHostContext(): HostContext {
  return {
    parentOrigin: null,
    port: null,
    walletConfigs: null,
    nearClient: null,
    tatchiPasskey: null,
    prefsUnsubscribe: null,
    onWindowMessage: undefined,
  };
}

export function ensurePasskeyManager(ctx: HostContext): TatchiPasskey {
  const { walletConfigs } = ctx;
  if (!walletConfigs) {
    throw new Error('Wallet service not configured. Call PM_SET_CONFIG first.');
  }
  const nearRpcUrl = resolvePrimaryNearRpcUrl(walletConfigs.chains || []);
  if (!ctx.nearClient) {
    ctx.nearClient = new MinimalNearClient(nearRpcUrl);
  }
  if (!ctx.tatchiPasskey) {
    const cfg = sanitizeWalletHostConfigs(walletConfigs);
    assertWalletHostConfigsNoNestedIframeWallet(cfg);
    __setWalletIframeHostMode(true);
    ctx.tatchiPasskey = new TatchiPasskey(cfg, ctx.nearClient);
    try {
      void ctx.tatchiPasskey.initWalletIframe().catch(() => {});
    } catch {}
    updateThemeBridge(ctx);
  }
  return ctx.tatchiPasskey!;
}

export function updateThemeBridge(ctx: HostContext): void {
  try {
    const pm = ctx.tatchiPasskey;
    if (!pm) return;
    const theme = pm.theme;
    if (theme === 'light' || theme === 'dark') {
      document.documentElement.setAttribute('data-w3a-theme', theme);
    }
  } catch {}
}

export function applyWalletConfig(ctx: HostContext, payload: PMSetConfigPayload): void {
  const prev = ctx.walletConfigs || ({} as TatchiConfigsInput);
  const nextSigningSessionPersistenceMode =
    payload?.signingSessionPersistenceMode ?? prev.signingSessionPersistenceMode;
  const nextSigningSessionSeal =
    nextSigningSessionPersistenceMode === 'sealed_refresh_v1'
      ? payload?.signingSessionSeal ?? prev.signingSessionSeal
      : undefined;
  const nextChains = Array.isArray(payload?.chains)
    ? payload.chains.map(cloneChainConfig)
    : Array.isArray(prev.chains)
      ? prev.chains.map(cloneChainConfig)
      : [];
  const prevLightColors = toStringRecord(prev.appearance?.tokens?.light?.colors);
  const prevDarkColors = toStringRecord(prev.appearance?.tokens?.dark?.colors);
  const incomingLightRaw = payload?.appearance?.tokens?.light?.colors;
  const incomingDarkRaw = payload?.appearance?.tokens?.dark?.colors;
  const nextLightColors =
    incomingLightRaw !== undefined ? toStringRecord(incomingLightRaw) : prevLightColors;
  const nextDarkColors =
    incomingDarkRaw !== undefined ? toStringRecord(incomingDarkRaw) : prevDarkColors;
  const incomingTheme = coerceThemeName(payload?.appearance?.theme);
  const prevTheme = coerceThemeName(prev.appearance?.theme);
  const nextTheme = incomingTheme ?? prevTheme;
  const hasAppearance =
    !!nextTheme ||
    Object.keys(nextLightColors).length > 0 ||
    Object.keys(nextDarkColors).length > 0;
  const nextAppearance = hasAppearance
    ? {
        ...(prev.appearance || {}),
        ...(nextTheme ? { theme: nextTheme } : {}),
        palette: 'default' as const,
        tokens: {
          light: { colors: nextLightColors },
          dark: { colors: nextDarkColors },
        },
      }
    : undefined;

  const base = {
    chains: nextChains,
    relayerAccount: payload?.relayerAccount ?? prev.relayerAccount ?? '',
    signingSessionDefaults: payload?.signingSessionDefaults ?? prev.signingSessionDefaults,
    signingSessionPersistenceMode: nextSigningSessionPersistenceMode,
    ...(nextSigningSessionSeal ? { signingSessionSeal: nextSigningSessionSeal } : {}),
    thresholdEcdsaPresignPool: payload?.thresholdEcdsaPresignPool ?? prev.thresholdEcdsaPresignPool,
    provisioningDefaults: payload?.provisioningDefaults ?? prev.provisioningDefaults,
    relayer:
      payload?.relayer || prev.relayer
        ? {
            ...(prev.relayer || {}),
            ...(payload?.relayer || {}),
            emailRecovery: {
              ...(prev.relayer?.emailRecovery || {}),
              ...(payload?.relayer?.emailRecovery || {}),
            },
          }
        : undefined,
    registration:
      payload?.registration === undefined ? prev.registration : payload.registration,
    authenticatorOptions: payload?.authenticatorOptions ?? prev.authenticatorOptions,
    iframeWallet: {
      ...(prev.iframeWallet || {}),
      ...(payload?.iframeWallet || {}),
    },
    appearance: nextAppearance ?? prev.appearance,
  } as TatchiConfigsInput;
  ctx.walletConfigs = sanitizeWalletHostConfigs(base);

  // Keep wallet-host theme + Lit token overrides in sync with app appearance config.
  try {
    if (nextTheme) {
      document.documentElement.setAttribute('data-w3a-theme', nextTheme);
    }
    upsertLitThemeOverrideStyle({
      darkColors: nextDarkColors,
      lightColors: nextLightColors,
    });
  } catch {}

  // Configure SDK embedded asset base for Lit modal/embedded components
  try {
    const assetsBaseUrl = payload?.assetsBaseUrl as string | undefined;
    const safeOrigin = window.location.origin || window.location.href;
    const defaultRoot = (() => {
      try {
        const base = new URL('/sdk/', safeOrigin).toString();
        return base.endsWith('/') ? base : base + '/';
      } catch {
        return '/sdk/';
      }
    })();
    let resolvedBase = defaultRoot;
    const assetsBaseUrlCandidate = isString(assetsBaseUrl) ? assetsBaseUrl : undefined;
    if (assetsBaseUrlCandidate !== undefined) {
      try {
        const u = new URL(assetsBaseUrlCandidate, safeOrigin);
        if (u.origin === safeOrigin) {
          const norm = u.toString().endsWith('/') ? u.toString() : u.toString() + '/';
          resolvedBase = norm;
        }
      } catch {}
    }
    setEmbeddedBase(resolvedBase);
  } catch {}

  // Reset instances so they re-initialize with new config lazily
  ctx.nearClient = null;
  ctx.tatchiPasskey = null;

  // Forward UI registry to iframe-lit-elem-mounter if provided
  try {
    const uiRegistry = payload?.uiRegistry;
    if (uiRegistry && typeof uiRegistry === 'object') {
      window.postMessage({ type: 'WALLET_UI_REGISTER_TYPES', payload: uiRegistry }, '*');
    }
  } catch {}
}
