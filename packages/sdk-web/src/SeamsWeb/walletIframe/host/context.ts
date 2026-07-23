import { MinimalNearClient } from '@/core/rpcClients/near/NearClient';
import { SeamsWeb } from '@/SeamsWeb';
import { __setWalletIframeHostMode } from '@/core/browser/walletIframe/host-mode';
import type { AppearanceConfigInput, SeamsConfigsInput, ThemeMode } from '@/core/types/seams';
import type { PMSetConfigPayload } from '../shared/messages';
import type { SdkLifecycleEvent, SdkLifecycleEventListener } from '@/core/types/sdkSentEvents';
import type { WalletSessionId } from '@/core/types/sdkSentEvents';
import type { WalletId } from '@shared/utils/domainIds';
import { isString } from '@shared/utils/validation';
import { setEmbeddedBase } from '@/core/walletRuntimePaths';
import { cloneChainConfig, resolvePrimaryNearRpcUrl } from '@/core/config/chains';
import {
  assertWalletHostConfigsNoNestedIframeWallet,
  sanitizeWalletHostConfigs,
} from './config-guards';
import {
  createCspStylesheetManager,
  getDefaultCspNonce,
} from '@/core/browser/walletIframe/csp-stylesheet';

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
  /* host-document dialogs (plain DOM, not lit) that must follow the app
     palette, e.g. the email-OTP recovery codes backup dialog */
  '.w3a-host-themed-dialog',
] as const;
const W3A_LIT_DARK_SELECTOR = W3A_LIT_HOST_SELECTORS.join(',\n');
const W3A_LIT_LIGHT_SELECTOR = W3A_LIT_HOST_SELECTORS.map(
  (selector) =>
    `${selector}[theme="light"],\n:root[data-w3a-theme="light"] ${selector}:not([theme="dark"])`,
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

function coerceThemeMode(value: unknown): ThemeMode | undefined {
  return value === 'light' || value === 'dark' ? value : undefined;
}

function objectRecord(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  return value as Record<string, unknown>;
}

function normalizeForStableSerialize(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map((entry) => normalizeForStableSerialize(entry));
  }
  if (value && typeof value === 'object') {
    const record = value as Record<string, unknown>;
    const normalized: Record<string, unknown> = {};
    for (const key of Object.keys(record).sort()) {
      normalized[key] = normalizeForStableSerialize(record[key]);
    }
    return normalized;
  }
  return value;
}

function stableSerialize(value: unknown): string {
  try {
    return JSON.stringify(normalizeForStableSerialize(value));
  } catch {
    return '';
  }
}

function buildWalletRuntimeResetFingerprint(config: SeamsConfigsInput | null | undefined): string {
  return stableSerialize({
    chains: config?.chains,
    relayerAccount: config?.relayerAccount,
    relayer: config?.relayer,
    registration: config?.registration,
    signingSessionDefaults: config?.signingSessionDefaults,
    signingSessionPersistenceMode: config?.signingSessionPersistenceMode,
    signingSessionSeal: config?.signingSessionSeal,
    routerAb: config?.routerAb,
    routerAbEcdsaDerivationPresignaturePool: config?.routerAbEcdsaDerivationPresignaturePool,
    provisioningDefaults: config?.provisioningDefaults,
    authenticatorOptions: config?.authenticatorOptions,
    iframeWallet: config?.iframeWallet,
  });
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

function serializeTokenOverrides(
  record: Record<string, string>,
  group: 'colors' | 'shape',
): string[] {
  const lines: string[] = [];
  for (const [rawName, rawValue] of Object.entries(record)) {
    const tokenName = sanitizeTokenName(rawName);
    if (!tokenName) continue;
    const tokenValue = sanitizeTokenValue(rawValue);
    if (!tokenValue) continue;
    // Use !important so app-provided token overrides keep precedence even if
    // generated w3a-components.css is loaded/reloaded later.
    lines.push(`  --w3a-${group}-${tokenName}: ${tokenValue} !important;`);
  }
  return lines;
}

function appearanceMode(appearance: unknown): ThemeMode | undefined {
  const record = objectRecord(appearance);
  if (!record) return undefined;
  const theme = record.theme;
  const legacyTheme = coerceThemeMode(theme);
  if (legacyTheme) return legacyTheme;
  return coerceThemeMode(objectRecord(theme)?.mode);
}

function appearanceThemeId(appearance: unknown, fallback: string): string {
  const theme = objectRecord(objectRecord(appearance)?.theme);
  const rawId = typeof theme?.id === 'string' ? theme.id.trim() : '';
  return rawId || fallback;
}

function legacyAppearanceColors(appearance: unknown, mode: ThemeMode): Record<string, string> {
  const tokens = objectRecord(objectRecord(appearance)?.tokens);
  return toStringRecord(objectRecord(objectRecord(tokens?.[mode])?.colors));
}

function objectAppearanceColors(appearance: unknown, mode: ThemeMode): Record<string, string> {
  const theme = objectRecord(objectRecord(appearance)?.theme);
  if (coerceThemeMode(theme?.mode) !== mode) return {};
  return toStringRecord(theme?.colors);
}

function appearanceColors(appearance: unknown, mode: ThemeMode): Record<string, string> {
  return {
    ...legacyAppearanceColors(appearance, mode),
    ...objectAppearanceColors(appearance, mode),
  };
}

function appearanceShape(appearance: unknown): Record<string, string> {
  const theme = objectRecord(objectRecord(appearance)?.theme);
  return toStringRecord(theme?.shape);
}

function normalizeWalletHostAppearance(args: {
  previous?: AppearanceConfigInput;
  incoming?: AppearanceConfigInput;
}): AppearanceConfigInput | undefined {
  if (args.incoming === undefined) return args.previous;
  const mode = appearanceMode(args.incoming) ?? appearanceMode(args.previous);
  if (!mode) return args.previous;
  const previousId = appearanceThemeId(args.previous, 'default');
  const id = appearanceThemeId(args.incoming, previousId);
  /* A different theme id is a theme switch: replace colors/shape wholesale so
     keys the new theme doesn't define can't leak from the old one. */
  const isThemeSwitch = id !== previousId;
  const colors = {
    ...(isThemeSwitch ? {} : appearanceColors(args.previous, mode)),
    ...appearanceColors(args.incoming, mode),
  };
  const shape = {
    ...(isThemeSwitch ? {} : appearanceShape(args.previous)),
    ...appearanceShape(args.incoming),
  };
  return {
    theme: {
      id,
      mode,
      colors,
      ...(Object.keys(shape).length > 0 ? { shape } : {}),
    },
    palette: 'default',
  };
}

function upsertLitThemeOverrideStyle(appearance?: AppearanceConfigInput): void {
  const mode = appearanceMode(appearance);
  const colors = mode ? appearanceColors(appearance, mode) : {};
  const lines = [
    ...serializeTokenOverrides(colors, 'colors'),
    ...serializeTokenOverrides(appearanceShape(appearance), 'shape'),
  ];
  const cssBlocks: string[] = [];

  if (mode && lines.length > 0) {
    const selector = mode === 'light' ? W3A_LIT_LIGHT_SELECTOR : W3A_LIT_DARK_SELECTOR;
    cssBlocks.push(`${selector} {\n${lines.join('\n')}\n}`);
  }

  const cssText = cssBlocks.join('\n\n').trim();
  if (!cssText) {
    getLitThemeOverrideStyleManager().deleteDynamicRule(W3A_LIT_THEME_OVERRIDE_RULE_ID);
    return;
  }
  getLitThemeOverrideStyleManager().setDynamicRule(W3A_LIT_THEME_OVERRIDE_RULE_ID, cssText);
}

export interface HostContext {
  parentOrigin: string | null;
  port: MessagePort | null;
  walletConfigs: SeamsConfigsInput | null;
  nearClient: MinimalNearClient | null;
  seamsWeb: SeamsWeb | null;
  prefsUnsubscribe?: (() => void) | null;
  lifecycleSource: SeamsWeb | null;
  lifecycleUnsubscribe: (() => void) | null;
  lifecycleListener: SdkLifecycleEventListener | null;
  expiredSessionsByWallet: Map<WalletId, Set<WalletSessionId>>;
  onWindowMessage?: (e: MessageEvent) => void;
}

export function createHostContext(): HostContext {
  return {
    parentOrigin: null,
    port: null,
    walletConfigs: null,
    nearClient: null,
    seamsWeb: null,
    prefsUnsubscribe: null,
    lifecycleSource: null,
    lifecycleUnsubscribe: null,
    lifecycleListener: null,
    expiredSessionsByWallet: new Map(),
    onWindowMessage: undefined,
  };
}

export function ensureSeamsWeb(ctx: HostContext): SeamsWeb {
  const { walletConfigs } = ctx;
  if (!walletConfigs) {
    throw new Error('Wallet service not configured. Call PM_SET_CONFIG first.');
  }
  const nearRpcUrl = resolvePrimaryNearRpcUrl(walletConfigs.chains || []);
  if (!ctx.nearClient) {
    ctx.nearClient = new MinimalNearClient(nearRpcUrl);
  }
  if (!ctx.seamsWeb) {
    const cfg = sanitizeWalletHostConfigs(walletConfigs);
    assertWalletHostConfigsNoNestedIframeWallet(cfg);
    __setWalletIframeHostMode(true);
    ctx.seamsWeb = new SeamsWeb(cfg, ctx.nearClient, { allowDirectWalletMode: 'wallet_host' });
    try {
      void ctx.seamsWeb.initWalletIframe().catch(() => {});
    } catch {}
    updateThemeBridge(ctx);
  }
  return ctx.seamsWeb!;
}

export function updateThemeBridge(ctx: HostContext): void {
  try {
    const pm = ctx.seamsWeb;
    if (!pm) return;
    const theme = pm.theme;
    if (theme === 'light' || theme === 'dark') {
      document.documentElement.setAttribute('data-w3a-theme', theme);
    }
  } catch {}
}

export function applyWalletConfig(ctx: HostContext, payload: PMSetConfigPayload): void {
  const prev = ctx.walletConfigs || ({} as SeamsConfigsInput);
  const prevRuntimeResetFingerprint = buildWalletRuntimeResetFingerprint(ctx.walletConfigs);
  const nextSigningSessionPersistenceMode =
    payload?.signingSessionPersistenceMode ?? prev.signingSessionPersistenceMode;
  const nextSigningSessionSeal =
    nextSigningSessionPersistenceMode === 'sealed_refresh_v1'
      ? (payload?.signingSessionSeal ?? prev.signingSessionSeal)
      : undefined;
  const nextChains = Array.isArray(payload?.chains)
    ? payload.chains.map(cloneChainConfig)
    : Array.isArray(prev.chains)
      ? prev.chains.map(cloneChainConfig)
      : [];
  const nextAppearance = normalizeWalletHostAppearance({
    previous: prev.appearance,
    incoming: payload?.appearance,
  });
  const nextTheme = appearanceMode(nextAppearance);

  const base = {
    chains: nextChains,
    relayerAccount: payload?.relayerAccount ?? prev.relayerAccount ?? '',
    signingSessionDefaults: payload?.signingSessionDefaults ?? prev.signingSessionDefaults,
    signingSessionPersistenceMode: nextSigningSessionPersistenceMode,
    ...(nextSigningSessionSeal ? { signingSessionSeal: nextSigningSessionSeal } : {}),
    routerAb: payload?.routerAb ?? prev.routerAb,
    routerAbEcdsaDerivationPresignaturePool:
      payload?.routerAbEcdsaDerivationPresignaturePool ?? prev.routerAbEcdsaDerivationPresignaturePool,
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
    registration: payload?.registration === undefined ? prev.registration : payload.registration,
    authenticatorOptions: payload?.authenticatorOptions ?? prev.authenticatorOptions,
    iframeWallet: {
      ...(prev.iframeWallet || {}),
      ...(payload?.iframeWallet || {}),
    },
    appearance: nextAppearance,
  } as SeamsConfigsInput;
  ctx.walletConfigs = sanitizeWalletHostConfigs(base);
  const nextRuntimeResetFingerprint = buildWalletRuntimeResetFingerprint(ctx.walletConfigs);

  // Keep wallet-host theme + Lit token overrides in sync with app appearance config.
  try {
    if (nextTheme) {
      document.documentElement.setAttribute('data-w3a-theme', nextTheme);
    }
    upsertLitThemeOverrideStyle(nextAppearance);
  } catch {}

  if (
    ctx.seamsWeb &&
    nextAppearance &&
    nextRuntimeResetFingerprint === prevRuntimeResetFingerprint
  ) {
    try {
      ctx.seamsWeb.setAppearance(nextAppearance);
    } catch {}
  }

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

  // Reset runtime instances only when signing/runtime config changes. Cosmetic config updates
  // (theme/tokens/UI registry/assets base) must not drop warm signing session state.
  if (nextRuntimeResetFingerprint !== prevRuntimeResetFingerprint) {
    ctx.seamsWeb?.dispose();
    ctx.prefsUnsubscribe?.();
    ctx.lifecycleUnsubscribe?.();
    ctx.prefsUnsubscribe = null;
    ctx.lifecycleSource = null;
    ctx.lifecycleUnsubscribe = null;
    ctx.nearClient = null;
    ctx.seamsWeb = null;
  }

  // Forward UI registry to iframe-lit-elem-mounter if provided
  try {
    const uiRegistry = payload?.uiRegistry;
    if (uiRegistry && typeof uiRegistry === 'object') {
      window.postMessage({ type: 'WALLET_UI_REGISTER_TYPES', payload: uiRegistry }, '*');
    }
  } catch {}
}

export function ensureWalletHostLifecycleSubscription(ctx: HostContext, pm: SeamsWeb): void {
  if (ctx.lifecycleSource === pm) return;
  ctx.lifecycleUnsubscribe?.();
  ctx.lifecycleSource = pm;
  ctx.lifecycleUnsubscribe = pm.onSdkLifecycleEvent(handleWalletHostLifecycleEvent.bind(null, ctx));
}

export function setWalletHostLifecycleListener(
  ctx: HostContext,
  listener: SdkLifecycleEventListener,
): void {
  ctx.lifecycleListener = listener;
  if (ctx.seamsWeb) ensureWalletHostLifecycleSubscription(ctx, ctx.seamsWeb);
}

function handleWalletHostLifecycleEvent(ctx: HostContext, event: SdkLifecycleEvent): void {
  const sessions = ctx.expiredSessionsByWallet.get(event.walletId);
  if (sessions?.has(event.walletSessionId)) return;
  if (sessions) sessions.add(event.walletSessionId);
  else ctx.expiredSessionsByWallet.set(event.walletId, new Set([event.walletSessionId]));
  ctx.lifecycleListener?.(event);
}
