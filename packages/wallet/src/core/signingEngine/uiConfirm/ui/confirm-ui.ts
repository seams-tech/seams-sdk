import { WalletIframeDomEvents } from '@/core/browser/walletIframe/events';
import { __isWalletIframeHostMode } from '@/core/browser/walletIframe/host-mode';
import type { UserConfirmSecurityContext, TransactionInputWasm } from '@/core/types';
import type { AppearanceConfig, ThemeMode } from '@/core/types/seams';
import {
  isActionArgsWasm,
  toActionArgsWasm,
  type ActionArgs,
  type ActionArgsWasm,
} from '@/core/types/actions';
import { resolveExplorerUrlForChainFamily } from '@/core/config/chains';
import type { TxDisplayModel } from '@/core/signingEngine/interfaces/display';
import { computeUiIntentDigestFromTxs, orderActionForDigest } from '@/utils/intentDigest';

import type { UiConfirmContext, UiConfirmSurfaceMeasurementBinding } from '../uiConfirm.types';
import type { TransactionSummary } from '@/core/signingEngine/stepUpConfirmation/channel/confirmTypes';
import type { EmailOtpConfirmPrompt, SigningAuthMode } from '../../stepUpConfirmation/types';
import type {
  ConfirmUIHandle,
  ConfirmUIPromptDiagnostics,
  ConfirmUISurfaceSource,
  ConfirmUIUpdate,
  ConfirmationUIMode,
  MountedConfirmUIHandle,
} from './confirm-ui-types';
import {
  CONFIRM_UI_ELEMENT_SELECTORS,
  W3A_CONFIRM_PORTAL_ID,
  W3A_TX_CONFIRMER_ID,
  ensureDefined,
} from './registry';
import {
  createWalletIframeSurfaceMeasurementReporter,
  type WalletIframeSurfaceMeasurementReporter,
} from '@/SeamsWeb/walletIframe/host/lit-ui/surface-measurement-reporter';
import { ensureExternalStyles } from './lit-components/css/css-loader';
import {
  attachConfirmSurfaceResizeChoreographer,
  CONFIRM_SURFACE_MODE_ATTR,
  type ConfirmSurfaceResizeChoreographer,
} from './confirm-surface-resize';

export type {
  ConfirmUIHandle,
  ConfirmUIPromptDiagnostics,
  ConfirmUISurfaceSource,
  ConfirmUIUpdate,
  ConfirmationUIMode,
  MountedConfirmUIHandle,
} from './confirm-ui-types';

function roundConfirmUiDurationMs(startedAt: number): number {
  return Math.max(0, Math.round(performance.now() - startedAt));
}

type ConfirmEventDetail = {
  confirmed?: boolean;
  error?: string;
  otpCode?: string;
  emailOtpChallengeId?: string;
};

type ConfirmDecisionResult = {
  confirmed: boolean;
  error?: string;
  otpCode?: string;
  emailOtpChallengeId?: string;
};

interface HostTxConfirmerElement extends HTMLElement {
  variant?: 'modal' | 'drawer';
  nearAccountId: string;
  txSigningRequests?: TransactionInputWasm[];
  model?: TxDisplayModel;
  intentDigest?: string;
  securityContext?: Partial<UserConfirmSecurityContext>;
  theme?: ThemeMode;
  appearance?: AppearanceConfig;
  loading?: boolean;
  deferClose?: boolean;
  errorMessage?: string;
  confirmText?: string;
  cancelText?: string;
  body?: string;
  title: string;
  signingAuthMode?: SigningAuthMode;
  emailOtpPrompt?: EmailOtpConfirmPrompt;
  requestUpdate?: () => void;
  nearExplorerUrl?: string;
  tempoExplorerUrl?: string;
  evmExplorerUrl?: string;
  updateComplete?: Promise<unknown>;
  close?: (confirmed: boolean) => void;
}

type ConfirmUIInternalUpdate = ConfirmUIUpdate & {
  nearExplorerUrl?: string;
  tempoExplorerUrl?: string;
  evmExplorerUrl?: string;
};

const confirmSurfaceMeasurementReporters = new WeakMap<
  HTMLElement,
  WalletIframeSurfaceMeasurementReporter
>();
// Lives exactly as long as the reporter: while the parent hugs this host, tree
// nodes inside it hand their height motion over so the box grows first.
const confirmSurfaceResizeChoreographers = new WeakMap<
  HTMLElement,
  ConfirmSurfaceResizeChoreographer
>();
const confirmSurfaceMeasurementBindings = new WeakMap<
  HTMLElement,
  UiConfirmSurfaceMeasurementBinding
>();

export type ConfirmUIRenderContext = {
  userPreferencesManager: Pick<UiConfirmContext['userPreferencesManager'], 'getCurrentWalletId'>;
  chains?: UiConfirmContext['chains'];
  getAppearance?: UiConfirmContext['getAppearance'];
  nearExplorerUrl?: string;
  tempoExplorerUrl?: string;
  evmExplorerUrl?: string;
  surfaceMeasurementBinding: UiConfirmSurfaceMeasurementBinding;
};

async function ensureTxConfirmerElementDefined(): Promise<void> {
  await ensureDefined(
    W3A_TX_CONFIRMER_ID,
    () => import('./lit-components/IframeTxConfirmer/tx-confirmer-wrapper'),
  );
}

export async function prewarmTxConfirmerUi(): Promise<void> {
  await ensureTxConfirmerElementDefined();
  const root = typeof document === 'undefined' ? null : document.documentElement;
  if (!root) return;
  await Promise.all([
    ensureExternalStyles(root, 'w3a-components.css', 'data-w3a-components-css'),
    ensureExternalStyles(root, 'tx-tree.css', 'data-w3a-tx-tree-css'),
    ensureExternalStyles(root, 'tx-confirmer.css', 'data-w3a-tx-confirmer-css'),
    ensureExternalStyles(root, 'halo-border.css', 'data-w3a-halo-border-css'),
    ensureExternalStyles(root, 'passkey-halo-loading.css', 'data-w3a-passkey-halo-loading-css'),
  ]);
}

const DEFAULT_CONFIRM_APPEARANCE: AppearanceConfig = {
  theme: {
    id: 'default',
    mode: 'dark',
    colors: {},
  },
  palette: 'default',
};

function isThemeMode(value: unknown): value is ThemeMode {
  return value === 'light' || value === 'dark';
}

function withAppearanceMode(appearance: AppearanceConfig, mode?: ThemeMode): AppearanceConfig {
  if (!isThemeMode(mode) || mode === appearance.theme.mode) return appearance;
  return {
    ...appearance,
    theme: {
      ...appearance.theme,
      mode,
    },
  };
}

function resolveAppearance(args: {
  ctx: ConfirmUIRenderContext;
  requestedAppearance?: AppearanceConfig;
  requestedMode?: ThemeMode;
}): AppearanceConfig {
  const base = args.requestedAppearance ?? args.ctx.getAppearance?.() ?? DEFAULT_CONFIRM_APPEARANCE;
  return withAppearanceMode(base, args.requestedMode);
}

function postWalletUiMessage(type: 'WALLET_UI_OPENED' | 'WALLET_UI_CLOSED'): void {
  try {
    if (!__isWalletIframeHostMode()) return;
    if (typeof window === 'undefined') return;
    if (window.parent === window) return;
    window.parent?.postMessage({ type }, '*');
  } catch {}
}

function uiModeToVariant(uiMode: ConfirmationUIMode): 'modal' | 'drawer' {
  return uiMode === 'drawer' ? 'drawer' : 'modal';
}

function normalizeTxSigningRequestsForDigest(
  txSigningRequests?: TransactionInputWasm[],
): TransactionInputWasm[] {
  return (txSigningRequests || []).map((tx) => ({
    receiverId: tx.receiverId,
    actions: (tx.actions || [])
      .map((action) =>
        isActionArgsWasm(action) ? action : toActionArgsWasm(action as unknown as ActionArgs),
      )
      .map((action) => orderActionForDigest(action as ActionArgsWasm) as ActionArgsWasm),
  }));
}

async function checkIntentDigestGuard(
  expectedIntentDigest: string | undefined,
  txSigningRequests?: TransactionInputWasm[],
): Promise<string | undefined> {
  const hasTxs = (txSigningRequests?.length || 0) > 0;
  if (!hasTxs || !expectedIntentDigest) return undefined;

  try {
    const normalizedTxs = normalizeTxSigningRequestsForDigest(txSigningRequests);
    const uiDigest = await computeUiIntentDigestFromTxs(normalizedTxs);
    return uiDigest === expectedIntentDigest ? undefined : 'INTENT_DIGEST_MISMATCH';
  } catch {
    return 'UI_DIGEST_VALIDATION_FAILED';
  }
}

function updateConfirmPortalState(portal: HTMLElement): void {
  if (portal.childElementCount > 0) {
    portal.classList.add('w3a-portal--visible');
  } else {
    portal.classList.remove('w3a-portal--visible');
  }
}

function mountedConfirmerHosts(): HTMLElement[] {
  const selector = CONFIRM_UI_ELEMENT_SELECTORS.join(',');
  const hosts: HTMLElement[] = [];
  for (const candidate of document.querySelectorAll<HTMLElement>(selector)) {
    if (candidate.parentElement?.closest(selector)) continue;
    hosts.push(candidate);
  }
  return hosts;
}

function cleanupExistingConfirmers(): void {
  for (const element of mountedConfirmerHosts()) {
    disconnectConfirmSurfaceMeasurementReporter(element);
    element.dispatchEvent(
      new CustomEvent(WalletIframeDomEvents.TX_CONFIRMER_CANCEL, { bubbles: true, composed: true }),
    );
    element.remove();
  }
  const portal = document.getElementById(W3A_CONFIRM_PORTAL_ID) as HTMLElement | null;
  if (portal) updateConfirmPortalState(portal);
}

function ensureConfirmPortal(): HTMLElement {
  let portal = document.getElementById(W3A_CONFIRM_PORTAL_ID) as HTMLElement | null;
  if (!portal) {
    portal = document.createElement('div');
    portal.id = W3A_CONFIRM_PORTAL_ID;
    portal.classList.add('w3a-portal');
    const root = document.body ?? document.documentElement;
    if (root) root.appendChild(portal);
  }
  return portal;
}

function removeHostConfirmerElement(element: HTMLElement): void {
  disconnectConfirmSurfaceMeasurementReporter(element);
  element.remove();
  const portal = document.getElementById(W3A_CONFIRM_PORTAL_ID) as HTMLElement | null;
  if (portal) updateConfirmPortalState(portal);
}

function postWalletUiClosedIfPortalEmpty(): void {
  const portal = document.getElementById(W3A_CONFIRM_PORTAL_ID);
  if ((portal?.childElementCount ?? 0) > 0) return;
  postWalletUiMessage('WALLET_UI_CLOSED');
}

const DRAWER_CLOSE_FALLBACK_MS = 250;

function closeHostConfirmerElement(
  element: HostTxConfirmerElement,
  confirmed: boolean,
  onClose: () => void,
): void {
  let finished = false;
  const finish = () => {
    if (finished) return;
    finished = true;
    removeHostConfirmerElement(element);
    onClose();
  };

  if (!confirmed) {
    element.dispatchEvent(
      new CustomEvent(WalletIframeDomEvents.TX_CONFIRMER_CANCEL, {
        detail: { confirmed: false },
        bubbles: true,
        composed: true,
      }),
    );
  }

  if (element.variant !== 'drawer') {
    finish();
    return;
  }

  const onDrawerCloseEnd = () => {
    window.clearTimeout(timeoutId);
    finish();
  };

  element.addEventListener('w3a:drawer-close-end', onDrawerCloseEnd as EventListener, {
    once: true,
  });
  element.close?.(confirmed);

  const timeoutId = window.setTimeout(() => {
    element.removeEventListener('w3a:drawer-close-end', onDrawerCloseEnd as EventListener);
    finish();
  }, DRAWER_CLOSE_FALLBACK_MS);
}

function setErrorAttribute(element: HTMLElement, message: string): void {
  if (message) {
    element.setAttribute('data-error-message', message);
  } else {
    element.removeAttribute('data-error-message');
  }
}

function resolveExplorerUrlsFromModel(
  ctx: ConfirmUIRenderContext,
  model?: TxDisplayModel,
): Pick<ConfirmUIUpdate, 'nearExplorerUrl' | 'tempoExplorerUrl' | 'evmExplorerUrl'> {
  const chain = model?.chain;
  if (chain !== 'near' && chain !== 'tempo' && chain !== 'evm') return {};

  const explorerUrl = resolveExplorerUrlForChainFamily({
    chains: ctx.chains,
    family: chain,
    chainId: model?.chainId,
  });
  if (!explorerUrl) return {};

  if (chain === 'near') return { nearExplorerUrl: explorerUrl };
  if (chain === 'tempo') return { tempoExplorerUrl: explorerUrl };
  return { evmExplorerUrl: explorerUrl };
}

function applyHostElementProps(
  ctx: ConfirmUIRenderContext,
  element: HostTxConfirmerElement,
  props?: ConfirmUIUpdate,
): void {
  if (!props) return;

  const update = props as ConfirmUIInternalUpdate;

  if (update.nearAccountId != null) element.nearAccountId = update.nearAccountId;
  if (Object.prototype.hasOwnProperty.call(update, 'model')) element.model = update.model;
  if (Object.prototype.hasOwnProperty.call(update, 'intentDigest')) {
    element.intentDigest = update.intentDigest;
  }
  if (update.securityContext != null) element.securityContext = update.securityContext;
  if (Object.prototype.hasOwnProperty.call(update, 'appearance')) {
    element.appearance = update.appearance;
    if (update.appearance) element.theme = update.appearance.theme.mode;
  }
  if (update.theme != null) {
    element.appearance = resolveAppearance({
      ctx,
      requestedAppearance: element.appearance,
      requestedMode: update.theme,
    });
    element.theme = element.appearance.theme.mode;
  }
  if (update.loading != null) element.loading = !!update.loading;
  if (update.confirmText != null) element.confirmText = update.confirmText;
  if (update.cancelText != null) element.cancelText = update.cancelText;
  if (update.body != null) element.body = update.body;
  if (update.title != null) element.title = update.title;
  if (Object.prototype.hasOwnProperty.call(update, 'errorMessage')) {
    const message = update.errorMessage ?? '';
    element.errorMessage = message;
    setErrorAttribute(element, message);
  }
  if (update.nearExplorerUrl != null) {
    element.nearExplorerUrl = update.nearExplorerUrl;
  }
  if (update.tempoExplorerUrl != null) {
    element.tempoExplorerUrl = update.tempoExplorerUrl;
  }
  if (update.evmExplorerUrl != null) {
    element.evmExplorerUrl = update.evmExplorerUrl;
  }
  if (update.signingAuthMode != null) element.signingAuthMode = update.signingAuthMode;
  if (update.emailOtpPrompt != null) element.emailOtpPrompt = update.emailOtpPrompt;

  if (
    update.nearExplorerUrl == null &&
    update.tempoExplorerUrl == null &&
    update.evmExplorerUrl == null
  ) {
    const explorerOverrides = resolveExplorerUrlsFromModel(ctx, update.model ?? element.model);
    if (explorerOverrides.nearExplorerUrl) {
      element.nearExplorerUrl = explorerOverrides.nearExplorerUrl;
    }
    if (explorerOverrides.tempoExplorerUrl) {
      element.tempoExplorerUrl = explorerOverrides.tempoExplorerUrl;
    }
    if (explorerOverrides.evmExplorerUrl) {
      element.evmExplorerUrl = explorerOverrides.evmExplorerUrl;
    }
  }

  element.requestUpdate?.();
}

function sameConfirmSurfaceMeasurementBinding(
  left: UiConfirmSurfaceMeasurementBinding | undefined,
  right: UiConfirmSurfaceMeasurementBinding,
): boolean {
  if (!left || left.kind !== right.kind) return false;
  switch (left.kind) {
    case 'disabled':
      return right.kind === 'disabled';
    case 'wallet_iframe':
      return (
        right.kind === 'wallet_iframe' &&
        left.requestId === right.requestId &&
        left.postMeasurement === right.postMeasurement &&
        left.hostSurfaceVariant === right.hostSurfaceVariant
      );
  }
}

function disconnectConfirmSurfaceMeasurementReporter(element: HTMLElement): void {
  confirmSurfaceMeasurementReporters.get(element)?.disconnect();
  confirmSurfaceMeasurementReporters.delete(element);
  confirmSurfaceResizeChoreographers.get(element)?.dispose();
  confirmSurfaceResizeChoreographers.delete(element);
  confirmSurfaceMeasurementBindings.delete(element);
}

function createConfirmSurfaceMeasurementReporter(
  binding: UiConfirmSurfaceMeasurementBinding,
  element: HTMLElement,
): WalletIframeSurfaceMeasurementReporter | null {
  switch (binding.kind) {
    case 'disabled':
      return null;
    case 'wallet_iframe':
      return createWalletIframeSurfaceMeasurementReporter({
        kind: 'request_surface',
        element,
        requestId: binding.requestId,
        postMeasurement: binding.postMeasurement,
      });
    default: {
      const exhaustive: never = binding;
      throw new Error(`Unhandled confirmation measurement binding: ${String(exhaustive)}`);
    }
  }
}

/**
 * Two independent values decide how a confirmation is laid out, and conflating
 * them is what once stranded the Email OTP export prompt in the top-left corner:
 *
 * - `data-w3a-confirm-variant` is what THIS confirmation renders (modal card or
 *   bottom sheet). It comes from the Confirmer UI setting.
 * - `data-w3a-confirm-surface` is the shape of the HOST BOX it renders into.
 *   `wallet-iframe` means the parent measured the card and sized the box to hug
 *   it, so the card must not position itself. `standalone` means the card owns a
 *   full-viewport canvas and centres (modal) or bottom-anchors (drawer) itself.
 *
 * They are usually the same value, so the box shape is inferred from the
 * variant. Key export is the exception: its box is pinned to a full-viewport
 * drawer for the whole request (the key viewer is always a drawer), while the
 * OTP prompt inside that box still follows the Confirmer UI setting. A modal
 * prompt in a full-viewport box must self-centre, so the box shape wins.
 */
function applyConfirmSurfaceMode(
  element: HTMLElement,
  binding: UiConfirmSurfaceMeasurementBinding,
): void {
  const variant = (element as HostTxConfirmerElement).variant;
  const hostBoxVariant =
    binding.kind === 'wallet_iframe' ? (binding.hostSurfaceVariant ?? variant) : variant;
  const surface =
    binding.kind === 'wallet_iframe' && hostBoxVariant === 'modal' ? 'wallet-iframe' : 'standalone';
  element.setAttribute(CONFIRM_SURFACE_MODE_ATTR, surface);
  if (variant) element.setAttribute('data-w3a-confirm-variant', variant);
}

function bindConfirmSurfaceMeasurementReporter(
  element: HTMLElement,
  binding: UiConfirmSurfaceMeasurementBinding,
): void {
  applyConfirmSurfaceMode(element, binding);
  if (
    sameConfirmSurfaceMeasurementBinding(confirmSurfaceMeasurementBindings.get(element), binding)
  ) {
    return;
  }
  disconnectConfirmSurfaceMeasurementReporter(element);
  confirmSurfaceMeasurementBindings.set(element, binding);
  const reporter = createConfirmSurfaceMeasurementReporter(binding, element);
  if (!reporter) return;
  confirmSurfaceMeasurementReporters.set(element, reporter);
  confirmSurfaceResizeChoreographers.set(element, attachConfirmSurfaceResizeChoreographer(element));
}

function createHostConfirmHandle(
  ctx: ConfirmUIRenderContext,
  element: HostTxConfirmerElement,
  onClose: () => void,
): MountedConfirmUIHandle {
  let closed = false;
  return {
    element,
    close: (confirmed: boolean) => {
      if (closed) return;
      closed = true;
      disconnectConfirmSurfaceMeasurementReporter(element);
      closeHostConfirmerElement(element, confirmed, onClose);
    },
    update: (props: ConfirmUIUpdate) => applyHostElementProps(ctx, element, props),
  };
}

export async function mountConfirmUI({
  ctx,
  summary,
  txSigningRequests,
  model,
  securityContext,
  loading,
  theme,
  appearance,
  uiMode,
  nearAccountIdOverride,
  signingAuthMode,
  emailOtpPrompt,
}: {
  ctx: ConfirmUIRenderContext;
  summary: TransactionSummary;
  txSigningRequests?: TransactionInputWasm[];
  model?: TxDisplayModel;
  securityContext?: Partial<UserConfirmSecurityContext>;
  loading?: boolean;
  theme?: ThemeMode;
  appearance?: AppearanceConfig;
  uiMode: ConfirmationUIMode;
  nearAccountIdOverride?: string;
  signingAuthMode?: SigningAuthMode;
  emailOtpPrompt?: EmailOtpConfirmPrompt;
}): Promise<MountedConfirmUIHandle> {
  await ensureTxConfirmerElementDefined();

  const variant = uiModeToVariant(uiMode);
  const { handle } = mountHostElement({
    ctx,
    summary,
    txSigningRequests,
    model,
    securityContext,
    loading,
    theme,
    appearance,
    variant,
    nearAccountIdOverride,
    signingAuthMode,
    emailOtpPrompt,
  });
  return handle;
}

type ResolveDecisionSurfaceArgs = {
  ctx: ConfirmUIRenderContext;
  summary: TransactionSummary;
  txSigningRequests: TransactionInputWasm[];
  model?: TxDisplayModel;
  securityContext?: Partial<UserConfirmSecurityContext>;
  loading?: boolean;
  theme: ThemeMode;
  appearance?: AppearanceConfig;
  variant: 'modal' | 'drawer';
  nearAccountIdOverride: string;
  signingAuthMode?: SigningAuthMode;
  emailOtpPrompt?: EmailOtpConfirmPrompt;
  surface: ConfirmUISurfaceSource;
};

function reuseMountedDecisionSurface(
  args: ResolveDecisionSurfaceArgs & {
    surface: Extract<ConfirmUISurfaceSource, { kind: 'reuse_mounted' }>;
  },
): {
  el: HostTxConfirmerElement;
  handle: MountedConfirmUIHandle;
  reused: true;
} {
  const handle = args.surface.handle;
  const el = handle.element as HostTxConfirmerElement;
  if (!el.isConnected) {
    throw new Error('Cannot reuse a detached confirmation surface');
  }
  el.variant = args.variant;
  bindConfirmSurfaceMeasurementReporter(el, args.ctx.surfaceMeasurementBinding);
  el.txSigningRequests = args.txSigningRequests;
  el.model = args.model;
  el.intentDigest = args.summary.intentDigest;
  el.securityContext = args.securityContext;
  el.appearance = resolveAppearance({
    ctx: args.ctx,
    requestedAppearance: args.appearance,
    requestedMode: args.theme,
  });
  el.theme = el.appearance.theme.mode;
  el.loading = args.loading ?? false;
  el.nearAccountId = args.nearAccountIdOverride;
  el.title = args.summary.title ?? '';
  el.body = args.summary.body ?? '';
  el.signingAuthMode = args.signingAuthMode;
  el.emailOtpPrompt = args.emailOtpPrompt;
  el.errorMessage = '';
  el.removeAttribute('data-error-message');
  el.requestUpdate?.();
  return { el, handle, reused: true };
}

function assertNeverConfirmationSurface(value: never): never {
  throw new Error(`Unhandled confirmation surface: ${JSON.stringify(value)}`);
}

function resolveDecisionSurface(args: ResolveDecisionSurfaceArgs): {
  el: HostTxConfirmerElement;
  handle: MountedConfirmUIHandle;
  reused: boolean;
} {
  switch (args.surface.kind) {
    case 'mount_new': {
      const mounted = mountHostElement({
        ctx: args.ctx,
        summary: args.summary,
        txSigningRequests: args.txSigningRequests,
        model: args.model,
        securityContext: args.securityContext,
        loading: args.loading,
        theme: args.theme,
        appearance: args.appearance,
        variant: args.variant,
        nearAccountIdOverride: args.nearAccountIdOverride,
        signingAuthMode: args.signingAuthMode,
        emailOtpPrompt: args.emailOtpPrompt,
      });
      return { ...mounted, reused: false };
    }
    case 'reuse_mounted':
      return reuseMountedDecisionSurface({
        ...args,
        surface: args.surface,
      });
    default:
      return assertNeverConfirmationSurface(args.surface);
  }
}

export async function prepareConfirmUISurface(args: {
  ctx: ConfirmUIRenderContext;
  summary: TransactionSummary;
  txSigningRequests: TransactionInputWasm[];
  model?: TxDisplayModel;
  securityContext?: Partial<UserConfirmSecurityContext>;
  loading?: boolean;
  theme: ThemeMode;
  appearance?: AppearanceConfig;
  uiMode: ConfirmationUIMode;
  nearAccountIdOverride: string;
  signingAuthMode?: SigningAuthMode;
  emailOtpPrompt?: EmailOtpConfirmPrompt;
  surface: ConfirmUISurfaceSource;
}): Promise<MountedConfirmUIHandle> {
  await ensureTxConfirmerElementDefined();
  const resolved = resolveDecisionSurface({
    ctx: args.ctx,
    summary: args.summary,
    txSigningRequests: args.txSigningRequests,
    model: args.model,
    securityContext: args.securityContext,
    loading: args.loading,
    theme: args.theme,
    appearance: args.appearance,
    variant: uiModeToVariant(args.uiMode),
    nearAccountIdOverride: args.nearAccountIdOverride,
    signingAuthMode: args.signingAuthMode,
    emailOtpPrompt: args.emailOtpPrompt,
    surface: args.surface,
  });
  return resolved.handle;
}

export async function awaitConfirmUIDecision({
  ctx,
  summary,
  txSigningRequests,
  model,
  securityContext,
  loading,
  theme,
  appearance,
  uiMode,
  nearAccountIdOverride,
  onMounted,
  signingAuthMode,
  emailOtpPrompt,
  surface,
}: {
  ctx: ConfirmUIRenderContext;
  summary: TransactionSummary;
  txSigningRequests: TransactionInputWasm[];
  model?: TxDisplayModel;
  securityContext?: Partial<UserConfirmSecurityContext>;
  loading?: boolean;
  theme: ThemeMode;
  appearance?: AppearanceConfig;
  uiMode: ConfirmationUIMode;
  nearAccountIdOverride: string;
  onMounted?: (handle: ConfirmUIHandle) => void;
  signingAuthMode?: SigningAuthMode;
  emailOtpPrompt?: EmailOtpConfirmPrompt;
  surface: ConfirmUISurfaceSource;
}): Promise<
  ConfirmDecisionResult & {
    handle: ConfirmUIHandle;
    diagnostics: ConfirmUIPromptDiagnostics;
  }
> {
  const elementDefineStartedAt = performance.now();
  await ensureTxConfirmerElementDefined();
  const elementDefineMs = roundConfirmUiDurationMs(elementDefineStartedAt);

  const variant = uiModeToVariant(uiMode);
  const resolvedVariant: 'modal' | 'drawer' = variant || 'modal';

  return new Promise((resolve) => {
    const mountStartedAt = performance.now();
    const { el, handle, reused } = resolveDecisionSurface({
      ctx,
      summary,
      txSigningRequests,
      model,
      securityContext,
      loading,
      theme,
      appearance,
      variant: resolvedVariant,
      nearAccountIdOverride,
      signingAuthMode,
      emailOtpPrompt,
      surface,
    });
    const mountMs = roundConfirmUiDurationMs(mountStartedAt);
    const decisionWaitStartedAt = performance.now();
    let hostFirstUpdateMs = 0;
    let hostInteractiveMs = reused ? mountMs : 0;
    let confirmEventMs = 0;
    const markDecisionWaitOffset = (currentValue: number): number =>
      currentValue > 0 ? currentValue : roundConfirmUiDurationMs(decisionWaitStartedAt);

    if (el.updateComplete) {
      void el.updateComplete
        .then(() => {
          hostFirstUpdateMs = markDecisionWaitOffset(hostFirstUpdateMs);
        })
        .catch(() => undefined);
    }

    try {
      onMounted?.(handle);
    } catch {}

    const finalize = (result: ConfirmDecisionResult) => {
      const diagnostics: ConfirmUIPromptDiagnostics = {
        kind: 'confirm_ui_prompt_diagnostics_v1',
        elementDefineMs,
        mountMs,
        hostFirstUpdateMs,
        hostInteractiveMs,
        confirmEventMs,
        decisionWaitMs: roundConfirmUiDurationMs(decisionWaitStartedAt),
      };
      cleanup();
      resolve({ ...result, handle, diagnostics });
    };

    const onConfirm = async (event: Event) => {
      confirmEventMs = markDecisionWaitOffset(confirmEventMs);
      const detail = (event as CustomEvent<ConfirmEventDetail> | undefined)?.detail;
      let confirmed = detail?.confirmed !== false;
      let error = typeof detail?.error === 'string' ? detail.error : undefined;

      if (confirmed) {
        const expectedIntentDigest = String(
          (el as HostTxConfirmerElement).intentDigest || summary?.intentDigest || '',
        ).trim();
        const guardError = await checkIntentDigestGuard(expectedIntentDigest, txSigningRequests);
        if (guardError) {
          confirmed = false;
          if (!error) error = guardError;
        }
      }

      if (!confirmed) {
        handle.update({
          errorMessage: error || '',
          loading: false,
        });
        finalize({ confirmed: false, error });
        return;
      }

      finalize({
        confirmed: true,
        ...(typeof detail?.otpCode === 'string' ? { otpCode: detail.otpCode } : {}),
        ...(typeof detail?.emailOtpChallengeId === 'string'
          ? { emailOtpChallengeId: detail.emailOtpChallengeId }
          : {}),
      });
    };

    const onCancel = (event?: Event) => {
      const detail = (event as CustomEvent<ConfirmEventDetail> | undefined)?.detail;
      const error = typeof detail?.error === 'string' ? detail.error : undefined;

      if (error) {
        handle.update({ errorMessage: error, loading: false });
      } else {
        handle.update({ loading: false });
      }

      finalize({ confirmed: false, error });
    };

    const onInteractive = () => {
      hostInteractiveMs = markDecisionWaitOffset(hostInteractiveMs);
    };

    const cleanup = () => {
      el.removeEventListener(
        WalletIframeDomEvents.TX_CONFIRMER_CONFIRM,
        onConfirm as EventListener,
      );
      el.removeEventListener(WalletIframeDomEvents.TX_CONFIRMER_CANCEL, onCancel as EventListener);
      el.removeEventListener(
        WalletIframeDomEvents.TX_CONFIRMER_INTERACTIVE,
        onInteractive as EventListener,
      );
    };

    el.addEventListener(WalletIframeDomEvents.TX_CONFIRMER_CONFIRM, onConfirm as EventListener);
    el.addEventListener(WalletIframeDomEvents.TX_CONFIRMER_CANCEL, onCancel as EventListener);
    el.addEventListener(
      WalletIframeDomEvents.TX_CONFIRMER_INTERACTIVE,
      onInteractive as EventListener,
    );
  });
}

function mountHostElement({
  ctx,
  summary,
  txSigningRequests,
  model,
  securityContext,
  loading,
  theme,
  appearance,
  variant,
  nearAccountIdOverride,
  signingAuthMode,
  emailOtpPrompt,
}: {
  ctx: ConfirmUIRenderContext;
  summary: TransactionSummary;
  txSigningRequests?: TransactionInputWasm[];
  model?: TxDisplayModel;
  securityContext?: Partial<UserConfirmSecurityContext>;
  loading?: boolean;
  theme?: ThemeMode;
  appearance?: AppearanceConfig;
  variant?: 'modal' | 'drawer';
  nearAccountIdOverride?: string;
  signingAuthMode?: SigningAuthMode;
  emailOtpPrompt?: EmailOtpConfirmPrompt;
}): { el: HostTxConfirmerElement; handle: MountedConfirmUIHandle } {
  const resolvedVariant: 'modal' | 'drawer' = variant || 'modal';
  cleanupExistingConfirmers();

  const element = document.createElement(W3A_TX_CONFIRMER_ID) as HostTxConfirmerElement;
  element.variant = resolvedVariant;
  element.nearAccountId =
    nearAccountIdOverride || ctx.userPreferencesManager.getCurrentWalletId() || '';
  element.txSigningRequests = txSigningRequests;
  element.model = model;

  if (ctx.nearExplorerUrl) {
    element.nearExplorerUrl = ctx.nearExplorerUrl;
  }
  if (ctx.tempoExplorerUrl) {
    element.tempoExplorerUrl = ctx.tempoExplorerUrl;
  }
  if (ctx.evmExplorerUrl) {
    element.evmExplorerUrl = ctx.evmExplorerUrl;
  }
  const explorerOverrides = resolveExplorerUrlsFromModel(ctx, model);
  if (explorerOverrides.nearExplorerUrl) {
    element.nearExplorerUrl = explorerOverrides.nearExplorerUrl;
  }
  if (explorerOverrides.tempoExplorerUrl) {
    element.tempoExplorerUrl = explorerOverrides.tempoExplorerUrl;
  }
  if (explorerOverrides.evmExplorerUrl) {
    element.evmExplorerUrl = explorerOverrides.evmExplorerUrl;
  }

  if ((txSigningRequests?.length || 0) > 0) {
    element.intentDigest = summary?.intentDigest;
  }

  if (securityContext) element.securityContext = securityContext;
  element.appearance = resolveAppearance({
    ctx,
    requestedAppearance: appearance,
    requestedMode: theme,
  });
  element.theme = element.appearance.theme.mode;
  if (loading != null) element.loading = !!loading;
  element.removeAttribute('data-error-message');
  element.deferClose = true;
  if (signingAuthMode) element.signingAuthMode = signingAuthMode;
  if (emailOtpPrompt) element.emailOtpPrompt = emailOtpPrompt;

  if (summary?.title != null) element.title = summary.title;
  if (summary?.body != null) element.body = summary.body;
  if (summary?.delegate && summary?.title == null) {
    element.title = 'Sign Delegate Action';
  }

  // Set the surface mode before connecting the custom element. The wallet
  // iframe host uses this attribute to hide provisional geometry; connecting
  // first lets a synchronous render paint the standalone/default surface for
  // one frame while the reporter is attached.
  applyConfirmSurfaceMode(element, ctx.surfaceMeasurementBinding);

  const portal = ensureConfirmPortal();
  portal.replaceChildren(element);
  updateConfirmPortalState(portal);

  bindConfirmSurfaceMeasurementReporter(element, ctx.surfaceMeasurementBinding);

  portal.classList.remove('w3a-portal--visible');
  requestAnimationFrame(() => {
    portal.classList.add('w3a-portal--visible');
  });

  postWalletUiMessage('WALLET_UI_OPENED');

  const handle = createHostConfirmHandle(ctx, element, postWalletUiClosedIfPortalEmpty);

  return { el: element, handle };
}

export type { TxConfirmerWrapperElement } from './lit-components/IframeTxConfirmer/tx-confirmer-wrapper';
export { W3A_TX_CONFIRMER_ID };
