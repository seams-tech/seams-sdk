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

import type { UiConfirmContext } from '../uiConfirm.types';
import type { TransactionSummary } from '@/core/signingEngine/stepUpConfirmation/channel/confirmTypes';
import type { EmailOtpConfirmPrompt, SigningAuthMode } from '../../stepUpConfirmation/types';
import type {
  ConfirmUIHandle,
  ConfirmUIPromptDiagnostics,
  ConfirmUIUpdate,
  ConfirmationUIMode,
} from './confirm-ui-types';
import {
  CONFIRM_UI_ELEMENT_SELECTORS,
  W3A_CONFIRM_PORTAL_ID,
  W3A_TX_CONFIRMER_ID,
  ensureDefined,
} from './registry';

export type {
  ConfirmUIHandle,
  ConfirmUIPromptDiagnostics,
  ConfirmUIUpdate,
  ConfirmationUIMode,
} from './confirm-ui-types';

const CONFIRM_STACK_CSS_VAR = '--w3a-confirm-stack-index';
const MAX_STACK_DEPTH = 4;

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

async function ensureTxConfirmerElementDefined(): Promise<void> {
  await ensureDefined(
    W3A_TX_CONFIRMER_ID,
    () => import('./lit-components/IframeTxConfirmer/tx-confirmer-wrapper'),
  );
}

export async function prewarmTxConfirmerUi(): Promise<void> {
  await ensureTxConfirmerElementDefined();
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
  ctx: UiConfirmContext;
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
  const children = Array.from(portal.children) as HTMLElement[];
  const total = children.length;

  // Topmost (last child) is depth=0; older/pending confirmers are offset progressively.
  for (let i = 0; i < total; i++) {
    const child = children[i];
    const depth = Math.min(total - 1 - i, MAX_STACK_DEPTH);
    try {
      child.style.setProperty(CONFIRM_STACK_CSS_VAR, String(depth));
    } catch {}
  }

  if (total > 0) {
    portal.classList.add('w3a-portal--visible');
  } else {
    portal.classList.remove('w3a-portal--visible');
  }
}

function cleanupExistingConfirmers(): void {
  const portal = document.getElementById(W3A_CONFIRM_PORTAL_ID);
  if (portal) {
    // Concurrent requests intentionally stack confirmers in the same portal.
    // Avoid auto-cancelling in-flight confirm UIs here.
    return;
  }

  const selectors = CONFIRM_UI_ELEMENT_SELECTORS as readonly string[];
  const elements = selectors.flatMap(
    (selector) => Array.from(document.querySelectorAll(selector)) as HTMLElement[],
  );

  for (const element of elements) {
    element.dispatchEvent(
      new CustomEvent(WalletIframeDomEvents.TX_CONFIRMER_CANCEL, { bubbles: true, composed: true }),
    );
    element.remove();
  }
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
  element.remove();
  const portal = document.getElementById(W3A_CONFIRM_PORTAL_ID) as HTMLElement | null;
  if (portal) updateConfirmPortalState(portal);
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
  ctx: UiConfirmContext,
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
  ctx: UiConfirmContext,
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

function createHostConfirmHandle(
  ctx: UiConfirmContext,
  element: HostTxConfirmerElement,
  onClose: () => void,
): ConfirmUIHandle {
  let closed = false;
  return {
    close: (confirmed: boolean) => {
      if (closed) return;
      closed = true;
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
  ctx: UiConfirmContext;
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
}): Promise<ConfirmUIHandle> {
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
}: {
  ctx: UiConfirmContext;
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
    const { el, handle } = mountHostElement({
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
    });
    const mountMs = roundConfirmUiDurationMs(mountStartedAt);
    const decisionWaitStartedAt = performance.now();
    let hostFirstUpdateMs = 0;
    let hostInteractiveMs = 0;
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
  ctx: UiConfirmContext;
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
}): { el: HostTxConfirmerElement; handle: ConfirmUIHandle } {
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

  const portal = ensureConfirmPortal();
  const wasEmpty = portal.childElementCount === 0;
  portal.insertBefore(element, portal.firstChild);
  updateConfirmPortalState(portal);

  if (wasEmpty) {
    portal.classList.remove('w3a-portal--visible');
    requestAnimationFrame(() => {
      portal.classList.add('w3a-portal--visible');
    });
  }

  postWalletUiMessage('WALLET_UI_OPENED');

  const handle = createHostConfirmHandle(ctx, element, () =>
    postWalletUiMessage('WALLET_UI_CLOSED'),
  );

  return { el: element, handle };
}

export type { TxConfirmerWrapperElement } from './lit-components/IframeTxConfirmer/tx-confirmer-wrapper';
export { W3A_TX_CONFIRMER_ID };
