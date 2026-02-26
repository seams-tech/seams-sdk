import { WalletIframeDomEvents } from '@/core/WalletIframe/events';
import { __isWalletIframeHostMode } from '@/core/WalletIframe/host-mode';
import type { UserConfirmSecurityContext, TransactionInputWasm } from '@/core/types';
import {
  isActionArgsWasm,
  toActionArgsWasm,
  type ActionArgs,
  type ActionArgsWasm,
} from '@/core/types/actions';
import { resolveExplorerUrlForChainFamily } from '@/core/config/chains';
import type { TxDisplayModel } from '@/core/signingEngine/touchConfirm/shared/displayModel';
import { computeUiIntentDigestFromTxs, orderActionForDigest } from '@/utils/intentDigest';

import type { TouchConfirmContext } from '..';
import type { TransactionSummary } from '../shared/confirmTypes';
import type {
  ConfirmUIHandle,
  ConfirmUIUpdate,
  ConfirmationUIMode,
  ThemeName,
} from './confirm-ui-types';
import { coerceThemeName } from '@shared/utils/theme';
import {
  CONFIRM_UI_ELEMENT_SELECTORS,
  W3A_CONFIRM_PORTAL_ID,
  W3A_TX_CONFIRMER_ID,
  ensureDefined,
} from './registry';

export type { ConfirmUIHandle, ConfirmUIUpdate, ConfirmationUIMode } from './confirm-ui-types';

const CONFIRM_STACK_CSS_VAR = '--w3a-confirm-stack-index';
const MAX_STACK_DEPTH = 4;

type ConfirmEventDetail = {
  confirmed?: boolean;
  error?: string;
};

interface HostTxConfirmerElement extends HTMLElement {
  variant?: 'modal' | 'drawer';
  nearAccountId: string;
  txSigningRequests?: TransactionInputWasm[];
  model?: TxDisplayModel;
  intentDigest?: string;
  securityContext?: Partial<UserConfirmSecurityContext>;
  theme?: ThemeName;
  loading?: boolean;
  deferClose?: boolean;
  errorMessage?: string;
  body?: string;
  title: string;
  requestUpdate?: () => void;
  nearExplorerUrl?: string;
  tempoExplorerUrl?: string;
  evmExplorerUrl?: string;
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

function resolveTheme(_ctx: TouchConfirmContext, requested?: ThemeName): ThemeName {
  return coerceThemeName(requested) || 'dark';
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

function setErrorAttribute(element: HTMLElement, message: string): void {
  if (message) {
    element.setAttribute('data-error-message', message);
  } else {
    element.removeAttribute('data-error-message');
  }
}

function resolveExplorerUrlsFromModel(
  ctx: TouchConfirmContext,
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
  ctx: TouchConfirmContext,
  element: HostTxConfirmerElement,
  props?: ConfirmUIUpdate,
): void {
  if (!props) return;

  const update = props as ConfirmUIInternalUpdate;

  if (update.nearAccountId != null) element.nearAccountId = update.nearAccountId;
  if (Object.prototype.hasOwnProperty.call(update, 'model')) element.model = update.model;
  if (update.securityContext != null) element.securityContext = update.securityContext;
  if (update.theme != null) element.theme = update.theme;
  if (update.loading != null) element.loading = !!update.loading;
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
  ctx: TouchConfirmContext,
  element: HostTxConfirmerElement,
  onClose: () => void,
): ConfirmUIHandle {
  return {
    close: (confirmed: boolean) => {
      try {
        // If closed programmatically before a user decision was emitted, dispatch a cancel
        // so awaiters can resolve and clean up listeners.
        if (!confirmed) {
          element.dispatchEvent(
            new CustomEvent(WalletIframeDomEvents.TX_CONFIRMER_CANCEL, {
              detail: { confirmed: false },
              bubbles: true,
              composed: true,
            }),
          );
        }
        removeHostConfirmerElement(element);
      } finally {
        onClose();
      }
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
  uiMode,
  nearAccountIdOverride,
}: {
  ctx: TouchConfirmContext;
  summary: TransactionSummary;
  txSigningRequests?: TransactionInputWasm[];
  model?: TxDisplayModel;
  securityContext?: Partial<UserConfirmSecurityContext>;
  loading?: boolean;
  theme?: ThemeName;
  uiMode: ConfirmationUIMode;
  nearAccountIdOverride?: string;
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
    variant,
    nearAccountIdOverride,
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
  uiMode,
  nearAccountIdOverride,
  onMounted,
}: {
  ctx: TouchConfirmContext;
  summary: TransactionSummary;
  txSigningRequests: TransactionInputWasm[];
  model?: TxDisplayModel;
  securityContext?: Partial<UserConfirmSecurityContext>;
  loading?: boolean;
  theme: ThemeName;
  uiMode: ConfirmationUIMode;
  nearAccountIdOverride: string;
  onMounted?: (handle: ConfirmUIHandle) => void;
}): Promise<{ confirmed: boolean; handle: ConfirmUIHandle; error?: string }> {
  await ensureTxConfirmerElementDefined();

  const variant = uiModeToVariant(uiMode);
  const resolvedVariant: 'modal' | 'drawer' = variant || 'modal';

  return new Promise((resolve) => {
    const { el, handle } = mountHostElement({
      ctx,
      summary,
      txSigningRequests,
      model,
      securityContext,
      loading,
      theme,
      variant: resolvedVariant,
      nearAccountIdOverride,
    });

    try {
      onMounted?.(handle);
    } catch {}

    const finalize = (result: { confirmed: boolean; error?: string }) => {
      cleanup();
      resolve({ ...result, handle });
    };

    const onConfirm = async (event: Event) => {
      const detail = (event as CustomEvent<ConfirmEventDetail> | undefined)?.detail;
      let confirmed = detail?.confirmed !== false;
      let error = typeof detail?.error === 'string' ? detail.error : undefined;

      if (confirmed) {
        const guardError = await checkIntentDigestGuard(summary?.intentDigest, txSigningRequests);
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

      finalize({ confirmed: true });
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

    const cleanup = () => {
      el.removeEventListener(
        WalletIframeDomEvents.TX_CONFIRMER_CONFIRM,
        onConfirm as EventListener,
      );
      el.removeEventListener(WalletIframeDomEvents.TX_CONFIRMER_CANCEL, onCancel as EventListener);
    };

    el.addEventListener(WalletIframeDomEvents.TX_CONFIRMER_CONFIRM, onConfirm as EventListener);
    el.addEventListener(WalletIframeDomEvents.TX_CONFIRMER_CANCEL, onCancel as EventListener);
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
  variant,
  nearAccountIdOverride,
}: {
  ctx: TouchConfirmContext;
  summary: TransactionSummary;
  txSigningRequests?: TransactionInputWasm[];
  model?: TxDisplayModel;
  securityContext?: Partial<UserConfirmSecurityContext>;
  loading?: boolean;
  theme?: ThemeName;
  variant?: 'modal' | 'drawer';
  nearAccountIdOverride?: string;
}): { el: HostTxConfirmerElement; handle: ConfirmUIHandle } {
  const resolvedVariant: 'modal' | 'drawer' = variant || 'modal';
  cleanupExistingConfirmers();

  const element = document.createElement(W3A_TX_CONFIRMER_ID) as HostTxConfirmerElement;
  element.variant = resolvedVariant;
  element.nearAccountId =
    nearAccountIdOverride || ctx.userPreferencesManager.getCurrentUserAccountId() || '';
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
  element.theme = resolveTheme(ctx, theme);
  if (loading != null) element.loading = !!loading;
  element.removeAttribute('data-error-message');
  element.deferClose = true;

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
