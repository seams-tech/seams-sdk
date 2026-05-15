/**
 * Host entry helpers for the wallet iframe.
 *
 * Boot sequence (high-level):
 * 1) `initWalletIFrame()` runs early bootstrap defaults for the iframe document.
 * 2) A host context is created for wallet config + MessagePort state.
 * 3) The Lit UI mounter is registered for WALLET_UI_* messages.
 * 4) PM_* handlers are wired and CONNECT/READY listeners are attached.
 */
import { bootstrapTransparentHost } from './bootstrap';

import type {
  ParentToChildEnvelope,
  ParentToChildType,
  ChildToParentEnvelope,
  ReadyPayload,
  PMSetConfigPayload,
  PreferencesChangedPayload,
  ProgressPayload,
} from '../shared/messages';
import { CONFIRM_UI_ELEMENT_SELECTORS } from '../../signingEngine/uiConfirm/ui/registry';
import { setupLitElemMounter } from './lit-ui/iframe-lit-elem-mounter';
import type { SeamsConfigsInput } from '../../types/seams';
import { isObject } from '@shared/utils/validation';
import { errorMessage } from '@shared/utils/errors';
import { SeamsPasskey } from '../../SeamsPasskey';
import { WalletIframeDomEvents } from '../events';
// handlers moved to dedicated module; host no longer imports per-call hook types
import { createWalletIframeHandlers } from './wallet-iframe-handlers';
import { applyWalletConfig, createHostContext, ensurePasskeyManager } from './context';
import {
  addHostListeners,
  post as postMessage,
  postToParent as postToParentMessage,
} from './messaging';
import {
  isWalletSignerBoundaryRequestType,
  isCanonicalSignerSessionBoundaryCode,
  resolveWalletBoundarySignerKind,
  resolveWalletBoundaryErrorCode,
  resolveWalletBoundaryErrorMessage,
} from './canonicalSignerErrorCode';
import { resolvePrimaryNearRpcUrl } from '../../config/chains';

const PROTOCOL: ReadyPayload['protocolVersion'] = '1.0.0';
let initialized = false;

export function initWalletIFrame(): void {
  if (initialized) return;
  initialized = true;

  // Early bootstrap (transparent surface, env shims, default asset base, telemetry)
  bootstrapTransparentHost();

  const ctx = createHostContext();

  // Track request-level cancellations
  const cancelledRequests = new Set<string>();
  const markCancelled = (rid?: string) => {
    if (rid) cancelledRequests.add(rid);
  };
  const isCancelled = (rid?: string) => !!rid && cancelledRequests.has(rid);
  const clearCancelled = (rid?: string) => {
    if (rid) cancelledRequests.delete(rid);
  };

  const post = (msg: ChildToParentEnvelope): void => {
    postMessage(ctx, msg);
  };

  const postToParent = (message: unknown): void => {
    postToParentMessage(ctx, message);
  };

  const postProgress = (requestId: string | undefined, payload: ProgressPayload): void => {
    if (!requestId) return;
    post({ type: 'PROGRESS', requestId, payload });
  };

  const emitCancellationPayload = (requestId: string | undefined): void => {
    if (!requestId) return;
    post({
      type: 'ERROR',
      requestId,
      payload: { code: 'cancelled', message: 'Request cancelled' },
    });
  };

  const respondIfCancelled = (requestId: string | undefined): boolean => {
    if (!requestId || !isCancelled(requestId)) return false;
    emitCancellationPayload(requestId);
    clearCancelled(requestId);
    return true;
  };

  const ensureSeamsPasskey = (): SeamsPasskey => {
    const prev = ctx.seamsPasskey;
    const pm = ensurePasskeyManager(ctx) as SeamsPasskey;
    if (prev !== pm) {
      const up = pm.preferences;

      // Bridge wallet-host preferences to the parent app so app UI can mirror wallet host state.
      ctx.prefsUnsubscribe?.();
      const emitPreferencesChanged = () => {
        const id = String(up.getCurrentWalletId?.() || '').trim();
        const walletId = id ? id : null;
        post({
          type: 'PREFERENCES_CHANGED',
          payload: {
            walletId,
            confirmationConfig: up.getConfirmationConfig(),
            updatedAt: Date.now(),
          } satisfies PreferencesChangedPayload,
        });
      };
      const unsubCfg = up.onConfirmationConfigChange?.(() => emitPreferencesChanged()) || null;
      const unsubCurrentWallet = up.onCurrentWalletChange?.(() => emitPreferencesChanged()) || null;
      ctx.prefsUnsubscribe = () => {
        try {
          unsubCfg?.();
        } catch {}
        try {
          unsubCurrentWallet?.();
        } catch {}
      };
      // Emit a best-effort snapshot as soon as the host is ready.
      Promise.resolve()
        .then(() => emitPreferencesChanged())
        .catch(() => {});
    }
    return pm;
  };

  const getSeamsPasskey = (): SeamsPasskey => ensureSeamsPasskey();

  // Unified handler map wired with minimal deps from this host
  const handlers = createWalletIframeHandlers({
    getSeamsPasskey: getSeamsPasskey,
    post,
    postProgress,
    postToParent,
    isCancelled,
    respondIfCancelled,
  });

  // Lightweight cross-origin control channel for small embedded UI surfaces (e.g., tx button).
  // This channel uses window.postMessage directly (not MessagePort) so that a standalone
  // iframe can instruct this host to render a clickable control that performs WebAuthn
  // operations within the same browsing context (satisfying user activation requirements).
  setupLitElemMounter({
    ensureSeamsPasskey: ensureSeamsPasskey,
    getSeamsPasskey: () => ctx.seamsPasskey,
    updateWalletConfigs: (patch) => {
      ctx.walletConfigs = {
        ...(ctx.walletConfigs || ({} as SeamsConfigsInput)),
        ...patch,
      } as SeamsConfigsInput;
    },
    postToParent,
  });

  /**
   * Main message handler for iframe communication
   * This function receives all messages from the parent application and routes them
   * to the appropriate SeamsPasskey operations.
   */
  const onPortMessage = async (e: MessageEvent<ParentToChildEnvelope>) => {
    const req = e.data as ParentToChildEnvelope;
    if (!req || !isObject(req)) return;
    const requestId = req.requestId;

    // Handle ping/pong for connection health checks
    if (req.type === 'PING') {
      // Initialize SeamsPasskey and prewarm workers on wallet origin (non-blocking)
      let canInitOnPing = false;
      try {
        canInitOnPing =
          !!ctx.walletConfigs?.relayerAccount &&
          !!resolvePrimaryNearRpcUrl(ctx.walletConfigs?.chains || []);
      } catch {
        canInitOnPing = false;
      }
      if (canInitOnPing) {
        Promise.resolve()
          .then(() => {
            const pm = ensureSeamsPasskey();
            return pm.initWalletIframe();
          })
          .catch(() => {});
      }
      post({ type: 'PONG', requestId });
      return;
    }

    // Handle configuration updates from parent
    if (req.type === 'PM_SET_CONFIG') {
      const payload = req.payload as PMSetConfigPayload;
      applyWalletConfig(ctx, payload);
      post({ type: 'PONG', requestId });
      return;
    }

    if (req.type === 'PM_CANCEL') {
      // Best-effort cancel: mark requestId and close any open modal inside the wallet host
      const rid = req.payload?.requestId;
      markCancelled(rid);
      // Cover all possible confirmation hosts used inside the wallet iframe
      const els = (CONFIRM_UI_ELEMENT_SELECTORS as readonly string[]).flatMap(
        (sel) => Array.from(document.querySelectorAll(sel)) as HTMLElement[],
      );
      for (const el of els) {
        try {
          el.dispatchEvent(
            new CustomEvent(WalletIframeDomEvents.TX_CONFIRMER_CANCEL, {
              bubbles: true,
              composed: true,
            }),
          );
        } catch {}
      }
      if (rid) {
        // Immediately emit a terminal cancellation for the original request.
        // Handlers may also emit their own cancelled error; router tolerates duplicates.
        emitCancellationPayload(rid);
      }
      post({ type: 'PONG', requestId });
      return;
    }

    try {
      // Widen handler type for dynamic dispatch. HandlerMap is strongly typed at creation,
      // but when indexing with a runtime key, TS cannot correlate the specific envelope type.
      const handler = handlers[req.type as ParentToChildType] as unknown as (
        r: ParentToChildEnvelope,
      ) => Promise<void>;
      if (handler) {
        await handler(req);
      }
    } catch (err: unknown) {
      const codeRaw =
        err && typeof err === 'object' && 'code' in err
          ? (err as { code?: unknown }).code
          : undefined;
      const detailsRaw =
        err && typeof err === 'object' && 'details' in err
          ? (err as { details?: unknown }).details
          : undefined;
      const message = errorMessage(err);
      const code = resolveWalletBoundaryErrorCode({
        requestType: req.type,
        rawCode: codeRaw,
        message,
        defaultCode: 'HOST_ERROR',
      });
      const canonicalMessage = resolveWalletBoundaryErrorMessage({
        requestType: req.type,
        rawCode: codeRaw,
        code,
        message,
      });
      if (isCanonicalSignerSessionBoundaryCode(code)) {
        try {
          console.error('[WalletIframeHost] signer boundary normalized to session failure', {
            requestType: req.type,
            normalizedCode: code,
            rawCode: String(codeRaw || ''),
            rawMessage: String(message || ''),
          });
        } catch {}
      }
      if (code === 'cancelled') {
        clearCancelled(requestId);
      }
      const details = (() => {
        const isSignerBoundary = isWalletSignerBoundaryRequestType(req.type);
        const rawCodeText = String(codeRaw || '').trim();
        const rawMessageText = String(message || '').trim();
        const signerKind = isSignerBoundary ? resolveWalletBoundarySignerKind(req.type) : null;
        const sessionFailureDetails = isCanonicalSignerSessionBoundaryCode(code)
          ? {
              sessionFailureCode: String(code || '').trim(),
              sessionFailureKind:
                String(code || '').trim() === 'threshold_session_kind_mismatch'
                  ? ('kind_mismatch' as const)
                  : ('not_ready' as const),
              ...(signerKind ? { signerKind } : {}),
            }
          : null;
        if (!isSignerBoundary) return detailsRaw;
        if (detailsRaw && typeof detailsRaw === 'object' && !Array.isArray(detailsRaw)) {
          return {
            ...(detailsRaw as Record<string, unknown>),
            ...(sessionFailureDetails || {}),
            ...(rawCodeText ? { rawCode: rawCodeText } : {}),
            ...(rawMessageText ? { rawMessage: rawMessageText } : {}),
          };
        }
        if (detailsRaw !== undefined) {
          return {
            details: detailsRaw,
            ...(sessionFailureDetails || {}),
            ...(rawCodeText ? { rawCode: rawCodeText } : {}),
            ...(rawMessageText ? { rawMessage: rawMessageText } : {}),
          };
        }
        if (!rawCodeText && !rawMessageText) return undefined;
        return {
          ...(sessionFailureDetails || {}),
          ...(rawCodeText ? { rawCode: rawCodeText } : {}),
          ...(rawMessageText ? { rawMessage: rawMessageText } : {}),
        };
      })();
      post({
        type: 'ERROR',
        requestId,
        payload: {
          code,
          message: canonicalMessage,
          ...(details !== undefined ? { details } : {}),
        },
      });
    }
  };

  addHostListeners(ctx, onPortMessage, PROTOCOL);
}

// Auto-init when this module is the entry bundle.
initWalletIFrame();
