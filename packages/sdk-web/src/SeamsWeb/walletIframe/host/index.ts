import { bootstrapTransparentHost } from './bootstrap';
import type {
  ChildToParentEnvelope,
  ParentToChildEnvelope,
  PMSetConfigPayload,
} from '../shared/messages';
import { WALLET_PROTOCOL_VERSION } from '../shared/messages';
import type { SeamsConfigsInput } from '@/core/types/seams';
import { WalletIframeDomEvents } from '@/core/browser/walletIframe/events';
import { isObject } from '@shared/utils/validation';
import { errorMessage } from '@shared/utils/errors';
import type { WalletHostRuntimeState } from './runtimeContext';
import {
  loadWalletHostRuntime,
  preloadWalletHostRegistrationSurface,
} from './runtimeLoader';
import {
  type RuntimeWalletHostRoute,
  routeRequiresRuntime,
  routeWalletHostRequest,
} from './requestRouter';

let initialized = false;

const CONFIRM_UI_SELECTORS = [
  'w3a-modal-tx-confirmer',
  'w3a-drawer-tx-confirmer',
  'w3a-tx-confirmer',
  'w3a-export-key-viewer',
  '[data-w3a-email-otp-recovery-code-dialog]',
] as const;

export type WalletHostRuntimeKind = RuntimeWalletHostRoute['kind'];

export type WalletHostEntryOptions = {
  supportedRuntimeRouteKinds?: ReadonlySet<WalletHostRuntimeKind>;
};

function routeIsSupported(
  route: RuntimeWalletHostRoute,
  supported: ReadonlySet<WalletHostRuntimeKind> | undefined,
): boolean {
  return !supported || supported.has(route.kind);
}

function registrationRuntimeIsSupported(
  supported: ReadonlySet<WalletHostRuntimeKind> | undefined,
): boolean {
  return !supported || supported.has('near');
}

export function initWalletIFrame(options: WalletHostEntryOptions = {}): void {
  if (initialized) return;
  initialized = true;

  bootstrapTransparentHost();

  const cancelledRequests = new Set<string>();
  const state: WalletHostRuntimeState = {
    parentOrigin: null,
    port: null,
    walletConfigs: null,
  };

  const post = (msg: ChildToParentEnvelope): void => {
    try {
      state.port?.postMessage(msg);
    } catch {}
  };

  const postToParent = (message: unknown): void => {
    const parentWindow = window.parent;
    if (!parentWindow) return;
    const target = state.parentOrigin && state.parentOrigin !== 'null' ? state.parentOrigin : '*';
    try {
      parentWindow.postMessage(message, target);
    } catch {}
  };

  const markCancelled = (rid?: string): void => {
    if (rid) cancelledRequests.add(rid);
  };
  const isCancelled = (rid?: string): boolean => !!rid && cancelledRequests.has(rid);
  const clearCancelled = (rid?: string): void => {
    if (rid) cancelledRequests.delete(rid);
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

  const cancelOpenConfirmers = (): void => {
    const els = CONFIRM_UI_SELECTORS.flatMap(
      (selector) => Array.from(document.querySelectorAll(selector)) as HTMLElement[],
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
      const recoveryCodeCloseButton = el.querySelector<HTMLButtonElement>(
        '[data-w3a-email-otp-recovery-code-dialog-close]',
      );
      recoveryCodeCloseButton?.click();
    }
  };

  const onPortMessage = async (e: MessageEvent<ParentToChildEnvelope>) => {
    const req = e.data as ParentToChildEnvelope;
    if (!req || !isObject(req)) return;
    const requestId = req.requestId;

    try {
      const route = routeWalletHostRequest(req);

      if (!routeRequiresRuntime(route)) {
        switch (route.type) {
          case 'PING':
            post({ type: 'PONG', requestId });
            return;
          case 'PM_SET_CONFIG':
            state.walletConfigs = {
              ...(state.walletConfigs || ({} as SeamsConfigsInput)),
              ...(route.request.payload as PMSetConfigPayload),
            } as SeamsConfigsInput;
            if (registrationRuntimeIsSupported(options.supportedRuntimeRouteKinds)) {
              await preloadWalletHostRegistrationSurface();
            }
            post({ type: 'PONG', requestId });
            return;
          case 'PM_CANCEL': {
            const rid = (route.request.payload as { requestId?: string } | undefined)?.requestId;
            markCancelled(rid);
            cancelOpenConfirmers();
            if (rid) emitCancellationPayload(rid);
            post({ type: 'PONG', requestId });
            return;
          }
        }
      }

      if (!routeIsSupported(route, options.supportedRuntimeRouteKinds)) {
        post({
          type: 'ERROR',
          requestId,
          payload: {
            code: 'unsupported_request',
            message: `Unsupported wallet iframe request type: ${route.type}`,
          },
        });
        return;
      }

      const runtime = await loadWalletHostRuntime(route);
      await runtime.handleWalletHostRuntimeRequest({
        state,
        req: route.request,
        post,
        postToParent,
        isCancelled,
        respondIfCancelled,
      });
    } catch (err: unknown) {
      const canonicalSignerErrors = await import('./canonicalSignerErrorCode');
      const codeRaw =
        err && typeof err === 'object' && 'code' in err
          ? (err as { code?: unknown }).code
          : undefined;
      const detailsRaw =
        err && typeof err === 'object' && 'details' in err
          ? (err as { details?: unknown }).details
          : undefined;
      const message = errorMessage(err);
      const code = canonicalSignerErrors.resolveWalletBoundaryErrorCode({
        requestType: req.type,
        rawCode: codeRaw,
        message,
        defaultCode: 'HOST_ERROR',
      });
      const canonicalMessage = canonicalSignerErrors.resolveWalletBoundaryErrorMessage({
        requestType: req.type,
        rawCode: codeRaw,
        code,
        message,
      });
      const details =
        detailsRaw && typeof detailsRaw === 'object'
          ? (detailsRaw as Record<string, unknown>)
          : undefined;
      const signerKind = canonicalSignerErrors.resolveWalletBoundarySignerKind({
        requestType: req.type,
        details,
      });
      post({
        type: 'ERROR',
        requestId,
        payload: {
          code,
          message: canonicalMessage,
          ...(canonicalSignerErrors.isWalletSignerBoundaryRequestType(req.type) &&
          canonicalSignerErrors.isCanonicalSignerSessionBoundaryCode(code) &&
          signerKind
            ? { signerKind }
            : {}),
        },
      });
    }
  };

  const onWindowMessage = (e: MessageEvent): void => {
    const { data, ports } = e as MessageEvent & { ports?: MessagePort[] };
    if (!data || typeof data !== 'object') return;
    if ((data as { type?: unknown }).type !== 'CONNECT' || !ports?.[0] || state.port) return;
    try {
      if ((e as MessageEvent).source !== window.parent) return;
    } catch {}
    if (typeof e.origin === 'string' && e.origin.length && e.origin !== 'null') {
      state.parentOrigin = e.origin;
    }
    state.port = ports[0];
    try {
      state.port.onmessage = (ev) => onPortMessage(ev as MessageEvent<ParentToChildEnvelope>);
      state.port.start?.();
    } catch {}
    post({ type: 'READY', payload: { protocolVersion: WALLET_PROTOCOL_VERSION } });
  };

  window.addEventListener('message', onWindowMessage);
}

try {
  initWalletIFrame();
} catch (e) {
  console.error('[WalletHost] init failed', e);
}
