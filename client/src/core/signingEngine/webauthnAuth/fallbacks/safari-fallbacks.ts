// Safari/WebAuthn fallbacks: centralized retry + top-level bridge
// - Encapsulates Safari-specific error handling (ancestor-origin, not-focused)
// - Bridges create/get to top-level via postMessage when needed
// - Keeps helpers private to reduce file count and surface area

import { secureRandomBase64Url } from '@shared/utils/secureRandomId';

type Kind = 'create' | 'get';

// Typed message names for parent-domain bridge
export const WebAuthnBridgeMessage = {
  Create: 'WALLET_WEBAUTHN_CREATE',
  Get: 'WALLET_WEBAUTHN_GET',
  CreateResult: 'WALLET_WEBAUTHN_CREATE_RESULT',
  GetResult: 'WALLET_WEBAUTHN_GET_RESULT',
} as const;

export type BridgeKind = typeof WebAuthnBridgeMessage.Create | typeof WebAuthnBridgeMessage.Get;
export type BridgeResultKind =
  | typeof WebAuthnBridgeMessage.CreateResult
  | typeof WebAuthnBridgeMessage.GetResult;

type ResultTypeFor<K extends BridgeKind> = K extends typeof WebAuthnBridgeMessage.Get
  ? typeof WebAuthnBridgeMessage.GetResult
  : typeof WebAuthnBridgeMessage.CreateResult;

function getResultTypeFor<K extends BridgeKind>(kind: K): ResultTypeFor<K> {
  return (
    kind === WebAuthnBridgeMessage.Get
      ? WebAuthnBridgeMessage.GetResult
      : WebAuthnBridgeMessage.CreateResult
  ) as ResultTypeFor<K>;
}

type BridgeOk = { ok: true; credential: unknown };
type BridgeErr = { ok: false; error?: string; timeout?: boolean };
type BridgeResponse = BridgeOk | BridgeErr;

type AnyPublicKeyOptions = PublicKeyCredentialCreationOptions | PublicKeyCredentialRequestOptions;

// Client interface used to request WebAuthn from the parent/top-level context
export type ParentDomainWebAuthnClient = {
  request<K extends BridgeKind>(
    kind: K,
    publicKey: AnyPublicKeyOptions,
    timeoutMs?: number,
  ): Promise<BridgeResponse>;
};

export interface OrchestratorDeps {
  rpId: string;
  inIframe: boolean;
  timeoutMs?: number;
  bridgeClient?: ParentDomainWebAuthnClient;
  // Gate for ancestor-error on GET; bridges for focus errors are always allowed when in iframe.
  permitGetBridgeOnAncestorError?: boolean;
  // Optional AbortSignal to cancel native navigator.credentials operations.
  // Note: parent-bridge path may not be abortable.
  abortSignal?: AbortSignal;
}

/**
 * Execute a WebAuthn operation with Safari-aware fallbacks.
 *
 * Steps:
 * 1) Try native WebAuthn via navigator.credentials.{create|get}
 * 2) If the failure matches Safari's ancestor-origin restriction and we are in an iframe,
 *    ask the parent/top-level window to perform the WebAuthn operation (bridge). If the
 *    parent reports a user cancellation, throw NotAllowedError; if it times out, continue.
 * 3) If the failure matches Safari's "document not focused" path, first attempt to refocus
 *    and retry native once; if still blocked and in an iframe, ask the parent window to handle it.
 * 4) Generic last resort: when in an iframe (constrained context), always attempt the parent
 *    WebAuthn once even if the error wasn't recognized as a Safari-specific case. If the parent
 *    path times out, surface a deterministic timeout error without re-trying native again.
 * 5) Otherwise, rethrow the original error.
 */
export async function executeWebAuthnWithParentFallbacksSafari(
  kind: Kind,
  publicKey: AnyPublicKeyOptions,
  deps: OrchestratorDeps,
): Promise<PublicKeyCredential | unknown> {
  const { inIframe, timeoutMs = 60000, permitGetBridgeOnAncestorError = true } = deps;
  const bridgeClient = deps.bridgeClient || new WindowParentDomainWebAuthnClient();

  const isTestForceNativeFail = (): boolean => {
    const g = globalThis as typeof globalThis & { __W3A_TEST_FORCE_NATIVE_FAIL?: unknown };
    const w =
      typeof window !== 'undefined'
        ? (window as Window & { __W3A_TEST_FORCE_NATIVE_FAIL?: unknown })
        : undefined;
    return !!g.__W3A_TEST_FORCE_NATIVE_FAIL || !!w?.__W3A_TEST_FORCE_NATIVE_FAIL;
  };
  const bumpCounter = (key: string) => {
    const g = globalThis as Record<string, unknown>;
    const current = typeof g[key] === 'number' ? (g[key] as number) : 0;
    g[key] = current + 1;
  };

  // Test harness fast-path: when explicitly forcing native fail, skip native and go straight to bridge.
  // Still bump native attempt counters for determinism in tests.
  if (isTestForceNativeFail()) {
    if (kind === 'create') bumpCounter('__W3A_TEST_NATIVE_CREATE_ATTEMPTS');
    else bumpCounter('__W3A_TEST_NATIVE_GET_ATTEMPTS');
    try {
      const bridged = await requestParentDomainWebAuthn(kind, publicKey, bridgeClient, timeoutMs);
      if (bridged?.ok) return bridged.credential;
      if (bridged && !bridged.timeout) {
        throw notAllowedError(bridged.error || 'WebAuthn cancelled or failed (bridge)');
      }
      throw new Error('WebAuthn bridge timeout');
    } catch (be: unknown) {
      // Ensure consistent error type for unit tests
      throw notAllowedError(safeMessage(be) || 'WebAuthn bridge failed');
    }
  }

  const tryNative = async () => {
    const publicKeyForAttempt = clonePublicKeyOptions(kind, publicKey);
    if (kind === 'create') {
      bumpCounter('__W3A_TEST_NATIVE_CREATE_ATTEMPTS');
      if (isTestForceNativeFail()) throw notAllowedError('Forced native fail (create)');
      // Build options with optional AbortSignal
      return await navigator.credentials.create({
        publicKey: publicKeyForAttempt as PublicKeyCredentialCreationOptions,
        ...(deps.abortSignal ? { signal: deps.abortSignal } : {}),
      });
    } else {
      bumpCounter('__W3A_TEST_NATIVE_GET_ATTEMPTS');
      if (isTestForceNativeFail()) throw notAllowedError('Forced native fail (get)');
      return await navigator.credentials.get({
        publicKey: publicKeyForAttempt as PublicKeyCredentialRequestOptions,
        ...(deps.abortSignal ? { signal: deps.abortSignal } : {}),
      });
    }
  };

  // Step 1: native attempt
  try {
    return await tryNative();
  } catch (e: unknown) {
    // If the user explicitly cancelled (generic NotAllowedError without Safari-specific hints),
    // do not attempt any bridge fallbacks that would re-prompt Touch ID. Propagate immediately.
    // This avoids double prompts when a user cancels the native sheet.
    const name = safeName(e);
    if (name === 'NotAllowedError' && !isAncestorOriginError(e) && !isDocumentNotFocusedError(e)) {
      throw e;
    }

    // Step 2: ancestor-origin restriction → parent bridge (when in iframe)
    if (isAncestorOriginError(e) && inIframe) {
      if (kind === 'get' && !permitGetBridgeOnAncestorError) {
        throw e;
      }
      try {
        const bridgedCredentials = await requestParentDomainWebAuthn(
          kind,
          publicKey,
          bridgeClient,
          timeoutMs,
        );
        if (bridgedCredentials?.ok) return bridgedCredentials.credential;
        if (bridgedCredentials && !bridgedCredentials.timeout) {
          throw notAllowedError(
            bridgedCredentials.error || 'WebAuthn get cancelled or failed (bridge)',
          );
        }
      } catch (be: unknown) {
        throw notAllowedError(safeMessage(be) || 'WebAuthn bridge failed');
      }
    }

    // Step 3: document-not-focused → refocus + retry native; then parent bridge if still blocked
    if (isDocumentNotFocusedError(e)) {
      const focused = await attemptRefocus();
      if (focused) {
        try {
          return await tryNative();
        } catch {}
      }
      if (inIframe) {
        try {
          const bridgedCredentials = await requestParentDomainWebAuthn(
            kind,
            publicKey,
            bridgeClient,
            timeoutMs,
          );
          if (bridgedCredentials?.ok) return bridgedCredentials.credential;
          if (bridgedCredentials && !bridgedCredentials.timeout) {
            throw notAllowedError(
              bridgedCredentials.error || 'WebAuthn get cancelled or failed (bridge)',
            );
          }
        } catch (be: unknown) {
          throw notAllowedError(safeMessage(be) || 'WebAuthn bridge failed');
        }
      }
    }

    // Step 4: generic last-resort bridge path for constrained iframe contexts
    if (inIframe) {
      try {
        const bridgedCredentials = await requestParentDomainWebAuthn(
          kind,
          publicKey,
          bridgeClient,
          timeoutMs,
        );
        if (bridgedCredentials?.ok) return bridgedCredentials.credential;
        if (bridgedCredentials && !bridgedCredentials.timeout) {
          throw notAllowedError(
            bridgedCredentials.error || 'WebAuthn cancelled or failed (bridge)',
          );
        }
        // Timeout: surface an explicit error without re‑trying native again
        throw new Error('WebAuthn bridge timeout');
      } catch (be: unknown) {
        throw notAllowedError(safeMessage(be) || 'WebAuthn bridge failed');
      }
    }

    // Step 5: not an iframe or no recognized fallback – rethrow original error
    throw e;
  }
}

// Request the parent/top-level window to perform the WebAuthn operation
export async function requestParentDomainWebAuthn(
  kind: Kind,
  publicKey: AnyPublicKeyOptions,
  client: ParentDomainWebAuthnClient,
  timeoutMs: number,
): Promise<BridgeResponse> {
  const publicKeyForBridge = clonePublicKeyOptions(kind, publicKey);
  if (kind === 'create') {
    return client.request(
      WebAuthnBridgeMessage.Create,
      publicKeyForBridge as PublicKeyCredentialCreationOptions,
      timeoutMs,
    );
  }
  return client.request(
    WebAuthnBridgeMessage.Get,
    publicKeyForBridge as PublicKeyCredentialRequestOptions,
    timeoutMs,
  );
}

// Default bridge client using window.parent postMessage protocol
export class WindowParentDomainWebAuthnClient implements ParentDomainWebAuthnClient {
  async request<K extends BridgeKind>(
    kind: K,
    publicKey: AnyPublicKeyOptions,
    timeoutMs = 60000,
  ): Promise<BridgeResponse> {
    const requestId = `${kind}:${Date.now()}:${secureRandomBase64Url(16, 'Safari WebAuthn bridge request IDs')}`;
    const resultType = getResultTypeFor(kind);

    return new Promise((resolve) => {
      let settled = false;
      const finish = (val: BridgeResponse) => {
        if (!settled) {
          settled = true;
          resolve(val);
        }
      };

      const onMessage = (ev: MessageEvent) => {
        const payload = ev?.data as unknown;
        if (!payload || typeof (payload as { type?: unknown }).type !== 'string') return;
        const t = (payload as { type: string }).type;
        if (t !== resultType) return;
        const rid = (payload as { requestId?: unknown }).requestId;
        if (rid !== requestId) return;
        window.removeEventListener('message', onMessage);
        const ok = !!(payload as { ok?: unknown }).ok;
        const cred = (payload as { credential?: unknown }).credential;
        const err = (payload as { error?: unknown }).error;
        if (ok && cred) return finish({ ok: true, credential: cred });
        return finish({ ok: false, error: typeof err === 'string' ? err : undefined });
      };
      window.addEventListener('message', onMessage);
      const envelope: {
        type: K;
        requestId: string;
        publicKey: PublicKeyCredentialCreationOptions | PublicKeyCredentialRequestOptions;
      } = { type: kind, requestId, publicKey };
      window.parent?.postMessage(envelope, '*');
      setTimeout(() => {
        window.removeEventListener('message', onMessage);
        finish({ ok: false, timeout: true });
      }, timeoutMs);
    });
  }
}

function clonePublicKeyOptions(kind: Kind, publicKey: AnyPublicKeyOptions): AnyPublicKeyOptions {
  return kind === 'create'
    ? cloneCreationOptions(publicKey as PublicKeyCredentialCreationOptions)
    : cloneRequestOptions(publicKey as PublicKeyCredentialRequestOptions);
}

function cloneCreationOptions(
  publicKey: PublicKeyCredentialCreationOptions,
): PublicKeyCredentialCreationOptions {
  return {
    ...publicKey,
    challenge: cloneBufferSource(publicKey.challenge),
    user: {
      ...publicKey.user,
      id: cloneBufferSource(publicKey.user.id),
    },
    excludeCredentials: publicKey.excludeCredentials?.map(cloneCredentialDescriptor),
    extensions: cloneCredentialExtensions(publicKey.extensions),
  };
}

function cloneRequestOptions(
  publicKey: PublicKeyCredentialRequestOptions,
): PublicKeyCredentialRequestOptions {
  return {
    ...publicKey,
    challenge: cloneBufferSource(publicKey.challenge),
    allowCredentials: publicKey.allowCredentials?.map(cloneCredentialDescriptor),
    extensions: cloneCredentialExtensions(publicKey.extensions),
  };
}

function cloneCredentialDescriptor(
  descriptor: PublicKeyCredentialDescriptor,
): PublicKeyCredentialDescriptor {
  return {
    ...descriptor,
    id: cloneBufferSource(descriptor.id),
  };
}

function cloneCredentialExtensions<T extends AuthenticationExtensionsClientInputs | undefined>(
  extensions: T,
): T {
  if (!extensions) return extensions;
  const cloned = { ...extensions } as Record<string, unknown>;
  const prf = cloned.prf;
  if (prf && typeof prf === 'object') {
    const prfRecord = { ...(prf as Record<string, unknown>) };
    if (prfRecord.eval && typeof prfRecord.eval === 'object') {
      prfRecord.eval = clonePrfEval(prfRecord.eval as Record<string, unknown>);
    }
    if (prfRecord.evalByCredential && typeof prfRecord.evalByCredential === 'object') {
      const evalByCredential: Record<string, unknown> = {};
      for (const [credentialId, evalValue] of Object.entries(
        prfRecord.evalByCredential as Record<string, unknown>,
      )) {
        evalByCredential[credentialId] =
          evalValue && typeof evalValue === 'object'
            ? clonePrfEval(evalValue as Record<string, unknown>)
            : evalValue;
      }
      prfRecord.evalByCredential = evalByCredential;
    }
    cloned.prf = prfRecord;
  }
  return cloned as T;
}

function clonePrfEval(input: Record<string, unknown>): Record<string, unknown> {
  return {
    ...input,
    ...(isBufferSource(input.first) ? { first: cloneBufferSource(input.first) } : {}),
    ...(isBufferSource(input.second) ? { second: cloneBufferSource(input.second) } : {}),
  };
}

function isBufferSource(value: unknown): value is BufferSource {
  return value instanceof ArrayBuffer || ArrayBuffer.isView(value);
}

function cloneBufferSource<T extends BufferSource>(value: T): T {
  if (value instanceof ArrayBuffer) {
    return value.slice(0) as T;
  }
  const view = value as ArrayBufferView;
  const bytes = new Uint8Array(view.buffer, view.byteOffset, view.byteLength);
  const clonedBytes = bytes.slice();
  if (value instanceof DataView) {
    return new DataView(clonedBytes.buffer) as unknown as T;
  }
  const ViewCtor = Object.getPrototypeOf(value).constructor as new (
    buffer: ArrayBuffer,
  ) => ArrayBufferView;
  return new ViewCtor(clonedBytes.buffer) as unknown as T;
}

function notAllowedError(message: string): Error {
  const e = new Error(message);
  Object.defineProperty(e, 'name', { value: 'NotAllowedError', configurable: true });
  return e;
}

// Private: error classification helpers
function isAncestorOriginError(err: unknown): boolean {
  const msg = safeMessage(err);
  return /origin of the document is not the same as its ancestors/i.test(msg);
}

function isDocumentNotFocusedError(err: unknown): boolean {
  const name = safeName(err);
  const msg = safeMessage(err);
  const isNotAllowed = name === 'NotAllowedError';
  const mentionsFocus = /document is not focused|not focused|focus/i.test(msg);
  return Boolean(isNotAllowed && mentionsFocus);
}

function safeMessage(err: unknown): string {
  return String((err as { message?: unknown })?.message || '');
}

function safeName(err: unknown): string {
  const n = (err as { name?: unknown })?.name;
  return typeof n === 'string' ? n : '';
}

// Private: focus utility to mitigate Safari focus issues
async function attemptRefocus(maxRetries = 2, delays: number[] = [50, 120]): Promise<boolean> {
  window.focus?.();
  if (document?.body) {
    document.body.focus?.();
  }

  const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));
  const total = Math.max(0, maxRetries);
  for (let i = 0; i <= total; i++) {
    const d = delays[i] ?? delays[delays.length - 1] ?? 80;
    await wait(d);
    if (document.hasFocus()) return true;
    window.focus?.();
  }
  return document.hasFocus();
}
