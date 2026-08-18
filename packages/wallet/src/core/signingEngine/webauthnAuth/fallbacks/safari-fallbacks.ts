// Safari/WebAuthn fallbacks: wallet-origin registration and GET-only parent bridging.

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

interface OrchestratorDepsBase {
  rpId: string;
  inIframe: boolean;
  timeoutMs?: number;
  bridgeClient?: ParentDomainWebAuthnClient;
  // Optional AbortSignal to cancel native navigator.credentials operations.
  // Note: parent-bridge path may not be abortable.
  abortSignal?: AbortSignal;
}

export type RegistrationOrchestratorDeps = OrchestratorDepsBase & {
  registrationOriginPolicy: 'wallet_origin_only';
};

export type AuthenticationOrchestratorDeps = OrchestratorDepsBase & {
  registrationOriginPolicy?: never;
};

export class WalletOriginWebAuthnUnavailableError extends Error {
  readonly code = 'wallet_origin_webauthn_unavailable';

  constructor(message: string) {
    super(message);
    this.name = 'WalletOriginWebAuthnUnavailableError';
  }
}

/** Execute WebAuthn once on the wallet origin. */
export function executeWebAuthnWithParentFallbacksSafari(
  kind: 'create',
  publicKey: PublicKeyCredentialCreationOptions,
  deps: RegistrationOrchestratorDeps,
): Promise<PublicKeyCredential | unknown>;
export function executeWebAuthnWithParentFallbacksSafari(
  kind: 'get',
  publicKey: PublicKeyCredentialRequestOptions,
  deps: AuthenticationOrchestratorDeps,
): Promise<PublicKeyCredential | unknown>;
export async function executeWebAuthnWithParentFallbacksSafari(
  kind: Kind,
  publicKey: AnyPublicKeyOptions,
  deps: RegistrationOrchestratorDeps | AuthenticationOrchestratorDeps,
): Promise<PublicKeyCredential | unknown> {
  const publicKeyForAttempt = clonePublicKeyOptions(kind, publicKey);
  try {
    if (kind === 'create') {
      return await navigator.credentials.create({
        publicKey: publicKeyForAttempt as PublicKeyCredentialCreationOptions,
        ...(deps.abortSignal ? { signal: deps.abortSignal } : {}),
      });
    }
    return await navigator.credentials.get({
      publicKey: publicKeyForAttempt as PublicKeyCredentialRequestOptions,
      ...(deps.abortSignal ? { signal: deps.abortSignal } : {}),
    });
  } catch (error: unknown) {
    if (kind === 'create' && (isAncestorOriginError(error) || isDocumentNotFocusedError(error))) {
      throw new WalletOriginWebAuthnUnavailableError(
        `Wallet-origin WebAuthn registration is unavailable: ${safeMessage(error)}`,
      );
    }
    throw error;
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
  const name = (err as { name?: unknown })?.name;
  return typeof name === 'string' ? name : '';
}
