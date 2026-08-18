import type {
  LinkedDeviceSessionProjectionV1,
  LinkedDeviceSessionTransportEventV1,
  LinkDevicePublicKeyB64u,
  QrLinkedDeviceSessionPayloadV4,
} from '@shared/device-linking';
import {
  parseLinkedDeviceSessionProjectionV1,
  parseLinkedDeviceSessionTransportEventV1,
  parseLinkedDeviceTargetPreparationV1,
} from '@shared/device-linking';
import {
  computeLinkedDevicePublicKeyDigestV1,
  LINKED_DEVICE_REQUEST_PROOF_HEADER_V1,
  LINKED_DEVICE_REQUEST_PROOF_MAX_TTL_MS_V1,
  LINKED_DEVICE_REQUEST_PROOF_NONCE_BYTES_V1,
  type LinkedDeviceRequestProofV1,
} from '@shared/device-linking';
import type { DigestB64u } from '@shared/utils/canonicalPrimitives';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import { base64UrlEncode } from '@shared/utils/base64';
import { sha256Bytes } from '@shared/utils/digests';
import { secureRandomBase64Url } from '@shared/utils/secureRandomId';
import { parseLinkDeviceSessionId, type LinkDeviceSessionId } from '@shared/signing-lanes/ids';
import { parseLinkedDeviceLocalAccountProjectionV1 } from '@shared/device-linking';
import type { LinkedDeviceLocalAccountProjectionV1 } from '@shared/device-linking';
import { parseLinkedDeviceCustodyTransferPackageV1 } from '@shared/device-linking/custodyTransfer';
import type { HttpTransport } from '@/core/platform/http';
import type {
  DeviceLinkingAuthenticatedTransportPortV1,
  DeviceLinkingKeyMaterialHandleV1,
  DeviceLinkingKeyMaterialPortV1,
  LinkSessionSnapshotV1,
  LinkSessionSubscriptionV1,
  LinkSessionOwnerTransportPortV1,
  LinkSessionTransportPortV1,
} from './deviceLinkingPorts';
import type { WalletAddAuthMethodFinalizeResponse } from '@/core/rpcClients/relayer/walletRegistration';
import { parseWebAuthnAuthenticatorDeviceInfo } from '@shared/utils/webauthnDeviceInfo';
import {
  parseWebAuthnCredentialIdB64u,
  parseWebAuthnRpId,
  parseWalletId,
} from '@shared/utils/domainIds';

export const LINKED_DEVICE_SESSION_HTTP_BASE_PATH_V1 = '/wallet/device-linking/v1/sessions';

const LINKED_DEVICE_POLL_MAX_DELAY_MS = 4_000;

/** Keep long-lived session polling responsive without creating a tight request loop. */
export function nextLinkedDevicePollingDelayMsV1(baseDelayMs: number, attempt: number): number {
  const boundedBaseDelayMs = Math.min(baseDelayMs, LINKED_DEVICE_POLL_MAX_DELAY_MS);
  const boundedAttempt = Math.min(Math.max(attempt, 0), 5);
  const exponentialDelayMs = Math.min(
    LINKED_DEVICE_POLL_MAX_DELAY_MS,
    boundedBaseDelayMs * 2 ** boundedAttempt,
  );
  const jitterWindowMs = Math.max(1, Math.min(boundedBaseDelayMs, exponentialDelayMs / 4));
  const jitterMs = Math.floor(Math.random() * jitterWindowMs);
  return Math.min(LINKED_DEVICE_POLL_MAX_DELAY_MS, exponentialDelayMs + jitterMs);
}

export type DeviceLinkingAuthenticatedSessionTransportOptionsV1 = {
  readonly http: HttpTransport;
  readonly relayerUrl: string;
  readonly keyMaterial: DeviceLinkingKeyMaterialPortV1;
  readonly keyMaterialHandle: DeviceLinkingKeyMaterialHandleV1;
  readonly devicePublicKeyB64u: LinkDevicePublicKeyB64u;
  readonly nowMs: () => number;
  readonly pollIntervalMs: number;
};

export type DeviceLinkingSessionTransportAssemblyOptionsV1 = {
  readonly owner: LinkSessionOwnerTransportPortV1;
  readonly http: HttpTransport;
  readonly relayerUrl: string;
  readonly keyMaterial: DeviceLinkingKeyMaterialPortV1;
  readonly nowMs: () => number;
  readonly pollIntervalMs: number;
};

type SessionMutationEnvelopeV1 = {
  readonly ok: true;
  readonly outcome: 'applied' | 'replayed';
  readonly session: LinkedDeviceSessionProjectionV1;
};

type DeviceRequestResponseV1 = {
  readonly status: number;
  readonly body: unknown;
};

export function createDeviceLinkingAuthenticatedSessionTransportV1(
  options: DeviceLinkingAuthenticatedSessionTransportOptionsV1,
): DeviceLinkingAuthenticatedTransportPortV1 {
  const baseUrl = normalizeBaseUrl(options.relayerUrl);
  if (!Number.isSafeInteger(options.pollIntervalMs) || options.pollIntervalMs <= 0) {
    throw new Error('linked-device session poll interval must be a positive integer');
  }
  return {
    createUnclaimedSessionV1: async (input) => {
      await requestMutationV1({
        options,
        baseUrl,
        method: 'POST',
        canonicalPath: LINKED_DEVICE_SESSION_HTTP_BASE_PATH_V1,
        linkSessionId: input.payload.linkSessionId,
        body: {
          kind: 'linked_device_session_create_request_v1',
          payload: input.payload,
        },
      });
    },
    getSessionV1: async ({ linkSessionId }) =>
      await requestSessionV1({ options, baseUrl, linkSessionId }),
    getTargetPreparationV1: async ({ linkSessionId }) => {
      const response = await requestDeviceV1({
        options,
        baseUrl,
        method: 'GET',
        canonicalPath: sessionActionPath(linkSessionId, 'target-preparation'),
        linkSessionId,
      });
      return parseLinkedDeviceTargetPreparationV1(response.body);
    },
    finalizeOwnerAuthMethodV1: async ({ linkSessionId, request }) => {
      const response = await requestDeviceV1({
        options,
        baseUrl,
        method: 'POST',
        canonicalPath: sessionActionPath(linkSessionId, 'owner-finalize'),
        linkSessionId,
        body: request,
      });
      return parseLinkedDeviceOwnerFinalizeResponseV1(response.body);
    },
    registerCustodyTransferRecipientV1: async ({ recipient }) => {
      const linkSessionId = requireLinkSessionId(recipient.linkSessionId);
      await requestDeviceV1({
        options,
        baseUrl,
        method: 'POST',
        canonicalPath: sessionActionPath(linkSessionId, 'custody-transfer-recipient'),
        linkSessionId,
        body: recipient,
      });
    },
    getCustodyTransferPackageV1: async ({ linkSessionId }) => {
      const response = await requestDeviceV1({
        options,
        baseUrl,
        method: 'GET',
        canonicalPath: sessionActionPath(linkSessionId, 'custody-transfer'),
        linkSessionId,
        allowNotFound: true,
      });
      // Device 1 has not sealed yet. Normal while the owner is approving.
      if (response.status === 404) return null;
      return parseLinkedDeviceCustodyTransferPackageV1(response.body);
    },
    cancelSessionV1: async ({ request }) => {
      await requestMutationV1({
        options,
        baseUrl,
        method: 'POST',
        canonicalPath: sessionActionPath(request.linkSessionId, 'cancel'),
        linkSessionId: request.linkSessionId,
        body: request,
      });
    },
    subscribeSessionV1: async ({ linkSessionId, onEvent }) =>
      await createPollingSubscriptionV1({
        options,
        baseUrl,
        linkSessionId,
        onEvent,
      }),
  };
}

/** Compose one direct transport port; owner auth remains an injected boundary. */
export function createDeviceLinkingSessionTransportPortV1(
  options: DeviceLinkingSessionTransportAssemblyOptionsV1,
): LinkSessionTransportPortV1 {
  return {
    ...options.owner,
    createAuthenticatedSessionTransportV1: ({ keyMaterial, devicePublicKeyB64u }) =>
      createDeviceLinkingAuthenticatedSessionTransportV1({
        http: options.http,
        relayerUrl: options.relayerUrl,
        keyMaterial: options.keyMaterial,
        keyMaterialHandle: keyMaterial,
        devicePublicKeyB64u,
        nowMs: options.nowMs,
        pollIntervalMs: options.pollIntervalMs,
      }),
  };
}

/**
 * The recipient registration carries its link session as a plain string,
 * because it is also the body the server parses. Re-parsing it here keeps the
 * signed canonical path derived from a branded id.
 */
function requireLinkSessionId(raw: string): LinkDeviceSessionId {
  const parsed = parseLinkDeviceSessionId(raw);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

async function requestSessionV1(input: {
  readonly options: DeviceLinkingAuthenticatedSessionTransportOptionsV1;
  readonly baseUrl: string;
  readonly linkSessionId: LinkDeviceSessionId;
}): Promise<LinkSessionSnapshotV1> {
  const response = await requestDeviceV1({
    options: input.options,
    baseUrl: input.baseUrl,
    method: 'GET',
    canonicalPath: sessionPath(input.linkSessionId),
    linkSessionId: input.linkSessionId,
  });
  return parseSessionMutationEnvelopeV1(response.body).session;
}

async function requestMutationV1(input: {
  readonly options: DeviceLinkingAuthenticatedSessionTransportOptionsV1;
  readonly baseUrl: string;
  readonly method: 'POST';
  readonly canonicalPath: string;
  readonly linkSessionId: LinkDeviceSessionId;
  readonly body: QrLinkedDeviceSessionPayloadV4 | Record<string, unknown>;
}): Promise<SessionMutationEnvelopeV1> {
  const response = await requestDeviceV1(input);
  return parseSessionMutationEnvelopeV1(response.body);
}

async function requestDeviceV1(input: {
  readonly options: DeviceLinkingAuthenticatedSessionTransportOptionsV1;
  readonly baseUrl: string;
  readonly method: 'GET' | 'POST';
  readonly canonicalPath: string;
  readonly linkSessionId: LinkDeviceSessionId;
  readonly body?: unknown;
  /**
   * A poll for something the other device has not produced yet. 404 is the
   * expected answer while waiting, so the caller wants it as a value rather
   * than an exception.
   */
  readonly allowNotFound?: boolean;
}): Promise<DeviceRequestResponseV1> {
  const bodyBytes = encodeRequestBodyV1(input.body);
  const bodyDigestB64u = parseDigestB64u(base64UrlEncode(await sha256Bytes(bodyBytes)));
  const issuedAtMs = input.options.nowMs();
  if (!Number.isSafeInteger(issuedAtMs) || issuedAtMs <= 0) {
    throw new Error('linked-device request clock is invalid');
  }
  const expiresAtMs = issuedAtMs + LINKED_DEVICE_REQUEST_PROOF_MAX_TTL_MS_V1;
  const requestNonceB64u = secureRandomBase64Url(
    LINKED_DEVICE_REQUEST_PROOF_NONCE_BYTES_V1,
    'linked-device request proof nonce',
  );
  const devicePublicKeyDigestB64u = await computeLinkedDevicePublicKeyDigestV1(
    input.options.devicePublicKeyB64u,
  );
  const signed = await input.options.keyMaterial.signDeviceSessionRequestV1({
    handle: input.options.keyMaterialHandle,
    linkSessionId: input.linkSessionId,
    method: input.method,
    canonicalPath: input.canonicalPath,
    bodyDigestB64u,
    devicePublicKeyDigestB64u,
    challengeB64u: requestNonceB64u,
    issuedAtMs,
    expiresAtMs,
  });
  const proof: LinkedDeviceRequestProofV1 = {
    kind: 'linked_device_request_proof_v1',
    linkSessionId: input.linkSessionId,
    devicePublicKeyDigestB64u,
    requestNonceB64u,
    method: input.method,
    canonicalPath: input.canonicalPath,
    bodyDigestB64u,
    issuedAtMs,
    expiresAtMs,
    signatureB64u: signed.signatureB64u,
  };
  const proofHeader = base64UrlEncode(new TextEncoder().encode(JSON.stringify(proof)));
  const response = await input.options.http.request({
    method: input.method,
    url: `${input.baseUrl}${input.canonicalPath}`,
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/json',
      [LINKED_DEVICE_REQUEST_PROOF_HEADER_V1]: proofHeader,
    },
    ...(input.body === undefined ? {} : { body: input.body }),
  });
  if (!response.ok) throw new Error(`linked-device request failed: ${response.message}`);
  if (input.allowNotFound && response.value.status === 404) return response.value;
  if (response.value.status < 200 || response.value.status >= 300) {
    throw new Error(parseHttpFailureMessageV1(response.value));
  }
  return response.value;
}

async function createPollingSubscriptionV1(input: {
  readonly options: DeviceLinkingAuthenticatedSessionTransportOptionsV1;
  readonly baseUrl: string;
  readonly linkSessionId: LinkDeviceSessionId;
  readonly onEvent: (event: LinkedDeviceSessionTransportEventV1) => void;
}): Promise<LinkSessionSubscriptionV1> {
  let closed = false;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let lastRevision: number | null = null;
  let firstPoll = true;
  let retryAttempt = 0;
  const poll = async (): Promise<void> => {
    if (closed) return;
    try {
      const session = await requestSessionV1({ ...input });
      if (lastRevision === null || session.revision !== lastRevision) {
        lastRevision = session.revision;
        retryAttempt = 0;
        input.onEvent(
          parseLinkedDeviceSessionTransportEventV1({
            kind: 'linked_device_session_event_v1',
            linkSessionId: session.linkSessionId,
            state: session.state,
            emittedAtMs: session.updatedAtMs,
          }),
        );
      } else {
        retryAttempt += 1;
      }
    } catch (error: unknown) {
      if (firstPoll) {
        closed = true;
        throw error;
      }
      retryAttempt += 1;
    } finally {
      firstPoll = false;
      if (!closed) {
        timer = setTimeout(
          () => void poll(),
          nextLinkedDevicePollingDelayMsV1(
            input.options.pollIntervalMs,
            Math.max(0, retryAttempt - 1),
          ),
        );
      }
    }
  };
  await poll();
  return {
    close: () => {
      closed = true;
      if (timer !== undefined) clearTimeout(timer);
    },
  };
}

function parseSessionMutationEnvelopeV1(raw: unknown): SessionMutationEnvelopeV1 {
  if (!isRecord(raw)) {
    throw new Error('linked-device response must be an object');
  }
  const keys = Object.keys(raw).sort();
  if (keys.join(',') !== 'ok,outcome,session') {
    throw new Error('linked-device response contains invalid fields');
  }
  if (raw.ok !== true || (raw.outcome !== 'applied' && raw.outcome !== 'replayed')) {
    throw new Error('linked-device response outcome is invalid');
  }
  return {
    ok: true,
    outcome: raw.outcome,
    session: parseLinkedDeviceSessionProjectionV1(raw.session),
  };
}

function parseHttpFailureMessageV1(response: DeviceRequestResponseV1): string {
  if (isRecord(response.body)) {
    const message = response.body.message;
    if (typeof message === 'string' && message.trim())
      return `linked-device request failed: ${message}`;
    const outcome = response.body.outcome;
    if (typeof outcome === 'string') return `linked-device request failed: ${outcome}`;
  }
  return `linked-device request failed with HTTP ${response.status}`;
}

/**
 * The finalize response, plus the local account identity that rides with it.
 *
 * Kept as a distinct return type rather than widened onto the canonical finalize
 * response: only the linked route carries this, because only a device that never
 * registered locally needs it.
 */
export type LinkedDeviceOwnerFinalizeResultV1 = {
  readonly response: WalletAddAuthMethodFinalizeResponse;
  readonly localAccount: LinkedDeviceLocalAccountProjectionV1;
};

function parseLinkedDeviceOwnerFinalizeResponseV1(raw: unknown): LinkedDeviceOwnerFinalizeResultV1 {
  if (!isRecord(raw) || raw.ok !== true) {
    throw new Error('linked-device owner finalize response is invalid');
  }
  const walletId = parseRequiredDomainId(parseWalletId(raw.walletId), 'walletId');
  const rpId = parseRequiredDomainId(parseWebAuthnRpId(raw.rpId), 'rpId');
  if (!isRecord(raw.authMethod)) {
    throw new Error('linked-device owner finalize response omitted auth method');
  }
  const authMethod = raw.authMethod;
  if (authMethod.kind !== 'passkey' || authMethod.status !== 'active') {
    throw new Error('linked-device owner finalize response is not an active passkey');
  }
  const credentialIdB64u = parseRequiredDomainId(
    parseWebAuthnCredentialIdB64u(authMethod.credentialIdB64u),
    'authMethod.credentialIdB64u',
  );
  if (
    typeof authMethod.credentialPublicKeyB64u !== 'string' ||
    !authMethod.credentialPublicKeyB64u.trim()
  ) {
    throw new Error('linked-device owner finalize response omitted credential public key');
  }
  const counter = authMethod.counter;
  if (typeof counter !== 'number' || !Number.isSafeInteger(counter) || counter < 0) {
    throw new Error('linked-device owner finalize response has an invalid counter');
  }
  const device = parseWebAuthnAuthenticatorDeviceInfo(authMethod.device);
  if (!device) {
    throw new Error('linked-device owner finalize response has invalid device metadata');
  }
  // Required, not optional: a linked finalize that omitted it would leave this
  // device unable to unlock, and failing here names the cause.
  const localAccount = parseLinkedDeviceLocalAccountProjectionV1(raw.localAccount);
  if (String(localAccount.walletId) !== String(walletId)) {
    throw new Error('linked-device owner finalize response local account names another wallet');
  }
  return {
    response: {
      ok: true,
      walletId,
      rpId,
      authMethod: {
        kind: 'passkey',
        status: 'active',
        credentialIdB64u,
        credentialPublicKeyB64u: authMethod.credentialPublicKeyB64u,
        counter,
        device,
      },
    },
    localAccount,
  };
}

function parseRequiredDomainId<T>(
  parsed:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
  label: string,
): T {
  if (!parsed.ok) throw new Error(`linked-device owner finalize ${label} ${parsed.error.message}`);
  return parsed.value;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function encodeRequestBodyV1(body: unknown): Uint8Array {
  if (body === undefined) return new Uint8Array();
  const encoded = JSON.stringify(body);
  if (typeof encoded !== 'string')
    throw new Error('linked-device request body is not JSON serializable');
  return new TextEncoder().encode(encoded);
}

function normalizeBaseUrl(value: string): string {
  const normalized = value.trim().replace(/\/+$/, '');
  if (!normalized) throw new Error('linked-device relayer URL is required');
  return normalized;
}

function sessionPath(linkSessionId: LinkDeviceSessionId): string {
  return `${LINKED_DEVICE_SESSION_HTTP_BASE_PATH_V1}/${String(linkSessionId)}`;
}

function sessionActionPath(
  linkSessionId: LinkDeviceSessionId,
  action:
    | 'approval'
    | 'wallet-session'
    | 'target-preparation'
    | 'owner-finalize'
    | 'provision'
    | 'holder-receipts'
    | 'credential'
    | 'custody-transfer'
    | 'custody-transfer-recipient'
    | 'receipt'
    | 'retry'
    | 'cancel',
): string {
  return `${sessionPath(linkSessionId)}/${action}`;
}
