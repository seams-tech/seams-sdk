import type { HttpTransport } from '@/core/platform/http';
import {
  walletSessionAuthorizationIdForCurve,
  walletSessionTokenForCurve,
  type ActiveWalletSessionAuthorizationProjection,
  type WalletSessionAuthorizationRepository,
} from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import type { WalletAuthenticationState } from '@/core/types/seams';
import type {
  DeviceLinkingOwnerAuthorizationPortV1,
  LinkSessionAuthenticationV1,
} from './deviceLinkingPorts';
import type {
  LinkedDeviceOwnerAuthorizationRequestV1,
  LinkedDeviceOwnerSourceLaneV1,
} from '@shared/device-linking';
import { parseLinkedDeviceOwnerAuthorizationRequestV1 } from '@shared/device-linking/parsers';
import type { LinkSessionOwnerAuthenticatedRequestPortV1 } from './deviceLinkingOwnerTransport';
import {
  parseLinkedDeviceEnrollmentKeyBindingV1,
  parseLinkedDeviceOwnerAuthorizationSourceV1,
  parseLinkedDeviceProtocolVersionV1,
} from '@shared/device-linking/parsers';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import { parseWalletId, type WalletId } from '@shared/utils/domainIds';
import { parseLaneOperationId, parseLaneOperationIdempotencyKey } from '@shared/signing-lanes/ids';

const OWNER_AUTHORIZATION_PATH = '/wallet/device-linking/v1/owner-authorization';

export type WalletHostManagementRequestV1 = {
  request(input: {
    readonly walletId: WalletId;
    readonly method: 'GET' | 'POST';
    readonly canonicalPath: string;
    readonly body?: unknown;
  }): Promise<{ readonly status: number; readonly body: unknown }>;
};

export type WalletHostOwnerSourceLaneHintsReaderV1 = (input: {
  readonly projection: ActiveWalletSessionAuthorizationProjection;
}) => Promise<readonly [LinkedDeviceOwnerSourceLaneV1, ...LinkedDeviceOwnerSourceLaneV1[]]>;

export type WalletHostOwnerAuthoritiesV1 = {
  readonly ownerAuthorization: DeviceLinkingOwnerAuthorizationPortV1;
  readonly ownerRequest: LinkSessionOwnerAuthenticatedRequestPortV1;
  readonly managementRequest: WalletHostManagementRequestV1;
};

export function createWalletHostOwnerAuthoritiesV1(input: {
  readonly http: HttpTransport;
  readonly relayerUrl: string;
  readonly walletSessions: Pick<
    WalletSessionAuthorizationRepository,
    'read' | 'readActiveForWallet'
  >;
  readonly readWalletAuthenticationState: () => WalletAuthenticationState;
  readonly hasLinkedDeviceSigningSession: (walletId: WalletId) => boolean;
  readonly readOwnerSourceLaneHintsV1: WalletHostOwnerSourceLaneHintsReaderV1;
  /**
   * Starts the owner add-auth-method ceremony a linked device will finalize.
   *
   * Injected rather than built here: it needs the wallet's relying party,
   * managed-scope credentials, and a fresh passkey assertion, all of which the
   * composition root already holds.
   */
  readonly startOwnerEnrollmentCeremonyV1: DeviceLinkingOwnerAuthorizationPortV1['startOwnerEnrollmentCeremonyV1'];
}): WalletHostOwnerAuthoritiesV1 {
  const context = normalizeContext(input);
  // Approval is retried whenever the scan flow is re-entered, so one ceremony
  // is reused while its live custody hold exists. The hold evicts this entry
  // when it seals or is discarded; a released hold never reaches a retry.
  const ownerEnrollmentCeremonies = new Map<
    string,
    ReturnType<DeviceLinkingOwnerAuthorizationPortV1['startOwnerEnrollmentCeremonyV1']>
  >();
  return {
    ownerAuthorization: {
      startOwnerEnrollmentCeremonyV1: async (request) => {
        const key = String(request.linkSessionId);
        const cached = ownerEnrollmentCeremonies.get(key);
        if (cached) return await cached;
        let started: ReturnType<
          DeviceLinkingOwnerAuthorizationPortV1['startOwnerEnrollmentCeremonyV1']
        >;
        started = input.startOwnerEnrollmentCeremonyV1(request).then(
          (value) => attachCustodyHoldEvictionV1(key, value, ownerEnrollmentCeremonies, started),
          (error: unknown) => {
            if (ownerEnrollmentCeremonies.get(key) === started) {
              ownerEnrollmentCeremonies.delete(key);
            }
            throw error;
          },
        );
        ownerEnrollmentCeremonies.set(key, started);
        try {
          return await started;
        } catch (error: unknown) {
          if (ownerEnrollmentCeremonies.get(key) === started) {
            ownerEnrollmentCeremonies.delete(key);
          }
          throw error;
        }
      },
      authenticateOwnerForLinkingV1: async (request) =>
        await authorizeOwnerForLinkingV1(context, request),
    },
    ownerRequest: {
      requestOwnerV1: async (request) => await requestAsAuthorizedOwnerV1(context, request),
    },
    managementRequest: {
      request: async (request) => await requestManagementAsOwnerV1(context, request),
    },
  };
}

function attachCustodyHoldEvictionV1(
  key: string,
  started: Awaited<
    ReturnType<DeviceLinkingOwnerAuthorizationPortV1['startOwnerEnrollmentCeremonyV1']>
  >,
  cache: Map<
    string,
    ReturnType<DeviceLinkingOwnerAuthorizationPortV1['startOwnerEnrollmentCeremonyV1']>
  >,
  cachedPromise: ReturnType<
    DeviceLinkingOwnerAuthorizationPortV1['startOwnerEnrollmentCeremonyV1']
  >,
): Awaited<ReturnType<DeviceLinkingOwnerAuthorizationPortV1['startOwnerEnrollmentCeremonyV1']>> {
  const evict = (): void => {
    if (cache.get(key) === cachedPromise) cache.delete(key);
  };
  const custodyHold = started.custodyHold;
  let released = false;
  return {
    ceremony: started.ceremony,
    custodyHold: {
      sealOnceV1: async (seal) => {
        try {
          return await custodyHold.sealOnceV1(seal);
        } finally {
          released = true;
          evict();
        }
      },
      discardV1: () => {
        if (released) return;
        released = true;
        evict();
        custodyHold.discardV1();
      },
    },
  };
}

type WalletHostOwnerAuthorityContextV1 = {
  readonly http: HttpTransport;
  readonly baseUrl: string;
  readonly walletSessions: Pick<
    WalletSessionAuthorizationRepository,
    'read' | 'readActiveForWallet'
  >;
  readonly readWalletAuthenticationState: () => WalletAuthenticationState;
  readonly hasLinkedDeviceSigningSession: (walletId: WalletId) => boolean;
  readonly readOwnerSourceLaneHintsV1: WalletHostOwnerSourceLaneHintsReaderV1;
};

function normalizeContext(input: {
  readonly http: HttpTransport;
  readonly relayerUrl: string;
  readonly walletSessions: Pick<
    WalletSessionAuthorizationRepository,
    'read' | 'readActiveForWallet'
  >;
  readonly readWalletAuthenticationState: () => WalletAuthenticationState;
  readonly hasLinkedDeviceSigningSession: (walletId: WalletId) => boolean;
  readonly readOwnerSourceLaneHintsV1: WalletHostOwnerSourceLaneHintsReaderV1;
}): WalletHostOwnerAuthorityContextV1 {
  const baseUrl = String(input.relayerUrl || '')
    .trim()
    .replace(/\/+$/, '');
  if (!baseUrl) throw new Error('Wallet-host device linking requires a Router URL');
  return { ...input, baseUrl };
}

async function authorizeOwnerForLinkingV1(
  context: WalletHostOwnerAuthorityContextV1,
  input: Parameters<DeviceLinkingOwnerAuthorizationPortV1['authenticateOwnerForLinkingV1']>[0],
): ReturnType<DeviceLinkingOwnerAuthorizationPortV1['authenticateOwnerForLinkingV1']> {
  const state = context.readWalletAuthenticationState();
  if (state.kind !== 'authenticated') {
    throw new Error('Device linking requires an authenticated owner wallet');
  }
  assertOwnerDeviceManagementAuthorityV1(context, state.walletId);
  const projection = await requireActiveWalletSessionForWalletV1(context, state.walletId);
  const orderedOwnerSourceLaneHints = await context.readOwnerSourceLaneHintsV1({
    projection,
  });
  const body: LinkedDeviceOwnerAuthorizationRequestV1 =
    parseLinkedDeviceOwnerAuthorizationRequestV1({
      payload: input.payload,
      requestedAtMs: input.requestedAtMs,
      orderedOwnerSourceLaneHints,
    });
  const response = await requestWithProjectionV1(context, projection, {
    method: 'POST',
    canonicalPath: OWNER_AUTHORIZATION_PATH,
    body,
  });
  if (response.status < 200 || response.status >= 300) {
    throw new Error(ownerRequestFailureMessage(response));
  }
  return parseOwnerAuthorizationResponseV1(response.body, projection);
}

async function requestAsAuthorizedOwnerV1(
  context: WalletHostOwnerAuthorityContextV1,
  input: Parameters<LinkSessionOwnerAuthenticatedRequestPortV1['requestOwnerV1']>[0],
): ReturnType<LinkSessionOwnerAuthenticatedRequestPortV1['requestOwnerV1']> {
  if (input.authentication.source.kind !== 'wallet_session') {
    throw new Error('Wallet-host device linking requires a reusable owner Wallet Session');
  }
  const read = await context.walletSessions.read(input.authentication.source.walletSessionId);
  if (read.kind !== 'found' || read.projection.status !== 'active') {
    throw new Error('Owner Wallet Session is unavailable');
  }
  const projection = read.projection;
  if (
    !projectionContainsAuthorizationId(
      projection,
      input.authentication.source.authorizationId,
    ) ||
    projection.expiresAtMs <= Date.now()
  ) {
    throw new Error('Owner Wallet Session identity is invalid or expired');
  }
  assertOwnerDeviceManagementAuthorityV1(context, projection.walletId);
  return await requestWithProjectionV1(context, projection, input);
}

async function requestManagementAsOwnerV1(
  context: WalletHostOwnerAuthorityContextV1,
  input: Parameters<WalletHostManagementRequestV1['request']>[0],
): ReturnType<WalletHostManagementRequestV1['request']> {
  assertOwnerDeviceManagementAuthorityV1(context, input.walletId);
  const projection = await requireActiveWalletSessionForWalletV1(context, input.walletId);
  return await requestWithProjectionV1(context, projection, input);
}

function assertOwnerDeviceManagementAuthorityV1(
  context: WalletHostOwnerAuthorityContextV1,
  walletId: WalletId,
): void {
  if (context.hasLinkedDeviceSigningSession(walletId)) {
    throw new Error('Signing-only linked-device sessions cannot manage devices');
  }
}

async function requireActiveWalletSessionForWalletV1(
  context: WalletHostOwnerAuthorityContextV1,
  walletId: WalletId,
): Promise<ActiveWalletSessionAuthorizationProjection> {
  const read = await context.walletSessions.readActiveForWallet(walletId);
  if (
    read.kind !== 'found' ||
    read.projection.status !== 'active' ||
    read.projection.expiresAtMs <= Date.now()
  ) {
    throw new Error('An active owner Wallet Session is required');
  }
  return read.projection;
}

async function requestWithProjectionV1(
  context: WalletHostOwnerAuthorityContextV1,
  projection: ActiveWalletSessionAuthorizationProjection,
  input: {
    readonly method: 'GET' | 'POST';
    readonly canonicalPath: string;
    readonly body?: unknown;
  },
): Promise<{ readonly status: number; readonly body: unknown }> {
  const walletSessionToken = preferredOwnerWalletSessionToken(projection);
  const response = await context.http.request({
    method: input.method,
    url: `${context.baseUrl}${input.canonicalPath}`,
    headers: { authorization: `Bearer ${walletSessionToken}` },
    ...(input.body === undefined ? {} : { body: input.body }),
  });
  if (!response.ok) throw new Error(`Owner Router request failed: ${response.message}`);
  return response.value;
}

function preferredOwnerWalletSessionToken(
  projection: ActiveWalletSessionAuthorizationProjection,
): string {
  const ed25519 = walletSessionTokenForCurve(projection, 'ed25519');
  if (ed25519) return ed25519;
  const ecdsa = walletSessionTokenForCurve(projection, 'ecdsa');
  if (ecdsa) return ecdsa;
  throw new Error('Owner Wallet Session has no supported signing token');
}

function projectionContainsAuthorizationId(
  projection: ActiveWalletSessionAuthorizationProjection,
  authorizationId: string,
): boolean {
  return (
    walletSessionAuthorizationIdForCurve(projection, 'ed25519') === authorizationId ||
    walletSessionAuthorizationIdForCurve(projection, 'ecdsa') === authorizationId
  );
}

function parseOwnerAuthorizationResponseV1(
  raw: unknown,
  projection: ActiveWalletSessionAuthorizationProjection,
): Awaited<ReturnType<DeviceLinkingOwnerAuthorizationPortV1['authenticateOwnerForLinkingV1']>> {
  const record = exactRecord(raw, [
    'authentication',
    'walletId',
    'ownerAuthorization',
    'policyDigestB64u',
    'operationId',
    'idempotencyKey',
    'orderedKeyBindings',
    'protocolVersions',
    'expiresAtMs',
  ]);
  const authenticationRecord = exactRecord(record.authentication, [
    'kind',
    'source',
    'proofDigestB64u',
  ]);
  if (authenticationRecord.kind !== 'link_session_authenticated_request_v1') {
    throw new Error('Owner authorization authentication kind is invalid');
  }
  const source = parseLinkedDeviceOwnerAuthorizationSourceV1(authenticationRecord.source);
  const ownerAuthorization = parseLinkedDeviceOwnerAuthorizationSourceV1(record.ownerAuthorization);
  assertWalletSessionSourceMatchesProjection(source, projection);
  assertSameOwnerAuthorization(source, ownerAuthorization);
  const authentication: LinkSessionAuthenticationV1 = {
    kind: 'link_session_authenticated_request_v1',
    source,
    proofDigestB64u: parseDigestB64u(String(authenticationRecord.proofDigestB64u)),
  };
  const walletId = parseWalletId(String(record.walletId));
  if (!walletId.ok || walletId.value !== projection.walletId) {
    throw new Error('Owner authorization wallet identity changed');
  }
  const orderedKeyBindings = parseNonEmptyArray(
    record.orderedKeyBindings,
    parseLinkedDeviceEnrollmentKeyBindingV1,
    'orderedKeyBindings',
  );
  const protocolVersions = parseNonEmptyArray(
    record.protocolVersions,
    parseLinkedDeviceProtocolVersionV1,
    'protocolVersions',
  );
  const operationId = parseLaneOperationId(record.operationId);
  if (!operationId.ok) throw new Error(operationId.error.message);
  const idempotencyKey = parseLaneOperationIdempotencyKey(record.idempotencyKey);
  if (!idempotencyKey.ok) throw new Error(idempotencyKey.error.message);
  return {
    authentication,
    walletId: walletId.value,
    ownerAuthorization,
    policyDigestB64u: parseDigestB64u(String(record.policyDigestB64u)),
    operationId: operationId.value,
    idempotencyKey: idempotencyKey.value,
    orderedKeyBindings,
    protocolVersions,
    expiresAtMs: positiveSafeInteger(record.expiresAtMs, 'expiresAtMs'),
  };
}

function parseNonEmptyArray<T>(
  raw: unknown,
  parse: (entry: unknown, label: string) => T,
  label: string,
): readonly [T, ...T[]] {
  if (!Array.isArray(raw) || raw.length === 0) throw new Error(`${label} must be non-empty`);
  const values = raw.map((entry, index) => parse(entry, `${label}[${index}]`));
  const first = values[0];
  if (first === undefined) throw new Error(`${label} must be non-empty`);
  return [first, ...values.slice(1)];
}

function assertWalletSessionSourceMatchesProjection(
  source: ReturnType<typeof parseLinkedDeviceOwnerAuthorizationSourceV1>,
  projection: ActiveWalletSessionAuthorizationProjection,
): void {
  if (
    source.kind !== 'wallet_session' ||
    source.walletSessionId !== projection.walletSessionId ||
    !projectionContainsAuthorizationId(projection, source.authorizationId)
  ) {
    throw new Error('Owner authorization Wallet Session identity changed');
  }
}

function assertSameOwnerAuthorization(
  left: ReturnType<typeof parseLinkedDeviceOwnerAuthorizationSourceV1>,
  right: ReturnType<typeof parseLinkedDeviceOwnerAuthorizationSourceV1>,
): void {
  if (
    left.kind !== 'wallet_session' ||
    right.kind !== 'wallet_session' ||
    left.walletSessionId !== right.walletSessionId ||
    left.authorizationId !== right.authorizationId
  ) {
    throw new Error('Owner authorization source changed');
  }
}

function exactRecord(raw: unknown, fields: readonly string[]): Record<string, unknown> {
  if (!isRecord(raw)) {
    throw new Error('Owner authorization response must be an object');
  }
  const record = raw;
  const expected = new Set(fields);
  const actual = Object.keys(record);
  if (actual.length !== expected.size || actual.some((field) => !expected.has(field))) {
    throw new Error('Owner authorization response has unexpected fields');
  }
  return record;
}

function ownerRequestFailureMessage(response: {
  readonly status: number;
  readonly body: unknown;
}): string {
  if (isRecord(response.body) && typeof response.body.message === 'string') {
    return `Owner authorization failed: ${response.body.message}`;
  }
  return `Owner authorization failed with HTTP ${response.status}`;
}

function positiveSafeInteger(raw: unknown, label: string): number {
  if (!Number.isSafeInteger(raw) || Number(raw) <= 0) {
    throw new Error(`${label} must be a positive safe integer`);
  }
  return Number(raw);
}

function isRecord(raw: unknown): raw is Record<string, unknown> {
  return raw !== null && typeof raw === 'object' && !Array.isArray(raw);
}
