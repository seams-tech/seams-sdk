import type { HttpTransport } from '@/core/platform/http';
import { DeviceLinkingError, DeviceLinkingErrorCode } from '@/core/types/linkDevice';
import type { UnlockedWalletEd25519ExportRootCapabilityV1 } from '@/core/signingEngine/workerManager/workerTypes';
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
import { hasDelegatedWalletPermissionV1 } from '@shared/authorization/delegatedAuthority';
import { parseLinkedDeviceOwnerAuthorizationRequestV1 } from '@shared/device-linking/parsers';
import type { LinkSessionOwnerAuthenticatedRequestPortV1 } from './deviceLinkingOwnerTransport';
import {
  parseLinkedDeviceOwnerAuthorizationSourceV1,
  parseLinkedDeviceOwnerSourceLaneV1,
} from '@shared/device-linking/parsers';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import { parseWalletId, type WalletId } from '@shared/utils/domainIds';

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
  readonly readOwnerSourceLaneHintsV1: WalletHostOwnerSourceLaneHintsReaderV1;
  /**
   * R103 zero-prompt handoff: reads the worker-held unlocked Ed25519 export-root
   * capability for a wallet, or undefined when none exists. Reading never
   * prompts.
   */
  readonly readUnlockedEd25519ExportRootCapabilityV1: (
    walletId: WalletId,
  ) => UnlockedWalletEd25519ExportRootCapabilityV1 | undefined;
}): WalletHostOwnerAuthoritiesV1 {
  const context = normalizeContext(input);
  return {
    ownerAuthorization: {
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

type WalletHostOwnerAuthorityContextV1 = {
  readonly http: HttpTransport;
  readonly baseUrl: string;
  readonly walletSessions: Pick<
    WalletSessionAuthorizationRepository,
    'read' | 'readActiveForWallet'
  >;
  readonly readWalletAuthenticationState: () => WalletAuthenticationState;
  readonly readOwnerSourceLaneHintsV1: WalletHostOwnerSourceLaneHintsReaderV1;
  readonly readUnlockedEd25519ExportRootCapabilityV1: (
    walletId: WalletId,
  ) => UnlockedWalletEd25519ExportRootCapabilityV1 | undefined;
};

function normalizeContext(input: {
  readonly http: HttpTransport;
  readonly relayerUrl: string;
  readonly walletSessions: Pick<
    WalletSessionAuthorizationRepository,
    'read' | 'readActiveForWallet'
  >;
  readonly readWalletAuthenticationState: () => WalletAuthenticationState;
  readonly readOwnerSourceLaneHintsV1: WalletHostOwnerSourceLaneHintsReaderV1;
  readonly readUnlockedEd25519ExportRootCapabilityV1: (
    walletId: WalletId,
  ) => UnlockedWalletEd25519ExportRootCapabilityV1 | undefined;
}): WalletHostOwnerAuthorityContextV1 {
  const baseUrl = String(input.relayerUrl || '')
    .trim()
    .replace(/\/+$/, '');
  if (!baseUrl) throw new Error('Wallet-host device linking requires a Router URL');
  return { ...input, baseUrl };
}

/**
 * The R103 fail-closed preflight, exact result `wallet_unlock_required`.
 *
 * Runs before the owner-authorization request, the QR claim, and everything
 * after them: a Device 1 that is locked, whose owner Wallet Session is gone,
 * or whose worker no longer holds the unlocked export-root capability gets this
 * one result, and the flow creates no claim, approval, credential, recipient
 * package, or authenticator prompt. Unlocking is the user's explicit act on
 * the wallet surface — never a side effect of scanning a QR.
 */
function walletUnlockRequiredV1(): DeviceLinkingError {
  return new DeviceLinkingError(
    'wallet_unlock_required',
    DeviceLinkingErrorCode.WALLET_UNLOCK_REQUIRED,
    'authorization',
  );
}

async function authorizeOwnerForLinkingV1(
  context: WalletHostOwnerAuthorityContextV1,
  input: Parameters<DeviceLinkingOwnerAuthorizationPortV1['authenticateOwnerForLinkingV1']>[0],
): ReturnType<DeviceLinkingOwnerAuthorizationPortV1['authenticateOwnerForLinkingV1']> {
  const state = context.readWalletAuthenticationState();
  if (state.kind !== 'authenticated') {
    throw walletUnlockRequiredV1();
  }
  const projection = await requireActiveWalletSessionForWalletV1(context, state.walletId);
  const orderedOwnerSourceLaneHints = await context.readOwnerSourceLaneHintsV1({
    projection,
  });
  const exportRootRequired =
    hasDelegatedWalletPermissionV1(input.payload.requestedPermission, 'export_keys') &&
    orderedOwnerSourceLaneHints.some((hint) => hint.keyFamily === 'ed25519');
  const ed25519ExportRootCapability = exportRootRequired
    ? context.readUnlockedEd25519ExportRootCapabilityV1(state.walletId)
    : undefined;
  if (
    exportRootRequired &&
    (!ed25519ExportRootCapability ||
      ed25519ExportRootCapability.walletId !== String(state.walletId) ||
      ed25519ExportRootCapability.walletSessionId !== String(projection.walletSessionId) ||
      ed25519ExportRootCapability.expiresAtMs <= Date.now())
  ) {
    throw walletUnlockRequiredV1();
  }
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
  const parsed = parseOwnerAuthorizationResponseV1(response.body, projection);
  if (exportRootRequired) {
    if (!ed25519ExportRootCapability) throw walletUnlockRequiredV1();
    return {
      ...parsed,
      exportRootRequirement: 'required',
      ed25519ExportRootCapability,
    };
  }
  return { ...parsed, exportRootRequirement: 'not_required' };
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
    !projectionContainsAuthorizationId(projection, input.authentication.source.authorizationId) ||
    projection.expiresAtMs <= Date.now()
  ) {
    throw new Error('Owner Wallet Session identity is invalid or expired');
  }
  return await requestWithProjectionV1(context, projection, input);
}

async function requestManagementAsOwnerV1(
  context: WalletHostOwnerAuthorityContextV1,
  input: Parameters<WalletHostManagementRequestV1['request']>[0],
): ReturnType<WalletHostManagementRequestV1['request']> {
  const projection = await requireActiveWalletSessionForWalletV1(context, input.walletId);
  return await requestWithProjectionV1(context, projection, input);
}

async function requireActiveWalletSessionForWalletV1(
  context: WalletHostOwnerAuthorityContextV1,
  walletId: WalletId,
): Promise<ActiveWalletSessionAuthorizationProjection> {
  const read = await context.walletSessions.readActiveForWallet(walletId);
  // One error per cause: this gate fails for reasons with different remedies
  // (unlock again, versus stale local rows from an older build), and a single
  // message made them indistinguishable in the field.
  switch (read.kind) {
    case 'found':
      break;
    case 'missing':
      throw walletUnlockRequiredV1();
    case 'corrupt':
      throw new Error(
        'Stored owner Wallet Session state is corrupt for this wallet — lock and unlock to replace it',
      );
    case 'persistence_unavailable':
      throw new Error('Owner Wallet Session storage is unavailable');
    default:
      read satisfies never;
      throw new Error('Unsupported owner Wallet Session read result');
  }
  if (read.projection.status !== 'active' || read.projection.expiresAtMs <= Date.now()) {
    throw walletUnlockRequiredV1();
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
): Omit<
  Awaited<ReturnType<DeviceLinkingOwnerAuthorizationPortV1['authenticateOwnerForLinkingV1']>>,
  'ed25519ExportRootCapability' | 'exportRootRequirement'
> {
  const record = exactRecord(raw, [
    'authentication',
    'walletId',
    'ownerAuthorization',
    'orderedOwnerSourceLaneHints',
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
  const orderedOwnerSourceLaneHints = parseNonEmptyArray(
    record.orderedOwnerSourceLaneHints,
    parseLinkedDeviceOwnerSourceLaneV1,
    'orderedOwnerSourceLaneHints',
  );
  return {
    authentication,
    walletId: walletId.value,
    ownerAuthorization,
    orderedOwnerSourceLaneHints,
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
  if (source.kind !== 'wallet_session') {
    throw new Error('Owner authorization did not return a Wallet Session source');
  }
  if (source.walletSessionId !== projection.walletSessionId) {
    throw new Error('Owner authorization Wallet Session id changed');
  }
  if (!projectionContainsAuthorizationId(projection, source.authorizationId)) {
    throw new Error('Owner authorization id changed');
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
