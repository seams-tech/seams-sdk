/**
 * NEAR RPC helpers
 *
 * This file centralizes helper calls made to the NEAR RPC (account existence checks,
 * access key polling, tx context fetch, etc).
 *
 * App session minting in SDK login flows is exchange-first (`POST /session/exchange`)
 * for BYO auth integration.
 */

import type { NearClient } from './NearClient';
import type { AccountId } from '../../types/accountIds';
import type { WebAuthnAuthenticationCredential } from '../../types/webauthn';
import type { ManagedRuntimeScopeBootstrap } from '../../config/managedRuntimeScope';

import { TransactionContext } from '../../types/rpc';
import { errorMessage } from '@shared/utils/errors';
import {
  joinNormalizedUrl,
  normalizeJwtCookieSessionKind,
  stripTrailingSlashes,
} from '@shared/utils/normalize';
import { ensureEd25519Prefix, isObject, requireTrimmedString } from '@shared/utils/validation';
import { redactCredentialExtensionOutputs } from '../../signingEngine/webauthnAuth/credentials/credentialExtensions';
import {
  parseRouterAbEcdsaPostRegistrationSessionActivationRequestV1,
  parseRouterAbEcdsaPostRegistrationSessionActivationResponseV1,
  type RouterAbEcdsaPostRegistrationSessionActivationRequestV1,
  type RouterAbEcdsaPostRegistrationSessionActivationResponseV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import {
  parseEd25519YaoRecoveryCapabilityV1,
  type ParsedYaoRecoveryCapabilityV1,
} from '../../signingEngine/flows/recovery/passkeyEd25519YaoRecovery';
import {
  parsePasskeyCustodyEnvelopeRecord,
  type PasskeyCustodyEnvelopeRecord,
} from '@shared/passkey-custody';

export async function fetchNonceBlockHashAndHeight({
  nearClient,
  nearPublicKeyStr,
  nearAccountId,
}: {
  nearClient: NearClient;
  nearPublicKeyStr: string;
  nearAccountId: AccountId;
}): Promise<TransactionContext> {
  // Get access key and transaction block info concurrently
  const [accessKeyInfo, txBlockInfo] = await Promise.all([
    nearClient.viewAccessKey(nearAccountId, nearPublicKeyStr).catch((e) => {
      throw new Error(`Failed to fetch Access Key`);
    }),
    nearClient.viewBlock({ finality: 'final' }).catch((e) => {
      throw new Error(`Failed to fetch Block Info`);
    }),
  ]);
  if (!accessKeyInfo || accessKeyInfo.nonce === undefined) {
    throw new Error(
      `Access key not found or invalid for account ${nearAccountId} with public key ${nearPublicKeyStr}. Response: ${JSON.stringify(accessKeyInfo)}`,
    );
  }
  const nextNonce = (BigInt(accessKeyInfo.nonce) + BigInt(1)).toString();
  const txBlockHeight = String(txBlockInfo.header.height);
  const txBlockHash = txBlockInfo.header.hash; // Keep original base58 string

  return {
    nearPublicKeyStr,
    accessKeyInfo,
    nextNonce,
    txBlockHeight,
    txBlockHash,
  };
}

// ===========================
// ACCESS KEY HELPERS
// ===========================

export type AccessKeyWaitOptions = {
  attempts?: number;
  delayMs?: number;
};

function sleep(ms: number): Promise<void> {
  return new Promise((res) => setTimeout(res, ms));
}

function isAccessKeyNotFoundError(err: unknown): boolean {
  const msg = String(errorMessage(err) || '').toLowerCase();
  if (!msg) return false;

  // Common NEAR node / near-api-js phrasing for missing access keys.
  if (
    msg.includes('unknown access key') ||
    msg.includes('unknown_access_key') ||
    msg.includes('unknownaccesskey')
  ) {
    return true;
  }
  if (msg.includes('accesskeydoesnotexist')) return true;
  if (msg.includes('access key does not exist')) return true;
  if (msg.includes("access key doesn't exist")) return true;
  if (msg.includes('access key not found')) return true;
  if (msg.includes('no such access key')) return true;
  if (
    msg.includes('viewing access key') &&
    msg.includes('does not exist') &&
    !msg.includes('account')
  )
    return true;

  return false;
}

export async function hasAccessKey(
  nearClient: NearClient,
  nearAccountId: string,
  publicKey: string,
  opts?: AccessKeyWaitOptions,
): Promise<boolean> {
  const expected = ensureEd25519Prefix(publicKey);
  if (!expected) return false;

  const attempts = Math.max(1, Math.floor(opts?.attempts ?? 6));
  const delayMs = Math.max(50, Math.floor(opts?.delayMs ?? 750));

  for (let i = 0; i < attempts; i++) {
    try {
      await nearClient.viewAccessKey(nearAccountId, expected);
      return true;
    } catch {
      // tolerate transient view errors during propagation; retry
    }
    if (i < attempts - 1) {
      await sleep(delayMs);
    }
  }
  return false;
}

export async function waitForAccessKeyAbsent(
  nearClient: NearClient,
  nearAccountId: string,
  publicKey: string,
  opts?: AccessKeyWaitOptions,
): Promise<boolean> {
  const expected = ensureEd25519Prefix(publicKey);
  if (!expected) return true;

  const attempts = Math.max(1, Math.floor(opts?.attempts ?? 6));
  const delayMs = Math.max(50, Math.floor(opts?.delayMs ?? 650));

  for (let i = 0; i < attempts; i++) {
    try {
      await nearClient.viewAccessKey(nearAccountId, expected);
    } catch (err: unknown) {
      if (isAccessKeyNotFoundError(err)) return true;
      // tolerate transient view errors during propagation; retry
    }
    if (i < attempts - 1) {
      await sleep(delayMs);
    }
  }
  return false;
}

// ===========================
// ACCOUNT HELPERS
// ===========================

/**
 * Best-effort on-chain account existence check.
 *
 * Used to short-circuit UX flows (e.g. registration) before prompting the user.
 * Returns `false` on unknown/non-deterministic failures so that downstream flows
 * can rely on the Router API/contract for final enforcement.
 */
export async function checkNearAccountExistsBestEffort(
  nearClient: NearClient,
  nearAccountId: string,
  opts?: { attempts?: number; delayMs?: number },
): Promise<boolean> {
  const isNotFound = (m: string) => /does not exist|UNKNOWN_ACCOUNT|unknown\s+account/i.test(m);
  const isRetryable = (m: string) =>
    /server error|internal|temporar|timeout|too many requests|429|empty response|rpc request failed|failed to fetch/i.test(
      m,
    );

  const attempts = Math.max(1, Math.floor(opts?.attempts ?? 2));
  const baseDelayMs = Math.max(50, Math.floor(opts?.delayMs ?? 150));

  for (let i = 1; i <= attempts; i++) {
    try {
      await nearClient.viewAccount(nearAccountId);
      return true;
    } catch (err: unknown) {
      const msg = errorMessage(err);
      const details =
        err && typeof err === 'object' && 'details' in err
          ? (err as { details?: unknown }).details
          : undefined;
      let detailsBlob = '';
      if (details) {
        try {
          detailsBlob = typeof details === 'string' ? details : JSON.stringify(details);
        } catch {
          detailsBlob = '';
        }
      }
      const combined = `${msg}\n${detailsBlob}`.trim();
      if (isNotFound(combined)) return false;
      if (isRetryable(combined) && i < attempts) {
        const backoffMs = baseDelayMs * Math.pow(2, i - 1);
        await sleep(backoffMs);
        continue;
      }
      console.warn(
        `[rpcCalls] Account existence check failed for '${nearAccountId}'; continuing:`,
        err,
      );
      return false;
    }
  }

  return false;
}

export type OidcSessionExchangeInput = {
  type: 'oidc_jwt';
  token: string;
  ecdsaSessionActivation?: never;
};

type PasskeySessionExchangeInputCore = {
  type: 'passkey_assertion';
  challengeId: string;
  webauthn_authentication: WebAuthnAuthenticationCredential;
  expected_origin?: string;
};

export type PasskeySessionExchangeInputWithoutEcdsaActivation = PasskeySessionExchangeInputCore & {
  ecdsaSessionActivation?: never;
};

export type PasskeySessionExchangeInputWithEcdsaActivation = PasskeySessionExchangeInputCore & {
  ecdsaSessionActivation: RouterAbEcdsaPostRegistrationSessionActivationRequestV1;
};

export type SessionExchangeInput =
  | OidcSessionExchangeInput
  | PasskeySessionExchangeInputWithoutEcdsaActivation
  | PasskeySessionExchangeInputWithEcdsaActivation;

type SessionExchangeFailure = {
  success: false;
  jwt?: never;
  sessionUserId?: never;
  sessionExpiresAt?: never;
  ecdsaSession?: never;
  walletCustody?: never;
  error: string;
};

type SessionExchangeSuccessCore = {
  success: true;
  jwt?: string;
  sessionUserId?: string;
  sessionExpiresAt?: string;
  error?: never;
};

export type PasskeySessionCustodyUnlockV1 = {
  readonly kind: 'wallet_custody_passkey_login_v1';
  readonly envelope: PasskeyCustodyEnvelopeRecord;
  readonly storeVersion: string;
  readonly ed25519:
    | { readonly kind: 'absent' }
    | {
        readonly kind: 'active';
        readonly nearAccountId: string;
        readonly nearEd25519SigningKeyId: string;
        readonly signerSlot: number;
        readonly publicKey: string;
        readonly relayerKeyId: string;
        readonly participantIds: readonly [number, number];
        readonly capability: ParsedYaoRecoveryCapabilityV1;
      };
};

export type SessionExchangeSuccessWithoutEcdsaActivation = SessionExchangeSuccessCore & {
  ecdsaSession?: never;
  walletCustody?: never;
};

export type SessionExchangeSuccessWithEcdsaActivation = SessionExchangeSuccessCore & {
  ecdsaSession: RouterAbEcdsaPostRegistrationSessionActivationResponseV1;
  walletCustody: PasskeySessionCustodyUnlockV1;
};

export type PasskeySessionExchangeSuccessWithoutEcdsaActivation = SessionExchangeSuccessCore & {
  ecdsaSession?: never;
  walletCustody: PasskeySessionCustodyUnlockV1;
};

export type SessionExchangeResult =
  | SessionExchangeFailure
  | SessionExchangeSuccessWithoutEcdsaActivation
  | PasskeySessionExchangeSuccessWithoutEcdsaActivation
  | SessionExchangeSuccessWithEcdsaActivation;

export type SessionExchangeResultFor<Input extends SessionExchangeInput> =
  Input extends PasskeySessionExchangeInputWithEcdsaActivation
    ? SessionExchangeFailure | SessionExchangeSuccessWithEcdsaActivation
    : Input extends PasskeySessionExchangeInputWithoutEcdsaActivation
      ? SessionExchangeFailure | PasskeySessionExchangeSuccessWithoutEcdsaActivation
      : SessionExchangeFailure | SessionExchangeSuccessWithoutEcdsaActivation;

export type SessionExchangeRuntimeScope =
  | {
      kind: 'unscoped';
    }
  | ({
      kind: 'managed';
    } & ManagedRuntimeScopeBootstrap);

type SessionExchangeRequestBody =
  | {
      sessionKind: 'jwt' | 'cookie';
      exchange: Record<string, unknown>;
    }
  | {
      sessionKind: 'jwt' | 'cookie';
      exchange: Record<string, unknown>;
      projectEnvironmentId: string;
    };

type SessionExchangeRequestTransport = {
  headers: Record<string, string>;
  body: SessionExchangeRequestBody;
};

function buildSessionExchangeRequestTransport(
  sessionKind: 'jwt' | 'cookie',
  exchange: Record<string, unknown>,
  runtimeScope: SessionExchangeRuntimeScope,
): SessionExchangeRequestTransport {
  switch (runtimeScope.kind) {
    case 'unscoped':
      return {
        headers: { 'Content-Type': 'application/json' },
        body: { sessionKind, exchange },
      };
    case 'managed': {
      const projectEnvironmentId = requireTrimmedString(
        runtimeScope.projectEnvironmentId,
        'runtimeScope.projectEnvironmentId',
      );
      const publishableKey = requireTrimmedString(
        runtimeScope.publishableKey,
        'runtimeScope.publishableKey',
      );
      return {
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${publishableKey}`,
        },
        body: { sessionKind, exchange, projectEnvironmentId },
      };
    }
    default:
      return assertNeverSessionExchangeRuntimeScope(runtimeScope);
  }
}

function assertNeverSessionExchangeRuntimeScope(value: never): never {
  throw new Error(`Unsupported session exchange runtime scope: ${JSON.stringify(value)}`);
}

function parsePasskeySessionCustodyUnlockV1(raw: unknown): PasskeySessionCustodyUnlockV1 {
  if (!isObject(raw) || raw.kind !== 'wallet_custody_passkey_login_v1') {
    throw new Error('Passkey session exchange returned invalid wallet custody unlock data');
  }
  if (!isObject(raw.ed25519)) {
    throw new Error('Passkey session exchange omitted Ed25519 custody continuity');
  }
  if (raw.ed25519.kind === 'absent') {
    return {
      kind: 'wallet_custody_passkey_login_v1',
      envelope: parsePasskeyCustodyEnvelopeRecord(raw.envelope),
      storeVersion: requireTrimmedString(raw.storeVersion, 'walletCustody.storeVersion'),
      ed25519: { kind: 'absent' },
    };
  }
  if (raw.ed25519.kind !== 'active') {
    throw new Error('Passkey session exchange returned invalid Ed25519 custody state');
  }
  const signerSlot = Number(raw.ed25519.signerSlot);
  const participantIds = raw.ed25519.participantIds;
  if (
    !Number.isSafeInteger(signerSlot) ||
    signerSlot < 1 ||
    !Array.isArray(participantIds) ||
    participantIds.length !== 2 ||
    !participantIds.every((value) => Number.isSafeInteger(value) && Number(value) > 0) ||
    participantIds[0] === participantIds[1]
  ) {
    throw new Error('Passkey session exchange returned invalid Ed25519 signer identity');
  }
  return {
    kind: 'wallet_custody_passkey_login_v1',
    envelope: parsePasskeyCustodyEnvelopeRecord(raw.envelope),
    storeVersion: requireTrimmedString(raw.storeVersion, 'walletCustody.storeVersion'),
    ed25519: {
      kind: 'active',
      nearAccountId: requireTrimmedString(
        raw.ed25519.nearAccountId,
        'walletCustody.ed25519.nearAccountId',
      ),
      nearEd25519SigningKeyId: requireTrimmedString(
        raw.ed25519.nearEd25519SigningKeyId,
        'walletCustody.ed25519.nearEd25519SigningKeyId',
      ),
      signerSlot,
      publicKey: requireTrimmedString(
        raw.ed25519.publicKey,
        'walletCustody.ed25519.publicKey',
      ),
      relayerKeyId: requireTrimmedString(
        raw.ed25519.relayerKeyId,
        'walletCustody.ed25519.relayerKeyId',
      ),
      participantIds: [Number(participantIds[0]), Number(participantIds[1])],
      capability: parseEd25519YaoRecoveryCapabilityV1(raw.ed25519.capability),
    },
  };
}

export function exchangeSession<Input extends SessionExchangeInput>(
  relayServerUrl: string,
  routePath: string,
  sessionKind: 'jwt' | 'cookie',
  input: Input,
  runtimeScope: SessionExchangeRuntimeScope,
): Promise<SessionExchangeResultFor<Input>>;
export async function exchangeSession(
  relayServerUrl: string,
  routePath: string,
  sessionKind: 'jwt' | 'cookie',
  input: SessionExchangeInput,
  runtimeScope: SessionExchangeRuntimeScope,
): Promise<SessionExchangeResult> {
  try {
    const exchangeType = String(input?.type || '')
      .trim()
      .toLowerCase();
    let exchangeBody: Record<string, unknown>;

    if (exchangeType === 'oidc_jwt') {
      const token = String((input as { token?: unknown }).token || '').trim();
      if (!token) throw new Error('Missing exchange token');
      exchangeBody = {
        type: 'oidc_jwt',
        token,
      };
    } else if (exchangeType === 'passkey_assertion') {
      const challengeId = String((input as { challengeId?: unknown }).challengeId || '').trim();
      if (!challengeId) throw new Error('Missing passkey challengeId');

      const webauthnAuthentication = (input as { webauthn_authentication?: unknown })
        .webauthn_authentication;
      if (!webauthnAuthentication || typeof webauthnAuthentication !== 'object') {
        throw new Error('Missing webauthn_authentication');
      }

      const expectedOrigin = String(
        (input as { expected_origin?: unknown }).expected_origin || '',
      ).trim();

      exchangeBody = {
        type: 'passkey_assertion',
        challengeId,
        webauthn_authentication: redactCredentialExtensionOutputs(
          webauthnAuthentication as WebAuthnAuthenticationCredential,
        ),
        ...(expectedOrigin ? { expected_origin: expectedOrigin } : {}),
        ...(input.ecdsaSessionActivation
          ? {
              ecdsa_session_activation:
                parseRouterAbEcdsaPostRegistrationSessionActivationRequestV1(
                  input.ecdsaSessionActivation,
                ),
            }
          : {}),
      };
    } else {
      throw new Error('Unsupported exchange.type');
    }

    const normalizedRoutePath = String(routePath || '').trim();
    const path = normalizedRoutePath
      ? normalizedRoutePath.startsWith('/')
        ? normalizedRoutePath
        : `/${normalizedRoutePath}`
      : '/';
    const url = joinNormalizedUrl(relayServerUrl, path);
    const requestTransport = buildSessionExchangeRequestTransport(
      sessionKind,
      exchangeBody,
      runtimeScope,
    );
    const response = await fetch(url, {
      method: 'POST',
      headers: requestTransport.headers,
      credentials: sessionKind === 'cookie' ? 'include' : 'omit',
      body: JSON.stringify(requestTransport.body),
    });

    const dataJson: unknown = await response.json().catch(() => ({}));
    const data: Record<string, unknown> = isObject(dataJson) ? dataJson : {};
    if (!response.ok) {
      return {
        success: false,
        error: typeof data.message === 'string' ? data.message : `HTTP ${response.status}`,
      };
    }
    if (data.ok !== true) {
      return {
        success: false,
        error: typeof data.message === 'string' ? data.message : 'Session exchange failed',
      };
    }

    const sessionObj = isObject(data.session) ? data.session : null;
    const sessionUserId =
      sessionObj && typeof sessionObj.userId === 'string' ? String(sessionObj.userId) : undefined;
    const sessionExpiresAt =
      sessionObj && typeof sessionObj.expiresAt === 'string'
        ? String(sessionObj.expiresAt)
        : undefined;
    const jwt = typeof data.jwt === 'string' ? data.jwt : undefined;
    const requestedEcdsaActivation =
      input.type === 'passkey_assertion' && input.ecdsaSessionActivation !== undefined;
    const walletCustody =
      input.type === 'passkey_assertion'
        ? parsePasskeySessionCustodyUnlockV1(data.walletCustody)
        : undefined;
    let ecdsaSession: RouterAbEcdsaPostRegistrationSessionActivationResponseV1 | undefined;
    if (requestedEcdsaActivation) {
      if (data.ecdsaSession === undefined) {
        throw new Error('Session exchange omitted the requested ECDSA Wallet Session activation');
      }
      ecdsaSession = parseRouterAbEcdsaPostRegistrationSessionActivationResponseV1(
        data.ecdsaSession,
      );
    } else if (data.ecdsaSession !== undefined) {
      throw new Error('Session exchange returned an unrequested ECDSA Wallet Session activation');
    }
    if (ecdsaSession) {
      return {
        success: true,
        ...(sessionUserId ? { sessionUserId } : {}),
        ...(sessionExpiresAt ? { sessionExpiresAt } : {}),
        ...(jwt ? { jwt } : {}),
        ecdsaSession,
        walletCustody,
      };
    }
    if (walletCustody) {
      return {
        success: true,
        ...(sessionUserId ? { sessionUserId } : {}),
        ...(sessionExpiresAt ? { sessionExpiresAt } : {}),
        ...(jwt ? { jwt } : {}),
        walletCustody,
      };
    }
    return {
      success: true,
      ...(sessionUserId ? { sessionUserId } : {}),
      ...(sessionExpiresAt ? { sessionExpiresAt } : {}),
      ...(jwt ? { jwt } : {}),
    };
  } catch (error: unknown) {
    return { success: false, error: errorMessage(error) || 'Failed to exchange session token' };
  }
}

// ===========================
// CONTRACT CALL RESPONSES
// ===========================

export interface CredentialIdsResult {
  credentialIds: string[];
}

export interface AuthenticatorsResult {
  authenticators: Array<[string, ContractStoredAuthenticator]>;
}

// Legacy on-chain authenticator shape (web3authn contract).
// The lite relayer stack no longer stores authenticators on-chain, but some older helpers/tests
// still reference this type via `AuthenticatorsResult`.
export type ContractStoredAuthenticator = Record<string, unknown>;

export type RecoveryAttemptStatus =
  | 'Started'
  | 'VerifyingDkim'
  | 'DkimFailed'
  | 'PolicyFailed'
  | 'Recovering'
  | 'AwaitingMoreEmails'
  | 'Complete'
  | 'Failed';

export type RecoveryAttempt = {
  request_id: string;
  status: RecoveryAttemptStatus | string;
  created_at_ms: number;
  updated_at_ms: number;
  error?: string | null;
  /**
   * 32-byte SHA-256 hash of "<canonical_from>|<account_id_lower>".
   * Returned by newer EmailRecoverer contracts (replaces `from_address`).
   */
  from_address_hash?: number[] | null;
  /** Legacy field (string email address). */
  from_address?: string | null;
  email_timestamp_ms?: number | null;
  newPublicKey?: string | null;
};

function normalizeByteArray(input: unknown): number[] | null | undefined {
  if (input == null) return input as null | undefined;

  if (Array.isArray(input)) {
    return input.map((v) => Number(v)).filter((v) => Number.isFinite(v));
  }

  if (typeof input === 'string' && input) {
    try {
      const bytes =
        typeof Buffer !== 'undefined'
          ? Buffer.from(input, 'base64')
          : Uint8Array.from(atob(input), (c) => c.charCodeAt(0));
      const arr =
        bytes instanceof Uint8Array ? Array.from(bytes) : Array.from(new Uint8Array(bytes));
      return arr;
    } catch {
      return undefined;
    }
  }

  return undefined;
}

export async function getEmailRecoveryAttempt(
  nearClient: NearClient,
  accountId: string,
  requestId: string,
): Promise<RecoveryAttempt | null> {
  const raw = await nearClient.view<
    { request_id: string },
    | (Omit<RecoveryAttempt, 'status' | 'from_address_hash'> & {
        status: unknown;
        from_address_hash?: unknown;
      })
    | null
  >({
    account: accountId,
    method: 'get_recovery_attempt',
    args: { request_id: requestId },
  });

  if (!raw) return null;

  // Normalization logic for status (string or object enum)
  const statusRaw = raw.status;
  const fromAddressHashRaw = raw.from_address_hash;
  const status = (() => {
    if (typeof statusRaw === 'string') return statusRaw.trim();
    if (statusRaw && typeof statusRaw === 'object') {
      const keys = Object.keys(statusRaw as Record<string, unknown>);
      if (keys.length === 1) {
        return String(keys[0] || '').trim();
      }
    }
    return '';
  })();

  const from_address_hash = (() => {
    const normalized = normalizeByteArray(fromAddressHashRaw);
    if (normalized !== undefined) return normalized;
    if (fromAddressHashRaw == null) return fromAddressHashRaw;
    return undefined;
  })();

  return {
    ...raw,
    from_address_hash,
    newPublicKey:
      typeof (raw as Record<string, unknown>).new_public_key === 'string'
        ? String((raw as Record<string, unknown>).new_public_key || '')
        : (raw.newPublicKey ?? null),
    status: status as RecoveryAttemptStatus,
  };
}
