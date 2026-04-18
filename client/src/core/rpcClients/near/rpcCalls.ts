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
import type { PasskeyManagerContext } from '../../TatchiPasskey';
import type { ConfirmationConfig } from '../../types/signer-worker';
import type { FinalExecutionOutcome } from '@near-js/types';

import { TransactionContext } from '../../types/rpc';
import { DEFAULT_WAIT_STATUS } from '../../types/rpc';
import { errorMessage } from '@shared/utils/errors';
import {
  joinNormalizedUrl,
  normalizeJwtCookieSessionKind,
  stripTrailingSlashes,
} from '@shared/utils/normalize';
import { ensureEd25519Prefix, isObject } from '@shared/utils/validation';
import { ActionType } from '../../types/actions';
import { resolvePrimaryNearRpcUrl } from '../../config/chains';
import {
  DeviceLinkingPhase,
  DeviceLinkingStatus,
  type DeviceLinkingSSEEvent,
  ActionPhase,
} from '../../types/sdkSentEvents';
import { redactCredentialExtensionOutputs } from '../../signingEngine/signers/webauthn/credentials';

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
 * can rely on the relay/contract for final enforcement.
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

export type SessionExchangeInput =
  | {
      type: 'oidc_jwt';
      token: string;
    }
  | {
      type: 'passkey_assertion';
      challengeId: string;
      webauthn_authentication: WebAuthnAuthenticationCredential;
      expected_origin?: string;
    };

export async function exchangeSession(
  relayServerUrl: string,
  routePath: string,
  sessionKind: 'jwt' | 'cookie',
  input: SessionExchangeInput,
): Promise<{
  success: boolean;
  jwt?: string;
  sessionUserId?: string;
  sessionExpiresAt?: string;
  error?: string;
}> {
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
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: sessionKind === 'cookie' ? 'include' : 'omit',
      body: JSON.stringify({
        sessionKind,
        exchange: exchangeBody,
      }),
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

export interface DeviceLinkingResult {
  linkedAccountId: string;
  signerSlot: number;
}

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

// ===========================
// DEVICE LINKING TRANSACTION CALLS
// ===========================

/**
 * Execute device1's linking transactions (AddKey + Contract mapping)
 * This function signs and broadcasts both transactions required for device linking
 */
export async function executeDeviceLinkingContractCalls({
  context,
  device1AccountId,
  device2PublicKey,
  onEvent,
  confirmationConfigOverride,
  confirmerText,
}: {
  context: PasskeyManagerContext;
  device1AccountId: AccountId;
  device2PublicKey: string;
  onEvent?: (event: DeviceLinkingSSEEvent) => void;
  confirmationConfigOverride?: Partial<ConfirmationConfig>;
  confirmerText?: { title?: string; body?: string };
}): Promise<{
  addKeyTxResult: FinalExecutionOutcome;
}> {
  const signTransactions = () =>
    context.signingEngine.signNear({
      chain: 'near',
      kind: 'transactionsWithActions',
      args: {
        sessionId:
          typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
            ? `link-device-${crypto.randomUUID()}`
            : `link-device-${Date.now()}-${Math.random().toString(16).slice(2)}`,
        rpcCall: {
          nearRpcUrl: resolvePrimaryNearRpcUrl(
            context.signingEngine.tatchiPasskeyConfigs.network.chains,
          ),
          nearAccountId: device1AccountId,
        },
        confirmationConfigOverride,
        title: confirmerText?.title,
        body: confirmerText?.body,
        transactions: [
          // Transaction 1: AddKey - Add Device2's key to Device1's account
          {
            receiverId: device1AccountId,
            actions: [
              {
                action_type: ActionType.AddKey,
                public_key: device2PublicKey,
                access_key: JSON.stringify({
                  // NEAR-style AccessKey JSON shape, matching near-api-js:
                  // { nonce: number, permission: { FullAccess: {} } }
                  nonce: 0,
                  permission: { FullAccess: {} },
                }),
              },
            ],
          },
        ],
        onEvent: (progress) => {
          // Keep device-linking progress semantic and surface signing as a loading state.
          if (progress.phase == ActionPhase.STEP_6_TRANSACTION_SIGNING_COMPLETE) {
            onEvent?.({
              step: 3,
              phase: DeviceLinkingPhase.STEP_3_AUTHORIZATION,
              status: DeviceLinkingStatus.PROGRESS,
              message: progress.message || 'Transaction signing in progress...',
            });
          }
        },
      },
    });

  // Sign both transactions with one PRF authentication
  const signedTransactions = await signTransactions();

  if (!signedTransactions[0]?.signedTransaction) {
    throw new Error('AddKey transaction signing failed');
  }

  let addKeyTxResult: FinalExecutionOutcome;
  try {
    addKeyTxResult = await context.nearClient.sendTransaction(
      signedTransactions[0].signedTransaction,
      DEFAULT_WAIT_STATUS.linkDeviceAddKey,
    );
  } catch (txError: unknown) {
    throw new Error(`Transaction broadcasting failed: ${errorMessage(txError)}`);
  }

  onEvent?.({
    step: 7,
    phase: DeviceLinkingPhase.STEP_7_LINKING_COMPLETE,
    status: DeviceLinkingStatus.SUCCESS,
    message: `Device key added successfully!`,
  });

  return {
    addKeyTxResult,
  };
}
