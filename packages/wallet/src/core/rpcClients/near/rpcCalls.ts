/**
 * NEAR RPC helpers
 *
 * This file centralizes helper calls made to the NEAR RPC (account existence checks,
 * access key polling, tx context fetch, etc).
 *
 * Wallet unlock verification and NEAR RPC helpers share this transport module.
 */

import type { NearClient } from './NearClient';
import type { AccountId } from '../../types/accountIds';
import type { WebAuthnAuthenticationCredential } from '../../types/webauthn';
import type { ThresholdEcdsaChainTarget } from '../../platform';

import { TransactionContext } from '../../types/rpc';
import { errorMessage } from '@shared/utils/errors';
import { joinNormalizedUrl } from '@shared/utils/normalize';
import { ensureEd25519Prefix, isObject, requireTrimmedString } from '@shared/utils/validation';
import { redactCredentialExtensionOutputs } from '../../signingEngine/webauthnAuth/credentials/credentialExtensions';
import {
  parseRouterAbEcdsaPostRegistrationSessionActivationPolicyV1,
  parseRouterAbEcdsaPostRegistrationSessionActivationResponseV1,
  parseRouterAbEcdsaDerivationPublicCapabilityV1,
  parseRouterAbEcdsaRegistrationActivationReceiptV1,
  type RouterAbEcdsaPostRegistrationSessionActivationPolicyV1,
  type RouterAbEcdsaPostRegistrationSessionActivationResponseV1,
  type RouterAbEcdsaRegistrationActivationReceiptV1,
  type RouterAbEcdsaDerivationPublicCapabilityV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import {
  normalizeRuntimePolicyScope,
  type RuntimePolicyScope,
} from '@shared/threshold/signingRootScope';
import {
  parseEd25519YaoRecoveryCapabilityV1,
  type ParsedYaoRecoveryCapabilityV1,
} from '../../signingEngine/flows/recovery/passkeyEd25519YaoRecovery';
import {
  parsePasskeyCustodyEnvelopeRecord,
  type PasskeyCustodyEnvelopeRecord,
} from '@shared/passkey-custody';
import {
  parseMpcWalletSigningQuotaId,
  parseWalletSessionAuthorizationId,
  parseWalletSessionId,
  type MpcWalletSigningQuotaId,
  type WalletSessionAuthorizationId,
  type WalletSessionId,
} from '@shared/authorization/capabilityKinds';
import {
  parseActiveWalletSessionV1,
  parseWalletSessionOperationCredentialV1,
  type ActiveWalletSessionV1,
  type WalletSessionOperationCredentialV1,
} from '@shared/device-linking';
import {
  parseThresholdEd25519SessionId,
  type ThresholdEd25519SessionId,
} from '@shared/utils/domainIds';
import {
  requireRouterAbEd25519NormalSigningState,
  type RouterAbEd25519NormalSigningState,
} from '@shared/utils/signingSessionSeal';

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

type PasskeyWalletUnlockInputCore = {
  type: 'passkey_assertion';
  challengeId: string;
  webauthn_authentication: WebAuthnAuthenticationCredential;
  ed25519SessionRequest:
    | { readonly kind: 'not_requested' }
    | { readonly kind: 'requested'; readonly remainingUses: number };
  expected_origin?: string;
};

export type PasskeyWalletUnlockInputWithoutEcdsaActivation = PasskeyWalletUnlockInputCore & {
  ecdsaSessionPolicy?: never;
};

export type PasskeyWalletUnlockInputWithEcdsaActivation = PasskeyWalletUnlockInputCore & {
  walletId: string;
  ecdsaSessionPolicy: RouterAbEcdsaPostRegistrationSessionActivationPolicyV1;
};

export type PasskeyWalletUnlockInput =
  | PasskeyWalletUnlockInputWithoutEcdsaActivation
  | PasskeyWalletUnlockInputWithEcdsaActivation;

type WalletUnlockFailure = {
  success: false;
  sessionUserId?: never;
  sessionExpiresAt?: never;
  ecdsaSession?: never;
  ed25519Session?: never;
  walletCustody?: never;
  error: string;
};

type WalletUnlockSuccessCore = {
  success: true;
  ed25519Session: PasskeyWalletUnlockEd25519Session | null;
  sessionUserId?: string;
  sessionExpiresAt?: string;
  error?: never;
};

export type PasskeyWalletUnlockEd25519Session = {
  readonly walletId: string;
  readonly nearAccountId: string;
  readonly nearEd25519SigningKeyId: string;
  readonly relayerKeyId: string;
  readonly participantIds: readonly [number, number];
  readonly thresholdSessionId: ThresholdEd25519SessionId;
  readonly authorizationId: WalletSessionAuthorizationId;
  readonly walletSessionId: WalletSessionId;
  readonly quotaId: MpcWalletSigningQuotaId;
  readonly expiresAtMs: number;
  readonly remainingUses: number;
  readonly runtimePolicyScope: RuntimePolicyScope;
  readonly routerAbNormalSigning: RouterAbEd25519NormalSigningState;
  readonly walletSessionToken: string;
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

export type PasskeySessionEcdsaCustodySignerV1 = {
  readonly chainTarget: ThresholdEcdsaChainTarget;
  readonly walletKey: {
    readonly walletId: string;
    readonly keyHandle: string;
    readonly ecdsaThresholdKeyId: string;
    readonly signingRootId: string;
    readonly signingRootVersion: string;
    readonly relayerKeyId: string;
    readonly contextBinding32B64u: string;
    readonly derivationClientSharePublicKey33B64u: string;
    readonly participantIds: readonly [number, number];
    readonly publicCapability: RouterAbEcdsaDerivationPublicCapabilityV1;
  };
  readonly activationReceipt: RouterAbEcdsaRegistrationActivationReceiptV1;
  readonly runtimePolicyScope: RuntimePolicyScope;
};

export type PasskeySessionEcdsaCustodyContinuityV1 = {
  readonly kind: 'wallet_custody_ecdsa_sync_continuity_v1';
  readonly signers: readonly PasskeySessionEcdsaCustodySignerV1[];
};

export type WalletUnlockSuccessWithoutEcdsaActivation = WalletUnlockSuccessCore & {
  ecdsaSession?: never;
  walletCustody?: never;
};

export type WalletUnlockSuccessWithEcdsaActivation = WalletUnlockSuccessCore & {
  ecdsaSession: RouterAbEcdsaPostRegistrationSessionActivationResponseV1;
  ecdsaActivationReceipt: RouterAbEcdsaRegistrationActivationReceiptV1;
  ecdsaCustody: PasskeySessionEcdsaCustodyContinuityV1;
  walletCustody: PasskeySessionCustodyUnlockV1;
};

export type PasskeyWalletUnlockSuccessWithoutEcdsaActivation = WalletUnlockSuccessCore & {
  ecdsaSession?: never;
  walletCustody: PasskeySessionCustodyUnlockV1;
};

export type WalletUnlockResult =
  | WalletUnlockFailure
  | WalletUnlockSuccessWithoutEcdsaActivation
  | PasskeyWalletUnlockSuccessWithoutEcdsaActivation
  | WalletUnlockSuccessWithEcdsaActivation;

export type WalletUnlockResultFor<Input extends PasskeyWalletUnlockInput> =
  Input extends PasskeyWalletUnlockInputWithEcdsaActivation
    ? WalletUnlockFailure | WalletUnlockSuccessWithEcdsaActivation
    : WalletUnlockFailure | PasskeyWalletUnlockSuccessWithoutEcdsaActivation;

function parsePasskeyWalletCustodyUnlockV1(raw: unknown): PasskeySessionCustodyUnlockV1 {
  if (!isObject(raw) || raw.kind !== 'wallet_custody_passkey_login_v1') {
    throw new Error('Passkey wallet unlock returned invalid custody data');
  }
  if (!isObject(raw.ed25519)) {
    throw new Error('Passkey wallet unlock omitted Ed25519 custody continuity');
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
    throw new Error('Passkey wallet unlock returned invalid Ed25519 custody state');
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
    throw new Error('Passkey wallet unlock returned invalid Ed25519 signer identity');
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
      publicKey: requireTrimmedString(raw.ed25519.publicKey, 'walletCustody.ed25519.publicKey'),
      relayerKeyId: requireTrimmedString(
        raw.ed25519.relayerKeyId,
        'walletCustody.ed25519.relayerKeyId',
      ),
      participantIds: [Number(participantIds[0]), Number(participantIds[1])],
      capability: parseEd25519YaoRecoveryCapabilityV1(raw.ed25519.capability),
    },
  };
}

function parseSessionEcdsaChainTarget(value: unknown): ThresholdEcdsaChainTarget {
  if (!isObject(value)) throw new Error('ECDSA custody chain target is invalid');
  const kind = requireTrimmedString(value.kind, 'ecdsaCustody.chainTarget.kind');
  const chainId = Number(value.chainId);
  const networkSlug = requireTrimmedString(
    value.networkSlug,
    'ecdsaCustody.chainTarget.networkSlug',
  );
  if (!Number.isSafeInteger(chainId) || chainId < 0 || !networkSlug) {
    throw new Error('ECDSA custody chain target is invalid');
  }
  if (kind === 'evm') {
    if (value.namespace !== 'eip155') throw new Error('ECDSA custody EVM namespace is invalid');
    return { kind: 'evm', namespace: 'eip155', chainId, networkSlug };
  }
  if (kind === 'tempo') return { kind: 'tempo', chainId, networkSlug };
  throw new Error('ECDSA custody chain target kind is invalid');
}

function parsePasskeySessionEcdsaCustodyContinuity(
  raw: unknown,
): PasskeySessionEcdsaCustodyContinuityV1 {
  if (!isObject(raw) || raw.kind !== 'wallet_custody_ecdsa_sync_continuity_v1') {
    throw new Error('Passkey wallet unlock returned invalid ECDSA custody continuity');
  }
  if (!Array.isArray(raw.signers)) {
    throw new Error('Passkey wallet unlock returned invalid ECDSA custody signers');
  }
  const signers: PasskeySessionEcdsaCustodySignerV1[] = [];
  for (const value of raw.signers) {
    if (!isObject(value) || !isObject(value.walletKey)) {
      throw new Error('Passkey wallet unlock returned invalid ECDSA custody signer');
    }
    const walletKey = value.walletKey;
    const participantIds = walletKey.participantIds;
    if (
      !Array.isArray(participantIds) ||
      participantIds.length !== 2 ||
      participantIds[0] !== 1 ||
      participantIds[1] !== 2
    ) {
      throw new Error('Passkey wallet unlock returned invalid ECDSA custody participants');
    }
    signers.push({
      chainTarget: parseSessionEcdsaChainTarget(value.chainTarget),
      walletKey: {
        walletId: requireTrimmedString(walletKey.walletId, 'ecdsaCustody.walletKey.walletId'),
        keyHandle: requireTrimmedString(walletKey.keyHandle, 'ecdsaCustody.walletKey.keyHandle'),
        ecdsaThresholdKeyId: requireTrimmedString(
          walletKey.ecdsaThresholdKeyId,
          'ecdsaCustody.walletKey.ecdsaThresholdKeyId',
        ),
        signingRootId: requireTrimmedString(
          walletKey.signingRootId,
          'ecdsaCustody.walletKey.signingRootId',
        ),
        signingRootVersion: requireTrimmedString(
          walletKey.signingRootVersion,
          'ecdsaCustody.walletKey.signingRootVersion',
        ),
        relayerKeyId: requireTrimmedString(
          walletKey.relayerKeyId,
          'ecdsaCustody.walletKey.relayerKeyId',
        ),
        contextBinding32B64u: requireTrimmedString(
          walletKey.contextBinding32B64u,
          'ecdsaCustody.walletKey.contextBinding32B64u',
        ),
        derivationClientSharePublicKey33B64u: requireTrimmedString(
          walletKey.derivationClientSharePublicKey33B64u,
          'ecdsaCustody.walletKey.derivationClientSharePublicKey33B64u',
        ),
        participantIds: [1, 2],
        publicCapability: parseRouterAbEcdsaDerivationPublicCapabilityV1(
          walletKey.publicCapability,
        ),
      },
      activationReceipt: parseRouterAbEcdsaRegistrationActivationReceiptV1(value.activationReceipt),
      runtimePolicyScope: normalizeRuntimePolicyScope(value.runtimePolicyScope),
    });
  }
  if (signers.length === 0) throw new Error('Passkey wallet unlock omitted ECDSA custody signers');
  return { kind: 'wallet_custody_ecdsa_sync_continuity_v1', signers };
}

/**
 * Resolves the Ed25519 session's admitting credential. The response issues one
 * only when it also issued the session; a reused session shares the credential
 * the same response already delivered for that exact Wallet Session.
 */
function requireEd25519SessionOperationCredential(input: {
  readonly raw: Record<string, unknown>;
  readonly walletSessionId: WalletSessionId;
  readonly unlockCredential: unknown;
}): WalletSessionOperationCredentialV1 {
  const sessionKind = input.raw.sessionKind;
  if (sessionKind === 'issued_wallet_session_v1') {
    const issued = parseWalletSessionOperationCredentialV1(input.raw.operationCredential);
    if (issued.walletSessionId !== input.walletSessionId) {
      throw new Error('Wallet unlock Ed25519 credential does not identify its session');
    }
    return issued;
  }
  if (sessionKind !== 'reused_wallet_session_v2') {
    throw new Error('Wallet unlock returned an unsupported Ed25519 session kind');
  }
  if (input.raw.operationCredential !== undefined) {
    throw new Error('Reused Ed25519 Wallet Session must not carry its own credential');
  }
  const reused = parseWalletSessionOperationCredentialV1(input.unlockCredential);
  if (reused.walletSessionId !== input.walletSessionId) {
    throw new Error('Wallet unlock Ed25519 session reuses another Wallet Session');
  }
  return reused;
}

function parsePasskeyWalletUnlockEd25519Session(
  raw: unknown,
  unlockCredential: unknown,
): PasskeyWalletUnlockEd25519Session | null {
  if (raw === null) return null;
  if (!isObject(raw)) throw new Error('Wallet unlock returned invalid Ed25519 session data');
  const thresholdSessionId = parseThresholdEd25519SessionId(raw.thresholdSessionId);
  const authorizationId = parseWalletSessionAuthorizationId(raw.authorizationId);
  const walletSessionId = parseWalletSessionId(raw.walletSessionId);
  const quotaId = parseMpcWalletSigningQuotaId(raw.quotaId);
  const expiresAtMs = Number(raw.expiresAtMs);
  const remainingUses = Number(raw.remainingUses);
  const runtimePolicyScope = normalizeRuntimePolicyScope(raw.runtimePolicyScope);
  const routerAbNormalSigning = requireRouterAbEd25519NormalSigningState(raw.routerAbNormalSigning);
  const participantIds = raw.participantIds;
  if (
    !thresholdSessionId.ok ||
    !authorizationId.ok ||
    !walletSessionId.ok ||
    !quotaId.ok ||
    !Number.isSafeInteger(expiresAtMs) ||
    expiresAtMs <= Date.now() ||
    !Number.isSafeInteger(remainingUses) ||
    remainingUses < 1 ||
    !Array.isArray(participantIds) ||
    participantIds.length !== 2 ||
    !participantIds.every(
      (participantId) => Number.isSafeInteger(participantId) && participantId > 0,
    ) ||
    participantIds[0] === participantIds[1]
  ) {
    throw new Error('Wallet unlock returned invalid Ed25519 session lifecycle');
  }
  const operationCredential = requireEd25519SessionOperationCredential({
    raw,
    walletSessionId: walletSessionId.value,
    unlockCredential,
  });
  return {
    walletId: requireTrimmedString(raw.walletId, 'ed25519Session.walletId'),
    nearAccountId: requireTrimmedString(raw.nearAccountId, 'ed25519Session.nearAccountId'),
    nearEd25519SigningKeyId: requireTrimmedString(
      raw.nearEd25519SigningKeyId,
      'ed25519Session.nearEd25519SigningKeyId',
    ),
    relayerKeyId: requireTrimmedString(raw.relayerKeyId, 'ed25519Session.relayerKeyId'),
    participantIds: [Number(participantIds[0]), Number(participantIds[1])],
    thresholdSessionId: thresholdSessionId.value,
    authorizationId: authorizationId.value,
    walletSessionId: walletSessionId.value,
    quotaId: quotaId.value,
    expiresAtMs,
    remainingUses,
    runtimePolicyScope,
    routerAbNormalSigning,
    walletSessionToken: operationCredential.token,
  };
}

export function verifyPasskeyWalletUnlock<Input extends PasskeyWalletUnlockInput>(
  relayServerUrl: string,
  input: Input,
): Promise<WalletUnlockResultFor<Input>>;
export async function verifyPasskeyWalletUnlock(
  relayServerUrl: string,
  input: PasskeyWalletUnlockInput,
): Promise<WalletUnlockResult> {
  try {
    if (input.type !== 'passkey_assertion') {
      throw new Error('Passkey wallet unlock requires a passkey assertion');
    }
    const challengeId = requireTrimmedString(input.challengeId, 'challengeId');
    const webauthnAuthentication = input.webauthn_authentication;
    const expectedOrigin = String(input.expected_origin || '').trim();
    const body: Record<string, unknown> = {
      unlockBackend: 'passkey',
      challengeId,
      ...('walletId' in input && input.walletId ? { walletId: input.walletId } : {}),
      webauthn_authentication: redactCredentialExtensionOutputs(webauthnAuthentication),
      ed25519SessionRequest: input.ed25519SessionRequest,
      ...(expectedOrigin ? { expected_origin: expectedOrigin } : {}),
      ...(input.ecdsaSessionPolicy
        ? {
            ecdsaSessionPolicy: parseRouterAbEcdsaPostRegistrationSessionActivationPolicyV1(
              input.ecdsaSessionPolicy,
            ),
          }
        : {}),
    };
    const url = joinNormalizedUrl(relayServerUrl, '/wallet/unlock/verify');
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'omit',
      body: JSON.stringify(body),
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
        error:
          typeof data.message === 'string' ? data.message : 'Wallet unlock verification failed',
      };
    }
    const requestedEcdsaActivation =
      input.type === 'passkey_assertion' && input.ecdsaSessionPolicy !== undefined;
    const ed25519Session = parsePasskeyWalletUnlockEd25519Session(
      data.ed25519Session,
      data.operationCredential,
    );
    if (input.ed25519SessionRequest.kind === 'requested' && !ed25519Session) {
      throw new Error('Wallet unlock omitted the requested Ed25519 Wallet Session');
    }
    if (input.ed25519SessionRequest.kind === 'not_requested' && ed25519Session) {
      throw new Error('Wallet unlock returned an unrequested Ed25519 Wallet Session');
    }
    const walletCustody = parsePasskeyWalletCustodyUnlockV1(data.walletCustody);
    let ecdsaSession: RouterAbEcdsaPostRegistrationSessionActivationResponseV1 | undefined;
    let ecdsaActivationReceipt: RouterAbEcdsaRegistrationActivationReceiptV1 | undefined;
    let ecdsaCustody: PasskeySessionEcdsaCustodyContinuityV1 | undefined;
    if (requestedEcdsaActivation) {
      if (data.ecdsaSession === undefined) {
        throw new Error('Wallet unlock omitted the requested ECDSA Wallet Session activation');
      }
      ecdsaSession = parseRouterAbEcdsaPostRegistrationSessionActivationResponseV1(
        data.ecdsaSession,
      );
      if (data.ecdsaActivationReceipt === undefined || data.ecdsaCustody === undefined) {
        throw new Error('Wallet unlock omitted ECDSA custody continuity');
      }
      ecdsaActivationReceipt = parseRouterAbEcdsaRegistrationActivationReceiptV1(
        data.ecdsaActivationReceipt,
      );
      ecdsaCustody = parsePasskeySessionEcdsaCustodyContinuity(data.ecdsaCustody);
      if (!walletCustody) {
        throw new Error('Wallet unlock omitted wallet custody for ECDSA activation');
      }
    } else if (data.ecdsaSession !== undefined) {
      throw new Error('Wallet unlock returned an unrequested ECDSA Wallet Session activation');
    }
    if (ecdsaSession && ecdsaActivationReceipt && ecdsaCustody && walletCustody) {
      return {
        success: true,
        ecdsaSession,
        ecdsaActivationReceipt,
        ecdsaCustody,
        ed25519Session,
        walletCustody,
      };
    }
    if (walletCustody) {
      return {
        success: true,
        ed25519Session,
        walletCustody,
      };
    }
    return {
      success: true,
      ed25519Session,
      walletCustody,
    };
  } catch (error: unknown) {
    return { success: false, error: errorMessage(error) || 'Failed to verify wallet unlock' };
  }
}

export type LinkedDevicePasskeyWalletSessionUnlockInput = {
  readonly challengeId: string;
  readonly webauthn_authentication: WebAuthnAuthenticationCredential;
  readonly ed25519SessionRequest:
    | { readonly kind: 'not_requested' }
    | { readonly kind: 'requested'; readonly remainingUses: number };
  readonly expected_origin?: string;
};

export type LinkedDevicePasskeyWalletSessionUnlockResult =
  | {
      readonly success: false;
      readonly error: string;
    }
  | {
      readonly success: true;
      readonly walletSession: ActiveWalletSessionV1;
      readonly operationCredential: WalletSessionOperationCredentialV1;
      readonly ed25519Session: PasskeyWalletUnlockEd25519Session | null;
    };

/**
 * Verifies a linked-device passkey and returns the exact ordinary Wallet
 * Session issued for its persisted V2 authority. Custody/session bootstrap
 * belongs to the caller's local material opener.
 */
export async function verifyLinkedDevicePasskeyWalletSession(
  relayServerUrl: string,
  input: LinkedDevicePasskeyWalletSessionUnlockInput,
): Promise<LinkedDevicePasskeyWalletSessionUnlockResult> {
  try {
    const challengeId = requireTrimmedString(input.challengeId, 'challengeId');
    const expectedOrigin = String(input.expected_origin || '').trim();
    const body: Record<string, unknown> = {
      unlockBackend: 'passkey',
      challengeId,
      webauthn_authentication: redactCredentialExtensionOutputs(input.webauthn_authentication),
      ed25519SessionRequest: input.ed25519SessionRequest,
      ...(expectedOrigin ? { expected_origin: expectedOrigin } : {}),
    };
    const response = await fetch(joinNormalizedUrl(relayServerUrl, '/wallet/unlock/verify'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'omit',
      body: JSON.stringify(body),
    });
    const dataJson: unknown = await response.json().catch(() => ({}));
    const data: Record<string, unknown> = isObject(dataJson) ? dataJson : {};
    if (!response.ok || data.ok !== true) {
      return {
        success: false,
        error:
          typeof data.message === 'string'
            ? data.message
            : `Wallet Session unlock failed (HTTP ${response.status})`,
      };
    }
    if (data.walletCustody !== undefined && data.walletCustody !== null) {
      throw new Error('Linked passkey unlock returned custody data');
    }
    if (data.ecdsaSession !== undefined && data.ecdsaSession !== null) {
      throw new Error('Linked passkey unlock returned an ECDSA activation');
    }
    const ed25519Session = parsePasskeyWalletUnlockEd25519Session(
      data.ed25519Session,
      data.operationCredential,
    );
    if (input.ed25519SessionRequest.kind === 'requested' && !ed25519Session) {
      throw new Error('Linked passkey unlock omitted the requested Ed25519 Wallet Session');
    }
    if (input.ed25519SessionRequest.kind === 'not_requested' && ed25519Session) {
      throw new Error('Linked passkey unlock returned an unrequested Ed25519 Wallet Session');
    }
    return {
      success: true,
      walletSession: parseActiveWalletSessionV1(data.walletSession),
      operationCredential: parseWalletSessionOperationCredentialV1(data.operationCredential),
      ed25519Session,
    };
  } catch (error: unknown) {
    return {
      success: false,
      error: errorMessage(error) || 'Failed to verify linked passkey Wallet Session',
    };
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
