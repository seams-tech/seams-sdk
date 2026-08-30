import {
  parseMpcWalletSigningQuotaId,
  parseReusableWalletSessionMintId,
  parseWalletSessionAuthorizationId,
  parseWalletSessionId,
  type MpcWalletSigningQuotaId,
  type ReusableWalletSessionMintId,
  type WalletSessionAuthorizationId,
  type WalletSessionId,
} from './capabilityKinds';
import {
  parseWalletAuthMethodId,
  parseWalletAuthorityId,
  parseWalletId,
  type WalletAuthMethodId,
  type WalletAuthorityId,
  type WalletId,
} from '../utils/domainIds';
import { isPlainObject } from '../utils/validation';

/**
 * The identity left by a committed issuance whose primary credential cannot
 * be returned. It is deliberately separate from any active session record:
 * this value authorizes exact-method recovery, never an operation.
 */
export type WalletSessionCommittedIdentityV1 = {
  readonly kind: 'already_committed_wallet_session_v1';
  readonly walletId: WalletId;
  readonly authorityId: WalletAuthorityId;
  readonly walletAuthMethodId: WalletAuthMethodId;
  readonly mintId: ReusableWalletSessionMintId;
  readonly authorizationId: WalletSessionAuthorizationId;
  readonly walletSessionId: WalletSessionId;
  readonly quotaId: MpcWalletSigningQuotaId;
};

/** The credential-free retry signal shared by issuer response boundaries. */
export type WalletSessionAlreadyCommittedResponseV1 = {
  readonly ok: false;
  readonly code: 'already_committed';
  readonly message: string;
  readonly next: 'unlock_exact_method';
  readonly committed: WalletSessionCommittedIdentityV1;
};

const COMMITTED_IDENTITY_FIELDS = [
  'kind',
  'walletId',
  'authorityId',
  'walletAuthMethodId',
  'mintId',
  'authorizationId',
  'walletSessionId',
  'quotaId',
] as const;

const NESTED_RESPONSE_FIELDS = ['ok', 'code', 'message', 'next', 'committed'] as const;

const FLAT_RESPONSE_FIELDS = [
  'ok',
  'code',
  'message',
  'next',
  'kind',
  'walletId',
  'authorityId',
  'walletAuthMethodId',
  'mintId',
  'authorizationId',
  'walletSessionId',
  'quotaId',
] as const;

const UNLOCK_FLAT_RESPONSE_FIELDS = [...FLAT_RESPONSE_FIELDS, 'unlocked', 'unlockBackend'] as const;

function hasOnlyFields(record: Record<string, unknown>, fields: readonly string[]): boolean {
  const actual = Object.keys(record);
  return actual.length === new Set(fields).size && actual.every((field) => fields.includes(field));
}

function parseCommittedIdentity(value: unknown): WalletSessionCommittedIdentityV1 | null {
  if (!isPlainObject(value) || !hasOnlyFields(value, COMMITTED_IDENTITY_FIELDS)) return null;
  if (value.kind !== 'already_committed_wallet_session_v1') return null;
  const walletId = parseWalletId(value.walletId);
  const authorityId = parseWalletAuthorityId(value.authorityId);
  const walletAuthMethodId = parseWalletAuthMethodId(value.walletAuthMethodId);
  const mintId = parseReusableWalletSessionMintId(value.mintId);
  const authorizationId = parseWalletSessionAuthorizationId(value.authorizationId);
  const walletSessionId = parseWalletSessionId(value.walletSessionId);
  const quotaId = parseMpcWalletSigningQuotaId(value.quotaId);
  if (
    !walletId.ok ||
    !authorityId.ok ||
    !walletAuthMethodId.ok ||
    !mintId.ok ||
    !authorizationId.ok ||
    !walletSessionId.ok ||
    !quotaId.ok
  ) {
    return null;
  }
  return {
    kind: 'already_committed_wallet_session_v1',
    walletId: walletId.value,
    authorityId: authorityId.value,
    walletAuthMethodId: walletAuthMethodId.value,
    mintId: mintId.value,
    authorizationId: authorizationId.value,
    walletSessionId: walletSessionId.value,
    quotaId: quotaId.value,
  };
}

function parseResponseEnvelope(
  value: Record<string, unknown>,
): Omit<WalletSessionAlreadyCommittedResponseV1, 'committed'> | null {
  if (
    value.ok !== false ||
    value.code !== 'already_committed' ||
    typeof value.message !== 'string' ||
    value.next !== 'unlock_exact_method'
  ) {
    return null;
  }
  return {
    ok: false,
    code: 'already_committed',
    message: value.message,
    next: 'unlock_exact_method',
  };
}

function parseFlatCommittedIdentity(
  value: Record<string, unknown>,
): WalletSessionCommittedIdentityV1 | null {
  if (
    !hasOnlyFields(value, FLAT_RESPONSE_FIELDS) &&
    !hasOnlyFields(value, UNLOCK_FLAT_RESPONSE_FIELDS)
  ) {
    return null;
  }
  if (
    hasOnlyFields(value, UNLOCK_FLAT_RESPONSE_FIELDS) &&
    (value.unlocked !== false ||
      (value.unlockBackend !== 'passkey' && value.unlockBackend !== 'email_otp'))
  ) {
    return null;
  }
  if (value.kind !== 'already_committed') return null;
  return parseCommittedIdentity({
    kind: 'already_committed_wallet_session_v1',
    walletId: value.walletId,
    authorityId: value.authorityId,
    walletAuthMethodId: value.walletAuthMethodId,
    mintId: value.mintId,
    authorizationId: value.authorizationId,
    walletSessionId: value.walletSessionId,
    quotaId: value.quotaId,
  });
}

function buildAlreadyCommittedResponse(
  envelope: Omit<WalletSessionAlreadyCommittedResponseV1, 'committed'>,
  committed: WalletSessionCommittedIdentityV1,
): WalletSessionAlreadyCommittedResponseV1 {
  return {
    ok: false,
    code: 'already_committed',
    message: envelope.message,
    next: 'unlock_exact_method',
    committed,
  };
}

export function parseWalletSessionAlreadyCommittedResponseV1(
  value: unknown,
): WalletSessionAlreadyCommittedResponseV1 | null {
  if (!isPlainObject(value)) return null;
  const envelope = parseResponseEnvelope(value);
  if (!envelope) return null;
  if (!hasOnlyFields(value, NESTED_RESPONSE_FIELDS)) return null;
  const committed = parseCommittedIdentity(value.committed);
  return committed ? buildAlreadyCommittedResponse(envelope, committed) : null;
}

export function parseWalletUnlockAlreadyCommittedResponseV1(
  value: unknown,
): WalletSessionAlreadyCommittedResponseV1 | null {
  if (!isPlainObject(value)) return null;
  const envelope = parseResponseEnvelope(value);
  if (!envelope) return null;
  const committed = parseFlatCommittedIdentity(value);
  return committed ? buildAlreadyCommittedResponse(envelope, committed) : null;
}
