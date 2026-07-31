import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import {
  normalizeInteger,
  normalizeOptionalNonEmptyString,
  normalizePositiveInteger,
} from '@shared/utils/normalize';
import {
  parseEmailOtpWalletAuthAuthority,
} from '@shared/utils/walletAuthAuthority';
import type { SigningSessionSealAuthMethod } from '@shared/utils/signingSessionSeal';
import { SIGNER_AUTH_METHODS } from '@shared/utils/signerDomain';
import { toAccountId, type AccountId, type StrictAccountId } from '@/core/types/accountIds';
import type {
  Ed25519LaneCandidate,
  LaneCandidateState,
  ThresholdEcdsaEmailOtpAuthContext,
  EmailOtpAuthUse,
  ThresholdEd25519SessionStoreSource,
} from '../identity/laneIdentity';
import {
  buildEmailOtpAuthContext,
  emailOtpAuthContextProvider,
  emailOtpAuthContextProviderUserId,
  emailOtpAuthContextRetention,
  laneCandidateStateFromRuntimePolicy,
} from '../identity/laneIdentity';
import type { EmailOtpAuthPolicy } from '@/core/types/seams';
import {
  parseRouterAbEd25519NormalSigningState,
  type RouterAbEd25519NormalSigningState,
} from '../../threshold/ed25519/routerAbNormalSigningState';
import {
  toWalletId,
  type WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  nearEd25519SigningKeyIdFromString,
  parseNearEd25519SigningKeyId,
  type NearEd25519SigningKeyId,
} from '@shared/utils/registrationIntent';
import { parseSignerSlot, type SignerSlot } from '@shared/utils/signerSlot';
import { toRpId } from '../identity/evmFamilyEcdsaIdentity';
import {
  type ExactEd25519SigningLaneIdentity,
} from '../identity/exactSigningLaneIdentity';
import {
  signingLaneAuthMethod,
  type SigningLaneAuthBinding,
} from '../identity/signingLaneAuthBinding';
import {
  SigningSessionIds,
  type ThresholdEd25519SessionId,
  type SigningGrantId,
} from '../operationState/types';
import {
  normalizeThresholdRuntimePolicyScope,
  type ThresholdRuntimePolicyScope,
} from '../../threshold/sessionPolicy';
import { signingRootScopeFromRuntimePolicyScope } from '@shared/threshold/signingRootScope';

// Raw persistence boundary shape. Core code uses ThresholdEd25519SessionRecord.
export type ThresholdEd25519SessionRow = {
  walletId: WalletId;
  nearAccountId: AccountId;
  nearEd25519SigningKeyId: NearEd25519SigningKeyId;
  rpId: string;
  passkeyCredentialIdB64u?: string;
  relayerUrl: string;
  relayerKeyId: string;
  participantIds: number[];
  signingRootId?: string;
  signingRootVersion?: string;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  signerSlot: number;
  routerAbNormalSigning: RouterAbEd25519NormalSigningState;
  thresholdSessionKind: 'jwt' | 'cookie';
  thresholdSessionId: string;
  signingGrantId?: string;
  walletSessionJwt?: string;
  expiresAtMs: number;
  remainingUses: number;
  emailOtpAuthContext?: ThresholdEcdsaEmailOtpAuthContext;
  updatedAtMs: number;
  source: ThresholdEd25519SessionStoreSource;
};

export type ThresholdEd25519SessionRecord = ThresholdEd25519SessionRow;

function nullableRecordInteger(value: unknown): number | null {
  const normalized = normalizeInteger(value);
  return normalized == null ? null : normalized;
}

const inMemoryEd25519RecordsByAccount = new Map<string, ThresholdEd25519SessionRecord>();
const inMemoryEd25519AccountBySessionId = new Map<string, string>();
const inMemoryEd25519RecordsByWallet = new Map<string, ThresholdEd25519SessionRecord>();
const inMemoryEd25519WalletBySessionId = new Map<string, string>();
const inMemoryEd25519RecordsByLane = new Map<string, ThresholdEd25519SessionRecord>();
const inMemoryEd25519LaneBySessionId = new Map<string, string>();

function normalizeStoredRuntimePolicyScope(
  obj: Record<string, unknown>,
): ThresholdRuntimePolicyScope | undefined {
  if (Object.prototype.hasOwnProperty.call(obj, 'runtimeSnapshotScope')) {
    throw new Error('Invalid threshold session record: stale runtimeSnapshotScope');
  }
  if (Object.prototype.hasOwnProperty.call(obj, 'runtimePolicyScope')) {
    const runtimePolicyScope = normalizeThresholdRuntimePolicyScope(obj.runtimePolicyScope);
    if (!runtimePolicyScope) {
      throw new Error('Invalid threshold session record: stale runtimePolicyScope');
    }
    return runtimePolicyScope;
  }
  return undefined;
}

function normalizeEmailOtpAuthContext(
  value: unknown,
): ThresholdEcdsaEmailOtpAuthContext {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('Invalid Email OTP auth context: missing context');
  }
  const obj = value as Record<string, unknown>;
  const policyRaw = String(obj.policy || '')
    .trim()
    .toLowerCase();
  if (policyRaw !== 'session' && policyRaw !== 'per_operation') {
    throw new Error('Invalid Email OTP auth context: invalid policy');
  }
  const policy: EmailOtpAuthPolicy = policyRaw;
  const authMethodRaw = String(obj.authMethod || '')
    .trim()
    .toLowerCase();
  if (authMethodRaw !== 'email_otp') {
    throw new Error('Invalid Email OTP auth context: invalid authMethod');
  }
  if (Object.prototype.hasOwnProperty.call(obj, 'authSubjectId')) {
    throw new Error('Invalid Email OTP auth context: deleted authSubjectId');
  }
  if (Object.prototype.hasOwnProperty.call(obj, 'retention')) {
    throw new Error('Invalid Email OTP auth context: deleted retention');
  }
  if (Object.prototype.hasOwnProperty.call(obj, 'reason')) {
    throw new Error('Invalid Email OTP auth context: deleted reason');
  }
  if (Object.prototype.hasOwnProperty.call(obj, 'consumedAtMs')) {
    throw new Error('Invalid Email OTP auth context: deleted consumedAtMs');
  }
  const authority = parseEmailOtpWalletAuthAuthority(obj.authority);
  if (!authority) {
    throw new Error('Invalid Email OTP auth context: invalid wallet auth authority');
  }
  const use = normalizeEmailOtpAuthUse(obj.use);
  switch (use.kind) {
    case 'session':
      return buildEmailOtpAuthContext({
        policy,
        retention: 'session',
        reason: use.reason,
        authority,
      });
    case 'single_use_pending':
      return buildEmailOtpAuthContext({
        policy,
        retention: 'single_use',
        authority,
      });
    case 'single_use_consumed':
      return buildEmailOtpAuthContext({
        policy,
        retention: 'single_use',
        authority,
        consumedAtMs: use.consumedAtMs,
      });
  }
  use satisfies never;
  throw new Error('Invalid Email OTP auth context: unsupported use');
}

function normalizeEmailOtpAuthUse(value: unknown): EmailOtpAuthUse {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('Invalid Email OTP auth context: missing use');
  }
  const obj = value as Record<string, unknown>;
  const kind = String(obj.kind || '')
    .trim()
    .toLowerCase();
  const reason = String(obj.reason || '')
    .trim()
    .toLowerCase();
  switch (kind) {
    case 'session':
      if (reason !== 'login' && reason !== 'sign') {
        throw new Error('Invalid Email OTP auth context: invalid session use reason');
      }
      return { kind: 'session', reason };
    case 'single_use_pending':
      if (Object.prototype.hasOwnProperty.call(obj, 'reason')) {
        throw new Error('Invalid Email OTP auth context: pending single-use reason is deleted');
      }
      return { kind: 'single_use_pending' };
    case 'single_use_consumed': {
      if (Object.prototype.hasOwnProperty.call(obj, 'reason')) {
        throw new Error('Invalid Email OTP auth context: consumed single-use reason is deleted');
      }
      const consumedAtMs = normalizePositiveInteger(obj.consumedAtMs);
      if (!consumedAtMs) {
        throw new Error('Invalid Email OTP auth context: missing consumedAtMs');
      }
      return { kind: 'single_use_consumed', consumedAtMs };
    }
  }
  throw new Error('Invalid Email OTP auth context: invalid use kind');
}

function parseThresholdEd25519SessionIdentity(obj: Record<string, unknown>): {
  walletId: ReturnType<typeof toWalletId>;
  nearAccountId: ReturnType<typeof toAccountId>;
  nearEd25519SigningKeyId: ReturnType<typeof nearEd25519SigningKeyIdFromString>;
} {
  const nearAccountIdRaw = String(obj.nearAccountId || '').trim();
  const walletIdRaw = String(obj.walletId || '').trim();
  const nearEd25519SigningKeyIdRaw = String(obj.nearEd25519SigningKeyId || '').trim();
  if (!walletIdRaw || !nearAccountIdRaw || !nearEd25519SigningKeyIdRaw) {
    throw new Error('Invalid threshold Ed25519 canonical session record: missing identity binding');
  }
  return {
    walletId: toWalletId(walletIdRaw),
    nearAccountId: toAccountId(nearAccountIdRaw),
    nearEd25519SigningKeyId: nearEd25519SigningKeyIdFromString(nearEd25519SigningKeyIdRaw),
  };
}

function normalizeThresholdEd25519SessionRecord(value: unknown): ThresholdEd25519SessionRecord {
  const obj = value && typeof value === 'object' ? (value as Record<string, unknown>) : {};
  const { walletId, nearAccountId, nearEd25519SigningKeyId } =
    parseThresholdEd25519SessionIdentity(obj);
  const rpId = String(obj.rpId || '').trim();
  const passkeyCredentialIdB64u = normalizeOptionalNonEmptyString(obj.passkeyCredentialIdB64u);
  const relayerUrl = String(obj.relayerUrl || '').trim();
  const relayerKeyId = String(obj.relayerKeyId || '').trim();
  const participantIds = normalizeThresholdEd25519ParticipantIds(obj.participantIds);
  const runtimePolicyScope = normalizeStoredRuntimePolicyScope(obj);
  const scopeBinding = runtimePolicyScope
    ? signingRootScopeFromRuntimePolicyScope(runtimePolicyScope)
    : null;
  const explicitSigningRootId = normalizeOptionalNonEmptyString(obj.signingRootId);
  const explicitSigningRootVersion = normalizeOptionalNonEmptyString(obj.signingRootVersion);
  const scopeSigningRootId = normalizeOptionalNonEmptyString(scopeBinding?.signingRootId);
  const scopeSigningRootVersion = normalizeOptionalNonEmptyString(scopeBinding?.signingRootVersion);
  if (explicitSigningRootId && scopeSigningRootId && explicitSigningRootId !== scopeSigningRootId) {
    throw new Error('Invalid threshold Ed25519 canonical session record: signingRootId mismatch');
  }
  if (
    explicitSigningRootVersion &&
    scopeSigningRootVersion &&
    explicitSigningRootVersion !== scopeSigningRootVersion
  ) {
    throw new Error(
      'Invalid threshold Ed25519 canonical session record: signingRootVersion mismatch',
    );
  }
  const signingRootId = explicitSigningRootId || scopeSigningRootId || '';
  const signingRootVersion = explicitSigningRootVersion || scopeSigningRootVersion || '';
  const signerSlot = normalizeInteger(obj.signerSlot);
  const routerAbNormalSigning = parseRouterAbEd25519NormalSigningState(obj.routerAbNormalSigning);
  const thresholdSessionKindRaw = String(obj.thresholdSessionKind || 'jwt')
    .trim()
    .toLowerCase();
  const thresholdSessionKind: 'jwt' | 'cookie' =
    thresholdSessionKindRaw === 'cookie' ? 'cookie' : 'jwt';
  const thresholdSessionId = String(obj.thresholdSessionId || '').trim();
  const signingGrantId = normalizeOptionalNonEmptyString(obj.signingGrantId);
  const walletSessionJwt = normalizeOptionalNonEmptyString(obj.walletSessionJwt);
  const expiresAtMs = normalizeInteger(obj.expiresAtMs);
  const remainingUses = normalizeInteger(obj.remainingUses);
  const updatedAtMs = normalizeInteger(obj.updatedAtMs) || Date.now();
  const sourceRaw = String(obj.source || '').trim();
  const source: ThresholdEd25519SessionStoreSource =
    sourceRaw === 'login' ||
    sourceRaw === 'registration' ||
    sourceRaw === 'add-signer' ||
    sourceRaw === 'manual-connect' ||
    sourceRaw === 'bootstrap' ||
    sourceRaw === 'email_otp'
      ? sourceRaw
      : 'manual-connect';
  const emailOtpAuthContext =
    source === 'email_otp'
      ? normalizeEmailOtpAuthContext(obj.emailOtpAuthContext)
      : null;

  if (!rpId || !relayerUrl || !relayerKeyId || !participantIds || !thresholdSessionId) {
    throw new Error('Invalid threshold Ed25519 canonical session record');
  }
  if (thresholdSessionKind === 'jwt' && !walletSessionJwt) {
    throw new Error('Invalid threshold Ed25519 canonical session record: missing walletSessionJwt');
  }
  if (expiresAtMs == null || expiresAtMs <= 0) {
    throw new Error('Invalid threshold Ed25519 canonical session record: missing expiresAtMs');
  }
  if (remainingUses == null || remainingUses < 0) {
    throw new Error('Invalid threshold Ed25519 canonical session record: missing remainingUses');
  }
  if (signerSlot == null || signerSlot <= 0) {
    throw new Error('Invalid threshold Ed25519 canonical session record: missing signerSlot');
  }
  if (!routerAbNormalSigning) {
    throw new Error(
      'Invalid threshold Ed25519 canonical session record: missing routerAbNormalSigning',
    );
  }
  return {
    walletId,
    nearAccountId,
    nearEd25519SigningKeyId,
    rpId,
    ...(passkeyCredentialIdB64u ? { passkeyCredentialIdB64u } : {}),
    relayerUrl,
    relayerKeyId,
    participantIds,
    ...(signingRootId ? { signingRootId } : {}),
    ...(signingRootVersion ? { signingRootVersion } : {}),
    ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
    signerSlot,
    routerAbNormalSigning,
    thresholdSessionKind,
    thresholdSessionId,
    ...(signingGrantId ? { signingGrantId } : {}),
    ...(walletSessionJwt ? { walletSessionJwt } : {}),
    expiresAtMs,
    remainingUses,
    ...(emailOtpAuthContext ? { emailOtpAuthContext } : {}),
    updatedAtMs,
    source,
  };
}

function forgetStaleInMemoryThresholdEd25519LaneForSession(args: {
  thresholdSessionId: string;
  currentLaneKey: string | null;
}): void {
  const thresholdSessionId = String(args.thresholdSessionId || '').trim();
  if (!thresholdSessionId) return;
  const currentLaneKey = String(args.currentLaneKey || '').trim();
  const indexedLaneKey = String(
    inMemoryEd25519LaneBySessionId.get(thresholdSessionId) || '',
  ).trim();
  if (!indexedLaneKey || indexedLaneKey === currentLaneKey) return;
  const indexedLaneRecord = inMemoryEd25519RecordsByLane.get(indexedLaneKey) || null;
  if (
    indexedLaneRecord &&
    String(indexedLaneRecord.thresholdSessionId || '').trim() === thresholdSessionId
  ) {
    inMemoryEd25519RecordsByLane.delete(indexedLaneKey);
  }
  inMemoryEd25519LaneBySessionId.delete(thresholdSessionId);
}

type Ed25519DefaultRecordPolicy = 'prefer_incoming' | 'prefer_current_generation';

function thresholdSessionRecordGeneration(record: {
  updatedAtMs?: number | null;
  expiresAtMs?: number | null;
}): number | null {
  const updatedAtGeneration = Math.floor(Number(record.updatedAtMs) || 0);
  if (Number.isFinite(updatedAtGeneration) && updatedAtGeneration > 0) {
    return updatedAtGeneration;
  }
  const generation = Math.floor(Number(record.expiresAtMs) || 0);
  return Number.isFinite(generation) && generation > 0 ? generation : null;
}

function shouldReplaceDefaultThresholdSessionRecord(args: {
  existing:
    | { thresholdSessionId?: string; updatedAtMs?: number | null; expiresAtMs?: number | null }
    | null
    | undefined;
  incoming: {
    thresholdSessionId?: string;
    updatedAtMs?: number | null;
    expiresAtMs?: number | null;
  };
  policy: Ed25519DefaultRecordPolicy;
}): boolean {
  if (args.policy === 'prefer_incoming') return true;
  const existing = args.existing;
  if (!existing) return true;
  const existingSessionId = String(existing.thresholdSessionId || '').trim();
  const incomingSessionId = String(args.incoming.thresholdSessionId || '').trim();
  if (existingSessionId && existingSessionId === incomingSessionId) return true;
  const existingGeneration = thresholdSessionRecordGeneration(existing);
  const incomingGeneration = thresholdSessionRecordGeneration(args.incoming);
  if (!existingGeneration && incomingGeneration) return true;
  if (existingGeneration && incomingGeneration) return incomingGeneration > existingGeneration;
  return !existingGeneration && !incomingGeneration;
}

function rememberInMemoryThresholdEd25519Record(
  record: ThresholdEd25519SessionRecord,
  defaultPolicy: Ed25519DefaultRecordPolicy = 'prefer_incoming',
): void {
  const accountKey = String(record.nearAccountId || '').trim();
  const walletKey = String(record.walletId || '').trim();
  const thresholdSessionId = String(record.thresholdSessionId || '').trim();
  if (!accountKey || !walletKey || !thresholdSessionId) return;
  const laneKey = getThresholdEd25519SessionLaneKeyForRecord(record);
  forgetStaleInMemoryThresholdEd25519LaneForSession({
    thresholdSessionId,
    currentLaneKey: laneKey,
  });

  // The account index tracks the default lane; the lane/session indexes retain
  // exact in-flight sessions so concurrent step-up operations cannot displace
  // each other's planned material.
  const previous = inMemoryEd25519RecordsByAccount.get(accountKey);
  if (
    shouldReplaceDefaultThresholdSessionRecord({
      existing: previous,
      incoming: record,
      policy: defaultPolicy,
    })
  ) {
    const previousSessionId = String(previous?.thresholdSessionId || '').trim();
    if (previousSessionId && previousSessionId !== thresholdSessionId) {
      inMemoryEd25519AccountBySessionId.delete(previousSessionId);
    }
    inMemoryEd25519RecordsByAccount.set(accountKey, record);
    inMemoryEd25519AccountBySessionId.set(thresholdSessionId, accountKey);
  }
  const previousWallet = inMemoryEd25519RecordsByWallet.get(walletKey);
  if (
    shouldReplaceDefaultThresholdSessionRecord({
      existing: previousWallet,
      incoming: record,
      policy: defaultPolicy,
    })
  ) {
    const previousWalletSessionId = String(previousWallet?.thresholdSessionId || '').trim();
    if (previousWalletSessionId && previousWalletSessionId !== thresholdSessionId) {
      inMemoryEd25519WalletBySessionId.delete(previousWalletSessionId);
    }
    inMemoryEd25519RecordsByWallet.set(walletKey, record);
    inMemoryEd25519WalletBySessionId.set(thresholdSessionId, walletKey);
  }

  if (!laneKey) return;
  const previousLaneRecord = inMemoryEd25519RecordsByLane.get(laneKey);
  const previousLaneSessionId = String(previousLaneRecord?.thresholdSessionId || '').trim();
  if (previousLaneSessionId && previousLaneSessionId !== thresholdSessionId) {
    inMemoryEd25519LaneBySessionId.delete(previousLaneSessionId);
  }
  inMemoryEd25519RecordsByLane.set(laneKey, record);
  inMemoryEd25519LaneBySessionId.set(thresholdSessionId, laneKey);
}

function getInMemoryThresholdEd25519SessionRecordForAccount(
  nearAccountIdRaw: AccountId | string,
): ThresholdEd25519SessionRecord | null {
  try {
    const accountKey = String(toAccountId(nearAccountIdRaw)).trim();
    return inMemoryEd25519RecordsByAccount.get(accountKey) || null;
  } catch {
    return null;
  }
}

function getInMemoryThresholdEd25519SessionRecordForWallet(
  walletIdRaw: WalletId | string,
): ThresholdEd25519SessionRecord | null {
  try {
    const walletKey = String(toWalletId(walletIdRaw)).trim();
    return inMemoryEd25519RecordsByWallet.get(walletKey) || null;
  } catch {
    return null;
  }
}

function getInMemoryThresholdEd25519SessionRecordByThresholdSessionId(
  thresholdSessionIdRaw: string,
): ThresholdEd25519SessionRecord | null {
  const thresholdSessionId = String(thresholdSessionIdRaw || '').trim();
  if (!thresholdSessionId) return null;

  const indexedLaneKey = String(
    inMemoryEd25519LaneBySessionId.get(thresholdSessionId) || '',
  ).trim();
  if (indexedLaneKey) {
    const indexedLaneRecord = inMemoryEd25519RecordsByLane.get(indexedLaneKey) || null;
    if (
      indexedLaneRecord &&
      String(indexedLaneRecord.thresholdSessionId || '').trim() === thresholdSessionId
    ) {
      return indexedLaneRecord;
    }
    inMemoryEd25519LaneBySessionId.delete(thresholdSessionId);
  }

  const indexedWalletKey = String(
    inMemoryEd25519WalletBySessionId.get(thresholdSessionId) || '',
  ).trim();
  if (indexedWalletKey) {
    const indexedWalletRecord = inMemoryEd25519RecordsByWallet.get(indexedWalletKey) || null;
    if (
      indexedWalletRecord &&
      String(indexedWalletRecord.thresholdSessionId || '').trim() === thresholdSessionId
    ) {
      return indexedWalletRecord;
    }
    inMemoryEd25519WalletBySessionId.delete(thresholdSessionId);
  }

  const indexedAccountKey = String(
    inMemoryEd25519AccountBySessionId.get(thresholdSessionId) || '',
  ).trim();
  if (indexedAccountKey) {
    const indexedRecord = inMemoryEd25519RecordsByAccount.get(indexedAccountKey) || null;
    if (
      indexedRecord &&
      String(indexedRecord.thresholdSessionId || '').trim() === thresholdSessionId
    ) {
      return indexedRecord;
    }
    inMemoryEd25519AccountBySessionId.delete(thresholdSessionId);
  }

  for (const [accountKey, record] of inMemoryEd25519RecordsByAccount.entries()) {
    if (String(record.thresholdSessionId || '').trim() !== thresholdSessionId) continue;
    inMemoryEd25519AccountBySessionId.set(thresholdSessionId, accountKey);
    return record;
  }

  for (const [walletKey, record] of inMemoryEd25519RecordsByWallet.entries()) {
    if (String(record.thresholdSessionId || '').trim() !== thresholdSessionId) continue;
    inMemoryEd25519WalletBySessionId.set(thresholdSessionId, walletKey);
    return record;
  }

  return null;
}

export type ThresholdEd25519SessionUpsertInput = {
  walletId: WalletId | string;
  nearAccountId: AccountId | string;
  nearEd25519SigningKeyId: NearEd25519SigningKeyId | string;
  rpId: string;
  passkeyCredentialIdB64u?: string;
  relayerUrl: string;
  relayerKeyId: string;
  participantIds: number[];
  signingRootId?: string;
  signingRootVersion?: string;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  signerSlot: number;
  routerAbNormalSigning: RouterAbEd25519NormalSigningState;
  thresholdSessionKind?: 'jwt' | 'cookie';
  thresholdSessionId: string;
  signingGrantId?: string;
  walletSessionJwt?: string;
  expiresAtMs: number;
  remainingUses: number;
  emailOtpAuthContext?: ThresholdEcdsaEmailOtpAuthContext;
  updatedAtMs?: number;
  source?: ThresholdEd25519SessionStoreSource;
};

function forgetInMemoryThresholdEd25519Record(record: ThresholdEd25519SessionRecord): void {
  const accountKey = String(record.nearAccountId || '').trim();
  const walletKey = String(record.walletId || '').trim();
  const thresholdSessionId = normalizeOptionalNonEmptyString(record.thresholdSessionId);
  if (accountKey) {
    const currentAccountRecord = inMemoryEd25519RecordsByAccount.get(accountKey) || null;
    if (
      currentAccountRecord &&
      String(currentAccountRecord.thresholdSessionId || '').trim() === thresholdSessionId
    ) {
      inMemoryEd25519RecordsByAccount.delete(accountKey);
    }
  }
  if (
    thresholdSessionId &&
    inMemoryEd25519AccountBySessionId.get(thresholdSessionId) === accountKey
  ) {
    inMemoryEd25519AccountBySessionId.delete(thresholdSessionId);
  }
  if (walletKey) {
    const currentWalletRecord = inMemoryEd25519RecordsByWallet.get(walletKey) || null;
    if (
      currentWalletRecord &&
      String(currentWalletRecord.thresholdSessionId || '').trim() === thresholdSessionId
    ) {
      inMemoryEd25519RecordsByWallet.delete(walletKey);
    }
  }
  if (
    thresholdSessionId &&
    inMemoryEd25519WalletBySessionId.get(thresholdSessionId) === walletKey
  ) {
    inMemoryEd25519WalletBySessionId.delete(thresholdSessionId);
  }
  const laneKey = getThresholdEd25519SessionLaneKeyForRecord(record);
  if (laneKey) {
    const currentLaneRecord = inMemoryEd25519RecordsByLane.get(laneKey) || null;
    if (
      currentLaneRecord &&
      String(currentLaneRecord.thresholdSessionId || '').trim() === thresholdSessionId
    ) {
      inMemoryEd25519RecordsByLane.delete(laneKey);
    }
  }
  if (
    thresholdSessionId &&
    laneKey &&
    inMemoryEd25519LaneBySessionId.get(thresholdSessionId) === laneKey
  ) {
    inMemoryEd25519LaneBySessionId.delete(thresholdSessionId);
  }
}

type ThresholdEd25519SessionAuthMethod = SigningSessionSealAuthMethod;

export type ThresholdEd25519SessionRecordKey = {
  walletId: WalletId;
  nearAccountId: StrictAccountId;
  nearEd25519SigningKeyId: NearEd25519SigningKeyId;
  authMethod: ThresholdEd25519SessionAuthMethod;
  signingGrantId: SigningGrantId;
  thresholdSessionId: ThresholdEd25519SessionId;
  signerSlot: SignerSlot;
};

export type ThresholdEd25519SessionRecordKeyInput = {
  walletId: unknown;
  nearAccountId: unknown;
  nearEd25519SigningKeyId: unknown;
  authMethod: ThresholdEd25519SessionAuthMethod;
  signingGrantId: unknown;
  thresholdSessionId: unknown;
  signerSlot: unknown;
};

function thresholdEd25519AuthMethodForRecord(
  record: ThresholdEd25519SessionRecord,
): ThresholdEd25519SessionAuthMethod {
  const source = record.source;
  switch (source) {
    case SIGNER_AUTH_METHODS.emailOtp:
      return SIGNER_AUTH_METHODS.emailOtp;
    case 'login':
    case 'registration':
    case 'add-signer':
    case 'manual-connect':
    case 'bootstrap':
      return SIGNER_AUTH_METHODS.passkey;
    default:
      source satisfies never;
      throw new Error(
        `[SigningEngine] unsupported threshold Ed25519 session source: ${String(source)}`,
      );
  }
}

function thresholdEd25519AuthBindingForRecord(
  record: ThresholdEd25519SessionRecord,
): SigningLaneAuthBinding {
  if (record.source === 'email_otp') {
    const providerSubjectId = record.emailOtpAuthContext
      ? emailOtpAuthContextProviderUserId(record.emailOtpAuthContext)
      : '';
    if (!providerSubjectId) {
      throw new Error('[SigningEngine] Email OTP Ed25519 record is missing auth subject');
    }
    return {
      kind: 'email_otp',
      providerSubjectId,
    };
  }
  const credentialIdB64u = normalizeOptionalNonEmptyString(record.passkeyCredentialIdB64u);
  if (!credentialIdB64u) {
    throw new Error('[SigningEngine] passkey Ed25519 record is missing credential id');
  }
  return {
    kind: 'passkey',
    rpId: toRpId(record.rpId),
    credentialIdB64u,
  };
}

export function thresholdEd25519LaneCandidateFromSessionRecord(args: {
  record: ThresholdEd25519SessionRecord;
  nowMs?: number;
}): Ed25519LaneCandidate | null {
  const signingGrantId = normalizeOptionalNonEmptyString(args.record.signingGrantId);
  if (!signingGrantId) return null;
  const signerSlot = normalizeInteger(args.record.signerSlot);
  if (signerSlot == null || signerSlot < 1) return null;
  return {
    kind: 'lane_candidate',
    walletId: args.record.walletId,
    nearAccountId: args.record.nearAccountId,
    nearEd25519SigningKeyId: args.record.nearEd25519SigningKeyId,
    signerSlot,
    auth: thresholdEd25519AuthBindingForRecord(args.record),
    curve: 'ed25519',
    chain: 'near',
    signingGrantId,
    thresholdSessionId: args.record.thresholdSessionId,
    state: laneCandidateStateFromRuntimePolicy({
      remainingUses: args.record.remainingUses,
      expiresAtMs: args.record.expiresAtMs,
      nowMs: args.nowMs,
    }),
    remainingUses: nullableRecordInteger(args.record.remainingUses),
    expiresAtMs: nullableRecordInteger(args.record.expiresAtMs),
    updatedAtMs: nullableRecordInteger(args.record.updatedAtMs),
    source: 'runtime_session_record',
  };
}

export function serializeThresholdEd25519SessionLaneKey(args: {
  walletId: WalletId;
  nearAccountId: StrictAccountId;
  nearEd25519SigningKeyId: NearEd25519SigningKeyId;
  authMethod: ThresholdEd25519SessionAuthMethod;
  signingGrantId: SigningGrantId;
  thresholdSessionId: ThresholdEd25519SessionId;
  signerSlot: SignerSlot;
}): string {
  const walletId = String(args.walletId).trim();
  const nearAccountId = String(args.nearAccountId).trim();
  const nearEd25519SigningKeyId = String(args.nearEd25519SigningKeyId).trim();
  const authMethod = args.authMethod;
  const signingGrantId = String(args.signingGrantId).trim();
  const thresholdSessionId = String(args.thresholdSessionId).trim();
  const signerSlot = args.signerSlot;
  if (
    !walletId ||
    !nearAccountId ||
    !nearEd25519SigningKeyId ||
    (authMethod !== 'email_otp' && authMethod !== 'passkey') ||
    !signingGrantId ||
    !thresholdSessionId ||
    signerSlot == null ||
    signerSlot < 1
  ) {
    throw new Error('[SigningEngine] invalid threshold Ed25519 lane key input');
  }
  return [
    encodeLaneToken(walletId),
    encodeLaneToken(nearAccountId),
    encodeLaneToken(nearEd25519SigningKeyId),
    encodeLaneToken(authMethod),
    encodeLaneToken(signingGrantId),
    encodeLaneToken(thresholdSessionId),
    encodeLaneToken(String(signerSlot)),
  ].join('|');
}

export function buildThresholdEd25519SessionRecordKey(
  args: ThresholdEd25519SessionRecordKeyInput,
): ThresholdEd25519SessionRecordKey {
  const signerSlot = parseSignerSlot(args.signerSlot);
  if (!signerSlot) {
    throw new Error('[SigningEngine] invalid threshold Ed25519 lane signerSlot');
  }
  if (typeof args.nearAccountId !== 'string') {
    throw new Error('[SigningEngine] invalid threshold Ed25519 lane nearAccountId');
  }
  if (args.authMethod !== 'email_otp' && args.authMethod !== 'passkey') {
    throw new Error('[SigningEngine] invalid threshold Ed25519 lane authMethod');
  }
  return {
    walletId: toWalletId(args.walletId),
    nearAccountId: toAccountId(args.nearAccountId),
    nearEd25519SigningKeyId: parseNearEd25519SigningKeyId(args.nearEd25519SigningKeyId),
    authMethod: args.authMethod,
    signingGrantId: SigningSessionIds.signingGrant(args.signingGrantId),
    thresholdSessionId: SigningSessionIds.thresholdEd25519Session(args.thresholdSessionId),
    signerSlot,
  };
}

export function thresholdEd25519SessionRecordKeyFromRecord(
  record: ThresholdEd25519SessionRecord,
): ThresholdEd25519SessionRecordKey | null {
  try {
    return buildThresholdEd25519SessionRecordKey({
      walletId: record.walletId,
      nearAccountId: record.nearAccountId,
      nearEd25519SigningKeyId: record.nearEd25519SigningKeyId,
      authMethod: thresholdEd25519AuthMethodForRecord(record),
      signingGrantId: record.signingGrantId,
      thresholdSessionId: record.thresholdSessionId,
      signerSlot: record.signerSlot,
    });
  } catch {
    return null;
  }
}

export function thresholdEd25519SessionRecordKeyFromExactIdentity(
  identity: ExactEd25519SigningLaneIdentity,
): ThresholdEd25519SessionRecordKey {
  const signer = identity.signer;
  return buildThresholdEd25519SessionRecordKey({
    walletId: signer.account.wallet.walletId,
    nearAccountId: signer.account.nearAccountId,
    nearEd25519SigningKeyId: signer.nearEd25519SigningKeyId,
    authMethod: signingLaneAuthMethod(identity.auth),
    signingGrantId: identity.signingGrantId,
    thresholdSessionId: identity.thresholdSessionId,
    signerSlot: signer.signerSlot,
  });
}

function getThresholdEd25519SessionLaneKeyForRecord(
  record: ThresholdEd25519SessionRecord,
): string | null {
  const key = thresholdEd25519SessionRecordKeyFromRecord(record);
  return key ? serializeThresholdEd25519SessionLaneKey(key) : null;
}

function storeThresholdEd25519SessionFact(args: {
  record: ThresholdEd25519SessionRecord;
  defaultPolicy: Ed25519DefaultRecordPolicy;
}): ThresholdEd25519SessionRecord {
  rememberInMemoryThresholdEd25519Record(args.record, args.defaultPolicy);
  return args.record;
}

function thresholdEd25519RecordMatchesLane(
  record: ThresholdEd25519SessionRecord,
  lane: ThresholdEd25519SessionRecordKey,
): boolean {
  return (
    String(record.walletId) === String(lane.walletId) &&
    String(record.nearAccountId) === String(lane.nearAccountId) &&
    String(record.nearEd25519SigningKeyId) === String(lane.nearEd25519SigningKeyId) &&
    thresholdEd25519AuthMethodForRecord(record) === lane.authMethod &&
    String(record.signingGrantId || '').trim() === String(lane.signingGrantId) &&
    String(record.thresholdSessionId || '').trim() === String(lane.thresholdSessionId) &&
    Number(record.signerSlot) === lane.signerSlot
  );
}

function encodeLaneToken(value: string): string {
  return encodeURIComponent(String(value || '').trim());
}

function decodeLaneToken(value: string): string | null {
  try {
    const decoded = decodeURIComponent(String(value || '').trim());
    return decoded || null;
  } catch {
    return null;
  }
}

export function buildThresholdEd25519SessionFact(
  args: ThresholdEd25519SessionUpsertInput,
): ThresholdEd25519SessionRecord | null {
  const nearAccountId = toAccountId(args.nearAccountId);
  const rawWalletId = String(args.walletId || '').trim();
  const rawNearEd25519SigningKeyId = String(args.nearEd25519SigningKeyId || '').trim();
  if (!rawWalletId || !rawNearEd25519SigningKeyId) {
    throw new Error(
      'Threshold Ed25519 session persistence requires walletId and nearEd25519SigningKeyId',
    );
  }
  const walletId = toWalletId(rawWalletId);
  const nearEd25519SigningKeyId = nearEd25519SigningKeyIdFromString(rawNearEd25519SigningKeyId);
  const signerSlot = Math.floor(Number(args.signerSlot) || 0);
  return normalizeThresholdEd25519SessionRecord({
    walletId,
    nearAccountId,
    nearEd25519SigningKeyId,
    rpId: String(args.rpId || '').trim(),
    ...(String(args.passkeyCredentialIdB64u || '').trim()
      ? { passkeyCredentialIdB64u: String(args.passkeyCredentialIdB64u || '').trim() }
      : {}),
    relayerUrl: String(args.relayerUrl || '').trim(),
    relayerKeyId: String(args.relayerKeyId || '').trim(),
    participantIds: args.participantIds,
    ...(String(args.signingRootId || '').trim()
      ? { signingRootId: String(args.signingRootId || '').trim() }
      : {}),
    ...(String(args.signingRootVersion || '').trim()
      ? { signingRootVersion: String(args.signingRootVersion || '').trim() }
      : {}),
    ...(args.runtimePolicyScope ? { runtimePolicyScope: args.runtimePolicyScope } : {}),
    signerSlot,
    routerAbNormalSigning: args.routerAbNormalSigning,
    thresholdSessionKind: String(args.thresholdSessionKind || 'jwt')
      .trim()
      .toLowerCase(),
    thresholdSessionId: String(args.thresholdSessionId || '').trim(),
    ...(String(args.signingGrantId || '').trim()
      ? { signingGrantId: String(args.signingGrantId || '').trim() }
      : {}),
    ...(String(args.walletSessionJwt || '').trim()
      ? { walletSessionJwt: String(args.walletSessionJwt || '').trim() }
      : {}),
    expiresAtMs: Math.floor(Number(args.expiresAtMs) || 0),
    remainingUses: Math.floor(Number(args.remainingUses) || 0),
    ...(args.emailOtpAuthContext ? { emailOtpAuthContext: args.emailOtpAuthContext } : {}),
    updatedAtMs: Math.floor(Number(args.updatedAtMs ?? Date.now()) || 0),
    source: args.source || 'manual-connect',
  });
}

export function upsertThresholdEd25519SessionFact(
  args: ThresholdEd25519SessionUpsertInput,
): ThresholdEd25519SessionRecord | null {
  const record = buildThresholdEd25519SessionFact(args);
  if (!record) return null;
  return storeThresholdEd25519SessionFact({
    record,
    defaultPolicy: 'prefer_current_generation',
  });
}

// Broad Ed25519 wallet/account readers expose default/discovery records only.
// Authority-bearing mutations must use exact lane-key helpers.
export function getStoredThresholdEd25519SessionRecordForAccount(
  nearAccountIdRaw: AccountId | string,
): ThresholdEd25519SessionRecord | null {
  const inMemory = getInMemoryThresholdEd25519SessionRecordForAccount(nearAccountIdRaw);
  if (inMemory) return inMemory;
  return null;
}

export function getStoredThresholdEd25519SessionRecordForWallet(
  walletIdRaw: WalletId | string,
): ThresholdEd25519SessionRecord | null {
  const inMemory = getInMemoryThresholdEd25519SessionRecordForWallet(walletIdRaw);
  if (inMemory) return inMemory;
  return null;
}

export function listStoredThresholdEd25519SessionLaneRecordsForWallet(
  walletIdRaw: WalletId | string,
): ThresholdEd25519SessionRecord[] {
  try {
    const walletKey = String(toWalletId(walletIdRaw)).trim();
    if (!walletKey) return [];
    const recordsBySessionId = new Map<string, ThresholdEd25519SessionRecord>();
    const add = (record: ThresholdEd25519SessionRecord | null): void => {
      if (!record) return;
      if (String(record.walletId || '').trim() !== walletKey) return;
      const thresholdSessionId = String(record.thresholdSessionId || '').trim();
      if (!thresholdSessionId) return;
      recordsBySessionId.set(thresholdSessionId, record);
    };
    add(inMemoryEd25519RecordsByWallet.get(walletKey) || null);
    for (const record of inMemoryEd25519RecordsByLane.values()) {
      add(record);
    }
    return [...recordsBySessionId.values()].sort(
      (left, right) =>
        Math.floor(Number(right.updatedAtMs) || 0) - Math.floor(Number(left.updatedAtMs) || 0),
    );
  } catch {
    return [];
  }
}

export function getStoredThresholdEd25519SessionRecordForLane(args: {
  walletId: WalletId | string;
  nearAccountId: AccountId | string;
  nearEd25519SigningKeyId: NearEd25519SigningKeyId | string;
  authMethod: ThresholdEd25519SessionAuthMethod;
  signingGrantId: SigningGrantId | string;
  thresholdSessionId: ThresholdEd25519SessionId | string;
  signerSlot: unknown;
}): ThresholdEd25519SessionRecord | null {
  let lane: ThresholdEd25519SessionRecordKey;
  let laneKey: string;
  try {
    lane = buildThresholdEd25519SessionRecordKey(args);
    laneKey = serializeThresholdEd25519SessionLaneKey(lane);
  } catch {
    return null;
  }
  const record = inMemoryEd25519RecordsByLane.get(laneKey) || null;
  if (record && thresholdEd25519RecordMatchesLane(record, lane)) return record;
  if (record) {
    inMemoryEd25519RecordsByLane.delete(laneKey);
    const thresholdSessionId = String(record.thresholdSessionId || '').trim();
    if (thresholdSessionId && inMemoryEd25519LaneBySessionId.get(thresholdSessionId) === laneKey) {
      inMemoryEd25519LaneBySessionId.delete(thresholdSessionId);
    }
  }
  return null;
}

export type ClearStoredThresholdEd25519SessionRecordForLaneKeyResult =
  | { readonly ok: true; readonly cleared: boolean }
  | {
      readonly ok: false;
      readonly code: 'mismatched_record';
      readonly message: string;
    };

export function clearStoredThresholdEd25519SessionRecordForLaneKey(
  lane: ThresholdEd25519SessionRecordKey,
): ClearStoredThresholdEd25519SessionRecordForLaneKeyResult {
  const laneKey = serializeThresholdEd25519SessionLaneKey(lane);
  const record = inMemoryEd25519RecordsByLane.get(laneKey) || null;
  if (!record) return { ok: true, cleared: false };
  if (!thresholdEd25519RecordMatchesLane(record, lane)) {
    return {
      ok: false,
      code: 'mismatched_record',
      message: '[SigningEngine] threshold Ed25519 lane clear refused mismatched record',
    };
  }
  forgetInMemoryThresholdEd25519Record(record);
  return { ok: true, cleared: true };
}

export function markThresholdEd25519EmailOtpSessionConsumedForWallet(args: {
  walletId: WalletId;
  thresholdSessionId: string;
  uses?: number;
  nowMs?: number;
}): ThresholdEd25519SessionRecord | null {
  const record = getStoredThresholdEd25519SessionRecordForWallet(args.walletId);
  if (!record || record.source !== 'email_otp' || !record.emailOtpAuthContext) return null;
  const expectedSessionId = String(args.thresholdSessionId).trim();
  const actualSessionId = String(record.thresholdSessionId || '').trim();
  if (!expectedSessionId || !actualSessionId || expectedSessionId !== actualSessionId) {
    return null;
  }
  const nowMs = Math.max(0, Math.floor(Number(args.nowMs ?? Date.now()) || 0));
  const uses = Math.max(1, Math.floor(Number(args.uses) || 1));
  const remainingUses = Math.max(0, Math.floor(Number(record.remainingUses) || 0) - uses);
  return upsertThresholdEd25519SessionFact({
    walletId: record.walletId,
    nearAccountId: record.nearAccountId,
    nearEd25519SigningKeyId: record.nearEd25519SigningKeyId,
    rpId: record.rpId,
    relayerUrl: record.relayerUrl,
    relayerKeyId: record.relayerKeyId,
    participantIds: record.participantIds,
    ...(record.runtimePolicyScope ? { runtimePolicyScope: record.runtimePolicyScope } : {}),
    signerSlot: record.signerSlot,
    routerAbNormalSigning: record.routerAbNormalSigning,
    thresholdSessionKind: record.thresholdSessionKind,
    thresholdSessionId: record.thresholdSessionId,
    ...(record.signingGrantId ? { signingGrantId: record.signingGrantId } : {}),
    ...(record.walletSessionJwt ? { walletSessionJwt: record.walletSessionJwt } : {}),
    expiresAtMs: record.expiresAtMs,
    remainingUses,
    emailOtpAuthContext: buildEmailOtpAuthContext({
      policy: record.emailOtpAuthContext.policy,
      retention: 'single_use',
      authority: record.emailOtpAuthContext.authority,
      consumedAtMs: nowMs,
    }),
    updatedAtMs: nowMs,
    source: 'email_otp',
  });
}

export function getStoredThresholdEd25519SessionRecordByThresholdSessionId(
  thresholdSessionIdRaw: string,
): ThresholdEd25519SessionRecord | null {
  const thresholdSessionId = String(thresholdSessionIdRaw || '').trim();
  if (!thresholdSessionId) return null;
  const inMemory = getInMemoryThresholdEd25519SessionRecordByThresholdSessionId(thresholdSessionId);
  if (inMemory) return inMemory;
  return null;
}

export function clearAllStoredThresholdEd25519SessionRecords(): void {
  inMemoryEd25519RecordsByAccount.clear();
  inMemoryEd25519AccountBySessionId.clear();
  inMemoryEd25519RecordsByWallet.clear();
  inMemoryEd25519WalletBySessionId.clear();
  inMemoryEd25519RecordsByLane.clear();
  inMemoryEd25519LaneBySessionId.clear();
}
