import {
  parseWalletSessionAuthorizationId,
  parseMpcWalletSigningQuotaId,
  type WalletSessionAuthorizationId,
  parseWalletSessionId,
  type MpcWalletSigningQuotaId,
  type WalletSessionId,
} from '@shared/authorization/capabilityKinds';
import {
  parseMpcMaterialActivationRef,
  parseWalletAuthMethodId,
  parseWalletAuthorityId,
  parseWalletId,
  type WalletAuthMethodId,
  type WalletAuthorityId,
  type WalletId,
} from '@shared/utils/domainIds';
import { parseDigestB64u, type DigestB64u } from '@shared/utils/canonicalPrimitives';
import { SEAMS_WALLET_INDEXES, SEAMS_WALLET_STORES } from '../schemaNames';
import { seamsWalletDB } from '../singletons';
import type { SeamsWalletDBManager } from './manager';
import type {
  ActiveWalletSessionV1,
  WalletSessionOperationCredentialV1,
  WalletCapabilitySubjectV1,
} from '@shared/device-linking/contracts';
import { parseWalletSessionOperationCredentialV1 } from '@shared/device-linking/parsers';
export type {
  ActiveWalletSessionV1,
  WalletSessionOperationCredentialV1,
  WalletCapabilitySubjectV1,
} from '@shared/device-linking/contracts';

export const WALLET_SESSION_AUTHORIZATION_RECORD_VERSION_V6 =
  'wallet_session_authorization_v6' as const;
export type WalletSessionAuthorizationRetirementReason =
  | 'expired'
  | 'exhausted'
  | 'replaced'
  | 'wallet_locked'
  | 'invalidated';

export type RetiredWalletSessionV1 = {
  readonly kind: 'retired_wallet_session_v1';
  readonly walletId: WalletId;
  readonly authorityId: WalletAuthorityId;
  readonly authMethodId: WalletAuthMethodId;
  readonly authorizationId: WalletSessionAuthorizationId;
  readonly quotaId: MpcWalletSigningQuotaId;
  readonly authorityDigestB64u: DigestB64u;
  readonly authorityRevocationEpoch: number;
  readonly capabilitySubjects: readonly [WalletCapabilitySubjectV1, ...WalletCapabilitySubjectV1[]];
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
  readonly retiredAtMs: number;
  readonly retirementReason: WalletSessionAuthorizationRetirementReason;
};

export type WalletSessionAuthorizationRecord = ActiveWalletSessionV1 | RetiredWalletSessionV1;

export type WalletSessionAuthorizationExactOperationCredentialReadResult =
  | {
      readonly kind: 'found';
      readonly record: ActiveWalletSessionV1;
      readonly operationCredential: WalletSessionOperationCredentialV1;
    }
  | {
      readonly kind: 'missing';
      readonly record?: never;
      readonly operationCredential?: never;
    }
  | {
      readonly kind: 'upgrade_required';
      readonly record?: never;
      readonly operationCredential?: never;
    };

export type WalletSessionAuthorizationExactActiveReadResult =
  | Extract<
      WalletSessionAuthorizationExactOperationCredentialReadResult,
      { readonly kind: 'found' | 'missing' | 'upgrade_required' }
    >
  | {
      readonly kind: 'corrupt';
      readonly record?: never;
      readonly operationCredential?: never;
    }
  | {
      readonly kind: 'persistence_unavailable';
      readonly record?: never;
      readonly operationCredential?: never;
    };

export class WalletSessionAuthorizationUpgradeRequiredError extends Error {
  readonly kind = 'upgrade_required';
  readonly code = 'upgrade_required';

  constructor(message: string) {
    super(message);
    this.name = 'WalletSessionAuthorizationUpgradeRequiredError';
  }
}

const STORE = SEAMS_WALLET_STORES.walletSessionAuthorizations;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function hasExactFields(record: Record<string, unknown>, expected: readonly string[]): boolean {
  const fields = Object.keys(record);
  return fields.length === expected.length && fields.every((field) => expected.includes(field));
}

function parseRetirementReason(value: unknown): WalletSessionAuthorizationRetirementReason | null {
  switch (value) {
    case 'expired':
    case 'exhausted':
    case 'replaced':
    case 'wallet_locked':
    case 'invalidated':
      return value;
    default:
      return null;
  }
}

type StoredActiveWalletSessionV6 = ActiveWalletSessionV1 & {
  readonly walletSessionId: WalletSessionId;
};

export type StoredExactWalletSessionAuthorizationRowV6 = {
  readonly record_version: typeof WALLET_SESSION_AUTHORIZATION_RECORD_VERSION_V6;
  readonly wallet_session_id: string;
  readonly authorization_id: string;
  readonly wallet_id: string;
  readonly wallet_authority_id: string;
  readonly wallet_auth_method_id: string;
  readonly authority_digest_b64u: string;
  readonly authority_revocation_epoch: number;
  readonly status: 'active';
  readonly issued_at_ms: number;
  readonly expires_at_ms: number;
  readonly record: StoredActiveWalletSessionV6;
  readonly operation_credential: WalletSessionOperationCredentialV1;
};

const EXACT_ACTIVE_FIELDS = [
  'kind',
  'walletId',
  'authorityId',
  'authMethodId',
  'authorizationId',
  'quotaId',
  'authorityDigestB64u',
  'authorityRevocationEpoch',
  'capabilitySubjects',
  'issuedAtMs',
  'expiresAtMs',
] as const;
const EXACT_RETIRED_FIELDS = [...EXACT_ACTIVE_FIELDS, 'retiredAtMs', 'retirementReason'] as const;
const EXACT_STORED_ROW_V6_FIELDS = [
  'record_version',
  'wallet_session_id',
  'authorization_id',
  'wallet_id',
  'wallet_authority_id',
  'wallet_auth_method_id',
  'authority_digest_b64u',
  'authority_revocation_epoch',
  'status',
  'issued_at_ms',
  'expires_at_ms',
  'record',
  'operation_credential',
] as const;

const FUTURE_WALLET_SESSION_AUTHORIZATION_RECORD_VERSION =
  /^wallet_session_authorization_v([0-9]+)$/;

function isFutureWalletSessionAuthorizationRow(value: unknown): boolean {
  if (!isRecord(value) || typeof value.record_version !== 'string') return false;
  const match = FUTURE_WALLET_SESSION_AUTHORIZATION_RECORD_VERSION.exec(value.record_version);
  if (!match) return false;
  const version = Number(match[1]);
  return Number.isSafeInteger(version) && version > 6;
}

function isKnownLegacyWalletSessionAuthorizationRow(value: unknown): boolean {
  if (!isRecord(value)) return false;
  if (
    value.record_version === 'wallet_session_authorization_v4' ||
    value.record_version === 'wallet_session_authorization_v5'
  ) {
    return true;
  }
  if (Object.prototype.hasOwnProperty.call(value, 'record_version')) return false;
  return isRecord(value.record) && value.record.recordVersion === 'wallet_session_authorization_v3';
}

function isStoredExactWalletSessionAuthorizationRowV6(value: unknown): boolean {
  return isRecord(value) && value.record_version === WALLET_SESSION_AUTHORIZATION_RECORD_VERSION_V6;
}

function futureWalletSessionAuthorizationRowMatchesExactScope(
  value: unknown,
  scope: {
    readonly walletId: WalletId;
    readonly authorityId: WalletAuthorityId;
    readonly authMethodId: WalletAuthMethodId;
  },
): boolean {
  if (!isFutureWalletSessionAuthorizationRow(value) || !isRecord(value)) return false;
  if (value.wallet_id !== scope.walletId) return false;
  if (
    typeof value.wallet_authority_id !== 'string' ||
    typeof value.wallet_auth_method_id !== 'string'
  ) {
    return true;
  }
  return (
    value.wallet_authority_id === scope.authorityId &&
    value.wallet_auth_method_id === scope.authMethodId
  );
}

function isNonNegativeSafeInteger(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

function storedWalletSessionRowKey(value: unknown): string {
  if (!isRecord(value) || typeof value.wallet_session_id !== 'string') {
    throw new Error('Stored Wallet Session authorization key is invalid');
  }
  return value.wallet_session_id;
}

async function settleAbortedTransaction(transaction: {
  readonly done: Promise<unknown>;
}): Promise<void> {
  try {
    await transaction.done;
  } catch {}
}

function walletCapabilitySubjectKey(subject: WalletCapabilitySubjectV1): string {
  switch (subject.kind) {
    case 'sign':
    case 'export_keys':
      return `${subject.kind}:${subject.keyFamily}:${subject.materialActivation.activationId}`;
    case 'link_devices':
    case 'revoke_devices':
      return subject.kind;
    default:
      return assertNeverWalletCapabilitySubject(subject);
  }
}

function assertNeverWalletCapabilitySubject(value: never): never {
  throw new Error(`Unknown Wallet Capability subject: ${String(value)}`);
}

function parseExactWalletCapabilitySubject(value: unknown): WalletCapabilitySubjectV1 | null {
  if (!isRecord(value)) return null;
  if (value.kind === 'sign' || value.kind === 'export_keys') {
    if (!hasExactFields(value, ['kind', 'keyFamily', 'materialActivation'])) return null;
    if (value.keyFamily !== 'ed25519' && value.keyFamily !== 'ecdsa_secp256k1') return null;
    const activation = parseMpcMaterialActivationRef(value.materialActivation);
    if (!activation.ok) return null;
    return {
      kind: value.kind,
      keyFamily: value.keyFamily,
      materialActivation: activation.value,
    };
  }
  if (value.kind === 'link_devices' || value.kind === 'revoke_devices') {
    return hasExactFields(value, ['kind']) ? { kind: value.kind } : null;
  }
  return null;
}

function parseExactWalletCapabilitySubjects(
  value: unknown,
): readonly [WalletCapabilitySubjectV1, ...WalletCapabilitySubjectV1[]] | null {
  if (!Array.isArray(value) || value.length === 0) return null;
  const parsed: WalletCapabilitySubjectV1[] = [];
  for (const rawSubject of value) {
    const subject = parseExactWalletCapabilitySubject(rawSubject);
    if (!subject) return null;
    parsed.push(subject);
  }

  const keys = new Set<string>();
  for (const subject of parsed) {
    const key = walletCapabilitySubjectKey(subject);
    if (keys.has(key)) return null;
    keys.add(key);
  }

  const [first, ...rest] = parsed;
  if (!first) return null;
  return [first, ...rest];
}

function parseExactWalletSessionRecord(value: unknown): WalletSessionAuthorizationRecord | null {
  if (!isRecord(value)) return null;
  const walletId = parseWalletId(value.walletId);
  const authorityId = parseWalletAuthorityId(value.authorityId);
  const authMethodId = parseWalletAuthMethodId(value.authMethodId);
  const authorizationId = parseWalletSessionAuthorizationId(value.authorizationId);
  const quotaId = parseMpcWalletSigningQuotaId(value.quotaId);
  if (!walletId.ok || !authorityId.ok || !authMethodId.ok || !authorizationId.ok || !quotaId.ok) {
    return null;
  }
  let authorityDigestB64u: DigestB64u;
  try {
    authorityDigestB64u = parseDigestB64u(value.authorityDigestB64u);
  } catch {
    return null;
  }
  const capabilitySubjects = parseExactWalletCapabilitySubjects(value.capabilitySubjects);
  if (
    !capabilitySubjects ||
    !isNonNegativeSafeInteger(value.authorityRevocationEpoch) ||
    !isNonNegativeSafeInteger(value.issuedAtMs) ||
    !isNonNegativeSafeInteger(value.expiresAtMs) ||
    value.expiresAtMs <= value.issuedAtMs
  ) {
    return null;
  }
  const identity = {
    walletId: walletId.value,
    authorityId: authorityId.value,
    authMethodId: authMethodId.value,
    authorizationId: authorizationId.value,
    quotaId: quotaId.value,
    authorityDigestB64u,
    authorityRevocationEpoch: value.authorityRevocationEpoch,
    capabilitySubjects,
    issuedAtMs: value.issuedAtMs,
    expiresAtMs: value.expiresAtMs,
  };
  if (value.kind === 'active_wallet_session_v1') {
    if (!hasExactFields(value, EXACT_ACTIVE_FIELDS)) return null;
    return {
      kind: 'active_wallet_session_v1',
      walletId: identity.walletId,
      authorityId: identity.authorityId,
      authMethodId: identity.authMethodId,
      authorizationId: identity.authorizationId,
      quotaId: identity.quotaId,
      authorityDigestB64u: identity.authorityDigestB64u,
      authorityRevocationEpoch: identity.authorityRevocationEpoch,
      capabilitySubjects: identity.capabilitySubjects,
      issuedAtMs: identity.issuedAtMs,
      expiresAtMs: identity.expiresAtMs,
    };
  }
  if (value.kind === 'retired_wallet_session_v1') {
    if (!hasExactFields(value, EXACT_RETIRED_FIELDS)) return null;
    if (!isNonNegativeSafeInteger(value.retiredAtMs) || value.retiredAtMs < identity.issuedAtMs) {
      return null;
    }
    const retirementReason = parseRetirementReason(value.retirementReason);
    if (!retirementReason) return null;
    if (retirementReason === 'expired' && value.retiredAtMs < identity.expiresAtMs) {
      return null;
    }
    return {
      kind: 'retired_wallet_session_v1',
      walletId: identity.walletId,
      authorityId: identity.authorityId,
      authMethodId: identity.authMethodId,
      authorizationId: identity.authorizationId,
      quotaId: identity.quotaId,
      authorityDigestB64u: identity.authorityDigestB64u,
      authorityRevocationEpoch: identity.authorityRevocationEpoch,
      capabilitySubjects: identity.capabilitySubjects,
      issuedAtMs: identity.issuedAtMs,
      expiresAtMs: identity.expiresAtMs,
      retiredAtMs: value.retiredAtMs,
      retirementReason,
    };
  }
  return null;
}

export function buildActiveWalletSessionV1(
  input: Omit<ActiveWalletSessionV1, 'kind'>,
): ActiveWalletSessionV1 {
  const record = parseExactWalletSessionRecord({
    kind: 'active_wallet_session_v1',
    walletId: input.walletId,
    authorityId: input.authorityId,
    authMethodId: input.authMethodId,
    authorizationId: input.authorizationId,
    quotaId: input.quotaId,
    authorityDigestB64u: input.authorityDigestB64u,
    authorityRevocationEpoch: input.authorityRevocationEpoch,
    capabilitySubjects: input.capabilitySubjects,
    issuedAtMs: input.issuedAtMs,
    expiresAtMs: input.expiresAtMs,
  });
  if (!record || record.kind !== 'active_wallet_session_v1') {
    throw new Error('Active Wallet Session v1 is invalid');
  }
  return record;
}

export function retireWalletSessionV1(args: {
  readonly active: ActiveWalletSessionV1;
  readonly reason: WalletSessionAuthorizationRetirementReason;
  readonly retiredAtMs: number;
}): RetiredWalletSessionV1 {
  if (!isNonNegativeSafeInteger(args.retiredAtMs)) {
    throw new Error('Retired Wallet Session v1 time is invalid');
  }
  const record = parseExactWalletSessionRecord({
    kind: 'retired_wallet_session_v1',
    walletId: args.active.walletId,
    authorityId: args.active.authorityId,
    authMethodId: args.active.authMethodId,
    authorizationId: args.active.authorizationId,
    quotaId: args.active.quotaId,
    authorityDigestB64u: args.active.authorityDigestB64u,
    authorityRevocationEpoch: args.active.authorityRevocationEpoch,
    capabilitySubjects: args.active.capabilitySubjects,
    issuedAtMs: args.active.issuedAtMs,
    expiresAtMs: args.active.expiresAtMs,
    retiredAtMs: args.retiredAtMs,
    retirementReason: args.reason,
  });
  if (!record || record.kind !== 'retired_wallet_session_v1') {
    throw new Error('Retired Wallet Session v1 is invalid');
  }
  return record;
}

export function toStoredExactWalletSessionAuthorizationRowV6(
  record: ActiveWalletSessionV1,
  operationCredential: WalletSessionOperationCredentialV1,
): StoredExactWalletSessionAuthorizationRowV6 {
  const parsedRecord = parseExactWalletSessionRecord(record);
  if (!parsedRecord || parsedRecord.kind !== 'active_wallet_session_v1') {
    throw new Error('Active Wallet Session v1 is invalid');
  }
  let parsedOperationCredential: WalletSessionOperationCredentialV1;
  try {
    parsedOperationCredential = parseWalletSessionOperationCredentialV1(operationCredential);
  } catch {
    throw new Error('Wallet Session operation credential is invalid');
  }
  const row: StoredExactWalletSessionAuthorizationRowV6 = {
    record_version: WALLET_SESSION_AUTHORIZATION_RECORD_VERSION_V6,
    wallet_session_id: parsedOperationCredential.walletSessionId,
    authorization_id: parsedRecord.authorizationId,
    wallet_id: parsedRecord.walletId,
    wallet_authority_id: parsedRecord.authorityId,
    wallet_auth_method_id: parsedRecord.authMethodId,
    authority_digest_b64u: parsedRecord.authorityDigestB64u,
    authority_revocation_epoch: parsedRecord.authorityRevocationEpoch,
    status: 'active',
    issued_at_ms: parsedRecord.issuedAtMs,
    expires_at_ms: parsedRecord.expiresAtMs,
    record: {
      kind: parsedRecord.kind,
      walletId: parsedRecord.walletId,
      authorityId: parsedRecord.authorityId,
      authMethodId: parsedRecord.authMethodId,
      authorizationId: parsedRecord.authorizationId,
      walletSessionId: parsedOperationCredential.walletSessionId,
      quotaId: parsedRecord.quotaId,
      authorityDigestB64u: parsedRecord.authorityDigestB64u,
      authorityRevocationEpoch: parsedRecord.authorityRevocationEpoch,
      capabilitySubjects: parsedRecord.capabilitySubjects,
      issuedAtMs: parsedRecord.issuedAtMs,
      expiresAtMs: parsedRecord.expiresAtMs,
    },
    operation_credential: parsedOperationCredential,
  };
  if (!parseStoredExactWalletSessionAuthorizationRowV6(row)) {
    throw new Error('Wallet Session authorization v6 is invalid');
  }
  return row;
}

export function parseStoredExactWalletSessionAuthorizationRowV6(value: unknown): {
  readonly record: ActiveWalletSessionV1;
  readonly operationCredential: WalletSessionOperationCredentialV1;
  readonly physicalKey: string;
} | null {
  if (!isRecord(value) || !hasExactFields(value, EXACT_STORED_ROW_V6_FIELDS)) return null;
  if (
    value.record_version !== WALLET_SESSION_AUTHORIZATION_RECORD_VERSION_V6 ||
    value.status !== 'active'
  ) {
    return null;
  }
  const walletSessionId = parseWalletSessionId(value.wallet_session_id);
  const authorizationId = parseWalletSessionAuthorizationId(value.authorization_id);
  if (!walletSessionId.ok || !authorizationId.ok) return null;
  let operationCredential: WalletSessionOperationCredentialV1;
  try {
    operationCredential = parseWalletSessionOperationCredentialV1(value.operation_credential);
  } catch {
    return null;
  }
  if (walletSessionId.value !== operationCredential.walletSessionId) return null;
  if (!isRecord(value.record)) return null;
  const recordWalletSessionId = parseWalletSessionId(value.record.walletSessionId);
  if (!recordWalletSessionId.ok || recordWalletSessionId.value !== walletSessionId.value) {
    return null;
  }
  const recordWithoutWalletSessionId = { ...value.record };
  delete recordWithoutWalletSessionId.walletSessionId;
  const record = parseExactWalletSessionRecord(recordWithoutWalletSessionId);
  if (
    !record ||
    record.kind !== 'active_wallet_session_v1' ||
    value.wallet_id !== record.walletId ||
    value.wallet_authority_id !== record.authorityId ||
    value.wallet_auth_method_id !== record.authMethodId ||
    value.authority_digest_b64u !== record.authorityDigestB64u ||
    value.authority_revocation_epoch !== record.authorityRevocationEpoch ||
    value.issued_at_ms !== record.issuedAtMs ||
    value.expires_at_ms !== record.expiresAtMs ||
    authorizationId.value !== record.authorizationId
  ) {
    return null;
  }
  return {
    record,
    operationCredential,
    physicalKey: walletSessionId.value,
  };
}

export class WalletSessionAuthorizationRepository {
  constructor(private readonly manager: SeamsWalletDBManager = seamsWalletDB) {}

  async writeExactWithOperationCredential(input: {
    readonly record: ActiveWalletSessionV1;
    readonly operationCredential: WalletSessionOperationCredentialV1;
  }): Promise<ActiveWalletSessionV1> {
    const parsed = parseExactWalletSessionRecord(input.record);
    if (!parsed || parsed.kind !== 'active_wallet_session_v1') {
      throw new Error('Active Wallet Session v1 is invalid');
    }
    const operationCredential = parseWalletSessionOperationCredentialV1(input.operationCredential);
    await this.replaceExactActive({
      active: parsed,
      operationCredential,
    });
    return parsed;
  }

  async readExact(
    walletSessionId: WalletSessionId,
  ): Promise<WalletSessionAuthorizationRecord | null> {
    const db = await this.manager.getDB();
    const tx = db.transaction(STORE, 'readwrite');
    const store = tx.objectStore(STORE);
    try {
      const raw = await store.get(walletSessionId);
      if (raw === undefined) {
        await tx.done;
        return null;
      }
      if (isFutureWalletSessionAuthorizationRow(raw)) {
        throw new WalletSessionAuthorizationUpgradeRequiredError(
          'Wallet Session authorization requires a newer client',
        );
      }
      if (isKnownLegacyWalletSessionAuthorizationRow(raw)) {
        await store.delete(storedWalletSessionRowKey(raw));
        await tx.done;
        return null;
      }
      if (!isStoredExactWalletSessionAuthorizationRowV6(raw)) {
        throw new Error('Stored Wallet Session authorization v6 is corrupt');
      }
      const parsed = parseStoredExactWalletSessionAuthorizationRowV6(raw);
      if (!parsed) throw new Error('Stored Wallet Session authorization v6 is corrupt');
      await tx.done;
      return parsed.record;
    } catch (error) {
      try {
        tx.abort();
      } catch {}
      await settleAbortedTransaction(tx);
      throw error;
    }
  }

  async readExactWithOperationCredential(input: {
    readonly walletId: WalletId;
    readonly authorityId: WalletAuthorityId;
    readonly authMethodId: WalletAuthMethodId;
  }): Promise<WalletSessionAuthorizationExactOperationCredentialReadResult> {
    const read = await this.readExactActiveForWallet(input);
    switch (read.kind) {
      case 'found':
      case 'missing':
      case 'upgrade_required':
        return read;
      case 'corrupt':
        throw new Error('Stored Wallet Session authorization v6 is corrupt');
      case 'persistence_unavailable':
        throw new Error('Wallet Session authorization persistence is unavailable');
    }
  }

  async readExactActiveForWallet(input: {
    readonly walletId: WalletId;
    readonly authorityId: WalletAuthorityId;
    readonly authMethodId: WalletAuthMethodId;
  }): Promise<WalletSessionAuthorizationExactActiveReadResult> {
    try {
      const db = await this.manager.getDB();
      const tx = db.transaction(STORE, 'readwrite');
      const store = tx.objectStore(STORE);
      try {
        const rows = await store.index(SEAMS_WALLET_INDEXES.walletId).getAll(input.walletId);
        let match: {
          readonly record: ActiveWalletSessionV1;
          readonly operationCredential: WalletSessionOperationCredentialV1;
        } | null = null;
        let upgradeRequired = false;
        let corrupt = false;
        for (const raw of rows) {
          if (futureWalletSessionAuthorizationRowMatchesExactScope(raw, input)) {
            upgradeRequired = true;
            continue;
          }
          if (isKnownLegacyWalletSessionAuthorizationRow(raw)) {
            await store.delete(storedWalletSessionRowKey(raw));
            continue;
          }
          if (!isStoredExactWalletSessionAuthorizationRowV6(raw)) {
            corrupt = true;
            break;
          }
          const parsed = parseStoredExactWalletSessionAuthorizationRowV6(raw);
          if (!parsed) {
            corrupt = true;
            break;
          }
          if (
            parsed.record.walletId !== input.walletId ||
            parsed.record.authorityId !== input.authorityId ||
            parsed.record.authMethodId !== input.authMethodId
          ) {
            continue;
          }
          if (match) {
            corrupt = true;
            break;
          }
          match = parsed;
        }
        if (corrupt) {
          try {
            tx.abort();
          } catch {}
          await settleAbortedTransaction(tx);
          return { kind: 'corrupt' };
        }
        await tx.done;
        if (upgradeRequired) return { kind: 'upgrade_required' };
        if (!match) return { kind: 'missing' };
        return {
          kind: 'found',
          record: match.record,
          operationCredential: match.operationCredential,
        };
      } catch {
        try {
          tx.abort();
        } catch {}
        await settleAbortedTransaction(tx);
        return { kind: 'persistence_unavailable' };
      }
    } catch {
      return { kind: 'persistence_unavailable' };
    }
  }

  async retireExactActiveForWallet(args: {
    readonly walletId: WalletId;
    readonly reason: WalletSessionAuthorizationRetirementReason;
    readonly retiredAtMs: number;
  }): Promise<readonly RetiredWalletSessionV1[]> {
    if (!isNonNegativeSafeInteger(args.retiredAtMs)) {
      throw new Error('Wallet Session v1 retirement time is invalid');
    }
    const db = await this.manager.getDB();
    const tx = db.transaction(STORE, 'readwrite');
    const store = tx.objectStore(STORE);
    const retired: RetiredWalletSessionV1[] = [];
    try {
      const rows = await store.index(SEAMS_WALLET_INDEXES.walletId).getAll(args.walletId);
      for (const raw of rows) {
        if (isFutureWalletSessionAuthorizationRow(raw)) continue;
        if (isKnownLegacyWalletSessionAuthorizationRow(raw)) {
          await store.delete(storedWalletSessionRowKey(raw));
          continue;
        }
        if (!isStoredExactWalletSessionAuthorizationRowV6(raw)) continue;
        const parsedCurrent = parseStoredExactWalletSessionAuthorizationRowV6(raw);
        if (!parsedCurrent) {
          tx.abort();
          throw new Error('Stored Wallet Session authorization v6 is corrupt');
        }
        const current = parsedCurrent.record;
        if (current.kind !== 'active_wallet_session_v1') continue;
        const next = retireWalletSessionV1({
          active: current,
          reason: args.reason,
          retiredAtMs: args.retiredAtMs,
        });
        await store.delete(parsedCurrent.physicalKey);
        retired.push(next);
      }
      await tx.done;
      return retired;
    } catch (error) {
      try {
        tx.abort();
      } catch {}
      await settleAbortedTransaction(tx);
      throw error;
    }
  }

  async replaceExactActive(args: {
    readonly active: ActiveWalletSessionV1;
    readonly operationCredential: WalletSessionOperationCredentialV1;
  }): Promise<ActiveWalletSessionV1> {
    const incoming = parseExactWalletSessionRecord(args.active);
    if (!incoming || incoming.kind !== 'active_wallet_session_v1') {
      throw new Error('Active Wallet Session v1 is invalid');
    }
    const operationCredential = parseWalletSessionOperationCredentialV1(args.operationCredential);
    const incomingRow = toStoredExactWalletSessionAuthorizationRowV6(incoming, operationCredential);
    const db = await this.manager.getDB();
    const tx = db.transaction(STORE, 'readwrite');
    const store = tx.objectStore(STORE);
    try {
      const rows = await store.index(SEAMS_WALLET_INDEXES.walletId).getAll(incoming.walletId);
      for (const raw of rows) {
        if (isFutureWalletSessionAuthorizationRow(raw)) continue;
        if (isKnownLegacyWalletSessionAuthorizationRow(raw)) {
          await store.delete(storedWalletSessionRowKey(raw));
          continue;
        }
        if (!isStoredExactWalletSessionAuthorizationRowV6(raw)) {
          tx.abort();
          throw new Error('Stored Wallet Session authorization row is corrupt');
        }
        const parsedCurrent = parseStoredExactWalletSessionAuthorizationRowV6(raw);
        if (!parsedCurrent) {
          tx.abort();
          throw new Error('Stored Wallet Session authorization v6 is corrupt');
        }
        const current = parsedCurrent.record;
        if (
          current.kind !== 'active_wallet_session_v1' ||
          current.authorityId !== incoming.authorityId ||
          current.authMethodId !== incoming.authMethodId
        ) {
          continue;
        }
        if (
          current.authorizationId === incoming.authorizationId &&
          parsedCurrent.operationCredential.walletSessionId === operationCredential.walletSessionId
        ) {
          continue;
        }
        await store.delete(parsedCurrent.physicalKey);
      }
      await store.put(incomingRow);
      await tx.done;
      return incoming;
    } catch (error) {
      try {
        tx.abort();
      } catch {}
      await settleAbortedTransaction(tx);
      throw error;
    }
  }

  async clearWallet(walletId: WalletId): Promise<void> {
    const db = await this.manager.getDB();
    const keys = await db.getAllKeysFromIndex(STORE, SEAMS_WALLET_INDEXES.walletId, walletId);
    if (keys.length === 0) return;
    const tx = db.transaction(STORE, 'readwrite');
    const store = tx.objectStore(STORE);
    for (const key of keys) {
      await store.delete(key);
    }
    await tx.done;
  }

  async clearAll(): Promise<void> {
    const db = await this.manager.getDB();
    await db.clear(STORE);
  }
}

export const walletSessionAuthorizations = new WalletSessionAuthorizationRepository();
