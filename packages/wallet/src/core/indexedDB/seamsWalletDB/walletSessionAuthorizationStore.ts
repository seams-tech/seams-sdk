import {
  parseMpcWalletSigningQuotaId,
  parseWalletSessionAuthorizationId,
  parseWalletSessionId,
  type MpcWalletSigningQuotaId,
  type WalletSessionId,
} from '@shared/authorization/capabilityKinds';
import type { ReusableWalletSessionAuthorizationId } from '@/core/types/seams';
import { parseWalletId, type WalletId } from '@shared/utils/domainIds';
import {
  parseThresholdEcdsaSessionId,
  parseThresholdEd25519SessionId,
  type ThresholdEcdsaSessionId,
  type ThresholdEd25519SessionId,
} from '@shared/utils/domainIds';
import { alphabetizeStringify } from '@shared/utils/digests';
import { isWalletAuthMethod, type WalletAuthMethod } from '@shared/utils/signerDomain';
import {
  requireOpaqueWalletSessionToken,
  type OpaqueWalletSessionToken,
} from '@shared/utils/sessionTokens';
import {
  parseWalletAuthAuthorityRef,
  type WalletAuthAuthorityRef,
} from '@shared/utils/walletAuthAuthority';
import { SEAMS_WALLET_INDEXES, SEAMS_WALLET_STORES } from '../schemaNames';
import { seamsWalletDB } from '../singletons';
import type { SeamsWalletDBManager } from './manager';

export const WALLET_SESSION_AUTHORIZATION_RECORD_VERSION =
  'wallet_session_authorization_v3' as const;

export type WalletSessionAuthorizationToken = OpaqueWalletSessionToken;

type Ed25519WalletSessionAuthorizationToken = {
  readonly authorizationId: ReusableWalletSessionAuthorizationId;
  readonly walletSessionToken: WalletSessionAuthorizationToken;
  readonly thresholdSessionId: ThresholdEd25519SessionId;
};

type EcdsaWalletSessionAuthorizationToken = {
  readonly authorizationId: ReusableWalletSessionAuthorizationId;
  readonly walletSessionToken: WalletSessionAuthorizationToken;
  readonly thresholdSessionId: ThresholdEcdsaSessionId;
};

export type WalletSessionAuthorizationTokenBundle =
  | {
      readonly kind: 'near_ed25519';
      readonly ed25519: Ed25519WalletSessionAuthorizationToken;
      readonly ecdsa?: never;
    }
  | {
      readonly kind: 'evm_family_ecdsa';
      readonly ecdsa: EcdsaWalletSessionAuthorizationToken;
      readonly ed25519?: never;
    }
  | {
      readonly kind: 'near_ed25519_and_evm_family_ecdsa';
      readonly ed25519: Ed25519WalletSessionAuthorizationToken;
      readonly ecdsa: EcdsaWalletSessionAuthorizationToken;
    };

type WalletSessionAuthorizationIdentity = {
  readonly recordVersion: typeof WALLET_SESSION_AUTHORIZATION_RECORD_VERSION;
  readonly walletId: WalletId;
  readonly walletSessionId: WalletSessionId;
  readonly quotaId: MpcWalletSigningQuotaId;
  readonly authMethod: WalletAuthMethod;
  readonly authority: WalletAuthAuthorityRef;
  readonly expiresAtMs: number;
};

export type ActiveWalletSessionAuthorizationProjection = WalletSessionAuthorizationIdentity & {
  readonly status: 'active';
  readonly walletSessionTokens: WalletSessionAuthorizationTokenBundle;
  readonly retirementReason?: never;
  readonly retiredAtMs?: never;
};

export type WalletSessionAuthorizationRetirementReason =
  | 'expired'
  | 'exhausted'
  | 'replaced'
  | 'wallet_locked'
  | 'invalidated';

export type RetiredWalletSessionAuthorizationProjection = WalletSessionAuthorizationIdentity & {
  readonly status: 'retired';
  readonly retirementReason: WalletSessionAuthorizationRetirementReason;
  readonly retiredAtMs: number;
  readonly walletSessionTokens?: never;
};

export type WalletSessionAuthorizationProjection =
  | ActiveWalletSessionAuthorizationProjection
  | RetiredWalletSessionAuthorizationProjection;

export type WalletSessionAuthorizationCurve = 'ed25519' | 'ecdsa';

function walletSessionAuthorizationCurveIdsAreDistinct(args: {
  readonly authorizationId: ReusableWalletSessionAuthorizationId;
  readonly walletSessionId: WalletSessionId;
  readonly quotaId: MpcWalletSigningQuotaId;
}): boolean {
  return new Set([args.authorizationId, args.walletSessionId, args.quotaId]).size === 3;
}

export function walletSessionAuthorizationIdForCurve(
  projection: ActiveWalletSessionAuthorizationProjection,
  curve: WalletSessionAuthorizationCurve,
): ReusableWalletSessionAuthorizationId | null {
  switch (projection.walletSessionTokens.kind) {
    case 'near_ed25519':
      return curve === 'ed25519' ? projection.walletSessionTokens.ed25519.authorizationId : null;
    case 'evm_family_ecdsa':
      return curve === 'ecdsa' ? projection.walletSessionTokens.ecdsa.authorizationId : null;
    case 'near_ed25519_and_evm_family_ecdsa':
      return curve === 'ed25519'
        ? projection.walletSessionTokens.ed25519.authorizationId
        : projection.walletSessionTokens.ecdsa.authorizationId;
    default:
      return assertNeverWalletSessionTokenBundle(projection.walletSessionTokens);
  }
}

export function walletSessionTokenForCurve(
  projection: ActiveWalletSessionAuthorizationProjection,
  curve: WalletSessionAuthorizationCurve,
): WalletSessionAuthorizationToken | null {
  switch (projection.walletSessionTokens.kind) {
    case 'near_ed25519':
      return curve === 'ed25519' ? projection.walletSessionTokens.ed25519.walletSessionToken : null;
    case 'evm_family_ecdsa':
      return curve === 'ecdsa' ? projection.walletSessionTokens.ecdsa.walletSessionToken : null;
    case 'near_ed25519_and_evm_family_ecdsa':
      return curve === 'ed25519'
        ? projection.walletSessionTokens.ed25519.walletSessionToken
        : projection.walletSessionTokens.ecdsa.walletSessionToken;
    default:
      return assertNeverWalletSessionTokenBundle(projection.walletSessionTokens);
  }
}

export function walletSessionThresholdSessionIdForCurve(
  projection: ActiveWalletSessionAuthorizationProjection,
  curve: 'ed25519',
): ThresholdEd25519SessionId | null;
export function walletSessionThresholdSessionIdForCurve(
  projection: ActiveWalletSessionAuthorizationProjection,
  curve: 'ecdsa',
): ThresholdEcdsaSessionId | null;
export function walletSessionThresholdSessionIdForCurve(
  projection: ActiveWalletSessionAuthorizationProjection,
  curve: WalletSessionAuthorizationCurve,
): ThresholdEd25519SessionId | ThresholdEcdsaSessionId | null {
  switch (projection.walletSessionTokens.kind) {
    case 'near_ed25519':
      return curve === 'ed25519' ? projection.walletSessionTokens.ed25519.thresholdSessionId : null;
    case 'evm_family_ecdsa':
      return curve === 'ecdsa' ? projection.walletSessionTokens.ecdsa.thresholdSessionId : null;
    case 'near_ed25519_and_evm_family_ecdsa':
      return curve === 'ed25519'
        ? projection.walletSessionTokens.ed25519.thresholdSessionId
        : projection.walletSessionTokens.ecdsa.thresholdSessionId;
    default:
      return assertNeverWalletSessionTokenBundle(projection.walletSessionTokens);
  }
}

function assertNeverWalletSessionTokenBundle(value: never): never {
  throw new Error(`Unknown Wallet Session token bundle: ${String(value)}`);
}

function mergeWalletSessionTokenBundles(
  existing: WalletSessionAuthorizationTokenBundle,
  incoming: WalletSessionAuthorizationTokenBundle,
): WalletSessionAuthorizationTokenBundle {
  switch (incoming.kind) {
    case 'near_ed25519':
      if (existing.kind === 'evm_family_ecdsa') {
        return {
          kind: 'near_ed25519_and_evm_family_ecdsa',
          ed25519: incoming.ed25519,
          ecdsa: existing.ecdsa,
        };
      }
      if (existing.kind === 'near_ed25519_and_evm_family_ecdsa') {
        return {
          kind: 'near_ed25519_and_evm_family_ecdsa',
          ed25519: incoming.ed25519,
          ecdsa: existing.ecdsa,
        };
      }
      return {
        kind: 'near_ed25519',
        ed25519: incoming.ed25519,
      };
    case 'evm_family_ecdsa':
      if (existing.kind === 'near_ed25519') {
        return {
          kind: 'near_ed25519_and_evm_family_ecdsa',
          ed25519: existing.ed25519,
          ecdsa: incoming.ecdsa,
        };
      }
      if (existing.kind === 'near_ed25519_and_evm_family_ecdsa') {
        return {
          kind: 'near_ed25519_and_evm_family_ecdsa',
          ed25519: existing.ed25519,
          ecdsa: incoming.ecdsa,
        };
      }
      return {
        kind: 'evm_family_ecdsa',
        ecdsa: incoming.ecdsa,
      };
    case 'near_ed25519_and_evm_family_ecdsa':
      if (existing.kind === 'near_ed25519') {
        return {
          kind: 'near_ed25519_and_evm_family_ecdsa',
          ed25519: incoming.ed25519,
          ecdsa: incoming.ecdsa,
        };
      }
      if (existing.kind === 'evm_family_ecdsa') {
        return {
          kind: 'near_ed25519_and_evm_family_ecdsa',
          ed25519: incoming.ed25519,
          ecdsa: incoming.ecdsa,
        };
      }
      return {
        kind: 'near_ed25519_and_evm_family_ecdsa',
        ed25519: incoming.ed25519,
        ecdsa: incoming.ecdsa,
      };
    default:
      return assertNeverWalletSessionTokenBundle(incoming);
  }
}

export type WalletSessionAuthorizationReadResult<
  TProjection extends WalletSessionAuthorizationProjection = WalletSessionAuthorizationProjection,
> =
  | {
      readonly kind: 'found';
      readonly projection: TProjection;
    }
  | {
      readonly kind: 'missing' | 'corrupt' | 'persistence_unavailable';
      readonly projection?: never;
    };

export type BuildActiveWalletSessionAuthorizationProjectionInput = Omit<
  ActiveWalletSessionAuthorizationProjection,
  'recordVersion' | 'status' | 'walletSessionTokens'
> & {
  readonly walletSessionTokens: unknown;
};

type StoredWalletSessionAuthorizationRow = {
  readonly wallet_session_id: string;
  readonly wallet_id: string;
  readonly status: WalletSessionAuthorizationProjection['status'];
  readonly expires_at_ms: number;
  readonly record: WalletSessionAuthorizationProjection;
};

const STORE = SEAMS_WALLET_STORES.walletSessionAuthorizations;
const ACTIVE_FIELDS = [
  'recordVersion',
  'status',
  'walletId',
  'walletSessionId',
  'quotaId',
  'walletSessionTokens',
  'authMethod',
  'authority',
  'expiresAtMs',
] as const;
const RETIRED_FIELDS = [
  'recordVersion',
  'status',
  'walletId',
  'walletSessionId',
  'quotaId',
  'authMethod',
  'authority',
  'expiresAtMs',
  'retirementReason',
  'retiredAtMs',
] as const;
const STORED_ROW_FIELDS = [
  'wallet_session_id',
  'wallet_id',
  'status',
  'expires_at_ms',
  'record',
] as const;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function hasExactFields(record: Record<string, unknown>, expected: readonly string[]): boolean {
  const fields = Object.keys(record);
  return fields.length === expected.length && fields.every((field) => expected.includes(field));
}

function isPositiveSafeInteger(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value > 0;
}

function parseEd25519WalletSessionAuthorizationToken(
  value: unknown,
): Ed25519WalletSessionAuthorizationToken | null {
  if (!isRecord(value)) return null;
  if (
    Object.keys(value).length !== 3 ||
    !Object.prototype.hasOwnProperty.call(value, 'authorizationId') ||
    !Object.prototype.hasOwnProperty.call(value, 'walletSessionToken') ||
    !Object.prototype.hasOwnProperty.call(value, 'thresholdSessionId')
  ) {
    return null;
  }
  const authorizationId = parseWalletSessionAuthorizationId(value.authorizationId);
  const thresholdSessionId = parseThresholdEd25519SessionId(value.thresholdSessionId);
  if (!authorizationId.ok || !thresholdSessionId.ok) return null;
  try {
    return {
      authorizationId: authorizationId.value,
      walletSessionToken: requireOpaqueWalletSessionToken(value.walletSessionToken),
      thresholdSessionId: thresholdSessionId.value,
    };
  } catch {
    return null;
  }
}

function parseEcdsaWalletSessionAuthorizationToken(
  value: unknown,
): EcdsaWalletSessionAuthorizationToken | null {
  if (!isRecord(value)) return null;
  if (
    Object.keys(value).length !== 3 ||
    !Object.prototype.hasOwnProperty.call(value, 'authorizationId') ||
    !Object.prototype.hasOwnProperty.call(value, 'walletSessionToken') ||
    !Object.prototype.hasOwnProperty.call(value, 'thresholdSessionId')
  ) {
    return null;
  }
  const authorizationId = parseWalletSessionAuthorizationId(value.authorizationId);
  const thresholdSessionId = parseThresholdEcdsaSessionId(value.thresholdSessionId);
  if (!authorizationId.ok || !thresholdSessionId.ok) return null;
  try {
    return {
      authorizationId: authorizationId.value,
      walletSessionToken: requireOpaqueWalletSessionToken(value.walletSessionToken),
      thresholdSessionId: thresholdSessionId.value,
    };
  } catch {
    return null;
  }
}

function walletSessionAuthorizationIdentityMatches(
  left: ActiveWalletSessionAuthorizationProjection,
  right: ActiveWalletSessionAuthorizationProjection,
): boolean {
  return (
    left.walletId === right.walletId &&
    left.walletSessionId === right.walletSessionId &&
    left.quotaId === right.quotaId &&
    left.authMethod === right.authMethod &&
    alphabetizeStringify(left.authority) === alphabetizeStringify(right.authority)
  );
}

function parseWalletSessionAuthorizationTokenBundle(
  value: unknown,
): WalletSessionAuthorizationTokenBundle | null {
  if (!isRecord(value)) return null;
  const kind = value.kind;
  if (kind === 'near_ed25519' && Object.keys(value).length === 2) {
    const ed25519 = parseEd25519WalletSessionAuthorizationToken(value.ed25519);
    return ed25519 ? { kind, ed25519 } : null;
  }
  if (kind === 'evm_family_ecdsa' && Object.keys(value).length === 2) {
    const ecdsa = parseEcdsaWalletSessionAuthorizationToken(value.ecdsa);
    return ecdsa ? { kind, ecdsa } : null;
  }
  if (kind === 'near_ed25519_and_evm_family_ecdsa' && Object.keys(value).length === 3) {
    const ed25519 = parseEd25519WalletSessionAuthorizationToken(value.ed25519);
    const ecdsa = parseEcdsaWalletSessionAuthorizationToken(value.ecdsa);
    return ed25519 && ecdsa ? { kind, ed25519, ecdsa } : null;
  }
  return null;
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

function parseIdentity(
  record: Record<string, unknown>,
): Omit<WalletSessionAuthorizationIdentity, 'recordVersion'> | null {
  const walletId = parseWalletId(record.walletId);
  const walletSessionId = parseWalletSessionId(record.walletSessionId);
  const quotaId = parseMpcWalletSigningQuotaId(record.quotaId);
  const authority = parseWalletAuthAuthorityRef(record.authority);
  if (
    !walletId.ok ||
    !walletSessionId.ok ||
    !quotaId.ok ||
    !authority ||
    authority.walletId !== walletId.value ||
    !isWalletAuthMethod(record.authMethod) ||
    !isPositiveSafeInteger(record.expiresAtMs)
  ) {
    return null;
  }
  return {
    walletId: walletId.value,
    walletSessionId: walletSessionId.value,
    quotaId: quotaId.value,
    authMethod: record.authMethod,
    authority,
    expiresAtMs: record.expiresAtMs,
  };
}

export function parseWalletSessionAuthorizationProjection(
  raw: unknown,
): WalletSessionAuthorizationProjection | null {
  if (!isRecord(raw)) return null;
  if (raw.recordVersion !== WALLET_SESSION_AUTHORIZATION_RECORD_VERSION) return null;
  const identity = parseIdentity(raw);
  if (!identity) return null;
  switch (raw.status) {
    case 'active': {
      if (!hasExactFields(raw, ACTIVE_FIELDS)) return null;
      const walletSessionTokens = parseWalletSessionAuthorizationTokenBundle(
        raw.walletSessionTokens,
      );
      if (!walletSessionTokens) return null;
      const curveAuthorizations =
        walletSessionTokens.kind === 'near_ed25519'
          ? [walletSessionTokens.ed25519]
          : walletSessionTokens.kind === 'evm_family_ecdsa'
            ? [walletSessionTokens.ecdsa]
            : [walletSessionTokens.ed25519, walletSessionTokens.ecdsa];
      if (
        curveAuthorizations.some(
          (authorization) =>
            !walletSessionAuthorizationCurveIdsAreDistinct({
              authorizationId: authorization.authorizationId,
              walletSessionId: identity.walletSessionId,
              quotaId: identity.quotaId,
            }),
        )
      ) {
        return null;
      }
      return {
        recordVersion: WALLET_SESSION_AUTHORIZATION_RECORD_VERSION,
        status: 'active',
        ...identity,
        walletSessionTokens,
      };
    }
    case 'retired': {
      if (!hasExactFields(raw, RETIRED_FIELDS)) return null;
      const retirementReason = parseRetirementReason(raw.retirementReason);
      if (!retirementReason || !isPositiveSafeInteger(raw.retiredAtMs)) return null;
      if (retirementReason === 'expired' && raw.retiredAtMs < identity.expiresAtMs) {
        return null;
      }
      return {
        recordVersion: WALLET_SESSION_AUTHORIZATION_RECORD_VERSION,
        status: 'retired',
        ...identity,
        retirementReason,
        retiredAtMs: raw.retiredAtMs,
      };
    }
    default:
      return null;
  }
}

export function buildActiveWalletSessionAuthorizationProjection(
  input: BuildActiveWalletSessionAuthorizationProjectionInput,
): ActiveWalletSessionAuthorizationProjection {
  const projection = parseWalletSessionAuthorizationProjection({
    recordVersion: WALLET_SESSION_AUTHORIZATION_RECORD_VERSION,
    status: 'active',
    walletId: input.walletId,
    walletSessionId: input.walletSessionId,
    quotaId: input.quotaId,
    walletSessionTokens: input.walletSessionTokens,
    authMethod: input.authMethod,
    authority: input.authority,
    expiresAtMs: input.expiresAtMs,
  });
  if (!projection || projection.status !== 'active') {
    throw new Error('Wallet Session authorization projection is invalid');
  }
  return projection;
}

export function retireWalletSessionAuthorizationProjection(args: {
  readonly active: ActiveWalletSessionAuthorizationProjection;
  readonly reason: WalletSessionAuthorizationRetirementReason;
  readonly retiredAtMs: number;
}): RetiredWalletSessionAuthorizationProjection {
  const projection = parseWalletSessionAuthorizationProjection({
    recordVersion: WALLET_SESSION_AUTHORIZATION_RECORD_VERSION,
    status: 'retired',
    walletId: args.active.walletId,
    walletSessionId: args.active.walletSessionId,
    quotaId: args.active.quotaId,
    authMethod: args.active.authMethod,
    authority: args.active.authority,
    expiresAtMs: args.active.expiresAtMs,
    retirementReason: args.reason,
    retiredAtMs: args.retiredAtMs,
  });
  if (!projection || projection.status !== 'retired') {
    throw new Error('Retired Wallet Session authorization projection is invalid');
  }
  return projection;
}

function toStoredRow(
  projection: WalletSessionAuthorizationProjection,
): StoredWalletSessionAuthorizationRow {
  return {
    wallet_session_id: projection.walletSessionId,
    wallet_id: projection.walletId,
    status: projection.status,
    expires_at_ms: projection.expiresAtMs,
    record: projection,
  };
}

function parseStoredRow(raw: unknown): WalletSessionAuthorizationProjection | null {
  if (!isRecord(raw) || !hasExactFields(raw, STORED_ROW_FIELDS)) return null;
  const projection = parseWalletSessionAuthorizationProjection(raw.record);
  if (
    !projection ||
    raw.wallet_session_id !== projection.walletSessionId ||
    raw.wallet_id !== projection.walletId ||
    raw.status !== projection.status ||
    raw.expires_at_ms !== projection.expiresAtMs
  ) {
    return null;
  }
  return projection;
}

function found<TProjection extends WalletSessionAuthorizationProjection>(
  projection: TProjection,
): WalletSessionAuthorizationReadResult<TProjection> {
  return { kind: 'found', projection };
}

export class WalletSessionAuthorizationRepository {
  constructor(private readonly manager: SeamsWalletDBManager = seamsWalletDB) {}

  async write(projection: RetiredWalletSessionAuthorizationProjection): Promise<void> {
    const parsed = parseWalletSessionAuthorizationProjection(projection);
    if (!parsed || parsed.status !== 'retired') {
      throw new Error('Retired Wallet Session authorization projection is invalid');
    }
    const db = await this.manager.getDB();
    await db.put(STORE, toStoredRow(parsed));
  }

  async replaceActive(args: {
    readonly active: ActiveWalletSessionAuthorizationProjection;
    readonly replacedAtMs: number;
  }): Promise<void> {
    const parsed = parseWalletSessionAuthorizationProjection(args.active);
    if (!parsed || parsed.status !== 'active') {
      throw new Error('Active Wallet Session authorization projection is invalid');
    }
    if (!isPositiveSafeInteger(args.replacedAtMs)) {
      throw new Error('Wallet Session authorization replacement time is invalid');
    }
    const db = await this.manager.getDB();
    const tx = db.transaction(STORE, 'readwrite');
    const store = tx.objectStore(STORE);
    try {
      const rows = await store.index(SEAMS_WALLET_INDEXES.walletId).getAll(parsed.walletId);
      for (const raw of rows) {
        const current = parseStoredRow(raw);
        if (!current) {
          tx.abort();
          throw new Error('Stored Wallet Session authorization projection is corrupt');
        }
        if (current.status !== 'active' || current.walletSessionId === parsed.walletSessionId) {
          continue;
        }
        const retired = retireWalletSessionAuthorizationProjection({
          active: current,
          reason: 'replaced',
          retiredAtMs: args.replacedAtMs,
        });
        await store.put(toStoredRow(retired));
      }
      await store.put(toStoredRow(parsed));
      await tx.done;
    } catch (error) {
      try {
        tx.abort();
      } catch {}
      await tx.done.catch(() => undefined);
      throw error;
    }
  }

  async createOrMergeExactActive(args: {
    readonly incoming: ActiveWalletSessionAuthorizationProjection;
    readonly mergedAtMs: number;
  }): Promise<ActiveWalletSessionAuthorizationProjection> {
    const incoming = parseWalletSessionAuthorizationProjection(args.incoming);
    if (!incoming || incoming.status !== 'active') {
      throw new Error('Active Wallet Session authorization projection is invalid');
    }
    if (!isPositiveSafeInteger(args.mergedAtMs)) {
      throw new Error('Wallet Session authorization merge time is invalid');
    }
    const db = await this.manager.getDB();
    const tx = db.transaction(STORE, 'readwrite');
    const store = tx.objectStore(STORE);
    try {
      const rows = await store.index(SEAMS_WALLET_INDEXES.walletId).getAll(incoming.walletId);
      const projections = rows.map(parseStoredRow);
      if (projections.some((projection) => projection === null)) {
        tx.abort();
        throw new Error('Stored Wallet Session authorization projection is corrupt');
      }
      const active = projections.filter(
        (projection): projection is ActiveWalletSessionAuthorizationProjection =>
          projection?.status === 'active',
      );
      if (active.length > 1) {
        tx.abort();
        throw new Error('Multiple active Wallet Session authorization projections found');
      }
      const current = active[0];
      if (current && !walletSessionAuthorizationIdentityMatches(current, incoming)) {
        tx.abort();
        throw new Error(
          'Wallet Session authorization identity does not match the active projection',
        );
      }
      const merged = current
        ? buildActiveWalletSessionAuthorizationProjection({
            walletId: incoming.walletId,
            walletSessionId: incoming.walletSessionId,
            quotaId: incoming.quotaId,
            walletSessionTokens: mergeWalletSessionTokenBundles(
              current.walletSessionTokens,
              incoming.walletSessionTokens,
            ),
            authMethod: incoming.authMethod,
            authority: incoming.authority,
            expiresAtMs: Math.min(current.expiresAtMs, incoming.expiresAtMs),
          })
        : incoming;
      await store.put(toStoredRow(merged));
      await tx.done;
      return merged;
    } catch (error) {
      try {
        tx.abort();
      } catch {}
      await tx.done.catch(() => undefined);
      throw error;
    }
  }

  async upsertActiveWithCurveMerge(args: {
    readonly incoming: ActiveWalletSessionAuthorizationProjection;
    readonly writtenAtMs: number;
  }): Promise<ActiveWalletSessionAuthorizationProjection> {
    const incoming = parseWalletSessionAuthorizationProjection(args.incoming);
    if (!incoming || incoming.status !== 'active') {
      throw new Error('Active Wallet Session authorization projection is invalid');
    }
    if (!isPositiveSafeInteger(args.writtenAtMs)) {
      throw new Error('Wallet Session authorization write time is invalid');
    }
    const db = await this.manager.getDB();
    const tx = db.transaction(STORE, 'readwrite');
    const store = tx.objectStore(STORE);
    try {
      const rows = await store.index(SEAMS_WALLET_INDEXES.walletId).getAll(incoming.walletId);
      const projections = rows.map(parseStoredRow);
      if (projections.some((projection) => projection === null)) {
        tx.abort();
        throw new Error('Stored Wallet Session authorization projection is corrupt');
      }
      const active = projections.filter(
        (projection): projection is ActiveWalletSessionAuthorizationProjection =>
          projection?.status === 'active',
      );
      if (active.length > 1) {
        tx.abort();
        throw new Error('Multiple active Wallet Session authorization projections found');
      }
      const current = active[0];
      if (!current) {
        await store.put(toStoredRow(incoming));
        await tx.done;
        return incoming;
      }

      if (walletSessionAuthorizationIdentityMatches(current, incoming)) {
        const merged = buildActiveWalletSessionAuthorizationProjection({
          walletId: incoming.walletId,
          walletSessionId: incoming.walletSessionId,
          quotaId: incoming.quotaId,
          walletSessionTokens: mergeWalletSessionTokenBundles(
            current.walletSessionTokens,
            incoming.walletSessionTokens,
          ),
          authMethod: incoming.authMethod,
          authority: incoming.authority,
          expiresAtMs: Math.min(current.expiresAtMs, incoming.expiresAtMs),
        });
        await store.put(toStoredRow(merged));
        await tx.done;
        return merged;
      }

      if (current.walletSessionId !== incoming.walletSessionId) {
        const retired = retireWalletSessionAuthorizationProjection({
          active: current,
          reason: 'replaced',
          retiredAtMs: args.writtenAtMs,
        });
        await store.put(toStoredRow(retired));
      }
      await store.put(toStoredRow(incoming));
      await tx.done;
      return incoming;
    } catch (error) {
      try {
        tx.abort();
      } catch {}
      await tx.done.catch(() => undefined);
      throw error;
    }
  }

  async read(walletSessionId: WalletSessionId): Promise<WalletSessionAuthorizationReadResult> {
    try {
      const db = await this.manager.getDB();
      const raw = await db.get(STORE, walletSessionId);
      if (raw === undefined) return { kind: 'missing' };
      const projection = parseStoredRow(raw);
      return projection ? found(projection) : { kind: 'corrupt' };
    } catch {
      return { kind: 'persistence_unavailable' };
    }
  }

  async readActiveForWallet(
    walletId: WalletId,
  ): Promise<WalletSessionAuthorizationReadResult<ActiveWalletSessionAuthorizationProjection>> {
    try {
      const db = await this.manager.getDB();
      const rows = await db.getAllFromIndex(STORE, SEAMS_WALLET_INDEXES.walletId, walletId);
      const projections = rows.map(parseStoredRow);
      if (projections.some((projection) => projection === null)) {
        return { kind: 'corrupt' };
      }
      const active = projections.filter(
        (projection): projection is ActiveWalletSessionAuthorizationProjection =>
          projection?.status === 'active',
      );
      if (active.length === 0) return { kind: 'missing' };
      if (active.length !== 1) return { kind: 'corrupt' };
      return found(active[0]!);
    } catch {
      return { kind: 'persistence_unavailable' };
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
