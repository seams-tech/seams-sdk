import {
  parseMpcWalletSigningQuotaId,
  parseSeamsSessionId,
  parseWalletSessionId,
  type MpcWalletSigningQuotaId,
  type SeamsSessionId,
  type WalletSessionId,
} from '@shared/authorization/capabilityKinds';
import { parseWalletId, type WalletId } from '@shared/utils/domainIds';
import { isWalletAuthMethod, type WalletAuthMethod } from '@shared/utils/signerDomain';
import { isWalletSessionJwt } from '@shared/utils/sessionTokens';
import {
  parseWalletAuthAuthorityRef,
  type WalletAuthAuthorityRef,
} from '@shared/utils/walletAuthAuthority';
import { SEAMS_WALLET_INDEXES, SEAMS_WALLET_STORES } from '../schemaNames';
import { seamsWalletDB } from '../singletons';
import type { SeamsWalletDBManager } from './manager';

export const WALLET_SESSION_AUTHORIZATION_RECORD_VERSION =
  'wallet_session_authorization_v1' as const;

declare const walletSessionAuthorizationJwtBrand: unique symbol;

export type WalletSessionAuthorizationJwt = string & {
  readonly [walletSessionAuthorizationJwtBrand]: true;
};

type WalletSessionAuthorizationIdentity = {
  readonly recordVersion: typeof WALLET_SESSION_AUTHORIZATION_RECORD_VERSION;
  readonly walletId: WalletId;
  readonly authorizationSessionId: SeamsSessionId;
  readonly walletSessionId: WalletSessionId;
  readonly quotaId: MpcWalletSigningQuotaId;
  readonly authMethod: WalletAuthMethod;
  readonly authority: WalletAuthAuthorityRef;
  readonly expiresAtMs: number;
};

export type ActiveWalletSessionAuthorizationProjection =
  WalletSessionAuthorizationIdentity & {
    readonly status: 'active';
    readonly walletSessionJwt: WalletSessionAuthorizationJwt;
    readonly retirementReason?: never;
    readonly retiredAtMs?: never;
  };

export type WalletSessionAuthorizationRetirementReason =
  | 'expired'
  | 'exhausted'
  | 'replaced'
  | 'wallet_locked'
  | 'invalidated';

export type RetiredWalletSessionAuthorizationProjection =
  WalletSessionAuthorizationIdentity & {
    readonly status: 'retired';
    readonly retirementReason: WalletSessionAuthorizationRetirementReason;
    readonly retiredAtMs: number;
    readonly walletSessionJwt?: never;
  };

export type WalletSessionAuthorizationProjection =
  | ActiveWalletSessionAuthorizationProjection
  | RetiredWalletSessionAuthorizationProjection;

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
  'recordVersion' | 'status' | 'walletSessionJwt'
> & {
  readonly walletSessionJwt: unknown;
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
  'authorizationSessionId',
  'walletSessionId',
  'quotaId',
  'walletSessionJwt',
  'authMethod',
  'authority',
  'expiresAtMs',
] as const;
const RETIRED_FIELDS = [
  'recordVersion',
  'status',
  'walletId',
  'authorizationSessionId',
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

function hasExactFields(
  record: Record<string, unknown>,
  expected: readonly string[],
): boolean {
  const fields = Object.keys(record);
  return (
    fields.length === expected.length &&
    fields.every((field) => expected.includes(field))
  );
}

function isPositiveSafeInteger(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value > 0;
}

function parseWalletSessionAuthorizationJwt(
  value: unknown,
): WalletSessionAuthorizationJwt | null {
  if (typeof value !== 'string') return null;
  const jwt = value.trim();
  return jwt && isWalletSessionJwt(jwt)
    ? (jwt as WalletSessionAuthorizationJwt)
    : null;
}

function parseRetirementReason(
  value: unknown,
): WalletSessionAuthorizationRetirementReason | null {
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
  const authorizationSessionId = parseSeamsSessionId(record.authorizationSessionId);
  const walletSessionId = parseWalletSessionId(record.walletSessionId);
  const quotaId = parseMpcWalletSigningQuotaId(record.quotaId);
  const authority = parseWalletAuthAuthorityRef(record.authority);
  if (
    !walletId.ok ||
    !authorizationSessionId.ok ||
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
    authorizationSessionId: authorizationSessionId.value,
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
      const walletSessionJwt = parseWalletSessionAuthorizationJwt(raw.walletSessionJwt);
      if (!walletSessionJwt) return null;
      return {
        recordVersion: WALLET_SESSION_AUTHORIZATION_RECORD_VERSION,
        status: 'active',
        ...identity,
        walletSessionJwt,
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
    authorizationSessionId: input.authorizationSessionId,
    walletSessionId: input.walletSessionId,
    quotaId: input.quotaId,
    walletSessionJwt: input.walletSessionJwt,
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
    authorizationSessionId: args.active.authorizationSessionId,
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
        if (
          current.status !== 'active' ||
          current.walletSessionId === parsed.walletSessionId
        ) {
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

  async read(
    walletSessionId: WalletSessionId,
  ): Promise<WalletSessionAuthorizationReadResult> {
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
      const rows = await db.getAllFromIndex(
        STORE,
        SEAMS_WALLET_INDEXES.walletId,
        walletId,
      );
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
    const keys = await db.getAllKeysFromIndex(
      STORE,
      SEAMS_WALLET_INDEXES.walletId,
      walletId,
    );
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
