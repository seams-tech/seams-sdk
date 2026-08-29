import {
  parseWalletSessionAuthorizationId,
  parseMpcWalletSigningQuotaId,
  parseReusableWalletSessionAuthorizationId,
  type WalletSessionAuthorizationId,
  parseWalletSessionId,
  type MpcWalletSigningQuotaId,
  type ReusableWalletSessionAuthorizationId,
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
import {
  parseThresholdEcdsaSessionId,
  parseThresholdEd25519SessionId,
  type ThresholdEcdsaSessionId,
  type ThresholdEd25519SessionId,
} from '@shared/utils/domainIds';
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

export const WALLET_SESSION_AUTHORIZATION_RECORD_VERSION =
  'wallet_session_authorization_v3' as const;
export const WALLET_SESSION_AUTHORIZATION_RECORD_VERSION_V4 =
  'wallet_session_authorization_v4' as const;
export const WALLET_SESSION_AUTHORIZATION_RECORD_VERSION_V5 =
  'wallet_session_authorization_v5' as const;
export const WALLET_SESSION_AUTHORIZATION_RECORD_VERSION_V6 =
  'wallet_session_authorization_v6' as const;

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

export type WalletSessionAuthorizationRecordV4 = ActiveWalletSessionV1 | RetiredWalletSessionV1;

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
  const authorizationId = parseReusableWalletSessionAuthorizationId(value.authorizationId);
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
  const authorizationId = parseReusableWalletSessionAuthorizationId(value.authorizationId);
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
    left.authority.kind === right.authority.kind &&
    left.authority.walletId === right.authority.walletId &&
    left.authority.authorityDigest === right.authority.authorityDigest &&
    left.authority.walletAuthMethodId === right.authority.walletAuthMethodId
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

type StoredExactWalletSessionAuthorizationRow = {
  readonly record_version: typeof WALLET_SESSION_AUTHORIZATION_RECORD_VERSION_V4;
  readonly wallet_session_id: string;
  readonly wallet_id: string;
  readonly wallet_authority_id: string;
  readonly wallet_auth_method_id: string;
  readonly authority_digest_b64u: string;
  readonly authority_revocation_epoch: number;
  readonly status: 'active' | 'retired';
  readonly issued_at_ms: number;
  readonly expires_at_ms: number;
  readonly record: WalletSessionAuthorizationRecordV4;
};

type StoredExactWalletSessionAuthorizationRowV5 = Omit<
  StoredExactWalletSessionAuthorizationRow,
  'record_version'
> & {
  readonly record_version: typeof WALLET_SESSION_AUTHORIZATION_RECORD_VERSION_V5;
  readonly operation_credential: WalletSessionOperationCredentialV1;
};

type StoredActiveWalletSessionV6 = ActiveWalletSessionV1 & {
  readonly walletSessionId: WalletSessionId;
};

export type StoredExactWalletSessionAuthorizationRowV6 = Omit<
  StoredExactWalletSessionAuthorizationRowV5,
  'record_version' | 'record'
> & {
  readonly record_version: typeof WALLET_SESSION_AUTHORIZATION_RECORD_VERSION_V6;
  readonly authorization_id: string;
  readonly record: StoredActiveWalletSessionV6;
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
const EXACT_STORED_ROW_FIELDS = [
  'record_version',
  'wallet_session_id',
  'wallet_id',
  'wallet_authority_id',
  'wallet_auth_method_id',
  'authority_digest_b64u',
  'authority_revocation_epoch',
  'status',
  'issued_at_ms',
  'expires_at_ms',
  'record',
] as const;
const EXACT_STORED_ROW_V5_FIELDS = [...EXACT_STORED_ROW_FIELDS, 'operation_credential'] as const;
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
    value.record_version === WALLET_SESSION_AUTHORIZATION_RECORD_VERSION_V4 ||
    value.record_version === WALLET_SESSION_AUTHORIZATION_RECORD_VERSION_V5
  ) {
    return true;
  }
  if (Object.prototype.hasOwnProperty.call(value, 'record_version')) return false;
  return (
    isRecord(value.record) &&
    value.record.recordVersion === WALLET_SESSION_AUTHORIZATION_RECORD_VERSION
  );
}

function isStoredExactWalletSessionAuthorizationRowV6(value: unknown): boolean {
  return isRecord(value) && value.record_version === WALLET_SESSION_AUTHORIZATION_RECORD_VERSION_V6;
}

function isKnownExactOrCurrentWalletSessionAuthorizationRow(value: unknown): boolean {
  return (
    isStoredExactWalletSessionAuthorizationRowV6(value) ||
    (isRecord(value) &&
      (value.record_version === WALLET_SESSION_AUTHORIZATION_RECORD_VERSION_V4 ||
        value.record_version === WALLET_SESSION_AUTHORIZATION_RECORD_VERSION_V5))
  );
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

function parseExactWalletSessionRecord(value: unknown): WalletSessionAuthorizationRecordV4 | null {
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

export function parseExactWalletSessionAuthorizationRecordV4(
  value: unknown,
): WalletSessionAuthorizationRecordV4 | null {
  return parseExactWalletSessionRecord(value);
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

export function toStoredExactWalletSessionAuthorizationRow(
  record: WalletSessionAuthorizationRecordV4,
): StoredExactWalletSessionAuthorizationRow {
  const parsed = parseExactWalletSessionRecord(record);
  if (!parsed) throw new Error('Wallet Session authorization v4 is invalid');
  return {
    record_version: WALLET_SESSION_AUTHORIZATION_RECORD_VERSION_V4,
    wallet_session_id: parsed.authorizationId,
    wallet_id: parsed.walletId,
    wallet_authority_id: parsed.authorityId,
    wallet_auth_method_id: parsed.authMethodId,
    authority_digest_b64u: parsed.authorityDigestB64u,
    authority_revocation_epoch: parsed.authorityRevocationEpoch,
    status: parsed.kind === 'active_wallet_session_v1' ? 'active' : 'retired',
    issued_at_ms: parsed.issuedAtMs,
    expires_at_ms: parsed.expiresAtMs,
    record: parsed,
  };
}

export function toStoredExactWalletSessionAuthorizationRowV5(
  record: ActiveWalletSessionV1,
  operationCredential: WalletSessionOperationCredentialV1,
): StoredExactWalletSessionAuthorizationRowV5 {
  const stored = toStoredExactWalletSessionAuthorizationRow(record);
  const parsedOperationCredential = parseWalletSessionOperationCredentialV1(operationCredential);
  return {
    record_version: WALLET_SESSION_AUTHORIZATION_RECORD_VERSION_V5,
    wallet_session_id: parsedOperationCredential.walletSessionId,
    wallet_id: stored.wallet_id,
    wallet_authority_id: stored.wallet_authority_id,
    wallet_auth_method_id: stored.wallet_auth_method_id,
    authority_digest_b64u: stored.authority_digest_b64u,
    authority_revocation_epoch: stored.authority_revocation_epoch,
    status: stored.status,
    issued_at_ms: stored.issued_at_ms,
    expires_at_ms: stored.expires_at_ms,
    record: stored.record,
    operation_credential: parsedOperationCredential,
  };
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

export function parseStoredExactWalletSessionAuthorizationRow(
  value: unknown,
): WalletSessionAuthorizationRecordV4 | null {
  if (!isRecord(value) || !hasExactFields(value, EXACT_STORED_ROW_FIELDS)) return null;
  const record = parseExactWalletSessionRecord(value.record);
  if (
    !record ||
    value.record_version !== WALLET_SESSION_AUTHORIZATION_RECORD_VERSION_V4 ||
    value.wallet_session_id !== record.authorizationId ||
    value.wallet_id !== record.walletId ||
    value.wallet_authority_id !== record.authorityId ||
    value.wallet_auth_method_id !== record.authMethodId ||
    value.authority_digest_b64u !== record.authorityDigestB64u ||
    value.authority_revocation_epoch !== record.authorityRevocationEpoch ||
    value.status !== (record.kind === 'active_wallet_session_v1' ? 'active' : 'retired') ||
    value.issued_at_ms !== record.issuedAtMs ||
    value.expires_at_ms !== record.expiresAtMs
  ) {
    return null;
  }
  return record;
}

export function parseStoredExactWalletSessionAuthorizationWithOperationCredential(value: unknown): {
  readonly record: ActiveWalletSessionV1;
  readonly operationCredential: WalletSessionOperationCredentialV1;
} | null {
  if (!isRecord(value) || !hasExactFields(value, EXACT_STORED_ROW_V5_FIELDS)) return null;
  if (value.record_version !== WALLET_SESSION_AUTHORIZATION_RECORD_VERSION_V5) return null;
  let operationCredential: WalletSessionOperationCredentialV1;
  try {
    operationCredential = parseWalletSessionOperationCredentialV1(value.operation_credential);
  } catch {
    return null;
  }
  const record = parseExactWalletSessionRecord(value.record);
  if (
    !record ||
    record.kind !== 'active_wallet_session_v1' ||
    value.wallet_session_id !== operationCredential.walletSessionId ||
    value.wallet_id !== record.walletId ||
    value.wallet_authority_id !== record.authorityId ||
    value.wallet_auth_method_id !== record.authMethodId ||
    value.authority_digest_b64u !== record.authorityDigestB64u ||
    value.authority_revocation_epoch !== record.authorityRevocationEpoch ||
    value.status !== 'active' ||
    value.issued_at_ms !== record.issuedAtMs ||
    value.expires_at_ms !== record.expiresAtMs
  ) {
    return null;
  }
  return { record, operationCredential };
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
        if (isFutureWalletSessionAuthorizationRow(raw)) continue;
        if (isKnownExactOrCurrentWalletSessionAuthorizationRow(raw)) {
          continue;
        }
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
      const projections = rows
        .filter((row) => !isFutureWalletSessionAuthorizationRow(row))
        .filter((row) => !isKnownExactOrCurrentWalletSessionAuthorizationRow(row))
        .map(parseStoredRow);
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
      const projections = rows
        .filter((row) => !isFutureWalletSessionAuthorizationRow(row))
        .filter((row) => !isKnownExactOrCurrentWalletSessionAuthorizationRow(row))
        .map(parseStoredRow);
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
      const projections = rows
        .filter((row) => !isFutureWalletSessionAuthorizationRow(row))
        .filter((row) => !isKnownExactOrCurrentWalletSessionAuthorizationRow(row))
        .map(parseStoredRow);
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

  async writeExact(
    record: WalletSessionAuthorizationRecordV4,
  ): Promise<WalletSessionAuthorizationRecordV4> {
    const parsed = parseExactWalletSessionRecord(record);
    if (!parsed) throw new Error('Wallet Session authorization v4 is invalid');
    const db = await this.manager.getDB();
    await db.put(STORE, toStoredExactWalletSessionAuthorizationRow(parsed));
    return parsed;
  }

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
      replacedAtMs: parsed.issuedAtMs,
    });
    return parsed;
  }

  async readExact(
    walletSessionId: WalletSessionId,
  ): Promise<WalletSessionAuthorizationRecordV4 | null> {
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
        if (isKnownLegacyWalletSessionAuthorizationRow(raw)) continue;
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
        await store.put(toStoredExactWalletSessionAuthorizationRow(next));
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
    readonly replacedAtMs: number;
  }): Promise<ActiveWalletSessionV1> {
    const incoming = parseExactWalletSessionRecord(args.active);
    if (!incoming || incoming.kind !== 'active_wallet_session_v1') {
      throw new Error('Active Wallet Session v1 is invalid');
    }
    const operationCredential = parseWalletSessionOperationCredentialV1(args.operationCredential);
    const incomingRow = toStoredExactWalletSessionAuthorizationRowV6(incoming, operationCredential);
    if (!isNonNegativeSafeInteger(args.replacedAtMs)) {
      throw new Error('Wallet Session v1 replacement time is invalid');
    }
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
          if (!parseStoredRow(raw)) {
            tx.abort();
            throw new Error('Stored Wallet Session authorization projection is corrupt');
          }
          continue;
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
        await store.put(
          toStoredExactWalletSessionAuthorizationRow(
            retireWalletSessionV1({
              active: current,
              reason: 'replaced',
              retiredAtMs: Math.max(args.replacedAtMs, current.issuedAtMs),
            }),
          ),
        );
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
