import {
  thresholdEcdsaChainTargetFromRequest,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { SealedRecoveryRecord } from '../sealedRecovery/recoveryRecord';

export type ExactSealedSessionIdentity =
  | {
      authMethod: 'email_otp' | 'passkey';
      curve: 'ed25519';
      thresholdSessionId: string;
    }
  | {
      authMethod: 'email_otp' | 'passkey';
      curve: 'ecdsa';
      thresholdSessionId: string;
      chainTarget: ThresholdEcdsaChainTarget;
    };

export type DurableSealedSessionDeleteReason =
  | 'account_removed'
  | 'device_removed'
  | 'expired'
  | 'exhausted'
  | 'invalid_persisted_record'
  | 'migration_rejected'
  | 'trusted_persisted_delete';

export type DeleteDurableSealedSessionCommand = {
  kind: 'delete_durable_sealed_session';
  durableRecord: ExactSealedSessionIdentity;
  deleteReason: DurableSealedSessionDeleteReason;
  preserveResolvedIdentity: boolean;
  scope?: never;
};

export type ExactSealedSessionRecordFilter =
  | {
      authMethod: 'email_otp' | 'passkey';
      curve: 'ed25519';
    }
  | {
      authMethod: 'email_otp' | 'passkey';
      curve: 'ecdsa';
      chainTarget: ThresholdEcdsaChainTarget;
    };

function normalizeNonEmptyString(value: unknown): string | null {
  const normalized = String(value ?? '').trim();
  return normalized || null;
}

function parseAuthMethod(value: unknown): 'email_otp' | 'passkey' | null {
  return value === 'email_otp' || value === 'passkey' ? value : null;
}

function parseCurve(value: unknown): 'ed25519' | 'ecdsa' | null {
  return value === 'ed25519' || value === 'ecdsa' ? value : null;
}

function parseChainTarget(value: unknown): ThresholdEcdsaChainTarget | null {
  if (typeof value !== 'object' || value === null) return null;
  const raw = value as {
    chain?: unknown;
    kind?: unknown;
    namespace?: unknown;
    chainId?: unknown;
    networkSlug?: unknown;
  };
  try {
    return thresholdEcdsaChainTargetFromRequest(raw);
  } catch {
    return null;
  }
}

function assertNever(value: never): never {
  throw new Error(`Unhandled durable sealed-session identity: ${String(value)}`);
}

export function parseDurableSealedSessionDeleteReason(
  value: unknown,
): DurableSealedSessionDeleteReason | null {
  switch (value) {
    case 'account_removed':
    case 'device_removed':
    case 'expired':
    case 'exhausted':
    case 'invalid_persisted_record':
    case 'migration_rejected':
    case 'trusted_persisted_delete':
      return value;
    default:
      return null;
  }
}

export function parseExactSealedSessionIdentity(
  value: unknown,
): ExactSealedSessionIdentity | null {
  if (typeof value !== 'object' || value === null) return null;
  const record = value as Record<string, unknown>;
  const authMethod = parseAuthMethod(record.authMethod);
  const curve = parseCurve(record.curve);
  const thresholdSessionId = normalizeNonEmptyString(record.thresholdSessionId);
  if (!authMethod || !curve || !thresholdSessionId) return null;
  if (curve === 'ed25519') {
    return {
      authMethod,
      curve: 'ed25519',
      thresholdSessionId,
    };
  }
  const chainTarget = parseChainTarget(record.chainTarget);
  if (!chainTarget) return null;
  return {
    authMethod,
    curve: 'ecdsa',
    thresholdSessionId,
    chainTarget,
  };
}

export function exactSealedSessionIdentityFromFilter(args: {
  thresholdSessionId: string;
  filter: ExactSealedSessionRecordFilter;
}): ExactSealedSessionIdentity | null {
  const thresholdSessionId = normalizeNonEmptyString(args.thresholdSessionId);
  if (!thresholdSessionId) return null;
  switch (args.filter.curve) {
    case 'ed25519':
      return {
        authMethod: args.filter.authMethod,
        curve: 'ed25519',
        thresholdSessionId,
      };
    case 'ecdsa':
      return {
        authMethod: args.filter.authMethod,
        curve: 'ecdsa',
        thresholdSessionId,
        chainTarget: args.filter.chainTarget,
      };
    default:
      return assertNever(args.filter);
  }
}

export function exactSealedSessionIdentityFromRecoveryRecord(
  record: SealedRecoveryRecord,
): ExactSealedSessionIdentity {
  switch (record.curve) {
    case 'ed25519':
      return {
        authMethod: record.authMethod,
        curve: 'ed25519',
        thresholdSessionId: record.thresholdSessionId,
      };
    case 'ecdsa':
      return {
        authMethod: record.authMethod,
        curve: 'ecdsa',
        thresholdSessionId: record.thresholdSessionId,
        chainTarget: record.chainTarget,
      };
    default:
      return assertNever(record);
  }
}

export function parseDeleteDurableSealedSessionCommand(
  value: unknown,
): DeleteDurableSealedSessionCommand | null {
  if (typeof value !== 'object' || value === null) return null;
  const raw = value as Record<string, unknown>;
  if (raw.kind !== 'delete_durable_sealed_session') return null;
  if (raw.scope != null) return null;
  const durableRecord = parseExactSealedSessionIdentity(raw.durableRecord);
  const deleteReason = parseDurableSealedSessionDeleteReason(raw.deleteReason);
  if (!durableRecord || !deleteReason) return null;
  if (typeof raw.preserveResolvedIdentity !== 'boolean') return null;
  return {
    kind: 'delete_durable_sealed_session',
    durableRecord,
    deleteReason,
    preserveResolvedIdentity: raw.preserveResolvedIdentity,
  };
}

export function createDeleteDurableSealedSessionCommand(args: {
  durableRecord: ExactSealedSessionIdentity;
  deleteReason: DurableSealedSessionDeleteReason;
  preserveResolvedIdentity: boolean;
}): DeleteDurableSealedSessionCommand {
  return {
    kind: 'delete_durable_sealed_session',
    durableRecord: args.durableRecord,
    deleteReason: args.deleteReason,
    preserveResolvedIdentity: args.preserveResolvedIdentity,
  };
}

export function exactSealedSessionFilterForIdentity(
  identity: ExactSealedSessionIdentity,
): ExactSealedSessionRecordFilter {
  switch (identity.curve) {
    case 'ed25519':
      return {
        authMethod: identity.authMethod,
        curve: 'ed25519',
      };
    case 'ecdsa':
      return {
        authMethod: identity.authMethod,
        curve: 'ecdsa',
        chainTarget: identity.chainTarget,
      };
    default:
      return assertNever(identity);
  }
}
