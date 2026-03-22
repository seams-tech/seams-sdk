import { toOptionalTrimmedString } from '@shared/utils/validation';
import type { RecoverySessionRecord } from './RecoverySessionStore';

export const DEFAULT_RECOVERY_SESSION_TTL_MS = 30 * 60_000;

function normalizeHexLike(value: unknown): string {
  const normalized = toOptionalTrimmedString(value);
  if (!normalized) return '';
  return normalized.startsWith('0x') ? normalized.toLowerCase() : normalized;
}

export function buildPreparedRecoverySessionRecord(input: {
  sessionId: string;
  userId: string;
  nearAccountId: string;
  deviceNumber: number;
  newNearPublicKey: string;
  newEvmOwnerAddress: string;
  recoveryDeadlineEpochSeconds: number;
  recoveryEmailPayloadHash: string;
  scope?: string;
  expiresAtMs?: number;
  nowMs?: number;
  metadata?: Record<string, unknown>;
}): RecoverySessionRecord | null {
  const sessionId = toOptionalTrimmedString(input.sessionId);
  const userId = toOptionalTrimmedString(input.userId);
  const nearAccountId = toOptionalTrimmedString(input.nearAccountId);
  const newNearPublicKey = toOptionalTrimmedString(input.newNearPublicKey);
  const newEvmOwnerAddress = normalizeHexLike(input.newEvmOwnerAddress);
  const recoveryDeadlineEpochSeconds = Math.floor(Number(input.recoveryDeadlineEpochSeconds));
  const recoveryEmailPayloadHash = toOptionalTrimmedString(input.recoveryEmailPayloadHash);
  const scope = toOptionalTrimmedString(input.scope);
  const deviceNumber = Math.floor(Number(input.deviceNumber));
  const nowMs = Number.isFinite(Number(input.nowMs)) ? Math.floor(Number(input.nowMs)) : Date.now();
  const expiresAtMs = Number.isFinite(Number(input.expiresAtMs))
    ? Math.floor(Number(input.expiresAtMs))
    : nowMs + DEFAULT_RECOVERY_SESSION_TTL_MS;

  if (
    !sessionId ||
    !userId ||
    !nearAccountId ||
    !newNearPublicKey ||
    !newEvmOwnerAddress ||
    !recoveryEmailPayloadHash
  ) {
    return null;
  }
  if (!Number.isFinite(deviceNumber) || deviceNumber < 1) return null;
  if (!Number.isFinite(expiresAtMs) || expiresAtMs <= nowMs) return null;
  if (!Number.isFinite(recoveryDeadlineEpochSeconds) || recoveryDeadlineEpochSeconds <= 0) {
    return null;
  }

  return {
    version: 'recovery_session_v1',
    sessionId,
    userId,
    nearAccountId,
    deviceNumber,
    status: 'prepared',
    createdAtMs: nowMs,
    updatedAtMs: nowMs,
    expiresAtMs,
    newNearPublicKey,
    newEvmOwnerAddress,
    recoveryDeadlineEpochSeconds,
    recoveryEmailPayloadHash,
    ...(scope ? { scope } : {}),
    ...(input.metadata ? { metadata: { ...input.metadata } } : {}),
  };
}
