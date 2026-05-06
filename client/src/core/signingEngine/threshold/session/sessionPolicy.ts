import { alphabetizeStringify, sha256BytesUtf8 } from '@shared/utils/digests';
import { base64UrlEncode } from '@shared/utils/encoders';
import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import {
  normalizeRuntimePolicyScope,
  type RuntimePolicyScope,
} from '@shared/threshold/signingRootScope';
import type {
  ThresholdEcdsaChainTarget,
  WalletSubjectId,
} from '../../session/signingSession/ecdsaChainTarget';

export type ThresholdRuntimePolicyScope = RuntimePolicyScope;

export const THRESHOLD_SESSION_POLICY_VERSION = 'threshold_session_v1' as const;

function decodeBase64UrlUtf8(input: string): string | null {
  const normalized = String(input || '')
    .trim()
    .replace(/-/g, '+')
    .replace(/_/g, '/');
  if (!normalized) return null;
  const padded = normalized + '='.repeat((4 - (normalized.length % 4 || 4)) % 4);
  try {
    if (typeof atob === 'function') {
      const binary = atob(padded);
      const bytes = Uint8Array.from(binary, (ch) => ch.charCodeAt(0));
      return new TextDecoder().decode(bytes);
    }
  } catch {}
  return null;
}

export function normalizeThresholdRuntimePolicyScope(
  value: unknown,
): ThresholdRuntimePolicyScope | undefined {
  try {
    return normalizeRuntimePolicyScope(value);
  } catch {
    return undefined;
  }
}

export function parseThresholdRuntimePolicyScopeFromJwt(
  jwtRaw: string | undefined,
): ThresholdRuntimePolicyScope | undefined {
  const jwt = String(jwtRaw || '').trim();
  if (!jwt) return undefined;
  const parts = jwt.split('.');
  if (parts.length < 2) return undefined;
  const payloadJson = decodeBase64UrlUtf8(parts[1] || '');
  if (!payloadJson) return undefined;
  try {
    const payload = JSON.parse(payloadJson) as { runtimePolicyScope?: unknown };
    return normalizeThresholdRuntimePolicyScope(payload.runtimePolicyScope);
  } catch {
    return undefined;
  }
}

export type Ed25519SessionPolicy = {
  version: typeof THRESHOLD_SESSION_POLICY_VERSION;
  nearAccountId: string;
  rpId: string;
  relayerKeyId: string;
  sessionId: string;
  walletSigningSessionId: string;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  /**
   * Optional signer set binding (participant ids).
   *
   * When present, the relayer must bind the session token to this signer set and ensure
   * downstream signature share usage is scoped to the same set.
   */
  participantIds?: number[];
  ttlMs: number;
  remainingUses: number;
};

export type EcdsaSessionPolicy = {
  version: typeof THRESHOLD_SESSION_POLICY_VERSION;
  userId: string;
  subjectId: WalletSubjectId;
  rpId: string;
  relayerKeyId: string;
  chainTarget: ThresholdEcdsaChainTarget;
  ecdsaThresholdKeyId: string;
  sessionId: string;
  walletSigningSessionId: string;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  /**
   * Optional signer set binding (participant ids).
   *
   * When present, the relayer must bind the session token to this signer set and ensure
   * downstream signature share usage is scoped to the same set.
   */
  participantIds?: number[];
  ttlMs: number;
  remainingUses: number;
};

// Upper bounds to avoid unbounded TTL/use values while still supporting practical
// "login once, sign many times" sessions.
export const THRESHOLD_SESSION_POLICY_MAX_TTL_MS = 30 * 24 * 60 * 60_000; // 30 days
export const THRESHOLD_SESSION_POLICY_MAX_USES = 1_000_000;

// Default policy used when callers do not specify a policy explicitly.
// These defaults are kept conservative to limit the blast radius of a stolen token.
export const DEFAULT_THRESHOLD_SESSION_POLICY: Pick<
  Ed25519SessionPolicy,
  'ttlMs' | 'remainingUses'
> = {
  ttlMs: 5 * 60_000,
  remainingUses: 5,
};

export function clampThresholdSessionPolicy(input: { ttlMs: number; remainingUses: number }): {
  ttlMs: number;
  remainingUses: number;
} {
  const ttlMs = Math.max(0, Math.floor(Number(input.ttlMs) || 0));
  const remainingUses = Math.max(0, Math.floor(Number(input.remainingUses) || 0));
  return {
    ttlMs: Math.min(ttlMs, THRESHOLD_SESSION_POLICY_MAX_TTL_MS),
    remainingUses: Math.min(remainingUses, THRESHOLD_SESSION_POLICY_MAX_USES),
  };
}

export function generateThresholdSessionId(): string {
  const id =
    typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
      ? crypto.randomUUID()
      : `tsess-${Date.now()}-${Math.random().toString(16).slice(2)}`;
  return `tsess-${id}`;
}

export function generateWalletSigningSessionId(): string {
  const id =
    typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
      ? crypto.randomUUID()
      : `wsess-${Date.now()}-${Math.random().toString(16).slice(2)}`;
  return `wsess-${id}`;
}

export async function computeEd25519SessionPolicyDigest32(
  policy: Ed25519SessionPolicy,
): Promise<string> {
  const json = alphabetizeStringify(policy);
  const bytes = await sha256BytesUtf8(json);
  return base64UrlEncode(bytes);
}

export async function computeEcdsaSessionPolicyDigest32(
  policy: EcdsaSessionPolicy,
): Promise<string> {
  const json = alphabetizeStringify(policy);
  const bytes = await sha256BytesUtf8(json);
  return base64UrlEncode(bytes);
}

export async function buildEd25519SessionPolicy(params: {
  nearAccountId: string;
  rpId: string;
  relayerKeyId: string;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  participantIds?: number[];
  sessionId?: string;
  walletSigningSessionId?: string;
  ttlMs?: number;
  remainingUses?: number;
}): Promise<{
  policy: Ed25519SessionPolicy;
  policyJson: string;
  sessionPolicyDigest32: string;
}> {
  const sessionId = params.sessionId || generateThresholdSessionId();
  const walletSigningSessionId =
    String(params.walletSigningSessionId || '').trim() || generateWalletSigningSessionId();
  const { ttlMs, remainingUses } = clampThresholdSessionPolicy({
    ttlMs: params.ttlMs ?? DEFAULT_THRESHOLD_SESSION_POLICY.ttlMs,
    remainingUses: params.remainingUses ?? DEFAULT_THRESHOLD_SESSION_POLICY.remainingUses,
  });
  const participantIds = normalizeThresholdEd25519ParticipantIds(params.participantIds);
  const runtimePolicyScope = normalizeThresholdRuntimePolicyScope(params.runtimePolicyScope);
  const policy: Ed25519SessionPolicy = {
    version: THRESHOLD_SESSION_POLICY_VERSION,
    nearAccountId: params.nearAccountId,
    rpId: params.rpId,
    relayerKeyId: params.relayerKeyId,
    sessionId,
    walletSigningSessionId,
    ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
    ...(participantIds ? { participantIds } : {}),
    ttlMs,
    remainingUses,
  };
  const sessionPolicyDigest32 = await computeEd25519SessionPolicyDigest32(policy);
  return { policy, policyJson: JSON.stringify(policy), sessionPolicyDigest32 };
}

export async function buildEcdsaSessionPolicy(params: {
  userId: string;
  subjectId: WalletSubjectId;
  rpId: string;
  relayerKeyId: string;
  chainTarget: ThresholdEcdsaChainTarget;
  ecdsaThresholdKeyId: string;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  participantIds?: number[];
  sessionId?: string;
  walletSigningSessionId?: string;
  ttlMs?: number;
  remainingUses?: number;
}): Promise<{
  policy: EcdsaSessionPolicy;
  policyJson: string;
  sessionPolicyDigest32: string;
}> {
  const sessionId = params.sessionId || generateThresholdSessionId();
  const walletSigningSessionId =
    String(params.walletSigningSessionId || '').trim() || generateWalletSigningSessionId();
  const { ttlMs, remainingUses } = clampThresholdSessionPolicy({
    ttlMs: params.ttlMs ?? DEFAULT_THRESHOLD_SESSION_POLICY.ttlMs,
    remainingUses: params.remainingUses ?? DEFAULT_THRESHOLD_SESSION_POLICY.remainingUses,
  });
  const participantIds = normalizeThresholdEd25519ParticipantIds(params.participantIds);
  const runtimePolicyScope = normalizeThresholdRuntimePolicyScope(params.runtimePolicyScope);
  const policy: EcdsaSessionPolicy = {
    version: THRESHOLD_SESSION_POLICY_VERSION,
    userId: params.userId,
    subjectId: params.subjectId,
    rpId: params.rpId,
    relayerKeyId: params.relayerKeyId,
    chainTarget: params.chainTarget,
    ecdsaThresholdKeyId: params.ecdsaThresholdKeyId,
    sessionId,
    walletSigningSessionId,
    ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
    ...(participantIds ? { participantIds } : {}),
    ttlMs,
    remainingUses,
  };
  const sessionPolicyDigest32 = await computeEcdsaSessionPolicyDigest32(policy);
  return { policy, policyJson: JSON.stringify(policy), sessionPolicyDigest32 };
}

export function isThresholdSessionAuthUnavailableError(err: unknown): boolean {
  const msg = err instanceof Error ? err.message : String(err);
  return (
    msg.includes('no cached threshold session token') ||
    msg.includes('threshold-ecdsa session token unavailable') ||
    msg.includes('threshold-ecdsa session record not available') ||
    msg.includes('relayer threshold session expired') ||
    msg.includes('threshold signingSession is not_found') ||
    msg.includes('threshold signingSession is expired') ||
    msg.includes('threshold signingSession is exhausted') ||
    msg.includes('threshold signingSession auth is unavailable') ||
    msg.includes('threshold session exhausted') ||
    msg.includes('threshold session expired') ||
    msg.includes('Missing or invalid threshold session token') ||
    msg.includes('Invalid session token kind') ||
    msg.includes('/authorize HTTP 401') ||
    msg.includes('/authorize HTTP 403')
  );
}

export function isThresholdSignerMissingKeyError(err: unknown): boolean {
  const msg = (err instanceof Error ? err.message : String(err)).toLowerCase();
  return (
    msg.includes('"code":"missing_key"') ||
    msg.includes('missing_key') ||
    msg.includes('unknown relayerkeyid')
  );
}
