import { alphabetizeStringify, sha256BytesUtf8 } from '@shared/utils/digests';
import { base64UrlEncode } from '@shared/utils/encoders';
import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';

export const THRESHOLD_SESSION_POLICY_VERSION = 'threshold_session_v1' as const;

export type Ed25519SessionPolicy = {
  version: typeof THRESHOLD_SESSION_POLICY_VERSION;
  nearAccountId: string;
  rpId: string;
  relayerKeyId: string;
  sessionId: string;
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
  rpId: string;
  relayerKeyId: string;
  sessionId: string;
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
export const DEFAULT_THRESHOLD_SESSION_POLICY: Pick<Ed25519SessionPolicy, 'ttlMs' | 'remainingUses'> = {
  ttlMs: 5 * 60_000,
  remainingUses: 5,
};

export function clampThresholdSessionPolicy(input: {
  ttlMs: number;
  remainingUses: number;
}): { ttlMs: number; remainingUses: number } {
  const ttlMs = Math.max(0, Math.floor(Number(input.ttlMs) || 0));
  const remainingUses = Math.max(0, Math.floor(Number(input.remainingUses) || 0));
  return {
    ttlMs: Math.min(ttlMs, THRESHOLD_SESSION_POLICY_MAX_TTL_MS),
    remainingUses: Math.min(remainingUses, THRESHOLD_SESSION_POLICY_MAX_USES),
  };
}

export function generateThresholdSessionId(): string {
  const id = (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function')
    ? crypto.randomUUID()
    : `tsess-${Date.now()}-${Math.random().toString(16).slice(2)}`;
  return `tsess-${id}`;
}

export async function computeEd25519SessionPolicyDigest32(policy: Ed25519SessionPolicy): Promise<string> {
  const json = alphabetizeStringify(policy);
  const bytes = await sha256BytesUtf8(json);
  return base64UrlEncode(bytes);
}

export async function computeEcdsaSessionPolicyDigest32(policy: EcdsaSessionPolicy): Promise<string> {
  const json = alphabetizeStringify(policy);
  const bytes = await sha256BytesUtf8(json);
  return base64UrlEncode(bytes);
}

export async function buildEd25519SessionPolicy(params: {
  nearAccountId: string;
  rpId: string;
  relayerKeyId: string;
  participantIds?: number[];
  sessionId?: string;
  ttlMs?: number;
  remainingUses?: number;
}): Promise<{
  policy: Ed25519SessionPolicy;
  policyJson: string;
  sessionPolicyDigest32: string;
}> {
  const sessionId = params.sessionId || generateThresholdSessionId();
  const { ttlMs, remainingUses } = clampThresholdSessionPolicy({
    ttlMs: params.ttlMs ?? DEFAULT_THRESHOLD_SESSION_POLICY.ttlMs,
    remainingUses: params.remainingUses ?? DEFAULT_THRESHOLD_SESSION_POLICY.remainingUses,
  });
  const participantIds = normalizeThresholdEd25519ParticipantIds(params.participantIds);
  const policy: Ed25519SessionPolicy = {
    version: THRESHOLD_SESSION_POLICY_VERSION,
    nearAccountId: params.nearAccountId,
    rpId: params.rpId,
    relayerKeyId: params.relayerKeyId,
    sessionId,
    ...(participantIds ? { participantIds } : {}),
    ttlMs,
    remainingUses,
  };
  const sessionPolicyDigest32 = await computeEd25519SessionPolicyDigest32(policy);
  return { policy, policyJson: JSON.stringify(policy), sessionPolicyDigest32 };
}

export async function buildEcdsaSessionPolicy(params: {
  userId: string;
  rpId: string;
  relayerKeyId: string;
  participantIds?: number[];
  sessionId?: string;
  ttlMs?: number;
  remainingUses?: number;
}): Promise<{
  policy: EcdsaSessionPolicy;
  policyJson: string;
  sessionPolicyDigest32: string;
}> {
  const sessionId = params.sessionId || generateThresholdSessionId();
  const { ttlMs, remainingUses } = clampThresholdSessionPolicy({
    ttlMs: params.ttlMs ?? DEFAULT_THRESHOLD_SESSION_POLICY.ttlMs,
    remainingUses: params.remainingUses ?? DEFAULT_THRESHOLD_SESSION_POLICY.remainingUses,
  });
  const participantIds = normalizeThresholdEd25519ParticipantIds(params.participantIds);
  const policy: EcdsaSessionPolicy = {
    version: THRESHOLD_SESSION_POLICY_VERSION,
    userId: params.userId,
    rpId: params.rpId,
    relayerKeyId: params.relayerKeyId,
    sessionId,
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
    msg.includes('relayer threshold session expired') ||
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
    msg.includes('unknown relayerkeyid') ||
    msg.includes('call /threshold-ed25519/keygen')
  );
}
