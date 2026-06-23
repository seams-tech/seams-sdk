import { alphabetizeStringify, sha256BytesUtf8 } from '@shared/utils/digests';
import { base64UrlEncode } from '@shared/utils/encoders';
import { secureRandomId } from '@shared/utils/secureRandomId';
import { normalizeJwtCookieSessionKind } from '@shared/utils/normalize';
import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import {
  normalizeRuntimePolicyScope,
  type RuntimePolicyScope,
} from '@shared/threshold/signingRootScope';
import {
  ThresholdEcdsaChainTarget,
  toWalletId,
  type WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { RouterAbEd25519NormalSigningState } from '@shared/utils/signingSessionSeal';
import {
  toEcdsaHssThresholdKeyId,
  toEcdsaHssThresholdSessionId,
  toEcdsaHssSigningGrantId,
  type EcdsaThresholdKeyId,
  type ThresholdEcdsaSessionId,
  type SigningGrantId,
} from '../session/identity/emailOtpHssIdentity';

export type ThresholdRuntimePolicyScope = RuntimePolicyScope;
export type ThresholdSessionKind = 'jwt' | 'cookie';

export const THRESHOLD_SESSION_POLICY_VERSION = 'threshold_session_v1' as const;
export const THRESHOLD_ECDSA_SESSION_POLICY_VERSION = 'threshold_session_policy_v2' as const;

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

export function normalizeThresholdSessionKind(value: unknown): ThresholdSessionKind {
  return normalizeJwtCookieSessionKind(value);
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
  walletId: string;
  nearAccountId: string;
  ed25519KeyScopeId: string;
  rpId: string;
  relayerKeyId: string;
  thresholdSessionId: string;
  signingGrantId: string;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  routerAbNormalSigning?: RouterAbEd25519NormalSigningState;
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

export type EcdsaHssSessionPolicy = {
  version: typeof THRESHOLD_ECDSA_SESSION_POLICY_VERSION;
  walletId: WalletId;
  subjectId?: never;
  walletSessionUserId?: never;
  rpId: string;
  chainTarget: ThresholdEcdsaChainTarget;
  keyHandle?: string;
  ecdsaThresholdKeyId?: EcdsaThresholdKeyId;
  sessionId: ThresholdEcdsaSessionId;
  signingGrantId: SigningGrantId;
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

export type EcdsaSessionPolicy = EcdsaHssSessionPolicy & {
  relayerKeyId: string;
  ecdsaThresholdKeyId: EcdsaThresholdKeyId;
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
  remainingUses: 3,
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
  return secureRandomId('tsess', 32, 'threshold session IDs');
}

export function generateSigningGrantId(): string {
  return secureRandomId('wsess', 32, 'signing grant IDs');
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
  walletId: string;
  nearAccountId: string;
  ed25519KeyScopeId: string;
  rpId: string;
  relayerKeyId: string;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  routerAbNormalSigning?: RouterAbEd25519NormalSigningState;
  participantIds?: number[];
  thresholdSessionId?: string;
  signingGrantId?: string;
  ttlMs?: number;
  remainingUses?: number;
}): Promise<{
  policy: Ed25519SessionPolicy;
  policyJson: string;
  sessionPolicyDigest32: string;
}> {
  const thresholdSessionId = params.thresholdSessionId || generateThresholdSessionId();
  const signingGrantId = String(params.signingGrantId || '').trim() || generateSigningGrantId();
  const { ttlMs, remainingUses } = clampThresholdSessionPolicy({
    ttlMs: params.ttlMs ?? DEFAULT_THRESHOLD_SESSION_POLICY.ttlMs,
    remainingUses: params.remainingUses ?? DEFAULT_THRESHOLD_SESSION_POLICY.remainingUses,
  });
  const participantIds = normalizeThresholdEd25519ParticipantIds(params.participantIds);
  const runtimePolicyScope = normalizeThresholdRuntimePolicyScope(params.runtimePolicyScope);
  const policy: Ed25519SessionPolicy = {
    version: THRESHOLD_SESSION_POLICY_VERSION,
    walletId: params.walletId,
    nearAccountId: params.nearAccountId,
    ed25519KeyScopeId: params.ed25519KeyScopeId,
    rpId: params.rpId,
    relayerKeyId: params.relayerKeyId,
    thresholdSessionId,
    signingGrantId,
    ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
    ...(params.routerAbNormalSigning
      ? { routerAbNormalSigning: params.routerAbNormalSigning }
      : {}),
    ...(participantIds ? { participantIds } : {}),
    ttlMs,
    remainingUses,
  };
  const sessionPolicyDigest32 = await computeEd25519SessionPolicyDigest32(policy);
  return { policy, policyJson: JSON.stringify(policy), sessionPolicyDigest32 };
}

export async function buildEcdsaSessionPolicy(params: {
  walletId: unknown;
  subjectId?: never;
  walletSessionUserId?: never;
  rpId: string;
  relayerKeyId: string;
  chainTarget: ThresholdEcdsaChainTarget;
  ecdsaThresholdKeyId: unknown;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  participantIds?: number[];
  sessionId?: unknown;
  signingGrantId?: unknown;
  ttlMs?: number;
  remainingUses?: number;
}): Promise<{
  policy: EcdsaSessionPolicy;
  policyJson: string;
  sessionPolicyDigest32: string;
}> {
  const hssPolicy = buildEcdsaHssSessionPolicy(params);
  if (!hssPolicy.ecdsaThresholdKeyId) {
    throw new Error('[threshold-ecdsa] ecdsaThresholdKeyId is required');
  }
  const relayerKeyId = String(params.relayerKeyId || '').trim();
  if (!relayerKeyId) {
    throw new Error('[threshold-ecdsa] relayerKeyId is required');
  }
  const policy: EcdsaSessionPolicy = {
    ...hssPolicy,
    relayerKeyId,
    ecdsaThresholdKeyId: hssPolicy.ecdsaThresholdKeyId,
  };
  const sessionPolicyDigest32 = await computeEcdsaSessionPolicyDigest32(policy);
  return { policy, policyJson: JSON.stringify(policy), sessionPolicyDigest32 };
}

export function buildEcdsaHssSessionPolicy(params: {
  walletId: unknown;
  subjectId?: never;
  walletSessionUserId?: never;
  rpId: string;
  chainTarget: ThresholdEcdsaChainTarget;
  keyHandle?: unknown;
  ecdsaThresholdKeyId?: unknown;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  participantIds?: number[];
  sessionId?: unknown;
  signingGrantId?: unknown;
  ttlMs?: number;
  remainingUses?: number;
}): EcdsaHssSessionPolicy {
  const sessionId = params.sessionId || generateThresholdSessionId();
  const signingGrantId = String(params.signingGrantId || '').trim() || generateSigningGrantId();
  const { ttlMs, remainingUses } = clampThresholdSessionPolicy({
    ttlMs: params.ttlMs ?? DEFAULT_THRESHOLD_SESSION_POLICY.ttlMs,
    remainingUses: params.remainingUses ?? DEFAULT_THRESHOLD_SESSION_POLICY.remainingUses,
  });
  const participantIds = normalizeThresholdEd25519ParticipantIds(params.participantIds);
  const runtimePolicyScope = normalizeThresholdRuntimePolicyScope(params.runtimePolicyScope);
  const keyHandle = String(params.keyHandle || '').trim();
  const ecdsaThresholdKeyId = String(params.ecdsaThresholdKeyId || '').trim();
  return {
    version: THRESHOLD_ECDSA_SESSION_POLICY_VERSION,
    walletId: toWalletId(params.walletId),
    rpId: params.rpId,
    chainTarget: params.chainTarget,
    ...(keyHandle ? { keyHandle } : {}),
    ...(ecdsaThresholdKeyId
      ? { ecdsaThresholdKeyId: toEcdsaHssThresholdKeyId(ecdsaThresholdKeyId) }
      : {}),
    sessionId: toEcdsaHssThresholdSessionId(sessionId),
    signingGrantId: toEcdsaHssSigningGrantId(signingGrantId),
    ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
    ...(participantIds ? { participantIds } : {}),
    ttlMs,
    remainingUses,
  };
}

export function isSigningSessionAuthUnavailableError(err: unknown): boolean {
  const msg = err instanceof Error ? err.message : String(err);
  return (
    msg.includes('threshold-ecdsa session record not available') ||
    msg.includes('relayer threshold session expired') ||
    msg.includes('threshold signingSession is not_found') ||
    msg.includes('threshold signingSession is expired') ||
    msg.includes('threshold signingSession is exhausted') ||
    msg.includes('signingSession auth is unavailable') ||
    msg.includes('signing-session consume returned not_found') ||
    msg.includes('Wallet Session auth is unavailable') ||
    msg.includes('threshold session exhausted') ||
    msg.includes('threshold session expired') ||
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

export function isThresholdSignerRepairableMaterialError(err: unknown): boolean {
  const msg = (err instanceof Error ? err.message : String(err)).toLowerCase();
  return (
    isThresholdSignerMissingKeyError(err) ||
    msg.includes('ed25519 verifying shares do not sum to group public key') ||
    msg.includes('client verifying share does not match x_client_base') ||
    msg.includes('router a/b ed25519 signing material handle') ||
    msg.includes('ed25519 hss material handle is not loaded') ||
    msg.includes('ed25519 worker material handle is not loaded')
  );
}
