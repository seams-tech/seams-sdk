import { stripTrailingSlashes, toTrimmedString } from '../../../../../../shared/src/utils/validation';
import type { ThresholdEcdsaSessionPolicy } from './thresholdSessionPolicy';
import type { WebAuthnAuthenticationCredential } from '../../../types/webauthn';
import { normalizeThresholdEd25519ParticipantIds } from '../../../../../../shared/src/threshold/participants';

export type ThresholdEcdsaSessionKind = 'jwt' | 'cookie';

export type ThresholdEcdsaAuthSession = {
  sessionKind: ThresholdEcdsaSessionKind;
  policy: ThresholdEcdsaSessionPolicy;
  policyJson: string;
  sessionPolicyDigest32: string;
  jwt?: string;
  expiresAtMs?: number;
};

type ThresholdEcdsaAuthSessionCacheEntry = ThresholdEcdsaAuthSession;

const authSessionCache = new Map<string, ThresholdEcdsaAuthSessionCacheEntry>();

export function makeThresholdEcdsaAuthSessionCacheKey(args: {
  userId: string;
  rpId: string;
  relayerUrl: string;
  relayerKeyId: string;
  participantIds?: number[];
}): string {
  const relayerUrl = stripTrailingSlashes(toTrimmedString(args.relayerUrl));
  const participantIds = normalizeThresholdEd25519ParticipantIds(args.participantIds);
  return [
    String(args.userId || '').trim(),
    String(args.rpId || '').trim(),
    relayerUrl,
    String(args.relayerKeyId || '').trim(),
    ...(participantIds ? [participantIds.join(',')] : []),
  ].join('|');
}

export function getCachedThresholdEcdsaAuthSession(cacheKey: string): ThresholdEcdsaAuthSession | null {
  const entry = authSessionCache.get(cacheKey);
  if (!entry) return null;

  if (typeof entry.expiresAtMs === 'number' && Number.isFinite(entry.expiresAtMs) && Date.now() >= entry.expiresAtMs) {
    authSessionCache.delete(cacheKey);
    return null;
  }

  return entry;
}

export function putCachedThresholdEcdsaAuthSession(cacheKey: string, entry: ThresholdEcdsaAuthSession): void {
  authSessionCache.set(cacheKey, entry);
}

export function clearCachedThresholdEcdsaAuthSession(cacheKey: string): void {
  authSessionCache.delete(cacheKey);
}

export function clearAllCachedThresholdEcdsaAuthSessions(): void {
  authSessionCache.clear();
}

export function getCachedThresholdEcdsaAuthSessionJwt(cacheKey: string): string | undefined {
  const cached = getCachedThresholdEcdsaAuthSession(cacheKey);
  const jwt = cached?.jwt;
  if (typeof jwt === 'string') {
    const trimmed = jwt.trim();
    if (trimmed) return trimmed;
  }
  if (cached) clearCachedThresholdEcdsaAuthSession(cacheKey);
  return undefined;
}

/**
 * Lite (WebAuthn-only) threshold session mint.
 *
 * The server verifies the WebAuthn assertion directly and binds the session to the
 * `sessionPolicyDigest32` by using it as the WebAuthn challenge bytes (base64url string).
 *
 * Notes:
 * - Callers must ensure the WebAuthn `challenge` equals the session policy digest.
 * - PRF outputs must never be sent to the relay; they should be used only in wallet origin.
 */
export async function mintThresholdEcdsaAuthSessionLite(args: {
  relayerUrl: string;
  sessionKind: ThresholdEcdsaSessionKind;
  relayerKeyId: string;
  clientVerifyingShareB64u: string;
  sessionPolicy: ThresholdEcdsaSessionPolicy;
  webauthnAuthentication: WebAuthnAuthenticationCredential;
}): Promise<{
  ok: boolean;
  sessionId?: string;
  expiresAtMs?: number;
  remainingUses?: number;
  jwt?: string;
  code?: string;
  message?: string;
}> {
  // Bootstrap-only ECDSA flow: `/threshold-ecdsa/session` is no longer exposed.
  // Keep this API surface as an explicit compatibility error.
  void args;
  return {
    ok: false,
    code: 'not_supported',
    message: 'Legacy threshold-ecdsa/session flow removed; use bootstrapThresholdEcdsaLite',
  };
}
