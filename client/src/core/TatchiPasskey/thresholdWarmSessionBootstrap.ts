import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import type {
  WebAuthnAuthenticationCredential,
  WebAuthnRegistrationCredential,
  AccountId,
} from '../types';
import { THRESHOLD_ED25519_2P_PARTICIPANT_IDS } from '../config/defaultConfigs';
import {
  buildAndCacheEd25519AuthSession,
  type Ed25519SessionKind,
} from '../signingEngine/threshold/session/ed25519AuthSession';
import { getPrfFirstB64uFromCredential } from '../signingEngine/threshold/webauthn';
import {
  THRESHOLD_SESSION_POLICY_VERSION,
  generateThresholdSessionId,
} from '../signingEngine/threshold/session/sessionPolicy';
import type { PasskeyManagerContext } from './index';
import { resolveThresholdWarmSessionDefaults } from './thresholdWarmSessionDefaults';

export type ThresholdWarmSessionPolicyDraft = {
  sessionId: string;
  ttlMs: number;
  remainingUses: number;
  participantIds?: number[];
};

export type ThresholdWarmSessionBootstrapPayload = {
  client_verifying_share_b64u: string;
  session_policy: {
    version: typeof THRESHOLD_SESSION_POLICY_VERSION;
    nearAccountId?: string;
    rpId: string;
    relayerKeyId?: string;
    sessionId: string;
    participantIds?: number[];
    ttlMs: number;
    remainingUses: number;
  };
  session_kind: 'jwt';
};

export type ThresholdWarmSessionRelayResult = {
  sessionKind?: string;
  sessionId?: string;
  expiresAtMs?: number;
  participantIds?: number[];
  remainingUses?: number;
  jwt?: string;
};

function parsePositiveInt(value: unknown): number {
  const n = typeof value === 'number' ? value : Number(value);
  if (!Number.isFinite(n) || n <= 0) return 0;
  return Math.floor(n);
}

export function createThresholdWarmSessionPolicyDraft(
  context: PasskeyManagerContext,
  input?: { sessionId?: string; participantIds?: number[] },
): ThresholdWarmSessionPolicyDraft | null {
  const defaults = resolveThresholdWarmSessionDefaults(context);
  if (!defaults) return null;
  const sessionId = String(input?.sessionId || '').trim() || generateThresholdSessionId();
  const participantIds = normalizeThresholdEd25519ParticipantIds(input?.participantIds);
  return {
    sessionId,
    ttlMs: defaults.ttlMs,
    remainingUses: defaults.remainingUses,
    ...(participantIds ? { participantIds } : {}),
  };
}

export function buildThresholdWarmSessionBootstrapPayload(args: {
  clientVerifyingShareB64u: string;
  rpId: string;
  policy: ThresholdWarmSessionPolicyDraft;
  nearAccountId?: string;
  relayerKeyId?: string;
}): ThresholdWarmSessionBootstrapPayload {
  return {
    client_verifying_share_b64u: String(args.clientVerifyingShareB64u || '').trim(),
    session_policy: {
      version: THRESHOLD_SESSION_POLICY_VERSION,
      ...(args.nearAccountId ? { nearAccountId: String(args.nearAccountId || '').trim() } : {}),
      rpId: String(args.rpId || '').trim(),
      ...(args.relayerKeyId ? { relayerKeyId: String(args.relayerKeyId || '').trim() } : {}),
      sessionId: String(args.policy.sessionId || '').trim(),
      ...(Array.isArray(args.policy.participantIds)
        ? { participantIds: args.policy.participantIds }
        : {}),
      ttlMs: args.policy.ttlMs,
      remainingUses: args.policy.remainingUses,
    },
    session_kind: 'jwt',
  };
}

export async function hydrateThresholdWarmSessionFromRelay(args: {
  context: PasskeyManagerContext;
  nearAccountId: AccountId | string;
  relayerUrl: string;
  rpId: string;
  relayerKeyId: string;
  credential: WebAuthnAuthenticationCredential | WebAuthnRegistrationCredential;
  requestedPolicy: ThresholdWarmSessionPolicyDraft;
  session: ThresholdWarmSessionRelayResult;
  participantIdsHint?: number[];
  setActiveSigningSessionId?: boolean;
}): Promise<{
  sessionId: string;
  expiresAtMs: number;
  remainingUses: number;
  participantIds: number[];
}> {
  const sessionKind = String(args.session?.sessionKind || 'jwt')
    .trim()
    .toLowerCase() as Ed25519SessionKind;
  if (sessionKind !== 'jwt') {
    throw new Error('threshold-ed25519 bootstrap sessionKind must be jwt');
  }

  const sessionId =
    String(args.session?.sessionId || '').trim() || String(args.requestedPolicy.sessionId || '').trim();
  const sessionJwt = String(args.session?.jwt || '').trim();
  const expiresAtMs = Number(args.session?.expiresAtMs);
  if (!sessionId || !sessionJwt || !Number.isFinite(expiresAtMs) || expiresAtMs <= 0) {
    throw new Error('threshold-ed25519 bootstrap response missing session fields');
  }

  const remainingUsesRaw = parsePositiveInt(args.session?.remainingUses);
  const remainingUses =
    remainingUsesRaw > 0 ? remainingUsesRaw : parsePositiveInt(args.requestedPolicy.remainingUses);
  if (remainingUses <= 0) {
    throw new Error('threshold-ed25519 bootstrap response missing remainingUses');
  }

  const participantIds =
    normalizeThresholdEd25519ParticipantIds(args.session?.participantIds) ||
    normalizeThresholdEd25519ParticipantIds(args.requestedPolicy.participantIds) ||
    normalizeThresholdEd25519ParticipantIds(args.participantIdsHint) ||
    [...THRESHOLD_ED25519_2P_PARTICIPANT_IDS];
  const prfFirstB64u = String(getPrfFirstB64uFromCredential(args.credential) || '').trim();
  if (!prfFirstB64u) {
    throw new Error('Missing PRF.first output from credential for threshold session hydration');
  }

  await args.context.signingEngine.hydrateSigningSession({
    nearAccountId: args.nearAccountId,
    sessionId,
    prfFirstB64u,
    expiresAtMs: Math.floor(expiresAtMs),
    remainingUses,
    setActiveSigningSessionId: args.setActiveSigningSessionId !== false,
  });
  await buildAndCacheEd25519AuthSession({
    nearAccountId: String(args.nearAccountId),
    rpId: String(args.rpId || '').trim(),
    relayerUrl: String(args.relayerUrl || '').trim(),
    relayerKeyId: String(args.relayerKeyId || '').trim(),
    participantIds,
    sessionKind: 'jwt',
    sessionId,
    expiresAtMs: Math.floor(expiresAtMs),
    remainingUses,
    jwt: sessionJwt,
  });

  return {
    sessionId,
    expiresAtMs: Math.floor(expiresAtMs),
    remainingUses,
    participantIds,
  };
}
