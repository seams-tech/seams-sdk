import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import { computeThresholdEcdsaKeygenIntentDigest } from '@/utils/intentDigest';
import { thresholdEcdsaBootstrap } from '@/core/rpcClients/near/rpcCalls';
import { cacheSigningSessionPrfFirstBestEffort } from '@/core/signingEngine/api/session/signingSessionState';
import { deriveThresholdSecp256k1ClientShareWasm } from '../../signers/wasm/ethSignerWasm';
import type { WorkerOperationContext } from '../../workerManager/executeWorkerOperation';
import {
  collectAuthenticationCredentialForChallengeB64u,
  getPrfFirstB64uFromCredential,
  type ThresholdIndexedDbPort,
  type ThresholdPrfFirstCachePort,
  type ThresholdWebAuthnPromptPort,
} from '../webauthn';
import {
  clampThresholdSessionPolicy,
  DEFAULT_THRESHOLD_SESSION_POLICY,
  generateThresholdSessionId,
  THRESHOLD_SESSION_POLICY_VERSION,
} from '../session/sessionPolicy';

type EcdsaSessionKind = 'jwt' | 'cookie';

function generateKeygenSessionId(): string {
  const id =
    typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
      ? crypto.randomUUID()
      : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  return `tecdsa-keygen-${id}`;
}

export async function bootstrapEcdsaSession(args: {
  indexedDB: ThresholdIndexedDbPort;
  touchIdPrompt: ThresholdWebAuthnPromptPort;
  prfFirstCache?: ThresholdPrfFirstCachePort;
  relayerUrl: string;
  userId: string;
  participantIds?: number[];
  sessionKind?: EcdsaSessionKind;
  sessionId?: string;
  clientVerifyingShareB64u?: string;
  bootstrapAuthorizationJwt?: string;
  ttlMs?: number;
  remainingUses?: number;
  workerCtx: WorkerOperationContext;
}): Promise<{
  ok: boolean;
  keygenSessionId?: string;
  rpId?: string;
  clientVerifyingShareB64u?: string;
  groupPublicKeyB64u?: string;
  ethereumAddress?: string;
  relayerKeyId?: string;
  relayerVerifyingShareB64u?: string;
  participantIds?: number[];
  chainId?: number;
  factory?: string;
  entryPoint?: string;
  salt?: string;
  counterfactualAddress?: string;
  sessionId?: string;
  expiresAtMs?: number;
  remainingUses?: number;
  jwt?: string;
  code?: string;
  message?: string;
}> {
  const sessionKind: EcdsaSessionKind = args.sessionKind || 'jwt';
  const rpId = args.touchIdPrompt.getRpId();
  if (!rpId) {
    return { ok: false, code: 'invalid_args', message: 'Missing rpId for WebAuthn' };
  }

  const userId = String(args.userId || '').trim();
  if (!userId) {
    return { ok: false, code: 'invalid_args', message: 'Missing userId' };
  }

  const keygenSessionId = generateKeygenSessionId();
  const bootstrapAuthorizationJwt = String(args.bootstrapAuthorizationJwt || '').trim();
  const providedClientVerifyingShareB64u = String(args.clientVerifyingShareB64u || '').trim();
  const useAuthorizationBootstrap = bootstrapAuthorizationJwt.length > 0;
  if (useAuthorizationBootstrap && !providedClientVerifyingShareB64u) {
    return {
      ok: false,
      code: 'invalid_args',
      message:
        'Missing threshold-ecdsa clientVerifyingShareB64u for authorization bootstrap; reconnect session priming and retry',
    };
  }
  let credential: Awaited<ReturnType<typeof collectAuthenticationCredentialForChallengeB64u>> | null =
    null;
  let prfFirstB64u: string | null = null;
  if (!useAuthorizationBootstrap) {
    const challengeB64u = await computeThresholdEcdsaKeygenIntentDigest({
      userId,
      rpId,
      keygenSessionId,
    });
    credential = await collectAuthenticationCredentialForChallengeB64u({
      indexedDB: args.indexedDB,
      touchIdPrompt: args.touchIdPrompt,
      nearAccountId: userId,
      challengeB64u,
    });

    prfFirstB64u = getPrfFirstB64uFromCredential(credential);
    if (!prfFirstB64u) {
      return {
        ok: false,
        code: 'unsupported',
        message: 'Missing PRF.first output from credential (requires a PRF-enabled passkey)',
      };
    }
  }

  try {
    const derived =
      prfFirstB64u
        ? await deriveThresholdSecp256k1ClientShareWasm({
            prfFirstB64u,
            userId,
            workerCtx: args.workerCtx,
          })
        : null;
    const clientVerifyingShareB64u =
      derived?.clientVerifyingShareB64u || providedClientVerifyingShareB64u;
    if (!clientVerifyingShareB64u) {
      return {
        ok: false,
        code: 'invalid_args',
        message:
          'Missing threshold-ecdsa client share for bootstrap; reconnect with WebAuthn or provide canonical session material',
      };
    }

    const { ttlMs, remainingUses } = clampThresholdSessionPolicy({
      ttlMs: args.ttlMs ?? DEFAULT_THRESHOLD_SESSION_POLICY.ttlMs,
      remainingUses: args.remainingUses ?? DEFAULT_THRESHOLD_SESSION_POLICY.remainingUses,
    });
    const participantIds = normalizeThresholdEd25519ParticipantIds(args.participantIds);
    const sessionId = args.sessionId || generateThresholdSessionId();
    const webauthnAuthentication = credential || undefined;
    const authorizationJwt = useAuthorizationBootstrap ? bootstrapAuthorizationJwt : undefined;

    const bootstrap = await thresholdEcdsaBootstrap(args.relayerUrl, {
      userId,
      rpId,
      keygenSessionId,
      clientVerifyingShareB64u,
      webauthnAuthentication,
      authorizationJwt,
      sessionPolicy: {
        version: THRESHOLD_SESSION_POLICY_VERSION,
        userId,
        rpId,
        sessionId,
        participantIds: participantIds || undefined,
        ttlMs,
        remainingUses,
      },
      sessionKind,
    });
    if (!bootstrap.ok) {
      return {
        ok: false,
        code: bootstrap.code || 'bootstrap_failed',
        message: bootstrap.error || bootstrap.message || 'Threshold bootstrap failed',
      };
    }

    const relayerKeyId = String(bootstrap.relayerKeyId || '').trim();
    if (!relayerKeyId) {
      return {
        ok: false,
        code: 'internal',
        message: 'Threshold bootstrap response missing relayerKeyId',
      };
    }

    const resolvedParticipantIds =
      normalizeThresholdEd25519ParticipantIds(bootstrap.participantIds) ||
      participantIds ||
      undefined;
    if (!resolvedParticipantIds) {
      return {
        ok: false,
        code: 'internal',
        message: 'Threshold bootstrap response missing participantIds',
      };
    }
    const resolvedSessionId = String(bootstrap.sessionId || sessionId).trim();
    if (!resolvedSessionId) {
      return {
        ok: false,
        code: 'internal',
        message: 'Threshold bootstrap response missing sessionId',
      };
    }
    const resolvedRemainingUses = Number.isFinite(Number(bootstrap.remainingUses))
      ? Math.floor(Number(bootstrap.remainingUses))
      : remainingUses;
    const expiresAtMs = Number.isFinite(Number(bootstrap.expiresAtMs))
      ? Math.floor(Number(bootstrap.expiresAtMs))
      : Date.now() + ttlMs;

    const prfFirstCache = args.prfFirstCache;
    if (prfFirstCache && prfFirstB64u) {
      await cacheSigningSessionPrfFirstBestEffort(prfFirstCache, {
        sessionId: resolvedSessionId,
        prfFirstB64u,
        expiresAtMs,
        remainingUses: resolvedRemainingUses,
      });
    }

    return {
      ok: true,
      keygenSessionId,
      rpId,
      clientVerifyingShareB64u,
      groupPublicKeyB64u: bootstrap.groupPublicKeyB64u,
      ethereumAddress: bootstrap.ethereumAddress,
      relayerKeyId,
      relayerVerifyingShareB64u: bootstrap.relayerVerifyingShareB64u,
      participantIds: resolvedParticipantIds,
      ...(typeof bootstrap.chainId === 'number' ? { chainId: bootstrap.chainId } : {}),
      ...(typeof bootstrap.factory === 'string' && bootstrap.factory.trim()
        ? { factory: bootstrap.factory.trim() }
        : {}),
      ...(typeof bootstrap.entryPoint === 'string' && bootstrap.entryPoint.trim()
        ? { entryPoint: bootstrap.entryPoint.trim() }
        : {}),
      ...(typeof bootstrap.salt === 'string' && bootstrap.salt.trim()
        ? { salt: bootstrap.salt.trim() }
        : {}),
      ...(typeof bootstrap.counterfactualAddress === 'string' &&
      bootstrap.counterfactualAddress.trim()
        ? { counterfactualAddress: bootstrap.counterfactualAddress.trim() }
        : {}),
      sessionId: resolvedSessionId,
      expiresAtMs,
      remainingUses: resolvedRemainingUses,
      jwt: bootstrap.jwt,
      ...(bootstrap.code ? { code: bootstrap.code } : {}),
      ...(bootstrap.message ? { message: bootstrap.message } : {}),
    };
  } catch (e: unknown) {
    const msg = String(
      e && typeof e === 'object' && 'message' in e
        ? (e as { message?: unknown }).message
        : e || 'bootstrap failed',
    );
    return { ok: false, code: 'internal', message: msg };
  }
}
