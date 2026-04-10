import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import { base64UrlDecode } from '@shared/utils/base64';
import { computeThresholdEcdsaKeygenIntentDigest } from '@/utils/intentDigest';
import {
  thresholdEcdsaHssFinalize,
  thresholdEcdsaHssPrepare,
  thresholdEcdsaHssRespond,
} from '@/core/rpcClients/relayer/thresholdEcdsa';
import { cacheSigningSessionPrfFirstBestEffort } from '@/core/signingEngine/api/session/signingSessionState';
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
import {
  createThresholdEcdsaHssHiddenEvalFinalizeMessage,
  encodeThresholdEcdsaHssHiddenEvalRequestMessage,
  parseThresholdEcdsaHssHiddenEvalServerResponseMessage,
} from './thresholdEcdsaHssTransport';
import {
  finalizeThresholdEcdsaHssClientRequestWasm,
  prepareThresholdEcdsaHssClientRequestWasm,
  prepareThresholdEcdsaHssSessionWasm,
} from '../../signers/wasm/hssClientSignerWasm';

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
  ecdsaThresholdKeyId?: string;
  participantIds?: number[];
  sessionKind?: EcdsaSessionKind;
  sessionId?: string;
  clientRootShare32B64u?: string;
  bootstrapAuthorizationJwt?: string;
  ttlMs?: number;
  remainingUses?: number;
  workerCtx: WorkerOperationContext;
}): Promise<{
  ok: boolean;
  keygenSessionId?: string;
  rpId?: string;
  ecdsaThresholdKeyId?: string;
  clientVerifyingShareB64u?: string;
  clientAdditiveShare32B64u?: string;
  thresholdEcdsaPublicKeyB64u?: string;
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
  const requestedSessionId = String(args.sessionId || '').trim();
  const ecdsaThresholdKeyId = String(args.ecdsaThresholdKeyId || '').trim();
  let providedClientRootShare32B64u = String(args.clientRootShare32B64u || '').trim();
  const useAuthorizationBootstrap = bootstrapAuthorizationJwt.length > 0;
  let authorizationBootstrapRecoveryError = '';
  if (
    useAuthorizationBootstrap &&
    !providedClientRootShare32B64u &&
    requestedSessionId &&
    typeof args.prfFirstCache?.dispensePrfFirstForThresholdSession === 'function'
  ) {
    const dispensed = await args.prfFirstCache.dispensePrfFirstForThresholdSession({
      sessionId: requestedSessionId,
      uses: 1,
    });
    if (dispensed.ok) {
      providedClientRootShare32B64u = String(dispensed.prfFirstB64u || '').trim();
    } else {
      authorizationBootstrapRecoveryError = `${String(dispensed.code || 'unknown').trim()}:${String(
        dispensed.message || 'failed to recover warm PRF.first',
      ).trim()}`;
    }
  }
  if (useAuthorizationBootstrap && !providedClientRootShare32B64u) {
    return {
      ok: false,
      code: 'invalid_args',
      message: requestedSessionId
        ? `Missing threshold-ecdsa clientRootShare32B64u for authorization bootstrap; reconnect session priming and retry${
            authorizationBootstrapRecoveryError
              ? ` (${authorizationBootstrapRecoveryError})`
              : ''
          }`
        : 'Missing threshold-ecdsa clientRootShare32B64u for authorization bootstrap; reconnect session priming and retry (missing sessionId)',
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
    const yClient32LeB64u = prfFirstB64u || providedClientRootShare32B64u;
    if (!yClient32LeB64u) {
      return {
        ok: false,
        code: 'invalid_args',
        message:
          'Missing threshold-ecdsa client root share for bootstrap; reconnect with WebAuthn or provide canonical session material',
      };
    }
    const yClient32Le = base64UrlDecode(yClient32LeB64u);
    if (yClient32Le.length !== 32) {
      return {
        ok: false,
        code: 'invalid_args',
        message: 'threshold-ecdsa clientRootShare32B64u must decode to 32 bytes',
      };
    }

    const { ttlMs, remainingUses } = clampThresholdSessionPolicy({
      ttlMs: args.ttlMs ?? DEFAULT_THRESHOLD_SESSION_POLICY.ttlMs,
      remainingUses: args.remainingUses ?? DEFAULT_THRESHOLD_SESSION_POLICY.remainingUses,
    });
    const participantIds = normalizeThresholdEd25519ParticipantIds(args.participantIds);
    const sessionId = requestedSessionId || generateThresholdSessionId();
    const webauthnAuthentication = credential || undefined;
    const authorizationJwt = useAuthorizationBootstrap ? bootstrapAuthorizationJwt : undefined;

    const prepare = await thresholdEcdsaHssPrepare(args.relayerUrl, {
      userId,
      rpId,
      operation: useAuthorizationBootstrap ? 'session_bootstrap' : 'registration_bootstrap',
      ...(useAuthorizationBootstrap && ecdsaThresholdKeyId ? { ecdsaThresholdKeyId } : {}),
      keygenSessionId,
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
    if (!prepare.ok) {
      return {
        ok: false,
        code: prepare.code || 'bootstrap_failed',
        message: prepare.error || prepare.message || 'Threshold bootstrap prepare failed',
      };
    }
    const ceremonyId = String(prepare.ceremonyId || '').trim();
    if (!ceremonyId) {
      return {
        ok: false,
        code: 'internal',
        message: 'Threshold bootstrap prepare response missing ceremonyId',
      };
    }
    const preparedServerSessionB64u = String(prepare.preparedServerSessionB64u || '').trim();
    const serverAssistInitB64u = String(prepare.serverAssistInitB64u || '').trim();
    if (!preparedServerSessionB64u || !serverAssistInitB64u) {
      return {
        ok: false,
        code: 'internal',
        message: 'Threshold bootstrap prepare response missing staged transport inputs',
      };
    }

    let preparedClientSession;
    try {
      preparedClientSession = await prepareThresholdEcdsaHssSessionWasm({
        context: {
          nearAccountId: userId,
          keyPurpose: 'evm-signing',
          keyVersion: 'v1',
        },
        clientRootShare32B64u: yClient32LeB64u,
        workerCtx: args.workerCtx,
      });
    } catch (error) {
      return {
        ok: false,
        code: 'internal',
        message:
          error instanceof Error
            ? error.message
            : 'Threshold ECDSA HSS client session preparation failed',
      };
    }

    let clientRequest;
    try {
      clientRequest = await prepareThresholdEcdsaHssClientRequestWasm({
        evaluatorDriverStateB64u: preparedClientSession.evaluatorDriverStateB64u,
        serverAssistInitMessageB64u: serverAssistInitB64u,
        clientRootShare32B64u: yClient32LeB64u,
        workerCtx: args.workerCtx,
      });
    } catch (error) {
      return {
        ok: false,
        code: 'internal',
        message:
          error instanceof Error
            ? error.message
            : 'Threshold ECDSA HSS client request preparation failed',
      };
    }

    const requestMessageB64u = encodeThresholdEcdsaHssHiddenEvalRequestMessage({
      ceremonyId,
      preparedServerSessionB64u,
      serverAssistInitB64u,
      clientEvalRequestB64u: clientRequest.clientEvalRequestB64u,
    });

    const respond = await thresholdEcdsaHssRespond(args.relayerUrl, {
      ceremonyId,
      requestMessageB64u,
      authorizationJwt,
      sessionKind,
    });
    if (!respond.ok) {
      return {
        ok: false,
        code: respond.code || 'bootstrap_failed',
        message: respond.error || respond.message || 'Threshold bootstrap respond failed',
      };
    }

    const responseMessageB64u = String(respond.responseMessageB64u || '').trim();
    if (!responseMessageB64u) {
      return {
        ok: false,
        code: 'internal',
        message: 'Threshold bootstrap respond response missing responseMessageB64u',
      };
    }
    let finalizeMessageB64u = '';
    try {
      const parsedResponse = parseThresholdEcdsaHssHiddenEvalServerResponseMessage(
        responseMessageB64u,
      );
      if (!parsedResponse) {
        throw new Error(
          'Threshold bootstrap respond response missing hidden-eval server response envelope',
        );
      }
      const clientFinalize = await finalizeThresholdEcdsaHssClientRequestWasm({
        evaluatorDriverStateB64u: preparedClientSession.evaluatorDriverStateB64u,
        serverEvalResponseB64u: parsedResponse.serverEvalResponseB64u,
        workerCtx: args.workerCtx,
      });
      finalizeMessageB64u = await createThresholdEcdsaHssHiddenEvalFinalizeMessage({
        ceremonyId,
        requestMessageB64u,
        responseMessageB64u,
        clientEvalFinalizeB64u: clientFinalize.clientEvalFinalizeB64u,
      });
    } catch (error) {
      return {
        ok: false,
        code: 'internal',
        message:
          error instanceof Error
            ? error.message
            : 'Threshold bootstrap respond response failed staged transport validation',
      };
    }

    const bootstrap = await thresholdEcdsaHssFinalize(args.relayerUrl, {
      ceremonyId,
      clientFinalizeMessageB64u: finalizeMessageB64u,
      authorizationJwt,
      sessionKind,
    });
    if (!bootstrap.ok) {
      return {
        ok: false,
        code: bootstrap.code || 'bootstrap_failed',
        message: bootstrap.error || bootstrap.message || 'Threshold bootstrap finalize failed',
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

    const cachedClientRootShare32B64u = prfFirstB64u || providedClientRootShare32B64u;
    const prfFirstCache = args.prfFirstCache;
    if (prfFirstCache && cachedClientRootShare32B64u) {
      await cacheSigningSessionPrfFirstBestEffort(prfFirstCache, {
        sessionId: resolvedSessionId,
        prfFirstB64u: cachedClientRootShare32B64u,
        expiresAtMs,
        remainingUses: resolvedRemainingUses,
      });
    }

    return {
      ok: true,
      keygenSessionId,
      rpId,
      ...(typeof bootstrap.ecdsaThresholdKeyId === 'string' && bootstrap.ecdsaThresholdKeyId.trim()
        ? { ecdsaThresholdKeyId: bootstrap.ecdsaThresholdKeyId.trim() }
        : {}),
      clientVerifyingShareB64u: String(bootstrap.clientVerifyingShareB64u || '').trim(),
      clientAdditiveShare32B64u: String(bootstrap.clientAdditiveShare32B64u || '').trim(),
      thresholdEcdsaPublicKeyB64u: bootstrap.thresholdEcdsaPublicKeyB64u,
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
