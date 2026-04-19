import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import { base64UrlEncode } from '@shared/utils/base64';
import { computeThresholdEcdsaKeygenIntentDigest } from '@/utils/intentDigest';
import {
  thresholdEcdsaHssFinalize,
  thresholdEcdsaHssPrepare,
  thresholdEcdsaHssRespond,
  type ThresholdEcdsaHssRouteAuth,
} from '@/core/rpcClients/relayer/thresholdEcdsa';
import type { AppOrThresholdSessionAuth } from '@shared/utils/sessionTokens';
import { cacheSigningSessionPrfFirstBestEffort } from '@/core/signingEngine/api/session/signingSessionState';
import type { WorkerOperationContext } from '../../workerManager/executeWorkerOperation';
import {
  type ThresholdIndexedDbPort,
  type WarmSessionMaterialWriter,
  type ThresholdWebAuthnPromptPort,
} from '../webauthn';
import {
  clampThresholdSessionPolicy,
  DEFAULT_THRESHOLD_SESSION_POLICY,
  generateThresholdSessionId,
  normalizeThresholdRuntimePolicyScope,
  THRESHOLD_SESSION_POLICY_VERSION,
  type ThresholdRuntimePolicyScope,
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
import { resolveThresholdEcdsaClientRootShare } from './thresholdClientSecretSource';

type EcdsaSessionKind = 'jwt' | 'cookie';

function joinUrlPath(base: string, path: string): string {
  return `${String(base || '').replace(/\/+$/, '')}/${String(path || '').replace(/^\/+/, '')}`;
}

async function postJsonExpectOk(args: {
  url: string;
  headers?: Record<string, string>;
  operation: string;
  body: unknown;
}): Promise<Record<string, unknown>> {
  if (typeof fetch !== 'function') {
    throw new Error(`${args.operation} requires fetch`);
  }
  const response = await fetch(args.url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(args.headers || {}),
    },
    credentials: 'omit',
    body: JSON.stringify(args.body),
  });
  const data = (await response.json().catch(() => ({}))) as Record<string, unknown>;
  if (!response.ok || data.ok === false) {
    throw new Error(
      String(data.message || data.code || `${args.operation} failed with HTTP ${response.status}`),
    );
  }
  return data;
}

async function requestManagedRegistrationBootstrapGrant(args: {
  relayerUrl: string;
  environmentId: string;
  publishableKey: string;
  nearAccountId: string;
  rpId: string;
}): Promise<{ token: string; runtimePolicyScope: ThresholdRuntimePolicyScope }> {
  const data = await postJsonExpectOk({
    url: joinUrlPath(args.relayerUrl, '/v1/registration/bootstrap-grants'),
    headers: { Authorization: `Bearer ${args.publishableKey}` },
    operation: 'Managed registration bootstrap grant',
    body: {
      environmentId: args.environmentId,
      newAccountId: args.nearAccountId,
      rpId: args.rpId,
      flow: 'registration_v1',
    },
  });
  const grant =
    data.grant && typeof data.grant === 'object' && !Array.isArray(data.grant)
      ? (data.grant as Record<string, unknown>)
      : {};
  const token = String(grant.token || '').trim();
  const orgId = String(grant.orgId || '').trim();
  const projectId = String(grant.projectId || '').trim();
  const envId = String(grant.envId || '').trim();
  if (!token || !orgId || !projectId || !envId) {
    throw new Error('Managed registration grant response missing token or runtime scope');
  }
  return {
    token,
    runtimePolicyScope: {
      orgId,
      projectId,
      envId,
    },
  };
}

function generateKeygenSessionId(): string {
  const id =
    typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
      ? crypto.randomUUID()
      : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  return `tecdsa-keygen-${id}`;
}

function zeroizeBytes(bytes?: Uint8Array | null): void {
  if (!(bytes instanceof Uint8Array)) return;
  bytes.fill(0);
}

export async function bootstrapEcdsaSession(args: {
  indexedDB: ThresholdIndexedDbPort;
  touchIdPrompt: ThresholdWebAuthnPromptPort;
  prfFirstCache?: WarmSessionMaterialWriter;
  relayerUrl: string;
  userId: string;
  ecdsaThresholdKeyId?: string;
  participantIds?: number[];
  sessionKind?: EcdsaSessionKind;
  sessionId?: string;
  clientRootShare32?: Uint8Array;
  clientRootShare32B64u?: string;
  bootstrapAuth?: AppOrThresholdSessionAuth;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  runtimeScopeBootstrap?: {
    environmentId: string;
    publishableKey: string;
  };
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
  signingRootId?: string;
  signingRootVersion?: string;
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
  const requestedSessionId = String(args.sessionId || '').trim();
  const ecdsaThresholdKeyId = String(args.ecdsaThresholdKeyId || '').trim();
  const providedClientRootShare32 =
    args.clientRootShare32 instanceof Uint8Array ? args.clientRootShare32 : undefined;
  const providedClientRootShare32B64u = String(args.clientRootShare32B64u || '').trim();
  const useAuthorizationBootstrap = Boolean(args.bootstrapAuth);
  if (useAuthorizationBootstrap && !providedClientRootShare32 && !providedClientRootShare32B64u) {
    return {
      ok: false,
      code: 'invalid_args',
      message: requestedSessionId
        ? 'Missing threshold-ecdsa client root share for authorization bootstrap; reconnect session priming and retry'
        : 'Missing threshold-ecdsa client root share for authorization bootstrap; reconnect session priming and retry (missing sessionId)',
    };
  }
  let credential: unknown = null;
  let yClient32Le: Uint8Array | null = null;

  try {
    const challengeB64u = !useAuthorizationBootstrap
      ? await computeThresholdEcdsaKeygenIntentDigest({
          userId,
          rpId,
          keygenSessionId,
        })
      : undefined;
    const resolvedClientRootShare = await resolveThresholdEcdsaClientRootShare({
      indexedDB: args.indexedDB,
      touchIdPrompt: args.touchIdPrompt,
      userId,
      challengeB64u,
      providedClientRootShare32,
      providedClientRootShare32B64u,
    });
    if (!resolvedClientRootShare.ok) {
      return resolvedClientRootShare;
    }
    credential = resolvedClientRootShare.credential || null;
    const clientRootShare32 = resolvedClientRootShare.clientRootShare32;
    yClient32Le = clientRootShare32;

    const { ttlMs, remainingUses } = clampThresholdSessionPolicy({
      ttlMs: args.ttlMs ?? DEFAULT_THRESHOLD_SESSION_POLICY.ttlMs,
      remainingUses: args.remainingUses ?? DEFAULT_THRESHOLD_SESSION_POLICY.remainingUses,
    });
    const participantIds = normalizeThresholdEd25519ParticipantIds(args.participantIds);
    const runtimeEnvironmentId = String(args.runtimeScopeBootstrap?.environmentId || '').trim();
    const runtimeScopePublishableKey = String(
      args.runtimeScopeBootstrap?.publishableKey || '',
    ).trim();
    const managedBootstrapGrant =
      !args.runtimePolicyScope && runtimeEnvironmentId && runtimeScopePublishableKey
        ? await requestManagedRegistrationBootstrapGrant({
            relayerUrl: args.relayerUrl,
            environmentId: runtimeEnvironmentId,
            publishableKey: runtimeScopePublishableKey,
            nearAccountId: userId,
            rpId,
          })
        : null;
    const runtimePolicyScope =
      normalizeThresholdRuntimePolicyScope(args.runtimePolicyScope) ||
      managedBootstrapGrant?.runtimePolicyScope;
    const sessionId = requestedSessionId || generateThresholdSessionId();
    const webauthnAuthentication = useAuthorizationBootstrap ? undefined : (credential as any);
    const routeAuth: ThresholdEcdsaHssRouteAuth | undefined = useAuthorizationBootstrap
      ? args.bootstrapAuth
      : managedBootstrapGrant?.token
        ? { kind: 'bootstrap_grant', token: managedBootstrapGrant.token }
        : runtimeScopePublishableKey
          ? { kind: 'publishable_key', token: runtimeScopePublishableKey }
          : undefined;
    const prepare = await thresholdEcdsaHssPrepare(args.relayerUrl, {
      userId,
      rpId,
      operation: useAuthorizationBootstrap ? 'session_bootstrap' : 'registration_bootstrap',
      ...(useAuthorizationBootstrap && ecdsaThresholdKeyId ? { ecdsaThresholdKeyId } : {}),
      keygenSessionId,
      webauthnAuthentication,
      auth: routeAuth,
      ...(runtimeEnvironmentId ? { runtimeEnvironmentId } : {}),
      sessionPolicy: {
        version: THRESHOLD_SESSION_POLICY_VERSION,
        userId,
        rpId,
        sessionId,
        ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
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
        clientRootShare32,
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
        clientRootShare32,
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
      auth: routeAuth,
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
      const parsedResponse =
        parseThresholdEcdsaHssHiddenEvalServerResponseMessage(responseMessageB64u);
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
      auth: routeAuth,
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

    const cachedClientRootShare32B64u = base64UrlEncode(clientRootShare32);
    const prfFirstCache = args.prfFirstCache;
    if (prfFirstCache && cachedClientRootShare32B64u) {
      await cacheSigningSessionPrfFirstBestEffort(prfFirstCache, {
        sessionId: resolvedSessionId,
        prfFirstB64u: cachedClientRootShare32B64u,
        expiresAtMs,
        remainingUses: resolvedRemainingUses,
        transport: {
          curve: 'ecdsa',
          relayerUrl: args.relayerUrl,
          ...(typeof bootstrap.jwt === 'string' && bootstrap.jwt.trim()
            ? { thresholdSessionJwt: bootstrap.jwt.trim() }
            : {}),
        },
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
      ...(typeof bootstrap.signingRootId === 'string' && bootstrap.signingRootId.trim()
        ? { signingRootId: bootstrap.signingRootId.trim() }
        : {}),
      ...(typeof bootstrap.signingRootVersion === 'string' && bootstrap.signingRootVersion.trim()
        ? { signingRootVersion: bootstrap.signingRootVersion.trim() }
        : {}),
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
  } finally {
    zeroizeBytes(yClient32Le);
  }
}
