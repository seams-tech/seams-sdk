import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import { base64UrlEncode } from '@shared/utils/base64';
import { computeThresholdEcdsaKeygenIntentDigest } from '@/utils/intentDigest';
import type { WebAuthnAuthenticationCredential } from '@/core/types/webauthn';
import {
  thresholdEcdsaHssFinalize,
  thresholdEcdsaHssPrepare,
  thresholdEcdsaHssRespond,
  type ThresholdEcdsaHssRouteAuth,
} from '@/core/rpcClients/relayer/thresholdEcdsa';
import {
  decodeJwtPayloadRecord,
} from '@shared/utils/sessionTokens';
import type { WorkerOperationContext } from '../../workerManager/executeWorkerOperation';
import {
  type ThresholdIndexedDbPort,
  type ThresholdWebAuthnPromptPort,
} from '../crypto/webauthn';
import {
  clampThresholdSessionPolicy,
  DEFAULT_THRESHOLD_SESSION_POLICY,
  generateThresholdSessionId,
  generateWalletSigningSessionId,
  normalizeThresholdRuntimePolicyScope,
  THRESHOLD_SESSION_POLICY_VERSION,
  type ThresholdRuntimePolicyScope,
  type ThresholdSessionKind,
} from '../sessionPolicy';
import {
  createThresholdEcdsaHssHiddenEvalFinalizeMessage,
  encodeThresholdEcdsaHssHiddenEvalRequestMessage,
  parseThresholdEcdsaHssHiddenEvalServerResponseMessage,
} from './hssTransport';
import {
  finalizeThresholdEcdsaHssClientRequestWasm,
  prepareThresholdEcdsaHssClientRequestWasm,
  prepareThresholdEcdsaHssSessionWasm,
} from '../crypto/hssClientSignerWasm';
import { resolveThresholdEcdsaClientRootShare } from './clientSecretSource';
import {
  type ThresholdEcdsaChainTarget,
  type WalletSubjectId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';

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
  const signingRootVersion = String(grant.signingRootVersion || '').trim();
  if (!token || !orgId || !projectId || !envId || !signingRootVersion) {
    throw new Error('Managed registration grant response missing token or runtime scope');
  }
  return {
    token,
    runtimePolicyScope: {
      orgId,
      projectId,
      envId,
      signingRootVersion,
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

function summarizeJwtClaims(jwtRaw: string | undefined): Record<string, unknown> {
  const payload = decodeJwtPayloadRecord(String(jwtRaw || '').trim());
  if (!payload) return { present: false };
  return {
    present: true,
    kind: payload.kind,
    sub: payload.sub,
    walletId: payload.walletId,
    userId: payload.userId,
    sessionId: payload.sessionId,
    walletSigningSessionId: payload.walletSigningSessionId,
    exp: payload.exp,
  };
}

function summarizeHssRouteAuth(auth: ThresholdEcdsaHssRouteAuth | undefined): Record<string, unknown> {
  if (!auth) return { kind: 'none' };
  if (auth.kind === 'threshold_session' || auth.kind === 'app_session') {
    return {
      kind: auth.kind,
      jwtClaims: summarizeJwtClaims(auth.jwt),
    };
  }
  if (auth.kind === 'cookie') return { kind: 'cookie' };
  return { kind: auth.kind, hasToken: Boolean(String(auth.token || '').trim()) };
}

type BootstrapEcdsaSessionBaseArgs = {
  indexedDB: ThresholdIndexedDbPort;
  touchIdPrompt: ThresholdWebAuthnPromptPort;
  relayerUrl: string;
  userId: string;
  subjectId: WalletSubjectId;
  chainTarget: ThresholdEcdsaChainTarget;
  chainId?: number;
  participantIds?: number[];
  sessionKind?: ThresholdSessionKind;
  clientRootShare32?: Uint8Array;
  clientRootShare32B64u?: string;
  webauthnAuthentication?: WebAuthnAuthenticationCredential;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  runtimeScopeBootstrap?: {
    environmentId: string;
    publishableKey: string;
  };
  ttlMs?: number;
  remainingUses?: number;
  workerCtx: WorkerOperationContext;
};

type BootstrapEcdsaRegistrationArgs = BootstrapEcdsaSessionBaseArgs & {
  bootstrapAuth?: ThresholdEcdsaHssRouteAuth;
  ecdsaThresholdKeyId?: string;
  sessionId?: string;
  walletSigningSessionId?: string;
};

type BootstrapEcdsaExactSessionArgs = BootstrapEcdsaSessionBaseArgs & {
  bootstrapAuth: ThresholdEcdsaHssRouteAuth;
  ecdsaThresholdKeyId: string;
  sessionId: string;
  walletSigningSessionId: string;
};

type BootstrapEcdsaSessionArgs =
  | BootstrapEcdsaRegistrationArgs
  | BootstrapEcdsaExactSessionArgs;

function isExactSessionBootstrapArgs(
  args: BootstrapEcdsaSessionArgs,
): args is BootstrapEcdsaExactSessionArgs {
  return Boolean(
    args.bootstrapAuth &&
      String(args.ecdsaThresholdKeyId || '').trim() &&
      String(args.sessionId || '').trim() &&
      String(args.walletSigningSessionId || '').trim(),
  );
}

export async function bootstrapEcdsaSession(args: BootstrapEcdsaSessionArgs): Promise<{
  ok: boolean;
  keygenSessionId?: string;
  rpId?: string;
  ecdsaThresholdKeyId?: string;
  clientVerifyingShareB64u?: string;
  clientAdditiveShare32B64u?: string;
  clientRootShare32B64u?: string;
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
  walletSigningSessionId?: string;
  expiresAtMs?: number;
  remainingUses?: number;
  signingRootId?: string;
  signingRootVersion?: string;
  jwt?: string;
  code?: string;
  message?: string;
}> {
  const sessionKind: ThresholdSessionKind = args.sessionKind || 'jwt';
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
  const requestedWalletSigningSessionId = String(args.walletSigningSessionId || '').trim();
  const ecdsaThresholdKeyId = String(args.ecdsaThresholdKeyId || '').trim();
  const providedClientRootShare32 =
    args.clientRootShare32 instanceof Uint8Array ? args.clientRootShare32 : undefined;
  const providedClientRootShare32B64u = String(args.clientRootShare32B64u || '').trim();
  const exactSessionBootstrap = isExactSessionBootstrapArgs(args);
  if (
    exactSessionBootstrap &&
    (!ecdsaThresholdKeyId || !requestedSessionId || !requestedWalletSigningSessionId)
  ) {
    return {
      ok: false,
      code: 'invalid_args',
      message:
        'Threshold ECDSA session bootstrap requires ecdsaThresholdKeyId, sessionId, and walletSigningSessionId',
    };
  }
  if (exactSessionBootstrap && !providedClientRootShare32 && !providedClientRootShare32B64u) {
    return {
      ok: false,
      code: 'invalid_args',
      message: requestedSessionId
        ? 'Missing threshold-ecdsa client root share for authorization bootstrap; reconnect session priming and retry'
        : 'Missing threshold-ecdsa client root share for authorization bootstrap; reconnect session priming and retry (missing sessionId)',
    };
  }
  let credential: WebAuthnAuthenticationCredential | null = null;
  let yClient32Le: Uint8Array | null = null;

  try {
    const challengeB64u = !exactSessionBootstrap
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
      providedCredential: args.webauthnAuthentication,
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
      !exactSessionBootstrap &&
      !args.runtimePolicyScope &&
      runtimeEnvironmentId &&
      runtimeScopePublishableKey
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
    const walletSigningSessionId =
      requestedWalletSigningSessionId || generateWalletSigningSessionId();
    // Authorization bootstraps may still be driven by a fresh WebAuthn proof
    // during passkey reauth. Preserve that proof so the server can refresh the
    // wallet signing-session budget for the newly minted threshold material.
    const webauthnAuthentication = args.webauthnAuthentication || credential || undefined;
    const hssAuth: ThresholdEcdsaHssRouteAuth | undefined = exactSessionBootstrap
      ? args.bootstrapAuth
      : args.bootstrapAuth
        ? args.bootstrapAuth
        : managedBootstrapGrant?.token
        ? { kind: 'bootstrap_grant', token: managedBootstrapGrant.token }
        : runtimeScopePublishableKey
          ? { kind: 'publishable_key', token: runtimeScopePublishableKey }
          : undefined;
    const sessionPolicy = {
      version: THRESHOLD_SESSION_POLICY_VERSION,
      userId,
      subjectId: args.subjectId,
      rpId,
      chainTarget: args.chainTarget,
      ...(ecdsaThresholdKeyId ? { ecdsaThresholdKeyId } : {}),
      sessionId,
      walletSigningSessionId,
      ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
      participantIds: participantIds || undefined,
      ttlMs,
      remainingUses,
    };
    try {
      console.info('[threshold-ecdsa][hss-prepare][diagnostic]', {
        operation: exactSessionBootstrap ? 'session_bootstrap' : 'registration_bootstrap',
        userId,
        rpId,
        keygenSessionId,
        chainId: args.chainId,
        ecdsaThresholdKeyId: ecdsaThresholdKeyId || undefined,
        requestedSessionId: requestedSessionId || undefined,
        plannedSessionPolicy: {
          sessionId: sessionPolicy.sessionId,
          walletSigningSessionId: sessionPolicy.walletSigningSessionId,
          remainingUses: sessionPolicy.remainingUses,
          ttlMs: sessionPolicy.ttlMs,
          participantCount: Array.isArray(sessionPolicy.participantIds)
            ? sessionPolicy.participantIds.length
            : 0,
          runtimePolicyScope: sessionPolicy.runtimePolicyScope,
        },
        auth: summarizeHssRouteAuth(hssAuth),
        hasWebAuthnAuthentication: Boolean(webauthnAuthentication),
        hasProvidedClientRootShare: Boolean(
          providedClientRootShare32 || providedClientRootShare32B64u,
        ),
      });
    } catch {}
    const prepare = exactSessionBootstrap
      ? await thresholdEcdsaHssPrepare(args.relayerUrl, {
          walletSessionUserId: userId,
          rpId,
          operation: 'session_bootstrap',
          ecdsaThresholdKeyId,
          keygenSessionId,
          webauthnAuthentication,
          auth: args.bootstrapAuth,
          ...(runtimeEnvironmentId ? { runtimeEnvironmentId } : {}),
          sessionPolicy,
          sessionKind,
        })
      : await thresholdEcdsaHssPrepare(args.relayerUrl, {
          walletSessionUserId: userId,
          rpId,
          operation: 'registration_bootstrap',
          keygenSessionId,
          webauthnAuthentication,
          ...(hssAuth ? { auth: hssAuth } : {}),
          ...(runtimeEnvironmentId ? { runtimeEnvironmentId } : {}),
          sessionPolicy,
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
      auth: hssAuth,
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
      auth: hssAuth,
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
    const resolvedWalletSigningSessionId = String(
      bootstrap.walletSigningSessionId || walletSigningSessionId,
    ).trim();
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

    return {
      ok: true,
      keygenSessionId,
      rpId,
      ...(typeof bootstrap.ecdsaThresholdKeyId === 'string' && bootstrap.ecdsaThresholdKeyId.trim()
        ? { ecdsaThresholdKeyId: bootstrap.ecdsaThresholdKeyId.trim() }
        : {}),
      clientVerifyingShareB64u: String(bootstrap.clientVerifyingShareB64u || '').trim(),
      clientAdditiveShare32B64u: String(bootstrap.clientAdditiveShare32B64u || '').trim(),
      clientRootShare32B64u: base64UrlEncode(clientRootShare32),
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
      walletSigningSessionId: resolvedWalletSigningSessionId,
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
