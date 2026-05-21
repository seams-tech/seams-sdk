import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import { base64UrlEncode } from '@shared/utils/base64';
import {
  computeEcdsaHssRoleLocalPasskeyBootstrapAuthDigest32B64u,
  computeEcdsaHssRoleLocalRelayerKeyId,
  computeEcdsaHssRoleLocalThresholdKeyId,
} from '@shared/threshold/ecdsaHssRoleLocalBootstrap';
import type { WebAuthnAuthenticationCredential } from '@/core/types/webauthn';
import type { ThresholdEcdsaHssRoleLocalClientState } from '../../interfaces/signing';
import {
  thresholdEcdsaHssRoleLocalBootstrap,
  type ThresholdEcdsaHssRoleLocalBootstrapRequest,
  type ThresholdEcdsaHssRouteAuth,
} from '@/core/rpcClients/relayer/thresholdEcdsa';
import { decodeJwtPayloadRecord } from '@shared/utils/sessionTokens';
import { signingRootScopeFromRuntimePolicyScope } from '@shared/threshold/signingRootScope';
import type { WorkerOperationContext } from '../../workerManager/executeWorkerOperation';
import {
  type ThresholdIndexedDbPort,
  type ThresholdWebAuthnPromptPort,
} from '../crypto/webauthn';
import {
  buildEcdsaHssSessionPolicy,
  clampThresholdSessionPolicy,
  DEFAULT_THRESHOLD_SESSION_POLICY,
  generateThresholdSessionId,
  generateWalletSigningSessionId,
  normalizeThresholdRuntimePolicyScope,
  type ThresholdRuntimePolicyScope,
  type ThresholdSessionKind,
} from '../sessionPolicy';
import {
  toEcdsaHssSigningRootId,
  toEcdsaHssSigningRootVersion,
  toEcdsaHssThresholdKeyId,
  toWalletSessionUserId,
} from '../../session/identity/emailOtpHssIdentity';
import {
  buildThresholdEcdsaHssRoleLocalClientBootstrapWasm,
} from '../crypto/hssClientSignerWasm';
import { resolveThresholdEcdsaClientRootShare } from './clientSecretSource';
import {
  type ThresholdEcdsaChainTarget,
  type WalletSubjectId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  EvmFamilyEcdsaKeyHandle,
  EvmFamilyEcdsaKeyIdentity,
  EvmFamilyEcdsaSessionLanePolicy,
} from '../../session/identity/evmFamilyEcdsaIdentity';
import {
  deriveBaseEcdsaSubjectIdFromKey,
  deriveEvmFamilyKeyFingerprint,
} from '../../session/identity/evmFamilyEcdsaIdentity';
import { thresholdEcdsaChainTargetKey } from '../../interfaces/ecdsaChainTarget';

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
  walletId: string;
  rpId: string;
}): Promise<{ token: string; runtimePolicyScope: ThresholdRuntimePolicyScope }> {
  const data = await postJsonExpectOk({
    url: joinUrlPath(args.relayerUrl, '/v1/registration/bootstrap-grants'),
    headers: { Authorization: `Bearer ${args.publishableKey}` },
    operation: 'Managed registration bootstrap grant',
    body: {
      environmentId: args.environmentId,
      newAccountId: args.walletId,
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
  requestId?: string;
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
  bootstrapAuth?: ThresholdEcdsaHssRouteAuth;
  keyHandle: EvmFamilyEcdsaKeyHandle;
  key: EvmFamilyEcdsaKeyIdentity;
  lanePolicy: EvmFamilyEcdsaSessionLanePolicy;
  ecdsaThresholdKeyId?: never;
  sessionId?: never;
  walletSigningSessionId?: never;
};

type BootstrapEcdsaSessionArgs =
  | BootstrapEcdsaRegistrationArgs
  | BootstrapEcdsaExactSessionArgs;

function isExactSessionBootstrapArgs(
  args: BootstrapEcdsaSessionArgs,
): args is BootstrapEcdsaExactSessionArgs {
  return Boolean(
    'keyHandle' in args &&
      args.keyHandle &&
      'key' in args &&
      args.key &&
      'lanePolicy' in args &&
      args.lanePolicy,
  );
}

export async function bootstrapEcdsaSession(args: BootstrapEcdsaSessionArgs): Promise<{
  ok: boolean;
  keygenSessionId?: string;
  rpId?: string;
  keyHandle?: string;
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
  sessionId?: string;
  walletSigningSessionId?: string;
  expiresAtMs?: number;
  remainingUses?: number;
  signingRootId?: string;
  signingRootVersion?: string;
  jwt?: string;
  ecdsaHssRoleLocalClientState?: ThresholdEcdsaHssRoleLocalClientState;
  code?: string;
  message?: string;
}> {
  const exactSessionBootstrap = isExactSessionBootstrapArgs(args);
  const sessionKind: ThresholdSessionKind = exactSessionBootstrap
    ? args.lanePolicy.thresholdSessionKind
    : args.sessionKind || 'jwt';
  const rpId = args.touchIdPrompt.getRpId();
  if (!rpId) {
    return { ok: false, code: 'invalid_args', message: 'Missing rpId for WebAuthn' };
  }

  const userId = exactSessionBootstrap
    ? String(args.key.walletId).trim()
    : String(args.userId || '').trim();
  if (!userId) {
    return { ok: false, code: 'invalid_args', message: 'Missing userId' };
  }

  const requestedKeygenSessionId = String(args.requestId || '').trim();
  const keygenSessionId = requestedKeygenSessionId || generateKeygenSessionId();
  const requestedSessionId = exactSessionBootstrap
    ? String(args.lanePolicy.thresholdSessionId).trim()
    : String(args.sessionId || '').trim();
  const requestedWalletSigningSessionId = exactSessionBootstrap
    ? String(args.lanePolicy.walletSigningSessionId).trim()
    : String(args.walletSigningSessionId || '').trim();
  const keyHandle = exactSessionBootstrap ? String(args.keyHandle).trim() : '';
  const ecdsaThresholdKeyId = exactSessionBootstrap ? '' : String(args.ecdsaThresholdKeyId || '').trim();
  const providedClientRootShare32 =
    args.clientRootShare32 instanceof Uint8Array ? args.clientRootShare32 : undefined;
  const providedClientRootShare32B64u = String(args.clientRootShare32B64u || '').trim();
  if (
    !exactSessionBootstrap &&
    args.bootstrapAuth &&
    ecdsaThresholdKeyId &&
    requestedSessionId &&
    requestedWalletSigningSessionId
  ) {
    return {
      ok: false,
      code: 'invalid_args',
      message:
        'Threshold ECDSA session bootstrap requires shared key identity and lane policy',
    };
  }
  if (
    exactSessionBootstrap &&
    (!keyHandle || !requestedSessionId || !requestedWalletSigningSessionId)
  ) {
    return {
      ok: false,
      code: 'invalid_args',
      message:
        'Threshold ECDSA session bootstrap requires keyHandle, sessionId, and walletSigningSessionId',
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
    const { ttlMs, remainingUses } = clampThresholdSessionPolicy({
      ttlMs: exactSessionBootstrap
        ? args.lanePolicy.ttlMs
        : args.ttlMs ?? DEFAULT_THRESHOLD_SESSION_POLICY.ttlMs,
      remainingUses: exactSessionBootstrap
        ? args.lanePolicy.remainingUses
        : args.remainingUses ?? DEFAULT_THRESHOLD_SESSION_POLICY.remainingUses,
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
            walletId: userId,
            rpId,
          })
        : null;
    const runtimePolicyScope =
      (exactSessionBootstrap
        ? normalizeThresholdRuntimePolicyScope(args.lanePolicy.runtimePolicyScope)
        : normalizeThresholdRuntimePolicyScope(args.runtimePolicyScope)) ||
      managedBootstrapGrant?.runtimePolicyScope;
    const sessionId = requestedSessionId || generateThresholdSessionId();
    const walletSigningSessionId =
      requestedWalletSigningSessionId || generateWalletSigningSessionId();
    const sessionPolicyChainTarget = exactSessionBootstrap
      ? args.lanePolicy.chainTarget
      : args.chainTarget;
    const sessionPolicySubjectId = exactSessionBootstrap
      ? deriveBaseEcdsaSubjectIdFromKey(args.key)
      : args.subjectId;
    const sessionPolicyParticipantIds = exactSessionBootstrap
      ? args.key.participantIds.map((participantId) => Number(participantId))
      : participantIds || undefined;
    const exactBootstrapSigningRootScope = exactSessionBootstrap
      ? {
          signingRootId: args.key.signingRootId,
          signingRootVersion: args.key.signingRootVersion,
        }
      : null;
    const firstBootstrapSigningRootScope =
      !exactSessionBootstrap && runtimePolicyScope
        ? signingRootScopeFromRuntimePolicyScope(runtimePolicyScope)
        : null;
    const roleLocalSigningRootScope =
      exactBootstrapSigningRootScope || firstBootstrapSigningRootScope;
    const exactBootstrapRelayerKeyId = exactSessionBootstrap
      ? await computeEcdsaHssRoleLocalRelayerKeyId({
          walletSessionUserId: userId,
          rpId,
        })
      : '';
    const firstBootstrapRelayerKeyId = firstBootstrapSigningRootScope
      ? await computeEcdsaHssRoleLocalRelayerKeyId({
          walletSessionUserId: userId,
          rpId,
        })
      : '';
    const firstBootstrapThresholdKeyId = firstBootstrapSigningRootScope
      ? await computeEcdsaHssRoleLocalThresholdKeyId({
          walletSessionUserId: userId,
          rpId,
          subjectId: sessionPolicySubjectId,
          signingRootId: firstBootstrapSigningRootScope.signingRootId,
          signingRootVersion: firstBootstrapSigningRootScope.signingRootVersion || 'default',
        })
      : '';
    const passkeyBootstrapIdentity =
      exactSessionBootstrap && exactBootstrapSigningRootScope && exactBootstrapRelayerKeyId
        ? {
            walletSessionUserId: userId,
            rpId,
            subjectId: sessionPolicySubjectId,
            ecdsaThresholdKeyId: toEcdsaHssThresholdKeyId(args.key.ecdsaThresholdKeyId),
            signingRootId: exactBootstrapSigningRootScope.signingRootId,
            signingRootVersion: exactBootstrapSigningRootScope.signingRootVersion || 'default',
            keyScope: 'evm-family' as const,
            relayerKeyId: exactBootstrapRelayerKeyId,
            requestId: keygenSessionId,
            sessionId,
            walletSigningSessionId,
            ttlMs,
            remainingUses,
            participantIds: sessionPolicyParticipantIds || [1, 2],
          }
        : !exactSessionBootstrap &&
            firstBootstrapSigningRootScope &&
            firstBootstrapRelayerKeyId &&
            firstBootstrapThresholdKeyId &&
            (!ecdsaThresholdKeyId || ecdsaThresholdKeyId === firstBootstrapThresholdKeyId)
          ? {
              walletSessionUserId: userId,
              rpId,
              subjectId: sessionPolicySubjectId,
              ecdsaThresholdKeyId: firstBootstrapThresholdKeyId,
              signingRootId: firstBootstrapSigningRootScope.signingRootId,
              signingRootVersion: firstBootstrapSigningRootScope.signingRootVersion || 'default',
              keyScope: 'evm-family' as const,
              relayerKeyId: firstBootstrapRelayerKeyId,
              requestId: keygenSessionId,
              sessionId,
              walletSigningSessionId,
              ttlMs,
              remainingUses,
              participantIds: sessionPolicyParticipantIds || [1, 2],
            }
          : null;
    if (!exactSessionBootstrap && !passkeyBootstrapIdentity) {
      return {
        ok: false,
        code: 'role_local_required',
        message:
          'Threshold ECDSA registration bootstrap requires runtimePolicyScope or runtimeScopeBootstrap for role-local key creation',
      };
    }
    const challengeB64u = passkeyBootstrapIdentity
      ? await computeEcdsaHssRoleLocalPasskeyBootstrapAuthDigest32B64u(
          passkeyBootstrapIdentity,
        )
      : undefined;
    const resolvedClientRootShare = await resolveThresholdEcdsaClientRootShare({
      indexedDB: args.indexedDB,
      touchIdPrompt: args.touchIdPrompt,
      walletId: userId,
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
    // Authorization bootstraps may still be driven by a fresh WebAuthn proof
    // during passkey reauth. Preserve that proof so the server can refresh the
    // wallet signing-session budget for the newly minted threshold material.
    const webauthnAuthentication = args.webauthnAuthentication || credential || undefined;
    const hssAuth: ThresholdEcdsaHssRouteAuth | undefined = (() => {
      if (exactSessionBootstrap) return args.bootstrapAuth;
      if (args.bootstrapAuth) return args.bootstrapAuth;
      if (!exactSessionBootstrap && passkeyBootstrapIdentity && runtimeScopePublishableKey) {
        return { kind: 'publishable_key', token: runtimeScopePublishableKey };
      }
      if (managedBootstrapGrant?.token) {
        return { kind: 'bootstrap_grant', token: managedBootstrapGrant.token };
      }
      if (runtimeScopePublishableKey) {
        return { kind: 'publishable_key', token: runtimeScopePublishableKey };
      }
      return undefined;
    })();
    const evmFamilyKeyFingerprint = exactSessionBootstrap
      ? deriveEvmFamilyKeyFingerprint(args.key)
      : undefined;
    const sessionPolicy = buildEcdsaHssSessionPolicy({
      walletSessionUserId: userId,
      subjectId: sessionPolicySubjectId,
      rpId,
      chainTarget: sessionPolicyChainTarget,
      ...(keyHandle ? { keyHandle } : {}),
      ...(ecdsaThresholdKeyId || firstBootstrapThresholdKeyId
        ? { ecdsaThresholdKeyId: ecdsaThresholdKeyId || firstBootstrapThresholdKeyId }
        : {}),
      sessionId,
      walletSigningSessionId,
      ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
      participantIds: sessionPolicyParticipantIds,
      ttlMs,
      remainingUses,
    });
    const preparedEcdsaThresholdKeyId = exactSessionBootstrap
      ? toEcdsaHssThresholdKeyId(args.key.ecdsaThresholdKeyId)
      : sessionPolicy.ecdsaThresholdKeyId ||
        (ecdsaThresholdKeyId ? toEcdsaHssThresholdKeyId(ecdsaThresholdKeyId) : undefined);
    const hssDiagnosticIdentity = {
      operation: exactSessionBootstrap ? 'session_bootstrap' : 'registration_bootstrap',
      userId,
      rpId,
      keygenSessionId,
      chainTargetKey: thresholdEcdsaChainTargetKey(sessionPolicyChainTarget),
      ...(evmFamilyKeyFingerprint ? { evmFamilyKeyFingerprint } : {}),
      keyHandle: keyHandle || undefined,
      ecdsaThresholdKeyId: ecdsaThresholdKeyId || undefined,
      requestedSessionId: requestedSessionId || undefined,
    };
    try {
      console.info('[threshold-ecdsa][hss-prepare][diagnostic]', {
        ...hssDiagnosticIdentity,
        chainId: args.chainId,
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
    const roleLocalRelayerKeyId =
      exactBootstrapRelayerKeyId ||
      (passkeyBootstrapIdentity ? firstBootstrapRelayerKeyId : '');
    const canUseRoleLocalBootstrap =
      Boolean(preparedEcdsaThresholdKeyId) &&
      Boolean(roleLocalSigningRootScope?.signingRootId) &&
      Boolean(roleLocalRelayerKeyId);
    if (
      canUseRoleLocalBootstrap &&
      preparedEcdsaThresholdKeyId &&
      roleLocalSigningRootScope &&
      roleLocalRelayerKeyId
    ) {
      let clientBootstrap;
      try {
        clientBootstrap = await buildThresholdEcdsaHssRoleLocalClientBootstrapWasm({
          context: {
            walletSessionUserId: toWalletSessionUserId(sessionPolicy.walletSessionUserId),
            subjectId: sessionPolicySubjectId,
            ecdsaThresholdKeyId: preparedEcdsaThresholdKeyId,
            signingRootId: toEcdsaHssSigningRootId(roleLocalSigningRootScope.signingRootId),
            signingRootVersion: toEcdsaHssSigningRootVersion(
              roleLocalSigningRootScope.signingRootVersion || 'default',
            ),
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
              : 'Threshold ECDSA role-local client bootstrap failed',
        };
      }

      const bootstrapRequestBase = {
        formatVersion: 'ecdsa-hss-role-local',
        walletSessionUserId: toWalletSessionUserId(sessionPolicy.walletSessionUserId),
        rpId,
        subjectId: sessionPolicySubjectId,
        ecdsaThresholdKeyId: preparedEcdsaThresholdKeyId,
        signingRootId: clientBootstrap.signingRootId,
        signingRootVersion: clientBootstrap.signingRootVersion,
        keyScope: 'evm-family',
        relayerKeyId: roleLocalRelayerKeyId,
        clientPublicKey33B64u: clientBootstrap.clientPublicKey33B64u,
        clientShareRetryCounter: clientBootstrap.clientShareRetryCounter,
        contextBinding32B64u: clientBootstrap.contextBinding32B64u,
        requestId: keygenSessionId,
        sessionId,
        walletSigningSessionId,
        ttlMs,
        remainingUses,
        participantIds: sessionPolicyParticipantIds || [1, 2],
        auth: hssAuth,
        sessionKind,
        ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
      } satisfies ThresholdEcdsaHssRoleLocalBootstrapRequest;
      const bootstrapRequest =
        passkeyBootstrapIdentity && webauthnAuthentication
          ? ({
              ...bootstrapRequestBase,
              passkeyBootstrapAuthorization: {
                kind: 'passkey_bootstrap',
                webauthn_authentication: webauthnAuthentication,
                ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
                ...(runtimeEnvironmentId ? { runtimeEnvironmentId } : {}),
              },
            } satisfies ThresholdEcdsaHssRoleLocalBootstrapRequest)
          : bootstrapRequestBase;
      const bootstrap = await thresholdEcdsaHssRoleLocalBootstrap(
        args.relayerUrl,
        bootstrapRequest,
      );
      if (!bootstrap.ok) {
        return {
          ok: false,
          code: bootstrap.code || 'bootstrap_failed',
          message: bootstrap.error || bootstrap.message || 'Threshold role-local bootstrap failed',
        };
      }
      const value = bootstrap.value;
      const nowMs = Date.now();
      const ecdsaHssRoleLocalClientState: ThresholdEcdsaHssRoleLocalClientState = {
        kind: 'role_local_ready',
        artifactKind: 'ecdsa-hss-role-local-client-state',
        contextBinding32B64u: clientBootstrap.contextBinding32B64u,
        clientShare32B64u: clientBootstrap.clientShare32B64u,
        clientPublicKey33B64u: clientBootstrap.clientPublicKey33B64u,
        clientShareRetryCounter: clientBootstrap.clientShareRetryCounter,
        relayerPublicKey33B64u: value.publicIdentity.relayerPublicKey33B64u,
        groupPublicKey33B64u: value.publicIdentity.groupPublicKey33B64u,
        ethereumAddress: value.publicIdentity.ethereumAddress,
        clientCaitSithInput: clientBootstrap.clientCaitSithInput,
        createdAtMs: nowMs,
        updatedAtMs: nowMs,
      };
      try {
        console.info('[threshold-ecdsa][hss-role-local-bootstrap][diagnostic]', {
          ...hssDiagnosticIdentity,
          ok: true,
          sessionId: value.sessionId,
          walletSigningSessionId: value.walletSigningSessionId,
          keyHandle: value.keyHandle,
          signingRootId: value.signingRootId,
          signingRootVersion: value.signingRootVersion,
        });
      } catch {}
      const thresholdEcdsaPublicKeyB64u =
        String(value.thresholdEcdsaPublicKeyB64u || '').trim() ||
        value.publicIdentity.groupPublicKey33B64u;
      const ethereumAddress =
        String(value.ethereumAddress || '').trim() || value.publicIdentity.ethereumAddress;
      if (
        String(value.publicIdentity.groupPublicKey33B64u || '').trim() !==
          thresholdEcdsaPublicKeyB64u ||
        String(value.publicIdentity.ethereumAddress || '').trim().toLowerCase() !==
          ethereumAddress.toLowerCase()
      ) {
        return {
          ok: false,
          code: 'identity_mismatch',
          message: 'Threshold ECDSA role-local bootstrap public identity mismatch',
        };
      }
      return {
        ok: true,
        keygenSessionId,
        rpId,
        keyHandle: value.keyHandle,
        ecdsaThresholdKeyId: value.ecdsaThresholdKeyId,
        clientVerifyingShareB64u: clientBootstrap.clientPublicKey33B64u,
        clientAdditiveShare32B64u: clientBootstrap.clientShare32B64u,
        clientRootShare32B64u: base64UrlEncode(clientRootShare32),
        thresholdEcdsaPublicKeyB64u,
        ethereumAddress,
        relayerKeyId: value.relayerKeyId,
        relayerVerifyingShareB64u: value.relayerVerifyingShareB64u,
        participantIds: value.participantIds,
        ...(typeof args.chainId === 'number' ? { chainId: args.chainId } : {}),
        sessionId: value.sessionId,
        walletSigningSessionId: value.walletSigningSessionId,
        expiresAtMs: value.expiresAtMs,
        remainingUses: value.remainingUses,
        ...(String(value.jwt || '').trim() ? { jwt: String(value.jwt).trim() } : {}),
        signingRootId: value.signingRootId,
        signingRootVersion: value.signingRootVersion,
        ecdsaHssRoleLocalClientState,
      };
    }
    return {
      ok: false,
      code: 'role_local_required',
      message:
        'Threshold ECDSA session bootstrap requires a role-local key identity and relayerKeyId',
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
