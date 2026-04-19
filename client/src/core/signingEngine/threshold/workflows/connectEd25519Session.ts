import { cacheSigningSessionPrfFirstBestEffort } from '@/core/signingEngine/api/session/signingSessionState';
import type { WebAuthnAuthenticationCredential } from '@/core/types/webauthn';
import type { WorkerOperationContext } from '../../workerManager/executeWorkerOperation';
import {
  collectAuthenticationCredentialForChallengeB64u,
  getPrfFirstB64uFromCredential,
  type ThresholdIndexedDbPort,
  type WarmSessionMaterialPort,
  type ThresholdWebAuthnPromptPort,
} from '../webauthn';
import { buildEd25519SessionPolicy } from '../session/sessionPolicy';
import type { ThresholdRuntimePolicyScope } from '../session/sessionPolicy';
import { mintEd25519AuthSession } from '../session/ed25519AuthSession';
import type { Ed25519SessionKind } from '../session/ed25519SessionTypes';
import { persistWarmSessionEd25519Capability } from '../../session/warmSessionPersistence';
import {
  createEmailOtpWalletAuthAdapter,
  createPasskeyWalletAuthAdapter,
  createWalletAuthModeResolver,
  resolveAccountAuthMetadataForSignerSource,
} from '../../auth';

function joinUrlPath(baseUrl: string, path: string): string {
  const base = String(baseUrl || '').replace(/\/+$/, '');
  const suffix = String(path || '').replace(/^\/?/, '/');
  return `${base}${suffix}`;
}

async function readJsonObject(response: Response): Promise<Record<string, unknown>> {
  const data = (await response.json().catch(() => ({}))) as unknown;
  return data && typeof data === 'object' && !Array.isArray(data)
    ? (data as Record<string, unknown>)
    : {};
}

async function resolveManagedRuntimePolicyScope(args: {
  relayerUrl: string;
  environmentId: string;
  publishableKey: string;
  nearAccountId: string;
  rpId: string;
}): Promise<ThresholdRuntimePolicyScope> {
  const response = await fetch(joinUrlPath(args.relayerUrl, '/v1/registration/bootstrap-grants'), {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${args.publishableKey}`,
    },
    body: JSON.stringify({
      environmentId: args.environmentId,
      newAccountId: args.nearAccountId,
      rpId: args.rpId,
      flow: 'registration_v1',
    }),
  });
  const data = await readJsonObject(response);
  if (!response.ok || data.ok === false) {
    throw new Error(
      String(
        data.message ||
          data.code ||
          `Managed runtime scope lookup failed with HTTP ${response.status}`,
      ),
    );
  }
  const grant =
    data.grant && typeof data.grant === 'object' && !Array.isArray(data.grant)
      ? (data.grant as Record<string, unknown>)
      : {};
  const orgId = String(grant.orgId || '').trim();
  const projectId = String(grant.projectId || '').trim();
  const envId = String(grant.envId || '').trim();
  if (!orgId || !projectId || !envId) {
    throw new Error('Managed runtime scope lookup response missing canonical runtime scope');
  }
  return { orgId, projectId, envId };
}

/**
 * Wallet-origin helper:
 * - build a threshold session policy (and digest)
 * - collect a WebAuthn assertion with challenge = `sessionPolicyDigest32`
 * - mint a relay threshold session token via `POST /threshold-ed25519/session` (lite)
 *
 * Notes:
 * - This function is intentionally standard-WebAuthn (no contract verifier).
 * - The WebAuthn credential sent to the relay is PRF-redacted in `mintEd25519AuthSession`.
 */
export async function connectEd25519Session(args: {
  indexedDB: ThresholdIndexedDbPort;
  touchIdPrompt: ThresholdWebAuthnPromptPort;
  prfFirstCache?: WarmSessionMaterialPort;
  relayerUrl: string;
  relayerKeyId: string;
  nearAccountId: string;
  participantIds?: number[];
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  runtimeScopeBootstrap?: {
    environmentId: string;
    publishableKey: string;
  };
  sessionKind?: Ed25519SessionKind;
  sessionId?: string;
  walletSigningSessionId?: string;
  ttlMs?: number;
  remainingUses?: number;
  appSessionJwt?: string;
  useAppSessionCookie?: boolean;
  localPrfCredential?: WebAuthnAuthenticationCredential;
  workerCtx?: WorkerOperationContext;
}): Promise<{
  ok: boolean;
  sessionId?: string;
  walletSigningSessionId?: string;
  expiresAtMs?: number;
  remainingUses?: number;
  jwt?: string;
  ecdsaHssClientRootShare32B64u?: string;
  code?: string;
  message?: string;
}> {
  const sessionKind: Ed25519SessionKind = args.sessionKind || 'jwt';
  const rpId = args.touchIdPrompt.getRpId();
  if (!rpId) {
    return { ok: false, code: 'invalid_args', message: 'Missing rpId for WebAuthn' };
  }
  const runtimePolicyScope =
    args.runtimePolicyScope ||
    (args.runtimeScopeBootstrap
      ? await resolveManagedRuntimePolicyScope({
          relayerUrl: args.relayerUrl,
          environmentId: args.runtimeScopeBootstrap.environmentId,
          publishableKey: args.runtimeScopeBootstrap.publishableKey,
          nearAccountId: args.nearAccountId,
          rpId,
        })
      : undefined);

  const { policy, sessionPolicyDigest32 } = await buildEd25519SessionPolicy({
    nearAccountId: args.nearAccountId,
    rpId,
    relayerKeyId: args.relayerKeyId,
    ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
    participantIds: args.participantIds,
    sessionId: args.sessionId,
    walletSigningSessionId: args.walletSigningSessionId,
    ttlMs: args.ttlMs,
    remainingUses: args.remainingUses,
  });

  let credential: WebAuthnAuthenticationCredential | undefined = args.localPrfCredential;
  const appSessionJwt = String(args.appSessionJwt || '').trim();
  const hasAppSessionAuth = Boolean(appSessionJwt || args.useAppSessionCookie === true);
  if (!hasAppSessionAuth) {
    const walletAuthResolver = createWalletAuthModeResolver({
      passkey: createPasskeyWalletAuthAdapter({
        challenge: async () =>
          await collectAuthenticationCredentialForChallengeB64u({
            indexedDB: args.indexedDB,
            touchIdPrompt: args.touchIdPrompt,
            nearAccountId: args.nearAccountId,
            challengeB64u: sessionPolicyDigest32,
          }),
        complete: async ({ response }) => ({
          method: 'passkey',
          webauthnAuthentication: response,
        }),
      }),
      emailOtp: createEmailOtpWalletAuthAdapter({
        challenge: async () => {
          throw new Error('Email OTP Ed25519 session mint is handled by the Email OTP login flow');
        },
        complete: async () => {
          throw new Error('Email OTP Ed25519 session mint is handled by the Email OTP login flow');
        },
      }),
    });
    const walletAuthPlan = await walletAuthResolver.resolveWalletAuthPlan({
      accountId: args.nearAccountId,
      accountAuth: resolveAccountAuthMetadataForSignerSource(),
      intent: 'session_mint',
      curve: 'ed25519',
    });
    if (walletAuthPlan.kind !== 'passkeyReauth') {
      return {
        ok: false,
        code: 'unsupported',
        message: 'Ed25519 session mint requires passkey authorization',
      };
    }

    // Collect WebAuthn assertion for challenge=sessionPolicyDigest32 when no app session is
    // available. Login warm-up uses the app-session JWT instead to avoid a second prompt.
    const credentialChallenge = await walletAuthPlan.challenge();
    const walletAuthProof = await walletAuthPlan.complete(credentialChallenge);
    credential = walletAuthProof.webauthnAuthentication as WebAuthnAuthenticationCredential;
  }

  if (!credential) {
    return {
      ok: false,
      code: 'invalid_args',
      message: 'Ed25519 session mint with app session requires local PRF credential material',
    };
  }

  const prfFirstB64u = getPrfFirstB64uFromCredential(credential);
  if (!prfFirstB64u) {
    return {
      ok: false,
      code: 'unsupported',
      message: 'Missing PRF.first output from credential (requires a PRF-enabled passkey)',
    };
  }

  // 3) Mint threshold auth session token/cookie with standard WebAuthn verification.
  const minted = await mintEd25519AuthSession({
    relayerUrl: args.relayerUrl,
    sessionKind,
    relayerKeyId: args.relayerKeyId,
    sessionPolicy: policy,
    ...(appSessionJwt || args.useAppSessionCookie === true
      ? {
          ...(appSessionJwt ? { appSessionJwt } : {}),
          ...(args.useAppSessionCookie ? { useAppSessionCookie: args.useAppSessionCookie } : {}),
        }
      : { webauthnAuthentication: credential }),
    runtimeEnvironmentId: args.runtimeScopeBootstrap?.environmentId,
    publishableKey: args.runtimeScopeBootstrap?.publishableKey,
  });
  if (!minted.ok) {
    return minted;
  }
  const requestedSessionId = String(policy.sessionId || '').trim();
  const resolvedSessionId =
    String(minted.sessionId || requestedSessionId).trim() || requestedSessionId;
  const walletSigningSessionId = String(
    minted.walletSigningSessionId || policy.walletSigningSessionId || '',
  ).trim();

  // Persist the canonical session record before sealing PRF cache state.
  // Sealed-refresh persistence resolves relayer transport from this record.
  const expiresAtMs = minted.expiresAtMs ?? Date.now() + policy.ttlMs;
  const remainingUses = minted.remainingUses ?? policy.remainingUses;
  const mintedRuntimePolicyScope = minted.runtimePolicyScope || runtimePolicyScope;
  persistWarmSessionEd25519Capability({
    nearAccountId: args.nearAccountId,
    rpId,
    relayerUrl: args.relayerUrl,
    relayerKeyId: args.relayerKeyId,
    ...(mintedRuntimePolicyScope ? { runtimePolicyScope: mintedRuntimePolicyScope } : {}),
    participantIds: args.participantIds,
    sessionKind,
    sessionId: resolvedSessionId,
    ...(walletSigningSessionId ? { walletSigningSessionId } : {}),
    expiresAtMs,
    remainingUses,
    jwt: minted.jwt,
    source: 'manual-connect',
  });

  // Cache PRF.first in-memory for the session TTL/uses window so subsequent signing can
  // consume the client share seed without prompting again (wallet-origin only).
  const prfFirstCache = args.prfFirstCache;
  if (prfFirstCache) {
    await cacheSigningSessionPrfFirstBestEffort(prfFirstCache, {
      sessionId: resolvedSessionId,
      prfFirstB64u,
      expiresAtMs,
      remainingUses,
    });
  }

  return {
    ok: true,
    sessionId: resolvedSessionId,
    ...(walletSigningSessionId ? { walletSigningSessionId } : {}),
    expiresAtMs,
    remainingUses,
    jwt: minted.jwt,
    ecdsaHssClientRootShare32B64u: prfFirstB64u,
  };
}
