import type { WebAuthnAuthenticationCredential } from '@/core/types/webauthn';
import type { WorkerOperationContext } from '../../workerManager/executeWorkerOperation';
import { collectAuthenticationCredentialForChallengeB64u } from '../../webauthnAuth/credentials/collectAuthenticationCredentialForChallengeB64u';
import {
  getPrfFirstB64uFromCredential,
  type ThresholdIndexedDbPort,
  type ThresholdWebAuthnPromptPort,
} from '../crypto/webauthn';
import { buildEd25519SessionPolicy } from '../sessionPolicy';
import {
  parseThresholdRuntimePolicyScopeFromJwt,
  type ThresholdRuntimePolicyScope,
  type ThresholdSessionKind,
} from '../sessionPolicy';
import { mintEd25519AuthSession } from '../ed25519/authSession';

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
  const signingRootVersion = String(grant.signingRootVersion || '').trim();
  if (!orgId || !projectId || !envId || !signingRootVersion) {
    throw new Error('Managed runtime scope lookup response missing canonical runtime scope');
  }
  return { orgId, projectId, envId, signingRootVersion };
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
  relayerUrl: string;
  relayerKeyId: string;
  nearAccountId: string;
  participantIds?: number[];
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  runtimeScopeBootstrap?: {
    environmentId: string;
    publishableKey: string;
  };
  sessionKind?: ThresholdSessionKind;
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
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  jwt?: string;
  ecdsaHssClientRootShare32B64u?: string;
  code?: string;
  message?: string;
}> {
  const sessionKind: ThresholdSessionKind = args.sessionKind || 'jwt';
  const rpId = args.touchIdPrompt.getRpId();
  if (!rpId) {
    return { ok: false, code: 'invalid_args', message: 'Missing rpId for WebAuthn' };
  }
  const appSessionJwt = String(args.appSessionJwt || '').trim();
  const hasAppSessionAuth = Boolean(appSessionJwt || args.useAppSessionCookie === true);
  const appSessionRuntimePolicyScope = parseThresholdRuntimePolicyScopeFromJwt(appSessionJwt);
  // JWT-backed unlocks with a signed runtime scope are already authenticated; bootstrap
  // grants are registration-style publishable-key flows and consume free registration quota.
  // Cookie-only calls may not have a session cookie in local/e2e runtimes, so keep their
  // existing managed bootstrap path unless the caller supplied canonical scope.
  const shouldResolveManagedRuntimePolicyScope =
    !appSessionRuntimePolicyScope && !args.runtimePolicyScope && Boolean(args.runtimeScopeBootstrap);
  const runtimePolicyScope =
    args.runtimePolicyScope ||
    appSessionRuntimePolicyScope ||
    (shouldResolveManagedRuntimePolicyScope && args.runtimeScopeBootstrap
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
  if (!hasAppSessionAuth && !credential) {
    // Collect WebAuthn only when the caller did not already confirm the same session policy.
    // A regression here ignored `localPrfCredential`, so post-exhaustion transaction signing
    // showed one tx confirmation and then a second TouchID prompt for the session mint.
    credential = await collectAuthenticationCredentialForChallengeB64u({
      indexedDB: args.indexedDB,
      touchIdPrompt: args.touchIdPrompt,
      nearAccountId: args.nearAccountId,
      challengeB64u: sessionPolicyDigest32,
    });
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
    ...(appSessionJwt
      ? {
          appSessionJwt,
        }
      : args.useAppSessionCookie === true
        ? {
            useAppSessionCookie: true,
            webauthnAuthentication: credential,
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

  const expiresAtMs = minted.expiresAtMs ?? Date.now() + policy.ttlMs;
  const remainingUses = minted.remainingUses ?? policy.remainingUses;
  const mintedRuntimePolicyScope = minted.runtimePolicyScope || runtimePolicyScope;

  return {
    ok: true,
    sessionId: resolvedSessionId,
    ...(walletSigningSessionId ? { walletSigningSessionId } : {}),
    expiresAtMs,
    remainingUses,
    ...(mintedRuntimePolicyScope ? { runtimePolicyScope: mintedRuntimePolicyScope } : {}),
    jwt: minted.jwt,
    ecdsaHssClientRootShare32B64u: prfFirstB64u,
  };
}
