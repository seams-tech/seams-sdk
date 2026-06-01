import type { WorkerOperationContext } from '../../workerManager/executeWorkerOperation';
import { collectAuthenticationCredentialForChallengeB64u } from '../../webauthnAuth/credentials/collectAuthenticationCredentialForChallengeB64u';
import type {
  ThresholdIndexedDbPort,
  ThresholdWebAuthnPromptPort,
} from '../crypto/webauthn';
import { buildEd25519SessionPolicy } from '../sessionPolicy';
import {
  parseThresholdRuntimePolicyScopeFromJwt,
  type ThresholdRuntimePolicyScope,
  type ThresholdSessionKind,
} from '../sessionPolicy';
import {
  buildThresholdEd25519WebAuthnPrfSecretSource,
  localPrfFirstForThresholdEd25519SessionMintAuthorization,
  mintEd25519AuthSession,
  type ThresholdEd25519SessionMintAuthorization,
} from '../ed25519/authSession';

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
  auth?: ThresholdEd25519SessionMintAuthorization;
  workerCtx?: WorkerOperationContext;
}): Promise<{
  ok: boolean;
  sessionId?: string;
  walletSigningSessionId?: string;
  expiresAtMs?: number;
  remainingUses?: number;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  jwt?: string;
  ecdsaHssPasskeyPrfFirstB64u?: string;
  code?: string;
  message?: string;
}> {
  const sessionKind: ThresholdSessionKind = args.sessionKind || 'jwt';
  const rpId = args.touchIdPrompt.getRpId();
  if (!rpId) {
    return { ok: false, code: 'invalid_args', message: 'Missing rpId for WebAuthn' };
  }
  const appSessionJwt =
    args.auth?.kind === 'app_session_jwt' ? String(args.auth.appSessionJwt || '').trim() : '';
  const appSessionRuntimePolicyScope = parseThresholdRuntimePolicyScopeFromJwt(appSessionJwt);
  const runtimePolicyScope = args.runtimePolicyScope || appSessionRuntimePolicyScope;

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

  let auth: ThresholdEd25519SessionMintAuthorization | undefined = args.auth;
  if (!auth) {
    // Collect WebAuthn only when the caller did not already confirm the same session policy.
    // A regression here ignored the provided PRF source, so post-exhaustion transaction signing
    // showed one tx confirmation and then a second TouchID prompt for the session mint.
    const credential = await collectAuthenticationCredentialForChallengeB64u({
      indexedDB: args.indexedDB,
      touchIdPrompt: args.touchIdPrompt,
      nearAccountId: args.nearAccountId,
      challengeB64u: sessionPolicyDigest32,
    });
    auth = {
      kind: 'threshold_session_policy_webauthn',
      policySecretSource: buildThresholdEd25519WebAuthnPrfSecretSource({
        credential,
        rpId,
      }),
    };
  }

  const prfFirstB64u = localPrfFirstForThresholdEd25519SessionMintAuthorization(auth);
  if (!prfFirstB64u) {
    return {
      ok: false,
      code: 'unsupported',
      message: 'Missing PRF.first output from credential (requires a PRF-enabled passkey)',
    };
  }

  // 3) Mint threshold auth session token/cookie with app-session or WebAuthn authorization.
  const minted = await mintEd25519AuthSession({
    relayerUrl: args.relayerUrl,
    sessionKind,
    relayerKeyId: args.relayerKeyId,
    sessionPolicy: policy,
    auth,
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
    ecdsaHssPasskeyPrfFirstB64u: prfFirstB64u,
  };
}
