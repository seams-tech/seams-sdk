import type { WorkerOperationContext } from '../../workerManager/executeWorkerOperation';
import { collectAuthenticationCredentialForChallengeB64u } from '../../webauthnAuth/credentials/collectAuthenticationCredentialForChallengeB64u';
import type { ThresholdCredentialStorePort, ThresholdWebAuthnPromptPort } from '../crypto/webauthn';
import { buildEd25519SessionPolicy } from '../sessionPolicy';
import {
  parseThresholdRuntimePolicyScopeFromJwt,
  type ThresholdRuntimePolicyScope,
} from '../sessionPolicy';
import type { RouterAbEd25519NormalSigningState } from './routerAbNormalSigningState';
import {
  buildThresholdEd25519WebAuthnPrfSecretSource,
  localPrfFirstForEd25519WalletSessionMintAuthorization,
  mintEd25519WalletSession,
  type Ed25519WalletSessionMintAuthorization,
} from '../ed25519/walletSession';

/**
 * Wallet-origin helper:
 * - build a threshold session policy (and digest)
 * - collect a WebAuthn assertion with challenge = `sessionPolicyDigest32`
 * - mint a Wallet Session JWT via `POST /v2/router-ab/wallet-session/ed25519`
 *
 * Notes:
 * - This function is intentionally standard-WebAuthn (no contract verifier).
 * - The WebAuthn credential sent to the relay is PRF-redacted in `mintEd25519WalletSession`.
 */
export async function connectEd25519Session(args: {
  credentialStore: ThresholdCredentialStorePort;
  touchIdPrompt: ThresholdWebAuthnPromptPort;
  relayerUrl: string;
  relayerKeyId: string;
  walletId: string;
  nearAccountId: string;
  nearEd25519SigningKeyId: string;
  participantIds?: number[];
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  routerAbNormalSigning?: RouterAbEd25519NormalSigningState;
  runtimeScopeBootstrap?: {
    environmentId: string;
    publishableKey: string;
  };
  sessionKind?: 'jwt';
  sessionId?: string;
  signingGrantId?: string;
  ttlMs?: number;
  remainingUses?: number;
  auth?: Ed25519WalletSessionMintAuthorization;
  workerCtx?: WorkerOperationContext;
}): Promise<{
  ok: boolean;
  sessionId?: string;
  signingGrantId?: string;
  expiresAtMs?: number;
  remainingUses?: number;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  routerAbNormalSigning?: RouterAbEd25519NormalSigningState;
  jwt?: string;
  ecdsaHssPasskeyPrfFirstB64u?: string;
  code?: string;
  message?: string;
}> {
  const sessionKind = 'jwt';
  const rpId = args.touchIdPrompt.getRpId();
  if (!rpId) {
    return { ok: false, code: 'invalid_args', message: 'Missing rpId for WebAuthn' };
  }
  const appSessionJwt =
    args.auth?.kind === 'app_session_jwt' ? String(args.auth.appSessionJwt || '').trim() : '';
  const appSessionRuntimePolicyScope = parseThresholdRuntimePolicyScopeFromJwt(appSessionJwt);
  const runtimePolicyScope = args.runtimePolicyScope || appSessionRuntimePolicyScope;

  const { policy, sessionPolicyDigest32 } = await buildEd25519SessionPolicy({
    walletId: args.walletId,
    nearAccountId: args.nearAccountId,
    nearEd25519SigningKeyId: args.nearEd25519SigningKeyId,
    rpId,
    relayerKeyId: args.relayerKeyId,
    ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
    ...(args.routerAbNormalSigning ? { routerAbNormalSigning: args.routerAbNormalSigning } : {}),
    participantIds: args.participantIds,
    thresholdSessionId: args.sessionId,
    signingGrantId: args.signingGrantId,
    ttlMs: args.ttlMs,
    remainingUses: args.remainingUses,
  });

  let auth: Ed25519WalletSessionMintAuthorization | undefined = args.auth;
  if (!auth) {
    // Collect WebAuthn only when the caller did not already confirm the same session policy.
    // A regression here ignored the provided PRF source, so post-exhaustion transaction signing
    // showed one tx confirmation and then a second TouchID prompt for the session mint.
    const credential = await collectAuthenticationCredentialForChallengeB64u({
      credentialStore: args.credentialStore,
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

  const prfFirstB64u = localPrfFirstForEd25519WalletSessionMintAuthorization(auth);
  if (!prfFirstB64u) {
    return {
      ok: false,
      code: 'unsupported',
      message: 'Missing PRF.first output from credential (requires a PRF-enabled passkey)',
    };
  }

  // 3) Mint a Wallet Session JWT with app-session or WebAuthn authorization.
  const minted = await mintEd25519WalletSession({
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
  const requestedSessionId = String(policy.thresholdSessionId || '').trim();
  const resolvedSessionId =
    String(minted.sessionId || requestedSessionId).trim() || requestedSessionId;
  const signingGrantId = String(minted.signingGrantId || policy.signingGrantId || '').trim();

  const expiresAtMs = minted.expiresAtMs ?? Date.now() + policy.ttlMs;
  const remainingUses = minted.remainingUses ?? policy.remainingUses;
  const mintedRuntimePolicyScope = minted.runtimePolicyScope || runtimePolicyScope;

  return {
    ok: true,
    sessionId: resolvedSessionId,
    ...(signingGrantId ? { signingGrantId } : {}),
    expiresAtMs,
    remainingUses,
    ...(mintedRuntimePolicyScope ? { runtimePolicyScope: mintedRuntimePolicyScope } : {}),
    ...(args.routerAbNormalSigning ? { routerAbNormalSigning: args.routerAbNormalSigning } : {}),
    jwt: minted.jwt,
    ecdsaHssPasskeyPrfFirstB64u: prfFirstB64u,
  };
}
