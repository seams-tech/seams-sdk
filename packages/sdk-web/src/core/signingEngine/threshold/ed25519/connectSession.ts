import type { WorkerOperationContext } from '../../workerManager/executeWorkerOperation';
import { collectAuthenticationCredentialForChallengeB64u } from '../../webauthnAuth/credentials/collectAuthenticationCredentialForChallengeB64u';
import type { ThresholdCredentialStorePort, ThresholdWebAuthnPromptPort } from '../crypto/webauthn';
import { buildEd25519SessionPolicy } from '../sessionPolicy';
import {
  parseThresholdRuntimePolicyScopeFromJwt,
  type Ed25519SessionPolicyAuthority,
  type ThresholdRuntimePolicyScope,
} from '../sessionPolicy';
import {
  isEmailOtpWalletAuthAuthority,
  isPasskeyWalletAuthAuthority,
  type PasskeyWalletAuthAuthority,
} from '@shared/utils/walletAuthAuthority';
import type { RouterAbEd25519NormalSigningState } from './routerAbNormalSigningState';
import {
  buildThresholdEd25519WebAuthnPrfSecretSource,
  localPrfFirstForEd25519WalletSessionMintAuthorization,
  mintEd25519WalletSession,
  type Ed25519WalletSessionMintAuthorization,
} from '../ed25519/walletSession';

export type ConnectEd25519SessionResult =
  | {
      ok: true;
      sessionId: string;
      signingGrantId: string;
      expiresAtMs: number;
      remainingUses: number;
      routerAbNormalSigning: RouterAbEd25519NormalSigningState;
      jwt: string;
      ecdsaDerivationPasskeyPrfFirstB64u: string;
      runtimePolicyScope?: ThresholdRuntimePolicyScope;
      code?: never;
      message?: never;
    }
  | {
      ok: false;
      code?: string;
      message?: string;
      sessionId?: never;
      signingGrantId?: never;
      expiresAtMs?: never;
      remainingUses?: never;
      runtimePolicyScope?: never;
      routerAbNormalSigning?: never;
      jwt?: never;
      ecdsaDerivationPasskeyPrfFirstB64u?: never;
    };

function assertNeverWalletAuthFactorKind(kind: never): never {
  throw new Error(`[threshold-ed25519] unsupported wallet auth factor kind: ${String(kind)}`);
}

function passkeyAuthorityFromEd25519SessionPolicyAuthority(
  authority: Ed25519SessionPolicyAuthority,
): PasskeyWalletAuthAuthority | null {
  if (isPasskeyWalletAuthAuthority(authority.authority)) {
    return authority.authority;
  }
  if (isEmailOtpWalletAuthAuthority(authority.authority)) return null;
  authority.authority satisfies never;
  return assertNeverWalletAuthFactorKind(authority.authority);
}

/**
 * Wallet-origin helper:
 * - build a threshold session policy (and digest)
 * - collect a WebAuthn assertion with challenge = `sessionPolicyDigest32`
 * - mint a Wallet Session JWT via `POST /router-ab/wallet-session/ed25519`
 *
 * Notes:
 * - This function is intentionally standard-WebAuthn (no contract verifier).
 * - The WebAuthn credential sent to the Router API is PRF-redacted in `mintEd25519WalletSession`.
 */
export async function connectEd25519Session(args: {
  credentialStore: ThresholdCredentialStorePort;
  touchIdPrompt: ThresholdWebAuthnPromptPort;
  relayerUrl: string;
  relayerKeyId: string;
  walletId: string;
  nearAccountId: string;
  nearEd25519SigningKeyId: string;
  authority: Ed25519SessionPolicyAuthority;
  participantIds?: number[];
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  routerAbNormalSigning: RouterAbEd25519NormalSigningState;
  runtimeScopeBootstrap?: {
    projectEnvironmentId: string;
    publishableKey: string;
  };
  sessionKind?: 'jwt';
  sessionId?: string;
  signingGrantId?: string;
  ttlMs?: number;
  remainingUses?: number;
  auth?: Ed25519WalletSessionMintAuthorization;
  workerCtx?: WorkerOperationContext;
}): Promise<ConnectEd25519SessionResult> {
  const sessionKind = 'jwt';
  const passkeyAuthority = passkeyAuthorityFromEd25519SessionPolicyAuthority(args.authority);
  const passkeyRpId = passkeyAuthority ? String(passkeyAuthority.verifier.rpId || '').trim() : '';
  if (passkeyAuthority && !passkeyRpId) {
    return { ok: false, code: 'invalid_args', message: 'Missing rpId for WebAuthn' };
  }
  const appSessionJwt =
    args.auth?.kind === 'app_session_jwt' ? String(args.auth.appSessionJwt || '').trim() : '';
  const appSessionRuntimePolicyScope = parseThresholdRuntimePolicyScopeFromJwt(appSessionJwt);
  const runtimePolicyScope = args.runtimePolicyScope || appSessionRuntimePolicyScope;

  const { policy, sessionPolicyDigest32 } = await buildEd25519SessionPolicy({
    nearAccountId: args.nearAccountId,
    nearEd25519SigningKeyId: args.nearEd25519SigningKeyId,
    authority: args.authority,
    relayerKeyId: args.relayerKeyId,
    ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
    routerAbNormalSigning: args.routerAbNormalSigning,
    participantIds: args.participantIds,
    thresholdSessionId: args.sessionId,
    signingGrantId: args.signingGrantId,
    ttlMs: args.ttlMs,
    remainingUses: args.remainingUses,
  });

  let auth: Ed25519WalletSessionMintAuthorization | undefined = args.auth;
  if (!auth) {
    if (!passkeyAuthority) {
      return {
        ok: false,
        code: 'invalid_args',
        message: 'Email OTP Ed25519 session mint requires explicit route authorization',
      };
    }
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
        rpId: passkeyRpId,
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
    projectEnvironmentId: args.runtimeScopeBootstrap?.projectEnvironmentId,
    publishableKey: args.runtimeScopeBootstrap?.publishableKey,
  });
  if (!minted.ok) {
    return {
      ok: false,
      ...(minted.code ? { code: minted.code } : {}),
      ...(minted.message ? { message: minted.message } : {}),
    };
  }
  const requestedSessionId = String(policy.thresholdSessionId || '').trim();
  const resolvedSessionId =
    String(minted.sessionId || requestedSessionId).trim() || requestedSessionId;
  const signingGrantId = String(minted.signingGrantId || policy.signingGrantId || '').trim();

  const expiresAtMs = minted.expiresAtMs ?? Date.now() + policy.ttlMs;
  const remainingUses = minted.remainingUses ?? policy.remainingUses;
  const mintedRuntimePolicyScope = minted.runtimePolicyScope || runtimePolicyScope;
  const jwt = String(minted.jwt || '').trim();
  if (!resolvedSessionId || !signingGrantId || !jwt) {
    return {
      ok: false,
      code: 'invalid_response',
      message: 'Threshold Ed25519 session mint returned incomplete lifecycle metadata',
    };
  }

  return {
    ok: true,
    sessionId: resolvedSessionId,
    signingGrantId,
    expiresAtMs,
    remainingUses,
    ...(mintedRuntimePolicyScope ? { runtimePolicyScope: mintedRuntimePolicyScope } : {}),
    routerAbNormalSigning: args.routerAbNormalSigning,
    jwt,
    ecdsaDerivationPasskeyPrfFirstB64u: prfFirstB64u,
  };
}
