import type { WorkerOperationContext } from '../../workerManager/executeWorkerOperation';
import { collectAuthenticationCredentialForChallengeB64u } from '../../webauthnAuth/credentials/collectAuthenticationCredentialForChallengeB64u';
import type { ThresholdCredentialStorePort, ThresholdWebAuthnPromptPort } from '../crypto/webauthn';
import { buildEd25519SessionPolicy } from '../sessionPolicy';
import type { Ed25519SessionPolicyAuthority, ThresholdRuntimePolicyScope } from '../sessionPolicy';
import {
  isEmailOtpWalletAuthAuthority,
  isPasskeyWalletAuthAuthority,
  type PasskeyWalletAuthAuthority,
} from '@shared/utils/walletAuthAuthority';
import type { RouterAbEd25519NormalSigningState } from './routerAbNormalSigningState';
import type { ThresholdEd25519SessionId } from '@shared/utils/domainIds';
import { SigningSessionIds } from '../../session/operationState/types';
import type {
  MpcWalletSigningQuotaId,
  WalletSessionAuthorizationId,
  WalletSessionId,
} from '@shared/authorization/capabilityKinds';
import {
  buildThresholdEd25519WebAuthnPrfSecretSource,
  localPrfFirstForEd25519WalletSessionMintAuthorization,
  mintEd25519WalletSession,
  type Ed25519WalletSessionMintAuthorization,
} from '../ed25519/walletSession';

export type ConnectEd25519SessionResult =
  | {
      ok: true;
      thresholdSessionId: ThresholdEd25519SessionId;
      authorizationId: WalletSessionAuthorizationId;
      walletSessionId: WalletSessionId;
      quotaId: MpcWalletSigningQuotaId;
      expiresAtMs: number;
      remainingUses: number;
      routerAbNormalSigning: RouterAbEd25519NormalSigningState;
      walletSessionToken: string;
      passkeyPrfFirstB64u: string;
      runtimePolicyScope: ThresholdRuntimePolicyScope;
      code?: never;
      message?: never;
    }
  | {
      ok: false;
      code?: string;
      message?: string;
      thresholdSessionId?: never;
      authorizationId?: never;
      walletSessionId?: never;
      quotaId?: never;
      expiresAtMs?: never;
      remainingUses?: never;
      runtimePolicyScope?: never;
      routerAbNormalSigning?: never;
      walletSessionToken?: never;
      passkeyPrfFirstB64u?: never;
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
  sessionKind?: 'opaque';
  thresholdSessionId?: ThresholdEd25519SessionId;
  ttlMs?: number;
  remainingUses?: number;
  auth?: Ed25519WalletSessionMintAuthorization;
  workerCtx?: WorkerOperationContext;
}): Promise<ConnectEd25519SessionResult> {
  const sessionKind = 'opaque';
  const passkeyAuthority = passkeyAuthorityFromEd25519SessionPolicyAuthority(args.authority);
  const passkeyRpId = passkeyAuthority ? String(passkeyAuthority.verifier.rpId || '').trim() : '';
  if (passkeyAuthority && !passkeyRpId) {
    return { ok: false, code: 'invalid_args', message: 'Missing rpId for WebAuthn' };
  }
  const { policy, sessionPolicyDigest32 } = await buildEd25519SessionPolicy({
    nearAccountId: args.nearAccountId,
    nearEd25519SigningKeyId: args.nearEd25519SigningKeyId,
    authority: args.authority,
    relayerKeyId: args.relayerKeyId,
    ...(args.runtimePolicyScope ? { runtimePolicyScope: args.runtimePolicyScope } : {}),
    routerAbNormalSigning: args.routerAbNormalSigning,
    participantIds: args.participantIds,
    thresholdSessionId: args.thresholdSessionId,
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

  // 3) Mint the opaque Wallet Session after proving the exact session policy.
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
  const requestedThresholdSessionId = policy.thresholdSessionId;
  const resolvedThresholdSessionId = minted.thresholdSessionId || requestedThresholdSessionId;

  const expiresAtMs = minted.expiresAtMs ?? Date.now() + policy.ttlMs;
  const remainingUses = minted.remainingUses ?? policy.remainingUses;
  const mintedRuntimePolicyScope = minted.runtimePolicyScope;
  const walletSessionToken = String(minted.walletSessionToken || '').trim();
  if (
    !resolvedThresholdSessionId ||
    !minted.authorizationId ||
    !minted.walletSessionId ||
    !minted.quotaId ||
    !walletSessionToken ||
    !mintedRuntimePolicyScope
  ) {
    return {
      ok: false,
      code: 'invalid_response',
      message: 'Threshold Ed25519 session mint returned incomplete lifecycle metadata',
    };
  }

  return {
    ok: true,
    thresholdSessionId: SigningSessionIds.thresholdEd25519Session(resolvedThresholdSessionId),
    authorizationId: minted.authorizationId,
    walletSessionId: minted.walletSessionId,
    quotaId: minted.quotaId,
    expiresAtMs,
    remainingUses,
    runtimePolicyScope: mintedRuntimePolicyScope,
    routerAbNormalSigning: args.routerAbNormalSigning,
    walletSessionToken,
    passkeyPrfFirstB64u: prfFirstB64u,
  };
}
