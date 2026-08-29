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
import type { WalletSessionCommittedIdentityV1 } from '@shared/authorization';
import type { WalletSessionOperationCredentialV1 } from '@shared/device-linking';
import {
  buildThresholdEd25519WebAuthnPrfSecretSource,
  localPrfFirstForEd25519WalletSessionMintAuthorization,
  mintEd25519WalletSession,
  type Ed25519WalletSessionMintAuthorization,
} from '../ed25519/walletSession';

type ConnectEd25519SessionSuccessBase = {
  readonly ok: true;
  readonly thresholdSessionId: ThresholdEd25519SessionId;
  readonly authorizationId: WalletSessionAuthorizationId;
  readonly walletSessionId: WalletSessionId;
  readonly quotaId: MpcWalletSigningQuotaId;
  readonly expiresAtMs: number;
  readonly remainingUses: number;
  readonly routerAbNormalSigning: RouterAbEd25519NormalSigningState;
  readonly passkeyPrfFirstB64u: string;
  readonly runtimePolicyScope: ThresholdRuntimePolicyScope;
  readonly code?: never;
  readonly message?: never;
};

export type ConnectEd25519SessionResult =
  | (ConnectEd25519SessionSuccessBase & {
      readonly sessionKind: 'issued_exact_wallet_session';
      readonly operationCredential: WalletSessionOperationCredentialV1;
    })
  | (ConnectEd25519SessionSuccessBase & {
      readonly sessionKind: 'already_committed_exact_wallet_session';
      readonly operationCredential?: never;
    })
  | {
      readonly ok: false;
      readonly code: 'already_committed';
      readonly message: string;
      readonly next: 'unlock_exact_method';
      readonly committed: WalletSessionCommittedIdentityV1;
      readonly thresholdSessionId?: never;
      readonly authorizationId?: never;
      readonly walletSessionId?: never;
      readonly quotaId?: never;
      readonly expiresAtMs?: never;
      readonly remainingUses?: never;
      readonly runtimePolicyScope?: never;
      readonly routerAbNormalSigning?: never;
      readonly passkeyPrfFirstB64u?: never;
      readonly sessionKind?: never;
      readonly operationCredential?: never;
    }
  | {
      readonly ok: false;
      readonly code: string;
      readonly message: string;
      readonly next?: never;
      readonly committed?: never;
      readonly thresholdSessionId?: never;
      readonly authorizationId?: never;
      readonly walletSessionId?: never;
      readonly quotaId?: never;
      readonly expiresAtMs?: never;
      readonly remainingUses?: never;
      readonly runtimePolicyScope?: never;
      readonly routerAbNormalSigning?: never;
      readonly passkeyPrfFirstB64u?: never;
      readonly sessionKind?: never;
      readonly operationCredential?: never;
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
 * - mint an exact Wallet Session operation credential or reuse an existing one
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
  thresholdSessionId?: ThresholdEd25519SessionId;
  ttlMs?: number;
  remainingUses?: number;
  auth?: Ed25519WalletSessionMintAuthorization;
  workerCtx?: WorkerOperationContext;
  existingWalletSessionToken?: string;
}): Promise<ConnectEd25519SessionResult> {
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
    sessionKind: 'opaque',
    relayerKeyId: args.relayerKeyId,
    sessionPolicy: policy,
    auth,
    projectEnvironmentId: args.runtimeScopeBootstrap?.projectEnvironmentId,
    publishableKey: args.runtimeScopeBootstrap?.publishableKey,
    ...(args.existingWalletSessionToken
      ? { existingWalletSessionToken: args.existingWalletSessionToken }
      : {}),
  });
  if (!minted.ok) {
    if (minted.code === 'already_committed') {
      return minted;
    }
    return {
      ok: false,
      code: minted.code,
      message: minted.message,
    };
  }
  const requestedThresholdSessionId = policy.thresholdSessionId;
  const resolvedThresholdSessionId = minted.thresholdSessionId || requestedThresholdSessionId;

  const expiresAtMs = minted.expiresAtMs;
  const remainingUses = minted.remainingUses;
  const mintedRuntimePolicyScope = minted.runtimePolicyScope;
  if (
    !resolvedThresholdSessionId ||
    !minted.authorizationId ||
    !minted.walletSessionId ||
    !minted.quotaId ||
    !mintedRuntimePolicyScope
  ) {
    return {
      ok: false,
      code: 'invalid_response',
      message: 'Threshold Ed25519 session mint returned incomplete lifecycle metadata',
    };
  }

  const successBase = {
    ok: true as const,
    thresholdSessionId: SigningSessionIds.thresholdEd25519Session(resolvedThresholdSessionId),
    authorizationId: minted.authorizationId,
    walletSessionId: minted.walletSessionId,
    quotaId: minted.quotaId,
    expiresAtMs,
    remainingUses,
    runtimePolicyScope: mintedRuntimePolicyScope,
    routerAbNormalSigning: args.routerAbNormalSigning,
    passkeyPrfFirstB64u: prfFirstB64u,
  };
  switch (minted.sessionKind) {
    case 'issued_exact_wallet_session':
      if (minted.operationCredential.walletSessionId !== minted.walletSessionId) {
        return {
          ok: false,
          code: 'invalid_response',
          message: 'Threshold Ed25519 session mint credential does not identify its session',
        };
      }
      return {
        ...successBase,
        sessionKind: minted.sessionKind,
        operationCredential: minted.operationCredential,
      };
    case 'already_committed_exact_wallet_session':
      return { ...successBase, sessionKind: minted.sessionKind };
    default:
      return assertNeverEd25519WalletSessionMintKind(minted);
  }
}

function assertNeverEd25519WalletSessionMintKind(kind: never): never {
  throw new Error(`[threshold-ed25519] unsupported Wallet Session mint kind: ${String(kind)}`);
}
