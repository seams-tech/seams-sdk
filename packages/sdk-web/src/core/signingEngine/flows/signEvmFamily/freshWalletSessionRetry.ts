import type { AccountAuthMetadata } from '@/core/signingEngine/interfaces/accountAuthMetadata';
import {
  SIGNING_SESSION_EXPIRY_DETECTION_SOURCES,
  SigningEventPhase,
} from '@/core/types/sdkSentEvents';
import { SIGNER_AUTH_METHODS } from '@shared/utils/signerDomain';
import type { EvmSignedResult } from '../../chains/evm/evmAdapter';
import type { TempoSignedResult } from '../../chains/tempo/tempoAdapter';
import type { SigningSessionCoordinator } from '../../session/SigningSessionCoordinator';
import type { ExactEcdsaSigningLaneIdentity } from '../../session/identity/exactSigningLaneIdentity';
import type { ActiveEvmFamilyWalletSessionAuthorization } from '../../session/material/ecdsaSigningCapability';
import {
  requireAuthoritativeExpiredWalletSessionAuthorizationBoundary,
  type ExpiredWalletSessionAuthorizationState,
} from '../../session/identity/clientSessionPersistenceState';
import { walletSessionFailureFromError } from '../../session/lifecycle/walletSessionFailure';
import { emitEvmFamilySigningEvent } from './events';
import {
  classifyEvmFamilyFreshAuthRetry,
  type EvmFamilyFreshAuthRetryDecision,
  type EvmFamilyFreshAuthRetrySideEffectState,
} from './freshAuthRetryPolicy';
import type {
  EvmFamilyChain,
  EvmFamilyLifecycleEventCallback,
  EvmFamilySenderSignatureAlgorithm,
} from './types';

export type EvmFamilyWalletSessionExpiryCandidate =
  | {
      readonly kind: 'exact_ecdsa_lane';
      readonly identity: ExactEcdsaSigningLaneIdentity;
      readonly authorization: ActiveEvmFamilyWalletSessionAuthorization;
      readonly expiresAtMs: unknown;
    }
  | {
      readonly kind: 'unavailable';
    };

export type EvmFamilyWalletSessionExpiryContext =
  | {
      readonly kind: 'authoritative_expiry';
      readonly state: ExpiredWalletSessionAuthorizationState;
    }
  | {
      readonly kind: 'expired_without_exact_lane';
    }
  | {
      readonly kind: 'not_expired';
    };

export function resolveEvmFamilyWalletSessionExpiryContext(args: {
  readonly error: unknown;
  readonly candidate: EvmFamilyWalletSessionExpiryCandidate;
  readonly detectedAtMs: number;
}): EvmFamilyWalletSessionExpiryContext {
  const failure = walletSessionFailureFromError(args.error);
  if (failure?.kind !== 'expired') return { kind: 'not_expired' };
  if (args.candidate.kind === 'unavailable') {
    return { kind: 'expired_without_exact_lane' };
  }
  return {
    kind: 'authoritative_expiry',
    state: requireAuthoritativeExpiredWalletSessionAuthorizationBoundary({
      source: {
        kind: 'ecdsa',
        laneIdentity: args.candidate.identity,
        authorization: args.candidate.authorization,
      },
      expiresAtMs: args.candidate.expiresAtMs,
      detectedAtMs: args.detectedAtMs,
    }),
  };
}

async function invalidateAuthoritativeEvmFamilyWalletSessionExpiry(args: {
  readonly context: EvmFamilyWalletSessionExpiryContext;
  readonly coordinator: SigningSessionCoordinator;
}): Promise<void> {
  switch (args.context.kind) {
    case 'not_expired':
    case 'expired_without_exact_lane':
      return;
    case 'authoritative_expiry': {
      const result = await args.coordinator.invalidateExpiredWalletSession({
        state: args.context.state,
        source: SIGNING_SESSION_EXPIRY_DETECTION_SOURCES.serverRejection,
      });
      if (result.kind === 'unavailable') {
        throw new Error('[SigningEngine][ecdsa] expired Wallet Session cleanup failed');
      }
      return;
    }
    default:
      return assertNeverEvmFamilyWalletSessionExpiryContext(args.context);
  }
}

function assertNeverEvmFamilyWalletSessionExpiryContext(value: never): never {
  throw new Error(
    `[SigningEngine][ecdsa] unsupported Wallet Session expiry context: ${String(value)}`,
  );
}

export async function retryEvmFamilyWithFreshWalletSessionAuthWhenRequired(args: {
  error: unknown;
  walletId: string;
  chain: EvmFamilyChain;
  senderSignatureAlgorithm: EvmFamilySenderSignatureAlgorithm;
  accountAuth: AccountAuthMetadata;
  alreadyRetryingFreshEmailOtpAuth?: boolean;
  hasEmailOtpSigningPlan?: boolean;
  sideEffectState: EvmFamilyFreshAuthRetrySideEffectState;
  signingSessionCoordinator: SigningSessionCoordinator;
  expiryContext: EvmFamilyWalletSessionExpiryContext;
  onDecision?: (decision: EvmFamilyFreshAuthRetryDecision) => void;
  onEvent?: EvmFamilyLifecycleEventCallback;
  retry: () => Promise<TempoSignedResult | EvmSignedResult>;
}): Promise<TempoSignedResult | EvmSignedResult | null> {
  const decision = classifyEvmFamilyFreshAuthRetry({
    trigger: 'wallet_session_reauthorization_required',
    error: args.error,
    senderSignatureAlgorithm: args.senderSignatureAlgorithm,
    accountAuth: args.accountAuth,
    alreadyRetryingFreshAuth: args.alreadyRetryingFreshEmailOtpAuth,
    hasEmailOtpSigningPlan: args.hasEmailOtpSigningPlan,
    sideEffectState: args.sideEffectState,
  });
  args.onDecision?.(decision);
  if (decision.kind !== 'retry') return null;

  await invalidateAuthoritativeEvmFamilyWalletSessionExpiry({
    context: args.expiryContext,
    coordinator: args.signingSessionCoordinator,
  });
  const emailOtp = args.accountAuth.primaryAuthMethod === SIGNER_AUTH_METHODS.emailOtp;
  emitEvmFamilySigningEvent(args.onEvent, {
    phase: emailOtp
      ? SigningEventPhase.STEP_06_AUTH_EMAIL_OTP_CHALLENGE_STARTED
      : SigningEventPhase.STEP_09_THRESHOLD_SESSION_RECONNECT_STARTED,
    status: 'running',
    walletId: args.walletId,
    message: emailOtp
      ? 'Signing session expired; requesting Email OTP reauthorization'
      : 'Signing session expired; requesting passkey reauthorization',
    interaction: { kind: 'none', overlay: 'none' },
    data: { chain: args.chain, reason: 'threshold_session_expired' },
  });
  return await args.retry();
}
