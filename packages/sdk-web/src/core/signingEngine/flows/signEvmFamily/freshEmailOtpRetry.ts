import type { AccountAuthMetadata } from '@/core/signingEngine/interfaces/accountAuthMetadata';
import { SigningEventPhase } from '@/core/types/sdkSentEvents';
import type { EvmSignedResult } from '../../chains/evm/evmAdapter';
import type { TempoSignedResult } from '../../chains/tempo/tempoAdapter';
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

export async function retryEvmFamilyWithFreshEmailOtpAuthWhenRequired(args: {
  error: unknown;
  walletId: string;
  chain: EvmFamilyChain;
  senderSignatureAlgorithm: EvmFamilySenderSignatureAlgorithm;
  accountAuth: AccountAuthMetadata;
  alreadyRetryingFreshEmailOtpAuth?: boolean;
  hasEmailOtpSigningPlan?: boolean;
  sideEffectState: EvmFamilyFreshAuthRetrySideEffectState;
  onDecision?: (decision: EvmFamilyFreshAuthRetryDecision) => void;
  onEvent?: EvmFamilyLifecycleEventCallback;
  retry: () => Promise<TempoSignedResult | EvmSignedResult>;
}): Promise<TempoSignedResult | EvmSignedResult | null> {
  const decision = classifyEvmFamilyFreshAuthRetry({
    trigger: 'email_otp_auth_unavailable',
    error: args.error,
    senderSignatureAlgorithm: args.senderSignatureAlgorithm,
    accountAuth: args.accountAuth,
    alreadyRetryingFreshAuth: args.alreadyRetryingFreshEmailOtpAuth,
    hasEmailOtpSigningPlan: args.hasEmailOtpSigningPlan,
    sideEffectState: args.sideEffectState,
  });
  args.onDecision?.(decision);
  if (decision.kind !== 'retry') return null;

  emitEvmFamilySigningEvent(args.onEvent, {
    phase: SigningEventPhase.STEP_06_AUTH_EMAIL_OTP_CHALLENGE_STARTED,
    status: 'running',
    walletId: args.walletId,
    message: 'Signing session expired; requesting Email OTP reauthorization',
    interaction: { kind: 'none', overlay: 'none' },
    data: { chain: args.chain, reason: 'threshold_session_expired' },
  });
  return await args.retry();
}
