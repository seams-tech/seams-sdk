import type { AccountAuthMetadata } from '@/core/signingEngine/auth';
import { SigningEventPhase } from '@/core/types/sdkSentEvents';
import { SIGNER_AUTH_METHODS } from '@shared/utils/signerDomain';
import type { EvmSignedResult } from '../../chainAdaptors/evm/evmAdapter';
import type { TempoSignedResult } from '../../chainAdaptors/tempo/tempoAdapter';
import { isThresholdSessionAuthUnavailableError } from '../../threshold/session/sessionPolicy';
import { isFreshEmailOtpReauthRequiredError } from './errors';
import { emitEvmFamilySigningEvent } from './events';
import type {
  EvmFamilyChain,
  EvmFamilyLifecycleEventCallback,
  EvmFamilySenderSignatureAlgorithm,
} from './types';

export async function retryEvmFamilyWithFreshEmailOtpAuthWhenRequired(args: {
  error: unknown;
  nearAccountId: string;
  chain: EvmFamilyChain;
  senderSignatureAlgorithm: EvmFamilySenderSignatureAlgorithm;
  accountAuth: AccountAuthMetadata;
  alreadyRetryingFreshEmailOtpAuth?: boolean;
  hasEmailOtpSigningPlan?: boolean;
  onEvent?: EvmFamilyLifecycleEventCallback;
  retry: () => Promise<TempoSignedResult | EvmSignedResult>;
}): Promise<TempoSignedResult | EvmSignedResult | null> {
  if (args.alreadyRetryingFreshEmailOtpAuth || args.hasEmailOtpSigningPlan) return null;
  if (args.senderSignatureAlgorithm !== 'secp256k1') return null;
  if (
    !isThresholdSessionAuthUnavailableError(args.error) &&
    !isFreshEmailOtpReauthRequiredError(args.error)
  ) {
    return null;
  }
  if (args.accountAuth.primaryAuthMethod !== SIGNER_AUTH_METHODS.emailOtp) return null;

  emitEvmFamilySigningEvent(args.onEvent, {
    phase: SigningEventPhase.STEP_06_AUTH_EMAIL_OTP_CHALLENGE_STARTED,
    status: 'running',
    accountId: args.nearAccountId,
    message: 'Signing session expired; requesting Email OTP reauthorization',
    interaction: { kind: 'none', overlay: 'none' },
    data: { chain: args.chain, reason: 'threshold_session_expired' },
  });
  return await args.retry();
}
