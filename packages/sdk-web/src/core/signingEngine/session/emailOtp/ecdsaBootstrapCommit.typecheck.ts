import type {
  ThresholdEcdsaChainTarget,
  WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdEcdsaSessionBootstrapResult } from '@/core/signingEngine/threshold/ecdsa/activation';
import type { EmailOtpEcdsaSessionPorts } from './ports';

declare const walletId: WalletId;
declare const chainTarget: ThresholdEcdsaChainTarget;
declare const bootstrap: ThresholdEcdsaSessionBootstrapResult;
declare const ports: EmailOtpEcdsaSessionPorts;

void ports.commitEvmFamilyThresholdEcdsaSessions({
  walletId,
  chainTarget,
  bootstrap,
  source: 'email_otp',
  emailOtpAuthContext: {
    policy: 'session',
    retention: 'session',
    reason: 'login',
    authMethod: 'email_otp',
  },
});

void ports.commitEvmFamilyThresholdEcdsaSessions({
  // @ts-expect-error Email OTP ECDSA bootstrap commit requires WalletId.
  walletId: 'alice.testnet',
  chainTarget,
  bootstrap,
  source: 'email_otp',
  emailOtpAuthContext: {
    policy: 'session',
    retention: 'session',
    reason: 'login',
    authMethod: 'email_otp',
  },
});

export {};
