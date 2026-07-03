import type {
  ThresholdEcdsaChainTarget,
  WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdEcdsaSessionBootstrapResult } from '@/core/signingEngine/threshold/ecdsa/activation';
import type { EmailOtpEcdsaSessionPorts } from './ports';
import { buildEmailOtpAuthContextForWalletAuthMethod } from '../identity/laneIdentity';

declare const walletId: WalletId;
declare const chainTarget: ThresholdEcdsaChainTarget;
declare const bootstrap: ThresholdEcdsaSessionBootstrapResult;
declare const ports: EmailOtpEcdsaSessionPorts;

const emailOtpAuthContext = buildEmailOtpAuthContextForWalletAuthMethod({
walletId: 'wallet.testnet',
emailHashHex: 'email-hash',
policy: 'session',
  retention: 'session',
  reason: 'login',
  provider: 'google',
  providerUserId: 'google-subject-1',
});

void ports.commitEvmFamilyThresholdEcdsaSessions({
  walletId,
  chainTarget,
  bootstrap,
  source: 'email_otp',
  emailOtpAuthContext,
});

void ports.commitEvmFamilyThresholdEcdsaSessions({
  // @ts-expect-error Email OTP ECDSA bootstrap commit requires WalletId.
  walletId: 'alice.testnet',
  chainTarget,
  bootstrap,
  source: 'email_otp',
  emailOtpAuthContext,
});

export {};
