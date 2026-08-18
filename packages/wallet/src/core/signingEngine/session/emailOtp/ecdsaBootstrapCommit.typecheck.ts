import type {
  ThresholdEcdsaChainTarget,
  WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdEcdsaSessionBootstrapResult } from '@/core/signingEngine/threshold/ecdsa/activation';
import type { EmailOtpEcdsaSessionPorts } from './ports';
import { buildEmailOtpAuthContextForWalletAuthMethod } from '../identity/laneIdentity';
import type { WalletAuthAuthorityRef } from '@shared/utils/walletAuthAuthority';

declare const walletId: WalletId;
declare const chainTarget: ThresholdEcdsaChainTarget;
declare const bootstrap: ThresholdEcdsaSessionBootstrapResult;
declare const authority: WalletAuthAuthorityRef;
declare const ports: EmailOtpEcdsaSessionPorts;

void bootstrap.session.runtimePolicyScope.projectId;
void bootstrap.session.walletSessionToken.trim();
void bootstrap.session.clientVerifyingShareB64u.trim();
void bootstrap.thresholdEcdsaKeyRef.keyHandle.trim();
void bootstrap.thresholdEcdsaKeyRef.participantIds.map(Number);
// @ts-expect-error The exact bootstrap session has no legacy session alias.
void bootstrap.session.sessionId;
// @ts-expect-error Client budget projection state is not bootstrap material state.
void bootstrap.session.projectionVersion;
// @ts-expect-error Exact material facts have one owner on the bootstrap key reference.
void bootstrap.keygen;

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
  authority,
  emailOtpAuthContext,
});

// @ts-expect-error Email OTP ECDSA bootstrap commit requires canonical authority.
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
  authority,
  emailOtpAuthContext,
});

export {};
