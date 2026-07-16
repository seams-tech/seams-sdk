import {
  thresholdEcdsaChainTargetFromChainFamily,
  toWalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  buildSessionBootstrapKeyContext,
  buildEvmFamilyEcdsaSessionLanePolicy,
} from './evmFamilyEcdsaIdentity';
import {
  THRESHOLD_ECDSA_SESSION_POLICY_VERSION,
  type EcdsaDerivationSessionPolicy,
} from '../../threshold/sessionPolicy';
import { deriveEvmFamilySigningKeySlotId } from '@shared/signing-lanes';
import {
  toEcdsaDerivationThresholdKeyId,
  toEcdsaDerivationThresholdSessionId,
  toEcdsaDerivationSigningGrantId,
  toEmailOtpAuthSubjectId,
  toWalletSessionUserId,
  type EmailOtpExistingKeyBootstrap,
  type EmailOtpRegistrationBootstrap,
  type EmailOtpAuthSubjectId,
  type SessionBootstrap,
  type WalletSessionUserId,
} from './emailOtpEcdsaDerivationIdentity';

const chainTarget = thresholdEcdsaChainTargetFromChainFamily({
  chain: 'evm',
  chainId: 11155111,
});
const walletSessionUserId = toWalletSessionUserId('wallet.testnet');
const walletId = toWalletId('wallet.testnet');
const authSubjectId = toEmailOtpAuthSubjectId('google:subject-1');
const ecdsaThresholdKeyId = toEcdsaDerivationThresholdKeyId('ecdsa-key-1');
const sessionId = toEcdsaDerivationThresholdSessionId('threshold-session-1');
const signingGrantId = toEcdsaDerivationSigningGrantId('signing-grant-1');
const evmFamilySigningKeySlotId = deriveEvmFamilySigningKeySlotId({
  walletId,
  signingRootId: 'project:dev',
  signingRootVersion: 'default',
});
const keyContext = buildSessionBootstrapKeyContext({
  walletId: walletSessionUserId,
  evmFamilySigningKeySlotId,
  participantIds: [1, 2],
});
const lanePolicy = buildEvmFamilyEcdsaSessionLanePolicy({
  chainTarget,
  thresholdSessionId: sessionId,
  signingGrantId,
  thresholdSessionKind: 'jwt',
  ttlMs: 60_000,
  remainingUses: 1,
});

void ({
  version: THRESHOLD_ECDSA_SESSION_POLICY_VERSION,
  walletId,
  evmFamilySigningKeySlotId,
  chainTarget,
  ecdsaThresholdKeyId,
  sessionId,
  signingGrantId,
  participantIds: [1, 2],
  ttlMs: 60_000,
  remainingUses: 1,
} satisfies EcdsaDerivationSessionPolicy);

// @ts-expect-error provider-scoped Email OTP subjects cannot become wallet-scoped DERIVATION ids
const invalidWalletSessionUserId: WalletSessionUserId = authSubjectId;

// @ts-expect-error wallet-scoped DERIVATION ids cannot become provider auth subjects
const invalidAuthSubjectId: EmailOtpAuthSubjectId = walletSessionUserId;

void invalidWalletSessionUserId;
void invalidAuthSubjectId;

void ({
  version: THRESHOLD_ECDSA_SESSION_POLICY_VERSION,
  // @ts-expect-error raw strings must be normalized to WalletSessionUserId first
  walletId: 'wallet.testnet',
  evmFamilySigningKeySlotId,
  chainTarget,
  ecdsaThresholdKeyId,
  sessionId,
  signingGrantId,
  ttlMs: 60_000,
  remainingUses: 1,
} satisfies EcdsaDerivationSessionPolicy);

void ({
  version: THRESHOLD_ECDSA_SESSION_POLICY_VERSION,
  walletId,
  evmFamilySigningKeySlotId,
  chainTarget,
  // @ts-expect-error raw key ids must be normalized to EcdsaThresholdKeyId first
  ecdsaThresholdKeyId: 'ecdsa-key-1',
  sessionId,
  signingGrantId,
  ttlMs: 60_000,
  remainingUses: 1,
} satisfies EcdsaDerivationSessionPolicy);

void ({
  operation: 'email_otp_bootstrap',
} satisfies EmailOtpRegistrationBootstrap);

void ({
  operation: 'email_otp_bootstrap',
  keyHandle: 'ederivation-key-handle-1',
} satisfies EmailOtpExistingKeyBootstrap);

void ({
  operation: 'session_bootstrap',
  keyHandle: 'ederivation-key-handle-1',
  keyContext,
  lanePolicy,
} satisfies SessionBootstrap);

void ({
  operation: 'email_otp_bootstrap',
  // @ts-expect-error registration bootstrap must not carry a preexisting ECDSA key id
  ecdsaThresholdKeyId,
} satisfies EmailOtpRegistrationBootstrap);

void ({
  operation: 'email_otp_bootstrap',
  // @ts-expect-error existing-key bootstrap must carry keyHandle
} satisfies EmailOtpExistingKeyBootstrap);

void ({
  operation: 'email_otp_bootstrap',
  // @ts-expect-error existing-key bootstrap rejects scattered threshold-key identity
  ecdsaThresholdKeyId,
  keyHandle: 'ederivation-key-handle-1',
} satisfies EmailOtpExistingKeyBootstrap);

void ({
  operation: 'session_bootstrap',
  keyContext,
  // @ts-expect-error session bootstrap requires a concrete lane policy
} satisfies SessionBootstrap);

void ({
  operation: 'session_bootstrap',
  keyHandle: 'ederivation-key-handle-1',
  keyContext,
  lanePolicy,
  // @ts-expect-error session bootstrap rejects top-level threshold-key identifiers
  ecdsaThresholdKeyId,
} satisfies SessionBootstrap);

void ({
  operation: 'session_bootstrap',
  keyContext,
  lanePolicy,
  // @ts-expect-error session bootstrap requires keyHandle at the boundary.
} satisfies SessionBootstrap);

export {};
