import { thresholdEcdsaChainTargetFromChainFamily } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  buildEvmFamilyEcdsaKeyIdentity,
  buildEvmFamilyEcdsaSessionLanePolicy,
} from './evmFamilyEcdsaIdentity';
import {
  THRESHOLD_SESSION_POLICY_VERSION,
  type EcdsaHssSessionPolicy,
} from '../../threshold/sessionPolicy';
import {
  toEcdsaHssThresholdKeyId,
  toEcdsaHssThresholdSessionId,
  toEcdsaHssWalletSigningSessionId,
  toEcdsaHssWalletSubjectId,
  toEmailOtpAuthSubjectId,
  toWalletSessionUserId,
  type EmailOtpExistingKeyBootstrap,
  type EmailOtpRegistrationBootstrap,
  type EmailOtpAuthSubjectId,
  type SessionBootstrap,
  type WalletSessionUserId,
} from './emailOtpHssIdentity';

const chainTarget = thresholdEcdsaChainTargetFromChainFamily({
  chain: 'evm',
  chainId: 11155111,
});
const walletSessionUserId = toWalletSessionUserId('wallet.testnet');
const authSubjectId = toEmailOtpAuthSubjectId('google:subject-1');
const subjectId = toEcdsaHssWalletSubjectId('wallet.testnet');
const ecdsaThresholdKeyId = toEcdsaHssThresholdKeyId('ecdsa-key-1');
const sessionId = toEcdsaHssThresholdSessionId('threshold-session-1');
const walletSigningSessionId = toEcdsaHssWalletSigningSessionId('wallet-signing-session-1');
const key = buildEvmFamilyEcdsaKeyIdentity({
  walletId: walletSessionUserId,
  subjectId,
  rpId: 'wallet.example.test',
  ecdsaThresholdKeyId,
  signingRootId: 'signing-root-1',
  signingRootVersion: 'default',
  participantIds: [1, 2],
  thresholdOwnerAddress: '0x1111111111111111111111111111111111111111',
});
const lanePolicy = buildEvmFamilyEcdsaSessionLanePolicy({
  chainTarget,
  thresholdSessionId: sessionId,
  walletSigningSessionId,
  thresholdSessionKind: 'jwt',
  ttlMs: 60_000,
  remainingUses: 1,
});

void ({
  version: THRESHOLD_SESSION_POLICY_VERSION,
  walletSessionUserId,
  subjectId,
  rpId: 'wallet.example.test',
  chainTarget,
  ecdsaThresholdKeyId,
  sessionId,
  walletSigningSessionId,
  participantIds: [1, 2],
  ttlMs: 60_000,
  remainingUses: 1,
} satisfies EcdsaHssSessionPolicy);

// @ts-expect-error provider-scoped Email OTP subjects cannot become wallet-scoped HSS ids
const invalidWalletSessionUserId: WalletSessionUserId = authSubjectId;

// @ts-expect-error wallet-scoped HSS ids cannot become provider auth subjects
const invalidAuthSubjectId: EmailOtpAuthSubjectId = walletSessionUserId;

void invalidWalletSessionUserId;
void invalidAuthSubjectId;

void ({
  version: THRESHOLD_SESSION_POLICY_VERSION,
  // @ts-expect-error raw strings must be normalized to WalletSessionUserId first
  walletSessionUserId: 'wallet.testnet',
  subjectId,
  rpId: 'wallet.example.test',
  chainTarget,
  ecdsaThresholdKeyId,
  sessionId,
  walletSigningSessionId,
  ttlMs: 60_000,
  remainingUses: 1,
} satisfies EcdsaHssSessionPolicy);

void ({
  version: THRESHOLD_SESSION_POLICY_VERSION,
  walletSessionUserId,
  subjectId,
  rpId: 'wallet.example.test',
  chainTarget,
  // @ts-expect-error raw key ids must be normalized to EcdsaThresholdKeyId first
  ecdsaThresholdKeyId: 'ecdsa-key-1',
  sessionId,
  walletSigningSessionId,
  ttlMs: 60_000,
  remainingUses: 1,
} satisfies EcdsaHssSessionPolicy);

void ({
  operation: 'email_otp_bootstrap',
} satisfies EmailOtpRegistrationBootstrap);

void ({
  operation: 'email_otp_bootstrap',
  ecdsaThresholdKeyId,
} satisfies EmailOtpExistingKeyBootstrap);

void ({
  operation: 'session_bootstrap',
  key,
  lanePolicy,
} satisfies SessionBootstrap);

void ({
  operation: 'email_otp_bootstrap',
  // @ts-expect-error registration bootstrap must not carry a preexisting ECDSA key id
  ecdsaThresholdKeyId,
} satisfies EmailOtpRegistrationBootstrap);

void ({
  operation: 'email_otp_bootstrap',
  // @ts-expect-error existing-key bootstrap must carry an ECDSA key id
} satisfies EmailOtpExistingKeyBootstrap);

void ({
  operation: 'session_bootstrap',
  key,
  // @ts-expect-error session bootstrap requires a concrete lane policy
} satisfies SessionBootstrap);

void ({
  operation: 'session_bootstrap',
  key,
  lanePolicy,
  // @ts-expect-error session bootstrap derives key id from canonical key identity
  ecdsaThresholdKeyId,
} satisfies SessionBootstrap);

export {};
