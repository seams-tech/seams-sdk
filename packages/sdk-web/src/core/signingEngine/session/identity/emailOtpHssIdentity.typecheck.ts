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
  type EcdsaHssSessionPolicy,
} from '../../threshold/sessionPolicy';
import { parseWalletKeyId } from '@shared/signing-lanes';
import {
  toEcdsaHssThresholdKeyId,
  toEcdsaHssThresholdSessionId,
  toEcdsaHssSigningGrantId,
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
const walletId = toWalletId('wallet.testnet');
const authSubjectId = toEmailOtpAuthSubjectId('google:subject-1');
const ecdsaThresholdKeyId = toEcdsaHssThresholdKeyId('ecdsa-key-1');
const sessionId = toEcdsaHssThresholdSessionId('threshold-session-1');
const signingGrantId = toEcdsaHssSigningGrantId('signing-grant-1');
const walletKeyIdResult = parseWalletKeyId('wallet-key-example-test');
if (!walletKeyIdResult.ok) throw new Error(walletKeyIdResult.error.message);
const walletKeyId = walletKeyIdResult.value;
const keyContext = buildSessionBootstrapKeyContext({
  walletId: walletSessionUserId,
  walletKeyId,
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
  walletKeyId,
  chainTarget,
  ecdsaThresholdKeyId,
  sessionId,
  signingGrantId,
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
  version: THRESHOLD_ECDSA_SESSION_POLICY_VERSION,
  // @ts-expect-error raw strings must be normalized to WalletSessionUserId first
  walletId: 'wallet.testnet',
  walletKeyId,
  chainTarget,
  ecdsaThresholdKeyId,
  sessionId,
  signingGrantId,
  ttlMs: 60_000,
  remainingUses: 1,
} satisfies EcdsaHssSessionPolicy);

void ({
  version: THRESHOLD_ECDSA_SESSION_POLICY_VERSION,
  walletId,
  walletKeyId,
  chainTarget,
  // @ts-expect-error raw key ids must be normalized to EcdsaThresholdKeyId first
  ecdsaThresholdKeyId: 'ecdsa-key-1',
  sessionId,
  signingGrantId,
  ttlMs: 60_000,
  remainingUses: 1,
} satisfies EcdsaHssSessionPolicy);

void ({
  operation: 'email_otp_bootstrap',
} satisfies EmailOtpRegistrationBootstrap);

void ({
  operation: 'email_otp_bootstrap',
  keyHandle: 'ehss-key-handle-1',
} satisfies EmailOtpExistingKeyBootstrap);

void ({
  operation: 'session_bootstrap',
  keyHandle: 'ehss-key-handle-1',
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
  keyHandle: 'ehss-key-handle-1',
} satisfies EmailOtpExistingKeyBootstrap);

void ({
  operation: 'session_bootstrap',
  keyContext,
  // @ts-expect-error session bootstrap requires a concrete lane policy
} satisfies SessionBootstrap);

void ({
  operation: 'session_bootstrap',
  keyHandle: 'ehss-key-handle-1',
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
