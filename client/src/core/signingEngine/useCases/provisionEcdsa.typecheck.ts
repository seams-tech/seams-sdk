import type {
  CredentialIdB64u,
  RelayerKeyId,
} from '@/core/platform';
import type {
  ThresholdEcdsaChainTarget,
  WalletId,
} from '../interfaces/ecdsaChainTarget';
import type { RpId } from '../session/identity/evmFamilyEcdsaIdentity';
import type {
  EcdsaThresholdKeyId,
  SigningRootId,
  SigningRootVersion,
} from '../session/identity/emailOtpHssIdentity';
import type {
  ProvisionEcdsaEmailOtpHandle,
  ProvisionEcdsaInput,
  ProvisionEcdsaRouteFacts,
  ProvisionEcdsaSuccess,
} from './provisionEcdsa';

declare const walletId: WalletId;
declare const rpId: RpId;
declare const chainTarget: ThresholdEcdsaChainTarget;
declare const credentialIdB64u: CredentialIdB64u;
declare const emailOtpHandle: ProvisionEcdsaEmailOtpHandle;
declare const ecdsaThresholdKeyId: EcdsaThresholdKeyId;
declare const signingRootId: SigningRootId;
declare const signingRootVersion: SigningRootVersion;
declare const relayerKeyId: RelayerKeyId;

const routeFacts = {
  relayerKeyId,
  requestId: 'request',
  sessionId: 'threshold-session',
  walletSigningSessionId: 'wallet-signing-session',
  ttlMs: 60_000,
  remainingUses: 8,
  sessionKind: 'jwt',
  auth: { kind: 'publishable_key', token: 'pk_test' },
} satisfies ProvisionEcdsaRouteFacts;

const validPasskeyInput = {
  walletId,
  rpId,
  chainTarget,
  keyHandle: 'ecdsa-key-handle',
  ecdsaThresholdKeyId,
  signingRootId,
  signingRootVersion,
  participantIds: [1, 2],
  authMethod: {
    kind: 'passkey',
    credentialIdB64u,
    challengeB64u: 'challenge',
  },
  route: routeFacts,
} satisfies ProvisionEcdsaInput;
void validPasskeyInput;

const passkeyInputWithEmailHandle = {
  walletId,
  rpId,
  chainTarget,
  keyHandle: 'ecdsa-key-handle',
  ecdsaThresholdKeyId,
  signingRootId,
  signingRootVersion,
  participantIds: [1, 2],
  authMethod: {
    kind: 'passkey',
    credentialIdB64u,
    challengeB64u: 'challenge',
    handle: emailOtpHandle,
  },
  route: routeFacts,
};
// @ts-expect-error passkey provisioning cannot carry Email OTP handles
passkeyInputWithEmailHandle satisfies ProvisionEcdsaInput;

const emailOtpInputWithChallenge = {
  walletId,
  rpId,
  chainTarget,
  keyHandle: 'ecdsa-key-handle',
  ecdsaThresholdKeyId,
  signingRootId,
  signingRootVersion,
  participantIds: [1, 2],
  authMethod: {
    kind: 'email_otp',
    handle: emailOtpHandle,
    challengeB64u: 'challenge',
  },
  route: routeFacts,
};
// @ts-expect-error Email OTP provisioning cannot carry passkey challenge material
emailOtpInputWithChallenge satisfies ProvisionEcdsaInput;

const inputWithoutKeyHandle = {
  walletId,
  rpId,
  chainTarget,
  ecdsaThresholdKeyId,
  signingRootId,
  signingRootVersion,
  participantIds: [1, 2],
  authMethod: {
    kind: 'email_otp',
    handle: emailOtpHandle,
  },
  route: routeFacts,
};
// @ts-expect-error ECDSA provisioning storage lookup requires keyHandle
inputWithoutKeyHandle satisfies ProvisionEcdsaInput;

const routeFactsWithoutAuth = {
  relayerKeyId,
  requestId: 'request',
  sessionId: 'threshold-session',
  walletSigningSessionId: 'wallet-signing-session',
  ttlMs: 60_000,
  remainingUses: 8,
  sessionKind: 'jwt',
};
// @ts-expect-error relayer bootstrap requires explicit route auth facts
routeFactsWithoutAuth satisfies ProvisionEcdsaRouteFacts;

const successWithoutRecord = {
  ok: true,
};
// @ts-expect-error ProvisionEcdsa success must carry the ready record
successWithoutRecord satisfies ProvisionEcdsaSuccess;
