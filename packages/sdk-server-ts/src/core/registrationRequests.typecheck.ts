import type {
  CreateAddSignerIntentRequest,
  CreateRegistrationIntentRequest,
  WalletAddAuthMethodStartRequest,
  WalletRegistrationStartRequest,
} from './types';
import {
  addAuthMethodIntentGrantFromString,
  implicitNearAccountProvisioning,
  registrationIntentGrantFromString,
  walletIdFromString,
  type AddAuthMethodIntentV1,
  type EmailOtpRegistrationProof,
  type RegistrationIntentV1,
} from '@shared/utils/registrationIntent';

const registrationIntent = {
  version: 'registration_intent_v1',
  walletId: walletIdFromString('wallet_alice'),
  rpId: 'wallet.example.test',
  authMethod: {
    kind: 'passkey',
  },
  signerSelection: {
    mode: 'ed25519_only',
    ed25519: {
      accountProvisioning: implicitNearAccountProvisioning(),
      signerSlot: 1,
      participantIds: [1, 2],
      keyPurpose: 'near_tx',
      keyVersion: 'threshold-ed25519-hss-v1',
      derivationVersion: 1,
    },
  },
  nonceB64u: 'nonce',
} satisfies RegistrationIntentV1;

const addAuthMethodIntent = {
  version: 'add_auth_method_intent_v1',
  walletId: walletIdFromString('wallet_alice'),
  rpId: 'wallet.example.test',
  authMethod: {
    kind: 'passkey',
  },
  nonceB64u: 'nonce',
} satisfies AddAuthMethodIntentV1;

const mixedAuthoritySpread = {
  emailOtpRegistrationProof: {
    version: 'email_otp_registration_proof_v1' as const,
    providerSubject: 'google:alice',
    email: 'alice@example.test',
    challengeId: 'challenge-1',
    otpCode: '123456',
    otpChannel: 'email_otp' as const,
    registrationIntentDigestB64u: 'digest',
    appSessionVersion: 'v1',
  },
};

const passkeyAuthoritySpread = {
  kind: 'passkey' as const,
  webauthnRegistration: { id: 'new-passkey-registration' },
  ...mixedAuthoritySpread,
};

const rawRegistrationIntentBody = {
  walletId: 'wallet_alice',
  rpId: 'wallet.example.test',
  authMethod: {
    kind: 'passkey' as const,
  },
  signerSelection: {
    mode: 'ed25519_only' as const,
  },
};

const rawAddSignerIntentBody = {
  walletId: 'wallet_alice',
  rpId: 'wallet.example.test',
  signerSelection: {
    mode: 'ed25519_only' as const,
  },
};

// @ts-expect-error Email OTP proofs must identify the provider subject that owns the OTP.
const invalidEmailOtpRegistrationProof: EmailOtpRegistrationProof = {
  version: 'email_otp_registration_proof_v1',
  email: 'alice@example.test',
  challengeId: 'challenge-1',
  otpCode: '123456',
  otpChannel: 'email_otp',
  registrationIntentDigestB64u: 'digest',
  appSessionVersion: 'v1',
};
void invalidEmailOtpRegistrationProof;

const invalidRegistrationStart: WalletRegistrationStartRequest = {
  registrationIntentGrant: registrationIntentGrantFromString('rig_1'),
  registrationIntentDigestB64u: 'digest',
  intent: registrationIntent,
  // @ts-expect-error registration start authority must stay branch-specific after broad spreads.
  authority: passkeyAuthoritySpread,
};
void invalidRegistrationStart;

const invalidAddAuthMethodStart: WalletAddAuthMethodStartRequest = {
  walletId: walletIdFromString('wallet_alice'),
  addAuthMethodIntentGrant: addAuthMethodIntentGrantFromString('waig_1'),
  addAuthMethodIntentDigestB64u: 'digest',
  intent: addAuthMethodIntent,
  auth: {
    kind: 'app_session',
    policy: {
      permission: 'wallet_auth_method_provision',
      walletId: walletIdFromString('wallet_alice'),
      authMethod: { kind: 'passkey' },
      expiresAtMs: 1,
    },
  },
  // @ts-expect-error add-auth-method start authority must stay branch-specific after broad spreads.
  authority: passkeyAuthoritySpread,
};
void invalidAddAuthMethodStart;

// @ts-expect-error raw route bodies must be normalized before createRegistrationIntent.
const invalidCreateRegistrationIntentRequest: CreateRegistrationIntentRequest =
  rawRegistrationIntentBody;
void invalidCreateRegistrationIntentRequest;

// @ts-expect-error raw route bodies must be normalized before createAddSignerIntent.
const invalidCreateAddSignerIntentRequest: CreateAddSignerIntentRequest = rawAddSignerIntentBody;
void invalidCreateAddSignerIntentRequest;

export {};
