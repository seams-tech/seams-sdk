import type {
  CreateAddAuthMethodIntentRequest,
  CreateAddSignerIntentRequest,
  CreateRegistrationIntentRequest,
  WalletAddAuthMethodStartRequest,
  WalletRegistrationEcdsaPreparePayload,
  WalletRegistrationFinalizeRequest,
  WalletRegistrationFinalizeResponse,
  WalletRegistrationStartResponse,
  WalletRegistrationStartRequest,
} from './registrationContracts';
import {
  addAuthMethodIntentGrantFromString,
  implicitNearAccountProvisioning,
  registrationIntentGrantFromString,
  walletIdFromString,
  type AddAuthMethodIntentV1,
  type EmailOtpRegistrationProof,
  type RegistrationIntentV1,
} from '@shared/utils/registrationIntent';
import { parseWebAuthnRpId } from '@shared/utils/domainIds';

function unwrapDomainId<T>(result: { ok: true; value: T } | { ok: false }): T {
  if (!result.ok) throw new Error('invalid type fixture domain id');
  return result.value;
}

const webAuthnRpId = unwrapDomainId(parseWebAuthnRpId('wallet.example.test'));

const registrationIntent = {
  version: 'registration_intent_v1',
  walletId: walletIdFromString('wallet_alice'),
  authMethod: {
    kind: 'passkey',
    rpId: webAuthnRpId,
  },
  signerSelection: {
    kind: 'signer_set',
    signers: [
      {
        kind: 'near_ed25519',
        accountProvisioning: implicitNearAccountProvisioning(),
        signerSlot: 1,
        participantIds: [1, 2],
        derivationVersion: 1,
      },
    ],
  },
  nonceB64u: 'nonce',
} satisfies RegistrationIntentV1;

const addAuthMethodIntent = {
  version: 'add_auth_method_intent_v1',
  walletId: walletIdFromString('wallet_alice'),
  authMethod: {
    kind: 'passkey',
    rpId: webAuthnRpId,
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
    kind: 'signer_set' as const,
    signers: [] as const,
  },
};

const rawAddSignerIntentBody = {
  walletId: 'wallet_alice',
  rpId: 'wallet.example.test',
  signerSelection: {
    mode: 'ed25519' as const,
  },
};

const rawAddAuthMethodIntentBody = {
  walletId: 'wallet_alice',
  rpId: 'wallet.example.test',
  authMethod: {
    kind: 'passkey' as const,
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
      authMethod: { kind: 'passkey', rpId: webAuthnRpId },
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

// @ts-expect-error raw route bodies must be normalized before createAddAuthMethodIntent.
const invalidCreateAddAuthMethodIntentRequest: CreateAddAuthMethodIntentRequest =
  rawAddAuthMethodIntentBody;
void invalidCreateAddAuthMethodIntentRequest;

declare const ecdsaPrepare: WalletRegistrationEcdsaPreparePayload;

const yaoAdmissionRequest = {
  scope: {
    lifecycle_id: 'registration-lifecycle',
    root_share_epoch: 'root-epoch-1',
    account_id: 'alice.testnet',
    wallet_session_id: 'wallet-session-1',
    signer_set_id: 'signer-set-1',
    signing_worker_id: 'signing-worker-1',
  },
  application_binding: {
    wallet_id: 'wallet_alice',
    near_ed25519_signing_key_id: 'near-key-1',
    signing_root_id: 'signing-root-1',
    key_creation_signer_slot: 1,
  },
  participant_ids: [1, 2] as const,
};

const validEd25519StartResponse = {
  ok: true,
  kind: 'near_ed25519',
  registrationCeremonyId: 'registration-ceremony-1',
  intent: registrationIntent,
  ed25519: { admissionRequest: yaoAdmissionRequest },
} satisfies WalletRegistrationStartResponse;
void validEd25519StartResponse;

const validMixedStartResponse = {
  ok: true,
  kind: 'near_ed25519_and_evm_family_ecdsa',
  registrationCeremonyId: 'registration-ceremony-2',
  intent: registrationIntent,
  ed25519: { admissionRequest: yaoAdmissionRequest },
  ecdsa: ecdsaPrepare,
} satisfies WalletRegistrationStartResponse;
void validMixedStartResponse;

const invalidEd25519StartWithEcdsa: WalletRegistrationStartResponse = {
  ok: true,
  kind: 'near_ed25519',
  registrationCeremonyId: 'registration-ceremony-invalid',
  intent: registrationIntent,
  ed25519: { admissionRequest: yaoAdmissionRequest },
  // @ts-expect-error near_ed25519 start cannot carry ECDSA preparation work.
  ecdsa: ecdsaPrepare,
};
void invalidEd25519StartWithEcdsa;

const invalidStartResponseWithoutSignerWork = {
  ok: true,
  registrationCeremonyId: 'registration-ceremony-3',
  intent: registrationIntent,
  // @ts-expect-error successful registration start must carry Ed25519 or ECDSA work.
} satisfies WalletRegistrationStartResponse;
void invalidStartResponseWithoutSignerWork;

const validEd25519FinalizeRequest = {
  registrationCeremonyId: 'registration-ceremony-1',
  kind: 'near_ed25519',
  ed25519: {
    activationReference: {
      kind: 'router_ab_ed25519_yao_activation_reference_v1',
      lifecycle_id: 'registration-lifecycle',
      session_id: Array.from({ length: 32 }, () => 1),
    },
  },
} satisfies WalletRegistrationFinalizeRequest;
void validEd25519FinalizeRequest;

const invalidEd25519FinalizeWithEcdsa: WalletRegistrationFinalizeRequest = {
  registrationCeremonyId: 'registration-ceremony-1',
  kind: 'near_ed25519' as const,
  ed25519: validEd25519FinalizeRequest.ed25519,
  // @ts-expect-error near_ed25519 finalize must not carry ECDSA work.
  ecdsa: {},
};
void invalidEd25519FinalizeWithEcdsa;

const invalidEd25519FinalizeWithoutActivation = {
  registrationCeremonyId: 'registration-ceremony-1',
  kind: 'near_ed25519' as const,
  // @ts-expect-error Ed25519 finalize requires an opaque activation reference.
  ed25519: {},
} satisfies WalletRegistrationFinalizeRequest;
void invalidEd25519FinalizeWithoutActivation;

declare const validEd25519FinalizeSuccess: Extract<
  WalletRegistrationFinalizeResponse,
  { ok: true; kind: 'near_ed25519' }
>;
declare const validEcdsaFinalizeSuccess: Extract<
  WalletRegistrationFinalizeResponse,
  { ok: true; kind: 'evm_family_ecdsa' }
>;

// @ts-expect-error Ed25519-only success cannot carry ECDSA wallet keys.
const invalidEd25519FinalizeSuccessWithEcdsa: WalletRegistrationFinalizeResponse = {
  ...validEd25519FinalizeSuccess,
  ecdsa: validEcdsaFinalizeSuccess.ecdsa,
};
void invalidEd25519FinalizeSuccessWithEcdsa;

const invalidEd25519SessionWithoutJwt = {
  ...validEd25519FinalizeSuccess.ed25519.session,
  // @ts-expect-error an activated Ed25519 signing session requires its Wallet Session JWT.
  walletSessionJwt: undefined,
} satisfies typeof validEd25519FinalizeSuccess.ed25519.session;
void invalidEd25519SessionWithoutJwt;

// @ts-expect-error ECDSA-only success cannot carry a NEAR account provisioning identity.
const invalidEcdsaFinalizeSuccessWithNearIdentity: WalletRegistrationFinalizeResponse = {
  ...validEcdsaFinalizeSuccess,
  accountProvisioning: validEd25519FinalizeSuccess.accountProvisioning,
};
void invalidEcdsaFinalizeSuccessWithNearIdentity;

export {};
