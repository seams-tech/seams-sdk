import {
  EMAIL_OTP_ED25519_YAO_LOCAL_MATERIAL_ALGORITHM,
  EMAIL_OTP_ED25519_YAO_LOCAL_MATERIAL_KEY_KIND,
  type EmailOtpEd25519YaoOpaqueLocalEnvelopeV1,
  type EmailOtpEd25519YaoStableCustodyBindingV1,
} from './ed25519YaoLocalMaterial';

const stableBinding: EmailOtpEd25519YaoStableCustodyBindingV1 = {
  kind: EMAIL_OTP_ED25519_YAO_LOCAL_MATERIAL_KEY_KIND,
  walletId: 'wallet-1',
  nearAccountId: 'near-account-1',
  provider: 'google',
  providerSubjectId: 'google:subject-1',
  enrollmentId: 'enrollment-1',
  enrollmentVersion: '1',
  enrollmentSealKeyVersion: 'seal-key-1',
  signerSlot: 1,
  nearEd25519SigningKeyId: 'ed25519-key-1',
  signingRootId: 'root-1',
  signingRootVersion: 'root-version-1',
  lifecycleId: 'lifecycle-1',
  rootShareEpoch: '1',
  signerSetId: 'signer-set-1',
  participantIds: [1, 2],
  signingWorkerId: 'signing-worker-1',
  registeredPublicKeyB64u: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
  signingWorkerVerifyingShareB64u: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
  stateEpoch: '1',
  activationTranscriptB64u: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
  activeCapabilityBindingB64u: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
  applicationBinding: {
    walletId: 'wallet-1',
    nearEd25519SigningKeyId: 'ed25519-key-1',
    signingRootId: 'root-1',
    keyCreationSignerSlot: 1,
  },
};

void stableBinding;

const rotatingSessionBinding: EmailOtpEd25519YaoStableCustodyBindingV1 = {
  ...stableBinding,
  // @ts-expect-error Rotating session authority cannot enter durable custody identity.
  thresholdSessionId: 'threshold-session-1',
};
void rotatingSessionBinding;

const secretBearingEnvelope: EmailOtpEd25519YaoOpaqueLocalEnvelopeV1 = {
  algorithm: EMAIL_OTP_ED25519_YAO_LOCAL_MATERIAL_ALGORITHM,
  nonceB64u: 'AAAAAAAAAAAAAAAA',
  ciphertextB64u: 'AQ',
  // @ts-expect-error Main-thread storage cannot accept plaintext secret material.
  clientSecret32B64u: 'AQ',
};
void secretBearingEnvelope;

export {};
