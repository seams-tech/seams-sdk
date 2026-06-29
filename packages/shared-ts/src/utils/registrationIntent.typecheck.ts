import {
  implicitNearAccountProvisioning,
  normalizeWalletAuthMethodTarget,
  sponsoredNamedNearAccountProvisioning,
  walletIdFromString,
  type AddAuthMethodIntentV1,
  type AddSignerIntentV1,
  type NearAccountOwnershipProofV1,
  type RegistrationAuthMethodInput,
  type RegistrationAuthority,
  type RegistrationIntentV1,
  type RegistrationSignerPlan,
  type RegistrationSignerSetSelection,
  type WalletAuthMethodRecord,
  type WalletAuthMethodTarget,
} from './registrationIntent';
import {
  parseAppSessionVersion,
  parseChallengeSubjectId,
  parseEmailOtpChallengeId,
  parseOrgId,
  parseProviderSubject,
  parseWebAuthnRpId,
} from './domainIds';
import { parseNamedNearAccountId } from './near';

function unwrapDomainId<T>(result: { ok: true; value: T } | { ok: false }): T {
  if (!result.ok) throw new Error('invalid type fixture domain id');
  return result.value;
}

const providerSubject = unwrapDomainId(parseProviderSubject('google:alice'));
const challengeSubjectId = unwrapDomainId(parseChallengeSubjectId('google:alice'));
const emailOtpChallengeId = unwrapDomainId(parseEmailOtpChallengeId('challenge'));
const orgId = unwrapDomainId(parseOrgId('org_test'));
const appSessionVersion = unwrapDomainId(parseAppSessionVersion('app-session-v1'));
const namedNearAccountId = unwrapDomainId(parseNamedNearAccountId('alice.testnet'));
const webAuthnRpId = unwrapDomainId(parseWebAuthnRpId('wallet.example.test'));

void ({
  version: 'near_account_ownership_proof_v1',
  message: {
    version: 'near_account_ownership_proof_message_v1',
    walletId: walletIdFromString('wallet_alice'),
    nearAccountId: 'alice.testnet',
    publicKey: 'ed25519:public-key',
    nonceB64u: 'nonce',
    issuedAtMs: 1,
    expiresAtMs: 2,
  },
  signatureB64u: 'signature',
} satisfies NearAccountOwnershipProofV1);

void ({
  version: 'near_account_ownership_proof_v1',
  message: {
    version: 'near_account_ownership_proof_message_v1',
    walletId: walletIdFromString('wallet_alice'),
    // @ts-expect-error NEAR account ownership proof messages do not carry passkey RP scope.
    rpId: 'wallet.example.test',
    nearAccountId: 'alice.testnet',
    publicKey: 'ed25519:public-key',
    nonceB64u: 'nonce',
    issuedAtMs: 1,
    expiresAtMs: 2,
  },
  signatureB64u: 'signature',
} satisfies NearAccountOwnershipProofV1);

const passkeyAuthMethod = {
  kind: 'passkey',
  rpId: webAuthnRpId,
} satisfies RegistrationAuthMethodInput;

// @ts-expect-error passkey registration auth carries its RP scope in the passkey branch.
const passkeyAuthMethodMissingRpId: RegistrationAuthMethodInput = {
  kind: 'passkey',
};
void passkeyAuthMethodMissingRpId;

const emailOtpAuthMethod = {
  kind: 'email_otp',
  proofKind: 'otp_challenge',
  email: 'alice@example.test',
  otpCode: '123456',
  appSessionJwt: 'app-session.jwt',
  challengeId: 'challenge',
} satisfies RegistrationAuthMethodInput;

const googleSsoRegistrationAuthMethod = {
  kind: 'email_otp',
  proofKind: 'google_sso_registration',
  email: 'alice@example.test',
  appSessionJwt: 'app-session.jwt',
  googleEmailOtpRegistrationAttemptId: 'registration-attempt-1',
  googleEmailOtpRegistrationOfferId: 'registration-offer-1',
  googleEmailOtpRegistrationCandidateId: 'registration-candidate-1',
} satisfies RegistrationAuthMethodInput;

const ecdsaSignerSetSelection = {
  kind: 'signer_set',
  signers: [
    {
      kind: 'evm_family_ecdsa',
      chainTargets: [{ kind: 'evm', namespace: 'eip155', chainId: 1 }],
      participantIds: [1, 2],
    },
  ],
} satisfies RegistrationSignerSetSelection;

const ed25519SignerSetSelection = {
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
} satisfies RegistrationSignerSetSelection;

const sponsoredNamedEd25519SignerSetSelection = {
  kind: 'signer_set',
  signers: [
    {
      kind: 'near_ed25519',
      accountProvisioning: sponsoredNamedNearAccountProvisioning(namedNearAccountId),
      signerSlot: 1,
      participantIds: [1, 2],
      derivationVersion: 1,
    },
  ],
} satisfies RegistrationSignerSetSelection;

void ({
  kind: 'signer_set',
  signers: [
    {
      kind: 'near_ed25519',
      accountProvisioning: implicitNearAccountProvisioning(),
      signerSlot: 1,
      participantIds: [1, 2],
      derivationVersion: 1,
    },
    {
      kind: 'evm_family_ecdsa',
      participantIds: [1, 2],
      chainTargets: [{ kind: 'evm', namespace: 'eip155', chainId: 1 }],
    },
  ],
} satisfies RegistrationSignerSetSelection);

void ({
  kind: 'signer_set',
  signers: [
    {
      kind: 'near_ed25519',
      accountProvisioning: implicitNearAccountProvisioning(),
      signerSlot: 1,
      participantIds: [1, 2],
      // @ts-expect-error signer-set NEAR Ed25519 requests do not carry protocol key fields.
      keyPurpose: 'near_tx',
      derivationVersion: 1,
    },
  ],
} satisfies RegistrationSignerSetSelection);

void ({
  kind: 'signer_set',
  signers: [
    // @ts-expect-error EVM-family ECDSA signer requests cannot carry NEAR account provisioning.
    {
      kind: 'evm_family_ecdsa',
      participantIds: [1, 2],
      chainTargets: [{ kind: 'evm', namespace: 'eip155', chainId: 1 }],
      accountProvisioning: implicitNearAccountProvisioning(),
    },
  ],
} satisfies RegistrationSignerSetSelection);

void ({
  kind: 'signer_set',
  signers: [
    // @ts-expect-error NEAR Ed25519 signer requests require account provisioning identity.
    {
      kind: 'near_ed25519',
      signerSlot: 1,
      participantIds: [1, 2],
      derivationVersion: 1,
    },
  ],
} satisfies RegistrationSignerSetSelection);

void ({
  kind: 'signer_set',
  signers: [
    // @ts-expect-error EVM-family ECDSA signer requests require chain target identity.
    {
      kind: 'evm_family_ecdsa',
      participantIds: [1, 2],
    },
  ],
} satisfies RegistrationSignerSetSelection);

void ({
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
  // @ts-expect-error signer-set selections do not carry legacy registration mode.
  mode: 'legacy_mode',
} satisfies RegistrationSignerSetSelection);

void ({
  kind: 'signer_set',
  branches: [
    // @ts-expect-error parsed signer plan branches require a stable branchKey.
    {
      kind: 'near_ed25519',
      accountProvisioning: implicitNearAccountProvisioning(),
      signerSlot: 1,
      participantIds: [1, 2],
      keyPurpose: 'near_tx',
      keyVersion: 'threshold-ed25519-hss-v1',
      derivationVersion: 1,
    },
  ],
} satisfies RegistrationSignerPlan);

const ed25519WithLegacyNearAccountId = {
  kind: 'signer_set',
  signers: [
    {
      kind: 'near_ed25519',
      accountProvisioning: implicitNearAccountProvisioning(),
      signerSlot: 1,
      participantIds: [1, 2],
      derivationVersion: 1,
      // @ts-expect-error signer-set NEAR Ed25519 requests use accountProvisioning, not nearAccountId.
      nearAccountId: 'alice.testnet',
    },
  ],
} satisfies RegistrationSignerSetSelection;
void ed25519WithLegacyNearAccountId;

const ed25519WithLegacyCreateBoolean = {
  kind: 'signer_set',
  signers: [
    {
      kind: 'near_ed25519',
      accountProvisioning: implicitNearAccountProvisioning(),
      signerSlot: 1,
      participantIds: [1, 2],
      derivationVersion: 1,
      // @ts-expect-error signer-set NEAR Ed25519 requests cannot carry legacy createNearAccount.
      createNearAccount: true,
    },
  ],
} satisfies RegistrationSignerSetSelection;
void ed25519WithLegacyCreateBoolean;

void ({
  version: 'registration_intent_v1',
  walletId: walletIdFromString('wallet_alice'),
  authMethod: emailOtpAuthMethod,
  signerSelection: ecdsaSignerSetSelection,
  nonceB64u: 'nonce',
} satisfies RegistrationIntentV1);

void ({
  version: 'registration_intent_v1',
  walletId: walletIdFromString('wallet_alice'),
  authMethod: googleSsoRegistrationAuthMethod,
  signerSelection: ed25519SignerSetSelection,
  nonceB64u: 'nonce',
} satisfies RegistrationIntentV1);

void ({
  version: 'registration_intent_v1',
  walletId: walletIdFromString('wallet_alice'),
  authMethod: passkeyAuthMethod,
  signerSelection: ed25519SignerSetSelection,
  nonceB64u: 'nonce',
} satisfies RegistrationIntentV1);

void ({
  version: 'registration_intent_v1',
  walletId: walletIdFromString('wallet_alice'),
  authMethod: passkeyAuthMethod,
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
      {
        kind: 'evm_family_ecdsa',
        participantIds: [1, 2],
        chainTargets: [{ kind: 'evm', namespace: 'eip155', chainId: 1 }],
      },
    ],
  },
  nonceB64u: 'nonce',
} satisfies RegistrationIntentV1);

void ({
  version: 'registration_intent_v1',
  walletId: walletIdFromString('alice.testnet'),
  authMethod: passkeyAuthMethod,
  signerSelection: sponsoredNamedEd25519SignerSetSelection,
  nonceB64u: 'nonce',
} satisfies RegistrationIntentV1);

void ({
  version: 'registration_intent_v1',
  walletId: walletIdFromString('wallet_alice'),
  authMethod: passkeyAuthMethod,
  signerSelection: ed25519SignerSetSelection,
  nonceB64u: 'nonce',
  // @ts-expect-error registration intents do not carry root passkey RP scope.
  rpId: 'wallet.example.test',
} satisfies RegistrationIntentV1);

void ({
  version: 'add_signer_intent_v1',
  walletId: walletIdFromString('wallet_alice'),
  signerSelection: {
    mode: 'ecdsa',
    ecdsa: {
      chainTargets: [{ kind: 'evm', namespace: 'eip155', chainId: 1 }],
      participantIds: [1, 2],
    },
  },
  nonceB64u: 'nonce',
  // @ts-expect-error add-signer intents do not carry root passkey RP scope.
  rpId: 'wallet.example.test',
} satisfies AddSignerIntentV1);

void ({
  version: 'add_auth_method_intent_v1',
  walletId: walletIdFromString('wallet_alice'),
  authMethod: { kind: 'passkey', rpId: webAuthnRpId },
  nonceB64u: 'nonce',
  // @ts-expect-error add-auth-method intents keep RP scope inside the passkey branch.
  rpId: 'wallet.example.test',
} satisfies AddAuthMethodIntentV1);

// @ts-expect-error registration intents require explicit authMethod.
const missingAuthMethod: RegistrationIntentV1 = {
  version: 'registration_intent_v1',
  walletId: walletIdFromString('wallet_alice'),
  signerSelection: ed25519SignerSetSelection,
  nonceB64u: 'nonce',
};
void missingAuthMethod;

// @ts-expect-error passkey registration auth cannot carry Email OTP fields.
const passkeyWithEmail: RegistrationAuthMethodInput = {
  kind: 'passkey',
  email: 'alice@example.test',
};
void passkeyWithEmail;

// @ts-expect-error Email OTP registration auth cannot carry passkey options.
const emailOtpWithAuthenticatorOptions: RegistrationAuthMethodInput = {
  kind: 'email_otp',
  proofKind: 'otp_challenge',
  email: 'alice@example.test',
  otpCode: '123456',
  appSessionJwt: 'app-session.jwt',
  authenticatorOptions: {},
};
void emailOtpWithAuthenticatorOptions;

// @ts-expect-error Email OTP registration auth requires an OTP code.
const emailOtpMissingOtpCode: RegistrationAuthMethodInput = {
  kind: 'email_otp',
  proofKind: 'otp_challenge',
  email: 'alice@example.test',
  appSessionJwt: 'app-session.jwt',
};
void emailOtpMissingOtpCode;

// @ts-expect-error Email OTP registration auth requires app-session authority.
const emailOtpMissingAppSession: RegistrationAuthMethodInput = {
  kind: 'email_otp',
  proofKind: 'otp_challenge',
  email: 'alice@example.test',
  otpCode: '123456',
};
void emailOtpMissingAppSession;

// @ts-expect-error Google SSO registration auth requires an offer id.
const googleSsoMissingOffer: RegistrationAuthMethodInput = {
  kind: 'email_otp',
  proofKind: 'google_sso_registration',
  email: 'alice@example.test',
  appSessionJwt: 'app-session.jwt',
  googleEmailOtpRegistrationAttemptId: 'registration-attempt-1',
  googleEmailOtpRegistrationCandidateId: 'registration-candidate-1',
};
void googleSsoMissingOffer;

// @ts-expect-error Google SSO registration auth requires a selected candidate id.
const googleSsoMissingCandidate: RegistrationAuthMethodInput = {
  kind: 'email_otp',
  proofKind: 'google_sso_registration',
  email: 'alice@example.test',
  appSessionJwt: 'app-session.jwt',
  googleEmailOtpRegistrationAttemptId: 'registration-attempt-1',
  googleEmailOtpRegistrationOfferId: 'registration-offer-1',
};
void googleSsoMissingCandidate;

void ({
  version: 'wallet_auth_method_v1',
  kind: 'passkey',
  status: 'active',
  walletId: walletIdFromString('wallet_alice'),
  rpId: webAuthnRpId,
  credentialIdB64u: 'credential',
  credentialPublicKeyB64u: 'public-key',
  counter: 0,
  createdAtMs: 1,
  updatedAtMs: 1,
} satisfies WalletAuthMethodRecord);

void ({
  kind: 'email_otp',
  proofKind: 'otp_challenge',
  walletId: walletIdFromString('wallet_alice'),
  providerSubject,
  challengeSubjectId,
  email: 'alice@example.test',
  emailHashHex: '00',
  challengeId: emailOtpChallengeId,
  registrationAuthorityId: emailOtpChallengeId,
  originalWalletId: walletIdFromString('wallet_alice_original'),
  finalWalletId: walletIdFromString('wallet_alice'),
  orgId,
  appSessionVersion,
  challengePurpose: 'registration_reroll',
  registrationIntentDigestB64u: 'digest',
} satisfies RegistrationAuthority);

// @ts-expect-error Email OTP authority requires the normalized challenge owner.
const emailOtpAuthorityMissingChallengeSubject: RegistrationAuthority = {
  kind: 'email_otp',
  proofKind: 'otp_challenge',
  walletId: walletIdFromString('wallet_alice'),
  providerSubject,
  email: 'alice@example.test',
  emailHashHex: '00',
  challengeId: emailOtpChallengeId,
  registrationAuthorityId: emailOtpChallengeId,
  originalWalletId: walletIdFromString('wallet_alice_original'),
  finalWalletId: walletIdFromString('wallet_alice'),
  orgId,
  appSessionVersion,
  challengePurpose: 'registration_reroll',
  registrationIntentDigestB64u: 'digest',
};
void emailOtpAuthorityMissingChallengeSubject;

void ({
  version: 'wallet_auth_method_v1',
  kind: 'email_otp',
  status: 'active',
  walletId: walletIdFromString('wallet_alice'),
  emailHashHex: '00',
  registrationAuthorityId: 'challenge',
  createdAtMs: 1,
  updatedAtMs: 1,
} satisfies WalletAuthMethodRecord);

const emailOtpAuthMethodWithRpId = {
  version: 'wallet_auth_method_v1',
  kind: 'email_otp',
  status: 'active',
  walletId: walletIdFromString('wallet_alice'),
  emailHashHex: '00',
  registrationAuthorityId: 'challenge',
  createdAtMs: 1,
  updatedAtMs: 1,
  // @ts-expect-error Email OTP auth-method records do not carry passkey RP scope.
  rpId: 'wallet.example.test',
} satisfies WalletAuthMethodRecord;
void emailOtpAuthMethodWithRpId;

void ({
  kind: 'passkey',
  rpId: webAuthnRpId,
  credentialIdB64u: 'credential',
} satisfies WalletAuthMethodTarget);

void ({
  kind: 'email_otp',
  email: 'alice@example.test',
} satisfies WalletAuthMethodTarget);

// @ts-expect-error passkey revoke target cannot carry Email OTP fields.
const passkeyTargetWithEmail: WalletAuthMethodTarget = {
  kind: 'passkey',
  rpId: webAuthnRpId,
  credentialIdB64u: 'credential',
  email: 'alice@example.test',
};
void passkeyTargetWithEmail;

// @ts-expect-error Email OTP revoke target cannot carry passkey credential ids.
const emailOtpTargetWithCredential: WalletAuthMethodTarget = {
  kind: 'email_otp',
  email: 'alice@example.test',
  credentialIdB64u: 'credential',
};
void emailOtpTargetWithCredential;

// @ts-expect-error Email OTP revoke target cannot carry passkey RP scope.
const emailOtpTargetWithRpId: WalletAuthMethodTarget = {
  kind: 'email_otp',
  email: 'alice@example.test',
  rpId: webAuthnRpId,
};
void emailOtpTargetWithRpId;

void normalizeWalletAuthMethodTarget({
  kind: 'passkey',
  rpId: webAuthnRpId,
  credentialIdB64u: 'credential',
});

export {};
