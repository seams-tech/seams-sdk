import {
  implicitNearAccountProvisioning,
  normalizeWalletAuthMethodTarget,
  sponsoredNamedNearAccountProvisioning,
  walletIdFromString,
  type RegistrationAuthMethodInput,
  type RegistrationAuthority,
  type RegistrationIntentV1,
  type RegistrationSignerSelection,
  type WalletAuthMethodRecord,
  type WalletAuthMethodTarget,
} from './registrationIntent';
import {
  parseAppSessionVersion,
  parseChallengeSubjectId,
  parseEmailOtpChallengeId,
  parseOrgId,
  parseProviderSubject,
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

const passkeyAuthMethod = {
  kind: 'passkey',
} satisfies RegistrationAuthMethodInput;

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

const ecdsaOnlySelection = {
  mode: 'ecdsa_only',
  ecdsa: {
    chainTargets: [{ kind: 'evm', namespace: 'eip155', chainId: 1 }],
    participantIds: [1, 2],
  },
} satisfies RegistrationSignerSelection;

const ed25519OnlySelection = {
  mode: 'ed25519_only',
  ed25519: {
    accountProvisioning: implicitNearAccountProvisioning(),
    signerSlot: 1,
    participantIds: [1, 2],
    keyPurpose: 'near_tx',
    keyVersion: 'threshold-ed25519-hss-v1',
    derivationVersion: 1,
  },
} satisfies RegistrationSignerSelection;

const sponsoredNamedEd25519OnlySelection = {
  mode: 'ed25519_only',
  ed25519: {
    accountProvisioning: sponsoredNamedNearAccountProvisioning(namedNearAccountId),
    signerSlot: 1,
    participantIds: [1, 2],
    keyPurpose: 'near_tx',
    keyVersion: 'threshold-ed25519-hss-v1',
    derivationVersion: 1,
  },
} satisfies RegistrationSignerSelection;

const ed25519WithLegacyNearAccountId: RegistrationSignerSelection = {
  mode: 'ed25519_only',
  ed25519: {
    // @ts-expect-error registration Ed25519 specs use accountProvisioning, not nearAccountId.
    nearAccountId: 'alice.testnet',
    signerSlot: 1,
    participantIds: [1, 2],
    keyPurpose: 'near_tx',
    keyVersion: 'threshold-ed25519-hss-v1',
    derivationVersion: 1,
  },
};
void ed25519WithLegacyNearAccountId;

const ed25519WithLegacyCreateBoolean: RegistrationSignerSelection = {
  mode: 'ed25519_only',
  ed25519: {
    accountProvisioning: implicitNearAccountProvisioning(),
    signerSlot: 1,
    participantIds: [1, 2],
    keyPurpose: 'near_tx',
    keyVersion: 'threshold-ed25519-hss-v1',
    derivationVersion: 1,
    // @ts-expect-error registration Ed25519 specs cannot carry legacy createNearAccount.
    createNearAccount: true,
  },
};
void ed25519WithLegacyCreateBoolean;

void ({
  version: 'registration_intent_v1',
  walletId: walletIdFromString('wallet_alice'),
  rpId: 'wallet.example.test',
  authMethod: emailOtpAuthMethod,
  signerSelection: ecdsaOnlySelection,
  nonceB64u: 'nonce',
} satisfies RegistrationIntentV1);

void ({
  version: 'registration_intent_v1',
  walletId: walletIdFromString('wallet_alice'),
  rpId: 'wallet.example.test',
  authMethod: googleSsoRegistrationAuthMethod,
  signerSelection: ed25519OnlySelection,
  nonceB64u: 'nonce',
} satisfies RegistrationIntentV1);

void ({
  version: 'registration_intent_v1',
  walletId: walletIdFromString('wallet_alice'),
  rpId: 'wallet.example.test',
  authMethod: passkeyAuthMethod,
  signerSelection: ed25519OnlySelection,
  nonceB64u: 'nonce',
} satisfies RegistrationIntentV1);

void ({
  version: 'registration_intent_v1',
  walletId: walletIdFromString('alice.testnet'),
  rpId: 'wallet.example.test',
  authMethod: passkeyAuthMethod,
  signerSelection: sponsoredNamedEd25519OnlySelection,
  nonceB64u: 'nonce',
} satisfies RegistrationIntentV1);

// @ts-expect-error registration intents require explicit authMethod.
const missingAuthMethod: RegistrationIntentV1 = {
  version: 'registration_intent_v1',
  walletId: walletIdFromString('wallet_alice'),
  rpId: 'wallet.example.test',
  signerSelection: ed25519OnlySelection,
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
  rpId: 'wallet.example.test',
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
  rpId: 'wallet.example.test',
  // @ts-expect-error Email OTP auth-method records do not carry passkey RP scope.
} satisfies WalletAuthMethodRecord;
void emailOtpAuthMethodWithRpId;

void ({
  kind: 'passkey',
  credentialIdB64u: 'credential',
} satisfies WalletAuthMethodTarget);

void ({
  kind: 'email_otp',
  email: 'alice@example.test',
} satisfies WalletAuthMethodTarget);

// @ts-expect-error passkey revoke target cannot carry Email OTP fields.
const passkeyTargetWithEmail: WalletAuthMethodTarget = {
  kind: 'passkey',
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

void normalizeWalletAuthMethodTarget({
  kind: 'passkey',
  credentialIdB64u: 'credential',
});

export {};
