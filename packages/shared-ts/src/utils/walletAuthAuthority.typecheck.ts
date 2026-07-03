import {
  canonicalWalletAuthorityBindingDigestInput,
  emailOtpWalletAuthAuthorityEmailHashHex,
  emailOtpWalletAuthAuthorityProvider,
  emailOtpWalletAuthAuthorityProviderUserId,
  walletAuthAuthorityRef,
  walletAuthorityBindingDigest,
  type ActiveWalletSession,
  type AuthBoundaryProof,
  type AuthFactorIdentity,
  type AuthMethodProof,
  type ProofFor,
  type EmailOtpFactorProfile,
  type EmailOtpFactorIdentity,
  type EmailOtpWalletAuthAuthority,
  type PasskeyFactorIdentity,
  type PasskeyWalletAuthAuthority,
  type WalletAuthAuthority,
  type WalletAuthAuthorityRef,
} from './walletAuthAuthority';
import {
  parseEmailOtpChallengeId,
  parseEmailOtpProviderUserId,
  parseAppSessionJwt,
  parseVerifiedEmailAddress,
  parseWalletAuthorityBindingDigest,
  parseWalletAuthMethodId,
  parseWalletId,
  parseWebAuthnCredentialIdB64u,
  parseWebAuthnRpId,
} from './domainIds';

function unwrapDomainId<T>(result: { ok: true; value: T } | { ok: false }): T {
  if (!result.ok) throw new Error('invalid wallet auth authority type fixture domain id');
  return result.value;
}

const rpId = unwrapDomainId(parseWebAuthnRpId('wallet.example.test'));
const credentialIdB64u = unwrapDomainId(parseWebAuthnCredentialIdB64u('credential-id'));
const providerUserId = unwrapDomainId(parseEmailOtpProviderUserId('google:alice'));
const challengeId = unwrapDomainId(parseEmailOtpChallengeId('challenge-id'));
const appSessionJwt = unwrapDomainId(parseAppSessionJwt('app-session.jwt'));
const walletId = unwrapDomainId(parseWalletId('alice.testnet'));
const authorityDigest = unwrapDomainId(parseWalletAuthorityBindingDigest('digest'));
const verifiedEmail = unwrapDomainId(parseVerifiedEmailAddress('alice@example.test'));
const emailHashHex = 'email-hash';

const passkeyAuthority = {
  walletId,
  factor: {
    kind: 'passkey',
    credentialIdB64u,
  },
  verifier: {
    kind: 'webauthn',
    rpId,
  },
  bindingId: unwrapDomainId(parseWalletAuthMethodId('passkey:wallet.example.test:credential-id')),
} satisfies PasskeyWalletAuthAuthority;
void passkeyAuthority;

const passkeyFactor = {
  kind: 'passkey',
  credentialIdB64u,
} satisfies PasskeyFactorIdentity;
void passkeyFactor;

const emailOtpAuthority = {
  walletId,
  factor: {
    kind: 'email_otp',
    provider: 'google',
    providerUserId,
  },
  verifier: {
    kind: 'email_otp_wallet_auth_method',
    emailHashHex,
  },
  bindingId: unwrapDomainId(parseWalletAuthMethodId('email_otp:alice.testnet:email-hash')),
} satisfies EmailOtpWalletAuthAuthority;
void emailOtpAuthority;
void (emailOtpWalletAuthAuthorityProvider(emailOtpAuthority) satisfies 'google' | 'email');
void (emailOtpWalletAuthAuthorityProviderUserId(emailOtpAuthority) satisfies typeof providerUserId);
void (emailOtpWalletAuthAuthorityEmailHashHex(emailOtpAuthority) satisfies string);

const emailOtpFactor = {
  kind: 'email_otp',
  provider: 'google',
  providerUserId,
} satisfies EmailOtpFactorIdentity;
void emailOtpFactor;

void ({
  walletId,
  factor: passkeyFactor,
  verifier: { kind: 'webauthn', rpId },
  bindingId: unwrapDomainId(parseWalletAuthMethodId('passkey:wallet.example.test:credential-id')),
} satisfies WalletAuthAuthority);

void ({
  walletId,
  factor: {
    kind: 'email_otp',
    provider: 'email',
    providerUserId,
  },
  verifier: {
    kind: 'email_otp_wallet_auth_method',
    emailHashHex,
  },
  bindingId: unwrapDomainId(parseWalletAuthMethodId('email_otp:alice.testnet:email-hash')),
} satisfies WalletAuthAuthority);

// @ts-expect-error passkey wallet auth authority cannot use the old flat method kind.
void ({ kind: 'passkey', rpId, credentialIdB64u } satisfies WalletAuthAuthority);

const invalidPasskeyAuthorityWithEmailProvider = {
  walletId,
  factor: passkeyFactor,
  verifier: { kind: 'webauthn', rpId },
  bindingId: unwrapDomainId(parseWalletAuthMethodId('passkey:wallet.example.test:credential-id')),
  providerUserId,
};
// @ts-expect-error passkey wallet auth authority cannot carry Email OTP provider identity.
void (invalidPasskeyAuthorityWithEmailProvider satisfies WalletAuthAuthority);

// @ts-expect-error Email OTP wallet auth authority cannot use the old flat method kind.
void ({ kind: 'email_otp', provider: 'google', providerUserId } satisfies WalletAuthAuthority);

const invalidEmailOtpAuthorityWithoutProviderUser = {
  walletId,
  factor: {
    kind: 'email_otp',
    provider: 'google',
  },
  verifier: {
    kind: 'email_otp_wallet_auth_method',
    emailHashHex,
  },
  bindingId: unwrapDomainId(parseWalletAuthMethodId('email_otp:alice.testnet:email-hash')),
};
// @ts-expect-error Email OTP wallet auth authority requires providerUserId.
void (invalidEmailOtpAuthorityWithoutProviderUser satisfies WalletAuthAuthority);

void ({
  factor: passkeyFactor,
  verifier: { kind: 'webauthn', rpId },
  bindingId: unwrapDomainId(parseWalletAuthMethodId('passkey:wallet.example.test:credential-id')),
  // @ts-expect-error passkey wallet auth authority requires walletId.
} satisfies WalletAuthAuthority);

const invalidPasskeyAuthorityWithoutBinding = {
  walletId,
  factor: passkeyFactor,
  verifier: { kind: 'webauthn', rpId },
};
// @ts-expect-error passkey wallet auth authority requires bindingId.
void (invalidPasskeyAuthorityWithoutBinding satisfies WalletAuthAuthority);

void ({
  kind: 'passkey',
  credentialIdB64u,
} satisfies AuthFactorIdentity);

void ({
  kind: 'email_otp',
  provider: 'email',
  providerUserId,
} satisfies AuthFactorIdentity);

void ({
  kind: 'passkey',
  credentialIdB64u,
  // @ts-expect-error passkey factor identity cannot carry RP verifier context.
  rpId,
} satisfies AuthFactorIdentity);

const invalidEmailOtpFactorWithCredential = {
  kind: 'email_otp',
  provider: 'google',
  providerUserId,
  credentialIdB64u,
};
// @ts-expect-error Email OTP factor identity cannot carry passkey credential identity.
void (invalidEmailOtpFactorWithCredential satisfies AuthFactorIdentity);

void ({
  kind: 'passkey',
  credentialIdB64u,
  // @ts-expect-error factor identity cannot carry wallet-bound verifier fields.
  walletId,
  verifier: { kind: 'webauthn', rpId },
  bindingId: unwrapDomainId(parseWalletAuthMethodId('passkey:wallet.example.test:credential-id')),
} satisfies AuthFactorIdentity);

void ({
  kind: 'email_otp',
  provider: 'google',
  providerUserId,
  // @ts-expect-error factor identity cannot carry wallet-bound verifier fields.
  walletId,
  verifier: {
    kind: 'email_otp_enrollment',
    enrollmentId: unwrapDomainId(parseWalletAuthMethodId('email_otp:alice.testnet:hash')),
  },
  bindingId: unwrapDomainId(parseWalletAuthMethodId('email_otp:alice.testnet:hash')),
} satisfies AuthFactorIdentity);

void ({
  factor: emailOtpFactor,
  email: verifiedEmail,
} satisfies EmailOtpFactorProfile);

void ({
  factor: emailOtpFactor,
  email: verifiedEmail,
  // @ts-expect-error factor profiles do not carry a self-labeling kind.
  kind: 'email_otp_authority_profile',
} satisfies EmailOtpFactorProfile);

void ({
  email: verifiedEmail,
  // @ts-expect-error factor profiles attach display email to factor identity, not wallet authority.
  authority: emailOtpAuthority,
} satisfies EmailOtpFactorProfile);

void ({
  kind: 'wallet_auth_authority_ref',
  walletId,
  authorityDigest,
} satisfies WalletAuthAuthorityRef);

void canonicalWalletAuthorityBindingDigestInput({ authority: emailOtpAuthority });
void walletAuthorityBindingDigest({ authority: emailOtpAuthority });
void walletAuthAuthorityRef({ authority: emailOtpAuthority });

void canonicalWalletAuthorityBindingDigestInput({
  authority: emailOtpAuthority,
  // @ts-expect-error authority digest helpers derive wallet identity from the bound authority.
  walletId,
});

void ({
  kind: 'wallet_auth_authority_ref',
  walletId,
  authorityDigest,
  // @ts-expect-error authority refs carry only stable digest identity, not raw authority data.
  authority: emailOtpAuthority,
} satisfies WalletAuthAuthorityRef);

void ({
  kind: 'active_wallet_session',
  authority: emailOtpAuthority,
  walletSessionJwt: 'wallet-session.jwt',
} satisfies ActiveWalletSession);

void ({
  kind: 'active_wallet_session',
  authority: emailOtpAuthority,
  walletSessionJwt: 'wallet-session.jwt',
  // @ts-expect-error active wallet sessions derive wallet identity from the bound authority.
  walletId,
} satisfies ActiveWalletSession);

const passkeyRegistrationProof = {
  kind: 'passkey_registration_credential',
  webauthnRegistration: {},
} satisfies AuthMethodProof;
void passkeyRegistrationProof;

const googleSsoRegistrationProof = {
  kind: 'google_sso_registration',
  registrationAttemptId: 'attempt',
  registrationOfferId: 'offer',
  registrationCandidateId: 'candidate',
  appSessionJwt,
} satisfies AuthMethodProof;
void googleSsoRegistrationProof;

const emailOtpChallengeProof = {
  kind: 'email_otp_challenge',
  challengeId,
  otpCode: '123456',
  appSessionJwt,
} satisfies AuthMethodProof;
void emailOtpChallengeProof;

void ({
  kind: 'email_otp_challenge',
  challengeId,
  otpCode: '123456',
  appSessionJwt,
  // @ts-expect-error Email OTP challenge proof is request-boundary data, not authority identity.
  providerUserId,
} satisfies AuthMethodProof);

void ({
  purpose: 'unlock',
  proof: emailOtpChallengeProof,
} satisfies AuthBoundaryProof);

void ({
  purpose: 'step_up',
  proof: emailOtpChallengeProof,
} satisfies AuthBoundaryProof);

void ({
  purpose: 'recovery',
  proof: emailOtpChallengeProof,
} satisfies AuthBoundaryProof);

void ({
  purpose: 'key_export',
  proof: emailOtpChallengeProof,
} satisfies AuthBoundaryProof);

void ({
  purpose: 'key_export',
  proof: {
    kind: 'passkey_assertion',
    assertion: {},
  },
} satisfies AuthBoundaryProof);

void ({
  purpose: 'registration',
  proof: googleSsoRegistrationProof,
} satisfies ProofFor<'registration'>);

void ({
  purpose: 'registration',
  proof: {
    // @ts-expect-error old per-operation passkey registration proof kind is deleted.
    kind: 'passkey_registration',
    webauthnRegistration: {},
  },
} satisfies AuthBoundaryProof);

void ({
  purpose: 'key_export',
  proof: {
    // @ts-expect-error old per-operation key-export proof kind is deleted.
    kind: 'passkey_key_export',
    assertion: {},
  },
} satisfies AuthBoundaryProof);

void ({
  purpose: 'unlock',
  proof: {
    kind: 'passkey_assertion',
    assertion: {},
    // @ts-expect-error passkey assertion proof cannot carry Email OTP challenge state.
    challengeId,
  },
} satisfies AuthBoundaryProof);

void ({
  // @ts-expect-error proof purpose is explicit and limited to known operation purposes.
  purpose: 'wallet_unlock',
  proof: emailOtpChallengeProof,
} satisfies AuthBoundaryProof);
