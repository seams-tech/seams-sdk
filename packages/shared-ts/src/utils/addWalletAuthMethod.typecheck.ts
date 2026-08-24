/**
 * Compile-time fixtures for the Refactor 109C addition contract.
 *
 * Every `@ts-expect-error` below is a state R109C forbids. If one of them ever
 * starts compiling, the branch union has been widened — a same-family
 * addition, a mixed target draft, an unverified value, or a cast has become
 * expressible — and this file fails the build rather than the behaviour
 * failing in a browser.
 */

import {
  addWalletAuthMethodSourceFamily,
  addWalletAuthMethodTargetFamily,
  buildEmailOtpToPasskeyAdditionV1,
  buildPasskeyToEmailOtpAdditionV1,
  parseAddWalletAuthMethodCeremonyIdV1,
  parseWalletAuthorityRevocationEpochV1,
  unreachableAddWalletAuthMethodBranch,
  type AddWalletAuthMethodBranchV1,
  type AddWalletAuthMethodIntentIdentityV1,
  type AddWalletAuthMethodResultV1,
  type AddWalletAuthMethodSourceV1,
  type VerifiedAddWalletAuthMethodInputV1,
  type VerifiedAddWalletAuthMethodSourceProofV1,
  type VerifiedAddWalletAuthMethodTargetV1,
  type WalletAuthMethodFamilyV1,
} from './addWalletAuthMethod';
import { parseDeviceId, parseWalletSessionId } from '../authorization/capabilityKinds';
import { parseDigestB64u } from './canonicalPrimitives';
import {
  parseWalletAuthMethodId,
  parseWalletAuthorityId,
  parseWalletId,
  parseWebAuthnCredentialIdB64u,
  parseWebAuthnRpId,
} from './domainIds';

function unwrapDomainId<T>(result: { ok: true; value: T } | { ok: false }): T {
  if (!result.ok) throw new Error('invalid type fixture domain id');
  return result.value;
}

const walletId = unwrapDomainId(parseWalletId('wallet:fixture'));
const walletAuthorityId = unwrapDomainId(parseWalletAuthorityId('wallet-authority:fixture'));
const sourceWalletAuthMethodId = unwrapDomainId(
  parseWalletAuthMethodId('wallet-auth-method:source'),
);
const targetWalletAuthMethodId = unwrapDomainId(
  parseWalletAuthMethodId('wallet-auth-method:target'),
);
const sourceWalletSessionId = unwrapDomainId(parseWalletSessionId('wallet-session:fixture'));
const deviceId = unwrapDomainId(parseDeviceId('device:fixture'));
const rpId = unwrapDomainId(parseWebAuthnRpId('wallet.example.test'));
const credentialIdB64u = unwrapDomainId(parseWebAuthnCredentialIdB64u('credential'));

/** 32 zero bytes, the only shape `parseDigestB64u` accepts. */
const digestB64u = parseDigestB64u('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA');
const otherDigestB64u = parseDigestB64u('AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA');

const source: AddWalletAuthMethodSourceV1 = {
  walletId,
  walletAuthorityId,
  sourceWalletAuthMethodId,
  sourceWalletSessionId,
  deviceId,
  authorityDigestB64u: digestB64u,
  revocationEpoch: parseWalletAuthorityRevocationEpochV1(0),
};

const intent: AddWalletAuthMethodIntentIdentityV1 = {
  addAuthMethodCeremonyId: parseAddWalletAuthMethodCeremonyIdV1('wauthc_fixture'),
  intentDigestB64u: digestB64u,
  targetWalletAuthMethodId,
  expiresAtMs: 1,
};

const passkeySourceProof: Extract<
  VerifiedAddWalletAuthMethodSourceProofV1,
  { kind: 'verified_passkey_source_proof_v1' }
> = {
  kind: 'verified_passkey_source_proof_v1',
  walletAuthMethodId: sourceWalletAuthMethodId,
  boundIntentDigestB64u: digestB64u,
  verifiedAtMs: 1,
};

const emailOtpSourceProof: Extract<
  VerifiedAddWalletAuthMethodSourceProofV1,
  { kind: 'verified_email_otp_source_proof_v1' }
> = {
  kind: 'verified_email_otp_source_proof_v1',
  walletAuthMethodId: sourceWalletAuthMethodId,
  boundIntentDigestB64u: digestB64u,
  verifiedAtMs: 1,
};

const emailOtpTarget: Extract<
  VerifiedAddWalletAuthMethodTargetV1,
  { kind: 'verified_email_otp_target_v1' }
> = {
  kind: 'verified_email_otp_target_v1',
  authMethod: {
    kind: 'email_otp',
    walletAuthMethodId: targetWalletAuthMethodId,
    walletId,
    emailHashHex: 'ab',
    registrationAuthorityId: 'google',
    createdAtMs: 1,
  },
  verificationDigestB64u: otherDigestB64u,
  verifiedAtMs: 1,
};

const passkeyTarget: Extract<
  VerifiedAddWalletAuthMethodTargetV1,
  { kind: 'verified_passkey_target_v1' }
> = {
  kind: 'verified_passkey_target_v1',
  authMethod: {
    kind: 'passkey',
    walletAuthMethodId: targetWalletAuthMethodId,
    walletId,
    rpId,
    credentialIdB64u,
    credentialPublicKeyB64u: 'public-key',
    counter: 0,
    createdAtMs: 1,
  },
  verificationDigestB64u: otherDigestB64u,
  verifiedAtMs: 1,
};

/* Both supported branches build. */
const passkeyToEmailOtp = buildPasskeyToEmailOtpAdditionV1({
  source,
  intent,
  sourceProof: passkeySourceProof,
  target: emailOtpTarget,
});
const emailOtpToPasskey = buildEmailOtpToPasskeyAdditionV1({
  source,
  intent,
  sourceProof: emailOtpSourceProof,
  target: passkeyTarget,
});
void passkeyToEmailOtp;
void emailOtpToPasskey;

/* Same-family addition: a Passkey source cannot add another Passkey. */
buildPasskeyToEmailOtpAdditionV1({
  source,
  intent,
  sourceProof: passkeySourceProof,
  // @ts-expect-error a Passkey source branch cannot verify a Passkey target
  target: passkeyTarget,
});

/* Same-family addition: an Email OTP source cannot add another Email OTP. */
buildEmailOtpToPasskeyAdditionV1({
  source,
  intent,
  sourceProof: emailOtpSourceProof,
  // @ts-expect-error an Email OTP source branch cannot verify an Email OTP target
  target: emailOtpTarget,
});

/* Source proof substitution across branches. */
buildPasskeyToEmailOtpAdditionV1({
  source,
  intent,
  // @ts-expect-error the Passkey-source branch requires a verified Passkey proof
  sourceProof: emailOtpSourceProof,
  target: emailOtpTarget,
});

/* The target factor cannot be satisfied by a source proof. */
buildEmailOtpToPasskeyAdditionV1({
  source,
  intent,
  sourceProof: emailOtpSourceProof,
  // @ts-expect-error a source proof is not independent target verification
  target: emailOtpSourceProof,
});

/* Mixed target fields: an Email OTP draft may not carry Passkey identity. */
const mixedTarget: VerifiedAddWalletAuthMethodTargetV1 = {
  kind: 'verified_email_otp_target_v1',
  // @ts-expect-error rpId belongs to the Passkey branch only
  authMethod: {
    kind: 'email_otp',
    walletAuthMethodId: targetWalletAuthMethodId,
    walletId,
    emailHashHex: 'ab',
    registrationAuthorityId: 'google',
    createdAtMs: 1,
    rpId,
  },
  verificationDigestB64u: otherDigestB64u,
  verifiedAtMs: 1,
};
void mixedTarget;

/* Unverified input: a raw factor value is not a verified target. */
buildEmailOtpToPasskeyAdditionV1({
  source,
  intent,
  sourceProof: emailOtpSourceProof,
  // @ts-expect-error an unverified draft cannot stand in for a verified target
  target: passkeyTarget.authMethod,
});

/* Identity substitution: a raw string cannot replace a branded identity. */
const rawSource: AddWalletAuthMethodSourceV1 = {
  ...source,
  // @ts-expect-error the source method id must be branded
  sourceWalletAuthMethodId: 'wallet-auth-method:source',
};
void rawSource;

/* Identity substitution: an authority id cannot stand in for a method id. */
const swappedSource: AddWalletAuthMethodSourceV1 = {
  ...source,
  // @ts-expect-error a WalletAuthorityId is not a WalletAuthMethodId
  sourceWalletAuthMethodId: walletAuthorityId,
};
void swappedSource;

/* Optional core identity: every source field is required. */
// @ts-expect-error the source session is required, not optional
const partialSource: AddWalletAuthMethodSourceV1 = {
  walletId,
  walletAuthorityId,
  sourceWalletAuthMethodId,
  deviceId,
  authorityDigestB64u: digestB64u,
  revocationEpoch: parseWalletAuthorityRevocationEpochV1(0),
};
void partialSource;

/* A bare number is not a validated revocation epoch. */
const rawEpochSource: AddWalletAuthMethodSourceV1 = {
  ...source,
  // @ts-expect-error the revocation epoch must be parsed, not assumed
  revocationEpoch: 3,
};
void rawEpochSource;

/* The result union has no open-ended branch. */
// @ts-expect-error 'partially_configured' is not an R109C outcome
const unknownResult: AddWalletAuthMethodResultV1 = { kind: 'partially_configured' };
void unknownResult;

/* Exhaustiveness: the switch below must cover both branches to compile. */
function targetFamilyByHand(branch: AddWalletAuthMethodBranchV1): WalletAuthMethodFamilyV1 {
  switch (branch) {
    case 'passkey_to_email_otp':
      return 'email_otp';
    case 'email_otp_to_passkey':
      return 'passkey';
    default:
      return unreachableAddWalletAuthMethodBranch(branch);
  }
}
void targetFamilyByHand;

/* A third branch is not addable without changing the union. */
// @ts-expect-error 'passkey_to_passkey' is not a branch R109C models
const unsupportedBranch: AddWalletAuthMethodBranchV1 = 'passkey_to_passkey';
void unsupportedBranch;

void addWalletAuthMethodTargetFamily('passkey_to_email_otp');
void addWalletAuthMethodSourceFamily('email_otp_to_passkey');

/* The verified input's branch is what selects the target family. */
function familyOf(verified: VerifiedAddWalletAuthMethodInputV1): WalletAuthMethodFamilyV1 {
  return addWalletAuthMethodTargetFamily(verified.branch);
}
void familyOf;
