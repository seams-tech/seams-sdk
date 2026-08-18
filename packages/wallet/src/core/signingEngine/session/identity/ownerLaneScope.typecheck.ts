/**
 * Compile-time contract for OwnerLaneScope (R103C): a Passkey owner scope
 * requires a signer slot, and an Email OTP scope cannot carry one.
 */
import type { OwnerLaneScope } from './signingLaneAuthBinding';
import { toRpId } from './evmFamilyEcdsaIdentity';

const passkeyScope: OwnerLaneScope = {
  auth: {
    kind: 'passkey',
    rpId: toRpId('wallet.example.localhost'),
    credentialIdB64u: 'credential-owner',
  },
  signerSlot: 1,
};
void passkeyScope;

// @ts-expect-error a Passkey owner scope requires its authenticator signer slot
const passkeyScopeWithoutSlot: OwnerLaneScope = {
  auth: {
    kind: 'passkey',
    rpId: toRpId('wallet.example.localhost'),
    credentialIdB64u: 'credential-owner',
  },
};
void passkeyScopeWithoutSlot;

const emailOtpScope: OwnerLaneScope = {
  auth: { kind: 'email_otp', providerSubjectId: 'provider-subject' },
};
void emailOtpScope;

// @ts-expect-error an Email OTP owner scope has no local authenticator and no slot
const emailOtpScopeWithSlot: OwnerLaneScope = {
  auth: { kind: 'email_otp', providerSubjectId: 'provider-subject' },
  signerSlot: 1,
};
void emailOtpScopeWithSlot;
