/**
 * Refactor 94C. Compile-time proof that the three-route request unions make
 * invalid registrations unrepresentable.
 *
 * These are the states a single object type with required `ecdsa` allowed and
 * shouldn't have: an Ed25519-only request carrying ECDSA work it has none of,
 * an ECDSA request missing the work it cannot run without, and Email OTP
 * enrollment attached to — or missing from — the wrong auth branch.
 *
 * Every `@ts-expect-error` here fails the build if the union ever stops
 * rejecting that shape.
 */

import type {
  ActivateEcdsaWorkV2,
  RespondEcdsaRegistrationWorkV2,
  WalletRegistrationActivateRequestV2,
  WalletRegistrationRespondRequestV2,
} from './threeRouteRegistrationContracts';

declare const signedSetup: WalletRegistrationRespondRequestV2['signedSetup'];
declare const webauthnRegistration: Extract<
  WalletRegistrationRespondRequestV2,
  { webauthn_registration: unknown }
>['webauthn_registration'];
declare const idempotencyKey: WalletRegistrationActivateRequestV2['idempotencyKey'];
/* Pre-typed so the fixtures below fail on the property that should be
   rejected, not on an incidental mismatch inside a nested literal. */
declare const respondEcdsa: RespondEcdsaRegistrationWorkV2;
declare const activateEcdsa: ActivateEcdsaWorkV2;
declare const emailOtpEnrollment: NonNullable<
  Extract<WalletRegistrationActivateRequestV2, { authMethod: 'email_otp' }>['emailOtpEnrollment']
>;

const RESPOND_BASE = {
  registrationCeremonyId: 'wrc_1',
  signedSetup,
  webauthn_registration: webauthnRegistration,
} as const;
const ACTIVATE_BASE = { registrationCeremonyId: 'wrc_1', signedSetup, idempotencyKey } as const;

/* --- valid shapes compile --- */

const ecdsaRespond: WalletRegistrationRespondRequestV2 = {
  ...RESPOND_BASE,
  kind: 'evm_family_ecdsa',
  ecdsa: respondEcdsa,
};

const ed25519OnlyRespond: WalletRegistrationRespondRequestV2 = {
  ...RESPOND_BASE,
  kind: 'near_ed25519',
};

const passkeyEcdsaActivate: WalletRegistrationActivateRequestV2 = {
  ...ACTIVATE_BASE,
  authMethod: 'passkey',
  kind: 'evm_family_ecdsa',
  ecdsa: activateEcdsa,
};

const emailOtpEd25519OnlyActivate: WalletRegistrationActivateRequestV2 = {
  ...ACTIVATE_BASE,
  authMethod: 'email_otp',
  emailOtpEnrollment,
  /* Enrollment is an auth concern, not an ECDSA one: an Ed25519-only wallet
     registered with Email OTP still enrolls. */
  kind: 'near_ed25519',
};

/* --- invalid shapes must not compile --- */

// An Ed25519-only ceremony has no ECDSA registration to send.
// @ts-expect-error Ed25519-only respond must not accept `ecdsa`
const ed25519RespondWithEcdsa: WalletRegistrationRespondRequestV2 = {
  ...RESPOND_BASE,
  kind: 'near_ed25519',
  ecdsa: respondEcdsa,
};

// @ts-expect-error Ed25519-only activate must not accept `ecdsa`
const ed25519ActivateWithEcdsa: WalletRegistrationActivateRequestV2 = {
  ...ACTIVATE_BASE,
  authMethod: 'passkey',
  kind: 'near_ed25519',
  ecdsa: activateEcdsa,
};

// @ts-expect-error an ECDSA respond cannot omit the registration it must forward
const ecdsaRespondWithoutEcdsa: WalletRegistrationRespondRequestV2 = {
  ...RESPOND_BASE,
  kind: 'evm_family_ecdsa',
};

// @ts-expect-error an ECDSA activate cannot omit the browser-verified activation
const ecdsaActivateWithoutEcdsa: WalletRegistrationActivateRequestV2 = {
  ...ACTIVATE_BASE,
  authMethod: 'passkey',
  kind: 'evm_family_ecdsa',
};

// @ts-expect-error passkey activation has no enrollment to carry
const passkeyActivateWithEnrollment: WalletRegistrationActivateRequestV2 = {
  ...ACTIVATE_BASE,
  authMethod: 'passkey',
  emailOtpEnrollment,
  kind: 'evm_family_ecdsa',
  ecdsa: activateEcdsa,
};

// @ts-expect-error Email OTP activation requires its enrollment material
const emailOtpActivateWithoutEnrollment: WalletRegistrationActivateRequestV2 = {
  ...ACTIVATE_BASE,
  authMethod: 'email_otp',
  kind: 'evm_family_ecdsa',
  ecdsa: activateEcdsa,
};

export type {
  WalletRegistrationActivateRequestV2 as _ActivateRequest,
  WalletRegistrationRespondRequestV2 as _RespondRequest,
};
export const _threeRouteRequestFixtures = [
  ecdsaRespond,
  ed25519OnlyRespond,
  passkeyEcdsaActivate,
  emailOtpEd25519OnlyActivate,
  ed25519RespondWithEcdsa,
  ed25519ActivateWithEcdsa,
  ecdsaRespondWithoutEcdsa,
  ecdsaActivateWithoutEcdsa,
  passkeyActivateWithEnrollment,
  emailOtpActivateWithoutEnrollment,
] as const;
