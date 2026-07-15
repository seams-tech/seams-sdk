import type {
  EmailOtpEd25519YaoRecoveryInputV1,
  EmailOtpEd25519YaoRegistrationInputV1,
} from './ed25519YaoActivation';

declare const registration: EmailOtpEd25519YaoRegistrationInputV1;
declare const recovery: EmailOtpEd25519YaoRecoveryInputV1;

registration.rootHandle.purpose satisfies 'registration' | 'recovery';
recovery.rootHandle.purpose satisfies 'registration' | 'recovery';

const invalidAuthority = {
  kind: 'email_otp_ed25519_yao_registration_input_v1',
  authority: {
    kind: 'verified_email_otp_ed25519_yao_authority_v1',
    walletId: 'wallet.testnet',
    providerSubject: 'google:subject',
    registrationAuthorityId: 'authority-1',
  },
  rootHandle: registration.rootHandle,
  admissionRequest: registration.admissionRequest,
  transport: registration.transport,
  nowMs: 1,
};
// @ts-expect-error A verified Email OTP authority requires its bearer token.
invalidAuthority satisfies EmailOtpEd25519YaoRegistrationInputV1;
