export type EmailOtpEd25519RegistrationClientSecretSource = {
  kind: 'email_otp_registration_ed25519_hss_client_secret_source';
  registrationAttemptId: string;
  walletId: string;
  authSubjectId: string;
  prfFirstB64u: string;
};

export type EmailOtpEcdsaRoleLocalRegistrationClientSecretSource = {
  kind: 'email_otp_registration_ecdsa_role_local_client_secret_source';
  registrationAttemptId: string;
  walletId: string;
  authSubjectId: string;
  clientRootShare32B64u: string;
};

function requireTrimmedString(value: unknown, label: string): string {
  const normalized = String(value ?? '').trim();
  if (!normalized) {
    throw new Error(`${label} is required for Email OTP Ed25519 registration client secret source`);
  }
  return normalized;
}

export function buildEmailOtpEd25519RegistrationClientSecretSource(args: {
  registrationAttemptId: string;
  walletId: string;
  authSubjectId: string;
  thresholdEd25519PrfFirstB64u: string;
}): EmailOtpEd25519RegistrationClientSecretSource {
  return {
    kind: 'email_otp_registration_ed25519_hss_client_secret_source',
    registrationAttemptId: requireTrimmedString(args.registrationAttemptId, 'registrationAttemptId'),
    walletId: requireTrimmedString(args.walletId, 'walletId'),
    authSubjectId: requireTrimmedString(args.authSubjectId, 'authSubjectId'),
    prfFirstB64u: requireTrimmedString(args.thresholdEd25519PrfFirstB64u, 'prfFirstB64u'),
  };
}

export function buildEmailOtpEcdsaRoleLocalRegistrationClientSecretSource(args: {
  registrationAttemptId: string;
  walletId: string;
  authSubjectId: string;
  clientRootShare32B64u: string;
}): EmailOtpEcdsaRoleLocalRegistrationClientSecretSource {
  return {
    kind: 'email_otp_registration_ecdsa_role_local_client_secret_source',
    registrationAttemptId: requireTrimmedString(args.registrationAttemptId, 'registrationAttemptId'),
    walletId: requireTrimmedString(args.walletId, 'walletId'),
    authSubjectId: requireTrimmedString(args.authSubjectId, 'authSubjectId'),
    clientRootShare32B64u: requireTrimmedString(args.clientRootShare32B64u, 'clientRootShare32B64u'),
  };
}
