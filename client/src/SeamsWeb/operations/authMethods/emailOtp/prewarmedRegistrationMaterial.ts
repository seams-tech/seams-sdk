import type { PrepareEmailOtpRegistrationEnrollmentMaterialInternalResult } from '@/core/signingEngine/flows/signEvmFamily/emailOtpPublic';
import type { EmailOtpRegistrationAuthMethodInput } from '@shared/utils/registrationIntent';

const PREWARMED_EMAIL_OTP_REGISTRATION_MATERIAL = Symbol(
  'prewarmedEmailOtpRegistrationMaterial',
);

export type EmailOtpPrewarmedRegistrationMaterial = {
  kind: 'email_otp_prewarmed_registration_material_v1';
  offerId: string;
  candidateId: string;
  walletId: string;
  providerSubject: string;
  material: PrepareEmailOtpRegistrationEnrollmentMaterialInternalResult;
};

type EmailOtpRegistrationAuthMethodWithPrewarmedMaterial =
  EmailOtpRegistrationAuthMethodInput & {
    [PREWARMED_EMAIL_OTP_REGISTRATION_MATERIAL]?: EmailOtpPrewarmedRegistrationMaterial;
  };

export type EmailOtpRegistrationEnrollmentMaterial =
  PrepareEmailOtpRegistrationEnrollmentMaterialInternalResult;

export function attachEmailOtpPrewarmedRegistrationMaterial(input: {
  authMethod: EmailOtpRegistrationAuthMethodInput;
  prewarmed: EmailOtpPrewarmedRegistrationMaterial;
}): EmailOtpRegistrationAuthMethodInput {
  return Object.assign({}, input.authMethod, {
    [PREWARMED_EMAIL_OTP_REGISTRATION_MATERIAL]: input.prewarmed,
  });
}

export function readEmailOtpPrewarmedRegistrationMaterial(
  authMethod: EmailOtpRegistrationAuthMethodInput,
): EmailOtpPrewarmedRegistrationMaterial | null {
  return (
    (authMethod as EmailOtpRegistrationAuthMethodWithPrewarmedMaterial)[
      PREWARMED_EMAIL_OTP_REGISTRATION_MATERIAL
    ] || null
  );
}

export function disposeEmailOtpPrewarmedRegistrationMaterial(
  prewarmed: EmailOtpPrewarmedRegistrationMaterial | null | undefined,
): void {
  if (!prewarmed) return;
  const recoveryKeys = prewarmed.material.recoveryKeys as unknown as string[];
  for (let i = 0; i < recoveryKeys.length; i += 1) {
    recoveryKeys[i] = '';
  }
  prewarmed.material.emailOtpEnrollment.recoveryWrappedEnrollmentEscrows.length = 0;
}
