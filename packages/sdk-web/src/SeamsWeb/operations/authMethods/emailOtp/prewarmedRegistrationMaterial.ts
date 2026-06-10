import type { PrepareEmailOtpRegistrationEnrollmentMaterialInternalResult } from '@/core/signingEngine/flows/signEvmFamily/emailOtpPublic';
import type { EmailOtpRegistrationAuthMethodInput } from '@shared/utils/registrationIntent';

const PREWARMED_EMAIL_OTP_REGISTRATION_MATERIAL = Symbol(
  'prewarmedEmailOtpRegistrationMaterial',
);

export type ActiveEmailOtpPrewarmedRegistrationMaterial = {
  kind: 'email_otp_prewarmed_registration_material_v1';
  state: 'active';
  offerId: string;
  candidateId: string;
  walletId: string;
  providerSubject: string;
  material: PrepareEmailOtpRegistrationEnrollmentMaterialInternalResult;
};

export type DisposedEmailOtpPrewarmedRegistrationMaterial = Omit<
  ActiveEmailOtpPrewarmedRegistrationMaterial,
  'state' | 'material'
> & {
  state: 'disposed';
  disposedAtMs: number;
  material?: never;
};

export type EmailOtpPrewarmedRegistrationMaterial =
  | ActiveEmailOtpPrewarmedRegistrationMaterial
  | DisposedEmailOtpPrewarmedRegistrationMaterial;

type EmailOtpRegistrationAuthMethodWithPrewarmedMaterial =
  EmailOtpRegistrationAuthMethodInput & {
    [PREWARMED_EMAIL_OTP_REGISTRATION_MATERIAL]?: EmailOtpPrewarmedRegistrationMaterial;
  };

export type EmailOtpRegistrationEnrollmentMaterial =
  PrepareEmailOtpRegistrationEnrollmentMaterialInternalResult;

function dropReadonlyArrayReferences(value: readonly unknown[]): void {
  (value as unknown[]).length = 0;
}

export function attachEmailOtpPrewarmedRegistrationMaterial(input: {
  authMethod: EmailOtpRegistrationAuthMethodInput;
  prewarmed: ActiveEmailOtpPrewarmedRegistrationMaterial;
}): EmailOtpRegistrationAuthMethodInput {
  return Object.assign({}, input.authMethod, {
    [PREWARMED_EMAIL_OTP_REGISTRATION_MATERIAL]: input.prewarmed,
  });
}

export function readEmailOtpPrewarmedRegistrationMaterial(
  authMethod: EmailOtpRegistrationAuthMethodInput,
): ActiveEmailOtpPrewarmedRegistrationMaterial | null {
  const prewarmed =
    (authMethod as EmailOtpRegistrationAuthMethodWithPrewarmedMaterial)[
      PREWARMED_EMAIL_OTP_REGISTRATION_MATERIAL
    ] || null;
  return prewarmed?.state === 'active' ? prewarmed : null;
}

export function disposeEmailOtpPrewarmedRegistrationMaterial(
  prewarmed: EmailOtpPrewarmedRegistrationMaterial | null | undefined,
): void {
  if (!prewarmed || prewarmed.state === 'disposed') return;
  dropReadonlyArrayReferences(prewarmed.material.recoveryKeys);
  prewarmed.material.emailOtpEnrollment.recoveryWrappedEnrollmentEscrows.length = 0;
  // JavaScript strings cannot be reliably zeroized; this drops SDK-held references.
  const mutable = prewarmed as unknown as {
    state: 'disposed';
    disposedAtMs: number;
    material?: PrepareEmailOtpRegistrationEnrollmentMaterialInternalResult;
  };
  delete mutable.material;
  mutable.state = 'disposed';
  mutable.disposedAtMs = Date.now();
}
