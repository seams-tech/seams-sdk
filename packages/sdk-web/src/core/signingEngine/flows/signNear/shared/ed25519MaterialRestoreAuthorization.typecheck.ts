import type {
  NearEd25519EmailOtpMaterialRestoreAuthorization,
  NearEd25519EmailOtpRecoveryCodeUnsealAuthorization,
} from '@/core/signingEngine/interfaces/near';
import type { RouterAbEd25519WorkerMaterialRestoreAuthorization } from './ed25519SigningMaterialReadiness';

const recoveryCodeUnsealAuthorization: NearEd25519EmailOtpRecoveryCodeUnsealAuthorization = {
  kind: 'recovery_code_material_authorization_handle_v1',
  handle: 'recovery-code-unseal-handle',
  purpose: 'unseal',
  authSubjectId: 'auth-subject',
  recoveryCodeBindingDigest: 'recovery-code-binding',
  materialBindingDigest: 'material-binding',
  expiresAtMs: 1_900_000_000_000,
};

const emailOtpRestoreAuthorization: NearEd25519EmailOtpMaterialRestoreAuthorization = {
  kind: 'ed25519_email_otp_material_unseal_authorization_available',
  unsealAuthorization: recoveryCodeUnsealAuthorization,
};
void emailOtpRestoreAuthorization;

const routerAbRestoreAuthorization: RouterAbEd25519WorkerMaterialRestoreAuthorization = {
  kind: 'unseal_authorization_available',
  unsealAuthorization: recoveryCodeUnsealAuthorization,
};
void routerAbRestoreAuthorization;

const unavailableEmailOtpRestoreAuthorization: NearEd25519EmailOtpMaterialRestoreAuthorization = {
  kind: 'ed25519_email_otp_material_unseal_authorization_unavailable',
  reason: 'no_recovery_code_material',
};
void unavailableEmailOtpRestoreAuthorization;

const invalidEmailOtpRestoreWithRecoverySecret = {
  kind: 'ed25519_email_otp_material_unseal_authorization_available',
  unsealAuthorization: recoveryCodeUnsealAuthorization,
  // @ts-expect-error Email OTP restore authorization must carry handles, not recovery-code secrets.
  recoveryCodeSecret32B64u: 'raw-recovery-code-secret',
} satisfies NearEd25519EmailOtpMaterialRestoreAuthorization;
void invalidEmailOtpRestoreWithRecoverySecret;

const invalidEmailOtpRestoreWithPrfBytes = {
  kind: 'ed25519_email_otp_material_unseal_authorization_available',
  unsealAuthorization: recoveryCodeUnsealAuthorization,
  // @ts-expect-error Email OTP restore authorization must not carry passkey PRF bytes.
  prfFirstBytes: new Uint8Array(32),
} satisfies NearEd25519EmailOtpMaterialRestoreAuthorization;
void invalidEmailOtpRestoreWithPrfBytes;

const invalidRouterAbRestoreWithRecoverySecret = {
  kind: 'unseal_authorization_available',
  unsealAuthorization: recoveryCodeUnsealAuthorization,
  // @ts-expect-error Router A/B restore authorization must carry opaque handles only.
  recoveryCodeSecret32: new Uint8Array(32),
} satisfies RouterAbEd25519WorkerMaterialRestoreAuthorization;
void invalidRouterAbRestoreWithRecoverySecret;

const invalidRouterAbRestoreWithPrfBytes = {
  kind: 'unseal_authorization_available',
  unsealAuthorization: recoveryCodeUnsealAuthorization,
  // @ts-expect-error Router A/B restore authorization must not carry raw PRF bytes.
  prfFirstBytes: new Uint8Array(32),
} satisfies RouterAbEd25519WorkerMaterialRestoreAuthorization;
void invalidRouterAbRestoreWithPrfBytes;

export {};
