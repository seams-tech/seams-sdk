import {
  prepareThresholdEd25519RecoveryCodeWorkerMaterialSealAuthorizationNearSignerWasm,
  prepareThresholdEd25519RecoveryCodeWorkerMaterialUnsealAuthorizationNearSignerWasm,
} from '@/core/signingEngine/chains/near/nearSignerWasm';
import { deriveThresholdEd25519HssClientInputsWasm } from '@/core/signingEngine/threshold/crypto/hssClientSignerWasm';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import type {
  ThresholdEd25519PrepareWorkerMaterialSealAuthorizationResult,
  ThresholdEd25519PrepareWorkerMaterialUnsealAuthorizationResult,
  ThresholdEd25519WorkerMaterialBindingInputWithoutVerifier,
} from '@/core/types/signer-worker';
import { alphabetizeStringify, sha256BytesUtf8 } from '@shared/utils/digests';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';

const WORKER_DEFAULT_MATERIAL_AUTHORIZATION_EXPIRES_AT_MS = 0;

export type EmailOtpEd25519RegistrationClientSecretSource = {
  kind: 'email_otp_registration_ed25519_recovery_code_secret_source';
  registrationAttemptId: string;
  walletId: string;
  authSubjectId: string;
  recoveryCodeSecret32B64u: string;
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
  thresholdEd25519RecoveryCodeSecret32B64u: string;
}): EmailOtpEd25519RegistrationClientSecretSource {
  return {
    kind: 'email_otp_registration_ed25519_recovery_code_secret_source',
    registrationAttemptId: requireTrimmedString(
      args.registrationAttemptId,
      'registrationAttemptId',
    ),
    walletId: requireTrimmedString(args.walletId, 'walletId'),
    authSubjectId: requireTrimmedString(args.authSubjectId, 'authSubjectId'),
    recoveryCodeSecret32B64u: requireTrimmedString(
      args.thresholdEd25519RecoveryCodeSecret32B64u,
      'thresholdEd25519RecoveryCodeSecret32B64u',
    ),
  };
}

export const EMAIL_OTP_ED25519_RECOVERY_CODE_BINDING_DIGEST_KIND =
  'email_otp_ed25519_recovery_code_binding_v1' as const;

export async function recoveryCodeBindingDigestForEmailOtpMaterial(args: {
  authSubjectId: string;
  rpId: string;
  nearAccountId: string;
}): Promise<string> {
  const authSubjectId = String(args.authSubjectId || '').trim();
  const rpId = String(args.rpId || '').trim();
  const nearAccountId = String(args.nearAccountId || '').trim();
  if (!authSubjectId || !rpId || !nearAccountId) {
    throw new Error('Email OTP threshold-ed25519 recovery-code binding is incomplete');
  }
  return base64UrlEncode(
    await sha256BytesUtf8(
      alphabetizeStringify({
        authSubjectId,
        kind: EMAIL_OTP_ED25519_RECOVERY_CODE_BINDING_DIGEST_KIND,
        nearAccountId,
        rpId,
      }),
    ),
  );
}

export async function deriveThresholdEd25519HssClientInputsFromEmailOtpRecoveryCode(args: {
  sessionId: string;
  signingRootId: string;
  nearAccountId: string;
  keyPurpose: string;
  keyVersion: string;
  participantIds: number[];
  derivationVersion: number;
  recoveryCodeSecret32B64u: string;
  workerCtx: WorkerOperationContext;
}): ReturnType<typeof deriveThresholdEd25519HssClientInputsWasm> {
  return await deriveThresholdEd25519HssClientInputsWasm({
    sessionId: args.sessionId,
    signingRootId: args.signingRootId,
    nearAccountId: args.nearAccountId,
    keyPurpose: args.keyPurpose,
    keyVersion: args.keyVersion,
    participantIds: args.participantIds,
    derivationVersion: args.derivationVersion,
    prfFirstB64u: args.recoveryCodeSecret32B64u,
    workerCtx: args.workerCtx,
  });
}

function zeroizeSecretBytes(bytes?: Uint8Array | null): void {
  if (bytes instanceof Uint8Array) bytes.fill(0);
}

function decodeMaterialAuthorizationSecret32B64u(value: string, fieldName: string): Uint8Array {
  const normalized = String(value || '').trim();
  if (!normalized) {
    throw new Error(`${fieldName} is required for Ed25519 material authorization`);
  }
  const decoded = base64UrlDecode(normalized);
  if (decoded.length !== 32) {
    zeroizeSecretBytes(decoded);
    throw new Error(`${fieldName} must decode to 32 bytes`);
  }
  return decoded;
}

export async function prepareRecoveryCodeSealAuthorizationForEmailOtp(args: {
  bindingInput: ThresholdEd25519WorkerMaterialBindingInputWithoutVerifier;
  authSubjectId: string;
  recoveryCodeBindingDigest: string;
  recoveryCodeSecret32B64u: string;
  workerCtx: WorkerOperationContext;
}): Promise<ThresholdEd25519PrepareWorkerMaterialSealAuthorizationResult> {
  const recoveryCodeSecret32 = decodeMaterialAuthorizationSecret32B64u(
    args.recoveryCodeSecret32B64u,
    'recoveryCodeSecret32B64u',
  );
  try {
    return await prepareThresholdEd25519RecoveryCodeWorkerMaterialSealAuthorizationNearSignerWasm({
      request: {
        bindingInput: args.bindingInput,
        authSubjectId: args.authSubjectId,
        recoveryCodeBindingDigest: args.recoveryCodeBindingDigest,
        recoveryCodeSecret32,
        expiresAtMs: WORKER_DEFAULT_MATERIAL_AUTHORIZATION_EXPIRES_AT_MS,
      },
      workerCtx: args.workerCtx,
    });
  } finally {
    zeroizeSecretBytes(recoveryCodeSecret32);
  }
}

export async function prepareRecoveryCodeUnsealAuthorizationForEmailOtp(args: {
  materialBindingDigest: string;
  authSubjectId: string;
  recoveryCodeBindingDigest: string;
  recoveryCodeSecret32B64u: string;
  expiresAtMs: number;
  workerCtx: WorkerOperationContext;
}): Promise<ThresholdEd25519PrepareWorkerMaterialUnsealAuthorizationResult> {
  const recoveryCodeSecret32 = decodeMaterialAuthorizationSecret32B64u(
    args.recoveryCodeSecret32B64u,
    'recoveryCodeSecret32B64u',
  );
  try {
    return await prepareThresholdEd25519RecoveryCodeWorkerMaterialUnsealAuthorizationNearSignerWasm(
      {
        request: {
          materialBindingDigest: String(args.materialBindingDigest || '').trim(),
          authSubjectId: args.authSubjectId,
          recoveryCodeBindingDigest: args.recoveryCodeBindingDigest,
          recoveryCodeSecret32,
          expiresAtMs: args.expiresAtMs,
        },
        workerCtx: args.workerCtx,
      },
    );
  } finally {
    zeroizeSecretBytes(recoveryCodeSecret32);
  }
}
