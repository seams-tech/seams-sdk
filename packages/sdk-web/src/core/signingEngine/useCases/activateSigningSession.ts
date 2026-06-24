import type { ClockPort } from '@/core/platform';
import { thresholdEcdsaChainTargetsEqual } from '../interfaces/ecdsaChainTarget';
import {
  assertNeverUseCase,
  useCaseFailure,
  type ActivateSigningSessionFailureCode,
  type ActivateSigningSessionInput,
  type ActivateSigningSessionLifecycleState,
  type ActivateSigningSessionResult,
  type ActivateSigningSessionSuccess,
  type NonEmptyReadonlyArray,
  type SigningSessionActivationAuth,
  type SigningSessionActivationEmailOtpEcdsaAuth,
  type SigningSessionActivationEmailOtpEd25519Auth,
  type SigningSessionActivationMaterial,
  type SigningSessionActivationPasskeyAuth,
  type SigningSessionSealWriteInput,
  type UnixTimeMs,
  type UseCaseFailure,
  type WarmSessionRemainingUses,
} from './lifecycle';

export type ActivateSigningSessionFailure = UseCaseFailure<ActivateSigningSessionFailureCode>;

export type ActivateSigningSessionSealPolicyInput = {
  walletId: ActivateSigningSessionInput['walletId'];
  walletKeyId: ActivateSigningSessionInput['walletKeyId'];
  rpId: ActivateSigningSessionInput['rpId'];
  auth: SigningSessionActivationAuth;
  material: SigningSessionActivationMaterial;
  nowMs: number;
};

export type ActivateSigningSessionSealPolicySuccess = {
  ok: true;
  expiresAtMs: UnixTimeMs;
  remainingUses: WarmSessionRemainingUses;
  code?: never;
  message?: never;
  retryable?: never;
};

export type ActivateSigningSessionSealPolicyFailureCode = Extract<
  ActivateSigningSessionFailureCode,
  'session_expired' | 'invalid_state'
>;

export type ActivateSigningSessionSealPolicyResult =
  | ActivateSigningSessionSealPolicySuccess
  | UseCaseFailure<ActivateSigningSessionSealPolicyFailureCode>;

export type ActivateSigningSessionSealWriteFailureCode = Extract<
  ActivateSigningSessionFailureCode,
  'seal_failed' | 'storage_failed'
>;

export type ActivateSigningSessionSealWriteResult =
  | { ok: true; code?: never; message?: never; retryable?: never }
  | UseCaseFailure<ActivateSigningSessionSealWriteFailureCode>;

export type ActivateSigningSessionDeps = {
  clock: Pick<ClockPort, 'nowMs'>;
  sealPolicy: {
    resolve(
      input: ActivateSigningSessionSealPolicyInput,
    ): ActivateSigningSessionSealPolicyResult | Promise<ActivateSigningSessionSealPolicyResult>;
  };
  sealWriter: {
    write(
      input: SigningSessionSealWriteInput,
    ): ActivateSigningSessionSealWriteResult | Promise<ActivateSigningSessionSealWriteResult>;
  };
  lifecycle?: {
    transition(state: ActivateSigningSessionLifecycleState): void | Promise<void>;
  };
};

export type ActivateSigningSessionUseCase = {
  activate(input: ActivateSigningSessionInput): Promise<ActivateSigningSessionResult>;
};

export function createActivateSigningSessionUseCase(
  deps: ActivateSigningSessionDeps,
): ActivateSigningSessionUseCase {
  return {
    activate: (input) => activateSigningSession(deps, input),
  };
}

function sameString(left: unknown, right: unknown): boolean {
  return String(left || '').trim() === String(right || '').trim();
}

function toNonEmptyReadonlyArray<T>(items: readonly T[]): NonEmptyReadonlyArray<T> | null {
  const first = items[0];
  if (first === undefined) return null;
  return [first, ...items.slice(1)];
}

function failure(input: {
  code: ActivateSigningSessionFailureCode;
  source: ActivateSigningSessionFailure['source'];
  message: string;
  retryable: boolean;
  cause?: unknown;
}): ActivateSigningSessionFailure {
  return useCaseFailure(input);
}

function failureFromUseCaseFailure(
  input: UseCaseFailure<ActivateSigningSessionFailureCode>,
): ActivateSigningSessionFailure {
  return failure({
    code: input.code,
    source: input.source,
    message: input.message,
    retryable: input.retryable,
    ...(input.cause === undefined ? {} : { cause: input.cause }),
  });
}

async function emit(
  deps: ActivateSigningSessionDeps,
  state: ActivateSigningSessionLifecycleState,
): Promise<void> {
  await deps.lifecycle?.transition(state);
}

async function emitFailure(
  deps: ActivateSigningSessionDeps,
  result: ActivateSigningSessionFailure,
): Promise<ActivateSigningSessionFailure> {
  const state =
    result.cause === undefined
      ? {
          kind: 'failed' as const,
          ok: false as const,
          code: result.code,
          source: result.source,
          message: result.message,
          retryable: result.retryable,
        }
      : {
          kind: 'failed' as const,
          ok: false as const,
          code: result.code,
          source: result.source,
          message: result.message,
          retryable: result.retryable,
          cause: result.cause,
        };
  await emit(deps, state);
  return result;
}

function isPasskeyAuth(
  auth: SigningSessionActivationAuth,
): auth is SigningSessionActivationPasskeyAuth {
  return auth.kind === 'passkey';
}

function isEmailOtpEd25519Auth(
  auth: SigningSessionActivationAuth,
): auth is SigningSessionActivationEmailOtpEd25519Auth {
  return auth.kind === 'email_otp' && auth.workerHandle.action === 'threshold_ed25519_session';
}

function isEmailOtpEcdsaAuth(
  auth: SigningSessionActivationAuth,
): auth is SigningSessionActivationEmailOtpEcdsaAuth {
  return auth.kind === 'email_otp' && auth.workerHandle.action === 'threshold_ecdsa_bootstrap';
}

function validateAuthMatchesInput(
  input: ActivateSigningSessionInput,
): ActivateSigningSessionFailure | null {
  if (!sameString(input.auth.walletId, input.walletId)) {
    return failure({
      code: 'auth_branch_mismatch',
      source: 'domain',
      message: 'Signing-session activation auth does not match the requested wallet',
      retryable: false,
    });
  }
  if (input.auth.kind === 'passkey') {
    if (sameString(input.auth.rpId, input.rpId)) return null;
    return failure({
      code: 'auth_branch_mismatch',
      source: 'domain',
      message: 'Passkey activation auth does not match the requested RP',
      retryable: false,
    });
  }

  const handle = input.auth.workerHandle;
  if (!sameString(handle.walletId, input.walletId)) {
    return failure({
      code: 'auth_branch_mismatch',
      source: 'domain',
      message: 'Email OTP activation handle does not match the requested wallet',
      retryable: false,
    });
  }
  if (!sameString(handle.authSubjectId, input.auth.authSubjectId)) {
    return failure({
      code: 'auth_branch_mismatch',
      source: 'domain',
      message: 'Email OTP activation handle does not match the requested auth subject',
      retryable: false,
    });
  }
  if (isEmailOtpEd25519Auth(input.auth)) {
    if (sameString(input.auth.rpId, input.rpId) && sameString(handle.rpId, input.rpId)) {
      return null;
    }
    return failure({
      code: 'auth_branch_mismatch',
      source: 'domain',
      message: 'Email OTP Ed25519 activation handle does not match the requested RP',
      retryable: false,
    });
  }
  if (isEmailOtpEcdsaAuth(input.auth)) {
    if (
      sameString(input.auth.walletKeyId, input.walletKeyId) &&
      sameString(handle.walletKeyId, input.walletKeyId)
    ) {
      return null;
    }
    return failure({
      code: 'auth_branch_mismatch',
      source: 'domain',
      message: 'Email OTP ECDSA activation handle does not match the requested wallet key',
      retryable: false,
    });
  }
  input.auth satisfies never;
  throw new Error('Unsupported signing-session activation auth branch');
}

function validateEcdsaRecordMatchesInput(args: {
  input: ActivateSigningSessionInput;
  material: Extract<SigningSessionActivationMaterial, { kind: 'ecdsa_session' }>;
}): ActivateSigningSessionFailure | null {
  const facts = args.material.record.publicFacts;
  if (
    !sameString(facts.walletId, args.input.walletId) ||
    !sameString(facts.walletKeyId, args.input.walletKeyId)
  ) {
    return failure({
      code: 'material_branch_mismatch',
      source: 'domain',
      message: 'ECDSA activation material does not match the requested wallet key',
      retryable: false,
    });
  }
  return null;
}

function validatePasskeyEcdsaMaterial(args: {
  auth: SigningSessionActivationPasskeyAuth;
  material: Extract<SigningSessionActivationMaterial, { kind: 'ecdsa_session' }>;
}): ActivateSigningSessionFailure | null {
  const record = args.material.record;
  if (
    record.authMethod.kind !== 'passkey' ||
    !sameString(record.authMethod.credentialIdB64u, args.auth.credentialIdB64u) ||
    !sameString(record.authMethod.rpId, args.auth.rpId)
  ) {
    return failure({
      code: 'auth_branch_mismatch',
      source: 'domain',
      message: 'Passkey activation auth does not match the ECDSA ready record',
      retryable: false,
    });
  }
  return null;
}

function validateEmailOtpEcdsaMaterial(args: {
  auth: SigningSessionActivationEmailOtpEcdsaAuth;
  material: Extract<SigningSessionActivationMaterial, { kind: 'ecdsa_session' }>;
}): ActivateSigningSessionFailure | null {
  const record = args.material.record;
  if (
    record.authMethod.kind !== 'email_otp' ||
    !sameString(record.authMethod.authSubjectId, args.auth.authSubjectId)
  ) {
    return failure({
      code: 'auth_branch_mismatch',
      source: 'domain',
      message: 'Email OTP activation auth does not match the ECDSA ready record',
      retryable: false,
    });
  }
  if (
    !thresholdEcdsaChainTargetsEqual(
      args.auth.workerHandle.chainTarget,
      record.publicFacts.chainTarget,
    )
  ) {
    return failure({
      code: 'auth_branch_mismatch',
      source: 'domain',
      message: 'Email OTP ECDSA activation handle does not match the ready-record chain target',
      retryable: false,
    });
  }
  return null;
}

function validatePolicySuccess(args: {
  policy: ActivateSigningSessionSealPolicySuccess;
  nowMs: number;
}): ActivateSigningSessionFailure | null {
  if (Number(args.policy.expiresAtMs) <= args.nowMs) {
    return failure({
      code: 'session_expired',
      source: 'budget',
      message: 'Signing-session activation policy produced an expired seal budget',
      retryable: false,
    });
  }
  if (Number(args.policy.remainingUses) <= 0) {
    return failure({
      code: 'invalid_state',
      source: 'budget',
      message: 'Signing-session activation policy produced an exhausted seal budget',
      retryable: false,
    });
  }
  return null;
}

function buildSealWrite(args: {
  auth: SigningSessionActivationAuth;
  material: SigningSessionActivationMaterial;
  expiresAtMs: UnixTimeMs;
  remainingUses: WarmSessionRemainingUses;
}): SigningSessionSealWriteInput | ActivateSigningSessionFailure {
  switch (args.material.kind) {
    case 'ed25519_session':
      if (isPasskeyAuth(args.auth)) {
        return {
          kind: 'passkey_ed25519_seal_write_v1',
          auth: args.auth,
          material: args.material,
          expiresAtMs: args.expiresAtMs,
          remainingUses: args.remainingUses,
        };
      }
      if (isEmailOtpEd25519Auth(args.auth)) {
        return {
          kind: 'email_otp_ed25519_seal_write_v1',
          auth: args.auth,
          material: args.material,
          expiresAtMs: args.expiresAtMs,
          remainingUses: args.remainingUses,
        };
      }
      return failure({
        code: 'auth_branch_mismatch',
        source: 'domain',
        message: 'Email OTP Ed25519 activation requires an Ed25519 worker-issued handle',
        retryable: false,
      });
    case 'ecdsa_session':
      if (isPasskeyAuth(args.auth)) {
        const mismatch = validatePasskeyEcdsaMaterial({
          auth: args.auth,
          material: args.material,
        });
        if (mismatch) return mismatch;
        return {
          kind: 'passkey_ecdsa_seal_write_v1',
          auth: args.auth,
          material: args.material,
          expiresAtMs: args.expiresAtMs,
          remainingUses: args.remainingUses,
        };
      }
      if (isEmailOtpEcdsaAuth(args.auth)) {
        const mismatch = validateEmailOtpEcdsaMaterial({
          auth: args.auth,
          material: args.material,
        });
        if (mismatch) return mismatch;
        return {
          kind: 'email_otp_ecdsa_seal_write_v1',
          auth: args.auth,
          material: args.material,
          expiresAtMs: args.expiresAtMs,
          remainingUses: args.remainingUses,
        };
      }
      return failure({
        code: 'auth_branch_mismatch',
        source: 'domain',
        message: 'Email OTP ECDSA activation requires an ECDSA worker-issued handle',
        retryable: false,
      });
    default:
      return assertNeverUseCase(args.material);
  }
}

function isFailure(
  result: SigningSessionSealWriteInput | ActivateSigningSessionFailure,
): result is ActivateSigningSessionFailure {
  return 'ok' in result && result.ok === false;
}

async function sealWriteForMaterial(args: {
  deps: ActivateSigningSessionDeps;
  input: ActivateSigningSessionInput;
  material: SigningSessionActivationMaterial;
  nowMs: number;
}): Promise<SigningSessionSealWriteInput | ActivateSigningSessionFailure> {
  if (args.material.kind === 'ecdsa_session') {
    const mismatch = validateEcdsaRecordMatchesInput({
      input: args.input,
      material: args.material,
    });
    if (mismatch) return mismatch;
  }

  const policy = await args.deps.sealPolicy.resolve({
    walletId: args.input.walletId,
    walletKeyId: args.input.walletKeyId,
    rpId: args.input.rpId,
    auth: args.input.auth,
    material: args.material,
    nowMs: args.nowMs,
  });
  if (!policy.ok) return failureFromUseCaseFailure(policy);

  const policyMismatch = validatePolicySuccess({
    policy,
    nowMs: args.nowMs,
  });
  if (policyMismatch) return policyMismatch;

  return buildSealWrite({
    auth: args.input.auth,
    material: args.material,
    expiresAtMs: policy.expiresAtMs,
    remainingUses: policy.remainingUses,
  });
}

async function writeSeals(args: {
  deps: ActivateSigningSessionDeps;
  writes: NonEmptyReadonlyArray<SigningSessionSealWriteInput>;
}): Promise<ActivateSigningSessionFailure | null> {
  for (const write of args.writes) {
    const result = await args.deps.sealWriter.write(write);
    if (!result.ok) return failureFromUseCaseFailure(result);
  }
  return null;
}

export async function activateSigningSession(
  deps: ActivateSigningSessionDeps,
  input: ActivateSigningSessionInput,
): Promise<ActivateSigningSessionResult> {
  await emit(deps, {
    kind: 'received_input',
    walletId: input.walletId,
    walletKeyId: input.walletKeyId,
    rpId: input.rpId,
    auth: input.auth,
    material: input.material,
  });

  const authMismatch = validateAuthMatchesInput(input);
  if (authMismatch) return emitFailure(deps, authMismatch);

  await emit(deps, {
    kind: 'validating_material',
    walletId: input.walletId,
    walletKeyId: input.walletKeyId,
    rpId: input.rpId,
    auth: input.auth,
    material: input.material,
  });

  const nowMs = deps.clock.nowMs();
  const sealWrites: SigningSessionSealWriteInput[] = [];
  for (const material of input.material) {
    const write = await sealWriteForMaterial({ deps, input, material, nowMs });
    if (isFailure(write)) return emitFailure(deps, write);
    sealWrites.push(write);
  }

  const nonEmptySealWrites = toNonEmptyReadonlyArray(sealWrites);
  if (!nonEmptySealWrites) {
    return emitFailure(
      deps,
      failure({
        code: 'invalid_state',
        source: 'domain',
        message: 'Signing-session activation requires at least one material branch',
        retryable: false,
      }),
    );
  }

  await emit(deps, {
    kind: 'writing_seals',
    walletId: input.walletId,
    walletKeyId: input.walletKeyId,
    rpId: input.rpId,
    sealWrites: nonEmptySealWrites,
  });

  const writeFailure = await writeSeals({ deps, writes: nonEmptySealWrites });
  if (writeFailure) return emitFailure(deps, writeFailure);

  const success: ActivateSigningSessionSuccess = {
    ok: true,
    sealedWrites: nonEmptySealWrites,
    activatedMaterials: input.material,
  };
  await emit(deps, {
    kind: 'activated',
    result: success,
  });
  return success;
}
