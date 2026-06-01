import type { ThresholdEcdsaChainTarget } from '../interfaces/ecdsaChainTarget';
import {
  useCaseFailure,
  type NonEmptyReadonlyArray,
  type ReadyEcdsaLane,
  type ReadyEd25519Lane,
  type ReauthRequiredLane,
  type SigningSessionSealWriteInput,
  type UnlockWalletFailureCode,
  type UnlockWalletInput,
  type UnlockWalletLifecycleState,
  type UnlockWalletResult,
  type UnlockWalletSuccess,
  type UseCaseFailure,
  type UseCaseWalletSessionReadiness,
} from './lifecycle';

export type UnlockWalletFailure = UseCaseFailure<UnlockWalletFailureCode>;

export type UnlockWalletAuthResult =
  | { ok: true; code?: never; message?: never; retryable?: never }
  | UseCaseFailure<
      Extract<
        UnlockWalletFailureCode,
        'missing_auth' | 'authenticator_failed' | 'email_otp_failed' | 'invalid_state'
      >
    >;

export type UnlockWalletRestoreResult =
  | {
      ok: true;
      restored: readonly (ReadyEd25519Lane | ReadyEcdsaLane)[];
      reauthRequired: readonly ReauthRequiredLane[];
      missingEcdsaTargets: readonly ThresholdEcdsaChainTarget[];
      sealWrites: readonly SigningSessionSealWriteInput[];
      code?: never;
      message?: never;
      retryable?: never;
    }
  | UseCaseFailure<
      Extract<
        UnlockWalletFailureCode,
        'session_expired' | 'stale_sealed_session' | 'storage_cleanup_failed' | 'invalid_state'
      >
    >;

export type UnlockWalletProvisionMissingEcdsaResult =
  | {
      ok: true;
      provisioned: readonly ReadyEcdsaLane[];
      sealWrites: readonly SigningSessionSealWriteInput[];
      code?: never;
      message?: never;
      retryable?: never;
    }
  | UseCaseFailure<
      Extract<
        UnlockWalletFailureCode,
        | 'signer_crypto_command_failed'
        | 'signer_crypto_invocation_failed'
        | 'relayer_failed'
        | 'budget_exhausted'
        | 'invalid_state'
      >
    >;

export type UnlockWalletSealWriteResult =
  | { ok: true; code?: never; message?: never; retryable?: never }
  | UseCaseFailure<Extract<UnlockWalletFailureCode, 'storage_cleanup_failed' | 'invalid_state'>>;

export type UnlockWalletReadinessInput = {
  input: UnlockWalletInput;
  restored: readonly (ReadyEd25519Lane | ReadyEcdsaLane)[];
  provisioned: readonly ReadyEcdsaLane[];
  reauthRequired: readonly ReauthRequiredLane[];
};

export type UnlockWalletDeps = {
  authenticator: {
    authenticate(input: UnlockWalletInput): Promise<UnlockWalletAuthResult>;
  };
  sessionRestorer: {
    restore(input: UnlockWalletInput): Promise<UnlockWalletRestoreResult>;
  };
  ecdsaProvisioner: {
    provisionMissing(input: {
      input: UnlockWalletInput;
      missingTargets: NonEmptyReadonlyArray<ThresholdEcdsaChainTarget>;
      restored: readonly (ReadyEd25519Lane | ReadyEcdsaLane)[];
    }): Promise<UnlockWalletProvisionMissingEcdsaResult>;
  };
  sealWriter: {
    writeAll(
      writes: NonEmptyReadonlyArray<SigningSessionSealWriteInput>,
    ): Promise<UnlockWalletSealWriteResult>;
  };
  readiness: {
    resolve(input: UnlockWalletReadinessInput): UseCaseWalletSessionReadiness;
  };
  lifecycle?: {
    transition(state: UnlockWalletLifecycleState): void | Promise<void>;
  };
};

export type UnlockWalletUseCase = {
  unlock(input: UnlockWalletInput): Promise<UnlockWalletResult>;
};

export function createUnlockWalletUseCase(deps: UnlockWalletDeps): UnlockWalletUseCase {
  return {
    unlock: (input) => unlockWallet(deps, input),
  };
}

function toNonEmptyReadonlyArray<T>(items: readonly T[]): NonEmptyReadonlyArray<T> | null {
  const first = items[0];
  if (first === undefined) return null;
  return [first, ...items.slice(1)];
}

function failure(input: {
  code: UnlockWalletFailureCode;
  source: UnlockWalletFailure['source'];
  message: string;
  retryable: boolean;
  cause?: unknown;
}): UnlockWalletFailure {
  return useCaseFailure(input);
}

async function emit(deps: UnlockWalletDeps, state: UnlockWalletLifecycleState): Promise<void> {
  await deps.lifecycle?.transition(state);
}

async function emitFailure(
  deps: UnlockWalletDeps,
  result: UnlockWalletFailure,
): Promise<UnlockWalletFailure> {
  await emit(deps, {
    kind: 'failed',
    ok: false,
    code: result.code,
    source: result.source,
    message: result.message,
    retryable: result.retryable,
    ...(result.cause === undefined ? {} : { cause: result.cause }),
  });
  return result;
}

export async function unlockWallet(
  deps: UnlockWalletDeps,
  input: UnlockWalletInput,
): Promise<UnlockWalletResult> {
  await emit(deps, { kind: 'received_input', ...input });

  await emit(deps, {
    kind: 'authenticating',
    walletId: input.walletId,
    rpId: input.rpId,
    auth: input.auth,
    ecdsaTargets: input.ecdsaTargets,
    idempotencyKey: input.idempotencyKey,
  });
  const auth = await deps.authenticator.authenticate(input);
  if (!auth.ok) return emitFailure(deps, auth);

  await emit(deps, {
    kind: 'restoring_sessions',
    walletId: input.walletId,
    rpId: input.rpId,
    auth: input.auth,
    ecdsaTargets: input.ecdsaTargets,
    idempotencyKey: input.idempotencyKey,
  });
  const restored = await deps.sessionRestorer.restore(input);
  if (!restored.ok) return emitFailure(deps, restored);

  let provisioned: readonly ReadyEcdsaLane[] = [];
  let provisionSealWrites: readonly SigningSessionSealWriteInput[] = [];
  const missingTargets = toNonEmptyReadonlyArray(restored.missingEcdsaTargets);
  if (missingTargets) {
    await emit(deps, {
      kind: 'provisioning_missing_ecdsa',
      walletId: input.walletId,
      rpId: input.rpId,
      restored: restored.restored,
      ecdsaTargets: input.ecdsaTargets,
      idempotencyKey: input.idempotencyKey,
    });
    const missing = await deps.ecdsaProvisioner.provisionMissing({
      input,
      missingTargets,
      restored: restored.restored,
    });
    if (!missing.ok) return emitFailure(deps, missing);
    if (missing.provisioned.length !== missingTargets.length) {
      return emitFailure(
        deps,
        failure({
          code: 'invalid_state',
          source: 'domain',
          message: 'Unlock provisioning did not return every missing ECDSA lane',
          retryable: false,
        }),
      );
    }
    provisioned = missing.provisioned;
    provisionSealWrites = missing.sealWrites;
  }

  const sealedWrites = toNonEmptyReadonlyArray([...restored.sealWrites, ...provisionSealWrites]);
  if (!sealedWrites) {
    return emitFailure(
      deps,
      failure({
        code: 'invalid_state',
        source: 'domain',
        message: 'Wallet unlock must write at least one signing-session seal',
        retryable: false,
      }),
    );
  }

  await emit(deps, {
    kind: 'sealing_sessions',
    walletId: input.walletId,
    restored: restored.restored,
    provisioned,
    idempotencyKey: input.idempotencyKey,
  });
  const sealWrite = await deps.sealWriter.writeAll(sealedWrites);
  if (!sealWrite.ok) return emitFailure(deps, sealWrite);

  const readiness = deps.readiness.resolve({
    input,
    restored: restored.restored,
    provisioned,
    reauthRequired: restored.reauthRequired,
  });
  const success: UnlockWalletSuccess = {
    ok: true,
    walletId: input.walletId,
    readiness,
    restored: restored.restored,
    provisioned,
    sealedWrites,
  };
  await emit(deps, { kind: 'ready', result: success });
  return success;
}
