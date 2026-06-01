import {
  useCaseFailure,
  type NonEmptyReadonlyArray,
  type ReadyEcdsaLane,
  type ReadyEd25519Lane,
  type ReadyWalletSessionReadiness,
  type RegisterWalletFailureCode,
  type RegisterWalletInput,
  type RegisterWalletLifecycleState,
  type RegisterWalletResult,
  type RegisterWalletSuccess,
  type RegistrationReadyLanes,
  type SigningSessionSealWriteInput,
  type UseCaseFailure,
  type WalletPreferenceWrite,
  type WalletSignerWrite,
} from './lifecycle';

export type RegisterWalletFailure = UseCaseFailure<RegisterWalletFailureCode>;

export type RegisterWalletAuthResult =
  | { ok: true; code?: never; message?: never; retryable?: never }
  | UseCaseFailure<
      Extract<
        RegisterWalletFailureCode,
        'authenticator_failed' | 'email_otp_failed' | 'stale_identity_mapping' | 'invalid_state'
      >
    >;

export type RegisterWalletEd25519ProvisionResult =
  | {
      ok: true;
      lane: ReadyEd25519Lane;
      sealWrite: SigningSessionSealWriteInput;
      walletSignerWrite: Extract<WalletSignerWrite, { kind: 'ed25519_wallet_signer_write_v1' }>;
      code?: never;
      message?: never;
      retryable?: never;
    }
  | UseCaseFailure<
      Extract<
        RegisterWalletFailureCode,
        | 'signer_crypto_command_failed'
        | 'signer_crypto_invocation_failed'
        | 'relayer_failed'
        | 'registration_incomplete'
        | 'invalid_state'
      >
    >;

export type RegisterWalletEcdsaProvisionResult =
  | {
      ok: true;
      lanes: readonly ReadyEcdsaLane[];
      sealWrites: readonly SigningSessionSealWriteInput[];
      walletSignerWrites: readonly Extract<
        WalletSignerWrite,
        { kind: 'ecdsa_wallet_signer_write_v1' }
      >[];
      code?: never;
      message?: never;
      retryable?: never;
    }
  | UseCaseFailure<
      Extract<
        RegisterWalletFailureCode,
        | 'signer_crypto_command_failed'
        | 'signer_crypto_invocation_failed'
        | 'relayer_failed'
        | 'registration_incomplete'
        | 'storage_failed'
        | 'invalid_state'
      >
    >;

export type RegisterWalletCommitInput = {
  input: RegisterWalletInput;
  readiness: ReadyWalletSessionReadiness;
  lanes: RegistrationReadyLanes;
  sealedWrites: NonEmptyReadonlyArray<SigningSessionSealWriteInput>;
  walletPreferenceWrite: WalletPreferenceWrite;
  walletSignerWrites: NonEmptyReadonlyArray<WalletSignerWrite>;
};

export type RegisterWalletCommitResult =
  | {
      ok: true;
      value?: RegisterWalletSuccess;
      code?: never;
      message?: never;
      retryable?: never;
    }
  | UseCaseFailure<
      Extract<
        RegisterWalletFailureCode,
        'wallet_id_collision' | 'registration_incomplete' | 'storage_failed' | 'invalid_state'
      >
    >;

export type RegisterWalletDeps = {
  authenticator: {
    authenticate(input: RegisterWalletInput): Promise<RegisterWalletAuthResult>;
  };
  ed25519Provisioner: {
    provision(input: RegisterWalletInput): Promise<RegisterWalletEd25519ProvisionResult>;
  };
  ecdsaProvisioner: {
    provision(input: {
      input: RegisterWalletInput;
      ed25519: ReadyEd25519Lane;
    }): Promise<RegisterWalletEcdsaProvisionResult>;
  };
  walletStore: {
    commitRegistration(input: RegisterWalletCommitInput): Promise<RegisterWalletCommitResult>;
  };
  lifecycle?: {
    transition(state: RegisterWalletLifecycleState): void | Promise<void>;
  };
};

export type RegisterWalletUseCase = {
  register(input: RegisterWalletInput): Promise<RegisterWalletResult>;
};

export function createRegisterWalletUseCase(deps: RegisterWalletDeps): RegisterWalletUseCase {
  return {
    register: (input) => registerWallet(deps, input),
  };
}

function toNonEmptyReadonlyArray<T>(items: readonly T[]): NonEmptyReadonlyArray<T> | null {
  const first = items[0];
  if (first === undefined) return null;
  return [first, ...items.slice(1)];
}

function failure(input: {
  code: RegisterWalletFailureCode;
  source: RegisterWalletFailure['source'];
  message: string;
  retryable: boolean;
  cause?: unknown;
}): RegisterWalletFailure {
  return useCaseFailure(input);
}

async function emit(deps: RegisterWalletDeps, state: RegisterWalletLifecycleState): Promise<void> {
  await deps.lifecycle?.transition(state);
}

async function emitFailure(
  deps: RegisterWalletDeps,
  result: RegisterWalletFailure,
): Promise<RegisterWalletFailure> {
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

function needsExplicitEcdsaLaneCount(input: RegisterWalletInput): number | null {
  return input.ecdsaTargets.kind === 'explicit' ? input.ecdsaTargets.targets.length : null;
}

function validateEcdsaProvisioning(args: {
  input: RegisterWalletInput;
  ecdsa: RegisterWalletEcdsaProvisionResult & { ok: true };
}): RegisterWalletFailure | null {
  const expectedCount = needsExplicitEcdsaLaneCount(args.input);
  if (expectedCount !== null && args.ecdsa.lanes.length !== expectedCount) {
    return failure({
      code: 'registration_incomplete',
      source: 'domain',
      message: 'Registration did not provision every requested ECDSA lane',
      retryable: false,
    });
  }
  if (args.ecdsa.lanes.length !== args.ecdsa.sealWrites.length) {
    return failure({
      code: 'invalid_state',
      source: 'domain',
      message: 'ECDSA provisioning returned mismatched lane and seal-write counts',
      retryable: false,
    });
  }
  if (args.ecdsa.lanes.length !== args.ecdsa.walletSignerWrites.length) {
    return failure({
      code: 'invalid_state',
      source: 'domain',
      message: 'ECDSA provisioning returned mismatched lane and signer-write counts',
      retryable: false,
    });
  }
  return null;
}

export async function registerWallet(
  deps: RegisterWalletDeps,
  input: RegisterWalletInput,
): Promise<RegisterWalletResult> {
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
    kind: 'provisioning_ed25519',
    walletId: input.walletId,
    rpId: input.rpId,
    auth: input.auth,
    ecdsaTargets: input.ecdsaTargets,
    idempotencyKey: input.idempotencyKey,
  });
  const ed25519 = await deps.ed25519Provisioner.provision(input);
  if (!ed25519.ok) return emitFailure(deps, ed25519);

  await emit(deps, {
    kind: 'provisioning_ecdsa',
    walletId: input.walletId,
    rpId: input.rpId,
    auth: input.auth,
    ecdsaTargets: input.ecdsaTargets,
    ed25519: ed25519.lane,
    idempotencyKey: input.idempotencyKey,
  });
  const ecdsa = await deps.ecdsaProvisioner.provision({ input, ed25519: ed25519.lane });
  if (!ecdsa.ok) return emitFailure(deps, ecdsa);

  const provisioningMismatch = validateEcdsaProvisioning({ input, ecdsa });
  if (provisioningMismatch) return emitFailure(deps, provisioningMismatch);

  const lanes: RegistrationReadyLanes = {
    ed25519: ed25519.lane,
    ecdsa: ecdsa.lanes,
  };
  const readiness: ReadyWalletSessionReadiness = {
    kind: 'ready',
    walletId: input.walletId,
    ed25519: [ed25519.lane],
    ecdsa: ecdsa.lanes,
  };
  const sealedWrites = toNonEmptyReadonlyArray([ed25519.sealWrite, ...ecdsa.sealWrites]);
  const walletSignerWrites = toNonEmptyReadonlyArray([
    ed25519.walletSignerWrite,
    ...ecdsa.walletSignerWrites,
  ]);
  if (!sealedWrites || !walletSignerWrites) {
    return emitFailure(
      deps,
      failure({
        code: 'invalid_state',
        source: 'domain',
        message: 'Registration must produce signing-session seals and wallet signer writes',
        retryable: false,
      }),
    );
  }
  const walletPreferenceWrite: WalletPreferenceWrite = {
    kind: 'wallet_preference_write_v1',
    walletId: input.walletId,
    rpId: input.rpId,
  };

  await emit(deps, {
    kind: 'sealing_sessions',
    walletId: input.walletId,
    rpId: input.rpId,
    lanes,
    idempotencyKey: input.idempotencyKey,
  });
  await emit(deps, {
    kind: 'persisting_wallet',
    walletId: input.walletId,
    readiness,
    lanes,
    sealedWrites,
    idempotencyKey: input.idempotencyKey,
  });

  const committed = await deps.walletStore.commitRegistration({
    input,
    readiness,
    lanes,
    sealedWrites,
    walletPreferenceWrite,
    walletSignerWrites,
  });
  if (!committed.ok) return emitFailure(deps, committed);

  const success: RegisterWalletSuccess = committed.value || {
    ok: true,
    walletId: input.walletId,
    readiness,
    lanes,
    sealedWrites,
    walletPreferenceWrite,
    walletSignerWrites,
  };
  await emit(deps, { kind: 'ready', ...success });
  return success;
}
