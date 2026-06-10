import {
  useCaseFailure,
  type ReadyEd25519Lane,
  type SignNearFailureCode,
  type SignNearInput,
  type SignNearLifecycleState,
  type SignNearResult,
  type SignNearSuccess,
  type UseCaseFailure,
  type WarmSessionBudgetSpend,
} from './lifecycle';

export type SignNearFailure = UseCaseFailure<SignNearFailureCode>;

export type SignNearLaneResolution =
  | {
      ok: true;
      lane: ReadyEd25519Lane;
      usedAuth: SignNearSuccess['usedAuth'];
      signingPath: SignNearSuccess['signingPath'];
      code?: never;
      message?: never;
      retryable?: never;
    }
  | UseCaseFailure<
      Extract<
        SignNearFailureCode,
        | 'missing_ready_ed25519_material'
        | 'ambiguous_lane_selection'
        | 'step_up_required'
        | 'invalid_state'
      >
    >;

export type SignNearValidationResult =
  | { ok: true; code?: never; message?: never; retryable?: never }
  | UseCaseFailure<
      Extract<
        SignNearFailureCode,
        'digest_mismatch' | 'scope_mismatch' | 'dispatch_ambiguous' | 'invalid_state'
      >
    >;

export type SignNearBudgetResult =
  | {
      ok: true;
      budgetSpend: WarmSessionBudgetSpend;
      code?: never;
      message?: never;
      retryable?: never;
    }
  | UseCaseFailure<Extract<SignNearFailureCode, 'budget_exhausted' | 'invalid_state'>>;

export type SignNearSigningResult =
  | SignNearSuccess
  | UseCaseFailure<
      Extract<SignNearFailureCode, 'presign_pool_failed' | 'relayer_failed' | 'invalid_state'>
    >;

export type SignNearDeps = {
  laneResolver: {
    resolve(input: SignNearInput): Promise<SignNearLaneResolution>;
  };
  requestValidator: {
    validate(input: {
      input: SignNearInput;
      lane: ReadyEd25519Lane;
    }): Promise<SignNearValidationResult>;
  };
  budget: {
    reserve(input: { input: SignNearInput; lane: ReadyEd25519Lane }): Promise<SignNearBudgetResult>;
  };
  signer: {
    sign(input: {
      input: SignNearInput;
      lane: ReadyEd25519Lane;
      budgetSpend: WarmSessionBudgetSpend;
      usedAuth: SignNearSuccess['usedAuth'];
      signingPath: SignNearSuccess['signingPath'];
    }): Promise<SignNearSigningResult>;
  };
  lifecycle?: {
    transition(state: SignNearLifecycleState): void | Promise<void>;
  };
};

export type SignNearUseCase = {
  sign(input: SignNearInput): Promise<SignNearResult>;
};

export function createSignNearUseCase(deps: SignNearDeps): SignNearUseCase {
  return {
    sign: (input) => signNear(deps, input),
  };
}

function failure(input: {
  code: SignNearFailureCode;
  source: SignNearFailure['source'];
  message: string;
  retryable: boolean;
  cause?: unknown;
}): SignNearFailure {
  return useCaseFailure(input);
}

async function emit(deps: SignNearDeps, state: SignNearLifecycleState): Promise<void> {
  await deps.lifecycle?.transition(state);
}

async function emitFailure(deps: SignNearDeps, result: SignNearFailure): Promise<SignNearFailure> {
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

function validateLane(args: {
  input: SignNearInput;
  lane: ReadyEd25519Lane;
}): SignNearFailure | null {
  if (
    String(args.lane.walletId) !== String(args.input.walletId) ||
    String(args.lane.rpId) !== String(args.input.rpId)
  ) {
    return failure({
      code: 'missing_ready_ed25519_material',
      source: 'domain',
      message: 'Resolved Ed25519 lane does not match wallet and RP',
      retryable: false,
    });
  }
  return null;
}

function validateSignedResult(args: {
  input: SignNearInput;
  result: SignNearSuccess;
}): SignNearFailure | null {
  if (
    args.result.kind !== args.input.kind ||
    String(args.result.walletId) !== String(args.input.walletId) ||
    String(args.result.accountId) !== String(args.input.accountId)
  ) {
    return failure({
      code: 'invalid_state',
      source: 'domain',
      message: 'NEAR signer returned a result for a different request branch',
      retryable: false,
    });
  }
  return null;
}

export async function signNear(deps: SignNearDeps, input: SignNearInput): Promise<SignNearResult> {
  await emit(deps, { kind: 'received_input', input });

  await emit(deps, { kind: 'resolving_ready_lane', input });
  const lane = await deps.laneResolver.resolve(input);
  if (!lane.ok) return emitFailure(deps, lane);
  const laneMismatch = validateLane({ input, lane: lane.lane });
  if (laneMismatch) return emitFailure(deps, laneMismatch);

  await emit(deps, {
    kind: 'validating_request',
    input,
    lane: lane.lane,
  });
  const validation = await deps.requestValidator.validate({ input, lane: lane.lane });
  if (!validation.ok) return emitFailure(deps, validation);

  await emit(deps, {
    kind: 'reserving_budget',
    input,
    lane: lane.lane,
  });
  const budget = await deps.budget.reserve({ input, lane: lane.lane });
  if (!budget.ok) return emitFailure(deps, budget);

  await emit(deps, {
    kind: 'signing',
    input,
    lane: lane.lane,
    budgetSpend: budget.budgetSpend,
  });
  const signed = await deps.signer.sign({
    input,
    lane: lane.lane,
    budgetSpend: budget.budgetSpend,
    usedAuth: lane.usedAuth,
    signingPath: lane.signingPath,
  });
  if (!signed.ok) return emitFailure(deps, signed);

  const resultMismatch = validateSignedResult({ input, result: signed });
  if (resultMismatch) return emitFailure(deps, resultMismatch);
  await emit(deps, { kind: 'signed', result: signed });
  return signed;
}
