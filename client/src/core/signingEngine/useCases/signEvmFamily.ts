import { thresholdEcdsaChainTargetsEqual } from '../interfaces/ecdsaChainTarget';
import {
  useCaseFailure,
  type ReadyEcdsaLane,
  type ReauthRequiredLane,
  type SignEvmFamilyFailureCode,
  type SignEvmFamilyInput,
  type SignEvmFamilyLifecycleState,
  type SignEvmFamilyResult,
  type SignEvmFamilySuccess,
  type UseCaseFailure,
  type WarmSessionBudgetSpend,
} from './lifecycle';

export type SignEvmFamilyFailure = UseCaseFailure<SignEvmFamilyFailureCode>;

export type SignEvmFamilyLaneResolution =
  | {
      ok: true;
      lane: ReadyEcdsaLane;
      usedAuth: SignEvmFamilySuccess['usedAuth'];
      staleLane?: ReadyEcdsaLane | ReauthRequiredLane;
      code?: never;
      message?: never;
      retryable?: never;
    }
  | UseCaseFailure<
      Extract<
        SignEvmFamilyFailureCode,
        | 'missing_ready_ecdsa_material'
        | 'auth_mismatch'
        | 'ambiguous_signer_selection'
        | 'chain_target_mismatch'
        | 'invalid_state'
      >
    >;

export type SignEvmFamilyBudgetResult =
  | {
      ok: true;
      budgetSpend: WarmSessionBudgetSpend;
      code?: never;
      message?: never;
      retryable?: never;
    }
  | UseCaseFailure<Extract<SignEvmFamilyFailureCode, 'budget_exhausted' | 'invalid_state'>>;

export type SignEvmFamilySigningResult =
  | SignEvmFamilySuccess
  | UseCaseFailure<
      Extract<
        SignEvmFamilyFailureCode,
        'relayer_failed' | 'signer_failed' | 'nonce_sender_unavailable' | 'invalid_state'
      >
    >;

export type SignEvmFamilyDeps = {
  laneResolver: {
    resolve(input: SignEvmFamilyInput): Promise<SignEvmFamilyLaneResolution>;
  };
  budget: {
    reserve(input: {
      input: SignEvmFamilyInput;
      lane: ReadyEcdsaLane;
    }): Promise<SignEvmFamilyBudgetResult>;
  };
  signer: {
    sign(input: {
      input: SignEvmFamilyInput;
      lane: ReadyEcdsaLane;
      budgetSpend: WarmSessionBudgetSpend;
      usedAuth: SignEvmFamilySuccess['usedAuth'];
    }): Promise<SignEvmFamilySigningResult>;
  };
  lifecycle?: {
    transition(state: SignEvmFamilyLifecycleState): void | Promise<void>;
  };
};

export type SignEvmFamilyUseCase = {
  sign(input: SignEvmFamilyInput): Promise<SignEvmFamilyResult>;
};

export function createSignEvmFamilyUseCase(deps: SignEvmFamilyDeps): SignEvmFamilyUseCase {
  return {
    sign: (input) => signEvmFamily(deps, input),
  };
}

function failure(input: {
  code: SignEvmFamilyFailureCode;
  source: SignEvmFamilyFailure['source'];
  message: string;
  retryable: boolean;
  cause?: unknown;
}): SignEvmFamilyFailure {
  return useCaseFailure(input);
}

async function emit(deps: SignEvmFamilyDeps, state: SignEvmFamilyLifecycleState): Promise<void> {
  await deps.lifecycle?.transition(state);
}

async function emitFailure(
  deps: SignEvmFamilyDeps,
  result: SignEvmFamilyFailure,
): Promise<SignEvmFamilyFailure> {
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

function validateInputBranch(input: SignEvmFamilyInput): SignEvmFamilyFailure | null {
  switch (input.kind) {
    case 'evm_transaction':
      if (input.chainTarget.kind === 'evm') return null;
      break;
    case 'tempo_transaction':
      if (input.chainTarget.kind === 'tempo') return null;
      break;
    default:
      return failure({
        code: 'invalid_state',
        source: 'domain',
        message: 'Unsupported EVM-family signing branch',
        retryable: false,
      });
  }
  return failure({
    code: 'chain_target_mismatch',
    source: 'domain',
    message: 'EVM-family signing branch does not match chain target',
    retryable: false,
  });
}

function validateResolvedLane(args: {
  input: SignEvmFamilyInput;
  lane: ReadyEcdsaLane;
}): SignEvmFamilyFailure | null {
  if (
    String(args.lane.walletId) !== String(args.input.walletId) ||
    String(args.lane.rpId) !== String(args.input.rpId) ||
    !thresholdEcdsaChainTargetsEqual(args.lane.chainTarget, args.input.chainTarget)
  ) {
    return failure({
      code: 'chain_target_mismatch',
      source: 'domain',
      message: 'Resolved ECDSA lane does not match wallet, RP, and chain target',
      retryable: false,
    });
  }
  return null;
}

function validateSigningResult(args: {
  input: SignEvmFamilyInput;
  result: SignEvmFamilySuccess;
}): SignEvmFamilyFailure | null {
  if (
    args.result.kind !== args.input.kind ||
    String(args.result.walletId) !== String(args.input.walletId) ||
    !thresholdEcdsaChainTargetsEqual(args.result.chainTarget, args.input.chainTarget)
  ) {
    return failure({
      code: 'invalid_state',
      source: 'domain',
      message: 'EVM-family signer returned a result for a different request branch',
      retryable: false,
    });
  }
  return null;
}

export async function signEvmFamily(
  deps: SignEvmFamilyDeps,
  input: SignEvmFamilyInput,
): Promise<SignEvmFamilyResult> {
  await emit(deps, { kind: 'received_input', input });
  const branchMismatch = validateInputBranch(input);
  if (branchMismatch) return emitFailure(deps, branchMismatch);

  await emit(deps, { kind: 'resolving_ready_lane', input });
  const lane = await deps.laneResolver.resolve(input);
  if (!lane.ok) return emitFailure(deps, lane);
  const laneMismatch = validateResolvedLane({ input, lane: lane.lane });
  if (laneMismatch) return emitFailure(deps, laneMismatch);

  if (lane.usedAuth === 'same_method_step_up') {
    await emit(deps, {
      kind: 'activating_same_method_session',
      input,
      staleLane: lane.staleLane || lane.lane,
    });
  }

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
  });
  if (!signed.ok) return emitFailure(deps, signed);

  const resultMismatch = validateSigningResult({ input, result: signed });
  if (resultMismatch) return emitFailure(deps, resultMismatch);
  await emit(deps, { kind: 'signed', result: signed });
  return signed;
}
