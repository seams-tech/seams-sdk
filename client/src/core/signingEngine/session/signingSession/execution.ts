import type {
  SigningOperationContext,
  SigningSessionPlan,
} from './types';
import {
  SigningSessionPlanKind,
  summarizeSigningLane,
  summarizeSigningSessionPlan,
  type SigningLaneSummary,
  type SigningPlanSummary,
} from './types';

export const SigningExecutionStateKind = {
  Planned: 'planned',
  ConfirmationDisplayed: 'confirmation_displayed',
  AuthReady: 'auth_ready',
  ThresholdReconnected: 'threshold_reconnected',
  NonceReady: 'nonce_ready',
  BudgetReserved: 'budget_reserved',
  Signed: 'signed',
  BudgetSpent: 'budget_spent',
  CleanedUp: 'cleaned_up',
  Completed: 'completed',
  Failed: 'failed',
} as const;

export type SigningExecutionStateKind =
  (typeof SigningExecutionStateKind)[keyof typeof SigningExecutionStateKind];

export const SigningExecutionCommandKind = {
  ShowConfirmation: 'showConfirmation',
  RequestOtp: 'requestOtp',
  RequestPasskey: 'requestPasskey',
  ReconnectThreshold: 'reconnectThreshold',
  PrepareNonce: 'prepareNonce',
  Sign: 'sign',
  ReserveBudget: 'reserveBudget',
  SpendBudget: 'spendBudget',
  Cleanup: 'cleanup',
} as const;

export type SigningExecutionCommandKind =
  (typeof SigningExecutionCommandKind)[keyof typeof SigningExecutionCommandKind];

export type SigningExecutionState =
  | { kind: typeof SigningExecutionStateKind.Planned; plan: SigningSessionPlan }
  | { kind: typeof SigningExecutionStateKind.ConfirmationDisplayed; plan: SigningSessionPlan }
  | { kind: typeof SigningExecutionStateKind.AuthReady; plan: SigningSessionPlan }
  | { kind: typeof SigningExecutionStateKind.ThresholdReconnected; plan: SigningSessionPlan }
  | { kind: typeof SigningExecutionStateKind.NonceReady; plan: SigningSessionPlan }
  | { kind: typeof SigningExecutionStateKind.BudgetReserved; plan: SigningSessionPlan }
  | { kind: typeof SigningExecutionStateKind.Signed; plan: SigningSessionPlan }
  | { kind: typeof SigningExecutionStateKind.BudgetSpent; plan: SigningSessionPlan }
  | { kind: typeof SigningExecutionStateKind.CleanedUp; plan: SigningSessionPlan }
  | { kind: typeof SigningExecutionStateKind.Completed; plan: SigningSessionPlan }
  | { kind: typeof SigningExecutionStateKind.Failed; plan?: SigningSessionPlan; reason: string };

export type SigningExecutionCommand =
  | {
      kind: typeof SigningExecutionCommandKind.ShowConfirmation;
      plan: SigningSessionPlan;
      operation?: SigningOperationContext;
    }
  | {
      kind: typeof SigningExecutionCommandKind.RequestOtp;
      plan: Extract<SigningSessionPlan, { kind: typeof SigningSessionPlanKind.EmailOtpReauth }>;
      operation?: SigningOperationContext;
    }
  | {
      kind: typeof SigningExecutionCommandKind.RequestPasskey;
      plan: Extract<SigningSessionPlan, { kind: typeof SigningSessionPlanKind.PasskeyReauth }>;
      operation?: SigningOperationContext;
    }
  | {
      kind: typeof SigningExecutionCommandKind.ReconnectThreshold;
      plan: Exclude<SigningSessionPlan, { kind: typeof SigningSessionPlanKind.NotReady }>;
      operation?: SigningOperationContext;
    }
  | {
      kind: typeof SigningExecutionCommandKind.PrepareNonce;
      plan: Exclude<SigningSessionPlan, { kind: typeof SigningSessionPlanKind.NotReady }>;
      operation?: SigningOperationContext;
    }
  | {
      kind: typeof SigningExecutionCommandKind.Sign;
      plan: Exclude<SigningSessionPlan, { kind: typeof SigningSessionPlanKind.NotReady }>;
      operation?: SigningOperationContext;
    }
  | {
      kind: typeof SigningExecutionCommandKind.ReserveBudget;
      plan: Exclude<SigningSessionPlan, { kind: typeof SigningSessionPlanKind.NotReady }>;
      operation?: SigningOperationContext;
    }
  | {
      kind: typeof SigningExecutionCommandKind.SpendBudget;
      plan: Exclude<SigningSessionPlan, { kind: typeof SigningSessionPlanKind.NotReady }>;
      operation?: SigningOperationContext;
    }
  | {
      kind: typeof SigningExecutionCommandKind.Cleanup;
      plan: Exclude<SigningSessionPlan, { kind: typeof SigningSessionPlanKind.NotReady }>;
      operation?: SigningOperationContext;
    };

export type SigningExecutionTransitionEvent = {
  event: 'signing_execution_transition';
  from: SigningExecutionStateKind;
  to: SigningExecutionStateKind;
  command?: SigningExecutionCommand['kind'];
  operationId?: SigningOperationContext['operationId'];
  plan: SigningPlanSummary;
  lane: SigningLaneSummary;
  reason?: string;
};

export type SigningExecutionStep = {
  from: SigningExecutionState;
  to: SigningExecutionState;
  command?: SigningExecutionCommand;
  traceEvent: SigningExecutionTransitionEvent;
};

export type SigningExecutionMachine = {
  initialState: SigningExecutionState;
  run(): SigningExecutionStep[];
};

export type SigningExecutionCommandExecutor = {
  execute(command: SigningExecutionCommand): Promise<void>;
};

export type RunSigningExecutionMachineResult =
  | {
      ok: true;
      finalState: Extract<
        SigningExecutionState,
        {
          kind:
            | typeof SigningExecutionStateKind.Completed
            | typeof SigningExecutionStateKind.Failed;
        }
      >;
      steps: SigningExecutionStep[];
    }
  | {
      ok: false;
      finalState: Extract<SigningExecutionState, { kind: typeof SigningExecutionStateKind.Failed }>;
      steps: SigningExecutionStep[];
      error: unknown;
    };

export function createSigningExecutionMachine(args: {
  plan: SigningSessionPlan;
  operation?: SigningOperationContext;
}): SigningExecutionMachine {
  const initialState: SigningExecutionState = {
    kind: SigningExecutionStateKind.Planned,
    plan: args.plan,
  };

  return {
    initialState,
    run() {
      return buildSigningExecutionSteps(args.plan, initialState, args.operation);
    },
  };
}

export async function runSigningExecutionMachine(args: {
  machine: SigningExecutionMachine;
  executor: SigningExecutionCommandExecutor;
  onTransition?: (event: SigningExecutionTransitionEvent) => void | Promise<void>;
}): Promise<RunSigningExecutionMachineResult> {
  return await runSigningExecutionSteps({
    steps: args.machine.run(),
    executor: args.executor,
    onTransition: args.onTransition,
  });
}

export async function runSigningExecutionSteps(args: {
  steps: SigningExecutionStep[];
  executor: SigningExecutionCommandExecutor;
  onTransition?: (event: SigningExecutionTransitionEvent) => void | Promise<void>;
}): Promise<RunSigningExecutionMachineResult> {
  const executedSteps: SigningExecutionStep[] = [];

  for (const step of args.steps) {
    if (step.command) {
      try {
        await args.executor.execute(step.command);
      } catch (error) {
        const failedStep = transition({
          from: step.from,
          to: {
            kind: SigningExecutionStateKind.Failed,
            plan: step.command.plan,
            reason: getExecutionErrorReason(error),
          },
          command: step.command,
          reason: getExecutionErrorReason(error),
        });
        await args.onTransition?.(failedStep.traceEvent);
        executedSteps.push(failedStep);
        return {
          ok: false,
          finalState: failedStep.to as Extract<
            SigningExecutionState,
            { kind: typeof SigningExecutionStateKind.Failed }
          >,
          steps: executedSteps,
          error,
        };
      }
    }

    await args.onTransition?.(step.traceEvent);
    executedSteps.push(step);

    if (step.to.kind === SigningExecutionStateKind.Failed) {
      return {
        ok: true,
        finalState: step.to,
        steps: executedSteps,
      };
    }
  }

  const finalState = executedSteps.at(-1)?.to;
  if (finalState?.kind !== SigningExecutionStateKind.Completed) {
    throw new Error('[SigningExecutionMachine] execution ended without a terminal state');
  }

  return {
    ok: true,
    finalState,
    steps: executedSteps,
  };
}

export function buildSigningPostSignExecutionSteps(
  plan: Exclude<SigningSessionPlan, { kind: typeof SigningSessionPlanKind.NotReady }>,
  operation?: SigningOperationContext,
): SigningExecutionStep[] {
  const steps: SigningExecutionStep[] = [];
  let state: SigningExecutionState = {
    kind: SigningExecutionStateKind.Signed,
    plan,
  };

  state = pushTransition(steps, state, {
    to: { kind: SigningExecutionStateKind.BudgetSpent, plan },
    command: withOperation({ kind: SigningExecutionCommandKind.SpendBudget, plan }, operation),
  });
  state = pushTransition(steps, state, {
    to: { kind: SigningExecutionStateKind.CleanedUp, plan },
    command: withOperation({ kind: SigningExecutionCommandKind.Cleanup, plan }, operation),
  });
  pushTransition(steps, state, {
    to: { kind: SigningExecutionStateKind.Completed, plan },
  });

  return steps;
}

export function createSigningExecutionCommandTraceEvent(args: {
  plan: Exclude<SigningSessionPlan, { kind: typeof SigningSessionPlanKind.NotReady }>;
  commandKind: SigningExecutionCommand['kind'];
  operation?: SigningOperationContext;
}): SigningExecutionTransitionEvent | null {
  const transition = signingExecutionTransitionForCommand(args.plan, args.commandKind);
  if (!transition) return null;
  return {
    event: 'signing_execution_transition',
    from: transition.from,
    to: transition.to,
    command: args.commandKind,
    ...(args.operation?.operationId ? { operationId: args.operation.operationId } : {}),
    plan: summarizeSigningSessionPlan(args.plan),
    lane: summarizeSigningLane(args.plan.lane),
  };
}

export function buildSigningExecutionSteps(
  plan: SigningSessionPlan,
  initialState: SigningExecutionState = { kind: SigningExecutionStateKind.Planned, plan },
  operation?: SigningOperationContext,
): SigningExecutionStep[] {
  if (plan.kind === SigningSessionPlanKind.NotReady) {
    return [
      transition({
        from: initialState,
        to: {
          kind: SigningExecutionStateKind.Failed,
          plan,
          reason: plan.reason,
        },
        reason: plan.reason,
      }),
    ];
  }

  const steps: SigningExecutionStep[] = [];
  let state = initialState;

  state = pushTransition(steps, state, {
    to: { kind: SigningExecutionStateKind.ConfirmationDisplayed, plan },
    command: withOperation({ kind: SigningExecutionCommandKind.ShowConfirmation, plan }, operation),
  });

  if (plan.kind === SigningSessionPlanKind.EmailOtpReauth) {
    state = pushTransition(steps, state, {
      to: { kind: SigningExecutionStateKind.AuthReady, plan },
      command: withOperation({ kind: SigningExecutionCommandKind.RequestOtp, plan }, operation),
    });
    state = pushTransition(steps, state, {
      to: { kind: SigningExecutionStateKind.ThresholdReconnected, plan },
      command: withOperation(
        { kind: SigningExecutionCommandKind.ReconnectThreshold, plan },
        operation,
      ),
    });
  } else if (plan.kind === SigningSessionPlanKind.PasskeyReauth) {
    state = pushTransition(steps, state, {
      to: { kind: SigningExecutionStateKind.AuthReady, plan },
      command: withOperation({ kind: SigningExecutionCommandKind.RequestPasskey, plan }, operation),
    });
    state = pushTransition(steps, state, {
      to: { kind: SigningExecutionStateKind.ThresholdReconnected, plan },
      command: withOperation(
        { kind: SigningExecutionCommandKind.ReconnectThreshold, plan },
        operation,
      ),
    });
  } else {
    state = pushTransition(steps, state, {
      to: { kind: SigningExecutionStateKind.AuthReady, plan },
    });
  }

  state = pushTransition(steps, state, {
    to: { kind: SigningExecutionStateKind.NonceReady, plan },
    command: withOperation({ kind: SigningExecutionCommandKind.PrepareNonce, plan }, operation),
  });
  state = pushTransition(steps, state, {
    to: { kind: SigningExecutionStateKind.BudgetReserved, plan },
    command: withOperation({ kind: SigningExecutionCommandKind.ReserveBudget, plan }, operation),
  });
  state = pushTransition(steps, state, {
    to: { kind: SigningExecutionStateKind.Signed, plan },
    command: withOperation({ kind: SigningExecutionCommandKind.Sign, plan }, operation),
  });
  state = pushTransition(steps, state, {
    to: { kind: SigningExecutionStateKind.BudgetSpent, plan },
    command: withOperation({ kind: SigningExecutionCommandKind.SpendBudget, plan }, operation),
  });
  state = pushTransition(steps, state, {
    to: { kind: SigningExecutionStateKind.CleanedUp, plan },
    command: withOperation({ kind: SigningExecutionCommandKind.Cleanup, plan }, operation),
  });
  pushTransition(steps, state, {
    to: { kind: SigningExecutionStateKind.Completed, plan },
  });

  return steps;
}

function signingExecutionTransitionForCommand(
  plan: Exclude<SigningSessionPlan, { kind: typeof SigningSessionPlanKind.NotReady }>,
  commandKind: SigningExecutionCommand['kind'],
): { from: SigningExecutionStateKind; to: SigningExecutionStateKind } | null {
  switch (commandKind) {
    case SigningExecutionCommandKind.ShowConfirmation:
      return {
        from: SigningExecutionStateKind.Planned,
        to: SigningExecutionStateKind.ConfirmationDisplayed,
      };
    case SigningExecutionCommandKind.RequestOtp:
      return plan.kind === SigningSessionPlanKind.EmailOtpReauth
        ? {
            from: SigningExecutionStateKind.ConfirmationDisplayed,
            to: SigningExecutionStateKind.AuthReady,
          }
        : null;
    case SigningExecutionCommandKind.RequestPasskey:
      return plan.kind === SigningSessionPlanKind.PasskeyReauth
        ? {
            from: SigningExecutionStateKind.ConfirmationDisplayed,
            to: SigningExecutionStateKind.AuthReady,
          }
        : null;
    case SigningExecutionCommandKind.ReconnectThreshold:
      return plan.kind === SigningSessionPlanKind.EmailOtpReauth ||
        plan.kind === SigningSessionPlanKind.PasskeyReauth
        ? {
            from: SigningExecutionStateKind.AuthReady,
            to: SigningExecutionStateKind.ThresholdReconnected,
          }
        : null;
    case SigningExecutionCommandKind.PrepareNonce:
      return {
        from:
          plan.kind === SigningSessionPlanKind.WarmSession
            ? SigningExecutionStateKind.AuthReady
            : SigningExecutionStateKind.ThresholdReconnected,
        to: SigningExecutionStateKind.NonceReady,
      };
    case SigningExecutionCommandKind.ReserveBudget:
      return {
        from: SigningExecutionStateKind.NonceReady,
        to: SigningExecutionStateKind.BudgetReserved,
      };
    case SigningExecutionCommandKind.Sign:
      return {
        from: SigningExecutionStateKind.BudgetReserved,
        to: SigningExecutionStateKind.Signed,
      };
    case SigningExecutionCommandKind.SpendBudget:
      return {
        from: SigningExecutionStateKind.Signed,
        to: SigningExecutionStateKind.BudgetSpent,
      };
    case SigningExecutionCommandKind.Cleanup:
      return {
        from: SigningExecutionStateKind.BudgetSpent,
        to: SigningExecutionStateKind.CleanedUp,
      };
  }
}

function pushTransition(
  steps: SigningExecutionStep[],
  from: SigningExecutionState,
  args: {
    to: SigningExecutionState;
    command?: SigningExecutionCommand;
    reason?: string;
  },
): SigningExecutionState {
  const step = transition({
    from,
    to: args.to,
    command: args.command,
    reason: args.reason,
  });
  steps.push(step);
  return step.to;
}

function transition(args: {
  from: SigningExecutionState;
  to: SigningExecutionState;
  command?: SigningExecutionCommand;
  reason?: string;
}): SigningExecutionStep {
  const plan = getTransitionPlan(args.from, args.to);
  return {
    from: args.from,
    to: args.to,
    command: args.command,
    traceEvent: {
      event: 'signing_execution_transition',
      from: args.from.kind,
      to: args.to.kind,
      ...(args.command ? { command: args.command.kind } : {}),
      ...(args.command?.operation ? { operationId: args.command.operation.operationId } : {}),
      plan: summarizeSigningSessionPlan(plan),
      lane: summarizeSigningLane(plan.lane),
      ...(args.reason ? { reason: args.reason } : {}),
    },
  };
}

function getTransitionPlan(
  from: SigningExecutionState,
  to: SigningExecutionState,
): SigningSessionPlan {
  const plan = 'plan' in to && to.plan ? to.plan : 'plan' in from ? from.plan : undefined;
  if (!plan) {
    throw new Error('[SigningExecutionMachine] transition plan is required');
  }
  return plan;
}

function withOperation<TCommand extends SigningExecutionCommand>(
  command: TCommand,
  operation: SigningOperationContext | undefined,
): TCommand {
  return operation ? ({ ...command, operation } as TCommand) : command;
}

function getExecutionErrorReason(error: unknown): string {
  if (error instanceof Error && error.message.trim()) {
    return error.message;
  }
  return 'execution_command_failed';
}
