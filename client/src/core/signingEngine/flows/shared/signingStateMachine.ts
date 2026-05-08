import type {
  SigningOperationContext,
  SigningSessionPlan,
} from '../../session/signingSession/types';
import {
  SigningSessionPlanKind,
  summarizeSigningLane,
  summarizeSigningSessionPlan,
  type SigningLaneSummary,
  type SigningPlanSummary,
} from '../../session/signingSession/types';
import type { OperationCommandExecutor, OperationTransitionObserver } from './operationPorts';
import type { PreparedOperation } from './operationState';

export const SigningOperationStateKind = {
  Planned: 'planned',
  ConfirmationDisplayed: 'confirmation_displayed',
  AuthReady: 'auth_ready',
  ThresholdConnected: 'threshold_connected',
  PayloadPrepared: 'payload_prepared',
  BudgetReserved: 'budget_reserved',
  Signed: 'signed',
  BudgetSpent: 'budget_spent',
  CleanedUp: 'cleaned_up',
  Completed: 'completed',
  Failed: 'failed',
} as const;

export type SigningOperationStateKind =
  (typeof SigningOperationStateKind)[keyof typeof SigningOperationStateKind];

export const SigningOperationCommandKind = {
  ShowConfirmation: 'showConfirmation',
  RequestOtp: 'requestOtp',
  RequestPasskey: 'requestPasskey',
  ConnectThreshold: 'connectThreshold',
  PreparePayload: 'preparePayload',
  Sign: 'sign',
  ReserveBudget: 'reserveBudget',
  SpendBudget: 'spendBudget',
  Cleanup: 'cleanup',
} as const;

export type SigningOperationCommandKind =
  (typeof SigningOperationCommandKind)[keyof typeof SigningOperationCommandKind];

export type SigningOperationState =
  | { kind: typeof SigningOperationStateKind.Planned; plan: SigningSessionPlan }
  | { kind: typeof SigningOperationStateKind.ConfirmationDisplayed; plan: SigningSessionPlan }
  | { kind: typeof SigningOperationStateKind.AuthReady; plan: SigningSessionPlan }
  | { kind: typeof SigningOperationStateKind.ThresholdConnected; plan: SigningSessionPlan }
  | { kind: typeof SigningOperationStateKind.PayloadPrepared; plan: SigningSessionPlan }
  | { kind: typeof SigningOperationStateKind.BudgetReserved; plan: SigningSessionPlan }
  | { kind: typeof SigningOperationStateKind.Signed; plan: SigningSessionPlan }
  | { kind: typeof SigningOperationStateKind.BudgetSpent; plan: SigningSessionPlan }
  | { kind: typeof SigningOperationStateKind.CleanedUp; plan: SigningSessionPlan }
  | { kind: typeof SigningOperationStateKind.Completed; plan: SigningSessionPlan }
  | { kind: typeof SigningOperationStateKind.Failed; plan: SigningSessionPlan; reason: string };

export type SigningOperationCommand =
  | {
      kind: typeof SigningOperationCommandKind.ShowConfirmation;
      plan: SigningSessionPlan;
      lane: SigningSessionPlan['lane'];
      operation?: SigningOperationContext;
    }
  | {
      kind: typeof SigningOperationCommandKind.RequestOtp;
      plan: Extract<SigningSessionPlan, { kind: typeof SigningSessionPlanKind.EmailOtpReauth }>;
      lane: Extract<
        SigningSessionPlan,
        { kind: typeof SigningSessionPlanKind.EmailOtpReauth }
      >['lane'];
      operation?: SigningOperationContext;
    }
  | {
      kind: typeof SigningOperationCommandKind.RequestPasskey;
      plan: Extract<SigningSessionPlan, { kind: typeof SigningSessionPlanKind.PasskeyReauth }>;
      lane: Extract<
        SigningSessionPlan,
        { kind: typeof SigningSessionPlanKind.PasskeyReauth }
      >['lane'];
      operation?: SigningOperationContext;
    }
  | {
      kind: typeof SigningOperationCommandKind.ConnectThreshold;
      plan: Exclude<SigningSessionPlan, { kind: typeof SigningSessionPlanKind.NotReady }>;
      lane: Exclude<SigningSessionPlan, { kind: typeof SigningSessionPlanKind.NotReady }>['lane'];
      operation?: SigningOperationContext;
    }
  | {
      kind: typeof SigningOperationCommandKind.PreparePayload;
      plan: Exclude<SigningSessionPlan, { kind: typeof SigningSessionPlanKind.NotReady }>;
      lane: Exclude<SigningSessionPlan, { kind: typeof SigningSessionPlanKind.NotReady }>['lane'];
      operation?: SigningOperationContext;
    }
  | {
      kind: typeof SigningOperationCommandKind.Sign;
      plan: Exclude<SigningSessionPlan, { kind: typeof SigningSessionPlanKind.NotReady }>;
      lane: Exclude<SigningSessionPlan, { kind: typeof SigningSessionPlanKind.NotReady }>['lane'];
      operation?: SigningOperationContext;
    }
  | {
      kind: typeof SigningOperationCommandKind.ReserveBudget;
      plan: Exclude<SigningSessionPlan, { kind: typeof SigningSessionPlanKind.NotReady }>;
      lane: Exclude<SigningSessionPlan, { kind: typeof SigningSessionPlanKind.NotReady }>['lane'];
      operation?: SigningOperationContext;
    }
  | {
      kind: typeof SigningOperationCommandKind.SpendBudget;
      plan: Exclude<SigningSessionPlan, { kind: typeof SigningSessionPlanKind.NotReady }>;
      lane: Exclude<SigningSessionPlan, { kind: typeof SigningSessionPlanKind.NotReady }>['lane'];
      operation?: SigningOperationContext;
    }
  | {
      kind: typeof SigningOperationCommandKind.Cleanup;
      plan: Exclude<SigningSessionPlan, { kind: typeof SigningSessionPlanKind.NotReady }>;
      lane: Exclude<SigningSessionPlan, { kind: typeof SigningSessionPlanKind.NotReady }>['lane'];
      operation?: SigningOperationContext;
    };

export type SigningOperationTransitionEvent = {
  event: 'signing_operation_transition';
  from: SigningOperationStateKind;
  to: SigningOperationStateKind;
  command?: SigningOperationCommand['kind'];
  operationId?: SigningOperationContext['operationId'];
  plan: SigningPlanSummary;
  lane: SigningLaneSummary;
  reason?: string;
};

export type SigningOperationStep = {
  from: SigningOperationState;
  to: SigningOperationState;
  command?: SigningOperationCommand;
  traceEvent: SigningOperationTransitionEvent;
};

export type SigningOperationCommandSequence = readonly SigningOperationCommand['kind'][];
export type SigningPostSignOperationCommandSequence = readonly (
  | typeof SigningOperationCommandKind.SpendBudget
  | typeof SigningOperationCommandKind.Cleanup
)[];

export type SigningOperationPlan = {
  kind: 'signing_operation_plan';
  sessionPlan: SigningSessionPlan;
  operation: SigningOperationContext | null;
  preparedOperation: PreparedOperation | null;
  commands: SigningOperationCommandSequence;
};

export type SigningPostSignOperationPlan = {
  kind: 'signing_post_sign_operation_plan';
  sessionPlan: Exclude<SigningSessionPlan, { kind: typeof SigningSessionPlanKind.NotReady }>;
  operation: SigningOperationContext | null;
  preparedOperation: PreparedOperation | null;
  commands: SigningPostSignOperationCommandSequence;
};

export type SigningOperationMachine = {
  initialState: SigningOperationState;
  run(): SigningOperationStep[];
};

export type SigningOperationCommandExecutor = OperationCommandExecutor<SigningOperationCommand>;
export type SigningOperationTransitionObserver =
  OperationTransitionObserver<SigningOperationTransitionEvent>;

export type RunSigningOperationMachineResult =
  | {
      ok: true;
      finalState: Extract<
        SigningOperationState,
        {
          kind:
            | typeof SigningOperationStateKind.Completed
            | typeof SigningOperationStateKind.Failed;
        }
      >;
      steps: SigningOperationStep[];
    }
  | {
      ok: false;
      finalState: Extract<SigningOperationState, { kind: typeof SigningOperationStateKind.Failed }>;
      steps: SigningOperationStep[];
      error: unknown;
    };

export type RunSigningOperationCommandStepsResult =
  | {
      ok: true;
      finalState: SigningOperationState;
      steps: SigningOperationStep[];
    }
  | {
      ok: false;
      finalState: Extract<SigningOperationState, { kind: typeof SigningOperationStateKind.Failed }>;
      steps: SigningOperationStep[];
      error: unknown;
    };

export function createSigningOperationPlan(args: {
  sessionPlan: SigningSessionPlan;
  operation: SigningOperationContext | null;
  preparedOperation: PreparedOperation | null;
  commands: SigningOperationCommandSequence;
}): SigningOperationPlan {
  return {
    kind: 'signing_operation_plan',
    sessionPlan: args.sessionPlan,
    operation: args.operation,
    preparedOperation: args.preparedOperation,
    commands: args.commands,
  };
}

export function createSigningPostSignOperationPlan(args: {
  sessionPlan: Exclude<SigningSessionPlan, { kind: typeof SigningSessionPlanKind.NotReady }>;
  operation: SigningOperationContext | null;
  preparedOperation: PreparedOperation | null;
  commands: SigningPostSignOperationCommandSequence;
}): SigningPostSignOperationPlan {
  return {
    kind: 'signing_post_sign_operation_plan',
    sessionPlan: args.sessionPlan,
    operation: args.operation,
    preparedOperation: args.preparedOperation,
    commands: args.commands,
  };
}

export function createSigningOperationMachine(args: {
  operationPlan: SigningOperationPlan;
}): SigningOperationMachine {
  const initialState: SigningOperationState = {
    kind: SigningOperationStateKind.Planned,
    plan: args.operationPlan.sessionPlan,
  };

  return {
    initialState,
    run() {
      return buildSigningOperationSteps(args.operationPlan, initialState);
    },
  };
}

export async function runSigningOperationMachine(args: {
  machine: SigningOperationMachine;
  executor: SigningOperationCommandExecutor;
  onTransition?: SigningOperationTransitionObserver;
}): Promise<RunSigningOperationMachineResult> {
  return await runSigningOperationSteps({
    steps: args.machine.run(),
    executor: args.executor,
    onTransition: args.onTransition,
  });
}

export async function runSigningOperationSteps(args: {
  steps: SigningOperationStep[];
  executor: SigningOperationCommandExecutor;
  onTransition?: SigningOperationTransitionObserver;
}): Promise<RunSigningOperationMachineResult> {
  const result = await runSigningOperationCommandSteps(args);
  if (!result.ok) return result;
  if (result.finalState.kind !== SigningOperationStateKind.Completed) {
    throw new Error('[SigningOperationMachine] operation ended without a terminal state');
  }
  return result as RunSigningOperationMachineResult;
}

export async function runSigningOperationCommandSteps(args: {
  steps: SigningOperationStep[];
  executor: SigningOperationCommandExecutor;
  onTransition?: SigningOperationTransitionObserver;
}): Promise<RunSigningOperationCommandStepsResult> {
  const executedSteps: SigningOperationStep[] = [];

  for (const step of args.steps) {
    if (step.command) {
      try {
        await args.executor.execute(step.command);
      } catch (error) {
        const failedStep = transition({
          from: step.from,
          to: {
            kind: SigningOperationStateKind.Failed,
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
            SigningOperationState,
            { kind: typeof SigningOperationStateKind.Failed }
          >,
          steps: executedSteps,
          error,
        };
      }
    }

    await args.onTransition?.(step.traceEvent);
    executedSteps.push(step);

    if (step.to.kind === SigningOperationStateKind.Failed) {
      return {
        ok: true,
        finalState: step.to,
        steps: executedSteps,
      };
    }
  }

  const finalState = executedSteps.at(-1)?.to || args.steps.at(-1)?.from;
  if (!finalState) {
    throw new Error('[SigningOperationMachine] command sequence produced no steps');
  }

  return {
    ok: true,
    finalState,
    steps: executedSteps,
  };
}

export async function runUnplannedSigningOperationCommandSequence(args: {
  commands: readonly SigningOperationCommand['kind'][];
  execute: (command: SigningOperationCommand['kind']) => Promise<void>;
}): Promise<void> {
  for (const command of args.commands) {
    await args.execute(command);
  }
}

export function buildSigningPostSignOperationSteps(
  operationPlan: SigningPostSignOperationPlan,
): SigningOperationStep[] {
  const plan = operationPlan.sessionPlan;
  const steps: SigningOperationStep[] = [];
  let state: SigningOperationState = {
    kind: SigningOperationStateKind.Signed,
    plan,
  };

  state = pushTransition(steps, state, {
    to: { kind: SigningOperationStateKind.BudgetSpent, plan },
    command: commandForPlan(operationPlan, {
      kind: SigningOperationCommandKind.SpendBudget,
      plan,
      lane: plan.lane,
    }),
  });
  state = pushTransition(steps, state, {
    to: { kind: SigningOperationStateKind.CleanedUp, plan },
    command: commandForPlan(operationPlan, {
      kind: SigningOperationCommandKind.Cleanup,
      plan,
      lane: plan.lane,
    }),
  });
  pushTransition(steps, state, {
    to: { kind: SigningOperationStateKind.Completed, plan },
  });

  return steps;
}

export function buildSigningOperationCommandSteps(
  operationPlan: SigningOperationPlan,
): SigningOperationStep[] {
  const steps = buildSigningOperationSteps(operationPlan);
  let lastCommandIndex = -1;
  steps.forEach((step, index) => {
    if (step.command) lastCommandIndex = index;
  });
  return lastCommandIndex >= 0 ? steps.slice(0, lastCommandIndex + 1) : [];
}

export function createSigningOperationCommandTraceEvent(args: {
  plan: Exclude<SigningSessionPlan, { kind: typeof SigningSessionPlanKind.NotReady }>;
  commandKind: SigningOperationCommand['kind'];
  operation?: SigningOperationContext;
}): SigningOperationTransitionEvent | null {
  const transition = signingOperationTransitionForCommand(args.plan, args.commandKind);
  if (!transition) return null;
  return {
    event: 'signing_operation_transition',
    from: transition.from,
    to: transition.to,
    command: args.commandKind,
    ...(args.operation?.operationId ? { operationId: args.operation.operationId } : {}),
    plan: summarizeSigningSessionPlan(args.plan),
    lane: summarizeSigningLane(args.plan.lane),
  };
}

export async function runSigningOperationCommandTrace<T>(args: {
  signingSessionPlan?: SigningSessionPlan;
  commandKind: SigningOperationCommand['kind'];
  onTransition?: SigningOperationTransitionObserver;
  operation?: SigningOperationContext;
  execute: () => Promise<T>;
}): Promise<T> {
  const result = await args.execute();
  const plan = args.signingSessionPlan;
  if (!plan || plan.kind === SigningSessionPlanKind.NotReady) return result;
  const traceEvent = createSigningOperationCommandTraceEvent({
    plan,
    commandKind: args.commandKind,
    ...(args.operation ? { operation: args.operation } : {}),
  });
  if (traceEvent) {
    await args.onTransition?.(traceEvent);
  }
  return result;
}

export async function runSigningOperationCommand<T>(args: {
  signingSessionPlan: SigningSessionPlan;
  signingOperation: SigningOperationContext;
  commandKind: SigningOperationCommand['kind'];
  execute: () => Promise<T>;
}): Promise<T> {
  let value: T | undefined;
  const operationPlan = createSigningOperationPlan({
    sessionPlan: args.signingSessionPlan,
    operation: args.signingOperation,
    preparedOperation: null,
    commands: [args.commandKind],
  });
  const executor: SigningOperationCommandExecutor = {
    execute: async (command) => {
      if (command.kind !== args.commandKind) return;
      value = await args.execute();
    },
  };
  const result = await runSigningOperationCommandSteps({
    steps: buildSigningOperationCommandSteps(operationPlan),
    executor,
  });
  if (!result.ok) throw result.error;
  if (result.finalState.kind === SigningOperationStateKind.Failed) {
    throw new Error(result.finalState.reason);
  }
  return value as T;
}

export function buildSigningOperationSteps(
  operationPlan: SigningOperationPlan,
  initialState: SigningOperationState = {
    kind: SigningOperationStateKind.Planned,
    plan: operationPlan.sessionPlan,
  },
): SigningOperationStep[] {
  const plan = operationPlan.sessionPlan;
  if (plan.kind === SigningSessionPlanKind.NotReady) {
    return [
      transition({
        from: initialState,
        to: {
          kind: SigningOperationStateKind.Failed,
          plan,
          reason: plan.reason,
        },
        reason: plan.reason,
      }),
    ];
  }

  const steps: SigningOperationStep[] = [];
  let state = initialState;

  state = pushTransition(steps, state, {
    to: { kind: SigningOperationStateKind.ConfirmationDisplayed, plan },
    command: commandForPlan(operationPlan, {
      kind: SigningOperationCommandKind.ShowConfirmation,
      plan,
      lane: plan.lane,
    }),
  });

  if (plan.kind === SigningSessionPlanKind.EmailOtpReauth) {
    state = pushTransition(steps, state, {
      to: { kind: SigningOperationStateKind.AuthReady, plan },
      command: commandForPlan(operationPlan, {
        kind: SigningOperationCommandKind.RequestOtp,
        plan,
        lane: plan.lane,
      }),
    });
    state = pushTransition(steps, state, {
      to: { kind: SigningOperationStateKind.ThresholdConnected, plan },
      command: commandForPlan(operationPlan, {
        kind: SigningOperationCommandKind.ConnectThreshold,
        plan,
        lane: plan.lane,
      }),
    });
  } else if (plan.kind === SigningSessionPlanKind.PasskeyReauth) {
    state = pushTransition(steps, state, {
      to: { kind: SigningOperationStateKind.AuthReady, plan },
      command: commandForPlan(operationPlan, {
        kind: SigningOperationCommandKind.RequestPasskey,
        plan,
        lane: plan.lane,
      }),
    });
    state = pushTransition(steps, state, {
      to: { kind: SigningOperationStateKind.ThresholdConnected, plan },
      command: commandForPlan(operationPlan, {
        kind: SigningOperationCommandKind.ConnectThreshold,
        plan,
        lane: plan.lane,
      }),
    });
  } else {
    state = pushTransition(steps, state, {
      to: { kind: SigningOperationStateKind.AuthReady, plan },
    });
  }

  state = pushTransition(steps, state, {
    to: { kind: SigningOperationStateKind.PayloadPrepared, plan },
    command: commandForPlan(operationPlan, {
      kind: SigningOperationCommandKind.PreparePayload,
      plan,
      lane: plan.lane,
    }),
  });
  state = pushTransition(steps, state, {
    to: { kind: SigningOperationStateKind.BudgetReserved, plan },
    command: commandForPlan(operationPlan, {
      kind: SigningOperationCommandKind.ReserveBudget,
      plan,
      lane: plan.lane,
    }),
  });
  state = pushTransition(steps, state, {
    to: { kind: SigningOperationStateKind.Signed, plan },
    command: commandForPlan(operationPlan, {
      kind: SigningOperationCommandKind.Sign,
      plan,
      lane: plan.lane,
    }),
  });
  state = pushTransition(steps, state, {
    to: { kind: SigningOperationStateKind.BudgetSpent, plan },
    command: commandForPlan(operationPlan, {
      kind: SigningOperationCommandKind.SpendBudget,
      plan,
      lane: plan.lane,
    }),
  });
  state = pushTransition(steps, state, {
    to: { kind: SigningOperationStateKind.CleanedUp, plan },
    command: commandForPlan(operationPlan, {
      kind: SigningOperationCommandKind.Cleanup,
      plan,
      lane: plan.lane,
    }),
  });
  pushTransition(steps, state, {
    to: { kind: SigningOperationStateKind.Completed, plan },
  });

  return steps;
}

function signingOperationTransitionForCommand(
  plan: Exclude<SigningSessionPlan, { kind: typeof SigningSessionPlanKind.NotReady }>,
  commandKind: SigningOperationCommand['kind'],
): { from: SigningOperationStateKind; to: SigningOperationStateKind } | null {
  switch (commandKind) {
    case SigningOperationCommandKind.ShowConfirmation:
      return {
        from: SigningOperationStateKind.Planned,
        to: SigningOperationStateKind.ConfirmationDisplayed,
      };
    case SigningOperationCommandKind.RequestOtp:
      return plan.kind === SigningSessionPlanKind.EmailOtpReauth
        ? {
            from: SigningOperationStateKind.ConfirmationDisplayed,
            to: SigningOperationStateKind.AuthReady,
          }
        : null;
    case SigningOperationCommandKind.RequestPasskey:
      return plan.kind === SigningSessionPlanKind.PasskeyReauth
        ? {
            from: SigningOperationStateKind.ConfirmationDisplayed,
            to: SigningOperationStateKind.AuthReady,
          }
        : null;
    case SigningOperationCommandKind.ConnectThreshold:
      return plan.kind === SigningSessionPlanKind.EmailOtpReauth ||
        plan.kind === SigningSessionPlanKind.PasskeyReauth
        ? {
            from: SigningOperationStateKind.AuthReady,
            to: SigningOperationStateKind.ThresholdConnected,
          }
        : null;
    case SigningOperationCommandKind.PreparePayload:
      return {
        from:
          plan.kind === SigningSessionPlanKind.WarmSession
            ? SigningOperationStateKind.AuthReady
            : SigningOperationStateKind.ThresholdConnected,
        to: SigningOperationStateKind.PayloadPrepared,
      };
    case SigningOperationCommandKind.ReserveBudget:
      return {
        from: SigningOperationStateKind.PayloadPrepared,
        to: SigningOperationStateKind.BudgetReserved,
      };
    case SigningOperationCommandKind.Sign:
      return {
        from: SigningOperationStateKind.BudgetReserved,
        to: SigningOperationStateKind.Signed,
      };
    case SigningOperationCommandKind.SpendBudget:
      return {
        from: SigningOperationStateKind.Signed,
        to: SigningOperationStateKind.BudgetSpent,
      };
    case SigningOperationCommandKind.Cleanup:
      return {
        from: SigningOperationStateKind.BudgetSpent,
        to: SigningOperationStateKind.CleanedUp,
      };
  }
}

function pushTransition(
  steps: SigningOperationStep[],
  from: SigningOperationState,
  args: {
    to: SigningOperationState;
    command?: SigningOperationCommand;
    reason?: string;
  },
): SigningOperationState {
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
  from: SigningOperationState;
  to: SigningOperationState;
  command?: SigningOperationCommand;
  reason?: string;
}): SigningOperationStep {
  const plan = getTransitionPlan(args.from, args.to);
  return {
    from: args.from,
    to: args.to,
    command: args.command,
    traceEvent: {
      event: 'signing_operation_transition',
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
  from: SigningOperationState,
  to: SigningOperationState,
): SigningSessionPlan {
  return 'plan' in to ? to.plan : from.plan;
}

function commandForPlan<
  TPlan extends Pick<SigningOperationPlan | SigningPostSignOperationPlan, 'commands' | 'operation'>,
  TCommand extends SigningOperationCommand,
>(operationPlan: TPlan, command: TCommand): TCommand | undefined {
  const commands = operationPlan.commands as SigningOperationCommandSequence;
  if (!commands.includes(command.kind)) return undefined;
  return withOperation(command, operationPlan.operation);
}

function withOperation<TCommand extends SigningOperationCommand>(
  command: TCommand,
  operation: SigningOperationContext | null,
): TCommand {
  return operation ? ({ ...command, operation } as TCommand) : command;
}

function getExecutionErrorReason(error: unknown): string {
  if (error instanceof Error && error.message.trim()) {
    return error.message;
  }
  return 'execution_command_failed';
}
