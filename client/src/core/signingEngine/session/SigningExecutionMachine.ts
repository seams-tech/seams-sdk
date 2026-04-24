import type {
  SigningOperationContext,
  SigningSessionPlan,
} from './signingSessionTypes';
import {
  summarizeSigningLane,
  summarizeSigningSessionPlan,
  type SigningLaneSummary,
  type SigningPlanSummary,
} from './signingSessionTypes';

export type SigningExecutionStateKind =
  | 'planned'
  | 'confirmation_displayed'
  | 'auth_ready'
  | 'threshold_reconnected'
  | 'nonce_ready'
  | 'budget_reserved'
  | 'signed'
  | 'budget_spent'
  | 'cleaned_up'
  | 'completed'
  | 'failed';

export type SigningExecutionState =
  | { kind: 'planned'; plan: SigningSessionPlan }
  | { kind: 'confirmation_displayed'; plan: SigningSessionPlan }
  | { kind: 'auth_ready'; plan: SigningSessionPlan }
  | { kind: 'threshold_reconnected'; plan: SigningSessionPlan }
  | { kind: 'nonce_ready'; plan: SigningSessionPlan }
  | { kind: 'budget_reserved'; plan: SigningSessionPlan }
  | { kind: 'signed'; plan: SigningSessionPlan }
  | { kind: 'budget_spent'; plan: SigningSessionPlan }
  | { kind: 'cleaned_up'; plan: SigningSessionPlan }
  | { kind: 'completed'; plan: SigningSessionPlan }
  | { kind: 'failed'; plan?: SigningSessionPlan; reason: string };

export type SigningExecutionCommand =
  | { kind: 'showConfirmation'; plan: SigningSessionPlan; operation?: SigningOperationContext }
  | {
      kind: 'requestOtp';
      plan: Extract<SigningSessionPlan, { kind: 'email_otp_reauth' }>;
      operation?: SigningOperationContext;
    }
  | {
      kind: 'requestPasskey';
      plan: Extract<SigningSessionPlan, { kind: 'passkey_reauth' }>;
      operation?: SigningOperationContext;
    }
  | {
      kind: 'reconnectThreshold';
      plan: Exclude<SigningSessionPlan, { kind: 'not_ready' }>;
      operation?: SigningOperationContext;
    }
  | {
      kind: 'prepareNonce';
      plan: Exclude<SigningSessionPlan, { kind: 'not_ready' }>;
      operation?: SigningOperationContext;
    }
  | {
      kind: 'sign';
      plan: Exclude<SigningSessionPlan, { kind: 'not_ready' }>;
      operation?: SigningOperationContext;
    }
  | {
      kind: 'reserveBudget';
      plan: Exclude<SigningSessionPlan, { kind: 'not_ready' }>;
      operation?: SigningOperationContext;
    }
  | {
      kind: 'spendBudget';
      plan: Exclude<SigningSessionPlan, { kind: 'not_ready' }>;
      operation?: SigningOperationContext;
    }
  | {
      kind: 'cleanup';
      plan: Exclude<SigningSessionPlan, { kind: 'not_ready' }>;
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
      finalState: Extract<SigningExecutionState, { kind: 'completed' | 'failed' }>;
      steps: SigningExecutionStep[];
    }
  | {
      ok: false;
      finalState: Extract<SigningExecutionState, { kind: 'failed' }>;
      steps: SigningExecutionStep[];
      error: unknown;
    };

export function createSigningExecutionMachine(args: {
  plan: SigningSessionPlan;
  operation?: SigningOperationContext;
}): SigningExecutionMachine {
  const initialState: SigningExecutionState = {
    kind: 'planned',
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
            kind: 'failed',
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
          finalState: failedStep.to as Extract<SigningExecutionState, { kind: 'failed' }>,
          steps: executedSteps,
          error,
        };
      }
    }

    await args.onTransition?.(step.traceEvent);
    executedSteps.push(step);

    if (step.to.kind === 'failed') {
      return {
        ok: true,
        finalState: step.to,
        steps: executedSteps,
      };
    }
  }

  const finalState = executedSteps.at(-1)?.to;
  if (finalState?.kind !== 'completed') {
    throw new Error('[SigningExecutionMachine] execution ended without a terminal state');
  }

  return {
    ok: true,
    finalState,
    steps: executedSteps,
  };
}

export function buildSigningPostSignExecutionSteps(
  plan: Exclude<SigningSessionPlan, { kind: 'not_ready' }>,
  operation?: SigningOperationContext,
): SigningExecutionStep[] {
  const steps: SigningExecutionStep[] = [];
  let state: SigningExecutionState = {
    kind: 'signed',
    plan,
  };

  state = pushTransition(steps, state, {
    to: { kind: 'budget_spent', plan },
    command: withOperation({ kind: 'spendBudget', plan }, operation),
  });
  state = pushTransition(steps, state, {
    to: { kind: 'cleaned_up', plan },
    command: withOperation({ kind: 'cleanup', plan }, operation),
  });
  pushTransition(steps, state, {
    to: { kind: 'completed', plan },
  });

  return steps;
}

export function createSigningExecutionCommandTraceEvent(args: {
  plan: Exclude<SigningSessionPlan, { kind: 'not_ready' }>;
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
  initialState: SigningExecutionState = { kind: 'planned', plan },
  operation?: SigningOperationContext,
): SigningExecutionStep[] {
  if (plan.kind === 'not_ready') {
    return [
      transition({
        from: initialState,
        to: {
          kind: 'failed',
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
    to: { kind: 'confirmation_displayed', plan },
    command: withOperation({ kind: 'showConfirmation', plan }, operation),
  });

  if (plan.kind === 'email_otp_reauth') {
    state = pushTransition(steps, state, {
      to: { kind: 'auth_ready', plan },
      command: withOperation({ kind: 'requestOtp', plan }, operation),
    });
    state = pushTransition(steps, state, {
      to: { kind: 'threshold_reconnected', plan },
      command: withOperation({ kind: 'reconnectThreshold', plan }, operation),
    });
  } else if (plan.kind === 'passkey_reauth') {
    state = pushTransition(steps, state, {
      to: { kind: 'auth_ready', plan },
      command: withOperation({ kind: 'requestPasskey', plan }, operation),
    });
    state = pushTransition(steps, state, {
      to: { kind: 'threshold_reconnected', plan },
      command: withOperation({ kind: 'reconnectThreshold', plan }, operation),
    });
  } else {
    state = pushTransition(steps, state, {
      to: { kind: 'auth_ready', plan },
    });
  }

  state = pushTransition(steps, state, {
    to: { kind: 'nonce_ready', plan },
    command: withOperation({ kind: 'prepareNonce', plan }, operation),
  });
  state = pushTransition(steps, state, {
    to: { kind: 'budget_reserved', plan },
    command: withOperation({ kind: 'reserveBudget', plan }, operation),
  });
  state = pushTransition(steps, state, {
    to: { kind: 'signed', plan },
    command: withOperation({ kind: 'sign', plan }, operation),
  });
  state = pushTransition(steps, state, {
    to: { kind: 'budget_spent', plan },
    command: withOperation({ kind: 'spendBudget', plan }, operation),
  });
  state = pushTransition(steps, state, {
    to: { kind: 'cleaned_up', plan },
    command: withOperation({ kind: 'cleanup', plan }, operation),
  });
  pushTransition(steps, state, {
    to: { kind: 'completed', plan },
  });

  return steps;
}

function signingExecutionTransitionForCommand(
  plan: Exclude<SigningSessionPlan, { kind: 'not_ready' }>,
  commandKind: SigningExecutionCommand['kind'],
): { from: SigningExecutionStateKind; to: SigningExecutionStateKind } | null {
  switch (commandKind) {
    case 'showConfirmation':
      return { from: 'planned', to: 'confirmation_displayed' };
    case 'requestOtp':
      return plan.kind === 'email_otp_reauth'
        ? { from: 'confirmation_displayed', to: 'auth_ready' }
        : null;
    case 'requestPasskey':
      return plan.kind === 'passkey_reauth'
        ? { from: 'confirmation_displayed', to: 'auth_ready' }
        : null;
    case 'reconnectThreshold':
      return plan.kind === 'email_otp_reauth' || plan.kind === 'passkey_reauth'
        ? { from: 'auth_ready', to: 'threshold_reconnected' }
        : null;
    case 'prepareNonce':
      return { from: plan.kind === 'warm_session' ? 'auth_ready' : 'threshold_reconnected', to: 'nonce_ready' };
    case 'reserveBudget':
      return { from: 'nonce_ready', to: 'budget_reserved' };
    case 'sign':
      return { from: 'budget_reserved', to: 'signed' };
    case 'spendBudget':
      return { from: 'signed', to: 'budget_spent' };
    case 'cleanup':
      return { from: 'budget_spent', to: 'cleaned_up' };
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
