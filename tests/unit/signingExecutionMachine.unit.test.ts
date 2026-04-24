import { expect, test } from '@playwright/test';
import { toAccountId } from '@/core/types/accountIds';
import {
  buildSigningPostSignExecutionSteps,
  createSigningExecutionMachine,
  runSigningExecutionMachine,
  runSigningExecutionSteps,
  type SigningExecutionCommand,
  type SigningExecutionCommandExecutor,
  type SigningExecutionStateKind,
  type SigningExecutionTransitionEvent,
} from '@/core/signingEngine/session/SigningExecutionMachine';
import {
  planSigningSession,
  type SigningSessionReadiness,
} from '@/core/signingEngine/session/SigningSessionPlanner';
import {
  SigningSessionIds,
  type SigningLaneContext,
  type SigningOperationContext,
  type SigningSessionPlan,
} from '@/core/signingEngine/session/signingSessionTypes';

test.describe('SigningExecutionMachine', () => {
  test('keeps warm-session signing free of auth prompt commands', () => {
    const lane = makeLane({
      authMethod: 'email_otp',
      chainFamily: 'tempo',
      curve: 'ecdsa',
      storageSource: 'email_otp',
    });
    const plan = planSigningSession({
      lane,
      readiness: ready(lane),
    });

    const steps = createSigningExecutionMachine({ plan }).run();

    expect(commandKinds(steps)).toEqual([
      'showConfirmation',
      'prepareNonce',
      'reserveBudget',
      'sign',
      'spendBudget',
      'cleanup',
    ]);
    expect(stateKinds(steps)).toEqual([
      'planned',
      'confirmation_displayed',
      'auth_ready',
      'nonce_ready',
      'budget_reserved',
      'signed',
      'budget_spent',
      'cleaned_up',
      'completed',
    ]);
  });

  test('runs exhausted Email OTP through confirmation before OTP and threshold reconnect', () => {
    const lane = makeLane({
      authMethod: 'email_otp',
      chainFamily: 'evm',
      curve: 'ecdsa',
      storageSource: 'email_otp',
    });
    const plan = planSigningSession({
      lane,
      readiness: exhausted(lane),
    });

    const steps = createSigningExecutionMachine({ plan }).run();

    expect(commandKinds(steps)).toEqual([
      'showConfirmation',
      'requestOtp',
      'reconnectThreshold',
      'prepareNonce',
      'reserveBudget',
      'sign',
      'spendBudget',
      'cleanup',
    ]);
    expect(commandKinds(steps)).not.toContain('requestPasskey');
    expect(steps[0].to.kind).toBe('confirmation_displayed');
    expect(steps[1].from.kind).toBe('confirmation_displayed');
  });

  test('runs exhausted passkey through passkey reauth, not OTP', () => {
    const lane = makeLane({
      authMethod: 'passkey',
      chainFamily: 'tempo',
      curve: 'ecdsa',
      sessionOrigin: 'login',
      storageSource: 'login',
    });
    const plan = planSigningSession({
      lane,
      readiness: exhausted(lane),
    });

    const steps = createSigningExecutionMachine({ plan }).run();

    expect(commandKinds(steps)).toEqual([
      'showConfirmation',
      'requestPasskey',
      'reconnectThreshold',
      'prepareNonce',
      'reserveBudget',
      'sign',
      'spendBudget',
      'cleanup',
    ]);
    expect(commandKinds(steps)).not.toContain('requestOtp');
  });

  test('fails not-ready plans without side-effect commands', () => {
    const lane = makeLane({
      thresholdSessionId: undefined,
    });
    const plan = planSigningSession({
      lane,
      readiness: {
        status: 'ready',
      },
    });

    const steps = createSigningExecutionMachine({ plan }).run();

    expect(plan.kind).toBe('not_ready');
    expect(commandKinds(steps)).toEqual([]);
    expect(stateKinds(steps)).toEqual(['planned', 'failed']);
    expect(steps[0].traceEvent.reason).toBe('missing_session');
  });

  test('trace events summarize decisions without session ids or secret-bearing plan bodies', () => {
    const lane = makeLane({
      authMethod: 'email_otp',
      chainFamily: 'evm',
      curve: 'ecdsa',
      storageSource: 'email_otp',
    });
    const plan = planSigningSession({
      lane,
      readiness: exhausted(lane),
    });

    const traceJson = JSON.stringify(
      createSigningExecutionMachine({ plan }).run().map((step) => step.traceEvent),
    );

    expect(traceJson).toContain('"authMethod":"email_otp"');
    expect(traceJson).toContain('"command":"requestOtp"');
    expect(traceJson).not.toContain(String(lane.thresholdSessionId));
    expect(traceJson).not.toContain(String(lane.walletSigningSessionId));
  });

  test('runner executes commands in machine order and emits transition traces', async () => {
    const lane = makeLane({
      authMethod: 'email_otp',
      chainFamily: 'evm',
      curve: 'ecdsa',
      storageSource: 'email_otp',
    });
    const plan = planSigningSession({
      lane,
      readiness: exhausted(lane),
    });
    const executedCommands: Array<SigningExecutionCommand['kind']> = [];
    const transitionEvents: SigningExecutionTransitionEvent[] = [];

    const result = await runSigningExecutionMachine({
      machine: createSigningExecutionMachine({ plan }),
      executor: {
        async execute(command) {
          executedCommands.push(command.kind);
        },
      },
      onTransition(event) {
        transitionEvents.push(event);
      },
    });

    expect(result.ok).toBe(true);
    expect(result.finalState.kind).toBe('completed');
    expect(executedCommands).toEqual(commandKinds(result.steps));
    expect(transitionEvents.map((event) => event.to).at(-1)).toBe('completed');
    expect(transitionEvents.map((event) => event.command).filter(Boolean)).toEqual(
      executedCommands,
    );
  });

  test('fake confirmed deps record auth prompts and budget spends for the selected lane', async () => {
    const otpLane = makeLane({
      authMethod: 'email_otp',
      chainFamily: 'evm',
      curve: 'ecdsa',
      storageSource: 'email_otp',
    });
    const passkeyLane = makeLane({
      authMethod: 'passkey',
      chainFamily: 'tempo',
      curve: 'ecdsa',
      storageSource: 'login',
    });
    const confirmedDeps = createFakeConfirmedDepsRecorder();
    const operations: SigningOperationContext[] = [
      {
        operationId: SigningSessionIds.signingOperation('confirmed-deps-otp-op'),
        intent: 'transaction_sign',
      },
      {
        operationId: SigningSessionIds.signingOperation('confirmed-deps-passkey-op'),
        intent: 'transaction_sign',
      },
    ];

    for (const [index, lane] of [otpLane, passkeyLane].entries()) {
      await runSigningExecutionMachine({
        machine: createSigningExecutionMachine({
          plan: planSigningSession({
            lane,
            readiness: exhausted(lane),
          }),
          operation: operations[index],
        }),
        executor: confirmedDeps,
      });
    }

    expect(confirmedDeps.prompts).toEqual([
      { kind: 'requestOtp', operationId: operations[0].operationId, authMethod: 'email_otp' },
      { kind: 'requestPasskey', operationId: operations[1].operationId, authMethod: 'passkey' },
    ]);
    expect(confirmedDeps.budgetSpends).toEqual([
      {
        operationId: operations[0].operationId,
        walletSigningSessionId: otpLane.walletSigningSessionId,
        authMethod: 'email_otp',
      },
      {
        operationId: operations[1].operationId,
        walletSigningSessionId: passkeyLane.walletSigningSessionId,
        authMethod: 'passkey',
      },
    ]);
  });

  test('emits trace order for warm, exhausted OTP, exhausted passkey, and cancellation flows', async () => {
    const warmLane = makeLane({
      authMethod: 'email_otp',
      chainFamily: 'tempo',
      curve: 'ecdsa',
      storageSource: 'email_otp',
    });
    const otpLane = makeLane({
      authMethod: 'email_otp',
      chainFamily: 'evm',
      curve: 'ecdsa',
      storageSource: 'email_otp',
    });
    const passkeyLane = makeLane({
      authMethod: 'passkey',
      chainFamily: 'evm',
      curve: 'ecdsa',
      storageSource: 'login',
    });

    const cases: Array<{
      name: string;
      plan: SigningSessionPlan;
      expected: string[];
    }> = [
      {
        name: 'warm',
        plan: planSigningSession({ lane: warmLane, readiness: ready(warmLane) }),
        expected: [
          'planned->confirmation_displayed:showConfirmation',
          'confirmation_displayed->auth_ready',
          'auth_ready->nonce_ready:prepareNonce',
          'nonce_ready->budget_reserved:reserveBudget',
          'budget_reserved->signed:sign',
          'signed->budget_spent:spendBudget',
          'budget_spent->cleaned_up:cleanup',
          'cleaned_up->completed',
        ],
      },
      {
        name: 'exhausted Email OTP',
        plan: planSigningSession({ lane: otpLane, readiness: exhausted(otpLane) }),
        expected: [
          'planned->confirmation_displayed:showConfirmation',
          'confirmation_displayed->auth_ready:requestOtp',
          'auth_ready->threshold_reconnected:reconnectThreshold',
          'threshold_reconnected->nonce_ready:prepareNonce',
          'nonce_ready->budget_reserved:reserveBudget',
          'budget_reserved->signed:sign',
          'signed->budget_spent:spendBudget',
          'budget_spent->cleaned_up:cleanup',
          'cleaned_up->completed',
        ],
      },
      {
        name: 'exhausted passkey',
        plan: planSigningSession({ lane: passkeyLane, readiness: exhausted(passkeyLane) }),
        expected: [
          'planned->confirmation_displayed:showConfirmation',
          'confirmation_displayed->auth_ready:requestPasskey',
          'auth_ready->threshold_reconnected:reconnectThreshold',
          'threshold_reconnected->nonce_ready:prepareNonce',
          'nonce_ready->budget_reserved:reserveBudget',
          'budget_reserved->signed:sign',
          'signed->budget_spent:spendBudget',
          'budget_spent->cleaned_up:cleanup',
          'cleaned_up->completed',
        ],
      },
    ];

    for (const row of cases) {
      const traces = createSigningExecutionMachine({ plan: row.plan })
        .run()
        .map((step) => step.traceEvent);

      expect.soft(traceSignatures(traces), row.name).toEqual(row.expected);
    }

    const cancellationEvents: SigningExecutionTransitionEvent[] = [];
    await runSigningExecutionMachine({
      machine: createSigningExecutionMachine({
        plan: planSigningSession({ lane: otpLane, readiness: exhausted(otpLane) }),
      }),
      executor: {
        async execute(command) {
          if (command.kind === 'requestOtp') {
            throw new Error('user_cancelled');
          }
        },
      },
      onTransition(event) {
        cancellationEvents.push(event);
      },
    });

    expect(traceSignatures(cancellationEvents)).toEqual([
      'planned->confirmation_displayed:showConfirmation',
      'confirmation_displayed->failed:requestOtp',
    ]);
    expect(cancellationEvents[1].reason).toBe('user_cancelled');
  });

  test('runner fails without executing later side effects when a command fails', async () => {
    const lane = makeLane({
      authMethod: 'email_otp',
      chainFamily: 'evm',
      curve: 'ecdsa',
      storageSource: 'email_otp',
    });
    const plan = planSigningSession({
      lane,
      readiness: exhausted(lane),
    });
    const executedCommands: Array<SigningExecutionCommand['kind']> = [];
    const transitionEvents: SigningExecutionTransitionEvent[] = [];

    const result = await runSigningExecutionMachine({
      machine: createSigningExecutionMachine({ plan }),
      executor: {
        async execute(command) {
          executedCommands.push(command.kind);
          if (command.kind === 'requestOtp') {
            throw new Error('user_cancelled');
          }
        },
      },
      onTransition(event) {
        transitionEvents.push(event);
      },
    });

    expect(result.ok).toBe(false);
    expect(result.finalState).toMatchObject({
      kind: 'failed',
      reason: 'user_cancelled',
    });
    expect(executedCommands).toEqual(['showConfirmation', 'requestOtp']);
    expect(executedCommands).not.toContain('sign');
    expect(executedCommands).not.toContain('spendBudget');
    expect(transitionEvents.map((event) => event.to)).toEqual([
      'confirmation_displayed',
      'failed',
    ]);
  });

  test('runner does not spend budget or cleanup after signing failure', async () => {
    const lane = makeLane({
      authMethod: 'email_otp',
      chainFamily: 'tempo',
      curve: 'ecdsa',
      storageSource: 'email_otp',
    });
    const plan = planSigningSession({
      lane,
      readiness: ready(lane),
    });
    const executedCommands: Array<SigningExecutionCommand['kind']> = [];

    const result = await runSigningExecutionMachine({
      machine: createSigningExecutionMachine({ plan }),
      executor: {
        async execute(command) {
          executedCommands.push(command.kind);
          if (command.kind === 'sign') {
            throw new Error('signing_failed');
          }
        },
      },
    });

    expect(result.ok).toBe(false);
    expect(result.finalState).toMatchObject({
      kind: 'failed',
      reason: 'signing_failed',
    });
    expect(executedCommands).toEqual([
      'showConfirmation',
      'prepareNonce',
      'reserveBudget',
      'sign',
    ]);
    expect(executedCommands).not.toContain('spendBudget');
    expect(executedCommands).not.toContain('cleanup');
  });

  test('post-sign runner executes only budget spend and cleanup commands', async () => {
    const lane = makeLane({
      authMethod: 'email_otp',
      chainFamily: 'tempo',
      curve: 'ecdsa',
      storageSource: 'email_otp',
    });
    const plan = expectPlanKind(
      planSigningSession({
        lane,
        readiness: ready(lane),
      }),
      'warm_session',
    );
    const executedCommands: Array<SigningExecutionCommand['kind']> = [];

    const result = await runSigningExecutionSteps({
      steps: buildSigningPostSignExecutionSteps(plan),
      executor: {
        async execute(command) {
          executedCommands.push(command.kind);
        },
      },
    });

    expect(result.ok).toBe(true);
    expect(result.finalState.kind).toBe('completed');
    expect(executedCommands).toEqual(['spendBudget', 'cleanup']);
    expect(stateKinds(result.steps)).toEqual(['signed', 'budget_spent', 'cleaned_up', 'completed']);
  });
});

function commandKinds(
  steps: ReturnType<ReturnType<typeof createSigningExecutionMachine>['run']>,
): Array<SigningExecutionCommand['kind']> {
  return steps.flatMap((step) => (step.command ? [step.command.kind] : []));
}

function stateKinds(
  steps: ReturnType<ReturnType<typeof createSigningExecutionMachine>['run']>,
): SigningExecutionStateKind[] {
  return [steps[0]?.from.kind, ...steps.map((step) => step.to.kind)].filter(
    Boolean,
  ) as SigningExecutionStateKind[];
}

function traceSignatures(events: SigningExecutionTransitionEvent[]): string[] {
  return events.map((event) =>
    event.command
      ? `${event.from}->${event.to}:${event.command}`
      : `${event.from}->${event.to}`,
  );
}

function makeLane(overrides: Partial<SigningLaneContext> = {}): SigningLaneContext {
  const curve = overrides.curve || 'ecdsa';
  const authMethod = overrides.authMethod || 'email_otp';
  const chainFamily = overrides.chainFamily || (curve === 'ed25519' ? 'near' : 'tempo');
  const thresholdSessionId =
    overrides.thresholdSessionId ||
    (curve === 'ed25519'
      ? SigningSessionIds.thresholdEd25519Session('tsess-ed25519-machine')
      : SigningSessionIds.thresholdEcdsaSession('tsess-ecdsa-machine'));

  return {
    accountId: toAccountId('machine.testnet'),
    authMethod,
    curve,
    keyKind: curve === 'ed25519' ? 'threshold_ed25519' : 'threshold_ecdsa_secp256k1',
    chainFamily,
    walletSigningSessionId: SigningSessionIds.walletSigningSession('wsess-machine'),
    thresholdSessionId,
    sessionOrigin: authMethod === 'email_otp' ? 'login' : 'registration',
    storageSource: authMethod === 'email_otp' ? 'email_otp' : 'login',
    retention: 'session',
    signingRootId: 'proj_machine:dev',
    signingRootVersion: 'default',
    ...overrides,
  };
}

function ready(lane: SigningLaneContext): SigningSessionReadiness {
  return {
    status: 'ready',
    thresholdSessionId: lane.thresholdSessionId,
    backingMaterialSessionId: lane.backingMaterialSessionId,
  };
}

function exhausted(lane: SigningLaneContext): SigningSessionReadiness {
  return {
    status: 'exhausted',
    thresholdSessionId: lane.thresholdSessionId,
    backingMaterialSessionId: lane.backingMaterialSessionId,
  };
}

function createFakeConfirmedDepsRecorder(): SigningExecutionCommandExecutor & {
  prompts: Array<{
    kind: 'requestOtp' | 'requestPasskey';
    operationId: SigningOperationContext['operationId'];
    authMethod: SigningLaneContext['authMethod'];
  }>;
  budgetSpends: Array<{
    operationId: SigningOperationContext['operationId'];
    walletSigningSessionId: SigningLaneContext['walletSigningSessionId'];
    authMethod: SigningLaneContext['authMethod'];
  }>;
} {
  const prompts: Array<{
    kind: 'requestOtp' | 'requestPasskey';
    operationId: SigningOperationContext['operationId'];
    authMethod: SigningLaneContext['authMethod'];
  }> = [];
  const budgetSpends: Array<{
    operationId: SigningOperationContext['operationId'];
    walletSigningSessionId: SigningLaneContext['walletSigningSessionId'];
    authMethod: SigningLaneContext['authMethod'];
  }> = [];

  return {
    prompts,
    budgetSpends,
    async execute(command) {
      if (command.kind === 'requestOtp' || command.kind === 'requestPasskey') {
        prompts.push({
          kind: command.kind,
          operationId: command.operation?.operationId || SigningSessionIds.signingOperation('missing-operation'),
          authMethod: command.plan.lane.authMethod,
        });
      }
      if (command.kind === 'spendBudget') {
        budgetSpends.push({
          operationId: command.operation?.operationId || SigningSessionIds.signingOperation('missing-operation'),
          walletSigningSessionId: command.plan.lane.walletSigningSessionId,
          authMethod: command.plan.lane.authMethod,
        });
      }
    },
  };
}

function expectPlanKind<TKind extends SigningSessionPlan['kind']>(
  plan: SigningSessionPlan,
  kind: TKind,
): Extract<SigningSessionPlan, { kind: TKind }> {
  expect(plan.kind).toBe(kind);
  return plan as Extract<SigningSessionPlan, { kind: TKind }>;
}
