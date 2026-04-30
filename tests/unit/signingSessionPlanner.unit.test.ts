import { expect, test } from '@playwright/test';
import { toAccountId } from '@/core/types/accountIds';
import {
  createSigningPlannerDecisionTraceEvent,
  planSigningSession,
  type SigningSessionReadiness,
} from '@/core/signingEngine/session/signingSession/planner';
import { buildWalletSigningSpendPlan } from '@/core/signingEngine/session/signingSession/budget';
import {
  SigningSessionIds,
  type SigningLaneContext,
  type SigningSessionPlan,
} from '@/core/signingEngine/session/signingSession/types';
import {
  createSigningBoundaryTraceEvent,
  emitSigningBoundaryTrace,
  emitSigningLaneResolutionTrace,
} from '@/core/signingEngine/session/signingSession/trace';

test.describe('SigningSessionPlanner', () => {
  test('plans core auth outcomes from the selected lane matrix', () => {
    const rows: Array<{
      name: string;
      lane: Partial<SigningLaneContext>;
      readinessStatus: SigningSessionReadiness['status'];
      forceFreshAuth?: boolean;
      expectedKind: SigningSessionPlan['kind'];
    }> = [
      {
        name: 'ready Email OTP ECDSA',
        lane: { authMethod: 'email_otp', curve: 'ecdsa', chainFamily: 'tempo' },
        readinessStatus: 'ready',
        expectedKind: 'warm_session',
      },
      {
        name: 'exhausted Email OTP ECDSA',
        lane: {
          authMethod: 'email_otp',
          curve: 'ecdsa',
          chainFamily: 'evm',
          storageSource: 'email_otp',
        },
        readinessStatus: 'exhausted',
        expectedKind: 'email_otp_reauth',
      },
      {
        name: 'exhausted passkey ECDSA',
        lane: {
          authMethod: 'passkey',
          curve: 'ecdsa',
          chainFamily: 'tempo',
          storageSource: 'login',
        },
        readinessStatus: 'exhausted',
        expectedKind: 'passkey_reauth',
      },
      {
        name: 'ready single-use Email OTP Ed25519',
        lane: {
          authMethod: 'email_otp',
          curve: 'ed25519',
          chainFamily: 'near',
          retention: 'single_use',
          storageSource: 'email_otp',
        },
        readinessStatus: 'ready',
        expectedKind: 'email_otp_reauth',
      },
      {
        name: 'force-fresh passkey Ed25519',
        lane: {
          authMethod: 'passkey',
          curve: 'ed25519',
          chainFamily: 'near',
          storageSource: 'login',
        },
        readinessStatus: 'ready',
        forceFreshAuth: true,
        expectedKind: 'passkey_reauth',
      },
    ];

    for (const row of rows) {
      const lane = makeLane(row.lane);
      const plan = planSigningSession({
        lane,
        readiness: {
          status: row.readinessStatus,
          thresholdSessionId: lane.thresholdSessionId,
          backingMaterialSessionId: lane.backingMaterialSessionId,
        },
        forceFreshAuth: row.forceFreshAuth,
      });

      expect.soft(plan.kind, row.name).toBe(row.expectedKind);
      expect.soft(plan.lane, row.name).toBe(lane);
    }
  });

  test('plans a warm Email OTP ECDSA transaction without a prompt', () => {
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

    expect(plan.lane.authMethod).toBe('email_otp');
    expect(plan.keyRef).toEqual({
      kind: 'cached',
      thresholdSessionId: lane.thresholdSessionId,
    });
  });

  test('plans Email OTP reauth for repeated exhausted ECDSA transactions on Tempo and EVM', () => {
    for (const chainFamily of ['tempo', 'evm'] as const) {
      const firstLane = makeLane({
        authMethod: 'email_otp',
        chainFamily,
        curve: 'ecdsa',
        storageSource: 'email_otp',
      });
      const secondLane = makeLane({ ...firstLane });

      const firstPlan = expectPlanKind(
        planSigningSession({
          lane: firstLane,
          readiness: exhausted(firstLane),
        }),
        'email_otp_reauth',
      );
      const secondPlan = expectPlanKind(
        planSigningSession({
          lane: secondLane,
          readiness: exhausted(secondLane),
        }),
        'email_otp_reauth',
      );

      expect(firstPlan.challenge.lane.authMethod).toBe('email_otp');
      expect(secondPlan.challenge.lane.authMethod).toBe('email_otp');
      expect(firstPlan.lane).toBe(firstLane);
      expect(secondPlan.lane).toBe(secondLane);
    }
  });

  test('plans passkey reauth for an active passkey lane even when an Email OTP lane exists', () => {
    const staleEmailOtpLane = makeLane({
      authMethod: 'email_otp',
      chainFamily: 'tempo',
      curve: 'ecdsa',
      storageSource: 'email_otp',
    });
    const activePasskeyLane = makeLane({
      authMethod: 'passkey',
      chainFamily: 'tempo',
      curve: 'ecdsa',
      storageSource: 'login',
      sessionOrigin: 'login',
    });

    const plan = expectPlanKind(
      planSigningSession({
        lane: activePasskeyLane,
        readiness: exhausted(activePasskeyLane),
      }),
      'passkey_reauth',
    );

    expect(staleEmailOtpLane.authMethod).toBe('email_otp');
    expect(plan.lane).toBe(activePasskeyLane);
    expect(plan.reconnect.lane.authMethod).toBe('passkey');
  });

  test('plans Email OTP reauth for an active OTP lane even when a newer passkey lane exists', () => {
    const activeEmailOtpLane = makeLane({
      authMethod: 'email_otp',
      chainFamily: 'evm',
      curve: 'ecdsa',
      storageSource: 'email_otp',
      sessionOrigin: 'login',
    });
    const newerPasskeyLane = makeLane({
      authMethod: 'passkey',
      chainFamily: 'evm',
      curve: 'ecdsa',
      storageSource: 'login',
      sessionOrigin: 'login',
    });

    const plan = expectPlanKind(
      planSigningSession({
        lane: activeEmailOtpLane,
        readiness: exhausted(activeEmailOtpLane),
      }),
      'email_otp_reauth',
    );

    expect(newerPasskeyLane.authMethod).toBe('passkey');
    expect(plan.lane).toBe(activeEmailOtpLane);
    expect(plan.challenge.lane.authMethod).toBe('email_otp');
  });

  test('plans Email OTP reauth for ready single-use Email OTP lanes', () => {
    const lane = makeLane({
      authMethod: 'email_otp',
      retention: 'single_use',
      storageSource: 'email_otp',
    });

    const plan = expectPlanKind(
      planSigningSession({
        lane,
        readiness: ready(lane),
      }),
      'email_otp_reauth',
    );

    expect(plan.challenge.chainFamily).toBe(lane.chainFamily);
  });

  test('blocks Email OTP lanes for passkey-only sensitive-operation policy', () => {
    const lane = makeLane({
      authMethod: 'email_otp',
      storageSource: 'email_otp',
    });

    const plan = expectPlanKind(
      planSigningSession({
        lane,
        readiness: ready(lane),
        sensitiveOperationPolicy: 'require_passkey',
      }),
      'not_ready',
    );

    expect(plan.reason).toBe('policy_blocked');
  });

  test('keeps budget-spend ids on the selected lane and dedupes repeated refs', () => {
    const lane = makeLane({
      backingMaterialSessionId: SigningSessionIds.backingMaterialSession('backing-1'),
      thresholdSessionId: SigningSessionIds.thresholdEcdsaSession('tsess-ecdsa-budget'),
    });

    const operationId = SigningSessionIds.signingOperation('selected-lane-budget-op');
    const budgetSpend = buildWalletSigningSpendPlan({
      operationId,
      intent: 'transaction_sign',
    }, lane, {
      backingMaterialSessionId: lane.backingMaterialSessionId,
      thresholdSessionId: lane.thresholdSessionId,
    });

    expect(budgetSpend).toMatchObject({
      operationId,
      nearAccountId: lane.accountId,
      walletSigningSessionId: lane.walletSigningSessionId,
      uses: 1,
      reason: 'transaction_sign',
    });
    expect(budgetSpend.thresholdSessionIds).toEqual([lane.thresholdSessionId]);
    expect(budgetSpend.backingMaterialSessionIds).toEqual([lane.backingMaterialSessionId]);
  });

  test('plans NEAR single and batched transactions as one user-visible budget spend', () => {
    for (const row of [
      { name: 'single NEAR transaction', transactionCount: 1 },
      { name: 'batched NEAR transactions', transactionCount: 3 },
    ]) {
      const lane = makeLane({
        authMethod: 'email_otp',
        chainFamily: 'near',
        curve: 'ed25519',
        storageSource: 'email_otp',
      });

      const plan = expectPlanKind(
        planSigningSession({
          lane,
          readiness: ready(lane),
        }),
        'warm_session',
      );

      const operationId = SigningSessionIds.signingOperation(`near-${row.transactionCount}-tx-op`);
      const budgetSpend = buildWalletSigningSpendPlan({
        operationId,
        intent: 'transaction_sign',
      }, plan.lane);
      expect.soft(budgetSpend.uses, row.name).toBe(1);
      expect.soft(budgetSpend.operationId, row.name).toBe(operationId);
      expect.soft(budgetSpend.walletSigningSessionId, row.name).toBe(
        lane.walletSigningSessionId,
      );
    }
  });

  test('plans Ed25519 and ECDSA lanes against the same wallet signing-session budget', () => {
    const walletSigningSessionId = SigningSessionIds.walletSigningSession(
      'wsess-shared-ed25519-ecdsa',
    );
    const ed25519Lane = makeLane({
      authMethod: 'email_otp',
      chainFamily: 'near',
      curve: 'ed25519',
      walletSigningSessionId,
      thresholdSessionId: SigningSessionIds.thresholdEd25519Session('tsess-shared-ed25519'),
      storageSource: 'email_otp',
    });
    const ecdsaLane = makeLane({
      authMethod: 'email_otp',
      chainFamily: 'tempo',
      curve: 'ecdsa',
      walletSigningSessionId,
      thresholdSessionId: SigningSessionIds.thresholdEcdsaSession('tsess-shared-ecdsa'),
      storageSource: 'email_otp',
    });

    const ed25519Plan = expectPlanKind(
      planSigningSession({
        lane: ed25519Lane,
        readiness: ready(ed25519Lane),
      }),
      'warm_session',
    );
    const ecdsaPlan = expectPlanKind(
      planSigningSession({
        lane: ecdsaLane,
        readiness: ready(ecdsaLane),
      }),
      'warm_session',
    );

    const ed25519Spend = buildWalletSigningSpendPlan({
      operationId: SigningSessionIds.signingOperation('shared-budget-ed25519-op'),
      intent: 'transaction_sign',
    }, ed25519Plan.lane);
    const ecdsaSpend = buildWalletSigningSpendPlan({
      operationId: SigningSessionIds.signingOperation('shared-budget-ecdsa-op'),
      intent: 'transaction_sign',
    }, ecdsaPlan.lane);

    expect(ed25519Spend.walletSigningSessionId).toBe(walletSigningSessionId);
    expect(ecdsaSpend.walletSigningSessionId).toBe(walletSigningSessionId);
    expect(ed25519Spend.thresholdSessionIds).toEqual([
      ed25519Lane.thresholdSessionId,
    ]);
    expect(ecdsaSpend.thresholdSessionIds).toEqual([ecdsaLane.thresholdSessionId]);
    expect(ed25519Spend.uses).toBe(1);
    expect(ecdsaSpend.uses).toBe(1);
  });

  test('selects the active signer lane from a fake dual-auth lane store before planning', () => {
    const rows: Array<{
      name: string;
      lanes: SigningLaneContext[];
      activeAuthMethod: SigningLaneContext['authMethod'];
      expectedPlanKind: SigningSessionPlan['kind'];
    }> = [
      {
        name: 'OTP-only account',
        lanes: [makeLane({ authMethod: 'email_otp', storageSource: 'email_otp' })],
        activeAuthMethod: 'email_otp',
        expectedPlanKind: 'email_otp_reauth',
      },
      {
        name: 'passkey-only account',
        lanes: [makeLane({ authMethod: 'passkey', storageSource: 'login' })],
        activeAuthMethod: 'passkey',
        expectedPlanKind: 'passkey_reauth',
      },
      {
        name: 'dual-auth active OTP account',
        lanes: [
          makeLane({
            authMethod: 'email_otp',
            storageSource: 'email_otp',
          }),
          makeLane({
            authMethod: 'passkey',
            storageSource: 'login',
          }),
        ],
        activeAuthMethod: 'email_otp',
        expectedPlanKind: 'email_otp_reauth',
      },
      {
        name: 'dual-auth active passkey account',
        lanes: [
          makeLane({
            authMethod: 'email_otp',
            storageSource: 'email_otp',
          }),
          makeLane({
            authMethod: 'passkey',
            storageSource: 'login',
          }),
        ],
        activeAuthMethod: 'passkey',
        expectedPlanKind: 'passkey_reauth',
      },
    ];

    for (const row of rows) {
      const lane = createFakeLaneStore(row.lanes).resolveActiveLane(row.activeAuthMethod);
      const plan = planSigningSession({
        lane,
        readiness: exhausted(lane),
      });

      expect.soft(plan.kind, row.name).toBe(row.expectedPlanKind);
      expect.soft(plan.lane, row.name).toBe(lane);
      expect.soft(plan.lane.authMethod, row.name).toBe(row.activeAuthMethod);
    }
  });

  test('fake lane store rejects ambiguous active signer lanes', () => {
    const activeOtpLane = makeLane({
      authMethod: 'email_otp',
    });
    const duplicateActiveOtpLane = makeLane({
      authMethod: 'email_otp',
    });

    expect(() =>
      createFakeLaneStore([activeOtpLane, duplicateActiveOtpLane]).resolveActiveLane('email_otp'),
    ).toThrow('[test] ambiguous active signing lane');
  });

  test('does not invent a cached key ref when ready state lacks a threshold session id', () => {
    const lane = makeLane({
      thresholdSessionId: undefined,
    });

    const plan = expectPlanKind(
      planSigningSession({
        lane,
        readiness: {
          status: 'ready',
        },
      }),
      'not_ready',
    );

    expect(plan.reason).toBe('missing_session');
  });

  test('builds redacted planner decision traces from the pure trace helper', () => {
    const lane = makeLane({
      authMethod: 'email_otp',
      chainFamily: 'evm',
      curve: 'ecdsa',
      thresholdSessionId: SigningSessionIds.thresholdEcdsaSession('tsess-secret-ish'),
      walletSigningSessionId: SigningSessionIds.walletSigningSession('wsess-secret-ish'),
    });

    const plannerInput = {
      lane,
      readiness: exhausted(lane),
    };
    const plan = planSigningSession(plannerInput);
    const trace = createSigningPlannerDecisionTraceEvent(plannerInput, plan);

    expect(plan.kind).toBe('email_otp_reauth');
    expect(trace).toMatchObject({
      event: 'signing_planner_decision',
      readinessStatus: 'exhausted',
      forceFreshAuth: false,
      plan: {
        kind: 'email_otp_reauth',
      },
      lane: {
        accountId: lane.accountId,
        authMethod: 'email_otp',
        curve: 'ecdsa',
        chainFamily: 'evm',
      },
    });

    const traceJson = JSON.stringify(trace);
    expect(traceJson).not.toContain('tsess-secret-ish');
    expect(traceJson).not.toContain('wsess-secret-ish');
    expect(traceJson).not.toContain('signingRootId');
  });

  test('emits redacted lane resolution traces when session tracing is enabled', () => {
    const lane = makeLane({
      authMethod: 'email_otp',
      chainFamily: 'evm',
      curve: 'ecdsa',
      thresholdSessionId: SigningSessionIds.thresholdEcdsaSession('tsess-secret-ish'),
      walletSigningSessionId: SigningSessionIds.walletSigningSession('wsess-secret-ish'),
    });
    const debugCalls: unknown[][] = [];
    const previousDebug = console.debug;
    const hadLocalStorage = Object.prototype.hasOwnProperty.call(globalThis, 'localStorage');
    const previousLocalStorage = (globalThis as { localStorage?: unknown }).localStorage;

    try {
      console.debug = (...args: unknown[]) => {
        debugCalls.push(args);
      };
      Object.defineProperty(globalThis, 'localStorage', {
        configurable: true,
        value: {
          getItem: (key: string) => (key === 'seams:debug:signing-session' ? '1' : null),
        },
      });

      emitSigningLaneResolutionTrace('evm-family', lane, {
        reason: 'unit_test_lane_resolution',
      });
    } finally {
      console.debug = previousDebug;
      if (hadLocalStorage) {
        Object.defineProperty(globalThis, 'localStorage', {
          configurable: true,
          value: previousLocalStorage,
        });
      } else {
        Reflect.deleteProperty(globalThis, 'localStorage');
      }
    }

    expect(debugCalls).toHaveLength(1);
    expect(debugCalls[0][0]).toBe('[SigningLane][evm-family]');
    expect(debugCalls[0][1]).toMatchObject({
      event: 'signing_lane_resolved',
      reason: 'unit_test_lane_resolution',
      lane: {
        accountId: lane.accountId,
        authMethod: 'email_otp',
        curve: 'ecdsa',
        chainFamily: 'evm',
      },
    });

    const traceJson = JSON.stringify(debugCalls);
    expect(traceJson).not.toContain('tsess-secret-ish');
    expect(traceJson).not.toContain('wsess-secret-ish');
    expect(traceJson).not.toContain('signingRootId');
  });

  test('emits redacted auth boundary traces when session tracing is enabled', () => {
    const lane = makeLane({
      authMethod: 'email_otp',
      chainFamily: 'near',
      curve: 'ed25519',
      thresholdSessionId: SigningSessionIds.thresholdEd25519Session('tsess-secret-ish'),
      walletSigningSessionId: SigningSessionIds.walletSigningSession('wsess-secret-ish'),
    });
    const debugCalls: unknown[][] = [];
    const previousDebug = console.debug;
    const hadLocalStorage = Object.prototype.hasOwnProperty.call(globalThis, 'localStorage');
    const previousLocalStorage = (globalThis as { localStorage?: unknown }).localStorage;

    try {
      console.debug = (...args: unknown[]) => {
        debugCalls.push(args);
      };
      Object.defineProperty(globalThis, 'localStorage', {
        configurable: true,
        value: {
          getItem: (key: string) => (key === 'seams:debug:signing-session' ? '1' : null),
        },
      });

      emitSigningBoundaryTrace(
        'near',
        createSigningBoundaryTraceEvent({
          event: 'auth_side_effect_started',
          lane,
          sideEffect: 'email_otp_challenge',
          phase: 'confirmed',
        }),
      );
    } finally {
      console.debug = previousDebug;
      if (hadLocalStorage) {
        Object.defineProperty(globalThis, 'localStorage', {
          configurable: true,
          value: previousLocalStorage,
        });
      } else {
        Reflect.deleteProperty(globalThis, 'localStorage');
      }
    }

    expect(debugCalls).toHaveLength(1);
    expect(debugCalls[0][0]).toBe('[SigningBoundary][near]');
    expect(debugCalls[0][1]).toMatchObject({
      event: 'auth_side_effect_started',
      sideEffect: 'email_otp_challenge',
      phase: 'confirmed',
      lane: {
        accountId: lane.accountId,
        authMethod: 'email_otp',
        curve: 'ed25519',
        chainFamily: 'near',
      },
    });

    const traceJson = JSON.stringify(debugCalls);
    expect(traceJson).not.toContain('tsess-secret-ish');
    expect(traceJson).not.toContain('wsess-secret-ish');
    expect(traceJson).not.toContain('signingRootId');
  });
});

function makeLane(overrides: Partial<SigningLaneContext> = {}): SigningLaneContext {
  const curve = overrides.curve || 'ecdsa';
  const authMethod = overrides.authMethod || 'email_otp';
  const chainFamily = overrides.chainFamily || (curve === 'ed25519' ? 'near' : 'tempo');
  const thresholdSessionId =
    overrides.thresholdSessionId ||
    (curve === 'ed25519'
      ? SigningSessionIds.thresholdEd25519Session('tsess-ed25519-1')
      : SigningSessionIds.thresholdEcdsaSession('tsess-ecdsa-1'));

  return {
    accountId: toAccountId('planner.testnet'),
    authMethod,
    curve,
    keyKind: curve === 'ed25519' ? 'threshold_ed25519' : 'threshold_ecdsa_secp256k1',
    chainFamily,
    walletSigningSessionId: SigningSessionIds.walletSigningSession('wsess-1'),
    thresholdSessionId,
    sessionOrigin: authMethod === 'email_otp' ? 'login' : 'registration',
    storageSource: authMethod === 'email_otp' ? 'email_otp' : 'login',
    retention: 'session',
    signingRootId: 'proj_test:dev',
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

function createFakeLaneStore(lanes: SigningLaneContext[]): {
  resolveActiveLane: (authMethod: SigningLaneContext['authMethod']) => SigningLaneContext;
} {
  return {
    resolveActiveLane: (authMethod) => {
      const matches = lanes.filter((lane) => lane.authMethod === authMethod);
      if (matches.length === 1) return matches[0];
      if (matches.length === 0) throw new Error('[test] active signing lane missing');
      throw new Error('[test] ambiguous active signing lane');
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
