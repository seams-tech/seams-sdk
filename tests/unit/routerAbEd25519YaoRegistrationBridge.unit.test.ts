import { expect, test } from '@playwright/test';
import { walletIdFromString } from '../../packages/shared-ts/src/utils/registrationIntent';
import {
  runRouterAbEd25519YaoRegistrationSideEffectV1,
  type RouterAbEd25519YaoRegistrationSideEffectClaimV1,
  type RouterAbEd25519YaoRegistrationSideEffectCompletionV1,
} from '../../packages/sdk-server-ts/src/router/routerAbEd25519YaoRegistrationSideEffectBoundary';
import { createRouterAbEd25519YaoProductRegistrationRequestScopedRuntimeV1 } from '../../packages/sdk-server-ts/src/router/routerAbEd25519YaoProductRegistrationRequestScopedRuntime';
import { buildEd25519YaoCapabilityFixture } from '../helpers/ed25519YaoCapabilityFixtures';
import {
  AlwaysConflictRegistrationBridgePartitionStore,
  createRegistrationBridgePartitionStore,
  OneConflictRegistrationBridgePartitionStore,
  RegistrationSideEffectMemoryStore,
  UnusedSessionAdapter,
} from './helpers/routerAbEd25519YaoRegistrationBridge.fixtures';

const REQUEST_FINGERPRINT = 'I1f3l6f4R6TT7IqKCMGEjU0RiRkmphAMYj6QJfG5UvQ';

type TestResponse = {
  readonly ok: true;
  readonly receipt: string;
};

class SideEffectProbe {
  calls = 0;

  constructor(
    private readonly store: RegistrationSideEffectMemoryStore<TestResponse>,
    private readonly fail = false,
    private readonly key = 'registration-finalize:lifecycle-1',
  ) {}

  async execute(): Promise<TestResponse> {
    this.calls += 1;
    const claimed = await this.store.read(this.key);
    if (
      claimed.kind !== 'present' ||
      claimed.value.kind !== 'router_ab_ed25519_yao_registration_side_effect_claim_v1'
    ) {
      throw new Error('side effect ran before its durable claim');
    }
    if (this.fail) throw new Error('effect response lost');
    return { ok: true, receipt: 'wallet-session-receipt' };
  }
}

function bridgeRunInput(probe: SideEffectProbe) {
  return {
    operation: 'finalize' as const,
    key: 'registration-finalize:lifecycle-1',
    requestFingerprint: REQUEST_FINGERPRINT,
    nowMs: fixedNow,
    execute: probe.execute.bind(probe),
  };
}

function startBridgeRunInput(probe: SideEffectProbe) {
  return {
    operation: 'start' as const,
    key: 'registration-start:intent-grant-digest',
    requestFingerprint: REQUEST_FINGERPRINT,
    nowMs: fixedNow,
    execute: probe.execute.bind(probe),
  };
}

function fixedNow(): number {
  return 1_725_000_000_000;
}

function registrationCapabilityFixture() {
  const walletId = walletIdFromString('wallet-registration-bridge');
  return {
    walletId,
    fixture: buildEd25519YaoCapabilityFixture({
      walletId,
      nearAccountId: 'wallet-registration-bridge.testnet',
      nearEd25519SigningKeyId: 'near-ed25519-registration-bridge',
      thresholdSessionId: 'threshold-registration-bridge',
      signerSlot: 1,
      signingWorkerId: 'signing-worker-bridge',
      participantIds: [1, 2],
      runtimePolicyScope: {
        orgId: 'org-registration-bridge',
        projectId: 'project-registration-bridge',
        envId: 'env-registration-bridge',
        signingRootVersion: 'root-registration-bridge-v1',
      },
      seed: 93,
    }),
  };
}

test.describe('registration side-effect persistence bridge', () => {
  test('claims before effects and replays the exact terminal response without repeating them', async () => {
    const store = new RegistrationSideEffectMemoryStore<TestResponse>();
    const probe = new SideEffectProbe(store);

    await expect(
      runRouterAbEd25519YaoRegistrationSideEffectV1(store, bridgeRunInput(probe)),
    ).resolves.toEqual({
      kind: 'executed',
      value: { ok: true, receipt: 'wallet-session-receipt' },
    });
    await expect(
      runRouterAbEd25519YaoRegistrationSideEffectV1(store, bridgeRunInput(probe)),
    ).resolves.toEqual({
      kind: 'exact_replay',
      value: { ok: true, receipt: 'wallet-session-receipt' },
    });
    expect(probe.calls).toBe(1);
  });

  test('protects registration-intent consumption with the same durable start claim', async () => {
    const store = new RegistrationSideEffectMemoryStore<TestResponse>();
    const probe = new SideEffectProbe(store, false, 'registration-start:intent-grant-digest');

    await expect(
      runRouterAbEd25519YaoRegistrationSideEffectV1(store, startBridgeRunInput(probe)),
    ).resolves.toEqual({
      kind: 'executed',
      value: { ok: true, receipt: 'wallet-session-receipt' },
    });
    await expect(
      runRouterAbEd25519YaoRegistrationSideEffectV1(store, startBridgeRunInput(probe)),
    ).resolves.toEqual({
      kind: 'exact_replay',
      value: { ok: true, receipt: 'wallet-session-receipt' },
    });
    expect(probe.calls).toBe(1);
  });

  test('leaves an uncertain claim durable and never retries an unknown effect', async () => {
    const store = new RegistrationSideEffectMemoryStore<TestResponse>();
    const probe = new SideEffectProbe(store, true);

    await expect(
      runRouterAbEd25519YaoRegistrationSideEffectV1(store, bridgeRunInput(probe)),
    ).resolves.toEqual({
      kind: 'uncertain',
      phase: 'effect',
      message: 'effect response lost',
    });
    await expect(
      runRouterAbEd25519YaoRegistrationSideEffectV1(store, bridgeRunInput(probe)),
    ).resolves.toEqual({ kind: 'in_progress' });
    expect(probe.calls).toBe(1);
  });

  test('does not invoke an effect when the durable claim write throws', async () => {
    const store = new RegistrationSideEffectMemoryStore<TestResponse>();
    store.throwClaimPuts = 1;
    const probe = new SideEffectProbe(store);

    await expect(
      runRouterAbEd25519YaoRegistrationSideEffectV1(store, bridgeRunInput(probe)),
    ).resolves.toEqual({
      kind: 'uncertain',
      phase: 'claim',
      message: 'side-effect claim write unavailable',
    });
    expect(probe.calls).toBe(0);
  });

  test('does not invoke an effect when the initial claim read throws', async () => {
    const store = new RegistrationSideEffectMemoryStore<TestResponse>();
    store.throwReads = 1;
    const probe = new SideEffectProbe(store);

    await expect(
      runRouterAbEd25519YaoRegistrationSideEffectV1(store, bridgeRunInput(probe)),
    ).resolves.toEqual({
      kind: 'uncertain',
      phase: 'claim',
      message: 'side-effect read unavailable',
    });
    expect(probe.calls).toBe(0);
  });

  test('does not invoke an effect when a competing claim cannot be read back', async () => {
    const store = new RegistrationSideEffectMemoryStore<TestResponse>();
    const claimWinner: RouterAbEd25519YaoRegistrationSideEffectClaimV1 = {
      kind: 'router_ab_ed25519_yao_registration_side_effect_claim_v1',
      operation: 'finalize',
      requestFingerprint: REQUEST_FINGERPRINT,
      claimedAtMs: fixedNow(),
    };
    store.claimWinner = claimWinner;
    store.throwReadCalls.add(2);
    const probe = new SideEffectProbe(store);

    await expect(
      runRouterAbEd25519YaoRegistrationSideEffectV1(store, bridgeRunInput(probe)),
    ).resolves.toEqual({
      kind: 'uncertain',
      phase: 'claim',
      message: 'side-effect read unavailable',
    });
    expect(probe.calls).toBe(0);
  });

  test('does not repeat an effect after its terminal write throws', async () => {
    const store = new RegistrationSideEffectMemoryStore<TestResponse>();
    store.throwTerminalPuts = 1;
    const probe = new SideEffectProbe(store);

    await expect(
      runRouterAbEd25519YaoRegistrationSideEffectV1(store, bridgeRunInput(probe)),
    ).resolves.toEqual({
      kind: 'uncertain',
      phase: 'terminal_commit',
      message: 'side-effect terminal write unavailable',
    });
    await expect(
      runRouterAbEd25519YaoRegistrationSideEffectV1(store, bridgeRunInput(probe)),
    ).resolves.toEqual({ kind: 'in_progress' });
    expect(probe.calls).toBe(1);
  });

  test('replays a committed terminal winner after its first reconciliation read throws', async () => {
    const store = new RegistrationSideEffectMemoryStore<TestResponse>();
    store.terminalWinner = {
      kind: 'router_ab_ed25519_yao_registration_side_effect_completion_v1',
      operation: 'finalize',
      requestFingerprint: REQUEST_FINGERPRINT,
      claimedAtMs: fixedNow(),
      completedAtMs: fixedNow(),
      response: { ok: true, receipt: 'wallet-session-receipt' },
    };
    store.throwReadCalls.add(3);
    const probe = new SideEffectProbe(store);

    await expect(
      runRouterAbEd25519YaoRegistrationSideEffectV1(store, bridgeRunInput(probe)),
    ).resolves.toEqual({
      kind: 'uncertain',
      phase: 'terminal_commit',
      message: 'side-effect read unavailable',
    });
    await expect(
      runRouterAbEd25519YaoRegistrationSideEffectV1(store, bridgeRunInput(probe)),
    ).resolves.toEqual({
      kind: 'exact_replay',
      value: { ok: true, receipt: 'wallet-session-receipt' },
    });
    expect(probe.calls).toBe(1);
  });

  test('reconciles an exact terminal winner after the effect response', async () => {
    const store = new RegistrationSideEffectMemoryStore<TestResponse>();
    const probe = new SideEffectProbe(store);
    const terminalWinner: RouterAbEd25519YaoRegistrationSideEffectCompletionV1<TestResponse> = {
      kind: 'router_ab_ed25519_yao_registration_side_effect_completion_v1',
      operation: 'finalize',
      requestFingerprint: REQUEST_FINGERPRINT,
      claimedAtMs: fixedNow(),
      completedAtMs: fixedNow(),
      response: { ok: true, receipt: 'wallet-session-receipt' },
    };
    store.terminalWinner = terminalWinner;

    await expect(
      runRouterAbEd25519YaoRegistrationSideEffectV1(store, bridgeRunInput(probe)),
    ).resolves.toEqual({
      kind: 'exact_replay',
      value: { ok: true, receipt: 'wallet-session-receipt' },
    });
    expect(probe.calls).toBe(1);
  });

  test('reapplies only deterministic capability state after a shared CAS conflict', async () => {
    const delegate = createRegistrationBridgePartitionStore();
    const store = new OneConflictRegistrationBridgePartitionStore(delegate);
    const runtime = createRouterAbEd25519YaoProductRegistrationRequestScopedRuntimeV1({
      signingWorkerId: 'signing-worker-bridge',
      session: new UnusedSessionAdapter(),
      store,
    });
    const { walletId, fixture } = registrationCapabilityFixture();

    await expect(
      runtime.installPersistedActiveCapability(fixture.capability),
    ).resolves.toMatchObject({
      ok: true,
      disposition: 'installed',
    });
    await expect(
      runtime.resolveActiveCapability({
        kind: 'router_ab_ed25519_yao_active_capability_lookup_v1',
        walletId,
        nearAccountId: 'wallet-registration-bridge.testnet',
        nearEd25519SigningKeyId: 'near-ed25519-registration-bridge',
        signerSlot: 1,
        signingWorkerId: 'signing-worker-bridge',
        participantIds: [1, 2],
      }),
    ).resolves.toMatchObject({ ok: true });
    await expect(delegate.load('registration-fixture-93')).resolves.toMatchObject({
      state: {
        export: { authorizationNonces: new Set(['concurrent-winner']) },
      },
    });
  });

  test('stops after one deterministic reconciliation when contention continues', async () => {
    const delegate = createRegistrationBridgePartitionStore();
    const store = new AlwaysConflictRegistrationBridgePartitionStore(delegate);
    const runtime = createRouterAbEd25519YaoProductRegistrationRequestScopedRuntimeV1({
      signingWorkerId: 'signing-worker-bridge',
      session: new UnusedSessionAdapter(),
      store,
    });
    const { fixture } = registrationCapabilityFixture();

    await expect(runtime.installPersistedActiveCapability(fixture.capability)).rejects.toThrow(
      'Request-scoped product state remained contended after one reconciliation',
    );
    expect(store.commitAttempts).toBe(2);
  });
});
