import { expect, test } from '@playwright/test';
import {
  ROUTER_AB_ED25519_YAO_RECOVERY_ACTIVATE_PATH_V1,
  ROUTER_AB_ED25519_YAO_RECOVERY_ADMISSION_PATH_V1,
  ROUTER_AB_ED25519_YAO_RECOVERY_EXECUTE_PATH_V1,
  type RouterAbEd25519YaoRecoveryActivationRequestV1,
  type RouterAbEd25519YaoRecoveryAdmissionRequestV1,
} from '@shared/utils/routerAbEd25519Yao';
import {
  handleRouterAbEd25519YaoRecoveryRequestScopedCloudflareV1,
  type RouterAbEd25519YaoRecoveryRequestScopedCloudflareInputV1,
} from '../../packages/sdk-server-ts/src/router/routerAbEd25519YaoRecoveryRequestScopedCloudflare';
import type {
  RouterAbEd25519YaoCapabilityPersistenceV1,
  RouterAbEd25519YaoCapabilityPersistenceResultV1,
  RouterAbEd25519YaoCapabilityReplacementOperationV1,
  RouterAbEd25519YaoRecoveryBackend,
  RouterAbEd25519YaoRecoveryBackendResult,
} from '../../packages/sdk-server-ts/src/router/routerAbEd25519YaoRecovery';
import type {
  RouterAbEd25519YaoProductRegistrationPartitionedStateCommitInputV1,
  RouterAbEd25519YaoProductRegistrationPartitionedStateCommitResultV1,
  RouterAbEd25519YaoProductRegistrationPartitionedStateStoreV1,
  RouterAbEd25519YaoProductRegistrationPartitionedStateV1,
} from '../../packages/sdk-server-ts/src/router/routerAbEd25519YaoProductRegistrationPartitionedStateStore';
import {
  buildRouterAbEd25519YaoRecoveryRequestScopedFixture,
  buildSecondRouterAbEd25519YaoRecoveryRequestScopedFixture,
  type RouterAbEd25519YaoRecoveryRequestScopedFixture,
} from './helpers/routerAbEd25519YaoRecoveryRequestScoped.fixtures';

type BackendMode =
  | 'success'
  | 'admission_uncertain'
  | 'execution_uncertain'
  | 'activation_uncertain';

class AppliedCapabilityPersistence implements RouterAbEd25519YaoCapabilityPersistenceV1 {
  replaceActiveCapability() {
    return { ok: true, disposition: 'applied' } as const;
  }
}

class ReceiptCapabilityPersistence implements RouterAbEd25519YaoCapabilityPersistenceV1 {
  calls = 0;
  writes = 0;
  private receipt: RouterAbEd25519YaoCapabilityReplacementOperationV1 | null = null;

  constructor(private readonly loseFirstResponse: boolean) {}

  replaceActiveCapability(input: {
    readonly operation: RouterAbEd25519YaoCapabilityReplacementOperationV1;
  }): RouterAbEd25519YaoCapabilityPersistenceResultV1 {
    this.calls += 1;
    if (this.receipt) {
      return this.receipt.operationId === input.operation.operationId &&
        this.receipt.operationFingerprint === input.operation.operationFingerprint
        ? { ok: true, disposition: 'exact_retry' }
        : {
            ok: false,
            disposition: 'rejected',
            code: 'operation_conflict',
            message: 'scripted capability operation conflict',
          };
    }
    this.receipt = input.operation;
    this.writes += 1;
    if (this.loseFirstResponse) {
      return {
        ok: false,
        disposition: 'uncertain',
        code: 'scripted_response_lost',
        message: 'capability replacement response was lost',
      };
    }
    return { ok: true, disposition: 'applied' };
  }
}

class OneShotTerminalConflictStore implements RouterAbEd25519YaoProductRegistrationPartitionedStateStoreV1 {
  private commitsUntilConflict = 2;

  constructor(
    private readonly delegate: RouterAbEd25519YaoProductRegistrationPartitionedStateStoreV1,
  ) {}

  async load(
    lifecycleId: string,
  ): Promise<RouterAbEd25519YaoProductRegistrationPartitionedStateV1> {
    return await this.delegate.load(lifecycleId);
  }

  async commit(
    input: RouterAbEd25519YaoProductRegistrationPartitionedStateCommitInputV1,
  ): Promise<RouterAbEd25519YaoProductRegistrationPartitionedStateCommitResultV1> {
    this.commitsUntilConflict -= 1;
    if (this.commitsUntilConflict === 0) {
      return { kind: 'version_mismatch', key: 'ceremony' };
    }
    return await this.delegate.commit(input);
  }
}

class InspectingRecoveryBackend implements RouterAbEd25519YaoRecoveryBackend {
  admitCalls = 0;
  executeCalls = 0;
  activateCalls = 0;

  constructor(
    private readonly fixture: RouterAbEd25519YaoRecoveryRequestScopedFixture,
    private readonly mode: BackendMode,
  ) {}

  async admitRecovery(
    _request: RouterAbEd25519YaoRecoveryAdmissionRequestV1,
  ): Promise<RouterAbEd25519YaoRecoveryBackendResult> {
    this.admitCalls += 1;
    await expectPersistedRecoveryKind(this.fixture, 'admitting');
    await expectPersistedCapabilityKind(this.fixture, 'suspended');
    if (this.mode === 'admission_uncertain') {
      throw new Error('recovery admission response was lost');
    }
    return { ok: true, body: this.fixture.admissionReceipt };
  }

  async executeRecovery(): Promise<RouterAbEd25519YaoRecoveryBackendResult> {
    this.executeCalls += 1;
    await expectPersistedRecoveryKind(this.fixture, 'executing');
    if (this.mode === 'execution_uncertain') {
      throw new Error('recovery execution response was lost');
    }
    return { ok: true, body: this.fixture.executionResult };
  }

  activateRecovery(
    request: RouterAbEd25519YaoRecoveryActivationRequestV1,
  ): Promise<RouterAbEd25519YaoRecoveryBackendResult> | RouterAbEd25519YaoRecoveryBackendResult {
    this.activateCalls += 1;
    return this.activate(request);
  }

  private async activate(
    request: RouterAbEd25519YaoRecoveryActivationRequestV1,
  ): Promise<RouterAbEd25519YaoRecoveryBackendResult> {
    await expectPersistedRecoveryKind(this.fixture, 'activating');
    if (this.mode === 'activation_uncertain') {
      throw new Error('recovery activation response was lost');
    }
    return { ok: true, body: request };
  }
}

test.describe('request-scoped recovery persistence', () => {
  test('persists admission and execution claims before backend calls', async () => {
    const fixture = await buildRouterAbEd25519YaoRecoveryRequestScopedFixture();
    const backend = new InspectingRecoveryBackend(fixture, 'success');

    const admission = await runRecoveryRequest(
      fixture,
      backend,
      ROUTER_AB_ED25519_YAO_RECOVERY_ADMISSION_PATH_V1,
      fixture.admission,
    );
    expect(admission.status).toBe(200);
    await expect(admission.json()).resolves.toEqual(fixture.admissionReceipt);
    await expectPersistedRecoveryKind(fixture, 'admitted');

    const execution = await runRecoveryRequest(
      fixture,
      backend,
      ROUTER_AB_ED25519_YAO_RECOVERY_EXECUTE_PATH_V1,
      fixture.execution,
    );
    expect(execution.status).toBe(200);
    await expect(execution.json()).resolves.toEqual(fixture.executionResult);
    await expectPersistedRecoveryKind(fixture, 'staged');
    expect({ admitCalls: backend.admitCalls, executeCalls: backend.executeCalls }).toEqual({
      admitCalls: 1,
      executeCalls: 1,
    });
  });

  test('rejects a backend session already claimed by another recovery ceremony', async () => {
    const first = await buildRouterAbEd25519YaoRecoveryRequestScopedFixture();
    const firstBackend = new InspectingRecoveryBackend(first, 'success');
    const firstAdmission = await runRecoveryRequest(
      first,
      firstBackend,
      ROUTER_AB_ED25519_YAO_RECOVERY_ADMISSION_PATH_V1,
      first.admission,
    );
    expect(firstAdmission.status).toBe(200);

    const second = await buildSecondRouterAbEd25519YaoRecoveryRequestScopedFixture(first.store);
    const secondBackend = new InspectingRecoveryBackend(second, 'success');
    const reusedSession = await runRecoveryRequest(
      second,
      secondBackend,
      ROUTER_AB_ED25519_YAO_RECOVERY_ADMISSION_PATH_V1,
      second.admission,
    );
    expect(reusedSession.status).toBe(502);
    await expect(reusedSession.json()).resolves.toMatchObject({
      ok: false,
      code: 'invalid_backend_response',
      message: 'recovery backend reused a session identifier',
    });
    await expectPersistedRecoveryKind(second, 'admission_failed');
    expect(secondBackend.admitCalls).toBe(1);
  });

  test('leaves an admission claim durable when the backend response is uncertain', async () => {
    const fixture = await buildRouterAbEd25519YaoRecoveryRequestScopedFixture();
    const uncertain = new InspectingRecoveryBackend(fixture, 'admission_uncertain');

    const first = await runRecoveryRequest(
      fixture,
      uncertain,
      ROUTER_AB_ED25519_YAO_RECOVERY_ADMISSION_PATH_V1,
      fixture.admission,
    );
    expect(first.status).toBe(503);
    await expect(first.json()).resolves.toMatchObject({
      ok: false,
      code: 'admission_failed',
    });
    await expectPersistedRecoveryKind(fixture, 'admitting');
    await expectPersistedCapabilityKind(fixture, 'suspended');

    const replayBackend = new InspectingRecoveryBackend(fixture, 'success');
    const replay = await runRecoveryRequest(
      fixture,
      replayBackend,
      ROUTER_AB_ED25519_YAO_RECOVERY_ADMISSION_PATH_V1,
      fixture.admission,
    );
    expect(replay.status).toBe(409);
    await expect(replay.json()).resolves.toMatchObject({
      ok: false,
      code: 'admission_in_progress',
    });
    expect({ firstCalls: uncertain.admitCalls, replayCalls: replayBackend.admitCalls }).toEqual({
      firstCalls: 1,
      replayCalls: 0,
    });
  });

  test('leaves an execution claim durable and never retries after an uncertain result', async () => {
    const fixture = await buildRouterAbEd25519YaoRecoveryRequestScopedFixture();
    const admissionBackend = new InspectingRecoveryBackend(fixture, 'success');
    const admission = await runRecoveryRequest(
      fixture,
      admissionBackend,
      ROUTER_AB_ED25519_YAO_RECOVERY_ADMISSION_PATH_V1,
      fixture.admission,
    );
    expect(admission.status).toBe(200);

    const uncertain = new InspectingRecoveryBackend(fixture, 'execution_uncertain');
    const first = await runRecoveryRequest(
      fixture,
      uncertain,
      ROUTER_AB_ED25519_YAO_RECOVERY_EXECUTE_PATH_V1,
      fixture.execution,
    );
    expect(first.status).toBe(503);
    await expect(first.json()).resolves.toMatchObject({
      ok: false,
      code: 'execution_failed',
    });
    await expectPersistedRecoveryKind(fixture, 'executing');

    const replayBackend = new InspectingRecoveryBackend(fixture, 'success');
    const replay = await runRecoveryRequest(
      fixture,
      replayBackend,
      ROUTER_AB_ED25519_YAO_RECOVERY_EXECUTE_PATH_V1,
      fixture.execution,
    );
    expect(replay.status).toBe(409);
    await expect(replay.json()).resolves.toMatchObject({
      ok: false,
      code: 'execution_in_progress',
    });
    expect({ firstCalls: uncertain.executeCalls, replayCalls: replayBackend.executeCalls }).toEqual(
      {
        firstCalls: 1,
        replayCalls: 0,
      },
    );
  });

  test('persists activation before side effects and redelivers the completed receipt', async () => {
    const fixture = await buildRouterAbEd25519YaoRecoveryRequestScopedFixture();
    const backend = new InspectingRecoveryBackend(fixture, 'success');
    await stageRecovery(fixture, backend);
    const persistence = new ReceiptCapabilityPersistence(false);

    const activated = await runRecoveryRequest(
      fixture,
      backend,
      ROUTER_AB_ED25519_YAO_RECOVERY_ACTIVATE_PATH_V1,
      fixture.activation,
      persistence,
    );
    expect(activated.status).toBe(200);
    await expectPersistedRecoveryKind(fixture, 'promoted');

    const replay = await runRecoveryRequest(
      fixture,
      backend,
      ROUTER_AB_ED25519_YAO_RECOVERY_ACTIVATE_PATH_V1,
      fixture.activation,
      persistence,
    );
    expect(replay.status).toBe(200);
    await expect(replay.json()).resolves.toEqual(await activated.json());
    expect({
      backendCalls: backend.activateCalls,
      persistenceCalls: persistence.calls,
      persistenceWrites: persistence.writes,
    }).toEqual({ backendCalls: 1, persistenceCalls: 1, persistenceWrites: 1 });
  });

  test('reconciles a lost capability-replacement response without a duplicate write', async () => {
    const fixture = await buildRouterAbEd25519YaoRecoveryRequestScopedFixture();
    const backend = new InspectingRecoveryBackend(fixture, 'success');
    await stageRecovery(fixture, backend);
    const persistence = new ReceiptCapabilityPersistence(true);

    const uncertain = await runRecoveryRequest(
      fixture,
      backend,
      ROUTER_AB_ED25519_YAO_RECOVERY_ACTIVATE_PATH_V1,
      fixture.activation,
      persistence,
    );
    expect(uncertain.status).toBe(503);
    await expectPersistedRecoveryKind(fixture, 'activating');

    const reconciled = await runRecoveryRequest(
      fixture,
      backend,
      ROUTER_AB_ED25519_YAO_RECOVERY_ACTIVATE_PATH_V1,
      fixture.activation,
      persistence,
    );
    expect(reconciled.status).toBe(200);
    await expectPersistedRecoveryKind(fixture, 'promoted');
    expect({
      backendCalls: backend.activateCalls,
      persistenceCalls: persistence.calls,
      persistenceWrites: persistence.writes,
    }).toEqual({ backendCalls: 2, persistenceCalls: 2, persistenceWrites: 1 });
  });

  test('replays the exact idempotent activation after transport uncertainty and writes once', async () => {
    const fixture = await buildRouterAbEd25519YaoRecoveryRequestScopedFixture();
    const stagingBackend = new InspectingRecoveryBackend(fixture, 'success');
    await stageRecovery(fixture, stagingBackend);
    const uncertainBackend = new InspectingRecoveryBackend(fixture, 'activation_uncertain');
    const persistence = new ReceiptCapabilityPersistence(false);

    const uncertain = await runRecoveryRequest(
      fixture,
      uncertainBackend,
      ROUTER_AB_ED25519_YAO_RECOVERY_ACTIVATE_PATH_V1,
      fixture.activation,
      persistence,
    );
    expect(uncertain.status).toBe(503);
    await expectPersistedRecoveryKind(fixture, 'activating');
    expect(persistence.writes).toBe(0);

    const reconciliationBackend = new InspectingRecoveryBackend(fixture, 'success');
    const reconciled = await runRecoveryRequest(
      fixture,
      reconciliationBackend,
      ROUTER_AB_ED25519_YAO_RECOVERY_ACTIVATE_PATH_V1,
      fixture.activation,
      persistence,
    );
    expect(reconciled.status).toBe(200);
    await expectPersistedRecoveryKind(fixture, 'promoted');
    expect({
      uncertainBackendCalls: uncertainBackend.activateCalls,
      reconciliationBackendCalls: reconciliationBackend.activateCalls,
      persistenceWrites: persistence.writes,
    }).toEqual({
      uncertainBackendCalls: 1,
      reconciliationBackendCalls: 1,
      persistenceWrites: 1,
    });
  });

  test('recovers a terminal state conflict from the capability receipt', async () => {
    const fixture = await buildRouterAbEd25519YaoRecoveryRequestScopedFixture();
    const backend = new InspectingRecoveryBackend(fixture, 'success');
    await stageRecovery(fixture, backend);
    const persistence = new ReceiptCapabilityPersistence(false);
    const conflictingStore = new OneShotTerminalConflictStore(fixture.store);

    const conflicted = await runRecoveryRequest(
      fixture,
      backend,
      ROUTER_AB_ED25519_YAO_RECOVERY_ACTIVATE_PATH_V1,
      fixture.activation,
      persistence,
      conflictingStore,
    );
    expect(conflicted.status).toBe(503);
    await expectPersistedRecoveryKind(fixture, 'activating');

    const reconciled = await runRecoveryRequest(
      fixture,
      backend,
      ROUTER_AB_ED25519_YAO_RECOVERY_ACTIVATE_PATH_V1,
      fixture.activation,
      persistence,
      conflictingStore,
    );
    expect(reconciled.status).toBe(200);
    await expectPersistedRecoveryKind(fixture, 'promoted');
    expect(persistence.writes).toBe(1);
  });
});

async function stageRecovery(
  fixture: RouterAbEd25519YaoRecoveryRequestScopedFixture,
  backend: RouterAbEd25519YaoRecoveryBackend,
): Promise<void> {
  const admission = await runRecoveryRequest(
    fixture,
    backend,
    ROUTER_AB_ED25519_YAO_RECOVERY_ADMISSION_PATH_V1,
    fixture.admission,
  );
  expect(admission.status).toBe(200);
  const execution = await runRecoveryRequest(
    fixture,
    backend,
    ROUTER_AB_ED25519_YAO_RECOVERY_EXECUTE_PATH_V1,
    fixture.execution,
  );
  expect(execution.status).toBe(200);
}

async function runRecoveryRequest(
  fixture: RouterAbEd25519YaoRecoveryRequestScopedFixture,
  backend: RouterAbEd25519YaoRecoveryBackend,
  path: string,
  body: unknown,
  capabilityPersistence: RouterAbEd25519YaoCapabilityPersistenceV1 = new AppliedCapabilityPersistence(),
  store: RouterAbEd25519YaoProductRegistrationPartitionedStateStoreV1 = fixture.store,
): Promise<Response> {
  const input: RouterAbEd25519YaoRecoveryRequestScopedCloudflareInputV1 = {
    request: new Request(`https://router.example.test${path}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    }),
    store,
    backend,
    authorization: fixture.authorization,
    capabilityPersistence,
  };
  return await handleRouterAbEd25519YaoRecoveryRequestScopedCloudflareV1(input);
}

async function expectPersistedRecoveryKind(
  fixture: RouterAbEd25519YaoRecoveryRequestScopedFixture,
  kind:
    | 'admitting'
    | 'admitted'
    | 'admission_failed'
    | 'executing'
    | 'staged'
    | 'activating'
    | 'promoted',
): Promise<void> {
  const snapshot = await fixture.store.load(fixture.lifecycleId);
  const states = [...snapshot.state.recovery.recoveries.values()];
  expect(states).toHaveLength(1);
  expect(states[0]?.kind).toBe(kind);
}

async function expectPersistedCapabilityKind(
  fixture: RouterAbEd25519YaoRecoveryRequestScopedFixture,
  kind: 'active' | 'suspended',
): Promise<void> {
  const snapshot = await fixture.store.load(fixture.lifecycleId);
  const capability = snapshot.state.recovery.capabilities.get(
    bytesToHex(fixture.admission.active_capability_binding),
  );
  expect(capability?.kind).toBe(kind);
}

function bytesToHex(value: readonly number[]): string {
  let result = '';
  for (const byte of value) result += byte.toString(16).padStart(2, '0');
  return result;
}
