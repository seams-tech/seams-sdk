import { expect, test } from '@playwright/test';
import {
  ROUTER_AB_ED25519_YAO_RECOVERY_ACTIVATE_PATH_V1,
  ROUTER_AB_ED25519_YAO_RECOVERY_ADMISSION_PATH_V1,
  ROUTER_AB_ED25519_YAO_RECOVERY_EXECUTE_PATH_V1,
  ROUTER_AB_ED25519_YAO_RECOVERY_STATUS_PATH_V1,
  ROUTER_AB_ED25519_YAO_WARM_RECOVERY_BOOTSTRAP_PATH_V1,
  type RouterAbEd25519YaoRecoveryActivationRequestV1,
  type RouterAbEd25519YaoRecoveryAdmissionRequestV1,
} from '@shared/utils/routerAbEd25519Yao';
import { CloudflareD1RouterAbEd25519YaoCapabilityPersistence } from '../../packages/wallet-server/src/router/cloudflare/d1/ed25519Yao/d1Ed25519YaoCapabilityPersistence';
import {
  handleRouterAbEd25519YaoRecoveryRequestScopedCloudflareV1,
  type RouterAbEd25519YaoRecoveryRequestScopedCloudflareInputV1,
} from '../../packages/wallet-server/src/router/domains/ed25519Yao/recovery/routerAbEd25519YaoRecoveryRequestScopedCloudflare';
import type {
  RouterAbEd25519YaoActiveCapabilityResolverV1,
  RouterAbEd25519YaoCapabilityPersistenceV1,
  RouterAbEd25519YaoCapabilityPersistenceResultV1,
  RouterAbEd25519YaoCapabilityReplacementOperationV1,
  RouterAbEd25519YaoRecoveryBackend,
  RouterAbEd25519YaoRecoveryBackendResult,
} from '../../packages/wallet-server/src/router/domains/ed25519Yao/recovery/routerAbEd25519YaoRecovery';
import type {
  RouterAbEd25519YaoProductRegistrationPartitionedStateCommitInputV1,
  RouterAbEd25519YaoProductRegistrationPartitionedStateCommitResultV1,
  RouterAbEd25519YaoProductRegistrationPartitionedStateStoreV1,
  RouterAbEd25519YaoProductRegistrationPartitionedStateV1,
} from '../../packages/wallet-server/src/router/domains/ed25519Yao/capabilityLifecycle/routerAbEd25519YaoProductRegistrationPartitionedStateStore';
import {
  buildRouterAbEd25519YaoRecoveryRequestScopedFixture,
  buildRouterAbEd25519YaoCapabilityReplacementFixture,
  buildSecondRouterAbEd25519YaoRecoveryRequestScopedFixture,
  type RouterAbEd25519YaoRecoveryRequestScopedFixture,
} from './helpers/routerAbEd25519YaoRecoveryRequestScoped.fixtures';
import {
  createRouterAbEd25519YaoExistingWalletD1Fixture,
  routerAbEd25519YaoCapabilityLookupFixture,
} from './helpers/routerAbEd25519YaoExistingWalletD1.fixtures';

const EXISTING_WALLET_NAMESPACE = 'yao-existing-wallet-recovery-test';

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

class SuccessfulRecoveryBackend implements RouterAbEd25519YaoRecoveryBackend {
  admitCalls = 0;
  executeCalls = 0;
  activateCalls = 0;

  constructor(private readonly fixture: RouterAbEd25519YaoRecoveryRequestScopedFixture) {}

  admitRecovery(): RouterAbEd25519YaoRecoveryBackendResult {
    this.admitCalls += 1;
    return { ok: true, body: this.fixture.admissionReceipt };
  }

  executeRecovery(): RouterAbEd25519YaoRecoveryBackendResult {
    this.executeCalls += 1;
    return { ok: true, body: this.fixture.executionResult };
  }

  activateRecovery(
    request: RouterAbEd25519YaoRecoveryActivationRequestV1,
  ): RouterAbEd25519YaoRecoveryBackendResult {
    this.activateCalls += 1;
    return { ok: true, body: request };
  }
}

test.describe('request-scoped recovery persistence', () => {
  test('reads the authoritative recovery stage and exact receipts by lifecycle', async () => {
    const fixture = await buildRouterAbEd25519YaoRecoveryRequestScopedFixture();
    const backend = new InspectingRecoveryBackend(fixture, 'success');
    const statusBody = {
      kind: 'router_ab_ed25519_yao_recovery_status_request_v1',
      admission: fixture.admission,
    } as const;

    const missing = await runRecoveryRequest(
      fixture,
      backend,
      ROUTER_AB_ED25519_YAO_RECOVERY_STATUS_PATH_V1,
      statusBody,
    );
    await expect(missing.json()).resolves.toEqual({
      stage: 'missing',
      lifecycle_id: fixture.lifecycleId,
    });

    await runRecoveryRequest(
      fixture,
      backend,
      ROUTER_AB_ED25519_YAO_RECOVERY_ADMISSION_PATH_V1,
      fixture.admission,
    );
    const admitted = await runRecoveryRequest(
      fixture,
      backend,
      ROUTER_AB_ED25519_YAO_RECOVERY_STATUS_PATH_V1,
      statusBody,
    );
    await expect(admitted.json()).resolves.toEqual({
      stage: 'admitted',
      lifecycle_id: fixture.lifecycleId,
      admission_receipt: fixture.admissionReceipt,
    });

    await runRecoveryRequest(
      fixture,
      backend,
      ROUTER_AB_ED25519_YAO_RECOVERY_EXECUTE_PATH_V1,
      fixture.execution,
    );
    const executed = await runRecoveryRequest(
      fixture,
      backend,
      ROUTER_AB_ED25519_YAO_RECOVERY_STATUS_PATH_V1,
      statusBody,
    );
    await expect(executed.json()).resolves.toEqual({
      stage: 'executed',
      lifecycle_id: fixture.lifecycleId,
      admission_receipt: fixture.admissionReceipt,
      execution_result: fixture.executionResult,
    });

    await runRecoveryRequest(
      fixture,
      backend,
      ROUTER_AB_ED25519_YAO_RECOVERY_ACTIVATE_PATH_V1,
      fixture.activation,
    );
    const promoted = await runRecoveryRequest(
      fixture,
      backend,
      ROUTER_AB_ED25519_YAO_RECOVERY_STATUS_PATH_V1,
      statusBody,
    );
    await expect(promoted.json()).resolves.toEqual({
      stage: 'promoted',
      lifecycle_id: fixture.lifecycleId,
      admission_receipt: fixture.admissionReceipt,
      execution_result: fixture.executionResult,
      activation_receipt: {
        binding: fixture.activation.binding,
        public_receipt: fixture.activation.public_receipt,
        active_capability_binding: fixture.admission.replacement_capability_binding,
        retired_capability_binding: fixture.admission.active_capability_binding,
      },
    });
  });

  test('rehydrates a registration-era D1 capability and completes recovery from empty partitioned state', async () => {
    const capability = buildRouterAbEd25519YaoCapabilityReplacementFixture();
    const fixture = await buildRouterAbEd25519YaoRecoveryRequestScopedFixture();
    const d1 = await createRouterAbEd25519YaoExistingWalletD1Fixture({
      namespace: EXISTING_WALLET_NAMESPACE,
      capability: capability.previous,
    });
    try {
      const initial = await d1.store.load(fixture.lifecycleId);
      expect(initial.state.recovery.capabilities.size).toBe(0);

      const backend = new SuccessfulRecoveryBackend(fixture);
      const warmBootstrap = await runRecoveryRequest(
        fixture,
        backend,
        ROUTER_AB_ED25519_YAO_WARM_RECOVERY_BOOTSTRAP_PATH_V1,
        {
          kind: 'router_ab_ed25519_yao_warm_recovery_bootstrap_request_v1',
          walletId: capability.walletId,
          nearAccountId: capability.nearAccountId,
          nearEd25519SigningKeyId: capability.nearSigningKeyId,
          signerSlot:
            capability.previous.admissionRequest.application_binding.key_creation_signer_slot,
          thresholdSessionId: capability.previous.admissionRequest.scope.threshold_session_id,
          signingWorkerId: capability.signingWorkerId,
          participantIds: capability.previous.admissionRequest.participant_ids,
        },
        new AppliedCapabilityPersistence(),
        d1.store,
        d1.runtime,
      );
      const warmBootstrapBody = await warmBootstrap.clone().json();
      expect(warmBootstrap.status, JSON.stringify(warmBootstrapBody)).toBe(200);
      expect(d1.persistedCapabilityLoadCount()).toBe(1);
      const hydrated = await d1.store.load(fixture.lifecycleId);
      expect(hydrated.state.recovery.capabilities.size).toBe(1);
      expect(fixture.admission.active_capability_binding).toEqual(
        capability.previous.activeCapabilityBinding,
      );

      const persistence = new CloudflareD1RouterAbEd25519YaoCapabilityPersistence({
        database: d1.database,
        scope: {
          namespace: EXISTING_WALLET_NAMESPACE,
          orgId: capability.previous.runtimePolicyScope.orgId,
          projectId: capability.previous.runtimePolicyScope.projectId,
          envId: capability.previous.runtimePolicyScope.envId,
        },
        walletStore: d1.walletStore,
        ensureSchema: false,
        now: fixedCapabilityPersistenceNow,
      });
      const admission = await runRecoveryRequest(
        fixture,
        backend,
        ROUTER_AB_ED25519_YAO_RECOVERY_ADMISSION_PATH_V1,
        fixture.admission,
        persistence,
        d1.store,
        d1.runtime,
      );
      const admissionBody = await admission.clone().json();
      expect(admission.status, JSON.stringify(admissionBody)).toBe(200);
      const execution = await runRecoveryRequest(
        fixture,
        backend,
        ROUTER_AB_ED25519_YAO_RECOVERY_EXECUTE_PATH_V1,
        fixture.execution,
        persistence,
        d1.store,
        d1.runtime,
      );
      expect(execution.status).toBe(200);
      const activation = await runRecoveryRequest(
        fixture,
        backend,
        ROUTER_AB_ED25519_YAO_RECOVERY_ACTIVATE_PATH_V1,
        fixture.activation,
        persistence,
        d1.store,
        d1.runtime,
      );
      const activationResponseBody = await activation.clone().json();
      expect(activation.status, JSON.stringify(activationResponseBody)).toBe(200);
      const activationBody = await activation.clone().text();
      const activationReplay = await runRecoveryRequest(
        fixture,
        backend,
        ROUTER_AB_ED25519_YAO_RECOVERY_ACTIVATE_PATH_V1,
        fixture.activation,
        persistence,
        d1.store,
        d1.runtime,
      );
      expect(activationReplay.status).toBe(200);
      expect(await activationReplay.text()).toBe(activationBody);

      const signer = await d1.walletStore.getEd25519SignerBySlot({
        walletId: capability.next.admissionRequest.application_binding.wallet_id,
        signerSlot: capability.next.admissionRequest.application_binding.key_creation_signer_slot,
      });
      expect(signer?.activeYaoCapability).toEqual(capability.next);
      await expect(
        d1.runtime.resolveActiveCapability(
          routerAbEd25519YaoCapabilityLookupFixture(capability.next),
        ),
      ).resolves.toMatchObject({
        ok: true,
        capability: { stateEpoch: capability.next.activationResult.public_receipt.state_epoch },
      });
      expect(d1.persistedCapabilityLoadCount()).toBe(1);
      expect({
        admissionCalls: backend.admitCalls,
        executionCalls: backend.executeCalls,
        activationCalls: backend.activateCalls,
      }).toEqual({ admissionCalls: 1, executionCalls: 1, activationCalls: 1 });
    } finally {
      d1.cleanup();
    }
  });

  test('rehydrates a pruned capability during direct recovery admission', async () => {
    const capability = buildRouterAbEd25519YaoCapabilityReplacementFixture();
    const fixture = await buildRouterAbEd25519YaoRecoveryRequestScopedFixture();
    const d1 = await createRouterAbEd25519YaoExistingWalletD1Fixture({
      namespace: `${EXISTING_WALLET_NAMESPACE}-direct-admission`,
      capability: capability.previous,
    });
    try {
      const initial = await d1.store.load(fixture.lifecycleId);
      expect(initial.state.recovery.capabilities.size).toBe(0);
      expect(fixture.admission.active_capability_binding).toEqual(
        capability.previous.activeCapabilityBinding,
      );

      const admission = await runRecoveryRequest(
        fixture,
        new SuccessfulRecoveryBackend(fixture),
        ROUTER_AB_ED25519_YAO_RECOVERY_ADMISSION_PATH_V1,
        fixture.admission,
        new AppliedCapabilityPersistence(),
        d1.store,
        d1.runtime,
      );

      const body = await admission.clone().json();
      expect(admission.status, JSON.stringify(body)).toBe(200);
      expect(d1.persistedCapabilityLoadCount()).toBe(1);
    } finally {
      d1.cleanup();
    }
  });

  test('routes warm recovery bootstrap through the request-scoped capability resolver', async () => {
    const fixture = await buildRouterAbEd25519YaoRecoveryRequestScopedFixture();
    const response = await runRecoveryRequest(
      fixture,
      new InspectingRecoveryBackend(fixture, 'success'),
      ROUTER_AB_ED25519_YAO_WARM_RECOVERY_BOOTSTRAP_PATH_V1,
      {
        kind: 'router_ab_ed25519_yao_warm_recovery_bootstrap_request_v1',
        walletId: 'wallet-recovery-1',
        nearAccountId: 'wallet-recovery-1.testnet',
        nearEd25519SigningKeyId: 'ed25519ks_recovery_1',
        signerSlot: 1,
        thresholdSessionId: 'wallet-session-recovery-1',
        signingWorkerId: 'signing-worker-recovery-1',
        participantIds: [1, 2],
      },
    );
    expect(response.status).toBe(404);
    await expect(response.json()).resolves.toMatchObject({
      ok: false,
      code: 'unknown_capability',
    });
  });

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
  capabilities: RouterAbEd25519YaoActiveCapabilityResolverV1 = fixture.capabilities,
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
    capabilities,
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

function fixedCapabilityPersistenceNow(): number {
  return 1_900_000_001_000;
}
