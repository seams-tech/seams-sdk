import { expect, test } from '@playwright/test';
import {
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
  RouterAbEd25519YaoRecoveryBackend,
  RouterAbEd25519YaoRecoveryBackendResult,
} from '../../packages/sdk-server-ts/src/router/routerAbEd25519YaoRecovery';
import {
  buildRouterAbEd25519YaoRecoveryRequestScopedFixture,
  type RouterAbEd25519YaoRecoveryRequestScopedFixture,
} from './helpers/routerAbEd25519YaoRecoveryRequestScoped.fixtures';

type BackendMode = 'success' | 'admission_uncertain' | 'execution_uncertain';

class InspectingRecoveryBackend implements RouterAbEd25519YaoRecoveryBackend {
  admitCalls = 0;
  executeCalls = 0;

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
    _request: RouterAbEd25519YaoRecoveryActivationRequestV1,
  ): RouterAbEd25519YaoRecoveryBackendResult {
    return {
      ok: false,
      status: 503,
      code: 'activation_outside_test_boundary',
      message: 'Recovery activation is outside the request-scoped test boundary',
    };
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
});

async function runRecoveryRequest(
  fixture: RouterAbEd25519YaoRecoveryRequestScopedFixture,
  backend: RouterAbEd25519YaoRecoveryBackend,
  path: string,
  body: unknown,
): Promise<Response> {
  const input: RouterAbEd25519YaoRecoveryRequestScopedCloudflareInputV1 = {
    request: new Request(`https://router.example.test${path}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    }),
    store: fixture.store,
    backend,
    authorization: fixture.authorization,
  };
  return await handleRouterAbEd25519YaoRecoveryRequestScopedCloudflareV1(input);
}

async function expectPersistedRecoveryKind(
  fixture: RouterAbEd25519YaoRecoveryRequestScopedFixture,
  kind: 'admitting' | 'admitted' | 'executing' | 'staged',
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
  const capabilities = [...snapshot.state.recovery.capabilities.values()];
  expect(capabilities).toHaveLength(1);
  expect(capabilities[0]?.kind).toBe(kind);
}
