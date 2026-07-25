import { expect, test } from '@playwright/test';
import {
  ROUTER_AB_ED25519_YAO_REGISTRATION_ADMISSION_PATH_V1,
  ROUTER_AB_ED25519_YAO_REGISTRATION_EXECUTE_PATH_V1,
} from '@shared/utils/routerAbEd25519Yao';
import {
  applyD1MigrationFiles,
  cleanupTemporaryD1Database,
  createTemporaryD1Database,
  listD1MigrationFiles,
} from '../helpers/sqliteD1';
import {
  bindLocalYaoRegistrationIntent,
  buildLocalYaoRegistrationFixture,
  callLocalYaoWorker,
  createLocalYaoWorkerEnv,
  LocalYaoRouterBindingFixture,
  registrationExecuteFromAdmission,
} from './helpers/d1LocalDevYaoPersistence.fixtures';

test.describe('local D1 Ed25519 Yao request reconstruction', () => {
  test('replays registration exactly across restart and rejects a conflicting request', async () => {
    const fixture = await createFixture();
    try {
      const registration = buildLocalYaoRegistrationFixture('registration-local-replay-1');
      await bindLocalYaoRegistrationIntent({
        signerDatabase: fixture.signer.database,
        fixture: registration,
      });

      const admission = await callLocalYaoWorker({
        env: fixture.env,
        path: ROUTER_AB_ED25519_YAO_REGISTRATION_ADMISSION_PATH_V1,
        body: registration.admission,
        grant: registration.grant,
      });
      expect(admission.status).toBe(200);
      const admissionReceipt = await admission.json();
      const executeRequest = registrationExecuteFromAdmission(admissionReceipt);
      const first = await callLocalYaoWorker({
        env: fixture.env,
        path: ROUTER_AB_ED25519_YAO_REGISTRATION_EXECUTE_PATH_V1,
        body: executeRequest,
        grant: registration.grant,
      });
      expect(first.status, await first.clone().text()).toBe(200);
      const firstBody = await first.text();

      const restartedEnv = createLocalYaoWorkerEnv({
        consoleDatabase: fixture.console.database,
        signerDatabase: fixture.signer.database,
        router: fixture.router,
      });
      const replay = await callLocalYaoWorker({
        env: restartedEnv,
        path: ROUTER_AB_ED25519_YAO_REGISTRATION_EXECUTE_PATH_V1,
        body: executeRequest,
        grant: registration.grant,
      });
      expect(replay.status).toBe(200);
      expect(await replay.text()).toBe(firstBody);
      expect(fixture.router.executeCalls).toBe(1);

      const conflict = await callLocalYaoWorker({
        env: restartedEnv,
        path: ROUTER_AB_ED25519_YAO_REGISTRATION_EXECUTE_PATH_V1,
        body: registrationExecuteFromAdmission(admissionReceipt, 19),
        grant: registration.grant,
      });
      expect(conflict.status).toBe(409);
      await expect(conflict.json()).resolves.toMatchObject({
        ok: false,
        code: 'binding_mismatch',
      });
      expect(fixture.router.executeCalls).toBe(1);
    } finally {
      fixture.cleanup();
    }
  });

  test('allows one Router effect when reconstructed requests race the same execution', async () => {
    const fixture = await createFixture();
    try {
      const registration = buildLocalYaoRegistrationFixture('registration-local-race-1');
      await bindLocalYaoRegistrationIntent({
        signerDatabase: fixture.signer.database,
        fixture: registration,
      });
      const admission = await callLocalYaoWorker({
        env: fixture.env,
        path: ROUTER_AB_ED25519_YAO_REGISTRATION_ADMISSION_PATH_V1,
        body: registration.admission,
        grant: registration.grant,
      });
      expect(admission.status).toBe(200);
      const executeRequest = registrationExecuteFromAdmission(await admission.json());

      fixture.router.deferNextExecute();
      const winner = callLocalYaoWorker({
        env: fixture.env,
        path: ROUTER_AB_ED25519_YAO_REGISTRATION_EXECUTE_PATH_V1,
        body: executeRequest,
        grant: registration.grant,
      });
      await fixture.router.waitUntilExecuteEntered();
      const contender = await callLocalYaoWorker({
        env: createLocalYaoWorkerEnv({
          consoleDatabase: fixture.console.database,
          signerDatabase: fixture.signer.database,
          router: fixture.router,
        }),
        path: ROUTER_AB_ED25519_YAO_REGISTRATION_EXECUTE_PATH_V1,
        body: executeRequest,
        grant: registration.grant,
      });
      expect(contender.status).toBe(409);
      await expect(contender.json()).resolves.toMatchObject({
        ok: false,
        code: 'execution_in_progress',
      });
      expect(fixture.router.executeCalls).toBe(1);

      fixture.router.releaseDeferredExecute();
      expect((await winner).status).toBe(200);
      const replay = await callLocalYaoWorker({
        env: fixture.env,
        path: ROUTER_AB_ED25519_YAO_REGISTRATION_EXECUTE_PATH_V1,
        body: executeRequest,
        grant: registration.grant,
      });
      expect(replay.status).toBe(200);
      expect(fixture.router.executeCalls).toBe(1);
    } finally {
      fixture.cleanup();
    }
  });
});

async function createFixture() {
  const console = createTemporaryD1Database();
  const signer = createTemporaryD1Database();
  try {
    await applyD1MigrationFiles(console.database, listD1MigrationFiles('d1-console'));
    await applyD1MigrationFiles(signer.database, listD1MigrationFiles('d1-signer'));
    const router = new LocalYaoRouterBindingFixture();
    return {
      console,
      signer,
      router,
      env: createLocalYaoWorkerEnv({
        consoleDatabase: console.database,
        signerDatabase: signer.database,
        router,
      }),
      cleanup(): void {
        cleanupTemporaryD1Database(console.tempDir);
        cleanupTemporaryD1Database(signer.tempDir);
      },
    };
  } catch (error: unknown) {
    cleanupTemporaryD1Database(console.tempDir);
    cleanupTemporaryD1Database(signer.tempDir);
    throw error;
  }
}
