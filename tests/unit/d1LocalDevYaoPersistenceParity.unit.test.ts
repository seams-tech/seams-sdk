import { expect, test } from '@playwright/test';
import {
  ROUTER_AB_ED25519_YAO_EXPORT_ADMISSION_PATH_V1,
  ROUTER_AB_ED25519_YAO_EXPORT_EXECUTE_PATH_V1,
  ROUTER_AB_ED25519_YAO_RECOVERY_ACTIVATE_PATH_V1,
  ROUTER_AB_ED25519_YAO_RECOVERY_ADMISSION_PATH_V1,
  ROUTER_AB_ED25519_YAO_RECOVERY_EXECUTE_PATH_V1,
  ROUTER_AB_ED25519_YAO_REGISTRATION_ADMISSION_PATH_V1,
  ROUTER_AB_ED25519_YAO_REGISTRATION_EXECUTE_PATH_V1,
  ROUTER_AB_ED25519_YAO_WARM_RECOVERY_BOOTSTRAP_PATH_V1,
} from '@shared/utils/routerAbEd25519Yao';
import {
  applyD1MigrationFiles,
  cleanupTemporaryD1Database,
  createTemporaryD1Database,
  listD1MigrationFiles,
} from '../helpers/sqliteD1';
import {
  bindLocalYaoRegistrationIntent,
  buildLocalYaoExistingWalletFixture,
  buildLocalYaoRegistrationFixture,
  callLocalYaoWorker,
  createLocalYaoEmailOtpExportAuthorization,
  createLocalYaoWorkerEnv,
  exportExecuteFromAdmission,
  localYaoOrigin,
  LocalYaoRouterBindingFixture,
  recoveryActivationFromExecution,
  recoveryExecuteFromAdmission,
  registrationExecuteFromAdmission,
} from './helpers/d1LocalDevYaoPersistence.fixtures';
import { createD1TenantRootCreationGrantServiceV1 } from '../../packages/wallet-console-server-ts/src/tenantRootCreation/d1';
import { tenantRootIdentityDigestB64uV1 } from '../../packages/wallet-console-server-ts/src/tenantRootCreation/grantSigner';

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

  test('bootstraps persisted capability and replays recovery across a Worker restart', async () => {
    const fixture = await createFixture();
    try {
      const recovery = await buildLocalYaoExistingWalletFixture({
        signerDatabase: fixture.signer.database,
        lifecycleId: 'recovery-local-replay-1',
      });
      const bootstrap = await callLocalYaoWorker({
        env: fixture.env,
        path: ROUTER_AB_ED25519_YAO_WARM_RECOVERY_BOOTSTRAP_PATH_V1,
        body: recovery.warmBootstrap,
        grant: recovery.token,
      });
      expect(bootstrap.status, await bootstrap.clone().text()).toBe(200);
      await expect(bootstrap.json()).resolves.toMatchObject({
        kind: 'router_ab_ed25519_yao_v2_session_bootstrap_v1',
        walletId: recovery.capability.admissionRequest.application_binding.wallet_id,
      });

      const admission = await callLocalYaoWorker({
        env: fixture.env,
        path: ROUTER_AB_ED25519_YAO_RECOVERY_ADMISSION_PATH_V1,
        body: recovery.recoveryAdmission,
        recoveryChallengeId: recovery.recoveryChallengeId,
      });
      expect(admission.status, await admission.clone().text()).toBe(200);
      const admissionBody = await admission.json();
      const executeRequest = recoveryExecuteFromAdmission(admissionBody);
      const executed = await callLocalYaoWorker({
        env: fixture.env,
        path: ROUTER_AB_ED25519_YAO_RECOVERY_EXECUTE_PATH_V1,
        body: executeRequest,
      });
      expect(executed.status, await executed.clone().text()).toBe(200);
      const executionBody = await executed.text();

      const restartedEnv = createLocalYaoWorkerEnv({
        consoleDatabase: fixture.console.database,
        signerDatabase: fixture.signer.database,
        router: fixture.router,
      });
      const replay = await callLocalYaoWorker({
        env: restartedEnv,
        path: ROUTER_AB_ED25519_YAO_RECOVERY_EXECUTE_PATH_V1,
        body: executeRequest,
      });
      expect(replay.status).toBe(200);
      expect(await replay.text()).toBe(executionBody);
      expect(fixture.router.recoveryExecuteCalls).toBe(1);

      const conflict = await callLocalYaoWorker({
        env: restartedEnv,
        path: ROUTER_AB_ED25519_YAO_RECOVERY_EXECUTE_PATH_V1,
        body: recoveryExecuteFromAdmission(admissionBody, 31),
      });
      expect(conflict.status).toBe(409);
      await expect(conflict.json()).resolves.toMatchObject({ ok: false, code: 'binding_mismatch' });
      expect(fixture.router.recoveryExecuteCalls).toBe(1);

      const activation = recoveryActivationFromExecution(JSON.parse(executionBody));
      const activated = await callLocalYaoWorker({
        env: restartedEnv,
        path: ROUTER_AB_ED25519_YAO_RECOVERY_ACTIVATE_PATH_V1,
        body: activation,
      });
      expect(activated.status, await activated.clone().text()).toBe(200);
      expect(fixture.router.recoveryPromotionCalls).toBe(1);
    } finally {
      fixture.cleanup();
    }
  });

  test('replays an Email OTP-authorized export across restart with one Router effect', async () => {
    const fixture = await createFixture();
    try {
      const existing = await buildLocalYaoExistingWalletFixture({
        signerDatabase: fixture.signer.database,
        lifecycleId: 'export-local-replay-1',
      });
      const authorization = await createLocalYaoEmailOtpExportAuthorization({
        env: fixture.env,
        signerDatabase: fixture.signer.database,
        token: existing.token,
        walletId: existing.capability.admissionRequest.application_binding.wallet_id,
        providerSubjectId: existing.emailOtp.providerSubjectId,
        walletAuthMethodId: existing.emailOtp.walletAuthMethodId,
      });
      const admission = await callLocalYaoWorker({
        env: fixture.env,
        path: ROUTER_AB_ED25519_YAO_EXPORT_ADMISSION_PATH_V1,
        body: { protocol: existing.exportProtocol, authorization },
        grant: existing.token,
        origin: localYaoOrigin(),
      });
      expect(admission.status, await admission.clone().text()).toBe(200);
      const admissionBody = await admission.json();
      const executeRequest = exportExecuteFromAdmission(admissionBody);
      const executed = await callLocalYaoWorker({
        env: fixture.env,
        path: ROUTER_AB_ED25519_YAO_EXPORT_EXECUTE_PATH_V1,
        body: {
          protocol: executeRequest,
        },
        grant: existing.token,
      });
      expect(executed.status, await executed.clone().text()).toBe(200);
      const executionBody = await executed.text();

      const restartedEnv = createLocalYaoWorkerEnv({
        consoleDatabase: fixture.console.database,
        signerDatabase: fixture.signer.database,
        router: fixture.router,
      });
      const replay = await callLocalYaoWorker({
        env: restartedEnv,
        path: ROUTER_AB_ED25519_YAO_EXPORT_EXECUTE_PATH_V1,
        body: {
          protocol: executeRequest,
        },
        grant: existing.token,
      });
      expect(replay.status).toBe(200);
      expect(await replay.text()).toBe(executionBody);
      expect(fixture.router.exportExecuteCalls).toBe(1);

      const conflict = await callLocalYaoWorker({
        env: restartedEnv,
        path: ROUTER_AB_ED25519_YAO_EXPORT_EXECUTE_PATH_V1,
        body: {
          protocol: exportExecuteFromAdmission(admissionBody, 41),
        },
        grant: existing.token,
      });
      expect(conflict.status).toBe(409);
      await expect(conflict.json()).resolves.toMatchObject({ ok: false, code: 'export_consumed' });
      expect(fixture.router.exportExecuteCalls).toBe(1);
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
    await activateFixtureTenantRoot(console.database);
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

async function activateFixtureTenantRoot(
  database: Parameters<typeof createD1TenantRootCreationGrantServiceV1>[0]['database'],
): Promise<void> {
  const identity = {
    orgId: 'org_abcdefgh1234',
    projectId: 'project-local-yao',
    envId: 'env-local-yao',
    signingRootId: 'project-local-yao:env-local-yao',
    signingRootVersion: 'root-local-yao-v1',
  };
  const identityDigestB64u = await tenantRootIdentityDigestB64uV1(identity);
  const custodyLineageB64u = Buffer.alloc(16, 0x22).toString('base64url');
  const grant = createD1TenantRootCreationGrantServiceV1({
    database,
    namespace: 'seams-local-yao-persistence',
  });
  const issuedAtMs = Date.now();
  await grant.putOrGetGrant({
    operationId: 'tenant-root-fixture',
    identity,
    identityDigestB64u,
    custodyLineageB64u,
    grantNonceB64u: Buffer.alloc(32, 0x33).toString('base64url'),
    grantKeyId: 'fixture-key',
    grantB64u: 'fixture-grant',
    grantDigestB64u: 'fixture-grant-digest',
    issuedAtMs,
    expiresAtMs: issuedAtMs + 120_000,
  });
  await grant.markActiveFromReady({
    operationId: 'tenant-root-fixture',
    identity,
    identityDigestB64u,
    custodyLineageB64u,
    ready: {
      revision: 1,
      rootCommitmentB64u: 'fixture-root-commitment',
      journalDigestB64u: 'fixture-journal-digest',
      capabilityDigestB64u: 'fixture-capability-digest',
    },
  });
}
