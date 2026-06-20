import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const IMPORT_PATHS = {
  routerAbEd25519WalletSessionState:
    '/sdk/esm/core/signingEngine/flows/signNear/shared/routerAbEd25519WalletSessionState.js',
  routerAbWalletSessionCredential:
    '/sdk/esm/core/signingEngine/flows/signNear/shared/routerAbWalletSessionCredential.js',
  warmSessionCapabilityReader:
    '/sdk/esm/core/signingEngine/session/warmCapabilities/capabilityReader.js',
  thresholdSessionStore: '/sdk/esm/core/signingEngine/session/persistence/records.js',
  routerAbSigningWalletSession:
    '/sdk/esm/core/signingEngine/session/routerAbSigningWalletSession.js',
  ed25519SigningMaterialReadiness:
    '/sdk/esm/core/signingEngine/flows/signNear/shared/ed25519SigningMaterialReadiness.js',
  ed25519MaterialRestoreAuthorization:
    '/sdk/esm/core/signingEngine/flows/signNear/shared/ed25519MaterialRestoreAuthorization.js',
  emailOtpClientSecretSource: '/sdk/esm/core/signingEngine/session/emailOtp/clientSecretSource.js',
  hssMaterialBinding: '/sdk/esm/core/signingEngine/threshold/ed25519/hssMaterialBinding.js',
  signerWorkerTypes: '/sdk/esm/core/types/signer-worker.js',
  ecdsaRoleLocalRecords: '/sdk/esm/core/signingEngine/session/persistence/ecdsaRoleLocalRecords.js',
} as const;

test.describe('Router A/B Ed25519 Wallet Session state', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipSeamsWebInit: true });
  });

  test('publishing a fresh Ed25519 runtime lane keeps stale exact lanes out of active listing', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const storeMod = await import(paths.thresholdSessionStore);
        const nearAccountId = 'alice.testnet';
        const common = {
          nearAccountId,
          rpId: 'example.localhost',
          relayerUrl: 'https://relay.example',
          relayerKeyId: 'rk-ed25519',
          participantIds: [1, 2],
          thresholdSessionKind: 'jwt' as const,
          expiresAtMs: Date.now() + 60_000,
        };

        storeMod.clearAllStoredThresholdEd25519SessionRecords();
        try {
          storeMod.upsertStoredThresholdEd25519SessionRecord({
            ...common,
            thresholdSessionId: 'old-passkey-session',
            signingGrantId: 'old-passkey-wallet-session',
            walletSessionJwt: 'jwt-old-passkey',
            remainingUses: 0,
            updatedAtMs: 1,
            source: 'login',
          });
          storeMod.upsertStoredThresholdEd25519SessionRecord({
            ...common,
            thresholdSessionId: 'old-otp-session',
            signingGrantId: 'old-otp-wallet-session',
            walletSessionJwt: 'jwt-old-otp',
            remainingUses: 0,
            updatedAtMs: 2,
            emailOtpAuthContext: {
              policy: 'per_operation',
              retention: 'single_use',
              reason: 'sign',
              authMethod: 'email_otp',
            },
            source: 'email_otp',
          });
          storeMod.upsertStoredThresholdEd25519SessionRecord({
            ...common,
            thresholdSessionId: 'fresh-otp-session',
            signingGrantId: 'fresh-otp-wallet-session',
            walletSessionJwt: 'jwt-fresh-otp',
            remainingUses: 1,
            updatedAtMs: 3,
            emailOtpAuthContext: {
              policy: 'per_operation',
              retention: 'single_use',
              reason: 'sign',
              authMethod: 'email_otp',
            },
            source: 'email_otp',
          });

          const records =
            storeMod.listStoredThresholdEd25519SessionRecordsForAccount(nearAccountId);
          return {
            records: records.map(
              (record: {
                source: string;
                thresholdSessionId: string;
                signingGrantId?: string;
                remainingUses: number;
              }) => ({
                source: record.source,
                thresholdSessionId: record.thresholdSessionId,
                signingGrantId: record.signingGrantId,
                remainingUses: record.remainingUses,
              }),
            ),
            oldPasskeyLanePresent: Boolean(
              storeMod.getStoredThresholdEd25519SessionRecordForLane({
                nearAccountId,
                authMethod: 'passkey',
                signingGrantId: 'old-passkey-wallet-session',
                thresholdSessionId: 'old-passkey-session',
              }),
            ),
            oldOtpLanePresent: Boolean(
              storeMod.getStoredThresholdEd25519SessionRecordForLane({
                nearAccountId,
                authMethod: 'email_otp',
                signingGrantId: 'old-otp-wallet-session',
                thresholdSessionId: 'old-otp-session',
              }),
            ),
            freshOtpLanePresent: Boolean(
              storeMod.getStoredThresholdEd25519SessionRecordForLane({
                nearAccountId,
                authMethod: 'email_otp',
                signingGrantId: 'fresh-otp-wallet-session',
                thresholdSessionId: 'fresh-otp-session',
              }),
            ),
          };
        } finally {
          storeMod.clearAllStoredThresholdEd25519SessionRecords();
        }
      },
      { paths: IMPORT_PATHS },
    );

    expect(result).toEqual({
      records: [
        {
          source: 'email_otp',
          thresholdSessionId: 'fresh-otp-session',
          signingGrantId: 'fresh-otp-wallet-session',
          remainingUses: 1,
        },
      ],
      oldPasskeyLanePresent: true,
      oldOtpLanePresent: true,
      freshOtpLanePresent: true,
    });
  });

  test('resolves canonical Router A/B-ready state from the warm-session record', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const helperMod = await import(paths.routerAbEd25519WalletSessionState);
        const routerAbMod = await import(paths.routerAbWalletSessionCredential);
        const capabilityReaderMod = await import(paths.warmSessionCapabilityReader);
        const storeMod = await import(paths.thresholdSessionStore);

        storeMod.clearAllStoredThresholdEd25519SessionRecords();
        storeMod.upsertStoredThresholdEd25519SessionRecord({
          nearAccountId: 'alice.testnet',
          rpId: 'example.localhost',
          relayerUrl: 'https://relay.example',
          relayerKeyId: 'rk-1',
          participantIds: [1, 2],
          runtimePolicyScope: {
            orgId: 'org-a',
            projectId: 'proj-a',
            envId: 'env-a',
            signingRootVersion: 'default',
          },
          clientVerifyingShareB64u: 'client-verifying-share',
          ed25519WorkerMaterialHandle: 'ed25519-worker-material:canonical-threshold-session:binding',
          ed25519WorkerMaterialBindingDigest: 'binding',
          thresholdSessionKind: 'jwt',
          thresholdSessionId: 'canonical-threshold-session',
          signingGrantId: 'canonical-wallet-session',
          walletSessionJwt: 'jwt-canonical',
          routerAbNormalSigning: {
            kind: 'router_ab_ed25519_normal_signing_v1',
            signingWorkerId: 'signing-worker-canonical',
          },
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 3,
          source: 'registration',
        });

        try {
          const signingSessionCoordinator = capabilityReaderMod.createWarmSessionCapabilityReader();
          const resolved = helperMod.resolveRouterAbEd25519WalletSessionStateFromCurrentRecord(
            signingSessionCoordinator.resolveEd25519RecordByThresholdSessionId(
              'canonical-threshold-session',
            ),
          );
          if (!resolved) throw new Error('canonical Ed25519 session did not resolve');
          const readyState = routerAbMod.requireRouterAbEd25519NormalSigningReadyState({
            state: resolved,
            thresholdSessionId: 'canonical-threshold-session',
            nearAccountId: 'alice.testnet',
            thresholdKeyMaterial: {
              nearAccountId: 'alice.testnet',
              publicKey: 'ed25519:canonical-public-key',
            },
          });
          return {
            kind: readyState.kind,
            thresholdSessionId: readyState.thresholdSessionId,
            signingGrantId: readyState.signingGrantId,
            exposesXClientBaseB64u: Object.prototype.hasOwnProperty.call(
              resolved,
              'xClientBaseB64u',
            ),
            exposesClientVerifyingShareB64u: Object.prototype.hasOwnProperty.call(
              resolved,
              'clientVerifyingShareB64u',
            ),
            signingMaterial: readyState.signingMaterial,
            signingRootId: readyState.signingRootId,
            relayerUrl: readyState.relayerUrl,
            signingWorkerId: readyState.signingWorkerId,
            credential: readyState.credential,
          };
        } finally {
          storeMod.clearAllStoredThresholdEd25519SessionRecords();
        }
      },
      { paths: IMPORT_PATHS },
    );

    expect(result).toEqual({
      kind: 'router_ab_ed25519_normal_signing_ready_state_v1',
      thresholdSessionId: 'canonical-threshold-session',
      signingGrantId: 'canonical-wallet-session',
      exposesXClientBaseB64u: false,
      exposesClientVerifyingShareB64u: false,
      signingMaterial: {
        kind: 'router_ab_ed25519_worker_material_ref_v1',
        materialHandle: 'ed25519-worker-material:canonical-threshold-session:binding',
        bindingDigest: 'binding',
        clientVerifierB64u: 'client-verifying-share',
      },
      signingRootId: 'proj-a:env-a',
      relayerUrl: 'https://relay.example',
      signingWorkerId: 'signing-worker-canonical',
      credential: {
        kind: 'jwt',
        walletSessionJwt: 'jwt-canonical',
      },
    });
  });

  test('restores sealed Ed25519 worker material before normal signing', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const readinessMod = await import(paths.ed25519SigningMaterialReadiness);
        const bindingMod = await import(paths.hssMaterialBinding);
        const signerWorkerTypes = await import(paths.signerWorkerTypes);
        const storeMod = await import(paths.thresholdSessionStore);
        const materialCreatedAtMs = 1_700_000_000_123;
        const clientVerifyingShareB64u = 'client-verifying-share';
        const material = await bindingMod.buildRouterAbEd25519WorkerMaterialBinding({
          nearAccountId: 'alice.testnet',
          signerSlot: 1,
          signingRootId: 'proj-a:env-a',
          signingRootVersion: 'v1',
          relayerKeyId: 'rk-1',
          keyVersion: 'threshold-ed25519-hss-v1',
          participantIds: [1, 2],
          clientVerifyingShareB64u,
          createdAtMs: materialCreatedAtMs,
        });
        const thresholdKeyMaterial = {
          kind: 'threshold_ed25519_v1',
          nearAccountId: 'alice.testnet',
          signerSlot: 1,
          publicKey: 'ed25519:group',
          relayerKeyId: 'rk-1',
          keyVersion: 'threshold-ed25519-hss-v1',
          participants: [
            { id: 1, role: 'client' },
            { id: 2, role: 'relayer', relayerKeyId: 'rk-1' },
          ],
          timestamp: materialCreatedAtMs - 1,
        };
        const calls: string[] = [];

        storeMod.clearAllStoredThresholdEd25519SessionRecords();
        try {
          storeMod.upsertStoredThresholdEd25519SessionRecord({
            nearAccountId: 'alice.testnet',
            rpId: 'example.localhost',
            relayerUrl: 'https://relay.example',
            relayerKeyId: 'rk-1',
            participantIds: [1, 2],
            signingRootId: 'proj-a:env-a',
            signingRootVersion: 'v1',
            runtimePolicyScope: {
              orgId: 'org-a',
              projectId: 'proj-a',
              envId: 'env-a',
              signingRootVersion: 'v1',
            },
            clientVerifyingShareB64u,
            ed25519WorkerMaterialBindingDigest: material.materialBindingDigest,
            sealedWorkerMaterialRef: `ed25519-worker-material-v1:${material.materialBindingDigest}`,
            sealedWorkerMaterialB64u: 'sealed-worker-material',
            materialFormatVersion: 'ed25519_worker_material_v1',
            materialKeyId: material.materialBinding.materialKeyId,
            materialCreatedAtMs,
            signerSlot: 1,
            keyVersion: 'threshold-ed25519-hss-v1',
            thresholdSessionKind: 'jwt',
            thresholdSessionId: 'restore-threshold-session',
            signingGrantId: 'restore-signing-grant',
            walletSessionJwt: 'jwt-restore',
            routerAbNormalSigning: {
              kind: 'router_ab_ed25519_normal_signing_v1',
              signingWorkerId: 'signing-worker-restore',
            },
            expiresAtMs: Date.now() + 60_000,
            remainingUses: 3,
            source: 'login',
          });
          const ready = await readinessMod.requireOrRestoreRouterAbEd25519WalletSessionState({
            ctx: {
              requestWorkerOperation: async ({
                kind,
                request,
              }: {
                kind: string;
                request: { type: string; payload: unknown };
              }) => {
                calls.push(`${kind}:${request.type}`);
                if (
                  request.type ===
                  signerWorkerTypes.NearSignerWorkerCustomRequestType
                    .ThresholdEd25519RestoreWorkerMaterial
                ) {
                  return {
                    ok: true,
                    materialHandle: 'restored-worker-material-handle',
                    materialBindingDigest: material.materialBindingDigest,
                    clientVerifyingShareB64u,
                    sealedWorkerMaterialRef: `ed25519-worker-material-v1:${material.materialBindingDigest}`,
                    sealedWorkerMaterialB64u: 'sealed-worker-material',
                    materialFormatVersion: 'ed25519_worker_material_v1',
                    materialKeyId: material.materialBinding.materialKeyId,
                    signerSlot: 1,
                    keyVersion: 'threshold-ed25519-hss-v1',
                  };
                }
                if (
                  request.type ===
                  signerWorkerTypes.NearSignerWorkerCustomRequestType
                    .ThresholdEd25519ValidateWorkerMaterial
                ) {
                  return {
                    materialHandle: 'restored-worker-material-handle',
                    bindingDigest: material.materialBindingDigest,
                    clientVerifyingShareB64u,
                  };
                }
                throw new Error(`unexpected worker call ${request.type}`);
              },
            },
            signingSessionCoordinator: {
              resolveEd25519RecordByThresholdSessionId: (thresholdSessionId: string) =>
                storeMod.getStoredThresholdEd25519SessionRecordByThresholdSessionId(
                  thresholdSessionId,
                ),
            },
            thresholdSessionId: 'restore-threshold-session',
            operation: 'near_transaction',
            nearAccountId: 'alice.testnet',
            thresholdKeyMaterial,
            restoreAuthorization: {
              kind: 'unseal_authorization_available',
              unsealAuthorization: {
                kind: 'passkey_prf_material_authorization_handle_v1',
                handle: 'unseal-handle',
                purpose: 'unseal',
                rpId: 'example.localhost',
                credentialIdB64u: 'credential',
                materialBindingDigest: material.materialBindingDigest,
                expiresAtMs: Date.now() + 60_000,
              },
            },
          });
          const persisted = storeMod.getStoredThresholdEd25519SessionRecordByThresholdSessionId(
            'restore-threshold-session',
          );
          return {
            calls,
            materialHandle: ready.signingMaterial.materialHandle,
            bindingDigest: ready.signingMaterial.bindingDigest,
            persistedHandle: persisted?.ed25519WorkerMaterialHandle,
            persistedMaterialCreatedAtMs: persisted?.materialCreatedAtMs,
          };
        } finally {
          storeMod.clearAllStoredThresholdEd25519SessionRecords();
        }
      },
      { paths: IMPORT_PATHS },
    );

    expect(result).toEqual({
      calls: [
        'nearSigner:thresholdEd25519RestoreWorkerMaterial',
        'nearSigner:thresholdEd25519ValidateWorkerMaterial',
      ],
      materialHandle: 'restored-worker-material-handle',
      bindingDigest: expect.any(String),
      persistedHandle: 'restored-worker-material-handle',
      persistedMaterialCreatedAtMs: 1_700_000_000_123,
    });
  });

  test('restores a signable Ed25519 record when the current worker has lost the material handle', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const readinessMod = await import(paths.ed25519SigningMaterialReadiness);
        const signingSessionMod = await import(paths.routerAbSigningWalletSession);
        const bindingMod = await import(paths.hssMaterialBinding);
        const signerWorkerTypes = await import(paths.signerWorkerTypes);
        const storeMod = await import(paths.thresholdSessionStore);
        const materialCreatedAtMs = 1_700_000_000_456;
        const clientVerifyingShareB64u = 'client-verifying-share';
        const material = await bindingMod.buildRouterAbEd25519WorkerMaterialBinding({
          nearAccountId: 'alice.testnet',
          signerSlot: 1,
          signingRootId: 'proj-a:env-a',
          signingRootVersion: 'v1',
          relayerKeyId: 'rk-1',
          keyVersion: 'threshold-ed25519-hss-v1',
          participantIds: [1, 2],
          clientVerifyingShareB64u,
          createdAtMs: materialCreatedAtMs,
        });
        const thresholdKeyMaterial = {
          kind: 'threshold_ed25519_v1',
          nearAccountId: 'alice.testnet',
          signerSlot: 1,
          publicKey: 'ed25519:group',
          keyVersion: 'threshold-ed25519-hss-v1',
          relayerKeyId: 'rk-1',
          participants: [
            { id: 1, role: 'client' },
            { id: 2, role: 'relayer', relayerKeyId: 'rk-1' },
          ],
          timestamp: materialCreatedAtMs - 1,
        };
        const calls: string[] = [];

        storeMod.clearAllStoredThresholdEd25519SessionRecords();
        try {
          storeMod.upsertStoredThresholdEd25519SessionRecord({
            nearAccountId: 'alice.testnet',
            rpId: 'example.localhost',
            relayerUrl: 'https://relay.example',
            relayerKeyId: 'rk-1',
            participantIds: [1, 2],
            signingRootId: 'proj-a:env-a',
            signingRootVersion: 'v1',
            runtimePolicyScope: {
              orgId: 'org-a',
              projectId: 'proj-a',
              envId: 'env-a',
              signingRootVersion: 'v1',
            },
            clientVerifyingShareB64u,
            ed25519WorkerMaterialHandle: 'stale-worker-material-handle',
            ed25519WorkerMaterialBindingDigest: material.materialBindingDigest,
            sealedWorkerMaterialRef: `ed25519-worker-material-v1:${material.materialBindingDigest}`,
            sealedWorkerMaterialB64u: 'sealed-worker-material',
            materialFormatVersion: 'ed25519_worker_material_v1',
            materialKeyId: material.materialBinding.materialKeyId,
            materialCreatedAtMs,
            signerSlot: 1,
            keyVersion: 'threshold-ed25519-hss-v1',
            thresholdSessionKind: 'jwt',
            thresholdSessionId: 'stale-threshold-session',
            signingGrantId: 'stale-signing-grant',
            walletSessionJwt: 'jwt-stale',
            routerAbNormalSigning: {
              kind: 'router_ab_ed25519_normal_signing_v1',
              signingWorkerId: 'signing-worker-stale',
            },
            expiresAtMs: Date.now() + 60_000,
            remainingUses: 3,
            source: 'login',
          });
          const staleRecord = storeMod.getStoredThresholdEd25519SessionRecordByThresholdSessionId(
            'stale-threshold-session',
          );
          signingSessionMod.markRouterAbEd25519WorkerMaterialRuntimeValidated(staleRecord);
          const stateBefore =
            signingSessionMod.classifyRouterAbEd25519PersistedSigningRecord(staleRecord);

          const ready = await readinessMod.requireOrRestoreRouterAbEd25519WalletSessionState({
            ctx: {
              requestWorkerOperation: async ({
                kind,
                request,
              }: {
                kind: string;
                request: { type: string; payload: { existingMaterialHandle?: string } };
              }) => {
                calls.push(`${kind}:${request.type}`);
                if (
                  request.type ===
                  signerWorkerTypes.NearSignerWorkerCustomRequestType
                    .ThresholdEd25519ValidateWorkerMaterial
                ) {
                  if (request.payload.existingMaterialHandle === 'stale-worker-material-handle') {
                    throw new Error('near signer worker Ed25519 HSS material handle is not loaded');
                  }
                  return {
                    materialHandle: 'restored-worker-material-handle',
                    bindingDigest: material.materialBindingDigest,
                    clientVerifyingShareB64u,
                  };
                }
                if (
                  request.type ===
                  signerWorkerTypes.NearSignerWorkerCustomRequestType
                    .ThresholdEd25519RestoreWorkerMaterial
                ) {
                  return {
                    ok: true,
                    materialHandle: 'restored-worker-material-handle',
                    materialBindingDigest: material.materialBindingDigest,
                    clientVerifyingShareB64u,
                    sealedWorkerMaterialRef: `ed25519-worker-material-v1:${material.materialBindingDigest}`,
                    sealedWorkerMaterialB64u: 'sealed-worker-material',
                    materialFormatVersion: 'ed25519_worker_material_v1',
                    materialKeyId: material.materialBinding.materialKeyId,
                    signerSlot: 1,
                    keyVersion: 'threshold-ed25519-hss-v1',
                  };
                }
                throw new Error(`unexpected worker call ${request.type}`);
              },
            },
            signingSessionCoordinator: {
              resolveEd25519RecordByThresholdSessionId: (thresholdSessionId: string) =>
                storeMod.getStoredThresholdEd25519SessionRecordByThresholdSessionId(
                  thresholdSessionId,
                ),
            },
            thresholdSessionId: 'stale-threshold-session',
            operation: 'near_transaction',
            nearAccountId: 'alice.testnet',
            thresholdKeyMaterial,
            restoreAuthorization: {
              kind: 'unseal_authorization_available',
              unsealAuthorization: {
                kind: 'passkey_prf_material_authorization_handle_v1',
                handle: 'unseal-handle',
                purpose: 'unseal',
                rpId: 'example.localhost',
                credentialIdB64u: 'credential',
                materialBindingDigest: material.materialBindingDigest,
                expiresAtMs: Date.now() + 60_000,
              },
            },
          });
          const persisted = storeMod.getStoredThresholdEd25519SessionRecordByThresholdSessionId(
            'stale-threshold-session',
          );
          return {
            stateBefore: { kind: stateBefore.kind, reason: stateBefore.reason || '' },
            calls,
            materialHandle: ready.signingMaterial.materialHandle,
            persistedHandle: persisted?.ed25519WorkerMaterialHandle,
          };
        } finally {
          storeMod.clearAllStoredThresholdEd25519SessionRecords();
        }
      },
      { paths: IMPORT_PATHS },
    );

    expect(result).toEqual({
      stateBefore: { kind: 'runtime_validated', reason: '' },
      calls: [
        'nearSigner:thresholdEd25519ValidateWorkerMaterial',
        'nearSigner:thresholdEd25519RestoreWorkerMaterial',
        'nearSigner:thresholdEd25519ValidateWorkerMaterial',
      ],
      materialHandle: 'restored-worker-material-handle',
      persistedHandle: 'restored-worker-material-handle',
    });
  });

  test('validates unvalidated Ed25519 runtime handle hints before requiring restore', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const readinessMod = await import(paths.ed25519SigningMaterialReadiness);
        const signingSessionMod = await import(paths.routerAbSigningWalletSession);
        const bindingMod = await import(paths.hssMaterialBinding);
        const signerWorkerTypes = await import(paths.signerWorkerTypes);
        const storeMod = await import(paths.thresholdSessionStore);
        const materialCreatedAtMs = 1_700_000_000_321;
        const clientVerifyingShareB64u = 'client-verifying-share';
        const material = await bindingMod.buildRouterAbEd25519WorkerMaterialBinding({
          nearAccountId: 'alice.testnet',
          signerSlot: 1,
          signingRootId: 'proj-a:env-a',
          signingRootVersion: 'v1',
          relayerKeyId: 'rk-1',
          keyVersion: 'threshold-ed25519-hss-v1',
          participantIds: [1, 2],
          clientVerifyingShareB64u,
          createdAtMs: materialCreatedAtMs,
        });
        const thresholdKeyMaterial = {
          kind: 'threshold_ed25519_v1',
          nearAccountId: 'alice.testnet',
          signerSlot: 1,
          publicKey: 'ed25519:group',
          keyVersion: 'threshold-ed25519-hss-v1',
          relayerKeyId: 'rk-1',
          participants: [
            { id: 1, role: 'client' },
            { id: 2, role: 'relayer', relayerKeyId: 'rk-1' },
          ],
          timestamp: materialCreatedAtMs - 1,
        };
        const calls: string[] = [];

        storeMod.clearAllStoredThresholdEd25519SessionRecords();
        try {
          storeMod.upsertStoredThresholdEd25519SessionRecord({
            nearAccountId: 'alice.testnet',
            rpId: 'example.localhost',
            relayerUrl: 'https://relay.example',
            relayerKeyId: 'rk-1',
            participantIds: [1, 2],
            signingRootId: 'proj-a:env-a',
            signingRootVersion: 'v1',
            runtimePolicyScope: {
              orgId: 'org-a',
              projectId: 'proj-a',
              envId: 'env-a',
              signingRootVersion: 'v1',
            },
            clientVerifyingShareB64u,
            ed25519WorkerMaterialHandle: 'runtime-worker-material-handle',
            ed25519WorkerMaterialBindingDigest: material.materialBindingDigest,
            materialCreatedAtMs,
            signerSlot: 1,
            keyVersion: 'threshold-ed25519-hss-v1',
            thresholdSessionKind: 'jwt',
            thresholdSessionId: 'runtime-threshold-session',
            signingGrantId: 'runtime-signing-grant',
            walletSessionJwt: 'jwt-runtime',
            routerAbNormalSigning: {
              kind: 'router_ab_ed25519_normal_signing_v1',
              signingWorkerId: 'signing-worker-runtime',
            },
            expiresAtMs: Date.now() + 60_000,
            remainingUses: 3,
            source: 'login',
          });
          const recordBefore = storeMod.getStoredThresholdEd25519SessionRecordByThresholdSessionId(
            'runtime-threshold-session',
          );
          const stateBefore =
            signingSessionMod.classifyRouterAbEd25519PersistedSigningRecord(recordBefore);

          let ready: { signingMaterial: { materialHandle: string; bindingDigest: string } } | null =
            null;
          let errorMessage = '';
          try {
            ready = await readinessMod.requireOrRestoreRouterAbEd25519WalletSessionState({
              ctx: {
                requestWorkerOperation: async ({
                  kind,
                  request,
                }: {
                  kind: string;
                  request: { type: string; payload: unknown };
                }) => {
                  calls.push(`${kind}:${request.type}`);
                  if (
                    request.type ===
                    signerWorkerTypes.NearSignerWorkerCustomRequestType
                      .ThresholdEd25519ValidateWorkerMaterial
                  ) {
                    return {
                      materialHandle: 'runtime-worker-material-handle',
                      bindingDigest: material.materialBindingDigest,
                      clientVerifyingShareB64u,
                    };
                  }
                  throw new Error(`unexpected worker call ${request.type}`);
                },
              },
              signingSessionCoordinator: {
                resolveEd25519RecordByThresholdSessionId: (thresholdSessionId: string) =>
                  storeMod.getStoredThresholdEd25519SessionRecordByThresholdSessionId(
                    thresholdSessionId,
                  ),
              },
              thresholdSessionId: 'runtime-threshold-session',
              operation: 'near_transaction',
              nearAccountId: 'alice.testnet',
              thresholdKeyMaterial,
              restoreAuthorization: { kind: 'unseal_authorization_unavailable' },
            });
          } catch (error) {
            errorMessage = error instanceof Error ? error.message : String(error);
          }
          return {
            stateBefore:
              stateBefore.kind === 'material_hint_unvalidated'
                ? { kind: stateBefore.kind, reason: stateBefore.reason }
                : { kind: stateBefore.kind, reason: stateBefore.reason || '' },
            calls,
            errorMessage,
            materialHandle: ready?.signingMaterial.materialHandle || '',
            bindingDigest: ready?.signingMaterial.bindingDigest || '',
          };
        } finally {
          storeMod.clearAllStoredThresholdEd25519SessionRecords();
        }
      },
      { paths: IMPORT_PATHS },
    );

    expect(result).toEqual({
      stateBefore: {
        kind: 'material_hint_unvalidated',
        reason: 'worker_material_unvalidated',
      },
      calls: ['nearSigner:thresholdEd25519ValidateWorkerMaterial'],
      errorMessage: '',
      materialHandle: 'runtime-worker-material-handle',
      bindingDigest: expect.any(String),
    });
  });

  test('prepares passkey unseal authorization for restore-available Ed25519 material', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const authorizationMod = await import(paths.ed25519MaterialRestoreAuthorization);
        const bindingMod = await import(paths.hssMaterialBinding);
        const signerWorkerTypes = await import(paths.signerWorkerTypes);
        const storeMod = await import(paths.thresholdSessionStore);
        const materialCreatedAtMs = 1_700_000_000_123;
        const clientVerifyingShareB64u = 'client-verifying-share';
        const material = await bindingMod.buildRouterAbEd25519WorkerMaterialBinding({
          nearAccountId: 'alice.testnet',
          signerSlot: 1,
          signingRootId: 'proj-a:env-a',
          signingRootVersion: 'v1',
          relayerKeyId: 'rk-1',
          keyVersion: 'threshold-ed25519-hss-v1',
          participantIds: [1, 2],
          clientVerifyingShareB64u,
          createdAtMs: materialCreatedAtMs,
        });
        const prfFirstBytes = Uint8Array.from(Array.from({ length: 32 }, (_, index) => index + 1));
        const prfFirstB64u = btoa(String.fromCharCode(...prfFirstBytes))
          .replace(/\+/g, '-')
          .replace(/\//g, '_')
          .replace(/=+$/g, '');
        let requestType = '';
        let materialBindingDigest = '';
        let credentialIdB64u = '';
        let prfFirstLengthAtCall = 0;
        let prfFirstFirstByteAtCall = 0;
        let capturedPrfFirstBytes: Uint8Array | null = null;

        storeMod.clearAllStoredThresholdEd25519SessionRecords();
        try {
          storeMod.upsertStoredThresholdEd25519SessionRecord({
            nearAccountId: 'alice.testnet',
            rpId: 'example.localhost',
            relayerUrl: 'https://relay.example',
            relayerKeyId: 'rk-1',
            participantIds: [1, 2],
            signingRootId: 'proj-a:env-a',
            signingRootVersion: 'v1',
            runtimePolicyScope: {
              orgId: 'org-a',
              projectId: 'proj-a',
              envId: 'env-a',
              signingRootVersion: 'v1',
            },
            clientVerifyingShareB64u,
            ed25519WorkerMaterialBindingDigest: material.materialBindingDigest,
            sealedWorkerMaterialRef: `ed25519-worker-material-v1:${material.materialBindingDigest}`,
            sealedWorkerMaterialB64u: 'sealed-worker-material',
            materialFormatVersion: 'ed25519_worker_material_v1',
            materialKeyId: material.materialBinding.materialKeyId,
            materialCreatedAtMs,
            signerSlot: 1,
            keyVersion: 'threshold-ed25519-hss-v1',
            thresholdSessionKind: 'jwt',
            thresholdSessionId: 'restore-auth-threshold-session',
            signingGrantId: 'restore-auth-signing-grant',
            walletSessionJwt: 'jwt-restore-auth',
            routerAbNormalSigning: {
              kind: 'router_ab_ed25519_normal_signing_v1',
              signingWorkerId: 'signing-worker-restore-auth',
            },
            expiresAtMs: Date.now() + 60_000,
            remainingUses: 3,
            source: 'login',
          });

          const resolved =
            await authorizationMod.resolveRouterAbEd25519WorkerMaterialRestoreAuthorizationForStepUp(
              {
                ctx: {
                  requestWorkerOperation: async ({
                    kind,
                    request,
                  }: {
                    kind: string;
                    request: { type: string; payload: Record<string, unknown> };
                  }) => {
                    const payload = request.payload as {
                      materialBindingDigest: string;
                      credentialIdB64u: string;
                      prfFirstBytes: Uint8Array;
                    };
                    requestType = `${kind}:${request.type}`;
                    materialBindingDigest = payload.materialBindingDigest;
                    credentialIdB64u = payload.credentialIdB64u;
                    prfFirstLengthAtCall = payload.prfFirstBytes.length;
                    prfFirstFirstByteAtCall = payload.prfFirstBytes[0] || 0;
                    capturedPrfFirstBytes = payload.prfFirstBytes;
                    return {
                      ok: true,
                      unsealAuthorization: {
                        kind: 'passkey_prf_material_authorization_handle_v1',
                        handle: 'prepared-unseal-handle',
                        purpose: 'unseal',
                        rpId: 'example.localhost',
                        credentialIdB64u: 'credential-id',
                        materialBindingDigest: payload.materialBindingDigest,
                        expiresAtMs: Date.now() + 60_000,
                      },
                      remainingUses: 1,
                    };
                  },
                },
                signingSessionCoordinator: {
                  resolveEd25519RecordByThresholdSessionId: (thresholdSessionId: string) =>
                    storeMod.getStoredThresholdEd25519SessionRecordByThresholdSessionId(
                      thresholdSessionId,
                    ),
                },
                thresholdSessionId: 'restore-auth-threshold-session',
                stepUpAuthorization: {
                  kind: 'passkey',
                  signingAuthPlan: { kind: 'passkeyReauth' },
                  credential: {
                    id: 'credential-id',
                    rawId: 'credential-id',
                    type: 'public-key',
                    response: {
                      clientDataJSON: '',
                      authenticatorData: '',
                      signature: '',
                    },
                    clientExtensionResults: {
                      prf: {
                        results: {
                          first: prfFirstB64u,
                        },
                      },
                    },
                  },
                  plannedPasskeyReconnect: {
                    sessionId: 'restore-auth-threshold-session',
                    signingGrantId: 'restore-auth-signing-grant',
                    sessionPolicyDigest32: 'policy-digest',
                  },
                },
              },
            );

          return {
            resolvedKind: resolved.kind,
            unsealHandle:
              resolved.kind === 'unseal_authorization_available'
                ? resolved.unsealAuthorization.handle
                : '',
            expectedRequestType: `nearSigner:${signerWorkerTypes.NearSignerWorkerCustomRequestType.ThresholdEd25519PreparePasskeyPrfWorkerMaterialUnsealAuthorization}`,
            requestType,
            materialBindingDigest,
            expectedMaterialBindingDigest: material.materialBindingDigest,
            credentialIdB64u,
            prfFirstLengthAtCall,
            prfFirstFirstByteAtCall,
            prfFirstBytesAfterCall: Array.from(capturedPrfFirstBytes || []),
          };
        } finally {
          storeMod.clearAllStoredThresholdEd25519SessionRecords();
        }
      },
      { paths: IMPORT_PATHS },
    );

    expect(result).toEqual({
      resolvedKind: 'unseal_authorization_available',
      unsealHandle: 'prepared-unseal-handle',
      expectedRequestType:
        'nearSigner:thresholdEd25519PreparePasskeyPrfWorkerMaterialUnsealAuthorization',
      requestType: 'nearSigner:thresholdEd25519PreparePasskeyPrfWorkerMaterialUnsealAuthorization',
      materialBindingDigest: result.expectedMaterialBindingDigest,
      expectedMaterialBindingDigest: expect.any(String),
      credentialIdB64u: 'credential-id',
      prfFirstLengthAtCall: 32,
      prfFirstFirstByteAtCall: 1,
      prfFirstBytesAfterCall: Array.from({ length: 32 }, () => 0),
    });
  });

  test('accepts opaque Email OTP recovery-code unseal authorization for restore-available Ed25519 material', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const authorizationMod = await import(paths.ed25519MaterialRestoreAuthorization);
        const clientSecretSourceMod = await import(paths.emailOtpClientSecretSource);
        const bindingMod = await import(paths.hssMaterialBinding);
        const storeMod = await import(paths.thresholdSessionStore);
        const materialCreatedAtMs = 1_700_000_000_123;
        const clientVerifyingShareB64u = 'client-verifying-share';
        const recoveryCodeBindingDigest =
          await clientSecretSourceMod.recoveryCodeBindingDigestForEmailOtpMaterial({
            authSubjectId: 'auth-subject',
            rpId: 'example.localhost',
            nearAccountId: 'alice.testnet',
          });
        const material = await bindingMod.buildRouterAbEd25519WorkerMaterialBinding({
          nearAccountId: 'alice.testnet',
          signerSlot: 1,
          signingRootId: 'proj-a:env-a',
          signingRootVersion: 'v1',
          relayerKeyId: 'rk-1',
          keyVersion: 'threshold-ed25519-hss-v1',
          participantIds: [1, 2],
          clientVerifyingShareB64u,
          createdAtMs: materialCreatedAtMs,
        });
        const workerCalls: string[] = [];

        storeMod.clearAllStoredThresholdEd25519SessionRecords();
        try {
          storeMod.upsertStoredThresholdEd25519SessionRecord({
            nearAccountId: 'alice.testnet',
            rpId: 'example.localhost',
            relayerUrl: 'https://relay.example',
            relayerKeyId: 'rk-1',
            participantIds: [1, 2],
            signingRootId: 'proj-a:env-a',
            signingRootVersion: 'v1',
            runtimePolicyScope: {
              orgId: 'org-a',
              projectId: 'proj-a',
              envId: 'env-a',
              signingRootVersion: 'v1',
            },
            clientVerifyingShareB64u,
            ed25519WorkerMaterialBindingDigest: material.materialBindingDigest,
            sealedWorkerMaterialRef: `ed25519-worker-material-v1:${material.materialBindingDigest}`,
            sealedWorkerMaterialB64u: 'sealed-worker-material',
            materialFormatVersion: 'ed25519_worker_material_v1',
            materialKeyId: material.materialBinding.materialKeyId,
            materialCreatedAtMs,
            signerSlot: 1,
            keyVersion: 'threshold-ed25519-hss-v1',
            thresholdSessionKind: 'jwt',
            thresholdSessionId: 'email-restore-auth-threshold-session',
            signingGrantId: 'email-restore-auth-signing-grant',
            walletSessionJwt: 'jwt-email-restore-auth',
            routerAbNormalSigning: {
              kind: 'router_ab_ed25519_normal_signing_v1',
              signingWorkerId: 'signing-worker-email-restore-auth',
            },
            expiresAtMs: Date.now() + 60_000,
            remainingUses: 1,
            emailOtpAuthContext: {
              authMethod: 'email_otp',
              policy: 'per_operation',
              retention: 'single_use',
              reason: 'sign',
              authSubjectId: 'auth-subject',
            },
            source: 'email_otp',
          });

          const resolved =
            await authorizationMod.resolveRouterAbEd25519WorkerMaterialRestoreAuthorizationForStepUp(
              {
                ctx: {
                  requestWorkerOperation: async ({ request }: { request: { type: string } }) => {
                    workerCalls.push(request.type);
                    throw new Error('Email OTP restore authorization should already be prepared');
                  },
                },
                signingSessionCoordinator: {
                  resolveEd25519RecordByThresholdSessionId: (thresholdSessionId: string) =>
                    storeMod.getStoredThresholdEd25519SessionRecordByThresholdSessionId(
                      thresholdSessionId,
                    ),
                },
                thresholdSessionId: 'email-restore-auth-threshold-session',
                stepUpAuthorization: {
                  kind: 'email_otp',
                  signingAuthPlan: { kind: 'emailOtpReauth', method: 'email_otp' },
                  challengeId: 'otp-challenge',
                  otpCode: '123456',
                  ed25519MaterialRestoreAuthorization: {
                    kind: 'ed25519_email_otp_material_unseal_authorization_available',
                    unsealAuthorization: {
                      kind: 'recovery_code_material_authorization_handle_v1',
                      handle: 'recovery-code-unseal-handle',
                      purpose: 'unseal',
                      authSubjectId: 'auth-subject',
                      recoveryCodeBindingDigest,
                      materialBindingDigest: material.materialBindingDigest,
                      expiresAtMs: Date.now() + 60_000,
                    },
                  },
                },
              },
            );

          return {
            resolvedKind: resolved.kind,
            unsealAuthorization:
              resolved.kind === 'unseal_authorization_available'
                ? resolved.unsealAuthorization
                : null,
            workerCalls,
            expectedRecoveryCodeBindingDigest: recoveryCodeBindingDigest,
          };
        } finally {
          storeMod.clearAllStoredThresholdEd25519SessionRecords();
        }
      },
      { paths: IMPORT_PATHS },
    );

    expect(result).toEqual({
      resolvedKind: 'unseal_authorization_available',
      unsealAuthorization: {
        kind: 'recovery_code_material_authorization_handle_v1',
        handle: 'recovery-code-unseal-handle',
        purpose: 'unseal',
        authSubjectId: 'auth-subject',
        recoveryCodeBindingDigest: result.expectedRecoveryCodeBindingDigest,
        materialBindingDigest: expect.any(String),
        expiresAtMs: expect.any(Number),
      },
      workerCalls: [],
      expectedRecoveryCodeBindingDigest: expect.any(String),
    });
    expect(result.expectedRecoveryCodeBindingDigest).not.toContain(':');
    expect(result.expectedRecoveryCodeBindingDigest).not.toContain('auth-subject');
  });

  test('rejects Router A/B-ready state without a persisted Ed25519 client verifier', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const helperMod = await import(paths.routerAbEd25519WalletSessionState);
        const signingSessionMod = await import(paths.routerAbSigningWalletSession);
        const capabilityReaderMod = await import(paths.warmSessionCapabilityReader);
        const storeMod = await import(paths.thresholdSessionStore);

        storeMod.clearAllStoredThresholdEd25519SessionRecords();
        try {
          storeMod.upsertStoredThresholdEd25519SessionRecord({
            nearAccountId: 'alice.testnet',
            rpId: 'example.localhost',
            relayerUrl: 'https://relay.example',
            relayerKeyId: 'rk-1',
            participantIds: [1, 2],
            runtimePolicyScope: {
              orgId: 'org-a',
              projectId: 'proj-a',
              envId: 'env-a',
              signingRootVersion: 'default',
            },
            ed25519WorkerMaterialHandle: 'ed25519-worker-material:partial-threshold-session:binding',
            ed25519WorkerMaterialBindingDigest: 'binding',
            thresholdSessionKind: 'jwt',
            thresholdSessionId: 'partial-threshold-session',
            signingGrantId: 'partial-wallet-session',
            walletSessionJwt: 'jwt-partial',
            routerAbNormalSigning: {
              kind: 'router_ab_ed25519_normal_signing_v1',
              signingWorkerId: 'signing-worker-canonical',
            },
            expiresAtMs: Date.now() + 60_000,
            remainingUses: 3,
            source: 'registration',
          });

          const signingSessionCoordinator = capabilityReaderMod.createWarmSessionCapabilityReader();
          const record = signingSessionCoordinator.resolveEd25519RecordByThresholdSessionId(
            'partial-threshold-session',
          );
          return {
            resolved: Boolean(helperMod.resolveRouterAbEd25519WalletSessionStateFromRecord(record)),
            classified: signingSessionMod.classifyRouterAbEd25519PersistedSigningRecord(record),
          };
        } finally {
          storeMod.clearAllStoredThresholdEd25519SessionRecords();
        }
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.resolved).toBe(false);
    expect(result.classified).toMatchObject({
      kind: 'auth_ready_material_pending',
      reason: 'missing_client_verifying_share',
    });
  });

  test('prefers the Ed25519 record when ECDSA shares the same threshold session id', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const helperMod = await import(paths.routerAbEd25519WalletSessionState);
        const routerAbMod = await import(paths.routerAbWalletSessionCredential);
        const capabilityReaderMod = await import(paths.warmSessionCapabilityReader);
        const storeMod = await import(paths.thresholdSessionStore);
        const ecdsaRoleLocalMod = await import(paths.ecdsaRoleLocalRecords);
        const ecdsaStoreDeps = {
          recordsByLane: new Map(),
          exportArtifactsByLane: new Map(),
        };

        storeMod.clearAllStoredThresholdEd25519SessionRecords();
        storeMod.clearAllThresholdEcdsaSessionRecords(ecdsaStoreDeps);

        storeMod.upsertStoredThresholdEd25519SessionRecord({
          nearAccountId: 'alice.testnet',
          rpId: 'example.localhost',
          relayerUrl: 'https://relay.example',
          relayerKeyId: 'rk-ed25519',
          participantIds: [1, 2],
          thresholdSessionKind: 'jwt',
          thresholdSessionId: 'shared-session-id',
          signingGrantId: 'shared-wallet-session',
          walletSessionJwt: 'jwt-ed25519',
          clientVerifyingShareB64u: 'client-verifying-share-ed25519',
          ed25519WorkerMaterialHandle: 'ed25519-worker-material:shared-session-id:binding',
          ed25519WorkerMaterialBindingDigest: 'binding',
          runtimePolicyScope: {
            orgId: 'org-a',
            projectId: 'proj-a',
            envId: 'env-a',
            signingRootVersion: 'default',
          },
          routerAbNormalSigning: {
            kind: 'router_ab_ed25519_normal_signing_v1',
            signingWorkerId: 'signing-worker-ed25519',
          },
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 3,
          updatedAtMs: Date.now(),
          source: 'login',
        });

        const chainTarget = {
          kind: 'evm',
          namespace: 'eip155',
          chainId: 5042002,
          networkSlug: 'arc-testnet',
        };
        const ecdsaRoleLocalReadyRecord = ecdsaRoleLocalMod.buildEcdsaRoleLocalReadyRecord({
          stateBlob: {
            kind: 'ecdsa_role_local_state_blob_v1',
            curve: 'secp256k1',
            encoding: 'base64url',
            producer: 'signer_core',
            stateBlobB64u: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
          },
          publicFacts: ecdsaRoleLocalMod.buildEcdsaRoleLocalPublicFacts({
            walletId: 'alice.testnet',
            rpId: 'example.localhost',
            chainTarget,
            keyHandle: 'key-handle-ecdsa',
            ecdsaThresholdKeyId: 'ecdsa-key-id',
            signingRootId: 'proj-a:env-a',
            signingRootVersion: 'default',
            clientParticipantId: 1,
            relayerParticipantId: 2,
            participantIds: [1, 2],
            contextBinding32B64u: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
            hssClientSharePublicKey33B64u: 'AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
            relayerPublicKey33B64u: 'AwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
            groupPublicKey33B64u: 'AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
            ethereumAddress: `0x${'11'.repeat(20)}`,
          }),
          authMethod: ecdsaRoleLocalMod.buildEcdsaRoleLocalPasskeyAuthMethod({
            credentialIdB64u: 'credential-ecdsa',
            rpId: 'example.localhost',
          }),
        });
        const ecdsaNormalSigning = {
          kind: 'router_ab_ecdsa_hss_normal_signing_v1',
          scope: {
            context: {
              wallet_id: 'alice.testnet',
              rp_id: 'example.localhost',
              key_scope: 'evm-family',
              ecdsa_threshold_key_id: 'ecdsa-key-id',
              signing_root_id: 'proj-a:env-a',
              signing_root_version: 'default',
              key_purpose: 'evm-family-signing',
              key_version: 'wallet-session-test',
            },
            public_identity: {
              context_binding_b64u: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
              client_public_key33_b64u: 'AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
              server_public_key33_b64u: 'AwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
              threshold_public_key33_b64u: 'AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
              ethereum_address20_b64u: 'ERERERERERERERERERERERERERE',
              client_share_retry_counter: 0,
              server_share_retry_counter: 0,
            },
            signing_worker: {
              server_id: 'signing-worker-ecdsa',
              key_epoch: 'epoch-ecdsa',
              recipient_encryption_key:
                'x25519:1111111111111111111111111111111111111111111111111111111111111111',
            },
            activation_epoch: 'shared-session-id',
          },
        };
        storeMod.upsertThresholdEcdsaSessionFromBootstrap(ecdsaStoreDeps, {
          walletId: 'alice.testnet',
          chainTarget,
          source: 'login',
          bootstrap: {
            thresholdEcdsaKeyRef: {
              type: 'threshold-ecdsa-secp256k1',
              userId: 'alice.testnet',
              chainTarget,
              relayerUrl: 'https://relay.example',
              keyHandle: 'key-handle-ecdsa',
              ecdsaThresholdKeyId: 'ecdsa-key-id',
              participantIds: [1, 2],
              backendBinding: {
                materialKind: 'role_local_ready_state_blob',
                relayerKeyId: 'rk-ecdsa',
                clientVerifyingShareB64u: 'AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
                stateBlob: ecdsaRoleLocalReadyRecord.stateBlob,
                ecdsaRoleLocalReadyRecord,
              },
              thresholdSessionKind: 'jwt',
              thresholdSessionId: 'shared-session-id',
              signingGrantId: 'shared-wallet-session',
              walletSessionJwt: 'jwt-ecdsa',
              routerAbEcdsaHssNormalSigning: ecdsaNormalSigning,
              ethereumAddress: `0x${'11'.repeat(20)}`,
              thresholdEcdsaPublicKeyB64u: 'AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
              relayerVerifyingShareB64u: 'AwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
            },
            keygen: {
              ok: true,
              rpId: 'example.localhost',
              ecdsaThresholdKeyId: 'ecdsa-key-id',
              clientVerifyingShareB64u: 'AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
              relayerKeyId: 'rk-ecdsa',
              participantIds: [1, 2],
              chainId: 5042002,
              ethereumAddress: `0x${'11'.repeat(20)}`,
              thresholdEcdsaPublicKeyB64u: 'AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
              relayerVerifyingShareB64u: 'AwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
            },
            session: {
              ok: true,
              sessionId: 'shared-session-id',
              signingGrantId: 'shared-wallet-session',
              jwt: 'jwt-ecdsa',
              expiresAtMs: Date.now() + 60_000,
              remainingUses: 3,
              runtimePolicyScope: {
                orgId: 'org-a',
                projectId: 'proj-a',
                envId: 'env-a',
                signingRootVersion: 'default',
              },
            },
          },
        });

        try {
          const signingSessionCoordinator = capabilityReaderMod.createWarmSessionCapabilityReader();
          const directEd25519 =
            storeMod.getStoredThresholdEd25519SessionRecordByThresholdSessionId(
              'shared-session-id',
            );
          const directScoped =
            signingSessionCoordinator.resolveEd25519RecordByThresholdSessionId('shared-session-id');
          const resolved =
            helperMod.resolveRouterAbEd25519WalletSessionStateFromCurrentRecord(directScoped);
          if (!resolved) throw new Error('shared Ed25519 session did not resolve');
          const readyState = routerAbMod.requireRouterAbEd25519NormalSigningReadyState({
            state: resolved,
            thresholdSessionId: 'shared-session-id',
            nearAccountId: 'alice.testnet',
            thresholdKeyMaterial: {
              nearAccountId: 'alice.testnet',
              publicKey: 'ed25519:ed25519-public-key',
            },
          });
          return {
            directEd25519RelayerKeyId: String(directEd25519?.relayerKeyId || ''),
            directScopedRelayerKeyId: String(directScoped?.relayerKeyId || ''),
            thresholdSessionId: readyState.thresholdSessionId,
            signingGrantId: readyState.signingGrantId,
            credential: readyState.credential,
          };
        } finally {
          storeMod.clearAllStoredThresholdEd25519SessionRecords();
          storeMod.clearAllThresholdEcdsaSessionRecords(ecdsaStoreDeps);
        }
      },
      { paths: IMPORT_PATHS },
    );

    expect(result).toEqual({
      directEd25519RelayerKeyId: 'rk-ed25519',
      directScopedRelayerKeyId: 'rk-ed25519',
      thresholdSessionId: 'shared-session-id',
      signingGrantId: 'shared-wallet-session',
      credential: {
        kind: 'jwt',
        walletSessionJwt: 'jwt-ed25519',
      },
    });
  });

  test('persisting an Ed25519 material handle keeps raw client-base material out of records', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const storeMod = await import(paths.thresholdSessionStore);
        const nearAccountId = 'alice.testnet';
        storeMod.clearAllStoredThresholdEd25519SessionRecords();
        try {
          storeMod.upsertStoredThresholdEd25519SessionRecord({
            nearAccountId,
            rpId: 'example.localhost',
            relayerUrl: 'https://relay.example',
            relayerKeyId: 'rk-ed25519',
            participantIds: [1, 2],
            signingRootId: 'proj-a:env-a',
            signingRootVersion: 'v1',
            runtimePolicyScope: {
              orgId: 'org-a',
              projectId: 'proj-a',
              envId: 'env-a',
              signingRootVersion: 'v1',
            },
            clientVerifyingShareB64u: 'old-client-verifying-share',
            thresholdSessionKind: 'jwt',
            thresholdSessionId: 'threshold-session',
            signingGrantId: 'wallet-session',
            walletSessionJwt: 'jwt-ed25519',
            routerAbNormalSigning: {
              kind: 'router_ab_ed25519_normal_signing_v1',
              signingWorkerId: 'signing-worker-ed25519',
            },
            expiresAtMs: Date.now() + 60_000,
            remainingUses: 3,
            source: 'login',
          });

          const persisted = storeMod.persistStoredThresholdEd25519SessionMaterialHandle({
            thresholdSessionId: 'threshold-session',
            ed25519WorkerMaterialHandle: 'ed25519-worker-material:threshold-session:new-binding',
            ed25519WorkerMaterialBindingDigest: 'new-binding',
            clientVerifyingShareB64u: 'new-client-verifying-share',
          });
          const readback =
            storeMod.getStoredThresholdEd25519SessionRecordByThresholdSessionId(
              'threshold-session',
            );
          return {
            persisted,
            readback,
          };
        } finally {
          storeMod.clearAllStoredThresholdEd25519SessionRecords();
        }
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.persisted?.xClientBaseB64u).toBeUndefined();
    expect(result.persisted).toMatchObject({
      thresholdSessionId: 'threshold-session',
      clientVerifyingShareB64u: 'new-client-verifying-share',
      ed25519WorkerMaterialHandle: 'ed25519-worker-material:threshold-session:new-binding',
      ed25519WorkerMaterialBindingDigest: 'new-binding',
    });
    expect(result.readback?.xClientBaseB64u).toBeUndefined();
    expect(result.readback?.clientVerifyingShareB64u).toBe('new-client-verifying-share');
  });

  test('repaired pending-material Ed25519 records resolve as signable Router A/B state', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const helperMod = await import(paths.routerAbEd25519WalletSessionState);
        const signingSessionMod = await import(paths.routerAbSigningWalletSession);
        const capabilityReaderMod = await import(paths.warmSessionCapabilityReader);
        const storeMod = await import(paths.thresholdSessionStore);
        const nearAccountId = 'alice.testnet';
        storeMod.clearAllStoredThresholdEd25519SessionRecords();
        try {
          storeMod.upsertStoredThresholdEd25519SessionRecord({
            nearAccountId,
            rpId: 'example.localhost',
            relayerUrl: 'https://relay.example',
            relayerKeyId: 'rk-ed25519',
            participantIds: [1, 2],
            runtimePolicyScope: {
              orgId: 'org-a',
              projectId: 'proj-a',
              envId: 'env-a',
              signingRootVersion: 'v1',
            },
            thresholdSessionKind: 'jwt',
            thresholdSessionId: 'pending-threshold-session',
            signingGrantId: 'pending-wallet-session',
            walletSessionJwt: 'jwt-ed25519',
            routerAbNormalSigning: {
              kind: 'router_ab_ed25519_normal_signing_v1',
              signingWorkerId: 'signing-worker-ed25519',
            },
            expiresAtMs: Date.now() + 60_000,
            remainingUses: 3,
            source: 'login',
          });

          const pendingRecord = storeMod.getStoredThresholdEd25519SessionRecordByThresholdSessionId(
            'pending-threshold-session',
          );
          const pendingState =
            signingSessionMod.classifyRouterAbEd25519PersistedSigningRecord(pendingRecord);
          const persisted = storeMod.persistStoredThresholdEd25519SessionMaterialHandle({
            thresholdSessionId: 'pending-threshold-session',
            ed25519WorkerMaterialHandle: 'ed25519-worker-material:pending-threshold-session:new-binding',
            ed25519WorkerMaterialBindingDigest: 'new-binding',
            clientVerifyingShareB64u: 'new-client-verifying-share',
          });
          const repairedRecord =
            storeMod.getStoredThresholdEd25519SessionRecordByThresholdSessionId(
              'pending-threshold-session',
            );
          signingSessionMod.markRouterAbEd25519WorkerMaterialRuntimeValidated(repairedRecord);
          const repairedState =
            signingSessionMod.classifyRouterAbEd25519PersistedSigningRecord(repairedRecord);
          const signingSessionCoordinator = capabilityReaderMod.createWarmSessionCapabilityReader();
          const resolved = helperMod.resolveRouterAbEd25519WalletSessionStateFromRecord(
            signingSessionCoordinator.resolveEd25519RecordByThresholdSessionId(
              'pending-threshold-session',
            ),
          );
          if (!resolved) throw new Error('repaired Ed25519 session did not resolve');
          return {
            pendingState,
            persisted,
            repairedState,
            resolved: {
              thresholdSessionId: resolved.thresholdSessionId,
              signingGrantId: resolved.signingGrantId,
              signingRootId: resolved.signingRootId,
              signingRootVersion: resolved.signingRootVersion,
              signingMaterial: resolved.signingMaterial,
            },
          };
        } finally {
          storeMod.clearAllStoredThresholdEd25519SessionRecords();
        }
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.pendingState).toMatchObject({
      kind: 'auth_ready_material_pending',
      reason: 'missing_material_handle',
    });
    expect(result.persisted).toMatchObject({
      thresholdSessionId: 'pending-threshold-session',
      clientVerifyingShareB64u: 'new-client-verifying-share',
    });
    expect(result.repairedState).toMatchObject({
      kind: 'runtime_validated',
      value: {
        signingRootId: 'proj-a:env-a',
        signingRootVersion: 'v1',
        signingMaterial: {
          kind: 'router_ab_ed25519_worker_material_ref_v1',
          materialHandle: 'ed25519-worker-material:pending-threshold-session:new-binding',
          bindingDigest: 'new-binding',
          clientVerifierB64u: 'new-client-verifying-share',
        },
      },
    });
    expect(result.resolved).toEqual({
      thresholdSessionId: 'pending-threshold-session',
      signingGrantId: 'pending-wallet-session',
      signingRootId: 'proj-a:env-a',
      signingRootVersion: 'v1',
      signingMaterial: {
        kind: 'router_ab_ed25519_worker_material_ref_v1',
        materialHandle: 'ed25519-worker-material:pending-threshold-session:new-binding',
        bindingDigest: 'new-binding',
        clientVerifierB64u: 'new-client-verifying-share',
      },
    });
  });

  test('prunes stale Ed25519 raw-material records from the active store', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const storeMod = await import(paths.thresholdSessionStore);
        const nearAccountId = 'alice.testnet';
        storeMod.clearAllStoredThresholdEd25519SessionRecords();
        try {
          const upserted = storeMod.upsertStoredThresholdEd25519SessionRecord({
            nearAccountId,
            rpId: 'example.localhost',
            relayerUrl: 'https://relay.example',
            relayerKeyId: 'rk-ed25519',
            participantIds: [1, 2],
            runtimePolicyScope: {
              orgId: 'org-a',
              projectId: 'proj-a',
              envId: 'env-a',
              signingRootVersion: 'v1',
            },
            xClientBaseB64u: 'stale-x-client-base',
            clientVerifyingShareB64u: 'stale-client-verifying-share',
            thresholdSessionKind: 'jwt',
            thresholdSessionId: 'stale-threshold-session',
            signingGrantId: 'stale-wallet-session',
            walletSessionJwt: 'jwt-ed25519',
            routerAbNormalSigning: {
              kind: 'router_ab_ed25519_normal_signing_v1',
              signingWorkerId: 'signing-worker-stale',
            },
            expiresAtMs: Date.now() + 60_000,
            remainingUses: 3,
            source: 'login',
          });

          return {
            upserted,
            accountRecord: storeMod.getStoredThresholdEd25519SessionRecordForAccount(nearAccountId),
            thresholdRecord:
              storeMod.getStoredThresholdEd25519SessionRecordByThresholdSessionId(
                'stale-threshold-session',
              ),
            laneRecord: storeMod.getStoredThresholdEd25519SessionRecordForLane({
              nearAccountId,
              authMethod: 'passkey',
              signingGrantId: 'stale-wallet-session',
              thresholdSessionId: 'stale-threshold-session',
            }),
            listed: storeMod.listStoredThresholdEd25519SessionRecordsForAccount(nearAccountId),
          };
        } finally {
          storeMod.clearAllStoredThresholdEd25519SessionRecords();
        }
      },
      { paths: IMPORT_PATHS },
    );

    expect(result).toEqual({
      upserted: null,
      accountRecord: null,
      thresholdRecord: null,
      laneRecord: null,
      listed: [],
    });
  });

  test('rejects stale threshold session records with runtimeSnapshotScope or environmentId', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const storeMod = await import(paths.thresholdSessionStore);

        const baseRecord = {
          nearAccountId: 'alice.testnet',
          rpId: 'example.localhost',
          relayerUrl: 'https://relay.example',
          relayerKeyId: 'rk-1',
          participantIds: [1, 2],
          thresholdSessionKind: 'jwt',
          thresholdSessionId: 'stale-threshold-session',
          signingGrantId: 'stale-wallet-session',
          walletSessionJwt: 'jwt-stale',
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 3,
          source: 'registration',
        };

        const attempts: string[] = [];
        try {
          storeMod.upsertStoredThresholdEd25519SessionRecord({
            ...baseRecord,
            runtimePolicyScope: {
              orgId: 'org-a',
              projectId: 'proj-a',
              envId: 'env-a',
              environmentId: 'env-a',
            },
          });
          attempts.push('accepted');
        } catch (error) {
          attempts.push(error instanceof Error ? error.message : String(error));
        }

        const staleRecord = {
          ...baseRecord,
          runtimeSnapshotScope: {
            orgId: 'org-a',
            projectId: 'proj-a',
            envId: 'env-a',
          },
        };
        sessionStorage.setItem(
          'seams:threshold-ed25519-session:v1:alice.testnet',
          JSON.stringify({ v: 1, record: staleRecord }),
        );
        sessionStorage.setItem(
          'seams:threshold-ed25519-session:v1:session-index',
          JSON.stringify({ 'stale-threshold-session': 'alice.testnet' }),
        );
        try {
          attempts.push(
            storeMod.getStoredThresholdEd25519SessionRecordByThresholdSessionId(
              'stale-threshold-session',
            ) === null
              ? 'stale-record-dropped'
              : 'accepted',
          );
        } catch (error) {
          const err = error as { name?: string; reason?: string };
          attempts.push(
            err?.name === 'ThresholdSessionStoreInvalidRecordError'
              ? `stale-record-invalid:${String(err.reason || '')}`
              : String(error || ''),
          );
        }

        storeMod.clearAllStoredThresholdEd25519SessionRecords();
        return attempts;
      },
      { paths: IMPORT_PATHS },
    );

    expect(result).toEqual([
      'Invalid threshold session record: stale runtimePolicyScope',
      'stale-record-dropped',
    ]);
  });

  test('rejects malformed canonical Ed25519 session records at the store boundary', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const storeMod = await import(paths.thresholdSessionStore);

        const makeBaseRecord = (thresholdSessionId: string): Record<string, unknown> => ({
          nearAccountId: `${thresholdSessionId}.testnet`,
          rpId: 'example.localhost',
          relayerUrl: 'https://relay.example',
          relayerKeyId: 'rk-1',
          participantIds: [1, 2],
          thresholdSessionKind: 'jwt',
          thresholdSessionId,
          signingGrantId: `wallet-${thresholdSessionId}`,
          walletSessionJwt: `jwt-${thresholdSessionId}`,
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 3,
          source: 'email_otp',
          emailOtpAuthContext: {
            policy: 'session',
            retention: 'session',
            reason: 'login',
            authMethod: 'email_otp',
          },
        });

        const writeRawRecord = (record: Record<string, unknown>) => {
          const nearAccountId = String(record.nearAccountId || '');
          const thresholdSessionId = String(record.thresholdSessionId || '');
          sessionStorage.setItem(
            `seams:threshold-ed25519-session:v1:${nearAccountId}`,
            JSON.stringify({ v: 1, record }),
          );
          sessionStorage.setItem(
            'seams:threshold-ed25519-session:v1:session-index',
            JSON.stringify({ [thresholdSessionId]: nearAccountId }),
          );
        };

        const malformedCases: Array<{
          name: string;
          record: Record<string, unknown>;
        }> = [
          {
            name: 'missing-remainingUses',
            record: ((record) => {
              delete record.remainingUses;
              return record;
            })(makeBaseRecord('missing-remaining-uses')),
          },
          {
            name: 'negative-remainingUses',
            record: {
              ...makeBaseRecord('negative-remaining-uses'),
              remainingUses: -1,
            },
          },
          {
            name: 'missing-expiresAtMs',
            record: ((record) => {
              delete record.expiresAtMs;
              return record;
            })(makeBaseRecord('missing-expires-at-ms')),
          },
          {
            name: 'invalid-expiresAtMs',
            record: {
              ...makeBaseRecord('invalid-expires-at-ms'),
              expiresAtMs: 0,
            },
          },
          {
            name: 'missing-jwt-for-jwt-session',
            record: ((record) => {
              delete record.walletSessionJwt;
              return record;
            })(makeBaseRecord('missing-jwt')),
          },
          {
            name: 'missing-email-otp-context',
            record: ((record) => {
              delete record.emailOtpAuthContext;
              return record;
            })(makeBaseRecord('missing-email-otp-context')),
          },
          {
            name: 'invalid-email-otp-retention',
            record: {
              ...makeBaseRecord('invalid-email-otp-retention'),
              emailOtpAuthContext: {
                policy: 'per_operation',
                retention: 'session',
                reason: 'sign',
                authMethod: 'email_otp',
              },
            },
          },
        ];

        const readErrorCode = (error: unknown) => {
          const err = error as { name?: string; reason?: string; code?: string };
          if (err?.name === 'ThresholdSessionStoreInvalidRecordError') {
            return `invalid:${String(err.reason || err.code || '')}`;
          }
          return 'missing';
        };

        const attempts: string[] = [];
        try {
          for (const attempt of malformedCases) {
            storeMod.clearAllStoredThresholdEd25519SessionRecords();
            writeRawRecord(attempt.record);
            try {
              const stored = storeMod.getStoredThresholdEd25519SessionRecordByThresholdSessionId(
                String(attempt.record.thresholdSessionId || ''),
              );
              attempts.push(`${attempt.name}:${stored === null ? 'rejected' : 'accepted'}`);
            } catch (error) {
              attempts.push(`${attempt.name}:${readErrorCode(error)}`);
            }
          }

          storeMod.clearAllStoredThresholdEd25519SessionRecords();
          const cookieRecordInput: Record<string, unknown> = {
            ...makeBaseRecord('cookie-without-jwt'),
            thresholdSessionKind: 'cookie',
            walletSessionJwt: undefined,
            clientVerifyingShareB64u: 'cookie-client-verifier',
            ed25519WorkerMaterialHandle: 'ed25519-worker-material:cookie-without-jwt:binding',
            ed25519WorkerMaterialBindingDigest: 'binding',
          };
          storeMod.upsertStoredThresholdEd25519SessionRecord({
            ...cookieRecordInput,
          });
          const cookieRecord =
            storeMod.getStoredThresholdEd25519SessionRecordByThresholdSessionId(
              'cookie-without-jwt',
            );
          attempts.push(`cookie-without-jwt:${cookieRecord ? 'accepted' : 'rejected'}`);
          return attempts;
        } finally {
          storeMod.clearAllStoredThresholdEd25519SessionRecords();
        }
      },
      { paths: IMPORT_PATHS },
    );

    expect(result).toEqual([
      'missing-remainingUses:rejected',
      'negative-remainingUses:rejected',
      'missing-expiresAtMs:rejected',
      'invalid-expiresAtMs:rejected',
      'missing-jwt-for-jwt-session:rejected',
      'missing-email-otp-context:rejected',
      'invalid-email-otp-retention:rejected',
      'cookie-without-jwt:accepted',
    ]);
  });
});
