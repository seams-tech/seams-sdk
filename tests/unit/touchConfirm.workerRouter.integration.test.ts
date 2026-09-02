import { expect, test } from '@playwright/test';
import { buildFullOwnerPermissionsV1 } from '@shared/authorization/delegatedAuthority';
import { buildPasskeyWalletAuthAuthority } from '@shared/utils/walletAuthAuthority';
import { setupBasicPasskeyTest } from '../setup';
import { canonicalEvmFamilyEcdsaSigningCapabilityFixture } from './helpers/ecdsaCapabilityManifest.fixtures';
import {
  buildPasskeyEcdsaSealedRuntimeRecordFixture,
  buildPasskeyEd25519SealedSessionRecordFixture,
} from './helpers/sealedSigningSession.fixtures';
import { buildLinkedDeviceManagementAuthorityFixture } from './helpers/linkedDeviceManagement.fixtures';
import {
  buildEvmFamilyEcdsaKeyIdentity,
  toThresholdOwnerAddress,
} from '../../packages/wallet/src/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import {
  buildEvmFamilyEcdsaSignerBinding,
  exactEcdsaSigningLaneIdentity,
} from '../../packages/wallet/src/core/signingEngine/session/identity/exactSigningLaneIdentity';
import type { CurrentEcdsaSealedSessionRecord } from '../../packages/wallet/src/core/signingEngine/session/persistence/sealedSessionStore';
import { walletIdFromString } from '../../packages/shared-ts/src/utils/registrationIntent';

const IMPORT_PATHS = {
  touchConfirmManager: '/_test-sdk/esm/core/signingEngine/uiConfirm/UiConfirmManager.js',
  passkeyMpcSessionManager:
    '/_test-sdk/esm/core/signingEngine/uiConfirm/PasskeyMpcSessionManager.js',
  passkeyMpcExportManager: '/_test-sdk/esm/core/signingEngine/uiConfirm/PasskeyMpcExportManager.js',
  sealedSessionStore: '/_test-sdk/esm/core/signingEngine/session/persistence/sealedSessionStore.js',
  activeEcdsaCapabilityRuntime:
    '/_test-sdk/esm/core/signingEngine/session/material/activeEcdsaCapabilityRuntime.js',
  ecdsaSealedRuntime:
    '/_test-sdk/esm/core/signingEngine/session/material/ecdsaSealedRuntime.js',
  availableSigningLanes:
    '/_test-sdk/esm/core/signingEngine/session/availability/availableSigningLanes.js',
  selectLane: '/_test-sdk/esm/core/signingEngine/session/identity/selectLane.js',
  indexedDB: '/_test-sdk/esm/core/indexedDB/index.js',
} as const;

async function buildPasskeyRestoreBrowserAuthorizationFixture(
  record: CurrentEcdsaSealedSessionRecord,
  label: string,
) {
  const factorAuthority = buildPasskeyWalletAuthAuthority({
    walletId: String(record.walletId),
    rpId: String(record.ecdsaRestore.rpId),
    credentialIdB64u: String(record.ecdsaRestore.credentialIdB64u),
  });
  return await buildLinkedDeviceManagementAuthorityFixture({
    label,
    permissions: buildFullOwnerPermissionsV1(),
    provenance: 'wallet_registration',
    keyFamily: 'ecdsa_secp256k1',
    materialActivation: record.ecdsaRestore.roleLocalMaterialRef.materialActivation,
    identity: {
      walletId: String(record.walletId),
      authorityId: `authority:passkey-restore-${label}`,
      walletAuthMethodId: factorAuthority.bindingId,
      rpId: String(record.ecdsaRestore.rpId),
      credentialIdB64u: String(record.ecdsaRestore.credentialIdB64u),
    },
    expiresAtMs: Date.now() + 5 * 60_000,
  });
}

async function installPasskeyRestoreBrowserState(input: {
  paths: typeof IMPORT_PATHS;
  sealedRecord: CurrentEcdsaSealedSessionRecord;
  browserAuthorization: Awaited<
    ReturnType<typeof buildPasskeyRestoreBrowserAuthorizationFixture>
  >;
}): Promise<void> {
  const sealedStoreMod = await import(input.paths.sealedSessionStore);
  const indexedDbMod = await import(input.paths.indexedDB);
  await sealedStoreMod.writeExactSealedSession(input.sealedRecord);
  await indexedDbMod.IndexedDBManager.persistFoundingWalletAuthority({
    authority: input.browserAuthorization.authority,
    authMethod: input.browserAuthorization.authMethod,
  });
  await indexedDbMod.walletSessionAuthorizations.writeExactWithOperationCredential({
    record: input.browserAuthorization.activeWalletSession,
    operationCredential: input.browserAuthorization.operationCredential,
  });
  const selected = await indexedDbMod.IndexedDBManager.resolveSelectedWalletAuthority(
    String(input.sealedRecord.walletId),
  );
  const exactSession = await indexedDbMod.walletSessionAuthorizations.readExactWithOperationCredential(
    {
      walletId: input.browserAuthorization.activeWalletSession.walletId,
      authorityId: input.browserAuthorization.authority.authorityId,
      authMethodId: input.browserAuthorization.authMethod.walletAuthMethodId,
    },
  );
  if (selected.kind !== 'resolved' || exactSession.kind !== 'found') {
    throw new Error(
      `Passkey restore authorization fixture failed to install: ${selected.kind}/${exactSession.kind}`,
    );
  }
}

function materialRestoreIdentityFromPasskeyRecord(record: CurrentEcdsaSealedSessionRecord) {
  const restore = record.ecdsaRestore;
  const walletId = walletIdFromString(String(record.walletId));
  const key = buildEvmFamilyEcdsaKeyIdentity({
    walletId,
    ecdsaThresholdKeyId: restore.ecdsaThresholdKeyId,
    signingRootId: restore.signingRootId,
    signingRootVersion: restore.signingRootVersion,
    participantIds: [...restore.participantIds],
    thresholdOwnerAddress: toThresholdOwnerAddress(restore.ethereumAddress),
  });
  return {
    kind: 'ecdsa_role_local_restore' as const,
    lane: exactEcdsaSigningLaneIdentity({
      signer: buildEvmFamilyEcdsaSignerBinding({
        walletId,
        materialActivation: restore.roleLocalMaterialRef.materialActivation,
        chainTarget: restore.chainTarget,
        keyHandle: restore.keyHandle,
        key,
      }),
      auth: {
        kind: 'passkey',
        rpId: restore.rpId,
        credentialIdB64u: restore.credentialIdB64u,
      },
    }),
    ecdsaThresholdKeyId: key.ecdsaThresholdKeyId,
  };
}

test.describe('UserConfirm worker router', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipSeamsWebInit: true });
  });

  test('mounts and closes the registration preparation modal', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.touchConfirmManager);
        const manager = mod.createUiConfirmManager({}, {
          touchIdPrompt: {
            getRpId: () => 'example.localhost',
          },
          userPreferencesManager: {
            getCurrentWalletId: () => '',
          },
        } as any);

        await manager.openRegistrationPreparationModal({
          walletLabel: 'alice.testnet',
          signerSlot: 1,
        });
        const confirmer = document.querySelector('w3a-tx-confirmer') as any;
        const mounted = confirmer
          ? {
              title: confirmer.title,
              body: confirmer.body,
              loading: confirmer.loading,
              nearAccountId: confirmer.nearAccountId,
              rpId: confirmer.securityContext?.rpId,
              signerSlot: confirmer.securityContext?.passkeyRegistration?.signerSlot,
            }
          : null;
        manager.closeRegistrationPreparationModal();
        return {
          mounted,
          remainingConfirmers: document.querySelectorAll('w3a-tx-confirmer').length,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result).toEqual({
      mounted: {
        title: 'Create your passkey',
        body: 'Preparing secure registration…',
        loading: true,
        nearAccountId: 'alice.testnet',
        rpId: 'example.localhost',
        signerSlot: 1,
      },
      remainingConfirmers: 0,
    });
  });

  test('routes concurrent responses by request id with one long-lived listener', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.touchConfirmManager);
        const manager = mod.createUiConfirmManager({}, {
          touchIdPrompt: {},
          nearClient: {},
          indexedDB: {},
          userPreferencesManager: {},
          nearContextFixture: {},
        } as any);

        const listeners: Record<'message' | 'error', Array<(event: any) => void>> = {
          message: [],
          error: [],
        };
        const postedMessages: any[] = [];

        const fakeWorker: Worker = {
          addEventListener: ((type: string, handler: (event: any) => void) => {
            if (type === 'message' || type === 'error') listeners[type].push(handler);
          }) as any,
          removeEventListener: ((type: string, handler: (event: any) => void) => {
            if (type !== 'message' && type !== 'error') return;
            listeners[type] = listeners[type].filter((fn) => fn !== handler);
          }) as any,
          postMessage: ((message: unknown) => {
            postedMessages.push(message);
          }) as any,
          terminate: (() => {}) as any,
        } as unknown as Worker;

        const emitMessage = (data: unknown) => {
          (manager as any).handleWorkerMessage({
            data,
            currentTarget: fakeWorker,
            target: fakeWorker,
          });
        };

        (manager as any).worker = fakeWorker;
        (manager as any).attachWorkerRouter(fakeWorker);

        const p1 = (manager as any).sendMessage(
          {
            type: 'PING',
            id: 'req-1',
            payload: {},
          },
          1000,
        );
        const p2 = (manager as any).sendMessage(
          {
            type: 'WARM_SESSION_STATUS_READ',
            id: 'req-2',
            payload: { sessionId: 'session-1' },
          },
          1000,
        );

        const listenersDuring = {
          message: listeners.message.length,
          error: listeners.error.length,
        };

        emitMessage({ id: 'req-2', success: true, data: { order: 2 } });
        emitMessage({ id: 'req-1', success: true, data: { order: 1 } });

        const [r1, r2] = await Promise.all([p1, p2]);

        return {
          listenersDuring,
          listenersAfter: {
            message: listeners.message.length,
            error: listeners.error.length,
          },
          pendingAfter: (manager as any).pendingWorkerRequests.size,
          postedIds: postedMessages.map((m) => (m as any)?.id),
          responseOrder: [(r1 as any)?.data?.order, (r2 as any)?.data?.order],
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.listenersDuring).toEqual({ message: 1, error: 1 });
    expect(result.listenersAfter).toEqual({ message: 1, error: 1 });
    expect(result.pendingAfter).toBe(0);
    expect(result.postedIds).toEqual(['req-1', 'req-2']);
    expect(result.responseOrder).toEqual([1, 2]);
  });

  test('cleans up pending request on timeout', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.touchConfirmManager);
        const manager = mod.createUiConfirmManager({}, {
          touchIdPrompt: {},
          nearClient: {},
          indexedDB: {},
          userPreferencesManager: {},
          nearContextFixture: {},
        } as any);

        const listeners: Record<'message' | 'error', Array<(event: any) => void>> = {
          message: [],
          error: [],
        };

        const fakeWorker: Worker = {
          addEventListener: ((type: string, handler: (event: any) => void) => {
            if (type === 'message' || type === 'error') listeners[type].push(handler);
          }) as any,
          removeEventListener: ((type: string, handler: (event: any) => void) => {
            if (type !== 'message' && type !== 'error') return;
            listeners[type] = listeners[type].filter((fn) => fn !== handler);
          }) as any,
          postMessage: (() => {}) as any,
          terminate: (() => {}) as any,
        } as unknown as Worker;

        (manager as any).worker = fakeWorker;
        (manager as any).attachWorkerRouter(fakeWorker);

        const timeoutResult = await (manager as any)
          .sendMessage(
            {
              type: 'PING',
              id: 'req-timeout',
              payload: {},
            },
            20,
          )
          .then(
            () => ({ ok: true, error: '' }),
            (error: any) => ({ ok: false, error: String(error?.message || error) }),
          );

        return {
          timeoutResult,
          pendingAfter: (manager as any).pendingWorkerRequests.size,
          listenersAfter: {
            message: listeners.message.length,
            error: listeners.error.length,
          },
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.timeoutResult.ok).toBe(false);
    expect(result.timeoutResult.error).toContain('communication timeout');
    expect(result.timeoutResult.error).toContain('PING');
    expect(result.pendingAfter).toBe(0);
    expect(result.listenersAfter).toEqual({ message: 1, error: 1 });
  });

  test('reads warm-session status snapshots in a single worker round trip', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.passkeyMpcSessionManager);
        const manager = mod.createPasskeyMpcSessionManager({
          signingSessionPersistenceMode: 'none',
          thresholdEcdsaSigningQueueByKey: new Map(),
          resolveCurrentEcdsaCapabilityRuntime: async () => ({
            kind: 'blocked',
            reason: 'missing_capability',
          }),
          persistSigningSessionSealForThresholdSession: async () => null,
          onPolicyResult: async () => {},
        });

        const listeners: Record<'message' | 'error', Array<(event: any) => void>> = {
          message: [],
          error: [],
        };
        const postedMessages: any[] = [];

        const fakeWorker: Worker = {
          addEventListener: ((type: string, handler: (event: any) => void) => {
            if (type === 'message' || type === 'error') listeners[type].push(handler);
          }) as any,
          removeEventListener: ((type: string, handler: (event: any) => void) => {
            if (type !== 'message' && type !== 'error') return;
            listeners[type] = listeners[type].filter((fn) => fn !== handler);
          }) as any,
          postMessage: ((message: unknown) => {
            postedMessages.push(message);
          }) as any,
          terminate: (() => {}) as any,
        } as unknown as Worker;

        const emitMessage = (data: unknown) => {
          (manager as any).handleWorkerMessage({
            data,
            currentTarget: fakeWorker,
            target: fakeWorker,
          });
        };

        const waitForPosted = async (index: number) => {
          for (let i = 0; i < 100; i += 1) {
            if (postedMessages[index]) return postedMessages[index];
            await new Promise((resolve) => setTimeout(resolve, 0));
          }
          throw new Error(`No worker message posted at index ${index}`);
        };

        (manager as any).worker = fakeWorker;

        const batchPromise = manager.getWarmSessionStatuses({
          thresholdSessionIds: ['sess-a', 'sess-b', 'sess-a'],
        });

        const posted = await waitForPosted(0);
        emitMessage({
          id: posted?.id,
          success: true,
          data: {
            results: [
              {
                thresholdSessionId: 'sess-a',
                result: {
                  ok: true,
                  remainingUses: 4,
                  expiresAtMs: Date.now() + 45_000,
                },
              },
              {
                thresholdSessionId: 'sess-b',
                result: {
                  ok: false,
                  code: 'not_found',
                  message: 'missing',
                },
              },
            ],
          },
        });

        const batchResult = await batchPromise;
        return {
          postedTypes: postedMessages.map((entry) => entry?.type),
          payloadThresholdSessionIds: postedMessages[0]?.payload?.thresholdSessionIds,
          batchResult,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.postedTypes).toEqual(['WARM_SESSION_STATUS_BATCH_READ']);
    expect(result.payloadThresholdSessionIds).toEqual(['sess-a', 'sess-b']);
    expect(result.batchResult).toEqual({
      results: [
        {
          thresholdSessionId: 'sess-a',
          result: {
            ok: true,
            remainingUses: expect.any(Number),
            expiresAtMs: expect.any(Number),
          },
        },
        {
          thresholdSessionId: 'sess-b',
          result: {
            ok: false,
            code: 'not_found',
            message: 'missing',
          },
        },
      ],
    });
  });

  test('rejects only the failed worker pending requests', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.touchConfirmManager);
        const sessionMod = await import(paths.passkeyMpcSessionManager);
        const sessionManager = sessionMod.createPasskeyMpcSessionManager({
          signingSessionPersistenceMode: 'none',
          thresholdEcdsaSigningQueueByKey: new Map(),
          resolveCurrentEcdsaCapabilityRuntime: async () => ({
            kind: 'blocked',
            reason: 'missing_capability',
          }),
          persistSigningSessionSealForThresholdSession: async () => null,
          onPolicyResult: async () => {},
        });
        const manager = mod.createUiConfirmManager(
          {},
          {
            touchIdPrompt: {},
            nearClient: {},
            indexedDB: {},
            userPreferencesManager: {},
            nearContextFixture: {},
          } as any,
          sessionManager,
          sessionManager,
        );

        const listeners: Record<'message' | 'error', Array<(event: any) => void>> = {
          message: [],
          error: [],
        };
        const fakeWorker: Worker = {
          addEventListener: ((type: string, handler: (event: any) => void) => {
            if (type === 'message' || type === 'error') listeners[type].push(handler);
          }) as any,
          removeEventListener: ((type: string, handler: (event: any) => void) => {
            if (type !== 'message' && type !== 'error') return;
            listeners[type] = listeners[type].filter((fn) => fn !== handler);
          }) as any,
          postMessage: (() => {}) as any,
          terminate: (() => {}) as any,
        } as unknown as Worker;
        const fakeSessionWorker: Worker = {
          addEventListener: (() => {}) as any,
          removeEventListener: (() => {}) as any,
          postMessage: (() => {}) as any,
          terminate: (() => {}) as any,
        } as unknown as Worker;

        const emitError = (message: string) => {
          for (const handler of [...listeners.error]) {
            handler({ message, currentTarget: fakeWorker, target: fakeWorker });
          }
        };

        (manager as any).worker = fakeWorker;
        (sessionManager as any).worker = fakeSessionWorker;
        (manager as any).attachWorkerRouter(fakeWorker);

        const p1 = (manager as any)
          .sendMessage(
            {
              type: 'PING',
              id: 'req-error-1',
              payload: {},
            },
            1000,
          )
          .then(
            () => ({ ok: true, error: '' }),
            (error: any) => ({ ok: false, error: String(error?.message || error) }),
          );
        const p2 = (sessionManager as any)
          .sendMessage(
            {
              type: 'WARM_SESSION_VOLATILE_MATERIAL_CLEAR',
              id: 'req-error-2',
              payload: { sessionId: 's1' },
            },
            1000,
          )
          .then(
            () => ({ ok: true, error: '' }),
            (error: any) => ({ ok: false, error: String(error?.message || error) }),
          );

        emitError('simulated worker crash');
        const r1 = await p1;
        const pendingAfterGenericError = (sessionManager as any).pendingRequests.size;
        (sessionManager as any).handleWorkerMessage({
          data: { id: 'req-error-2', success: true, data: { success: true } },
          currentTarget: fakeSessionWorker,
          target: fakeSessionWorker,
        });
        const r2 = await p2;

        return {
          r1,
          r2,
          pendingAfterGenericError,
          pendingAfter: (sessionManager as any).pendingRequests.size,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.r1.ok).toBe(false);
    expect(result.r2.ok).toBe(true);
    expect(result.r1.error).toContain('UserConfirm worker failed: simulated worker crash');
    expect(result.pendingAfterGenericError).toBe(1);
    expect(result.pendingAfter).toBe(0);
  });

  test('cleans up pending request when aborted', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.touchConfirmManager);
        const manager = mod.createUiConfirmManager({}, {
          touchIdPrompt: {},
          nearClient: {},
          indexedDB: {},
          userPreferencesManager: {},
          nearContextFixture: {},
        } as any);

        const listeners: Record<'message' | 'error', Array<(event: any) => void>> = {
          message: [],
          error: [],
        };

        const fakeWorker: Worker = {
          addEventListener: ((type: string, handler: (event: any) => void) => {
            if (type === 'message' || type === 'error') listeners[type].push(handler);
          }) as any,
          removeEventListener: ((type: string, handler: (event: any) => void) => {
            if (type !== 'message' && type !== 'error') return;
            listeners[type] = listeners[type].filter((fn) => fn !== handler);
          }) as any,
          postMessage: (() => {}) as any,
          terminate: (() => {}) as any,
        } as unknown as Worker;

        (manager as any).worker = fakeWorker;
        (manager as any).attachWorkerRouter(fakeWorker);

        const controller = new AbortController();
        const aborted = (manager as any)
          .sendMessage(
            {
              type: 'PING',
              id: 'req-abort',
              payload: {},
            },
            1_000,
            controller.signal,
          )
          .then(
            () => ({ ok: true, error: '' }),
            (error: any) => ({ ok: false, error: String(error?.message || error) }),
          );
        controller.abort();
        const result = await aborted;

        return {
          result,
          pendingAfter: (manager as any).pendingWorkerRequests.size,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.result.ok).toBe(false);
    expect(result.result.error).toContain('request aborted');
    expect(result.result.error).toContain('PING');
    expect(result.pendingAfter).toBe(0);
  });

  test('routes signing-session seal and rehydrate worker messages', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.touchConfirmManager);
        const sessionMod = await import(paths.passkeyMpcSessionManager);
        const sealedStoreMod = await import(paths.sealedSessionStore);
        const sessionManager = sessionMod.createPasskeyMpcSessionManager({
          signingSessionPersistenceMode: 'sealed_refresh_v1',
          thresholdEcdsaSigningQueueByKey: new Map(),
          resolveCurrentEcdsaCapabilityRuntime: async () => ({
            kind: 'blocked',
            reason: 'missing_capability',
          }),
          persistSigningSessionSealForThresholdSession: async () => null,
          onPolicyResult: async () => {},
        });
        const manager = mod.createUiConfirmManager(
          {
            signingSessionPersistenceMode: 'sealed_refresh_v1',
          },
          {
            touchIdPrompt: {},
            nearClient: {},
            indexedDB: {},
            userPreferencesManager: {},
            nearContextFixture: {},
          } as any,
          sessionManager,
          sessionManager,
        );

        const listeners: Record<'message' | 'error', Array<(event: any) => void>> = {
          message: [],
          error: [],
        };
        const postedMessages: any[] = [];

        const fakeWorker: Worker = {
          addEventListener: ((type: string, handler: (event: any) => void) => {
            if (type === 'message' || type === 'error') listeners[type].push(handler);
          }) as any,
          removeEventListener: ((type: string, handler: (event: any) => void) => {
            if (type !== 'message' && type !== 'error') return;
            listeners[type] = listeners[type].filter((fn) => fn !== handler);
          }) as any,
          postMessage: ((message: unknown) => {
            postedMessages.push(message);
          }) as any,
          terminate: (() => {}) as any,
        } as unknown as Worker;

        const emitMessage = (data: unknown) => {
          (sessionManager as any).handleWorkerMessage({
            data,
            currentTarget: fakeWorker,
            target: fakeWorker,
          });
        };

        const restoreResolution: unknown = { state: 'pending' };
        const waitForPosted = async (index: number) => {
          for (let i = 0; i < 100; i += 1) {
            if (postedMessages[index]) return postedMessages[index];
            await new Promise((resolve) => setTimeout(resolve, 0));
          }
          return null;
        };

        await new Promise<void>((resolve, reject) => {
          const request = indexedDB.deleteDatabase('seams_wallet');
          request.onsuccess = () => resolve();
          request.onerror = () =>
            reject(request.error || new Error('Failed to clear sealed session test database'));
          request.onblocked = () => resolve();
        });
        (sessionManager as any).worker = fakeWorker;

        const sealPromise = sessionManager.sealAndPersistWarmSessionMaterial({
          sessionId: 'session-seal',
          transport: {
            relayerUrl: 'https://relay.example',
            walletSessionJwt: 'jwt-session',
            shamirPrimeB64u: 'AQAB',
          },
        });
        const sealRequest = await waitForPosted(0);
        emitMessage({
          id: sealRequest?.id,
          success: true,
          data: {
            ok: true,
            sealedSecretB64u: 'sealed-b64u',
            keyVersion: 'kek-v1',
            remainingUses: 9,
            expiresAtMs: 1700000000000,
          },
        });
        const sealResult = await sealPromise;

        const rehydratePromise = sessionManager.rehydrateWarmSessionMaterial({
          sessionId: 'session-seal',
          sealedSecretB64u: 'sealed-b64u',
          keyVersion: 'kek-v1',
          remainingUses: 9,
          expiresAtMs: 1700000000000,
          transport: {
            relayerUrl: 'https://relay.example',
            walletSessionJwt: 'jwt-session',
            shamirPrimeB64u: 'AQAB',
          },
        });
        const rehydrateRequest = await waitForPosted(1);
        emitMessage({
          id: rehydrateRequest?.id,
          success: true,
          data: {
            ok: true,
            remainingUses: 8,
            expiresAtMs: 1700000000500,
          },
        });
        const rehydrateResult = await rehydratePromise;

        return {
          postedTypes: postedMessages.map((entry) => entry?.type),
          sealResult,
          rehydrateResult,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.postedTypes).toEqual(['WARM_SESSION_SEAL_AND_PERSIST', 'WARM_SESSION_REHYDRATE']);
    expect(result.sealResult).toEqual({
      ok: true,
      sealedSecretB64u: 'sealed-b64u',
      keyVersion: 'kek-v1',
      remainingUses: 9,
      expiresAtMs: 1700000000000,
    });
    expect(result.rehydrateResult).toEqual({
      ok: true,
      remainingUses: 8,
      expiresAtMs: 1700000000500,
    });
  });

  test('sealed mode restores only through explicit signing restore command', async ({ page }) => {
    const fixture = await canonicalEvmFamilyEcdsaSigningCapabilityFixture('passkey');
    const sealedRecord = buildPasskeyEcdsaSealedRuntimeRecordFixture({
      manifest: fixture.manifest,
      thresholdSessionId: 'session-rehydrate',
      remainingUses: 10,
    });
    const browserAuthorization = await buildPasskeyRestoreBrowserAuthorizationFixture(
      sealedRecord,
      'explicit',
    );
    await page.evaluate(installPasskeyRestoreBrowserState, {
      paths: IMPORT_PATHS,
      sealedRecord,
      browserAuthorization,
    });
    const materialRestoreIdentity = materialRestoreIdentityFromPasskeyRecord(sealedRecord);
    const result = await page.evaluate(
      async ({ paths, sealedRecord, materialRestoreIdentity, manifest }) => {
        const sessionMod = await import(paths.passkeyMpcSessionManager);
        const sealedStoreMod = await import(paths.sealedSessionStore);
        const runtimeMod = await import(paths.ecdsaSealedRuntime);
        const manager = sessionMod.createPasskeyMpcSessionManager({
          signingSessionPersistenceMode: 'sealed_refresh_v1',
          thresholdEcdsaSigningQueueByKey: new Map(),
          resolveCurrentEcdsaCapabilityRuntime: async ({ walletId, chainTarget }) =>
            runtimeMod.resolveExactEcdsaSealedRuntime({
              manifest,
              walletId,
              chainTarget,
              sealedRecords: [sealedRecord],
            }),
          persistSigningSessionSealForThresholdSession: async () => null,
          onPolicyResult: async () => {},
        });

        const listeners: Record<'message' | 'error', Array<(event: any) => void>> = {
          message: [],
          error: [],
        };
        const postedMessages: any[] = [];

        const fakeWorker: Worker = {
          addEventListener: ((type: string, handler: (event: any) => void) => {
            if (type === 'message' || type === 'error') listeners[type].push(handler);
          }) as any,
          removeEventListener: ((type: string, handler: (event: any) => void) => {
            if (type !== 'message' && type !== 'error') return;
            listeners[type] = listeners[type].filter((fn) => fn !== handler);
          }) as any,
          postMessage: ((message: unknown) => {
            postedMessages.push(message);
          }) as any,
          terminate: (() => {}) as any,
        } as unknown as Worker;

        const emitMessage = (data: unknown) => {
          (manager as any).handleWorkerMessage({
            data,
            currentTarget: fakeWorker,
            target: fakeWorker,
          });
        };

        const waitForPosted = async (index: number) => {
          for (let i = 0; i < 100; i += 1) {
            if (postedMessages[index]) return postedMessages[index];
            await new Promise((resolve) => setTimeout(resolve, 0));
          }
          return null;
        };

        (manager as any).worker = fakeWorker;

        const restorePromise = manager.restorePersistedSessionForSigning({
          walletId: String(sealedRecord.walletId),
          curve: 'ecdsa',
          chainTarget: sealedRecord.ecdsaRestore.chainTarget,
          thresholdSessionId: 'session-rehydrate',
          reason: 'transaction',
          materialRestoreIdentity,
        });

        const rehydrate = await waitForPosted(0);
        emitMessage({
          id: rehydrate?.id,
          success: true,
          data: {
            ok: true,
            remainingUses: 8,
            expiresAtMs: Date.now() + 45_000,
          },
        });

        const restoredStatusRead = await waitForPosted(1);
        emitMessage({
          id: restoredStatusRead?.id,
          success: true,
          data: {
            ok: true,
            remainingUses: 8,
            expiresAtMs: Date.now() + 45_000,
          },
        });

        const restoreResult = await restorePromise;
        const statusPromise = manager.getWarmSessionStatus({
          sessionId: 'session-rehydrate',
        });
        const statusRead = await waitForPosted(2);
        emitMessage({
          id: statusRead?.id,
          success: true,
          data: {
            ok: true,
            remainingUses: 8,
            expiresAtMs: Date.now() + 45_000,
          },
        });
        const statusResult = await statusPromise;
        const persisted = await sealedStoreMod.readExactSealedSession('session-rehydrate', {
          authMethod: 'passkey',
          curve: 'ecdsa',
          chainTarget: sealedRecord.ecdsaRestore.chainTarget,
        });

        return {
          postedTypes: postedMessages.map((entry) => entry?.type),
          restoreResult,
          statusResult,
          persistedPolicy: {
            remainingUses: persisted?.remainingUses,
          },
        };
      },
      { paths: IMPORT_PATHS, sealedRecord, materialRestoreIdentity, manifest: fixture.manifest },
    );
    expect(result.postedTypes).toEqual([
      'WARM_SESSION_REHYDRATE',
      'WARM_SESSION_STATUS_READ',
      'WARM_SESSION_STATUS_READ',
    ]);
    expect(result.restoreResult).toEqual({
      kind: 'completed',
      attempted: 1,
      restored: 1,
      deferred: 0,
    });
    expect(result.statusResult.ok).toBe(true);
    expect(result.statusResult.remainingUses).toBe(8);
    expect(result.persistedPolicy.remainingUses).toBe(8);
  });

  test('sealed mode refreshes ECDSA policy without top-level signing-root metadata', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.touchConfirmManager);
        const sealedStoreMod = await import(paths.sealedSessionStore);
        await new Promise<void>((resolve, reject) => {
          const request = indexedDB.deleteDatabase('seams_wallet');
          request.onsuccess = () => resolve();
          request.onerror = () =>
            reject(request.error || new Error('Failed to clear sealed session test database'));
          request.onblocked = () => resolve();
        });

        const chainTarget = {
          kind: 'evm' as const,
          namespace: 'eip155' as const,
          chainId: 5042002,
          networkSlug: 'arc-testnet',
        };
        const record = sealedStoreMod.buildCurrentSealedSessionRecord({
          thresholdSessionId: 'session-ecdsa-policy-refresh',
          curve: 'ecdsa',
          authMethod: 'passkey',
          walletId: 'alice.testnet',
          relayerUrl: 'https://relay-ecdsa.example',
          sealedSecretB64u: 'sealed-ecdsa-policy-refresh',
          ecdsaRestore: {
            chainTarget,
            source: 'manual-bootstrap',
            rpId: 'example.localhost',
            sessionKind: 'cookie',
            keyHandle: 'key-handle-ecdsa-policy-refresh',
            ethereumAddress: '0x1111111111111111111111111111111111111111',
            relayerKeyId: 'rk-ecdsa',
            participantIds: [3, 7],
          },
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 4,
          updatedAtMs: Date.now(),
        });
        if (!record) throw new Error('invalid ECDSA sealed session fixture');
        await sealedStoreMod.writeExactSealedSession(record);

        const manager = mod.createUiConfirmManager(
          {
            signingSessionPersistenceMode: 'sealed_refresh_v1',
          },
          {
            touchIdPrompt: {},
            nearClient: {},
            indexedDB: {},
            userPreferencesManager: {},
            nearContextFixture: {},
          } as any,
        );
        await (manager as any).recordSessionUseConsumed(
          'session-ecdsa-policy-refresh',
          {
            ok: true,
            expiresAtMs: Date.now() + 45_000,
            remainingUses: 2,
          },
          'ecdsa',
          chainTarget,
        );

        const refreshed = await sealedStoreMod.readExactSealedSession(
          'session-ecdsa-policy-refresh',
          {
            authMethod: 'passkey',
            curve: 'ecdsa',
            chainTarget,
          },
        );
        return {
          remainingUses: refreshed?.remainingUses ?? null,
          sealedSecretB64u: refreshed?.sealedSecretB64u ?? null,
          hasTopLevelSigningRoot:
            !!refreshed &&
            (Object.prototype.hasOwnProperty.call(refreshed, 'signingRootId') ||
              Object.prototype.hasOwnProperty.call(refreshed, 'signingRootVersion')),
          restoreChainId: refreshed?.ecdsaRestore?.chainTarget.chainId ?? null,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.remainingUses).toBe(2);
    expect(result.sealedSecretB64u).toBe('sealed-ecdsa-policy-refresh');
    expect(result.hasTopLevelSigningRoot).toBe(false);
    expect(result.restoreChainId).toBe(5042002);
  });

  test('sealed mode retains expired passkey Ed25519 policy as an exact reauth anchor', async ({
    page,
  }) => {
    const initialRecord = buildPasskeyEd25519SealedSessionRecordFixture({
      walletId: 'alice.testnet',
      thresholdSessionId: 'session-ed25519-expiry-anchor',
      nearAccountId: 'alice.testnet',
      nearEd25519SigningKeyId: 'near-ed25519-key-expiry-anchor',
      credentialIdB64u: 'credential-ed25519-expiry-anchor',
      signerSlot: 1,
      expiresAtMs: Date.now() + 60_000,
      remainingUses: 3,
    });
    const result = await page.evaluate(
      async ({ paths, initialRecord }) => {
        const mod = await import(paths.touchConfirmManager);
        const sealedStoreMod = await import(paths.sealedSessionStore);
        const availableLanesMod = await import(paths.availableSigningLanes);
        const selectLaneMod = await import(paths.selectLane);
        await new Promise<void>((resolve, reject) => {
          const request = indexedDB.deleteDatabase('seams_wallet');
          request.onsuccess = () => resolve();
          request.onerror = () =>
            reject(request.error || new Error('Failed to clear sealed session test database'));
          request.onblocked = () => resolve();
        });

        const thresholdSessionId = 'session-ed25519-expiry-anchor';
        await sealedStoreMod.writeExactSealedSession(initialRecord);
        const initialStored = await sealedStoreMod.readExactEd25519SealedSession({
          authMethod: 'passkey',
          materialActivation: initialRecord.ed25519Restore.materialActivation,
        });
        if (!initialStored) throw new Error('Ed25519 expiry-anchor fixture was not persisted');

        const manager = mod.createUiConfirmManager(
          {
            signingSessionPersistenceMode: 'sealed_refresh_v1',
          },
          {
            touchIdPrompt: {},
            nearClient: {},
            indexedDB: {},
            userPreferencesManager: {},
            nearContextFixture: {},
          } as any,
        );
        const listeners: Record<'message' | 'error', Array<(event: any) => void>> = {
          message: [],
          error: [],
        };
        const postedMessages: any[] = [];
        const fakeWorker: Worker = {
          addEventListener: ((type: string, handler: (event: any) => void) => {
            if (type === 'message' || type === 'error') listeners[type].push(handler);
          }) as any,
          removeEventListener: ((type: string, handler: (event: any) => void) => {
            if (type !== 'message' && type !== 'error') return;
            listeners[type] = listeners[type].filter((fn) => fn !== handler);
          }) as any,
          postMessage: ((message: unknown) => {
            postedMessages.push(message);
          }) as any,
          terminate: (() => {}) as any,
        } as unknown as Worker;
        (manager as any).worker = fakeWorker;
        (manager as any).passkeyMpcSessionWorker = fakeWorker;
        (manager as any).attachWorkerRouter(fakeWorker);

        const observedExpiredAtMs = Date.now();
        const consumePromise = manager.consumeWarmSessionUses({
          sessionId: thresholdSessionId,
          uses: 1,
          curve: 'ed25519',
          chain: 'near',
        });
        for (let attempts = 0; !postedMessages[0] && attempts < 100; attempts += 1) {
          await new Promise((resolve) => setTimeout(resolve, 0));
        }
        const consumeRequest = postedMessages[0];
        if (!consumeRequest) throw new Error('Warm-session consume request was not posted');
        for (const handler of [...listeners.message]) {
          handler({
            currentTarget: fakeWorker,
            target: fakeWorker,
            data: {
              id: consumeRequest.id,
              success: true,
              data: {
                ok: false,
                code: 'expired',
                message: 'Warm-session material expired for threshold session',
              },
            },
          });
        }
        const consumeResult = await consumePromise;
        const retained = await sealedStoreMod.readExactEd25519SealedSession({
          authMethod: 'passkey',
          materialActivation: initialRecord.ed25519Restore.materialActivation,
        });
        const availableLanes = await availableLanesMod.readAvailableSigningLanes(
          {
            walletId: 'alice.testnet',
            authMethod: 'passkey',
            ecdsaChainTargets: [],
          },
          {
            listSealedRecordsForWallet: async ({ walletId, filter }) =>
              filter.curve === 'ed25519'
                ? await sealedStoreMod.listExactSealedSessionsForWallet({
                    walletId,
                    filter: { authMethod: 'passkey', curve: 'ed25519' },
                  })
                : await sealedStoreMod.listExactSealedSessionsForWallet({
                    walletId,
                    filter: {
                      authMethod: 'passkey',
                      curve: 'ecdsa',
                      chainTarget: filter.chainTarget,
                    },
                  }),
            listRuntimeEcdsaLanesForWallet: async () => [],
          },
        );
        const selection = selectLaneMod.selectTransactionLane({
          intent: {
            walletId: 'alice.testnet',
            curve: 'ed25519',
            chain: 'near',
            signerSelection: {
              kind: 'near_account',
              nearAccountId: 'alice.testnet',
            },
            authSelectionPolicy: { kind: 'any' },
            operationUsesNeeded: 1,
          },
          availableLanes,
        });
        return {
          availableEd25519Candidates: availableLanes.candidates.ed25519.near,
          consumeResult,
          postedType: consumeRequest.type,
          retained,
          selection,
          observedExpiredAtMs,
        };
      },
      { paths: IMPORT_PATHS, initialRecord },
    );

    expect(result.postedType).toBe('WARM_SESSION_MATERIAL_CONSUME');
    expect(result.consumeResult).toMatchObject({ ok: false, code: 'expired' });
    expect(result.retained).not.toBeNull();
    expect(result.retained?.expiresAtMs).toBeLessThanOrEqual(Date.now());
    expect(result.retained?.expiresAtMs).toBeGreaterThanOrEqual(result.observedExpiredAtMs);
    expect(result.retained).toMatchObject({
      curve: 'ed25519',
      authMethod: 'passkey',
      remainingUses: 3,
      sealedSecretB64u: 'ed25519-sealed-runtime-secret',
    });
    expect(result.availableEd25519Candidates).toHaveLength(1);
    expect(result.availableEd25519Candidates[0]).toMatchObject({
      state: 'expired',
      source: 'durable_sealed_record',
      thresholdSessionId: 'session-ed25519-expiry-anchor',
    });
    expect(result.selection).toMatchObject({
      ok: true,
      selectionCandidate: {
        kind: 'near_ed25519_transaction_reauth_lane',
      },
    });
  });

  test('sealed mode dedupes concurrent explicit restores (remove-server-seal single-flight)', async ({
    page,
  }) => {
    const fixture = await canonicalEvmFamilyEcdsaSigningCapabilityFixture('passkey');
    const sealedRecord = buildPasskeyEcdsaSealedRuntimeRecordFixture({
      manifest: fixture.manifest,
      thresholdSessionId: 'session-single-flight-remove',
      remainingUses: 10,
    });
    const browserAuthorization = await buildPasskeyRestoreBrowserAuthorizationFixture(
      sealedRecord,
      'single-flight',
    );
    await page.evaluate(installPasskeyRestoreBrowserState, {
      paths: IMPORT_PATHS,
      sealedRecord,
      browserAuthorization,
    });
    const materialRestoreIdentity = materialRestoreIdentityFromPasskeyRecord(sealedRecord);
    const result = await page.evaluate(
      async ({ paths, sealedRecord, materialRestoreIdentity, manifest }) => {
        const sessionMod = await import(paths.passkeyMpcSessionManager);
        const runtimeMod = await import(paths.ecdsaSealedRuntime);
        const manager = sessionMod.createPasskeyMpcSessionManager({
          signingSessionPersistenceMode: 'sealed_refresh_v1',
          thresholdEcdsaSigningQueueByKey: new Map(),
          resolveCurrentEcdsaCapabilityRuntime: async ({ walletId, chainTarget }) =>
            runtimeMod.resolveExactEcdsaSealedRuntime({
              manifest,
              walletId,
              chainTarget,
              sealedRecords: [sealedRecord],
            }),
          persistSigningSessionSealForThresholdSession: async () => null,
          onPolicyResult: async () => {},
        });

        const listeners: Record<'message' | 'error', Array<(event: any) => void>> = {
          message: [],
          error: [],
        };
        const postedMessages: any[] = [];

        const fakeWorker: Worker = {
          addEventListener: ((type: string, handler: (event: any) => void) => {
            if (type === 'message' || type === 'error') listeners[type].push(handler);
          }) as any,
          removeEventListener: ((type: string, handler: (event: any) => void) => {
            if (type !== 'message' && type !== 'error') return;
            listeners[type] = listeners[type].filter((fn) => fn !== handler);
          }) as any,
          postMessage: ((message: unknown) => {
            postedMessages.push(message);
          }) as any,
          terminate: (() => {}) as any,
        } as unknown as Worker;

        const emitMessage = (data: unknown) => {
          (manager as any).handleWorkerMessage({
            data,
            currentTarget: fakeWorker,
            target: fakeWorker,
          });
        };

        const waitForPosted = async (index: number) => {
          for (let i = 0; i < 100; i += 1) {
            if (postedMessages[index]) return postedMessages[index];
            await new Promise((resolve) => setTimeout(resolve, 0));
          }
          throw new Error(`No worker message posted at index ${index}`);
        };

        (manager as any).worker = fakeWorker;

        const restoreInput = {
          walletId: String(sealedRecord.walletId),
          curve: 'ecdsa' as const,
          chainTarget: sealedRecord.ecdsaRestore.chainTarget,
          thresholdSessionId: 'session-single-flight-remove',
          reason: 'transaction' as const,
          materialRestoreIdentity,
        };
        const p1 = manager.restorePersistedSessionForSigning({
          ...restoreInput,
        });
        const p2 = manager.restorePersistedSessionForSigning({
          ...restoreInput,
        });

        const rehydrate = await waitForPosted(0);
        emitMessage({
          id: rehydrate?.id,
          success: true,
          data: {
            ok: true,
            remainingUses: 8,
            expiresAtMs: Date.now() + 45_000,
          },
        });

        const finalPeek = await waitForPosted(1);
        emitMessage({
          id: finalPeek?.id,
          success: true,
          data: {
            ok: true,
            remainingUses: 8,
            expiresAtMs: Date.now() + 45_000,
          },
        });

        const [r1, r2] = await Promise.all([p1, p2]);
        return {
          postedTypes: postedMessages.map((entry) => entry?.type),
          rehydrateMessageCount: postedMessages.filter(
            (entry) => entry?.type === 'WARM_SESSION_REHYDRATE',
          ).length,
          r1,
          r2,
        };
      },
      { paths: IMPORT_PATHS, sealedRecord, materialRestoreIdentity, manifest: fixture.manifest },
    );

    expect(result.rehydrateMessageCount).toBe(1);
    expect(result.postedTypes).toEqual(['WARM_SESSION_REHYDRATE', 'WARM_SESSION_STATUS_READ']);
    expect(result.r1.restored + result.r2.restored).toBe(1);
    expect(result.r1.deferred + result.r2.deferred).toBe(0);
  });

  test('sealed mode dedupes concurrent explicit restores across manager instances', async ({
    page,
  }) => {
    const fixture = await canonicalEvmFamilyEcdsaSigningCapabilityFixture('passkey');
    const sealedRecord = buildPasskeyEcdsaSealedRuntimeRecordFixture({
      manifest: fixture.manifest,
      thresholdSessionId: 'session-cross-manager-remove',
      remainingUses: 10,
    });
    const browserAuthorization = await buildPasskeyRestoreBrowserAuthorizationFixture(
      sealedRecord,
      'cross-manager',
    );
    await page.evaluate(installPasskeyRestoreBrowserState, {
      paths: IMPORT_PATHS,
      sealedRecord,
      browserAuthorization,
    });
    const materialRestoreIdentity = materialRestoreIdentityFromPasskeyRecord(sealedRecord);
    const result = await page.evaluate(
      async ({ paths, sealedRecord, materialRestoreIdentity, manifest }) => {
        const sessionMod = await import(paths.passkeyMpcSessionManager);
        const runtimeMod = await import(paths.ecdsaSealedRuntime);
        const managerDeps = {
          signingSessionPersistenceMode: 'sealed_refresh_v1' as const,
          thresholdEcdsaSigningQueueByKey: new Map(),
          resolveCurrentEcdsaCapabilityRuntime: async ({ walletId, chainTarget }: any) =>
            runtimeMod.resolveExactEcdsaSealedRuntime({
              manifest,
              walletId,
              chainTarget,
              sealedRecords: [sealedRecord],
            }),
          persistSigningSessionSealForThresholdSession: async () => null,
          onPolicyResult: async () => {},
        };

        const managerA = sessionMod.createPasskeyMpcSessionManager(managerDeps);
        const managerB = sessionMod.createPasskeyMpcSessionManager(managerDeps);

        const listenersA: Record<'message' | 'error', Array<(event: any) => void>> = {
          message: [],
          error: [],
        };
        const listenersB: Record<'message' | 'error', Array<(event: any) => void>> = {
          message: [],
          error: [],
        };
        const postedA: any[] = [];
        const postedB: any[] = [];

        const makeWorker = (
          listeners: Record<'message' | 'error', Array<(event: any) => void>>,
          postedMessages: any[],
        ): Worker =>
          ({
            addEventListener: ((type: string, handler: (event: any) => void) => {
              if (type === 'message' || type === 'error') listeners[type].push(handler);
            }) as any,
            removeEventListener: ((type: string, handler: (event: any) => void) => {
              if (type !== 'message' && type !== 'error') return;
              listeners[type] = listeners[type].filter((fn) => fn !== handler);
            }) as any,
            postMessage: ((message: unknown) => {
              postedMessages.push(message);
            }) as any,
            terminate: (() => {}) as any,
          }) as unknown as Worker;

        const workerA = makeWorker(listenersA, postedA);
        const workerB = makeWorker(listenersB, postedB);

        const emitMessage = (manager: unknown, worker: Worker, data: unknown) => {
          (manager as any).handleWorkerMessage({
            data,
            currentTarget: worker,
            target: worker,
          });
        };

        const waitForPosted = async (postedMessages: any[], index: number) => {
          for (let i = 0; i < 100; i += 1) {
            if (postedMessages[index]) return postedMessages[index];
            await new Promise((resolve) => setTimeout(resolve, 0));
          }
          throw new Error(`No worker message posted at index ${index}`);
        };

        (managerA as any).worker = workerA;
        (managerB as any).worker = workerB;

        const restoreInput = {
          walletId: String(sealedRecord.walletId),
          curve: 'ecdsa' as const,
          chainTarget: sealedRecord.ecdsaRestore.chainTarget,
          thresholdSessionId: 'session-cross-manager-remove',
          reason: 'transaction' as const,
          materialRestoreIdentity,
        };
        const p1 = managerA.restorePersistedSessionForSigning({
          ...restoreInput,
        });
        const p2 = managerB.restorePersistedSessionForSigning({
          ...restoreInput,
        });

        const rehydrateA = await waitForPosted(postedA, 0);
        emitMessage(managerA, workerA, {
          id: rehydrateA?.id,
          success: true,
          data: {
            ok: true,
            remainingUses: 8,
            expiresAtMs: Date.now() + 45_000,
          },
        });

        const finalPeekA = await waitForPosted(postedA, 1);
        emitMessage(managerA, workerA, {
          id: finalPeekA?.id,
          success: true,
          data: {
            ok: true,
            remainingUses: 8,
            expiresAtMs: Date.now() + 45_000,
          },
        });

        const [r1, r2] = await Promise.all([p1, p2]);
        return {
          postedTypesA: postedA.map((entry) => entry?.type),
          postedTypesB: postedB.map((entry) => entry?.type),
          totalRehydrateCount:
            postedA.filter((entry) => entry?.type === 'WARM_SESSION_REHYDRATE').length +
            postedB.filter((entry) => entry?.type === 'WARM_SESSION_REHYDRATE').length,
          r1,
          r2,
        };
      },
      { paths: IMPORT_PATHS, sealedRecord, materialRestoreIdentity, manifest: fixture.manifest },
    );

    expect(result.postedTypesA).toEqual(['WARM_SESSION_REHYDRATE', 'WARM_SESSION_STATUS_READ']);
    expect(result.postedTypesB).toEqual([]);
    expect(result.totalRehydrateCount).toBe(1);
    expect(result.r1.restored + result.r2.restored).toBe(1);
    expect(result.r1.deferred + result.r2.deferred).toBe(0);
  });

  test('non-sealed mode does not rehydrate from persisted record on cache miss', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.touchConfirmManager);
        const sealedStoreMod = await import(paths.sealedSessionStore);
        const manager = mod.createUiConfirmManager(
          {
            signingSessionPersistenceMode: 'none',
          },
          {
            touchIdPrompt: {},
            nearClient: {},
            indexedDB: {},
            userPreferencesManager: {},
            nearContextFixture: {},
          } as any,
        );

        const listeners: Record<'message' | 'error', Array<(event: any) => void>> = {
          message: [],
          error: [],
        };
        const postedMessages: any[] = [];

        const fakeWorker: Worker = {
          addEventListener: ((type: string, handler: (event: any) => void) => {
            if (type === 'message' || type === 'error') listeners[type].push(handler);
          }) as any,
          removeEventListener: ((type: string, handler: (event: any) => void) => {
            if (type !== 'message' && type !== 'error') return;
            listeners[type] = listeners[type].filter((fn) => fn !== handler);
          }) as any,
          postMessage: ((message: unknown) => {
            postedMessages.push(message);
          }) as any,
          terminate: (() => {}) as any,
        } as unknown as Worker;

        const emitMessage = (data: unknown) => {
          for (const handler of [...listeners.message]) {
            handler({ data, currentTarget: fakeWorker, target: fakeWorker });
          }
        };

        const waitForPosted = async (index: number) => {
          for (let i = 0; i < 100; i += 1) {
            if (postedMessages[index]) return postedMessages[index];
            await new Promise((resolve) => setTimeout(resolve, 0));
          }
          throw new Error(`No worker message posted at index ${index}`);
        };

        await new Promise<void>((resolve, reject) => {
          const request = indexedDB.deleteDatabase('seams_wallet');
          request.onsuccess = () => resolve();
          request.onerror = () =>
            reject(request.error || new Error('Failed to clear sealed session test database'));
          request.onblocked = () => resolve();
        });
        await sealedStoreMod.writeExactSealedSession(
          sealedStoreMod.buildCurrentSealedSessionRecord({
            thresholdSessionId: 'session-no-rehydrate',
            curve: 'ecdsa',
            authMethod: 'passkey',
            relayerUrl: 'https://relay.example',
            ecdsaRestore: {
              chainTarget: { kind: 'tempo', chainId: 42431, networkSlug: 'tempo-moderato' },
              source: 'manual-bootstrap',
              rpId: 'example.com',
              sessionKind: 'cookie',
              keyHandle: 'key-handle-ecdsa',
              ecdsaThresholdKeyId: 'ecdsa-key',
              ethereumAddress: `0x${'33'.repeat(20)}`,
              relayerKeyId: 'relayer-key',
              clientVerifyingShareB64u: 'client-verifying-share',
              thresholdEcdsaPublicKeyB64u: 'AhERERERERERERERERERERERERERERERERERERERERER',
              participantIds: [1, 2, 3],
              runtimePolicyScope: {
                orgId: 'org-test',
                projectId: 'sr-test',
                envId: 'dev',
                signingRootVersion: 'default',
              },
            },
            sealedSecretB64u: 'sealed-prf',
            keyVersion: 'kek-v2',
            expiresAtMs: Date.now() + 60_000,
            remainingUses: 10,
            updatedAtMs: Date.now(),
          })!,
        );

        (manager as any).worker = fakeWorker;
        (manager as any).passkeyMpcSessionWorker = fakeWorker;
        (manager as any).attachWorkerRouter(fakeWorker);

        const statusPromise = manager.getWarmSessionStatus({
          sessionId: 'session-no-rehydrate',
        });
        const firstStatusRead = await waitForPosted(0);
        emitMessage({
          id: firstStatusRead?.id,
          success: true,
          data: {
            ok: false,
            code: 'not_found',
            message: 'Warm-session material is not available for threshold session',
          },
        });
        const statusResult = await statusPromise;
        await new Promise((resolve) => setTimeout(resolve, 5));

        return {
          postedTypes: postedMessages.map((entry) => entry?.type),
          statusResult,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.postedTypes).toEqual(['WARM_SESSION_STATUS_READ']);
    expect(result.statusResult).toEqual({
      ok: false,
      code: 'not_found',
      message: 'Warm-session material is not available for threshold session',
    });
  });

  test('non-sealed mode hard-blocks seal/rehydrate worker calls', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const sessionMod = await import(paths.passkeyMpcSessionManager);
        const manager = sessionMod.createPasskeyMpcSessionManager({
          signingSessionPersistenceMode: 'none',
          thresholdEcdsaSigningQueueByKey: new Map(),
          resolveCurrentEcdsaCapabilityRuntime: async () => ({
            kind: 'blocked',
            reason: 'missing_capability',
          }),
          persistSigningSessionSealForThresholdSession: async () => null,
          onPolicyResult: async () => {},
        });

        const listeners: Record<'message' | 'error', Array<(event: any) => void>> = {
          message: [],
          error: [],
        };
        const postedMessages: any[] = [];

        const fakeWorker: Worker = {
          addEventListener: ((type: string, handler: (event: any) => void) => {
            if (type === 'message' || type === 'error') listeners[type].push(handler);
          }) as any,
          removeEventListener: ((type: string, handler: (event: any) => void) => {
            if (type !== 'message' && type !== 'error') return;
            listeners[type] = listeners[type].filter((fn) => fn !== handler);
          }) as any,
          postMessage: ((message: unknown) => {
            postedMessages.push(message);
          }) as any,
          terminate: (() => {}) as any,
        } as unknown as Worker;

        (manager as any).worker = fakeWorker;

        const sealed = await manager.sealAndPersistWarmSessionMaterial({
          sessionId: 'session-disabled',
          transport: {
            relayerUrl: 'https://relay.example',
            shamirPrimeB64u: 'AQAB',
          },
        });
        const rehydrated = await manager.rehydrateWarmSessionMaterial({
          sessionId: 'session-disabled',
          sealedSecretB64u: 'sealed-prf',
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 5,
          transport: {
            relayerUrl: 'https://relay.example',
            shamirPrimeB64u: 'AQAB',
          },
        });

        return {
          sealed,
          rehydrated,
          postedTypes: postedMessages.map((entry) => entry?.type),
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.sealed).toEqual({
      ok: false,
      code: 'not_enabled',
      message: 'Passkey MPC session sealing requires sealed refresh mode',
    });
    expect(result.rehydrated).toEqual({
      ok: false,
      code: 'not_enabled',
      message: 'Passkey MPC session rehydration requires sealed refresh mode',
    });
    expect(result.postedTypes).toEqual([]);
  });

  test('sealed mode preserves persisted material after worker reports expired restore', async ({
    page,
  }) => {
    const fixture = await canonicalEvmFamilyEcdsaSigningCapabilityFixture('passkey');
    const sealedRecord = buildPasskeyEcdsaSealedRuntimeRecordFixture({
      manifest: fixture.manifest,
      thresholdSessionId: 'session-expired',
      remainingUses: 2,
    });
    const browserAuthorization = await buildPasskeyRestoreBrowserAuthorizationFixture(
      sealedRecord,
      'expired',
    );
    await page.evaluate(installPasskeyRestoreBrowserState, {
      paths: IMPORT_PATHS,
      sealedRecord,
      browserAuthorization,
    });
    const materialRestoreIdentity = materialRestoreIdentityFromPasskeyRecord(sealedRecord);
    const result = await page.evaluate(
      async ({ paths, sealedRecord, materialRestoreIdentity, manifest }) => {
        const sessionMod = await import(paths.passkeyMpcSessionManager);
        const sealedStoreMod = await import(paths.sealedSessionStore);
        const runtimeMod = await import(paths.ecdsaSealedRuntime);
        const manager = sessionMod.createPasskeyMpcSessionManager({
          signingSessionPersistenceMode: 'sealed_refresh_v1',
          thresholdEcdsaSigningQueueByKey: new Map(),
          resolveCurrentEcdsaCapabilityRuntime: async ({ walletId, chainTarget }) =>
            runtimeMod.resolveExactEcdsaSealedRuntime({
              manifest,
              walletId,
              chainTarget,
              sealedRecords: [sealedRecord],
            }),
          persistSigningSessionSealForThresholdSession: async () => null,
          onPolicyResult: async () => {},
        });

        const listeners: Record<'message' | 'error', Array<(event: any) => void>> = {
          message: [],
          error: [],
        };
        const postedMessages: any[] = [];

        const fakeWorker: Worker = {
          addEventListener: ((type: string, handler: (event: any) => void) => {
            if (type === 'message' || type === 'error') listeners[type].push(handler);
          }) as any,
          removeEventListener: ((type: string, handler: (event: any) => void) => {
            if (type !== 'message' && type !== 'error') return;
            listeners[type] = listeners[type].filter((fn) => fn !== handler);
          }) as any,
          postMessage: ((message: unknown) => {
            postedMessages.push(message);
          }) as any,
          terminate: (() => {}) as any,
        } as unknown as Worker;

        const emitMessage = (data: unknown) => {
          (manager as any).handleWorkerMessage({
            data,
            currentTarget: fakeWorker,
            target: fakeWorker,
          });
        };

        const waitForPosted = async (index: number) => {
          for (let i = 0; i < 100; i += 1) {
            if (postedMessages[index]) return postedMessages[index];
            await new Promise((resolve) => setTimeout(resolve, 0));
          }
          throw new Error(`No worker message posted at index ${index}`);
        };

        (manager as any).worker = fakeWorker;

        const restorePromise = manager.restorePersistedSessionForSigning({
          walletId: String(sealedRecord.walletId),
          curve: 'ecdsa',
          chainTarget: sealedRecord.ecdsaRestore.chainTarget,
          thresholdSessionId: 'session-expired',
          reason: 'transaction',
          materialRestoreIdentity,
        });
        const rehydrate = await waitForPosted(0);
        emitMessage({
          id: rehydrate?.id,
          success: true,
          data: {
            ok: false,
            code: 'expired',
            message: 'Warm-session material expired for threshold session',
          },
        });
        const restoreResult = await restorePromise;
        await new Promise((resolve) => setTimeout(resolve, 5));
        const activeAfter = await sealedStoreMod.readExactSealedSession('session-expired', {
          authMethod: 'passkey',
          curve: 'ecdsa',
          chainTarget: sealedRecord.ecdsaRestore.chainTarget,
        });
        const durableRecordsAfter = await sealedStoreMod.listEcdsaSealedSessionsForWallet({
          walletId: String(sealedRecord.walletId),
          filter: { authMethod: 'passkey', curve: 'ecdsa' },
        });
        const inactiveAfter = durableRecordsAfter.find(
          (record: { recordKind?: string }) =>
            record.recordKind === 'ecdsa_inactive_sealed_material_v1',
        );

        return {
          postedTypes: postedMessages.map((entry) => entry?.type),
          restoreResult,
          activeAfter,
          inactiveAfter,
        };
      },
      { paths: IMPORT_PATHS, sealedRecord, materialRestoreIdentity, manifest: fixture.manifest },
    );

    expect(result.postedTypes).toEqual(['WARM_SESSION_REHYDRATE']);
    expect(result.restoreResult).toEqual({
      kind: 'completed',
      attempted: 1,
      restored: 0,
      deferred: 1,
    });
    expect(result.activeAfter).toBeNull();
    expect(result.inactiveAfter).toMatchObject({
      recordKind: 'ecdsa_inactive_sealed_material_v1',
      authorizationRetirementReason: 'expired',
      sealedSecretB64u: sealedRecord.sealedSecretB64u,
      keyVersion: sealedRecord.keyVersion,
    });
  });

  test('exportPrivateKeysWithUi strips secret fields from worker payload', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.passkeyMpcExportManager);
        const manager = mod.createPasskeyMpcExportManager({
          touchIdPrompt: {},
          nearClient: {},
          webauthnCredentialStore: {},
          passkeyAuthenticatorStore: {},
          userPreferencesManager: {},
          nonceCoordinator: {},
          operationStepUpPreparation: {},
          relayerUrl: 'https://relay.example',
          loadEcdsaRoleLocalReadyRecord: async () => null,
        } as any);

        const listeners: Record<'message' | 'error', Array<(event: any) => void>> = {
          message: [],
          error: [],
        };
        const postedMessages: any[] = [];

        const fakeWorker: Worker = {
          addEventListener: ((type: string, handler: (event: any) => void) => {
            if (type === 'message' || type === 'error') listeners[type].push(handler);
          }) as any,
          removeEventListener: ((type: string, handler: (event: any) => void) => {
            if (type !== 'message' && type !== 'error') return;
            listeners[type] = listeners[type].filter((fn) => fn !== handler);
          }) as any,
          postMessage: ((message: unknown) => {
            postedMessages.push(message);
          }) as any,
          terminate: (() => {}) as any,
        } as unknown as Worker;

        const emitMessage = (data: unknown) => {
          for (const handler of [...listeners.message]) {
            handler({ data, currentTarget: fakeWorker, target: fakeWorker });
          }
        };

        (manager as any).worker = fakeWorker;
        fakeWorker.addEventListener('message', (manager as any).boundHandleWorkerMessage);
        fakeWorker.addEventListener('error', (manager as any).boundHandleWorkerError);

        const exportPromise = manager.exportPrivateKeysWithUi({
          nearAccountId: 'alice.testnet',
          signerSlot: 1,
          hasThresholdKeyMaterial: true,
          chain: 'near',
        } as any);
        const posted = await new Promise<any>((resolve, reject) => {
          let attempts = 0;
          const poll = () => {
            if (postedMessages.length) {
              resolve(postedMessages[0]);
              return;
            }
            attempts += 1;
            if (attempts > 50) {
              reject(new Error('No worker message posted for export request'));
              return;
            }
            setTimeout(poll, 0);
          };
          poll();
        });

        emitMessage({
          id: posted?.id,
          success: true,
          data: {
            ok: true,
            accountId: 'alice.testnet',
            exportedSchemes: ['ed25519'],
            privateKey: 'ed25519:SECRET',
            keys: [{ privateKey: 'ed25519:SECRET' }],
          },
        });

        const parsed = await exportPromise;
        return {
          postedType: posted?.type,
          parsed,
          hasPrivateKeyField: Object.prototype.hasOwnProperty.call(parsed, 'privateKey'),
          hasKeysField: Object.prototype.hasOwnProperty.call(parsed, 'keys'),
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.postedType).toBe('EXPORT_PRIVATE_KEYS_WITH_UI');
    expect(result.parsed).toEqual({
      ok: true,
      accountId: 'alice.testnet',
      exportedSchemes: ['ed25519'],
    });
    expect(result.hasPrivateKeyField).toBe(false);
    expect(result.hasKeysField).toBe(false);
  });

  test('exportPrivateKeysWithUi rejects malformed worker response payload', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.passkeyMpcExportManager);
        const manager = mod.createPasskeyMpcExportManager({
          touchIdPrompt: {},
          nearClient: {},
          webauthnCredentialStore: {},
          passkeyAuthenticatorStore: {},
          userPreferencesManager: {},
          nonceCoordinator: {},
          operationStepUpPreparation: {},
          relayerUrl: 'https://relay.example',
          loadEcdsaRoleLocalReadyRecord: async () => null,
        } as any);

        const listeners: Record<'message' | 'error', Array<(event: any) => void>> = {
          message: [],
          error: [],
        };
        const postedMessages: any[] = [];

        const fakeWorker: Worker = {
          addEventListener: ((type: string, handler: (event: any) => void) => {
            if (type === 'message' || type === 'error') listeners[type].push(handler);
          }) as any,
          removeEventListener: ((type: string, handler: (event: any) => void) => {
            if (type !== 'message' && type !== 'error') return;
            listeners[type] = listeners[type].filter((fn) => fn !== handler);
          }) as any,
          postMessage: ((message: unknown) => {
            postedMessages.push(message);
          }) as any,
          terminate: (() => {}) as any,
        } as unknown as Worker;

        const emitMessage = (data: unknown) => {
          for (const handler of [...listeners.message]) {
            handler({ data, currentTarget: fakeWorker, target: fakeWorker });
          }
        };

        (manager as any).worker = fakeWorker;
        fakeWorker.addEventListener('message', (manager as any).boundHandleWorkerMessage);
        fakeWorker.addEventListener('error', (manager as any).boundHandleWorkerError);

        const exportResult = manager
          .exportPrivateKeysWithUi({
            nearAccountId: 'alice.testnet',
            signerSlot: 1,
            hasThresholdKeyMaterial: true,
            chain: 'near',
          } as any)
          .then(
            () => ({ ok: true, error: '' }),
            (error: any) => ({ ok: false, error: String(error?.message || error) }),
          );

        const posted = await new Promise<any>((resolve, reject) => {
          let attempts = 0;
          const poll = () => {
            if (postedMessages.length) {
              resolve(postedMessages[0]);
              return;
            }
            attempts += 1;
            if (attempts > 50) {
              reject(new Error('No worker message posted for export request'));
              return;
            }
            setTimeout(poll, 0);
          };
          poll();
        });
        emitMessage({
          id: posted?.id,
          success: true,
          data: {
            ok: true,
            accountId: 'alice.testnet',
            exportedSchemes: ['rsa2048'],
          },
        });

        return {
          postedType: posted?.type,
          exportResult: await exportResult,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.postedType).toBe('EXPORT_PRIVATE_KEYS_WITH_UI');
    expect(result.exportResult.ok).toBe(false);
    expect(result.exportResult.error).toContain('invalid worker response payload');
  });
});
