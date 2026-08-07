import { expect, test } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';
import {
  cacheCredentialBoundarySetupExportPrfFirst,
  generateSessionId,
} from '@/core/signingEngine/session/passkey/prfCache';

test.describe('signing session PRF cache utilities', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
  });

  test('cache helper operates only on PRF claim state', async () => {
    const putCalls: Array<Record<string, unknown>> = [];
    await cacheCredentialBoundarySetupExportPrfFirst(
      {
        putWarmSessionMaterial: async (args) => {
          putCalls.push(args);
        },
      },
      {
        thresholdSessionId: 'session-hydrated',
        prfFirstB64u: 'AQ',
        expiresAtMs: 123_456,
        remainingUses: 2,
        transport: {
          curve: 'ecdsa',
          walletId: 'wallet.testnet',
          chainTarget: { kind: 'tempo', chainId: 42431 },
          relayerUrl: 'https://relay.example.test',
          walletSessionId: 'wallet-session',
          quotaId: 'quota-session',
        },
      },
    );

    expect(putCalls).toEqual([
      {
        thresholdSessionId: 'session-hydrated',
        prfFirstB64u: 'AQ',
        expiresAtMs: 123_456,
        remainingUses: 2,
        transport: {
          curve: 'ecdsa',
          walletId: 'wallet.testnet',
          chainTarget: { kind: 'tempo', chainId: 42431 },
          relayerUrl: 'https://relay.example.test',
          walletSessionId: 'wallet-session',
          quotaId: 'quota-session',
        },
      },
    ]);
  });

  test('generateSessionId fails closed when WebCrypto randomness is unavailable', () => {
    const originalCrypto = globalThis.crypto;
    Object.defineProperty(globalThis, 'crypto', { configurable: true, value: {} });
    let message: string | null = null;
    try {
      generateSessionId('threshold-ed25519');
    } catch (error) {
      message = error instanceof Error ? error.message : String(error);
    } finally {
      Object.defineProperty(globalThis, 'crypto', {
        configurable: true,
        value: originalCrypto,
      });
    }

    expect(message).toBe('WebCrypto getRandomValues is required for passkey PRF cache session IDs');
  });

  test('signing engine global clear path wipes all volatile worker PRF cache entries', () => {
    const source = fs.readFileSync(
      path.resolve(
        process.cwd(),
        '../packages/sdk-web/src/core/signingEngine/session/warmCapabilities/clearVolatileWarmSigningMaterial.ts',
      ),
      'utf8',
    );

    expect(source).toContain(
      'if (walletId == null && hasVolatileWarmSessionMaterialClearAll(deps.touchConfirm))',
    );
    expect(source).toContain('clearAllVolatileWarmSessionMaterial');
  });

  test('single warm material clear leaves durable Shamir3pass restore records intact', () => {
    const source = fs.readFileSync(
      path.resolve(
        process.cwd(),
        '../packages/sdk-web/src/core/signingEngine/uiConfirm/PasskeyMpcSessionManager.ts',
      ),
      'utf8',
    );
    const clearStart = source.indexOf('clearVolatileWarmSessionMaterial = async');
    const clearEnd = source.indexOf('clearAllVolatileWarmSessionMaterial = async', clearStart);
    const clearBlock = source.slice(clearStart, clearEnd);

    expect(clearStart).toBeGreaterThan(0);
    expect(clearEnd).toBeGreaterThan(clearStart);
    expect(clearBlock).toContain("type: 'WARM_SESSION_VOLATILE_MATERIAL_CLEAR'");
    expect(clearBlock).not.toContain('deleteDurableSealedSessionRecordFromStore');
    expect(clearBlock).not.toContain('deleteExactSealedSession');
    expect(source).toContain('deleteDurableSealedSessionRecord(command)');
    expect(source).not.toContain("type: 'WARM_SESSION_DELETE_PERSISTED'");
  });

  test('volatile all-clear cannot delete durable sealed records', () => {
    const source = fs.readFileSync(
      path.resolve(
        process.cwd(),
        '../packages/sdk-web/src/core/signingEngine/uiConfirm/PasskeyMpcSessionManager.ts',
      ),
      'utf8',
    );
    const allClearStart = source.indexOf('clearAllVolatileWarmSessionMaterial = async');
    const end = source.indexOf('async sealAndPersistWarmSessionMaterial', allClearStart);
    const allClearBlock = source.slice(allClearStart, end);

    expect(allClearStart).toBeGreaterThan(0);
    expect(allClearBlock).toContain('if (!this.worker && !this.initializationPromise) return;');
    expect(allClearBlock).toContain("type: 'WARM_SESSION_VOLATILE_MATERIAL_CLEAR_ALL'");
    expect(allClearBlock).not.toContain('clearAllSealedSessions');
    expect(allClearBlock).not.toContain('deleteExactSealedSession');
  });

  test('durable sealed-session delete no longer uses session-id-only worker payloads', () => {
    const workerTypesSource = fs.readFileSync(
      path.resolve(process.cwd(), '../packages/sdk-web/src/core/types/secure-confirm-worker.ts'),
      'utf8',
    );
    const durableCommandSource = fs.readFileSync(
      path.resolve(
        process.cwd(),
        '../packages/sdk-web/src/core/signingEngine/session/persistence/durableSealedSessionCommands.ts',
      ),
      'utf8',
    );
    const uiConfirmTypesSource = fs.readFileSync(
      path.resolve(
        process.cwd(),
        '../packages/sdk-web/src/core/signingEngine/uiConfirm/uiConfirm.types.ts',
      ),
      'utf8',
    );

    expect(workerTypesSource).not.toContain('WARM_SESSION_DELETE_PERSISTED');
    expect(workerTypesSource).not.toContain('WarmSessionDeletePersistedPayload');
    expect(durableCommandSource).toContain('DeleteDurableSealedSessionCommand');
    expect(durableCommandSource).toContain('parseDeleteDurableSealedSessionCommand');
    expect(uiConfirmTypesSource).not.toContain('WarmSessionPersistedRecordDeleter');
  });

  test('durable and volatile command parsers reject cross-lifetime payloads', () => {
    const durableCommandSource = fs.readFileSync(
      path.resolve(
        process.cwd(),
        '../packages/sdk-web/src/core/signingEngine/session/persistence/durableSealedSessionCommands.ts',
      ),
      'utf8',
    );
    const volatileCommandSource = fs.readFileSync(
      path.resolve(
        process.cwd(),
        '../packages/sdk-web/src/core/signingEngine/session/warmCapabilities/volatileWarmMaterialCommands.ts',
      ),
      'utf8',
    );

    expect(durableCommandSource).toContain("raw.kind !== 'delete_durable_sealed_session'");
    expect(durableCommandSource).toContain('if (raw.scope != null) return null;');
    expect(durableCommandSource).toContain('parseDurableSealedSessionDeleteReason');
    expect(volatileCommandSource).toContain("raw.kind !== 'clear_volatile_warm_material'");
    expect(volatileCommandSource).toContain('raw.durableRecord != null');
    expect(volatileCommandSource).toContain('raw.deleteReason != null');
  });

  test('volatile worker clear payloads use the boundary command parser', () => {
    const workerSource = fs.readFileSync(
      path.resolve(
        process.cwd(),
        '../packages/sdk-web/src/core/signingEngine/workerManager/workers/passkey-mpc-session.worker.ts',
      ),
      'utf8',
    );
    const volatileCommandSource = fs.readFileSync(
      path.resolve(
        process.cwd(),
        '../packages/sdk-web/src/core/signingEngine/session/warmCapabilities/volatileWarmMaterialCommands.ts',
      ),
      'utf8',
    );

    expect(workerSource).toContain('parseClearVolatileWarmMaterialCommand');
    expect(volatileCommandSource).toContain('parseVolatileWarmSessionScope');
    expect(volatileCommandSource).toContain('createClearAllVolatileWarmSessionMaterialCommand');
  });

  test('passkey server-sealed PRF reuse is scoped to wallet-session authority facts', () => {
    const workerSource = fs.readFileSync(
      path.resolve(
        process.cwd(),
        '../packages/sdk-web/src/core/signingEngine/workerManager/workers/passkey-mpc-session.worker.ts',
      ),
      'utf8',
    );
    expect(workerSource).toContain('type PasskeyServerSealedSecretCacheScope = {');
    expect(workerSource).toContain("kind: 'passkey_registration'");
    expect(workerSource).toContain('cacheScope.walletId');
    expect(workerSource).toContain('cacheScope.credentialIdB64u');
    expect(workerSource).toContain('cacheScope.walletSessionId');
    expect(workerSource).toContain('cacheScope.quotaId');
    expect(workerSource).toContain('!cacheScope');
  });

  test('reuse warm ECDSA bootstrap restores sealed material and fails closed instead of fresh prompting', () => {
    const source = fs.readFileSync(
      path.resolve(
        process.cwd(),
        '../packages/sdk-web/src/core/signingEngine/session/passkey/ecdsaWarmCapabilityBootstrap.ts',
      ),
      'utf8',
    );
    const reuseStart = source.indexOf('async function bootstrapReuseWarmEcdsaCapabilityNoPrompt');
    const publicStart = source.indexOf('export async function bootstrapWarmEcdsaCapability');
    const reuseBlock = source.slice(reuseStart, publicStart);

    expect(reuseStart).toBeGreaterThan(0);
    expect(publicStart).toBeGreaterThan(reuseStart);
    expect(reuseBlock).toContain('discoverPersistedSessionsForWallet');
    expect(reuseBlock).toContain("code: 'missing_exact_material'");
    expect(source).not.toContain('claimPasskeyEcdsaPrfFirst');
    expect(reuseBlock).not.toContain('TouchIdPrompt');
    expect(reuseBlock).not.toContain('collectAuthenticationCredential');
    expect(reuseBlock).not.toContain('claimPasskeyEcdsaPrfFirst({');
    expect(reuseBlock).not.toContain('bootstrapPasskeyCookieReconnect(');
    expect(reuseBlock).not.toContain('bootstrapDirectEcdsaRequest(');
    expect(reuseBlock).not.toContain('freshBootstrap');
  });

  test('demo threshold owner display reads do not bootstrap ECDSA sessions', () => {
    const source = fs.readFileSync(
      path.resolve(
        process.cwd(),
        '../apps/seams-site/src/flows/demo/hooks/useDemoThresholdAccountState.ts',
      ),
      'utf8',
    );

    expect(source).toContain('ThresholdOwnerAddressReadResult');
    expect(source).toContain('thresholdEcdsaEthereumAddress');
    expect(source).not.toContain('bootstrapEcdsaSession');
    expect(source).not.toContain('reuse_warm_ecdsa_bootstrap');
    expect(source).not.toContain('bootstrapIfMissing');
  });
});
