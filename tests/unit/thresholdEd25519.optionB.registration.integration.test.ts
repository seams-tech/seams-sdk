import { test, expect } from '@playwright/test';
import { setupBasicPasskeyTest, SDK_ESM_PATHS, sdkEsmPath } from '../setup';
import { DEFAULT_TEST_CONFIG } from '../setup/config';
import bs58 from 'bs58';
import { ed25519 } from '@noble/curves/ed25519.js';
import { createHash } from 'node:crypto';

const IMPORT_PATHS = {
  indexedDb: sdkEsmPath('core/indexedDB/index.js'),
  tatchi: SDK_ESM_PATHS.tatchiPasskey,
} as const;
const DUAL_KEY_ED25519_KEY_VERSION_V1 = 'option-b-v1';

function toB64u(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64url');
}

function bytesToHex(input: Uint8Array): string {
  return Buffer.from(input).toString('hex');
}

function getEd25519PointCtor(): any {
  const pointCtor = (ed25519 as any).ExtendedPoint || (ed25519 as any).Point;
  if (!pointCtor) throw new Error('ed25519 point constructor is unavailable');
  return pointCtor;
}

function ed25519PointToBytes(point: any): Uint8Array {
  if (typeof point.toRawBytes === 'function') return point.toRawBytes();
  return point.toBytes();
}

function compute2of2GroupPk(input: {
  clientVerifyingShareB64u: string;
  relayerVerifyingShareB64u: string;
}): string {
  const pointCtor = getEd25519PointCtor();
  const clientBytes = new Uint8Array(Buffer.from(input.clientVerifyingShareB64u, 'base64url'));
  const relayerBytes = new Uint8Array(Buffer.from(input.relayerVerifyingShareB64u, 'base64url'));
  const clientPoint = pointCtor.fromHex(bytesToHex(clientBytes));
  const relayerPoint = pointCtor.fromHex(bytesToHex(relayerBytes));
  const groupPoint = clientPoint.multiply(2n).subtract(relayerPoint);
  return `ed25519:${bs58.encode(ed25519PointToBytes(groupPoint))}`;
}

test.describe('Threshold Ed25519 (registration) — threshold-first account creation', () => {
  test.setTimeout(90_000);

  test.beforeEach(async ({ page }) => {
    // We run the core registration flow in same-origin mode for deterministic tests
    // (avoid depending on the wallet iframe host being available).
    const blankPageUrl = new URL('/__test_blank.html', DEFAULT_TEST_CONFIG.frontendUrl).toString();
    await setupBasicPasskeyTest(page, {
      frontendUrl: blankPageUrl,
      skipPasskeyManagerInit: true,
    });

    // setupBasicPasskeyTest() skips bootstrap "global fallbacks" when tatchi init is skipped.
    // WebAuthn mocks expect base64UrlEncode/base64UrlDecode to be present on window.
    await page.evaluate(async (base64Path) => {
      const { base64UrlEncode, base64UrlDecode } = await import(base64Path);
      (window as any).base64UrlEncode = base64UrlEncode;
      (window as any).base64UrlDecode = base64UrlDecode;
    }, SDK_ESM_PATHS.base64);
  });

  test('registration stores threshold material without local on-chain bootstrap', async ({
    page,
  }) => {
    let sendTxCount = 0;
    let thresholdPublicKey = '';
    let recoveryPublicKey = '';
    let relayIntentDigest32: number[] | null = null;
    let recoveryShareRequestCount = 0;
    let recoveryShareRequest:
      | {
          nearAccountId: string;
          rpId: string;
          keyVersion: string;
        }
      | null = null;
    let bootstrapRecoveryPublicKey = '';
    let bootstrapRecoveryExportCapable = false;
    let bootstrapKeyVersion = '';
    const relayerKeyId = 'relayer-keyid-mock-1';
    const relayerVerifyingShareB64u = toB64u(ed25519PointToBytes(getEd25519PointCtor().BASE));
    let thresholdActivatedOnChain = false;
    const accountsOnChain = new Set<string>();

    await page.route('**://test.rpc.fastnear.com/**', async (route) => {
      const req = route.request();
      const method = req.method().toUpperCase();

      const corsHeaders = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'POST,OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
      };

      if (method === 'OPTIONS') {
        await route.fulfill({ status: 204, headers: corsHeaders, body: '' });
        return;
      }

      if (method !== 'POST') {
        return route.fallback();
      }

      let body: any = {};
      try {
        body = JSON.parse(req.postData() || '{}');
      } catch {
        body = {};
      }

      const rpcMethod = body?.method;
      const params = body?.params || {};
      const id = body?.id ?? '1';

      const blockHash = bs58.encode(Buffer.alloc(32, 7));
      const blockHeight = 123;

      if (rpcMethod === 'block') {
        await route.fulfill({
          status: 200,
          headers: { 'Content-Type': 'application/json', ...corsHeaders },
          body: JSON.stringify({
            jsonrpc: '2.0',
            id,
            result: { header: { hash: blockHash, height: blockHeight } },
          }),
        });
        return;
      }

      if (rpcMethod === 'query' && params?.request_type === 'call_function') {
        const methodName = params?.method_name;
        const resultBytes = Array.from(Buffer.from(JSON.stringify({ verified: true }), 'utf8'));
        await route.fulfill({
          status: 200,
          headers: { 'Content-Type': 'application/json', ...corsHeaders },
          body: JSON.stringify({
            jsonrpc: '2.0',
            id,
            result: {
              result: resultBytes,
              logs: [`mock call_function ${String(methodName || '')}`],
            },
          }),
        });
        return;
      }

      if (rpcMethod === 'query' && params?.request_type === 'view_account') {
        const accountId = String(params?.account_id || '');
        if (!accountsOnChain.has(accountId)) {
          await route.fulfill({
            status: 200,
            headers: { 'Content-Type': 'application/json', ...corsHeaders },
            body: JSON.stringify({
              jsonrpc: '2.0',
              id,
              error: {
                code: -32000,
                message: 'UNKNOWN_ACCOUNT',
                data: 'UNKNOWN_ACCOUNT',
              },
            }),
          });
          return;
        }
        await route.fulfill({
          status: 200,
          headers: { 'Content-Type': 'application/json', ...corsHeaders },
          body: JSON.stringify({
            jsonrpc: '2.0',
            id,
            result: {
              amount: '0',
              locked: '0',
              code_hash: '11111111111111111111111111111111',
              storage_usage: 0,
              storage_paid_at: 0,
              block_height: blockHeight,
              block_hash: blockHash,
            },
          }),
        });
        return;
      }

      if (rpcMethod === 'query' && params?.request_type === 'view_account') {
        const accountId = String(params?.account_id || '');
        if (!accountsOnChain.has(accountId)) {
          await route.fulfill({
            status: 200,
            headers: { 'Content-Type': 'application/json', ...corsHeaders },
            body: JSON.stringify({
              jsonrpc: '2.0',
              id,
              error: {
                code: -32000,
                message: 'UNKNOWN_ACCOUNT',
                data: 'UNKNOWN_ACCOUNT',
              },
            }),
          });
          return;
        }
        await route.fulfill({
          status: 200,
          headers: { 'Content-Type': 'application/json', ...corsHeaders },
          body: JSON.stringify({
            jsonrpc: '2.0',
            id,
            result: {
              amount: '0',
              locked: '0',
              code_hash: '11111111111111111111111111111111',
              storage_usage: 0,
              storage_paid_at: 0,
              block_height: blockHeight,
              block_hash: blockHash,
            },
          }),
        });
        return;
      }

      if (rpcMethod === 'query' && params?.request_type === 'view_access_key') {
        await route.fulfill({
          status: 200,
          headers: { 'Content-Type': 'application/json', ...corsHeaders },
          body: JSON.stringify({
            jsonrpc: '2.0',
            id,
            result: {
              block_hash: blockHash,
              block_height: blockHeight,
              nonce: 0,
              permission: 'FullAccess',
            },
          }),
        });
        return;
      }

      if (rpcMethod === 'query' && params?.request_type === 'view_access_key_list') {
        const keys: any[] = [];
        if (thresholdActivatedOnChain && thresholdPublicKey) {
          keys.push({
            public_key: thresholdPublicKey,
            access_key: { nonce: 0, permission: 'FullAccess' },
          });
        }
        if (thresholdActivatedOnChain && recoveryPublicKey) {
          keys.push({
            public_key: recoveryPublicKey,
            access_key: { nonce: 0, permission: 'FullAccess' },
          });
        }
        await route.fulfill({
          status: 200,
          headers: { 'Content-Type': 'application/json', ...corsHeaders },
          body: JSON.stringify({
            jsonrpc: '2.0',
            id,
            result: { keys },
          }),
        });
        return;
      }

      if (rpcMethod === 'send_tx') {
        sendTxCount += 1;
        thresholdActivatedOnChain = true;
        await route.fulfill({
          status: 200,
          headers: { 'Content-Type': 'application/json', ...corsHeaders },
          body: JSON.stringify({
            jsonrpc: '2.0',
            id,
            result: {
              status: { SuccessValue: '' },
              transaction: { hash: `mock-tx-${Date.now()}` },
              transaction_outcome: { id: `mock-tx-outcome-${Date.now()}` },
              receipts_outcome: [],
            },
          }),
        });
        return;
      }

      await route.fulfill({
        status: 200,
        headers: { 'Content-Type': 'application/json', ...corsHeaders },
        body: JSON.stringify({ jsonrpc: '2.0', id, result: {} }),
      });
    });

    await page.route('**/registration/recovery-share', async (route) => {
      const req = route.request();
      const method = req.method().toUpperCase();
      const corsHeaders = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'POST,OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
      };

      if (method === 'OPTIONS') {
        await route.fulfill({ status: 204, headers: corsHeaders, body: '' });
        return;
      }

      const payload = JSON.parse(req.postData() || '{}');
      recoveryShareRequestCount += 1;
      recoveryShareRequest = {
        nearAccountId: String(payload?.nearAccountId || ''),
        rpId: String(payload?.rpId || ''),
        keyVersion: String(payload?.keyVersion || ''),
      };

      await route.fulfill({
        status: 200,
        headers: { 'Content-Type': 'application/json', ...corsHeaders },
        body: JSON.stringify({
          ok: true,
          recoveryServerShareB64u: Buffer.alloc(32, 5).toString('base64url'),
          keyVersion: DUAL_KEY_ED25519_KEY_VERSION_V1,
        }),
      });
    });

    await page.route('**/registration/bootstrap', async (route) => {
      const req = route.request();
      const method = req.method().toUpperCase();

      const corsHeaders = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'POST,OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
      };

      if (method === 'OPTIONS') {
        await route.fulfill({ status: 204, headers: corsHeaders, body: '' });
        return;
      }

      const post = req.postData() || '{}';
      const payload = JSON.parse(post);
      const accountId = String(payload?.new_account_id || '');
      if (accountId) {
        accountsOnChain.add(accountId);
      }
      // Extract the 32-byte challenge digest from the WebAuthn clientDataJSON.
      // This should be `sha256("register:<accountId>:<deviceNumber>")` (base64url).
      const clientDataJSONB64u = payload?.webauthn_registration?.response?.clientDataJSON;
      if (typeof clientDataJSONB64u === 'string' && clientDataJSONB64u) {
        try {
          const clientData = JSON.parse(
            Buffer.from(clientDataJSONB64u, 'base64url').toString('utf8'),
          );
          const challengeB64u = clientData?.challenge;
          if (typeof challengeB64u === 'string' && challengeB64u) {
            relayIntentDigest32 = Array.from(Buffer.from(challengeB64u, 'base64url'));
          }
        } catch {}
      }
      const clientVerifyingShareB64u =
        payload?.threshold_ed25519?.client_verifying_share_b64u || '';
      const thresholdSessionPolicy = payload?.threshold_ed25519?.session_policy || null;
      const thresholdSessionId = String(
        thresholdSessionPolicy?.sessionId || thresholdSessionPolicy?.session_id || '',
      ).trim();
      const thresholdSessionTtlMs = (() => {
        const n = Number(thresholdSessionPolicy?.ttlMs || thresholdSessionPolicy?.ttl_ms);
        return Number.isFinite(n) && n > 0 ? Math.floor(n) : 60_000;
      })();
      const thresholdSessionRemainingUses = (() => {
        const n = Number(
          thresholdSessionPolicy?.remainingUses || thresholdSessionPolicy?.remaining_uses,
        );
        return Number.isFinite(n) && n > 0 ? Math.floor(n) : 10_000;
      })();
      bootstrapRecoveryPublicKey = String(
        payload?.threshold_ed25519?.recovery_public_key || '',
      ).trim();
      bootstrapRecoveryExportCapable = payload?.threshold_ed25519?.recovery_export_capable === true;
      bootstrapKeyVersion = String(payload?.threshold_ed25519?.key_version || '').trim();

      thresholdPublicKey = compute2of2GroupPk({
        clientVerifyingShareB64u,
        relayerVerifyingShareB64u,
      });
      recoveryPublicKey = bootstrapRecoveryPublicKey;
      // Threshold-only: relay creates the account directly with the threshold key.
      thresholdActivatedOnChain = true;

      await route.fulfill({
        status: 200,
        headers: { 'Content-Type': 'application/json', ...corsHeaders },
        body: JSON.stringify({
          success: true,
          transactionHash: `mock_atomic_tx_${Date.now()}`,
          thresholdEd25519: {
            relayerKeyId,
            publicKey: thresholdPublicKey,
            keyVersion: bootstrapKeyVersion,
            recoveryExportCapable: bootstrapRecoveryExportCapable,
            recoveryPublicKey,
            relayerVerifyingShareB64u,
            ...(thresholdSessionId
              ? {
                  session: {
                    sessionKind: 'jwt',
                    sessionId: thresholdSessionId,
                    expiresAtMs: Date.now() + thresholdSessionTtlMs,
                    participantIds: [1, 2],
                    remainingUses: thresholdSessionRemainingUses,
                    jwt: 'mock-threshold-ed25519-registration-jwt',
                  },
                }
              : {}),
          },
        }),
      });
    });

    const registration = await page.evaluate(
      async ({ paths }) => {
        try {
          const { TatchiPasskey } = await import(paths.tatchi);
          const suffix =
            typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
              ? crypto.randomUUID()
              : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
          const accountId = `e2e${suffix}.w3a-v1.testnet`;

          const pm = new TatchiPasskey({
            nearNetwork: 'testnet',
            nearRpcUrl: 'https://test.rpc.fastnear.com',
            relayer: { url: 'http://localhost:3000' },
            iframeWallet: { walletOrigin: '' },
          });

          const confirmConfig = {
            uiMode: 'none',
            behavior: 'skipClick',
            autoProceedDelay: 0,
          };

          (window as any).__registrationEvents = [];

          const res = await pm.registration.registerPasskeyInternal(
            accountId,
            {
              signerOptions: {
                tempo: {
                  enabled: false,
                  participantIds: [1, 2],
                  signingSession: { kind: 'jwt', ttlMs: 1, remainingUses: 1 },
                },
                evm: {
                  enabled: false,
                  participantIds: [1, 2],
                  signingSession: { kind: 'jwt', ttlMs: 1, remainingUses: 1 },
                },
              },
              onEvent: (event: any) => {
                try {
                  (window as any).__registrationEvents.push(event);
                } catch {}
              },
            },
            confirmConfig as any,
          );

          return { accountId, success: !!res?.success, error: res?.error };
        } catch (error: any) {
          return { accountId: 'unknown', success: false, error: error?.message || String(error) };
        }
      },
      { paths: IMPORT_PATHS },
    );

    if (!registration.success) {
      throw new Error(`registration failed: ${registration.error || 'unknown'}`);
    }

    expect(sendTxCount).toBe(0);
    expect(thresholdActivatedOnChain).toBe(true);
    expect(thresholdPublicKey).toMatch(/^ed25519:/);
    expect(recoveryPublicKey).toMatch(/^ed25519:/);
    expect(relayIntentDigest32).toBeTruthy();
    expect(relayIntentDigest32).toHaveLength(32);
    expect(recoveryShareRequestCount).toBe(1);
    expect(recoveryShareRequest).not.toBeNull();
    expect(recoveryShareRequest?.nearAccountId).toBe(registration.accountId);
    expect(String(recoveryShareRequest?.rpId || '')).toMatch(/^(localhost|127\.0\.0\.1)$/);
    expect(recoveryShareRequest?.keyVersion).toBe(DUAL_KEY_ED25519_KEY_VERSION_V1);
    expect(bootstrapKeyVersion).toBe(DUAL_KEY_ED25519_KEY_VERSION_V1);
    expect(bootstrapRecoveryExportCapable).toBe(true);
    expect(bootstrapRecoveryPublicKey).toBe(recoveryPublicKey);
    // ConfirmTxFlow binds `sha256("register:<accountId>:<deviceNumber>")` into the WebAuthn challenge.
    const expectedIntentDigest32 = Array.from(
      createHash('sha256').update(`register:${registration.accountId}:1`, 'utf8').digest(),
    );
    expect(relayIntentDigest32).toEqual(expectedIntentDigest32);

    // Wait for local vault to be updated with threshold material.
    await expect
      .poll(
        async () => {
          return await page.evaluate(
            async ({ paths, accountId }) => {
              const { IndexedDBManager } = await import(paths.indexedDb);
              const rec = await IndexedDBManager.getNearThresholdKeyMaterial(
                String(accountId || '')
                  .trim()
                  .toLowerCase(),
                1,
              );
              return !!rec;
            },
            { paths: IMPORT_PATHS, accountId: registration.accountId },
          );
        },
        { timeout: 10_000 },
      )
      .toBe(true);

    await expect
      .poll(
        async () => {
          return await page.evaluate(() => {
            const events = (window as any).__registrationEvents;
            if (!Array.isArray(events)) return null;
            return (
              events.find(
                (e: any) =>
                  e?.phase === 'threshold-key-enrollment' && e?.thresholdKeyReady === true,
              ) ?? null
            );
          });
        },
        { timeout: 10_000 },
      )
      .not.toBeNull();

    const thresholdReadyEvent = await page.evaluate(() => {
      const events = (window as any).__registrationEvents;
      if (!Array.isArray(events)) return null;
      return (
        events.find(
          (e: any) => e?.phase === 'threshold-key-enrollment' && e?.thresholdKeyReady === true,
        ) ?? null
      );
    });

    expect(thresholdReadyEvent?.thresholdPublicKey).toBe(thresholdPublicKey);
    expect(thresholdReadyEvent?.relayerKeyId).toBe(relayerKeyId);

    const stored = await page.evaluate(
      async ({ paths, accountId }) => {
        const { IndexedDBManager } = await import(paths.indexedDb);
        const normalizedAccountId = String(accountId || '')
          .trim()
          .toLowerCase();
        const context = await IndexedDBManager.clientDB.resolveNearAccountContext(normalizedAccountId);
        const thresholdRec = await IndexedDBManager.getNearThresholdKeyMaterial(
          normalizedAccountId,
          1,
        );
        const rawThresholdRec =
          context?.profileId && context?.sourceChainIdKey
            ? await IndexedDBManager.nearKeysDB.getKeyMaterial(
                context.profileId,
                1,
                context.sourceChainIdKey,
                'threshold_share_v1',
              )
            : null;
        return {
          threshold: thresholdRec ? { ...thresholdRec } : null,
          rawThreshold: rawThresholdRec
            ? {
                ...rawThresholdRec,
                payload: rawThresholdRec.payload ? { ...rawThresholdRec.payload } : null,
              }
            : null,
        };
      },
      { paths: IMPORT_PATHS, accountId: registration.accountId },
    );

    expect(stored?.threshold?.kind).toBe('threshold_ed25519_2p_v1');
    expect(stored?.threshold?.publicKey).toBe(thresholdPublicKey);
    expect(String(stored?.threshold?.wrapKeySalt || '')).not.toBe('');
    expect(String(stored?.threshold?.relayerKeyId || '')).toBe(relayerKeyId);
    expect(String(stored?.threshold?.recoveryPublicKey || '')).toBe(recoveryPublicKey);
    expect(String(stored?.threshold?.keyVersion || '')).toBe(DUAL_KEY_ED25519_KEY_VERSION_V1);
    expect(stored?.threshold?.recoveryExportCapable).toBe(true);
    expect(String(stored?.rawThreshold?.wrapKeySalt || '')).not.toBe('');
    expect(stored?.rawThreshold?.payload).toMatchObject({
      relayerKeyId,
      recoveryPublicKey,
      keyVersion: DUAL_KEY_ED25519_KEY_VERSION_V1,
      recoveryExportCapable: true,
      clientShareDerivation: 'prf_first_v1',
    });
    expect(stored?.rawThreshold?.payload?.recoveryClientShareB64u).toBeUndefined();
    expect(stored?.rawThreshold?.payload?.recoveryServerShareB64u).toBeUndefined();
    expect(stored?.rawThreshold?.payload?.seedB64u).toBeUndefined();
    expect(stored?.rawThreshold?.payload?.recoveredSeedB64u).toBeUndefined();
    expect(stored?.rawThreshold?.payload?.privateKey).toBeUndefined();
    expect(stored?.rawThreshold?.payload?.nearPrivateKey).toBeUndefined();
    expect(stored?.rawThreshold?.payload?.paillierPrivateKeyB64u).toBeUndefined();
  });

  test('registration fails if relay omits threshold key material (no stored threshold material)', async ({
    page,
  }) => {
    let sendTxCount = 0;
    const accountsOnChain = new Set<string>();

    await page.route('**://test.rpc.fastnear.com/**', async (route) => {
      const req = route.request();
      const method = req.method().toUpperCase();
      const corsHeaders = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'POST,OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
      };

      if (method === 'OPTIONS') {
        await route.fulfill({ status: 204, headers: corsHeaders, body: '' });
        return;
      }
      if (method !== 'POST') return route.fallback();

      let body: any = {};
      try {
        body = JSON.parse(req.postData() || '{}');
      } catch {
        body = {};
      }

      const rpcMethod = body?.method;
      const params = body?.params || {};
      const id = body?.id ?? '1';
      const blockHash = bs58.encode(Buffer.alloc(32, 9));
      const blockHeight = 456;

      if (rpcMethod === 'block') {
        await route.fulfill({
          status: 200,
          headers: { 'Content-Type': 'application/json', ...corsHeaders },
          body: JSON.stringify({
            jsonrpc: '2.0',
            id,
            result: { header: { hash: blockHash, height: blockHeight } },
          }),
        });
        return;
      }

      if (rpcMethod === 'query' && params?.request_type === 'call_function') {
        const resultBytes = Array.from(Buffer.from(JSON.stringify({ verified: true }), 'utf8'));
        await route.fulfill({
          status: 200,
          headers: { 'Content-Type': 'application/json', ...corsHeaders },
          body: JSON.stringify({ jsonrpc: '2.0', id, result: { result: resultBytes, logs: [] } }),
        });
        return;
      }

      if (rpcMethod === 'query' && params?.request_type === 'view_account') {
        const accountId = String(params?.account_id || '');
        if (!accountsOnChain.has(accountId)) {
          await route.fulfill({
            status: 200,
            headers: { 'Content-Type': 'application/json', ...corsHeaders },
            body: JSON.stringify({
              jsonrpc: '2.0',
              id,
              error: {
                code: -32000,
                message: 'UNKNOWN_ACCOUNT',
                data: 'UNKNOWN_ACCOUNT',
              },
            }),
          });
          return;
        }
        await route.fulfill({
          status: 200,
          headers: { 'Content-Type': 'application/json', ...corsHeaders },
          body: JSON.stringify({
            jsonrpc: '2.0',
            id,
            result: {
              amount: '0',
              locked: '0',
              code_hash: '11111111111111111111111111111111',
              storage_usage: 0,
              storage_paid_at: 0,
              block_height: blockHeight,
              block_hash: blockHash,
            },
          }),
        });
        return;
      }

      if (rpcMethod === 'query' && params?.request_type === 'view_account') {
        const accountId = String(params?.account_id || '');
        if (!accountsOnChain.has(accountId)) {
          await route.fulfill({
            status: 200,
            headers: { 'Content-Type': 'application/json', ...corsHeaders },
            body: JSON.stringify({
              jsonrpc: '2.0',
              id,
              error: {
                code: -32000,
                message: 'UNKNOWN_ACCOUNT',
                data: 'UNKNOWN_ACCOUNT',
              },
            }),
          });
          return;
        }
        await route.fulfill({
          status: 200,
          headers: { 'Content-Type': 'application/json', ...corsHeaders },
          body: JSON.stringify({
            jsonrpc: '2.0',
            id,
            result: {
              amount: '0',
              locked: '0',
              code_hash: '11111111111111111111111111111111',
              storage_usage: 0,
              storage_paid_at: 0,
              block_height: blockHeight,
              block_hash: blockHash,
            },
          }),
        });
        return;
      }

      if (rpcMethod === 'query' && params?.request_type === 'view_access_key') {
        await route.fulfill({
          status: 200,
          headers: { 'Content-Type': 'application/json', ...corsHeaders },
          body: JSON.stringify({
            jsonrpc: '2.0',
            id,
            result: {
              block_hash: blockHash,
              block_height: blockHeight,
              nonce: 0,
              permission: 'FullAccess',
            },
          }),
        });
        return;
      }

      if (rpcMethod === 'query' && params?.request_type === 'view_access_key_list') {
        const keys: any[] = [];
        await route.fulfill({
          status: 200,
          headers: { 'Content-Type': 'application/json', ...corsHeaders },
          body: JSON.stringify({ jsonrpc: '2.0', id, result: { keys } }),
        });
        return;
      }

      if (rpcMethod === 'send_tx') {
        sendTxCount += 1;
        await route.fulfill({
          status: 200,
          headers: { 'Content-Type': 'application/json', ...corsHeaders },
          body: JSON.stringify({
            jsonrpc: '2.0',
            id,
            result: {
              status: { SuccessValue: '' },
              transaction: { hash: `mock-tx-${Date.now()}` },
              transaction_outcome: { id: `mock-tx-outcome-${Date.now()}` },
              receipts_outcome: [],
            },
          }),
        });
        return;
      }

      await route.fulfill({
        status: 200,
        headers: { 'Content-Type': 'application/json', ...corsHeaders },
        body: JSON.stringify({ jsonrpc: '2.0', id, result: {} }),
      });
    });

    await page.route('**/registration/recovery-share', async (route) => {
      const req = route.request();
      const method = req.method().toUpperCase();
      const corsHeaders = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'POST,OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
      };
      if (method === 'OPTIONS') {
        await route.fulfill({ status: 204, headers: corsHeaders, body: '' });
        return;
      }

      await route.fulfill({
        status: 200,
        headers: { 'Content-Type': 'application/json', ...corsHeaders },
        body: JSON.stringify({
          ok: true,
          recoveryServerShareB64u: Buffer.alloc(32, 6).toString('base64url'),
          keyVersion: DUAL_KEY_ED25519_KEY_VERSION_V1,
        }),
      });
    });

    await page.route('**/registration/bootstrap', async (route) => {
      const req = route.request();
      const method = req.method().toUpperCase();
      const corsHeaders = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'POST,OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
      };
      if (method === 'OPTIONS') {
        await route.fulfill({ status: 204, headers: corsHeaders, body: '' });
        return;
      }

      const payload = JSON.parse(req.postData() || '{}');
      const accountId = String(payload?.new_account_id || '');
      if (accountId) {
        accountsOnChain.add(accountId);
      }

      await route.fulfill({
        status: 200,
        headers: { 'Content-Type': 'application/json', ...corsHeaders },
        body: JSON.stringify({
          success: true,
          transactionHash: `mock_atomic_tx_${Date.now()}`,
          // thresholdEd25519 intentionally omitted
        }),
      });
    });

    const registration = await page.evaluate(
      async ({ paths }) => {
        try {
          const { TatchiPasskey } = await import(paths.tatchi);
          const suffix =
            typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
              ? crypto.randomUUID()
              : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
          const accountId = `e2e${suffix}.w3a-v1.testnet`;

          const pm = new TatchiPasskey({
            nearNetwork: 'testnet',
            nearRpcUrl: 'https://test.rpc.fastnear.com',
            relayer: { url: 'http://localhost:3000' },
            iframeWallet: { walletOrigin: '' },
          });

          const confirmConfig = {
            uiMode: 'none',
            behavior: 'skipClick',
            autoProceedDelay: 0,
          };

          (window as any).__registrationEvents = [];
          const res = await pm.registration.registerPasskeyInternal(
            accountId,
            {
              signerOptions: {
                tempo: {
                  enabled: false,
                  participantIds: [1, 2],
                  signingSession: { kind: 'jwt', ttlMs: 1, remainingUses: 1 },
                },
                evm: {
                  enabled: false,
                  participantIds: [1, 2],
                  signingSession: { kind: 'jwt', ttlMs: 1, remainingUses: 1 },
                },
              },
              onEvent: (event: any) => {
                try {
                  (window as any).__registrationEvents.push(event);
                } catch {}
              },
            },
            confirmConfig as any,
          );
          return { accountId, success: !!res?.success, error: res?.error };
        } catch (error: any) {
          return { accountId: 'unknown', success: false, error: error?.message || String(error) };
        }
      },
      { paths: IMPORT_PATHS },
    );

    expect(registration.success).toBe(false);
    expect(Boolean(registration.error)).toBe(true);
    expect(sendTxCount).toBe(0);

    const stored = await page.evaluate(
      async ({ paths, accountId }) => {
        const { IndexedDBManager } = await import(paths.indexedDb);
        const rec = await IndexedDBManager.getNearThresholdKeyMaterial(
          String(accountId || '')
            .trim()
            .toLowerCase(),
          1,
        );
        return rec ? { ...rec } : null;
      },
      { paths: IMPORT_PATHS, accountId: registration.accountId },
    );

    expect(stored).toBeNull();
  });

  test('registration fails before bootstrap when recovery-share preflight fails', async ({ page }) => {
    let recoveryShareRequestCount = 0;
    let bootstrapRequestCount = 0;

    await page.route('**/registration/recovery-share', async (route) => {
      const req = route.request();
      const method = req.method().toUpperCase();
      const corsHeaders = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'POST,OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
      };
      if (method === 'OPTIONS') {
        await route.fulfill({ status: 204, headers: corsHeaders, body: '' });
        return;
      }
      recoveryShareRequestCount += 1;
      await route.fulfill({
        status: 500,
        headers: { 'Content-Type': 'application/json', ...corsHeaders },
        body: JSON.stringify({
          ok: false,
          code: 'internal',
          message: 'threshold-ed25519 recovery-share preparation failed in test',
        }),
      });
    });

    await page.route('**/registration/bootstrap', async (route) => {
      const method = route.request().method().toUpperCase();
      const corsHeaders = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'POST,OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
      };
      if (method === 'OPTIONS') {
        await route.fulfill({ status: 204, headers: corsHeaders, body: '' });
        return;
      }
      bootstrapRequestCount += 1;
      await route.fulfill({
        status: 500,
        headers: { 'Content-Type': 'application/json', ...corsHeaders },
        body: JSON.stringify({ success: false, error: 'bootstrap should not be reached' }),
      });
    });

    const registration = await page.evaluate(
      async ({ paths }) => {
        try {
          const { TatchiPasskey } = await import(paths.tatchi);
          const suffix =
            typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
              ? crypto.randomUUID()
              : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
          const accountId = `e2e${suffix}.w3a-v1.testnet`;

          const pm = new TatchiPasskey({
            nearNetwork: 'testnet',
            nearRpcUrl: 'https://test.rpc.fastnear.com',
            relayer: { url: 'http://localhost:3000' },
            iframeWallet: { walletOrigin: '' },
          });

          const confirmConfig = {
            uiMode: 'none',
            behavior: 'skipClick',
            autoProceedDelay: 0,
          };

          const res = await pm.registration.registerPasskeyInternal(
            accountId,
            {
              signerOptions: {
                tempo: {
                  enabled: false,
                  participantIds: [1, 2],
                  signingSession: { kind: 'jwt', ttlMs: 1, remainingUses: 1 },
                },
                evm: {
                  enabled: false,
                  participantIds: [1, 2],
                  signingSession: { kind: 'jwt', ttlMs: 1, remainingUses: 1 },
                },
              },
            },
            confirmConfig as any,
          );
          return { accountId, success: !!res?.success, error: res?.error };
        } catch (error: any) {
          return { accountId: 'unknown', success: false, error: error?.message || String(error) };
        }
      },
      { paths: IMPORT_PATHS },
    );

    expect(registration.success).toBe(false);
    expect(String(registration.error || '')).toContain('recovery-share');
    expect(recoveryShareRequestCount).toBe(1);
    expect(bootstrapRequestCount).toBe(0);
  });

  test('registration rejects operational-only threshold bootstrap results', async ({ page }) => {
    let recoveryShareRequestCount = 0;
    let bootstrapRequestCount = 0;
    const relayerVerifyingShareB64u = toB64u(ed25519PointToBytes(getEd25519PointCtor().BASE));

    await page.route('**/registration/recovery-share', async (route) => {
      const req = route.request();
      const method = req.method().toUpperCase();
      const corsHeaders = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'POST,OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
      };
      if (method === 'OPTIONS') {
        await route.fulfill({ status: 204, headers: corsHeaders, body: '' });
        return;
      }
      recoveryShareRequestCount += 1;
      await route.fulfill({
        status: 200,
        headers: { 'Content-Type': 'application/json', ...corsHeaders },
        body: JSON.stringify({
          ok: true,
          recoveryServerShareB64u: Buffer.alloc(32, 8).toString('base64url'),
          keyVersion: DUAL_KEY_ED25519_KEY_VERSION_V1,
        }),
      });
    });

    await page.route('**/registration/bootstrap', async (route) => {
      const req = route.request();
      const method = req.method().toUpperCase();
      const corsHeaders = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'POST,OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
      };
      if (method === 'OPTIONS') {
        await route.fulfill({ status: 204, headers: corsHeaders, body: '' });
        return;
      }
      bootstrapRequestCount += 1;
      const payload = JSON.parse(req.postData() || '{}');
      const thresholdSessionPolicy = payload?.threshold_ed25519?.session_policy || null;
      const thresholdSessionId = String(
        thresholdSessionPolicy?.sessionId || thresholdSessionPolicy?.session_id || '',
      ).trim();
      const thresholdSessionTtlMs = (() => {
        const n = Number(thresholdSessionPolicy?.ttlMs || thresholdSessionPolicy?.ttl_ms);
        return Number.isFinite(n) && n > 0 ? Math.floor(n) : 60_000;
      })();
      const thresholdSessionRemainingUses = (() => {
        const n = Number(
          thresholdSessionPolicy?.remainingUses || thresholdSessionPolicy?.remaining_uses,
        );
        return Number.isFinite(n) && n > 0 ? Math.floor(n) : 10_000;
      })();
      const thresholdPublicKey = compute2of2GroupPk({
        clientVerifyingShareB64u: String(
          payload?.threshold_ed25519?.client_verifying_share_b64u || '',
        ),
        relayerVerifyingShareB64u,
      });

      await route.fulfill({
        status: 200,
        headers: { 'Content-Type': 'application/json', ...corsHeaders },
        body: JSON.stringify({
          success: true,
          transactionHash: `mock_atomic_tx_${Date.now()}`,
          thresholdEd25519: {
            relayerKeyId: 'relayer-keyid-mock-1',
            publicKey: thresholdPublicKey,
            keyVersion: DUAL_KEY_ED25519_KEY_VERSION_V1,
            recoveryExportCapable: true,
            relayerVerifyingShareB64u,
            ...(thresholdSessionId
              ? {
                  session: {
                    sessionKind: 'jwt',
                    sessionId: thresholdSessionId,
                    expiresAtMs: Date.now() + thresholdSessionTtlMs,
                    participantIds: [1, 2],
                    remainingUses: thresholdSessionRemainingUses,
                    jwt: 'mock-threshold-ed25519-registration-jwt',
                  },
                }
              : {}),
          },
        }),
      });
    });

    const registration = await page.evaluate(
      async ({ paths }) => {
        try {
          const { TatchiPasskey } = await import(paths.tatchi);
          const suffix =
            typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
              ? crypto.randomUUID()
              : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
          const accountId = `e2e${suffix}.w3a-v1.testnet`;

          const pm = new TatchiPasskey({
            nearNetwork: 'testnet',
            nearRpcUrl: 'https://test.rpc.fastnear.com',
            relayer: { url: 'http://localhost:3000' },
            iframeWallet: { walletOrigin: '' },
          });

          const confirmConfig = {
            uiMode: 'none',
            behavior: 'skipClick',
            autoProceedDelay: 0,
          };

          const res = await pm.registration.registerPasskeyInternal(
            accountId,
            {
              signerOptions: {
                tempo: {
                  enabled: false,
                  participantIds: [1, 2],
                  signingSession: { kind: 'jwt', ttlMs: 1, remainingUses: 1 },
                },
                evm: {
                  enabled: false,
                  participantIds: [1, 2],
                  signingSession: { kind: 'jwt', ttlMs: 1, remainingUses: 1 },
                },
              },
            },
            confirmConfig as any,
          );
          return { accountId, success: !!res?.success, error: res?.error };
        } catch (error: any) {
          return { accountId: 'unknown', success: false, error: error?.message || String(error) };
        }
      },
      { paths: IMPORT_PATHS },
    );

    expect(registration.success).toBe(false);
    expect(String(registration.error || '')).toContain(
      'Atomic registration returned an incomplete threshold-ed25519 Option B package',
    );
    expect(recoveryShareRequestCount).toBe(1);
    expect(bootstrapRequestCount).toBe(1);

    const stored = await page.evaluate(
      async ({ paths, accountId }) => {
        const { IndexedDBManager } = await import(paths.indexedDb);
        const rec = await IndexedDBManager.getNearThresholdKeyMaterial(
          String(accountId || '')
            .trim()
            .toLowerCase(),
          1,
        );
        return rec ? { ...rec } : null;
      },
      { paths: IMPORT_PATHS, accountId: registration.accountId },
    );

    expect(stored).toBeNull();
  });
});
