/**
 * Threshold Ed25519 (2-party) — derived relayer share mode restart.
 *
 * This test proves that in `THRESHOLD_ED25519_SHARE_MODE=derived` the relayer does not need to
 * persist long-lived signing shares: after a relayer restart (fresh in-memory stores), signing
 * still succeeds because the relayer deterministically re-derives its signing share from
 * `THRESHOLD_ED25519_MASTER_SECRET_B64U` plus the canonical registration context.
 */

import { test, expect } from '@playwright/test';
import bs58 from 'bs58';
import { ed25519 } from '@noble/curves/ed25519.js';
import { DEFAULT_TEST_CONFIG } from '../setup/config';
import { createRelayRouter } from '@server/router/express-adaptor';
import { startExpressRouter } from '../relayer/helpers';
import {
  createInMemoryJwtSessionAdapter,
  installFastNearRpcMock,
  installThresholdEd25519RegistrationMocks,
  makeAuthServiceForThreshold,
  persistThresholdEd25519RegistrationMaterial,
  setupThresholdE2ePage,
} from './thresholdEd25519.testUtils';
import { threshold_ed25519_compute_near_tx_signing_digests } from '../../wasm/near_signer/pkg/wasm_signer_worker.js';

test.describe('threshold-ed25519 derived share mode restart', () => {
  test.setTimeout(180_000);

  test.beforeEach(async ({ page }) => {
    await setupThresholdE2ePage(page);
  });

  test('signs successfully after relayer restart (no persisted relayer signing share)', async ({
    page,
  }) => {
    test.fixme(true, 'Option B relayer derived-mode restart is not implemented yet');
    const keysOnChain = new Set<string>();
    const nonceByPublicKey = new Map<string, number>();
    let sendTxCount = 0;

    const masterSecretB64u = Buffer.alloc(32, 7).toString('base64url');
    const derivedConfig = {
      THRESHOLD_ED25519_SHARE_MODE: 'derived',
      THRESHOLD_ED25519_MASTER_SECRET_B64U: masterSecretB64u,
    } as const;

    const frontendOrigin = new URL(DEFAULT_TEST_CONFIG.frontendUrl).origin;

    const startDerivedRelayer = async (): Promise<{
      baseUrl: string;
      threshold: ReturnType<typeof makeAuthServiceForThreshold>['threshold'];
      close: () => Promise<void>;
    }> => {
      const { service, threshold } = makeAuthServiceForThreshold(keysOnChain, derivedConfig);
      await service.getRelayerAccount();
      const session = createInMemoryJwtSessionAdapter();
      const router = createRelayRouter(service, {
        corsOrigins: [frontendOrigin],
        threshold,
        session,
      });
      const server = await startExpressRouter(router);
      return { ...server, threshold };
    };

    const relayer1Counts = { keygen: 0, session: 0, authorize: 0, init: 0, finalize: 0 };
    const relayer2Counts = { keygen: 0, session: 0, authorize: 0, init: 0, finalize: 0 };

    type ExtractedSignedTx = { nonce: string; blockHash: number[]; signature: number[] };
    type FlowResult =
      | {
          ok: true;
          accountId: string;
          operationalPublicKey: string;
          txInput: { receiverId: string; wasmActions: unknown[] };
          signed: ExtractedSignedTx;
        }
      | { ok: false; error: string };

    const srv1 = await startDerivedRelayer();
    let baseline: FlowResult | null = null;
    try {
      await page.route(`${srv1.baseUrl}/threshold-ed25519/session`, async (route) => {
        const req = route.request();
        if (req.method().toUpperCase() === 'POST') relayer1Counts.session += 1;
        await route.fallback();
      });
      await page.route(`${srv1.baseUrl}/threshold-ed25519/authorize`, async (route) => {
        const req = route.request();
        if (req.method().toUpperCase() === 'POST') relayer1Counts.authorize += 1;
        await route.fallback();
      });
      await page.route(`${srv1.baseUrl}/threshold-ed25519/sign/init`, async (route) => {
        const req = route.request();
        if (req.method().toUpperCase() === 'POST') relayer1Counts.init += 1;
        await route.fallback();
      });
      await page.route(`${srv1.baseUrl}/threshold-ed25519/sign/finalize`, async (route) => {
        const req = route.request();
        if (req.method().toUpperCase() === 'POST') relayer1Counts.finalize += 1;
        await route.fallback();
      });
      await installThresholdEd25519RegistrationMocks(page, {
        relayerBaseUrl: srv1.baseUrl,
        keysOnChain,
        nonceByPublicKey,
        onBootstrap: async (bootstrap) => {
          await persistThresholdEd25519RegistrationMaterial({
            threshold: srv1.threshold,
            ...bootstrap,
          });
        },
      });

      await installFastNearRpcMock(page, {
        keysOnChain,
        nonceByPublicKey,
        onSendTx: () => {
          sendTxCount += 1;
        },
        strictAccessKeyLookup: true,
      });

      baseline = (await page.evaluate(
        async ({ relayerUrl }) => {
          try {
            const { TatchiPasskey } = await import('/sdk/esm/core/TatchiPasskey/index.js');
            const { ActionType, toActionArgsWasm } = await import('/sdk/esm/core/types/actions.js');
            const suffix =
              typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
                ? crypto.randomUUID()
                : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
            const accountId = `e2ederived${suffix}.w3a-v1.testnet`;

            const pm = new TatchiPasskey({
              nearNetwork: 'testnet',
              nearRpcUrl: 'https://test.rpc.fastnear.com',
              relayer: { url: relayerUrl },
              signingSessionDefaults: { ttlMs: 60_000, remainingUses: 10 },
              iframeWallet: { walletOrigin: '' },
            });

            const confirmConfig = { uiMode: 'none', behavior: 'skipClick', autoProceedDelay: 0 };

            const reg = await pm.registration.registerPasskeyInternal(
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
            if (!reg?.success) return { ok: false, error: reg?.error || 'registration failed' };

            const login = await pm.auth.unlock(accountId);
            if (!login?.success) return { ok: false, error: login?.error || 'login failed' };

            const receiverId = 'w3a-v1.testnet';
            const actions = [{ type: ActionType.Transfer, amount: '1' }];
            const wasmActions = actions.map(toActionArgsWasm);

            const signed = await pm.near.signTransactionsWithActions({
              nearAccountId: accountId,
              transactions: [{ receiverId, actions }],
              options: {
                confirmationConfig: confirmConfig as any,
              },
            });

            if (!Array.isArray(signed) || signed.length !== 1) {
              return {
                ok: false,
                error: `expected 1 signed tx, got ${Array.isArray(signed) ? signed.length : 'non-array'}`,
              };
            }

            const signedTx: any = signed[0]?.signedTransaction;
            const signatureData = signedTx?.signature?.signatureData;
            const tx = signedTx?.transaction;
            if (!tx || !signatureData) {
              return { ok: false, error: 'invalid signed transaction shape' };
            }

            return {
              ok: true,
              accountId,
              operationalPublicKey: String(reg.operationalPublicKey || ''),
              txInput: { receiverId, wasmActions },
              signed: {
                nonce: typeof tx.nonce === 'bigint' ? tx.nonce.toString() : String(tx.nonce || ''),
                blockHash: Array.from(tx.blockHash || []) as number[],
                signature: Array.from(signatureData) as number[],
              },
            };
          } catch (e: any) {
            return { ok: false, error: e?.message || String(e) };
          }
        },
        { relayerUrl: srv1.baseUrl },
      )) as FlowResult;

      if (!baseline.ok) {
        throw new Error(`baseline derived-mode signing failed: ${baseline.error || 'unknown'}`);
      }
    } finally {
      await srv1.close().catch(() => undefined);
    }

    const srv2 = await startDerivedRelayer();
    let afterRestart: FlowResult | null = null;
    try {
      await page.route(`${srv2.baseUrl}/threshold-ed25519/session`, async (route) => {
        const req = route.request();
        if (req.method().toUpperCase() === 'POST') relayer2Counts.session += 1;
        await route.fallback();
      });
      await page.route(`${srv2.baseUrl}/threshold-ed25519/authorize`, async (route) => {
        const req = route.request();
        if (req.method().toUpperCase() === 'POST') relayer2Counts.authorize += 1;
        await route.fallback();
      });
      await page.route(`${srv2.baseUrl}/threshold-ed25519/sign/init`, async (route) => {
        const req = route.request();
        if (req.method().toUpperCase() === 'POST') relayer2Counts.init += 1;
        await route.fallback();
      });
      await page.route(`${srv2.baseUrl}/threshold-ed25519/sign/finalize`, async (route) => {
        const req = route.request();
        if (req.method().toUpperCase() === 'POST') relayer2Counts.finalize += 1;
        await route.fallback();
      });

      afterRestart = (await page.evaluate(
        async ({ relayerUrl, accountId }) => {
          try {
            const { TatchiPasskey } = await import('/sdk/esm/core/TatchiPasskey/index.js');
            const { ActionType, toActionArgsWasm } = await import('/sdk/esm/core/types/actions.js');

            const pm = new TatchiPasskey({
              nearNetwork: 'testnet',
              nearRpcUrl: 'https://test.rpc.fastnear.com',
              relayer: { url: relayerUrl },
              signingSessionDefaults: { ttlMs: 60_000, remainingUses: 10 },
              iframeWallet: { walletOrigin: '' },
            });

            const confirmConfig = { uiMode: 'none', behavior: 'skipClick', autoProceedDelay: 0 };

            // After relayer restart, we must re-login (fresh threshold session / UserConfirm confirmation).
            const login = await pm.auth.unlock(accountId);
            if (!login?.success) return { ok: false, error: login?.error || 'login failed' };

            const receiverId = 'w3a-v1.testnet';
            const actions = [{ type: ActionType.Transfer, amount: '1' }];
            const wasmActions = actions.map(toActionArgsWasm);

            const signed = await pm.near.signTransactionsWithActions({
              nearAccountId: accountId,
              transactions: [{ receiverId, actions }],
              options: {
                confirmationConfig: confirmConfig as any,
              },
            });

            if (!Array.isArray(signed) || signed.length !== 1) {
              return {
                ok: false,
                error: `expected 1 signed tx, got ${Array.isArray(signed) ? signed.length : 'non-array'}`,
              };
            }

            const signedTx: any = signed[0]?.signedTransaction;
            const signatureData = signedTx?.signature?.signatureData;
            const tx = signedTx?.transaction;
            if (!tx || !signatureData) {
              return { ok: false, error: 'invalid signed transaction shape' };
            }

            // Pull keys from IndexedDB-backed state for verification in the test process.
            return {
              ok: true,
              accountId,
              operationalPublicKey: String(login?.operationalPublicKey || ''),
              txInput: { receiverId, wasmActions },
              signed: {
                nonce: typeof tx.nonce === 'bigint' ? tx.nonce.toString() : String(tx.nonce || ''),
                blockHash: Array.from(tx.blockHash || []) as number[],
                signature: Array.from(signatureData) as number[],
              },
            };
          } catch (e: any) {
            return { ok: false, error: e?.message || String(e) };
          }
        },
        { relayerUrl: srv2.baseUrl, accountId: (baseline as any).accountId },
      )) as FlowResult;

      if (!afterRestart.ok) {
        throw new Error(
          `derived-mode signing after restart failed: ${afterRestart.error || 'unknown'}`,
        );
      }
    } finally {
      await srv2.close().catch(() => undefined);
    }

    expect(sendTxCount).toBe(0);

    // Baseline (srv1) should sign via derived-mode relayer with no separate enrollment.
    expect(relayer1Counts.keygen).toBe(0);
    expect(relayer1Counts.session).toBe(1);
    expect(relayer1Counts.authorize).toBeGreaterThanOrEqual(1);
    expect(relayer1Counts.init).toBe(1);
    expect(relayer1Counts.finalize).toBe(1);

    // After restart (srv2), no keygen should be required to sign (shares are derived).
    expect(relayer2Counts.keygen).toBe(0);
    expect(relayer2Counts.session).toBe(1);
    expect(relayer2Counts.authorize).toBeGreaterThanOrEqual(1);
    expect(relayer2Counts.init).toBe(1);
    expect(relayer2Counts.finalize).toBe(1);

    if (!baseline || !baseline.ok || !afterRestart || !afterRestart.ok) {
      throw new Error('Unexpected missing signing results');
    }

    const operationalPkStr = String(baseline.operationalPublicKey);
    const toPkBytes = (pk: string): Uint8Array => {
      const raw = pk.includes(':') ? pk.split(':')[1] : pk;
      return bs58.decode(raw);
    };
    const wrongPublicKey = `ed25519:${bs58.encode(ed25519.getPublicKey(new Uint8Array(32).fill(45)))}`;

    const computeDigest = (signed: { nonce: string; blockHash: number[] }): Uint8Array => {
      const signingPayload = {
        kind: 'near_tx',
        txSigningRequests: [
          {
            nearAccountId: String(baseline!.ok ? baseline!.accountId : ''),
            receiverId: String(baseline!.ok ? baseline!.txInput.receiverId : ''),
            actions: baseline!.ok ? baseline!.txInput.wasmActions : [],
          },
        ],
        transactionContext: {
          nearPublicKeyStr: operationalPkStr,
          nextNonce: String(signed.nonce),
          txBlockHash: bs58.encode(Uint8Array.from(signed.blockHash)),
          txBlockHeight: '424242',
        },
      };

      const digestsUnknown: unknown =
        threshold_ed25519_compute_near_tx_signing_digests(signingPayload);
      if (!Array.isArray(digestsUnknown) || digestsUnknown.length === 0) {
        throw new Error('Expected a non-empty signing digests array');
      }
      const digest0 = digestsUnknown[0];
      if (!(digest0 instanceof Uint8Array) || digest0.length !== 32) {
        throw new Error('Expected digest[0] to be a 32-byte Uint8Array');
      }
      return digest0;
    };

    const verifyThresholdSigned = (signed: ExtractedSignedTx): void => {
      const digest = computeDigest(signed);
      const sigBytes = Uint8Array.from(signed.signature);
      expect(sigBytes.length).toBe(64);
      expect(ed25519.verify(sigBytes, digest, toPkBytes(operationalPkStr))).toBe(true);
      expect(ed25519.verify(sigBytes, digest, toPkBytes(wrongPublicKey))).toBe(false);
    };

    verifyThresholdSigned(baseline.signed);
    verifyThresholdSigned(afterRestart.signed);
  });
});
