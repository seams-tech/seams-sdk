/**
 * Threshold Ed25519 (2-party) — batch near-tx signing.
 *
 * Validates that batch signing produces valid threshold signatures per-transaction (no local fallback),
 * and that the relayer FROST endpoints are exercised once per digest.
 */

import { test, expect } from '@playwright/test';
import bs58 from 'bs58';
import { ed25519 } from '@noble/curves/ed25519.js';
import {
  installFastNearRpcMock,
  installThresholdEd25519RegistrationMocks,
  makeAuthServiceForThreshold,
  persistThresholdEd25519RegistrationMaterial,
  setupManagedThresholdRegistrationHarness,
  setupThresholdE2ePage,
} from './thresholdEd25519.testUtils';
import { threshold_ed25519_compute_near_tx_signing_digests } from '../../wasm/near_signer/pkg/wasm_signer_worker.js';

const BATCH_RUNTIME_POLICY_SCOPE = {
  orgId: 'org_threshold_batch',
  projectId: 'proj_threshold_batch',
  envId: 'dev',
} as const;

test.describe('threshold-ed25519 batch signing', () => {
  test.setTimeout(180_000);

  test.beforeEach(async ({ page }) => {
    await setupThresholdE2ePage(page);
  });

  test('happy path: batch (2 txs) threshold signatures verify and relayer is called per digest', async ({
    page,
  }) => {
    const keysOnChain = new Set<string>();
    const nonceByPublicKey = new Map<string, number>();
    let sendTxCount = 0;

    const { service, threshold } = makeAuthServiceForThreshold(keysOnChain);
    await service.getRelayerAccount();
    const managedRegistrationHarness = await setupManagedThresholdRegistrationHarness({
      page,
      service,
      threshold,
      keyName: 'threshold-batch-browser',
      orgId: 'org_threshold_batch',
      orgSlug: 'threshold-batch-org',
      orgName: 'Threshold Batch Org',
      projectId: 'proj_threshold_batch',
      projectName: 'Threshold Batch Project',
    });

    const relayerCounts = { keygen: 0, session: 0, authorize: 0, init: 0, finalize: 0 };

    try {
      await page.route(
        `${managedRegistrationHarness.baseUrl}/threshold-ed25519/session`,
        async (route) => {
          const req = route.request();
          if (req.method().toUpperCase() === 'POST') relayerCounts.session += 1;
          await route.fallback();
        },
      );

      await page.route(
        `${managedRegistrationHarness.baseUrl}/threshold-ed25519/authorize`,
        async (route) => {
          const req = route.request();
          if (req.method().toUpperCase() === 'POST') {
            relayerCounts.authorize += 1;
          }
          await route.fallback();
        },
      );

      await page.route(
        `${managedRegistrationHarness.baseUrl}/threshold-ed25519/sign/init`,
        async (route) => {
          const req = route.request();
          if (req.method().toUpperCase() === 'POST') relayerCounts.init += 1;
          await route.fallback();
        },
      );
      await page.route(
        `${managedRegistrationHarness.baseUrl}/threshold-ed25519/sign/finalize`,
        async (route) => {
          const req = route.request();
          if (req.method().toUpperCase() === 'POST') relayerCounts.finalize += 1;
          await route.fallback();
        },
      );

      await installThresholdEd25519RegistrationMocks(page, {
        relayerBaseUrl: managedRegistrationHarness.baseUrl,
        keysOnChain,
        nonceByPublicKey,
        session: managedRegistrationHarness.session,
        threshold,
        runtimePolicyScope: BATCH_RUNTIME_POLICY_SCOPE,
        onBootstrap: async (bootstrap) => {
          await persistThresholdEd25519RegistrationMaterial({ threshold, ...bootstrap });
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

      type ExtractedSignedTx = {
        signerId: string;
        receiverId: string;
        nonce: string;
        blockHash: number[];
        signature: number[];
        borshBytes: number[];
      };

      type BatchSigningResult =
        | {
            ok: true;
            accountId: string;
            operationalPublicKey: string;
            ecdsaTempoKeyRef: {
              ecdsaThresholdKeyId: string;
              relayerKeyId: string;
              thresholdSessionId: string;
              participantIds: number[];
              ethereumAddress: string;
            };
            txInput: { receiverId: string; wasmActions: unknown[] };
            signedTxs: ExtractedSignedTx[];
          }
        | { ok: false; error: string };

      const result = (await page.evaluate(
        async ({ relayerUrl, managedRegistration }) => {
          try {
            const { SeamsPasskey } = await import('/sdk/esm/core/SeamsPasskey/index.js');
            const { ActionType, toActionArgsWasm } = await import('/sdk/esm/core/types/actions.js');
            const suffix =
              typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
                ? crypto.randomUUID()
                : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
            const accountId = `e2ebatch${suffix}.w3a-v1.testnet`;

            const pm = new SeamsPasskey({
              nearNetwork: 'testnet',
              nearRpcUrl: 'https://test.rpc.fastnear.com',
              relayer: { url: relayerUrl },
              ...(managedRegistration
                ? {
                    registration: {
                      mode: 'managed' as const,
                      environmentId: String(managedRegistration.environmentId || ''),
                      publishableKey: String(managedRegistration.publishableKey || ''),
                    },
                  }
                : {}),
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

            const ecdsaTempoKeyRef = (() => {
              try {
                const keyRef = (
                  pm.getContext().signingEngine as any
                ).getThresholdEcdsaKeyRefForSigning({
                  nearAccountId: accountId,
                  chain: 'tempo',
                });
                return {
                  ecdsaThresholdKeyId: String(keyRef?.ecdsaThresholdKeyId || ''),
                  relayerKeyId: String(
                    keyRef?.relayerKeyId || keyRef?.backendBinding?.relayerKeyId || '',
                  ),
                  thresholdSessionId: String(keyRef?.thresholdSessionId || ''),
                  participantIds: Array.isArray(keyRef?.participantIds)
                    ? keyRef.participantIds
                        .map((value: unknown) => Number(value))
                        .filter(Number.isFinite)
                    : [],
                  ethereumAddress: String(keyRef?.ethereumAddress || ''),
                };
              } catch (error: any) {
                throw new Error(error?.message || 'post-registration ECDSA key ref is unavailable');
              }
            })();
            if (
              !ecdsaTempoKeyRef.ecdsaThresholdKeyId ||
              !ecdsaTempoKeyRef.relayerKeyId ||
              !ecdsaTempoKeyRef.thresholdSessionId ||
              ecdsaTempoKeyRef.participantIds.length === 0 ||
              !/^0x[0-9a-f]{40}$/i.test(ecdsaTempoKeyRef.ethereumAddress)
            ) {
              return {
                ok: false,
                error: `post-registration ECDSA key ref incomplete: ${JSON.stringify(ecdsaTempoKeyRef)}`,
              };
            }

            const receiverId = 'w3a-v1.testnet';
            const actions = [{ type: ActionType.Transfer, amount: '1' }];
            const wasmActions = actions.map(toActionArgsWasm);

            const signed = await pm.near.signTransactionsWithActions({
              nearAccount: { accountId },
              transactions: [
                { receiverId, actions },
                { receiverId, actions },
              ],
              options: {
                confirmationConfig: confirmConfig as any,
              },
            });

            if (!Array.isArray(signed) || signed.length !== 2) {
              return {
                ok: false,
                error: `expected 2 signed txs, got ${Array.isArray(signed) ? signed.length : 'non-array'}`,
              };
            }

            const extractSigned = (item: any) => {
              const signedTx = item?.signedTransaction as any;
              const signatureData = signedTx?.signature?.signatureData;
              const tx = signedTx?.transaction;
              const borshBytes = signedTx?.borsh_bytes;
              if (!tx || !signatureData || !borshBytes) {
                throw new Error('invalid signed transaction shape');
              }
              return {
                signerId: String(tx.signerId || ''),
                receiverId: String(tx.receiverId || ''),
                nonce: typeof tx.nonce === 'bigint' ? tx.nonce.toString() : String(tx.nonce || ''),
                blockHash: Array.from(tx.blockHash || []) as number[],
                signature: Array.from(signatureData) as number[],
                borshBytes: (Array.isArray(borshBytes) ? borshBytes : []) as number[],
              };
            };

            return {
              ok: true,
              accountId,
              operationalPublicKey: String(reg.operationalPublicKey || ''),
              ecdsaTempoKeyRef,
              txInput: { receiverId, wasmActions },
              signedTxs: [extractSigned(signed[0]), extractSigned(signed[1])],
            };
          } catch (e: any) {
            return { ok: false, error: e?.message || String(e) };
          }
        },
        {
          relayerUrl: managedRegistrationHarness.baseUrl,
          managedRegistration: managedRegistrationHarness.managedRegistration,
        },
      )) as BatchSigningResult;

      if (!result.ok) {
        throw new Error(`batch signing test failed: ${result.error || 'unknown'}`);
      }

      expect(sendTxCount).toBe(0);
      expect(relayerCounts.keygen).toBe(0);
      expect(relayerCounts.session).toBe(0);
      expect(relayerCounts.authorize).toBeGreaterThanOrEqual(2);
      expect(relayerCounts.authorize).toBeLessThanOrEqual(4);
      expect(relayerCounts.init).toBe(2);
      expect(relayerCounts.finalize).toBe(2);
      expect(result.ecdsaTempoKeyRef.ecdsaThresholdKeyId).toBeTruthy();
      expect(result.ecdsaTempoKeyRef.relayerKeyId).toBeTruthy();
      expect(result.ecdsaTempoKeyRef.thresholdSessionId).toBeTruthy();
      expect(result.ecdsaTempoKeyRef.participantIds).toEqual([1, 2]);
      expect(result.ecdsaTempoKeyRef.ethereumAddress).toMatch(/^0x[0-9a-f]{40}$/);

      const operationalPkStr = String(result.operationalPublicKey);
      const toPkBytes = (pk: string): Uint8Array => {
        const raw = pk.includes(':') ? pk.split(':')[1] : pk;
        return bs58.decode(raw);
      };
      const wrongPublicKey = `ed25519:${bs58.encode(ed25519.getPublicKey(new Uint8Array(32).fill(43)))}`;

      const computeDigest = (signed: { nonce: string; blockHash: number[] }): Uint8Array => {
        const signingPayload = {
          kind: 'near_tx',
          txSigningRequests: [
            {
              nearAccountId: String(result.accountId),
              receiverId: String(result.txInput.receiverId),
              actions: result.txInput.wasmActions,
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

      for (const signed of result.signedTxs) {
        const digest = computeDigest(signed);
        const sigBytes = Uint8Array.from(signed.signature);
        expect(sigBytes.length).toBe(64);
        expect(ed25519.verify(sigBytes, digest, toPkBytes(operationalPkStr))).toBe(true);
        expect(ed25519.verify(sigBytes, digest, toPkBytes(wrongPublicKey))).toBe(false);
      }
    } finally {
      await managedRegistrationHarness.close().catch(() => undefined);
    }
  });
});
