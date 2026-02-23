import { expect, test, type Page } from '@playwright/test';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { keccak256, parseTransaction, recoverTransactionAddress, serializeTransaction } from 'viem';
import { publicKeyToAddress } from 'viem/accounts';
import { corsHeadersForRoute } from '../e2e/thresholdEd25519.testUtils';
import {
  runThresholdEcdsaTempoFlow,
  setupThresholdEcdsaTempoHarness,
} from '../helpers/thresholdEcdsaTempoFlow';

type CounterKey = 'authorize' | 'presignInit' | 'presignStep' | 'signInit' | 'signFinalize';
type Counters = Record<CounterKey, number>;

const EIP1559_TEST_TX = {
  chainId: 11155111n,
  nonce: 7n,
  maxPriorityFeePerGas: 1_500_000_000n,
  maxFeePerGas: 3_000_000_000n,
  gasLimit: 21_000n,
  to: `0x${'22'.repeat(20)}` as const,
  value: 12_345n,
  data: '0x' as const,
  accessList: [],
};

function asBigInt(value: bigint | number | undefined, field: string): bigint {
  if (typeof value === 'bigint') return value;
  if (typeof value === 'number') return BigInt(value);
  throw new Error(`Expected ${field} to be bigint/number`);
}

function bytesToHex(input: Uint8Array): string {
  return Buffer.from(input).toString('hex');
}

function secpPointFromCompressedHex(compressed33: Uint8Array): any {
  const pointCtor = ((secp256k1 as any).ProjectivePoint || (secp256k1 as any).Point) as
    | { fromHex: (hex: string | Uint8Array) => any }
    | undefined;
  if (!pointCtor || typeof pointCtor.fromHex !== 'function') {
    throw new Error('secp256k1 point constructor is unavailable');
  }
  return pointCtor.fromHex(bytesToHex(compressed33));
}

async function observePostCalls(
  page: Page,
  url: string,
  counters: Counters,
  key: CounterKey,
): Promise<void> {
  await page.route(url, async (route) => {
    if (route.request().method().toUpperCase() === 'POST') {
      counters[key] += 1;
    }
    await route.fallback();
  });
}

async function signTempoWithExistingPasskey(
  page: Page,
  args: {
    relayerUrl: string;
    accountId: string;
    thresholdEcdsaPresignPool?: {
      enabled?: boolean;
      targetDepth?: number;
      lowWatermark?: number;
      maxRefillInFlight?: number;
      refillAttemptTimeoutMs?: number;
    };
  },
): Promise<{
  ok: boolean;
  keygen?: { participantIds?: number[]; relayerKeyId?: string; clientVerifyingShareB64u?: string };
  session?: { ok: boolean; sessionId?: string };
  signed?: { chain: 'tempo'; kind: 'tempoTransaction'; senderHashHex: string; rawTxHex: string };
  error?: string;
}> {
  return await page.evaluate(async (input) => {
    const sdkMod = await import('/sdk/esm/index.js');
    const { TatchiPasskey } = sdkMod as any;

    const confirmationConfig = {
      uiMode: 'none' as const,
      behavior: 'skipClick' as const,
      autoProceedDelay: 0,
    };

    const pm = new TatchiPasskey({
      nearNetwork: 'testnet',
      nearRpcUrl: 'https://test.rpc.fastnear.com',
      relayerAccount: 'web3-authn-v4.testnet',
      ...(input.thresholdEcdsaPresignPool
        ? { thresholdEcdsaPresignPool: input.thresholdEcdsaPresignPool }
        : {}),
      relayer: {
        url: input.relayerUrl,
        smartAccountDeploymentMode: 'observe',
      },
      iframeWallet: {
        walletOrigin: '',
        walletServicePath: '/wallet-service',
        sdkBasePath: '/sdk',
        rpIdOverride: 'example.localhost',
      },
    });

    try {
      const boot = await pm.tempo.bootstrapEcdsaSession({
        nearAccountId: input.accountId,
        options: { relayerUrl: input.relayerUrl },
      });
      const signed = await pm.tempo.signTempo({
        nearAccountId: input.accountId,
        request: {
          chain: 'tempo',
          kind: 'tempoTransaction',
          senderSignatureAlgorithm: 'secp256k1',
          tx: {
            chainId: 42431n,
            maxPriorityFeePerGas: 1n,
            maxFeePerGas: 2n,
            gasLimit: 21_000n,
            calls: [{ to: '0x' + '11'.repeat(20), value: 0n, input: '0x' }],
            accessList: [],
            nonceKey: 0n,
            nonce: 2n,
            validBefore: null,
            validAfter: null,
            feePayerSignature: { kind: 'none' as const },
            aaAuthorizationList: [],
          },
        },
        options: { confirmationConfig },
      });

      return {
        ok: true,
        keygen: boot.keygen,
        session: boot.session,
        signed,
      };
    } catch (e: unknown) {
      return {
        ok: false,
        error: String(
          (e && typeof e === 'object' && 'message' in e)
            ? (e as { message?: unknown }).message
            : e || 'signTempo failed',
        ),
      };
    }
  }, args);
}

test.describe('Threshold ECDSA Tempo high-level API', () => {
  test.setTimeout(180_000);

  test('secp256k1 happy path', async ({ page }) => {
    const harness = await setupThresholdEcdsaTempoHarness(page);
    const counters: Counters = {
      authorize: 0,
      presignInit: 0,
      presignStep: 0,
      signInit: 0,
      signFinalize: 0,
    };

    try {
      await observePostCalls(page, `${harness.baseUrl}/threshold-ecdsa/authorize`, counters, 'authorize');
      await observePostCalls(page, `${harness.baseUrl}/threshold-ecdsa/presign/init`, counters, 'presignInit');
      await observePostCalls(page, `${harness.baseUrl}/threshold-ecdsa/presign/step`, counters, 'presignStep');
      await observePostCalls(page, `${harness.baseUrl}/threshold-ecdsa/sign/init`, counters, 'signInit');
      await observePostCalls(page, `${harness.baseUrl}/threshold-ecdsa/sign/finalize`, counters, 'signFinalize');

      const result = await runThresholdEcdsaTempoFlow(page, {
        relayerUrl: harness.baseUrl,
      });

      expect(result.ok, result.error || JSON.stringify(result)).toBe(true);
      expect(result.keygen?.ok).toBe(true);
      expect(result.session?.ok).toBe(true);
      expect(result.session?.sessionId).toBeTruthy();
      expect(result.signed?.chain).toBe('tempo');
      expect(result.signed?.kind).toBe('tempoTransaction');
      expect(result.signed?.rawTxHex?.startsWith('0x')).toBeTruthy();
      expect(counters.authorize).toBeGreaterThanOrEqual(1);
      expect(counters.presignInit).toBeGreaterThanOrEqual(1);
      expect(counters.signInit).toBeGreaterThanOrEqual(1);
      expect(counters.signFinalize).toBeGreaterThanOrEqual(1);
    } finally {
      await harness.close();
    }
  });

  test('eip1559 raw tx is EVM-parseable and recovers threshold signer', async ({ page }) => {
    const harness = await setupThresholdEcdsaTempoHarness(page);

    try {
      const result = await runThresholdEcdsaTempoFlow(page, {
        relayerUrl: harness.baseUrl,
        signingKind: 'eip1559',
      });

      expect(result.ok, result.error || JSON.stringify(result)).toBe(true);
      expect(result.keygen?.ok).toBe(true);
      expect(result.session?.ok).toBe(true);
      expect(result.signed?.chain).toBe('evm');
      expect(result.signed?.kind).toBe('eip1559');

      if (!result.signed || result.signed.kind !== 'eip1559') {
        throw new Error('Expected eip1559 signed result');
      }

      const expectedSigningHashHex = keccak256(
        serializeTransaction({
          type: 'eip1559',
          chainId: Number(EIP1559_TEST_TX.chainId),
          nonce: Number(EIP1559_TEST_TX.nonce),
          maxPriorityFeePerGas: EIP1559_TEST_TX.maxPriorityFeePerGas,
          maxFeePerGas: EIP1559_TEST_TX.maxFeePerGas,
          gas: EIP1559_TEST_TX.gasLimit,
          to: EIP1559_TEST_TX.to,
          value: EIP1559_TEST_TX.value,
          data: EIP1559_TEST_TX.data,
          accessList: EIP1559_TEST_TX.accessList,
        }),
      );
      expect(result.signed.txHashHex).toBe(expectedSigningHashHex);
      expect(result.signed.rawTxHex.startsWith('0x02')).toBe(true);

      const parsedTx = parseTransaction(result.signed.rawTxHex as `0x${string}`);
      expect(parsedTx.type).toBe('eip1559');
      expect(asBigInt(parsedTx.chainId, 'chainId')).toBe(EIP1559_TEST_TX.chainId);
      expect(asBigInt(parsedTx.nonce, 'nonce')).toBe(EIP1559_TEST_TX.nonce);
      expect(asBigInt(parsedTx.maxPriorityFeePerGas, 'maxPriorityFeePerGas')).toBe(EIP1559_TEST_TX.maxPriorityFeePerGas);
      expect(asBigInt(parsedTx.maxFeePerGas, 'maxFeePerGas')).toBe(EIP1559_TEST_TX.maxFeePerGas);
      expect(asBigInt(parsedTx.gas, 'gas')).toBe(EIP1559_TEST_TX.gasLimit);
      expect((parsedTx.to || '').toLowerCase()).toBe(EIP1559_TEST_TX.to.toLowerCase());
      expect(parsedTx.value).toBe(EIP1559_TEST_TX.value);
      expect((parsedTx.data || '0x').toLowerCase()).toBe(EIP1559_TEST_TX.data);
      expect(parsedTx.accessList || []).toEqual([]);

      const recoveredAddress = await recoverTransactionAddress({
        serializedTransaction: result.signed.rawTxHex as `0x02${string}`,
      });
      const groupPublicKeyCompressed = Buffer.from(String(result.keygen?.groupPublicKeyB64u || ''), 'base64url');
      expect(groupPublicKeyCompressed.length).toBe(33);

      const groupPoint = secpPointFromCompressedHex(groupPublicKeyCompressed);
      const groupPublicKeyUncompressedHex = `0x${groupPoint.toHex(false)}` as `0x${string}`;
      const expectedSignerAddress = publicKeyToAddress(groupPublicKeyUncompressedHex);
      expect(recoveredAddress.toLowerCase()).toBe(expectedSignerAddress.toLowerCase());
    } finally {
      await harness.close();
    }
  });

  test('fails when threshold session is missing/expired', async ({ page }) => {
    const harness = await setupThresholdEcdsaTempoHarness(page);
    try {
      const result = await runThresholdEcdsaTempoFlow(page, {
        relayerUrl: harness.baseUrl,
        connectSession: false,
      });

      expect(result.ok).toBe(false);
      const msg = String(result.error || '');
      expect(msg).toMatch(
        /missing canonical threshold ECDSA session|Missing threshold signingSessionId|threshold-ecdsa session token unavailable|threshold session expired|PRF\.first not cached for threshold session/i,
      );
    } finally {
      await harness.close();
    }
  });

  test('handles pool_empty by refilling presign and retrying sign/init', async ({ page }) => {
    const harness = await setupThresholdEcdsaTempoHarness(page);
    const counters: Counters = {
      authorize: 0,
      presignInit: 0,
      presignStep: 0,
      signInit: 0,
      signFinalize: 0,
    };
    let forcedPoolEmpty = false;

    try {
      await observePostCalls(page, `${harness.baseUrl}/threshold-ecdsa/authorize`, counters, 'authorize');
      await observePostCalls(page, `${harness.baseUrl}/threshold-ecdsa/presign/init`, counters, 'presignInit');
      await observePostCalls(page, `${harness.baseUrl}/threshold-ecdsa/presign/step`, counters, 'presignStep');
      await observePostCalls(page, `${harness.baseUrl}/threshold-ecdsa/sign/finalize`, counters, 'signFinalize');

      await page.route(`${harness.baseUrl}/threshold-ecdsa/sign/init`, async (route) => {
        if (route.request().method().toUpperCase() === 'POST') {
          counters.signInit += 1;
          if (!forcedPoolEmpty) {
            forcedPoolEmpty = true;
            await route.fulfill({
              status: 200,
              headers: {
                'Content-Type': 'application/json',
                ...corsHeadersForRoute(route),
              },
              body: JSON.stringify({
                ok: false,
                code: 'pool_empty',
                message: 'forced pool-empty for retry path',
              }),
            });
            return;
          }
        }
        await route.fallback();
      });

      const result = await runThresholdEcdsaTempoFlow(page, {
        relayerUrl: harness.baseUrl,
      });

      expect(forcedPoolEmpty).toBe(true);
      expect(counters.signInit).toBeGreaterThanOrEqual(2);
      expect(counters.presignInit).toBeGreaterThanOrEqual(2);
      if (!result.ok) {
        expect(String(result.error || '')).toMatch(/bigR mismatch|mpcSessionId expired or invalid/i);
      } else {
        expect(counters.signFinalize).toBeGreaterThanOrEqual(1);
      }
    } finally {
      await harness.close();
    }
  });

  test('repeated same-account signs complete after warm-up even when presign/init is blocked', async ({ page }) => {
    const harness = await setupThresholdEcdsaTempoHarness(page);
    const counters: Counters = {
      authorize: 0,
      presignInit: 0,
      presignStep: 0,
      signInit: 0,
      signFinalize: 0,
    };
    let blockPresignInit = false;
    let blockedPresignInitCalls = 0;

    try {
      await observePostCalls(page, `${harness.baseUrl}/threshold-ecdsa/authorize`, counters, 'authorize');
      await observePostCalls(page, `${harness.baseUrl}/threshold-ecdsa/presign/step`, counters, 'presignStep');
      await observePostCalls(page, `${harness.baseUrl}/threshold-ecdsa/sign/init`, counters, 'signInit');
      await observePostCalls(page, `${harness.baseUrl}/threshold-ecdsa/sign/finalize`, counters, 'signFinalize');

      await page.route(`${harness.baseUrl}/threshold-ecdsa/presign/init`, async (route) => {
        if (route.request().method().toUpperCase() === 'POST') {
          counters.presignInit += 1;
          if (blockPresignInit) {
            blockedPresignInitCalls += 1;
            await new Promise((resolve) => setTimeout(resolve, 5_000));
            await route.fulfill({
              status: 500,
              headers: {
                'Content-Type': 'application/json',
                ...corsHeadersForRoute(route),
              },
              body: JSON.stringify({
                ok: false,
                code: 'forced_presign_init_blocked',
                message: 'forced blocked presign/init',
              }),
            });
            return;
          }
        }
        await route.fallback();
      });

      const first = await runThresholdEcdsaTempoFlow(page, {
        relayerUrl: harness.baseUrl,
        thresholdEcdsaPresignPool: {
          enabled: true,
          targetDepth: 4,
          lowWatermark: 0,
          maxRefillInFlight: 2,
          refillAttemptTimeoutMs: 45_000,
        },
      });
      expect(first.ok, first.error || JSON.stringify(first)).toBe(true);
      expect(first.keygen?.ok).toBe(true);

      for (let i = 0; i < 240 && counters.presignInit < 4; i += 1) {
        await page.waitForTimeout(50);
      }
      expect(counters.presignInit).toBeGreaterThanOrEqual(4);
      await page.waitForTimeout(200);

      blockPresignInit = true;
      const startedAt = Date.now();
      const second = await signTempoWithExistingPasskey(page, {
        relayerUrl: harness.baseUrl,
        accountId: first.accountId,
        thresholdEcdsaPresignPool: {
          enabled: true,
          targetDepth: 4,
          lowWatermark: 0,
          maxRefillInFlight: 2,
          refillAttemptTimeoutMs: 45_000,
        },
      });
      const elapsedMs = Date.now() - startedAt;

      expect(second.ok, second.error || JSON.stringify(second)).toBe(true);
      expect(second.signed?.chain).toBe('tempo');
      expect(second.signed?.kind).toBe('tempoTransaction');
      expect(counters.signInit).toBeGreaterThanOrEqual(2);
      expect(counters.signFinalize).toBeGreaterThanOrEqual(2);
      expect(elapsedMs).toBeLessThan(5_000);

      for (let i = 0; i < 80 && blockedPresignInitCalls < 1; i += 1) {
        await page.waitForTimeout(50);
      }
      expect(blockedPresignInitCalls).toBeGreaterThanOrEqual(1);
    } finally {
      await harness.close();
    }
  });

});
