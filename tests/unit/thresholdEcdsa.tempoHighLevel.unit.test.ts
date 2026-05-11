import { expect, test, type Page } from '@playwright/test';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { keccak256, parseTransaction, recoverTransactionAddress, serializeTransaction } from 'viem';
import { publicKeyToAddress } from 'viem/accounts';
import { thresholdEcdsaChainTargetFromChainFamily } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { corsHeadersForRoute } from '../e2e/thresholdEd25519.testUtils';
import {
  runThresholdEcdsaTempoFlow,
  setupThresholdEcdsaTempoHarness,
} from '../helpers/thresholdEcdsaTempoFlow';

type CounterKey = 'authorize' | 'presignInit' | 'presignStep' | 'signInit' | 'signFinalize';
type Counters = Record<CounterKey, number>;

const EIP1559_TEST_TX = {
  chainId: 11155111n,
  maxPriorityFeePerGas: 1_500_000_000n,
  maxFeePerGas: 3_000_000_000n,
  gasLimit: 21_000n,
  to: `0x${'22'.repeat(20)}` as const,
  value: 12_345n,
  data: '0x' as const,
  accessList: [],
};

const TEMPO_CHAIN_TARGET = thresholdEcdsaChainTargetFromChainFamily({
  chain: 'tempo',
  chainId: 42431,
});
const EVM_CHAIN_TARGET = thresholdEcdsaChainTargetFromChainFamily({
  chain: 'evm',
  chainId: 11155111,
});

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
    chainTarget: {
      kind: 'tempo';
      chainId: number;
      networkSlug: string;
    };
  },
): Promise<{
  ok: boolean;
  keygen?: {
    ecdsaThresholdKeyId?: string;
    participantIds?: number[];
    thresholdEcdsaPublicKeyB64u?: string;
    ethereumAddress?: string;
  };
  session?: { ok: boolean; sessionId?: string };
  signed?: { chain: 'tempo'; kind: 'tempoTransaction'; senderHashHex: string; rawTxHex: string };
  error?: string;
}> {
  return await page.evaluate(async (input) => {
    const sdkMod = await import('/sdk/esm/index.js');
    const { SeamsPasskey } = sdkMod as any;

    const confirmationConfig = {
      uiMode: 'none' as const,
      behavior: 'skipClick' as const,
      autoProceedDelay: 0,
    };

    const existingPm = (globalThis as any).__w3aTempoHighLevelPm;
    const pm = existingPm || new SeamsPasskey({
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
    if (!existingPm) (globalThis as any).__w3aTempoHighLevelPm = pm;

    try {
      const boot = await pm.tempo.bootstrapEcdsaSession({
        kind: 'reuse_warm_ecdsa_bootstrap',
        nearAccountId: input.accountId,
        chainTarget: input.chainTarget,
        relayerUrl: input.relayerUrl,
      });
      const signed = await pm.tempo.signTempo({
        nearAccountId: input.accountId,
        subjectId: input.accountId,
        request: {
          chain: 'tempo',
          kind: 'tempoTransaction',
          senderSignatureAlgorithm: 'secp256k1',
          tx: {
            chainId: 42431,
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
        chainTarget: input.chainTarget,
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
          e && typeof e === 'object' && 'message' in e
            ? (e as { message?: unknown }).message
            : e || 'signTempo failed',
        ),
      };
    }
  }, args);
}

async function bootstrapEvmSessionWithExistingPasskey(
  page: Page,
  args: {
    relayerUrl: string;
    accountId: string;
    chainTarget: {
      kind: 'evm';
      namespace: 'eip155';
      chainId: number;
      networkSlug: string;
    };
  },
): Promise<{
  ok: boolean;
  sessionId?: string;
  error?: string;
}> {
  return await page.evaluate(async (input) => {
    const sdkMod = await import('/sdk/esm/index.js');
    const { SeamsPasskey } = sdkMod as any;

    const existingPm = (globalThis as any).__w3aTempoHighLevelPm;
    const pm = existingPm || new SeamsPasskey({
      nearNetwork: 'testnet',
      nearRpcUrl: 'https://test.rpc.fastnear.com',
      relayerAccount: 'web3-authn-v4.testnet',
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
    if (!existingPm) (globalThis as any).__w3aTempoHighLevelPm = pm;

    try {
      const boot = await (globalThis as any).__w3aBootstrapFreshTempoEcdsaSession({
        pm,
        accountId: input.accountId,
        relayerUrl: input.relayerUrl,
        ttlMs: 120_000,
        remainingUses: 4,
        chainTarget: input.chainTarget,
      });
      return {
        ok: true,
        sessionId: String(boot?.session?.sessionId || ''),
      };
    } catch (e: unknown) {
      return {
        ok: false,
        error: String(
          e && typeof e === 'object' && 'message' in e
            ? (e as { message?: unknown }).message
            : e || 'bootstrapEcdsaSession(evm) failed',
        ),
      };
    }
  }, args);
}

type ConcurrentSignMode = 'tempo-tempo' | 'tempo-evm';

async function runConcurrentThresholdSignsWithExistingPasskey(
  page: Page,
  args: {
    relayerUrl: string;
    accountId: string;
    mode: ConcurrentSignMode;
  },
): Promise<{
  first: { ok: boolean; chain?: string; kind?: string; error?: string };
  second: { ok: boolean; chain?: string; kind?: string; error?: string };
}> {
  return await page.evaluate(async (input) => {
    const sdkMod = await import('/sdk/esm/index.js');
    const { SeamsPasskey } = sdkMod as any;

    const confirmationConfig = {
      uiMode: 'none' as const,
      behavior: 'skipClick' as const,
      autoProceedDelay: 0,
    };

    const existingPm = (globalThis as any).__w3aTempoHighLevelPm;
    const pm = existingPm || new SeamsPasskey({
      nearNetwork: 'testnet',
      nearRpcUrl: 'https://test.rpc.fastnear.com',
      relayerAccount: 'web3-authn-v4.testnet',
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
    if (!existingPm) (globalThis as any).__w3aTempoHighLevelPm = pm;

    const tempoRequest = {
      chain: 'tempo' as const,
      kind: 'tempoTransaction' as const,
      senderSignatureAlgorithm: 'secp256k1' as const,
      tx: {
        chainId: 42431,
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
    };

    const evmRequest = {
      chain: 'evm' as const,
      kind: 'eip1559' as const,
      senderSignatureAlgorithm: 'secp256k1' as const,
      tx: {
        chainId: 11155111,
        maxPriorityFeePerGas: 1_500_000_000n,
        maxFeePerGas: 3_000_000_000n,
        gasLimit: 21_000n,
        to: '0x' + '22'.repeat(20),
        value: 12_345n,
        data: '0x',
        accessList: [],
      },
    };

    const toResult = (settled: PromiseSettledResult<any>) => {
      if (settled.status === 'fulfilled') {
        return {
          ok: true,
          chain: String(settled.value?.chain || ''),
          kind: String(settled.value?.kind || ''),
        };
      }
      const reason = settled.reason;
      return {
        ok: false,
        error: String(
          reason && typeof reason === 'object' && 'message' in reason
            ? (reason as { message?: unknown }).message
            : reason || 'signTempo failed',
        ),
      };
    };

    if (!existingPm) {
      const login = await pm.unlock(input.accountId, {
        session: {
          kind: 'jwt',
          relayUrl: input.relayerUrl,
          exchange: { type: 'passkey_assertion' },
        },
        signingSession: { ttlMs: 120_000, remainingUses: 4 },
      });
      if (!login?.success) {
        return {
          first: { ok: false, error: String(login?.error || 'unlock failed') },
          second: { ok: false, error: String(login?.error || 'unlock failed') },
        };
      }
    }

    const firstPromise = pm.tempo.signTempo({
      nearAccountId: input.accountId,
      subjectId: input.accountId,
      request: tempoRequest,
      chainTarget: {
        kind: 'tempo',
        chainId: 42431,
        networkSlug: 'tempo-moderato',
      },
      options: { confirmationConfig },
    });
    const secondPromise =
      input.mode === 'tempo-tempo'
        ? pm.tempo.signTempo({
            nearAccountId: input.accountId,
            subjectId: input.accountId,
            request: tempoRequest,
            chainTarget: {
              kind: 'tempo',
              chainId: 42431,
              networkSlug: 'tempo-moderato',
            },
            options: { confirmationConfig },
          })
        : pm.tempo.signTempo({
            nearAccountId: input.accountId,
            subjectId: input.accountId,
            request: evmRequest,
            chainTarget: {
              kind: 'evm',
              namespace: 'eip155',
              chainId: 11155111,
              networkSlug: 'ethereum-sepolia',
            },
            options: { confirmationConfig },
          });

    const [first, second] = await Promise.allSettled([firstPromise, secondPromise]);
    return {
      first: toResult(first),
      second: toResult(second),
    };
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
      await observePostCalls(
        page,
        `${harness.baseUrl}/threshold-ecdsa/authorize`,
        counters,
        'authorize',
      );
      await observePostCalls(
        page,
        `${harness.baseUrl}/threshold-ecdsa/presign/init`,
        counters,
        'presignInit',
      );
      await observePostCalls(
        page,
        `${harness.baseUrl}/threshold-ecdsa/presign/step`,
        counters,
        'presignStep',
      );
      await observePostCalls(
        page,
        `${harness.baseUrl}/threshold-ecdsa/sign/init`,
        counters,
        'signInit',
      );
      await observePostCalls(
        page,
        `${harness.baseUrl}/threshold-ecdsa/sign/finalize`,
        counters,
        'signFinalize',
      );

      const result = await runThresholdEcdsaTempoFlow(page, {
        relayerUrl: harness.baseUrl,
      });

      expect(result.ok, result.error || JSON.stringify(result)).toBe(true);
      expect(result.keygen?.ok).toBe(true);
      expect(String(result.keygen?.ecdsaThresholdKeyId || '')).toBeTruthy();
      expect(String(result.keygen?.thresholdEcdsaPublicKeyB64u || '')).toBeTruthy();
      expect(String(result.keygen?.ethereumAddress || '')).toBeTruthy();
      expect(result.session?.kind).toBe('connected');
      if (!result.session || result.session.kind !== 'connected') {
        throw new Error('Expected connected ECDSA session');
      }
      expect(result.session.sessionId).toBeTruthy();
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
      expect(String(result.keygen?.ecdsaThresholdKeyId || '')).toBeTruthy();
      expect(String(result.keygen?.thresholdEcdsaPublicKeyB64u || '')).toBeTruthy();
      expect(String(result.keygen?.ethereumAddress || '')).toBeTruthy();
      expect(result.session?.kind).toBe('connected');
      expect(result.signed?.chain).toBe('evm');
      expect(result.signed?.kind).toBe('eip1559');

      if (!result.signed || result.signed.kind !== 'eip1559') {
        throw new Error('Expected eip1559 signed result');
      }

      const parsedTx = parseTransaction(result.signed.rawTxHex as `0x${string}`);
      expect(parsedTx.type).toBe('eip1559');
      expect(asBigInt(parsedTx.chainId, 'chainId')).toBe(EIP1559_TEST_TX.chainId);
      expect(asBigInt(parsedTx.nonce, 'nonce')).toBeGreaterThanOrEqual(0n);
      expect(asBigInt(parsedTx.maxPriorityFeePerGas, 'maxPriorityFeePerGas')).toBe(
        EIP1559_TEST_TX.maxPriorityFeePerGas,
      );
      expect(asBigInt(parsedTx.maxFeePerGas, 'maxFeePerGas')).toBe(EIP1559_TEST_TX.maxFeePerGas);
      expect(asBigInt(parsedTx.gas, 'gas')).toBe(EIP1559_TEST_TX.gasLimit);
      expect((parsedTx.to || '').toLowerCase()).toBe(EIP1559_TEST_TX.to.toLowerCase());
      expect(parsedTx.value).toBe(EIP1559_TEST_TX.value);
      expect((parsedTx.data || '0x').toLowerCase()).toBe(EIP1559_TEST_TX.data);
      expect(parsedTx.accessList || []).toEqual([]);
      const expectedSigningHashHex = keccak256(
        serializeTransaction({
          type: 'eip1559',
          chainId: Number(asBigInt(parsedTx.chainId, 'chainId')),
          nonce: Number(asBigInt(parsedTx.nonce, 'nonce')),
          maxPriorityFeePerGas: asBigInt(parsedTx.maxPriorityFeePerGas, 'maxPriorityFeePerGas'),
          maxFeePerGas: asBigInt(parsedTx.maxFeePerGas, 'maxFeePerGas'),
          gas: asBigInt(parsedTx.gas, 'gas'),
          to: parsedTx.to as `0x${string}`,
          value: parsedTx.value,
          data: (parsedTx.data || '0x') as `0x${string}`,
          accessList: parsedTx.accessList || [],
        }),
      );
      expect(result.signed.txHashHex).toBe(expectedSigningHashHex);
      expect(result.signed.rawTxHex.startsWith('0x02')).toBe(true);

      const recoveredAddress = await recoverTransactionAddress({
        serializedTransaction: result.signed.rawTxHex as `0x02${string}`,
      });
      const groupPublicKeyCompressed = Buffer.from(
        String(result.keygen?.thresholdEcdsaPublicKeyB64u || ''),
        'base64url',
      );
      expect(groupPublicKeyCompressed.length).toBe(33);

      const groupPoint = secpPointFromCompressedHex(groupPublicKeyCompressed);
      const groupPublicKeyUncompressedHex = `0x${groupPoint.toHex(false)}` as `0x${string}`;
      const expectedSignerAddress = publicKeyToAddress(groupPublicKeyUncompressedHex);
      expect(recoveredAddress.toLowerCase()).toBe(expectedSignerAddress.toLowerCase());
    } finally {
      await harness.close();
    }
  });

  test('reconnects when threshold session is missing/expired', async ({ page }) => {
    const harness = await setupThresholdEcdsaTempoHarness(page);
    try {
      const result = await runThresholdEcdsaTempoFlow(page, {
        relayerUrl: harness.baseUrl,
        connectSession: false,
      });

      expect(result.ok, result.error || JSON.stringify(result)).toBe(true);
      expect(result.signed?.chain).toBe('tempo');
      expect(result.signed?.kind).toBe('tempoTransaction');
      expect(result.signed?.rawTxHex?.startsWith('0x')).toBeTruthy();
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
      await observePostCalls(
        page,
        `${harness.baseUrl}/threshold-ecdsa/authorize`,
        counters,
        'authorize',
      );
      await observePostCalls(
        page,
        `${harness.baseUrl}/threshold-ecdsa/presign/init`,
        counters,
        'presignInit',
      );
      await observePostCalls(
        page,
        `${harness.baseUrl}/threshold-ecdsa/presign/step`,
        counters,
        'presignStep',
      );
      await observePostCalls(
        page,
        `${harness.baseUrl}/threshold-ecdsa/sign/finalize`,
        counters,
        'signFinalize',
      );

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
        expect(String(result.error || '')).toMatch(
          /bigR mismatch|mpcSessionId expired or invalid/i,
        );
      } else {
        expect(counters.signFinalize).toBeGreaterThanOrEqual(1);
      }
    } finally {
      await harness.close();
    }
  });

  test('repeated same-account signs complete after warm-up even when presign/init is blocked', async ({
    page,
  }) => {
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
      await observePostCalls(
        page,
        `${harness.baseUrl}/threshold-ecdsa/authorize`,
        counters,
        'authorize',
      );
      await observePostCalls(
        page,
        `${harness.baseUrl}/threshold-ecdsa/presign/step`,
        counters,
        'presignStep',
      );
      await observePostCalls(
        page,
        `${harness.baseUrl}/threshold-ecdsa/sign/init`,
        counters,
        'signInit',
      );
      await observePostCalls(
        page,
        `${harness.baseUrl}/threshold-ecdsa/sign/finalize`,
        counters,
        'signFinalize',
      );

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
        chainTarget: {
          kind: 'tempo',
          chainId: 42431,
          networkSlug: 'tempo-moderato',
        },
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

  test('same-lane concurrent tempo commits stay serialized at authorize', async ({ page }) => {
    const harness = await setupThresholdEcdsaTempoHarness(page);
    let authorizePostCount = 0;
    let releaseFirstAuthorize: (() => void) | null = null;

    try {
      const first = await runThresholdEcdsaTempoFlow(page, {
        relayerUrl: harness.baseUrl,
      });
      expect(first.ok, first.error || JSON.stringify(first)).toBe(true);

      await page.route(`${harness.baseUrl}/threshold-ecdsa/authorize`, async (route) => {
        if (route.request().method().toUpperCase() !== 'POST') {
          await route.fallback();
          return;
        }
        authorizePostCount += 1;
        if (authorizePostCount === 1) {
          await new Promise<void>((resolve) => {
            releaseFirstAuthorize = () => resolve();
          });
        }
        await route.fallback();
      });

      const pending = runConcurrentThresholdSignsWithExistingPasskey(page, {
        relayerUrl: harness.baseUrl,
        accountId: first.accountId,
        mode: 'tempo-tempo',
      });

      for (let i = 0; i < 60 && authorizePostCount < 1; i += 1) {
        await page.waitForTimeout(50);
      }
      expect(authorizePostCount).toBe(1);
      await page.waitForTimeout(400);
      expect(authorizePostCount).toBe(1);

      const releaseFirstAuthorizeFn = releaseFirstAuthorize as (() => void) | null;
      releaseFirstAuthorizeFn?.();
      const result = await pending;
      expect(authorizePostCount).toBeGreaterThanOrEqual(2);
      expect(result.first.ok || result.second.ok).toBe(true);
    } finally {
      await harness.close();
    }
  });

  test('cross-lane tempo+evm commits can both reach sign/init before first lane releases', async ({
    page,
  }) => {
    const harness = await setupThresholdEcdsaTempoHarness(page);
    let signInitPostCount = 0;
    let releaseFirstSignInit: (() => void) | null = null;

    try {
      const first = await runThresholdEcdsaTempoFlow(page, {
        relayerUrl: harness.baseUrl,
      });
      expect(first.ok, first.error || JSON.stringify(first)).toBe(true);

      const evmBoot = await bootstrapEvmSessionWithExistingPasskey(page, {
        relayerUrl: harness.baseUrl,
        accountId: first.accountId,
        chainTarget: {
          kind: 'evm',
          namespace: 'eip155',
          chainId: 11155111,
          networkSlug: 'ethereum-sepolia',
        },
      });
      expect(evmBoot.ok, evmBoot.error || JSON.stringify(evmBoot)).toBe(true);

      await page.route(`${harness.baseUrl}/threshold-ecdsa/sign/init`, async (route) => {
        if (route.request().method().toUpperCase() !== 'POST') {
          await route.fallback();
          return;
        }
        signInitPostCount += 1;
        if (signInitPostCount === 1) {
          await new Promise<void>((resolve) => {
            releaseFirstSignInit = () => resolve();
          });
        }
        await route.fallback();
      });

      const pending = runConcurrentThresholdSignsWithExistingPasskey(page, {
        relayerUrl: harness.baseUrl,
        accountId: first.accountId,
        mode: 'tempo-evm',
      });

      for (let i = 0; i < 120 && signInitPostCount < 2; i += 1) {
        await page.waitForTimeout(50);
      }
      expect(signInitPostCount).toBeGreaterThanOrEqual(2);

      const releaseFirstSignInitFn = releaseFirstSignInit as (() => void) | null;
      releaseFirstSignInitFn?.();
      const result = await pending;
      expect(result.first.ok || result.second.ok).toBe(true);
    } finally {
      await harness.close();
    }
  });
});
