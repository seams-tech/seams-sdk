import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';
import { evmFamilySigningTargetFromExplicitTarget } from '@/core/signingEngine/flows/signEvmFamily/types';
import {
  buildEcdsaLaneBudgetStatusCheck,
  type AuthenticatedEcdsaLaneBudgetStatusCheck,
} from '@/core/signingEngine/session/budget/budget';
import { readTrustedWalletSigningBudgetStatus } from '@/core/signingEngine/session/budget/budgetStatusReader';
import { thresholdEcdsaChainTargetFromChainFamily } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  buildBaseEvmFamilyEcdsaKeyIdentity,
  buildEvmFamilyEcdsaKeyIdentity,
  toEvmFamilyEcdsaKeyHandle,
} from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import {
  createThresholdEcdsaBootstrapFixture,
  createThresholdEcdsaStoreFixture,
  resetWarmSessionFixtureState,
  seedEcdsaWarmSessionRecord,
  testEcdsaChainTarget,
} from './helpers/warmSessionStore.fixtures';
import { thresholdEcdsaSessionRecordReadModel } from '@/core/signingEngine/session/persistence/records';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const budgetChainTarget = thresholdEcdsaChainTargetFromChainFamily({
  chain: 'tempo',
  chainId: 42431,
  networkSlug: 'tempo-moderato',
});

function authenticatedEcdsaBudgetCheck(args: {
  walletId: string;
  walletSigningSessionId: string;
  thresholdSessionId: string;
  walletSessionJwt: string;
}): AuthenticatedEcdsaLaneBudgetStatusCheck {
  const key = buildBaseEvmFamilyEcdsaKeyIdentity({
    walletId: args.walletId,
    rpId: 'localhost',
    ecdsaThresholdKeyId: 'ecdsa-budget-key',
    signingRootId: 'project:dev',
    signingRootVersion: 'default',
    participantIds: [1, 2],
    thresholdOwnerAddress: `0x${'22'.repeat(20)}`,
  });
  return {
    kind: 'authenticated_ecdsa_lane_budget_status_check',
    key,
    keyHandle: toEvmFamilyEcdsaKeyHandle('ecdsa-budget-key-handle'),
    chainTarget: budgetChainTarget,
    walletSigningSessionId: args.walletSigningSessionId,
    thresholdSessionId: args.thresholdSessionId,
    trustedStatusAuth: {
      relayerUrl: 'https://relay.example',
      thresholdSessionId: args.thresholdSessionId,
      walletSessionJwt: args.walletSessionJwt,
    },
  };
}

test.describe('EVM-family request boundaries', () => {
  test('allows EIP-1559 transaction encoding against a Tempo signing target', () => {
    const chainTarget = thresholdEcdsaChainTargetFromChainFamily({
      chain: 'tempo',
      chainId: 42431,
      networkSlug: 'tempo-testnet',
    });
    const request = {
      chain: 'evm',
      kind: 'eip1559',
      senderSignatureAlgorithm: 'secp256k1',
      tx: {
        chainId: 42431,
        maxPriorityFeePerGas: 1n,
        maxFeePerGas: 2n,
        gasLimit: 21_000n,
        to: `0x${'11'.repeat(20)}`,
        value: 0n,
        data: '0x',
        accessList: [],
      },
    } as any;

    expect(evmFamilySigningTargetFromExplicitTarget({ request, chainTarget })).toEqual(chainTarget);
  });

  test('derives Tempo family from concrete request kind when request.chain drifts', () => {
    const chainTarget = thresholdEcdsaChainTargetFromChainFamily({
      chain: 'tempo',
      chainId: 42431,
      networkSlug: 'tempo-testnet',
    });
    const request = {
      chain: 'evm',
      kind: 'tempoTransaction',
      senderSignatureAlgorithm: 'secp256k1',
      tx: {
        chainId: 42431,
        maxPriorityFeePerGas: 1n,
        maxFeePerGas: 2n,
        gasLimit: 21_000n,
        nonceKey: 1n,
        calls: [{ to: `0x${'11'.repeat(20)}`, value: 0n }],
      },
    } as any;

    expect(evmFamilySigningTargetFromExplicitTarget({ request, chainTarget })).toEqual(chainTarget);
  });

  test('routes Tempo EIP-1559 requests through the Tempo flow with the EVM encoder', () => {
    const transactionExecutor = fs.readFileSync(
      path.join(
        repoRoot,
        'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/transactionExecutor.ts',
      ),
      'utf8',
    );
    expect(transactionExecutor).toContain(
      "args.chainTarget.kind === 'evm' || args.request.kind === 'eip1559'",
    );
    expect(transactionExecutor).toContain(
      "targetKind === 'tempo' ? loadSignEvmFamilyWithUiConfirmForTempo : loadSignEvmWithUiConfirm",
    );
    expect(transactionExecutor).toContain('requireRawEip1559ThresholdOwnerNonceSenderIdentity');
    expect(transactionExecutor).toContain('thresholdOwnerNonceSenderIdentity');
    expect(transactionExecutor).toContain(
      'raw EIP-1559 signing requires prepared threshold ECDSA owner address',
    );

    const signEvmFamilyWithUiConfirmForTempo = fs.readFileSync(
      path.join(
        repoRoot,
        'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/signEvmFamilyWithUiConfirmForTempo.ts',
      ),
      'utf8',
    );
    expect(signEvmFamilyWithUiConfirmForTempo).toContain("args.request.kind === 'eip1559'");
    expect(signEvmFamilyWithUiConfirmForTempo).toContain(
      'new EvmAdapter(workerCtx).buildIntent(request)',
    );
    expect(signEvmFamilyWithUiConfirmForTempo).toContain("targetKind: 'tempo'");
  });

  test('refreshes step-up ECDSA lanes with the normalized signing target chain', () => {
    const signEvmFamily = fs.readFileSync(
      path.join(repoRoot, 'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/signEvmFamily.ts'),
      'utf8',
    );

    const emailOtpRefreshCall = signEvmFamily.slice(
      signEvmFamily.indexOf('completeEvmFamilyEmailOtpSigningRefresh({'),
      signEvmFamily.indexOf('completeEvmFamilyEmailOtpSigningRefresh({') + 400,
    );
    expect(emailOtpRefreshCall).toContain('chain: requestChain');
    expect(emailOtpRefreshCall).not.toContain('chain: args.request.chain');

    const keyRefRefreshStart = signEvmFamily.lastIndexOf(
      'updateResolvedEvmFamilyEcdsaSigningLaneIdentity({',
      signEvmFamily.indexOf("context: 'EVM-family signing record refresh'"),
    );
    const keyRefRefreshCall = signEvmFamily.slice(keyRefRefreshStart, keyRefRefreshStart + 400);
    expect(keyRefRefreshCall).toContain('chain: requestChain');
    expect(keyRefRefreshCall).not.toContain('chain: args.request.chain');
  });
});

test.describe('Trusted wallet signing budget status', () => {
  test('resolves ECDSA budget auth from the exact chain target when session ids are shared', async () => {
    const ecdsaSessions = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaSessions);
    const walletId = 'budget-shared-target.testnet';
    const thresholdSessionId = 'threshold-session-shared-target';
    const walletSigningSessionId = 'wallet-session-shared-target';
    const ecdsaThresholdKeyId = 'ecdsa-budget-key';
    const keyHandle = 'ecdsa-budget-key-handle';
    const tempoRecord = seedEcdsaWarmSessionRecord(ecdsaSessions, {
      nearAccountId: walletId,
      chain: 'tempo',
      source: 'email_otp',
      bootstrap: createThresholdEcdsaBootstrapFixture({
        nearAccountId: walletId,
        chain: 'tempo',
        sessionId: thresholdSessionId,
        walletSigningSessionId,
        ecdsaThresholdKeyId,
        keyHandle,
        walletSessionJwt: 'tempo-target-token',
      }),
    });
    const evmTarget = testEcdsaChainTarget('evm');
    const evmRecord = seedEcdsaWarmSessionRecord(ecdsaSessions, {
      nearAccountId: walletId,
      chain: 'evm',
      source: 'email_otp',
      bootstrap: createThresholdEcdsaBootstrapFixture({
        nearAccountId: walletId,
        chain: 'evm',
        sessionId: thresholdSessionId,
        walletSigningSessionId,
        ecdsaThresholdKeyId,
        keyHandle,
        walletSessionJwt: 'evm-target-token',
      }),
    });
    if (!tempoRecord || !evmRecord) throw new Error('failed to seed shared-target ECDSA records');
    expect(evmRecord.walletSessionJwt).not.toBe(tempoRecord.walletSessionJwt);

    const originalFetch = globalThis.fetch;
    const authorizations: string[] = [];
    globalThis.fetch = (async (
      _input: RequestInfo | URL,
      init?: RequestInit,
    ): Promise<Response> => {
      const authorization = String(new Headers(init?.headers).get('Authorization') || '');
      authorizations.push(authorization);
      return new Response(
        JSON.stringify({
          ok: true,
          walletSigningSessionId,
          thresholdSessionId,
          status: 'active',
          remainingUses: 2,
          expiresAtMs: 1_777_777_777_000,
          projectionVersion: 'projection-v1',
        }),
        {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        },
      );
    }) as typeof fetch;

    try {
      const status = await readTrustedWalletSigningBudgetStatus(
        { ecdsaSessions },
        buildEcdsaLaneBudgetStatusCheck({
          key: thresholdEcdsaSessionRecordReadModel(evmRecord).key,
          keyHandle: evmRecord.keyHandle,
          chainTarget: evmTarget,
          walletSigningSessionId,
          thresholdSessionId,
        }),
      );

      expect(status).toMatchObject({
        sessionId: walletSigningSessionId,
        status: 'active',
        remainingUses: 2,
      });
      expect(authorizations).toEqual([`Bearer ${evmRecord.walletSessionJwt}`]);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('does not fetch trusted budget status with cookie-only ECDSA records', async () => {
    const ecdsaSessions = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaSessions);
    const walletId = 'budget-cookie-only.testnet';
    const thresholdSessionId = 'threshold-session-cookie-only';
    const walletSigningSessionId = 'wallet-session-cookie-only';
    const record = seedEcdsaWarmSessionRecord(ecdsaSessions, {
      nearAccountId: walletId,
      chain: 'evm',
      source: 'login',
      bootstrap: createThresholdEcdsaBootstrapFixture({
        nearAccountId: walletId,
        chain: 'evm',
        sessionId: thresholdSessionId,
        walletSigningSessionId,
        sessionKind: 'cookie',
      }),
    });
    if (!record) throw new Error('failed to seed cookie-only ECDSA record');

    const originalFetch = globalThis.fetch;
    let fetchCount = 0;
    globalThis.fetch = (async (): Promise<Response> => {
      fetchCount += 1;
      return new Response(JSON.stringify({ ok: false, code: 'unexpected_cookie_fallback' }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' },
      });
    }) as typeof fetch;

    try {
      const status = await readTrustedWalletSigningBudgetStatus(
        { ecdsaSessions },
        buildEcdsaLaneBudgetStatusCheck({
          key: thresholdEcdsaSessionRecordReadModel(record).key,
          keyHandle: record.keyHandle,
          chainTarget: testEcdsaChainTarget('evm'),
          walletSigningSessionId,
          thresholdSessionId,
        }),
      );

      expect(status).toBeNull();
      expect(fetchCount).toBe(0);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('treats auth-rejected not_found status as budget_unknown', async () => {
    const ecdsaSessions = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaSessions);
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (): Promise<Response> =>
      new Response(
        JSON.stringify({
          ok: true,
          walletSigningSessionId: 'wallet-session-missing',
          thresholdSessionId: 'threshold-session-missing',
          status: 'not_found',
          statusCode: 'unauthorized',
        }),
        {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        },
      )) as typeof fetch;

    try {
      const status = await readTrustedWalletSigningBudgetStatus(
        { ecdsaSessions },
        authenticatedEcdsaBudgetCheck({
          walletId: 'budget-not-found.testnet',
          walletSigningSessionId: 'wallet-session-missing',
          thresholdSessionId: 'threshold-session-missing',
          walletSessionJwt: 'stale-jwt',
        }),
      );

      expect(status).toEqual({
        sessionId: 'wallet-session-missing',
        status: 'budget_unknown',
        statusCode: 'status_unavailable',
      });
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('accepts trusted active budget status only with exact session identities', async () => {
    const ecdsaSessions = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaSessions);
    const originalFetch = globalThis.fetch;
    const calls: Array<{ authorization: string; thresholdSessionId: string }> = [];
    globalThis.fetch = (async (
      _input: RequestInfo | URL,
      init?: RequestInit,
    ): Promise<Response> => {
      const headers = new Headers(init?.headers);
      const authorization = String(headers.get('Authorization') || '');
      const payload = JSON.parse(String(init?.body || '{}')) as {
        thresholdSessionId?: string;
      };
      calls.push({
        authorization,
        thresholdSessionId: String(payload.thresholdSessionId || ''),
      });
      if (authorization === 'Bearer fresh-jwt') {
        return new Response(
          JSON.stringify({
            ok: true,
            walletSigningSessionId: 'wallet-session-fresh',
            thresholdSessionId: 'threshold-session-fresh',
            status: 'active',
            remainingUses: 3,
            expiresAtMs: 1_777_777_777_000,
            projectionVersion: 'projection-v1',
          }),
          {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          },
        );
      }
      return new Response(JSON.stringify({ ok: false, code: 'unexpected_auth' }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' },
      });
    }) as typeof fetch;

    try {
      const status = await readTrustedWalletSigningBudgetStatus(
        { ecdsaSessions },
        authenticatedEcdsaBudgetCheck({
          walletId: 'budget-current.testnet',
          walletSigningSessionId: 'wallet-session-fresh',
          thresholdSessionId: 'threshold-session-fresh',
          walletSessionJwt: 'fresh-jwt',
        }),
      );

      expect(status).toMatchObject({
        sessionId: 'wallet-session-fresh',
        status: 'active',
        remainingUses: 3,
        projectionVersion: 'projection-v1',
      });
      expect(calls).toEqual([
        {
          authorization: 'Bearer fresh-jwt',
          thresholdSessionId: 'threshold-session-fresh',
        },
      ]);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('coalesces identical concurrent trusted budget status reads', async () => {
    const ecdsaSessions = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaSessions);
    const originalFetch = globalThis.fetch;
    let callCount = 0;
    let resolveFetch: () => void = () => undefined;
    const fetchGate = new Promise<void>((resolve) => {
      resolveFetch = resolve;
    });
    globalThis.fetch = (async (): Promise<Response> => {
      callCount += 1;
      await fetchGate;
      return new Response(
        JSON.stringify({
          ok: true,
          walletSigningSessionId: 'wallet-session-coalesced',
          thresholdSessionId: 'threshold-session-coalesced',
          status: 'active',
          remainingUses: 3,
          expiresAtMs: 1_777_777_777_000,
          projectionVersion: 'projection-v1',
        }),
        {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        },
      );
    }) as typeof fetch;

    const args = authenticatedEcdsaBudgetCheck({
      walletId: 'budget-coalesced.testnet',
      walletSigningSessionId: 'wallet-session-coalesced',
      thresholdSessionId: 'threshold-session-coalesced',
      walletSessionJwt: 'fresh-jwt',
    });

    try {
      const first = readTrustedWalletSigningBudgetStatus({ ecdsaSessions }, args);
      const second = readTrustedWalletSigningBudgetStatus({ ecdsaSessions }, args);

      expect(callCount).toBe(1);
      resolveFetch();

      const [firstStatus, secondStatus] = await Promise.all([first, second]);
      expect(firstStatus).toMatchObject({
        sessionId: 'wallet-session-coalesced',
        status: 'active',
        projectionVersion: 'projection-v1',
      });
      expect(secondStatus).toEqual(firstStatus);
    } finally {
      resolveFetch();
      globalThis.fetch = originalFetch;
    }
  });

  test('does not reuse completed trusted budget status reads', async () => {
    const ecdsaSessions = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaSessions);
    const originalFetch = globalThis.fetch;
    let callCount = 0;
    globalThis.fetch = (async (): Promise<Response> => {
      callCount += 1;
      return new Response(
        JSON.stringify({
          ok: true,
          walletSigningSessionId: 'wallet-session-fresh-read',
          thresholdSessionId: 'threshold-session-fresh-read',
          status: 'active',
          remainingUses: 3,
          expiresAtMs: 1_777_777_777_000,
          projectionVersion: `projection-v${callCount}`,
        }),
        {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        },
      );
    }) as typeof fetch;

    const args = authenticatedEcdsaBudgetCheck({
      walletId: 'budget-fresh-read.testnet',
      walletSigningSessionId: 'wallet-session-fresh-read',
      thresholdSessionId: 'threshold-session-fresh-read',
      walletSessionJwt: 'fresh-jwt',
    });

    try {
      const first = await readTrustedWalletSigningBudgetStatus({ ecdsaSessions }, args);
      const second = await readTrustedWalletSigningBudgetStatus({ ecdsaSessions }, args);

      expect(callCount).toBe(2);
      expect(first?.projectionVersion).toBe('projection-v1');
      expect(second?.projectionVersion).toBe('projection-v2');
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('rejects trusted budget status when response wallet session identity drifts', async () => {
    const ecdsaSessions = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaSessions);
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (): Promise<Response> =>
      new Response(
        JSON.stringify({
          ok: true,
          walletSigningSessionId: 'wallet-session-other',
          thresholdSessionId: 'threshold-session-fresh',
          status: 'active',
          remainingUses: 3,
          expiresAtMs: 1_777_777_777_000,
          projectionVersion: 'projection-v1',
        }),
        {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        },
      )) as typeof fetch;

    try {
      const status = await readTrustedWalletSigningBudgetStatus(
        { ecdsaSessions },
        authenticatedEcdsaBudgetCheck({
          walletId: 'budget-mismatch.testnet',
          walletSigningSessionId: 'wallet-session-fresh',
          thresholdSessionId: 'threshold-session-fresh',
          walletSessionJwt: 'fresh-jwt',
        }),
      );

      expect(status).toBeNull();
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('rejects trusted budget status when response threshold session identity drifts', async () => {
    const ecdsaSessions = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaSessions);
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (): Promise<Response> =>
      new Response(
        JSON.stringify({
          ok: true,
          walletSigningSessionId: 'wallet-session-fresh',
          thresholdSessionId: 'threshold-session-other',
          status: 'active',
          remainingUses: 3,
          expiresAtMs: 1_777_777_777_000,
          projectionVersion: 'projection-v1',
        }),
        {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        },
      )) as typeof fetch;

    try {
      const status = await readTrustedWalletSigningBudgetStatus(
        { ecdsaSessions },
        authenticatedEcdsaBudgetCheck({
          walletId: 'budget-threshold-mismatch.testnet',
          walletSigningSessionId: 'wallet-session-fresh',
          thresholdSessionId: 'threshold-session-fresh',
          walletSessionJwt: 'fresh-jwt',
        }),
      );

      expect(status).toBeNull();
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('rejects trusted active budget status without projection metadata', async () => {
    const ecdsaSessions = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaSessions);
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (): Promise<Response> =>
      new Response(
        JSON.stringify({
          ok: true,
          walletSigningSessionId: 'wallet-session-fresh',
          thresholdSessionId: 'threshold-session-fresh',
          status: 'active',
          remainingUses: 3,
          expiresAtMs: 1_777_777_777_000,
        }),
        {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        },
      )) as typeof fetch;

    try {
      const status = await readTrustedWalletSigningBudgetStatus(
        { ecdsaSessions },
        authenticatedEcdsaBudgetCheck({
          walletId: 'budget-projection-missing.testnet',
          walletSigningSessionId: 'wallet-session-fresh',
          thresholdSessionId: 'threshold-session-fresh',
          walletSessionJwt: 'fresh-jwt',
        }),
      );

      expect(status).toBeNull();
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
