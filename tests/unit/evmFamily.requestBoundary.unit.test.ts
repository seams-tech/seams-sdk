import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';
import { evmFamilySigningTargetFromExplicitTarget } from '@/core/signingEngine/flows/signEvmFamily/types';
import { readTrustedWalletSigningBudgetStatus } from '@/core/signingEngine/session/budget/budgetStatusReader';
import { thresholdEcdsaChainTargetFromChainFamily } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  createThresholdEcdsaStoreFixture,
  resetWarmSessionFixtureState,
} from './helpers/warmSessionStore.fixtures';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

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
        'client/src/core/signingEngine/flows/signEvmFamily/transactionExecutor.ts',
      ),
      'utf8',
    );
    expect(transactionExecutor).toContain(
      "args.chainTarget.kind === 'evm' || args.request.kind === 'eip1559'",
    );
    expect(transactionExecutor).toContain(
      "targetKind === 'tempo' ? loadSignTempoWithUiConfirm : loadSignEvmWithUiConfirm",
    );

    const signTempoWithUiConfirm = fs.readFileSync(
      path.join(
        repoRoot,
        'client/src/core/signingEngine/flows/signEvmFamily/signTempoWithUiConfirm.ts',
      ),
      'utf8',
    );
    expect(signTempoWithUiConfirm).toContain("args.request.kind === 'eip1559'");
    expect(signTempoWithUiConfirm).toContain('new EvmAdapter(workerCtx).buildIntent(request)');
    expect(signTempoWithUiConfirm).toContain("targetKind: 'tempo'");
  });

  test('refreshes step-up ECDSA lanes with the normalized signing target chain', () => {
    const signEvmFamily = fs.readFileSync(
      path.join(repoRoot, 'client/src/core/signingEngine/flows/signEvmFamily/signEvmFamily.ts'),
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
      signEvmFamily.indexOf("context: 'EVM-family signing keyRef refresh'"),
    );
    const keyRefRefreshCall = signEvmFamily.slice(keyRefRefreshStart, keyRefRefreshStart + 400);
    expect(keyRefRefreshCall).toContain('chain: requestChain');
    expect(keyRefRefreshCall).not.toContain('chain: args.request.chain');
  });
});

test.describe('Trusted wallet signing budget status', () => {
  test('accepts typed not_found status without an HTTP auth failure', async () => {
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
        {
          kind: 'authenticated_threshold_budget_status_check',
          nearAccountId: 'budget-not-found.testnet',
          walletSigningSessionId: 'wallet-session-missing',
          targetThresholdSessionIds: ['threshold-session-missing'],
          trustedStatusAuth: {
            relayerUrl: 'https://relay.example',
            thresholdSessionId: 'threshold-session-missing',
            thresholdSessionAuthToken: 'stale-jwt',
          },
        },
      );

      expect(status).toEqual({
        sessionId: 'wallet-session-missing',
        status: 'not_found',
        statusCode: 'unauthorized',
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
    globalThis.fetch = (async (_input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
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
        {
          kind: 'authenticated_threshold_budget_status_check',
          nearAccountId: 'budget-current.testnet',
          walletSigningSessionId: 'wallet-session-fresh',
          targetThresholdSessionIds: ['threshold-session-fresh'],
          trustedStatusAuth: {
            relayerUrl: 'https://relay.example',
            thresholdSessionId: 'threshold-session-fresh',
            thresholdSessionAuthToken: 'fresh-jwt',
          },
        },
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
        {
          kind: 'authenticated_threshold_budget_status_check',
          nearAccountId: 'budget-mismatch.testnet',
          walletSigningSessionId: 'wallet-session-fresh',
          targetThresholdSessionIds: ['threshold-session-fresh'],
          trustedStatusAuth: {
            relayerUrl: 'https://relay.example',
            thresholdSessionId: 'threshold-session-fresh',
            thresholdSessionAuthToken: 'fresh-jwt',
          },
        },
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
        {
          kind: 'authenticated_threshold_budget_status_check',
          nearAccountId: 'budget-threshold-mismatch.testnet',
          walletSigningSessionId: 'wallet-session-fresh',
          targetThresholdSessionIds: ['threshold-session-fresh'],
          trustedStatusAuth: {
            relayerUrl: 'https://relay.example',
            thresholdSessionId: 'threshold-session-fresh',
            thresholdSessionAuthToken: 'fresh-jwt',
          },
        },
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
        {
          kind: 'authenticated_threshold_budget_status_check',
          nearAccountId: 'budget-projection-missing.testnet',
          walletSigningSessionId: 'wallet-session-fresh',
          targetThresholdSessionIds: ['threshold-session-fresh'],
          trustedStatusAuth: {
            relayerUrl: 'https://relay.example',
            thresholdSessionId: 'threshold-session-fresh',
            thresholdSessionAuthToken: 'fresh-jwt',
          },
        },
      );

      expect(status).toBeNull();
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
