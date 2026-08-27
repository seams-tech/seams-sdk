import { expect, test } from '@playwright/test';
import { createD1ConsoleWalletService } from '../../packages/wallet-console-server-ts/src/wallets/d1';
import { cleanupTemporaryD1Database, createTemporaryD1Database } from '../helpers/sqliteD1';

const ORG_ID = 'org_balance_test';
const PROJECT_ID = 'project_balance_test';
const CONSOLE_ENVIRONMENT_ID = 'env_balance_test:dev';
const SIGNER_ENVIRONMENT_ID = 'local';
const WALLET_ID = 'wallet-balance-test';
const NEAR_ACCOUNT_ID = 'a'.repeat(64);
const EVM_ADDRESS = `0x${'b'.repeat(40)}`;

class MutableClock {
  constructor(private currentMs: number) {}

  now(): Date {
    return new Date(this.currentMs);
  }

  advance(ms: number): void {
    this.currentMs += ms;
  }
}

class WalletRpcFetchStub {
  calls = 0;
  private failTempo = false;

  rejectTempoRequests(): void {
    this.failTempo = true;
  }

  async fetch(_input: string | URL | Request, init?: RequestInit): Promise<Response> {
    this.calls += 1;
    const body = String(init?.body || '');
    if (body.includes('"method":"query"')) {
      return Response.json({
        jsonrpc: '2.0',
        id: 1,
        error: {
          code: -32000,
          message: 'Server error',
          cause: { name: 'UNKNOWN_ACCOUNT' },
          data: `account ${NEAR_ACCOUNT_ID} does not exist while viewing`,
        },
      });
    }
    if (body.includes('"method":"eth_call"')) {
      if (this.failTempo) return new Response('unavailable', { status: 503 });
      return Response.json({ jsonrpc: '2.0', id: 1, result: '0x12d450' });
    }
    if (body.includes('"method":"eth_getBalance"')) {
      return Response.json({ jsonrpc: '2.0', id: 1, result: '0x1bc16d674ec80000' });
    }
    return new Response('unexpected method', { status: 400 });
  }
}

test('wallet balance snapshots bridge signer environments, cache reads, and preserve stale values', async () => {
  const consoleState = createTemporaryD1Database();
  const signerState = createTemporaryD1Database();
  try {
    await signerState.database.exec(`
      CREATE TABLE wallet_signers (
        namespace TEXT NOT NULL,
        org_id TEXT NOT NULL,
        project_id TEXT NOT NULL,
        env_id TEXT NOT NULL,
        wallet_id TEXT NOT NULL,
        signer_family TEXT NOT NULL,
        record_json TEXT NOT NULL
      );
    `);
    await signerState.database
      .prepare(
        `INSERT INTO wallet_signers
          (namespace, org_id, project_id, env_id, wallet_id, signer_family, record_json)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
      )
      .bind(
        'seams-test',
        ORG_ID,
        PROJECT_ID,
        SIGNER_ENVIRONMENT_ID,
        WALLET_ID,
        'ed25519',
        JSON.stringify({ nearAccountId: NEAR_ACCOUNT_ID }),
      )
      .run();
    await signerState.database
      .prepare(
        `INSERT INTO wallet_signers
          (namespace, org_id, project_id, env_id, wallet_id, signer_family, record_json)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
      )
      .bind(
        'seams-test',
        ORG_ID,
        PROJECT_ID,
        SIGNER_ENVIRONMENT_ID,
        WALLET_ID,
        'ecdsa',
        JSON.stringify({ walletKey: { thresholdOwnerAddress: EVM_ADDRESS } }),
      )
      .run();

    const clock = new MutableClock(Date.UTC(2026, 7, 27, 0, 0, 0));
    const rpc = new WalletRpcFetchStub();
    const service = await createD1ConsoleWalletService({
      database: consoleState.database,
      namespace: 'seams-test',
      ensureSchema: true,
      now: clock.now.bind(clock),
      balanceReader: {
        signerDatabase: signerState.database,
        fetchImpl: rpc.fetch.bind(rpc),
      },
    });
    if (!service.upsertWallet || !service.refreshBalances) {
      throw new Error('D1 wallet service is missing required balance operations');
    }
    const context = {
      orgId: ORG_ID,
      actorUserId: 'balance-test',
      projectId: PROJECT_ID,
      environmentId: CONSOLE_ENVIRONMENT_ID,
    };
    await service.upsertWallet(context, {
      id: WALLET_ID,
      projectId: PROJECT_ID,
      environmentId: CONSOLE_ENVIRONMENT_ID,
      userId: WALLET_ID,
      externalRefId: WALLET_ID,
      address: WALLET_ID,
      chain: 'Multichain',
    });

    const refreshed = await service.refreshBalances(context, { walletIds: [WALLET_ID] });
    expect(refreshed.failures).toEqual([]);
    expect(refreshed.refreshedWalletIds).toEqual([WALLET_ID]);
    expect(refreshed.wallets[0]?.balanceMinor).toBe(323);
    expect(refreshed.wallets[0]?.funded).toBe(true);
    expect(refreshed.wallets[0]?.chain).toBe('Multichain');
    expect(refreshed.wallets[0]?.gasBalances).toEqual({
      observedAt: '2026-08-27T00:00:00.000Z',
      near: { accountId: NEAR_ACCOUNT_ID, balanceYocto: '0' },
      tempo: { address: EVM_ADDRESS, alphaUsdRaw: '1234000' },
      arc: { address: EVM_ADDRESS, usdcRaw: '2000000000000000000' },
    });

    const callsAfterRefresh = rpc.calls;
    const cached = await service.refreshBalances(context, { walletIds: [WALLET_ID] });
    expect(cached.freshWalletIds).toEqual([WALLET_ID]);
    expect(rpc.calls).toBe(callsAfterRefresh);

    clock.advance(5 * 60 * 1_000 + 1);
    rpc.rejectTempoRequests();
    const failed = await service.refreshBalances(context, { walletIds: [WALLET_ID] });
    expect(failed.failures).toEqual([
      { walletId: WALLET_ID, message: 'eth_call returned HTTP 503' },
    ]);
    expect((await service.getWallet(context, WALLET_ID))?.balanceMinor).toBe(323);
  } finally {
    cleanupTemporaryD1Database(consoleState.tempDir);
    cleanupTemporaryD1Database(signerState.tempDir);
  }
});
