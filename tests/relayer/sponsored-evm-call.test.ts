import type { IncomingMessage, ServerResponse } from 'node:http';
import http from 'node:http';
import expressImport from 'express';
import { expect, test } from '@playwright/test';
import {
  createInMemoryConsoleApiKeyService,
  createInMemoryConsoleRuntimeSnapshotService,
  type ConsoleApiKeyService,
} from '@server/router/express-adaptor';
import { createInMemoryConsoleSponsoredCallService } from '@server';
import {
  fetchJson,
  startExpressRouter,
} from './helpers';
import { registerSponsoredEvmCallRoute } from '@server';

type ExpressMiddleware = (req: unknown, res: unknown, next: (err?: unknown) => void) => unknown;
type ExpressAppLike = ((req: unknown, res: unknown) => unknown) & {
  use: (...args: unknown[]) => unknown;
};
type ExpressLike = { (): ExpressAppLike; json: (options?: unknown) => ExpressMiddleware };

const express: ExpressLike = (() => {
  const maybeDefault = (expressImport as unknown as { default?: unknown }).default;
  if (typeof maybeDefault === 'function') return maybeDefault as ExpressLike;
  return expressImport as unknown as ExpressLike;
})();

const apiKeyCtx = {
  orgId: 'org-tempo-sponsor',
  actorUserId: 'user-tempo-sponsor-admin',
  roles: ['admin'],
};
const environmentId = 'env-tempo-sponsor-prod';
const allowedOrigin = 'https://app.example.com';
const blockedOrigin = 'https://blocked.example.com';
const walletAddress = '0x1111111111111111111111111111111111111111' as const;
const tokenAddress = '0x20c0000000000000000000000000000000000001' as const;
const sponsorAddress = '0x2222222222222222222222222222222222222222' as const;
const sponsorPrivateKeyHex =
  '0x1111111111111111111111111111111111111111111111111111111111111111' as const;
const contractAddress = '0xbb85080E6953f25197ec68798360667140EbAf4b' as const;
const selector = '0x428dc451' as const;
const txHash = '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' as const;
const gasUsedHex = '0x5208';
const gasUsedDec = '21000';
const effectiveGasPriceHex = '0x77359400';
const effectiveGasPriceDec = '2000000000';
const spendWeiDec = '42000000000000';

type BillingUsageEventSpy = {
  walletId: string;
  action: string;
  succeeded: boolean;
  sourceEventId?: string;
};

function encodeTempoDripInput(tokenAddresses: readonly `0x${string}`[]): `0x${string}` {
  const encodedAddresses = tokenAddresses
    .map((address) => address.slice(2).toLowerCase().padStart(64, '0'))
    .join('');
  const offsetHex = (32).toString(16).padStart(64, '0');
  const lengthHex = tokenAddresses.length.toString(16).padStart(64, '0');
  return `0x${selector.slice(2)}${offsetHex}${lengthHex}${encodedAddresses}` as `0x${string}`;
}

function makeBillingSpy() {
  const events: BillingUsageEventSpy[] = [];
  return {
    events,
    service: {
      async recordUsageEvent(
        _ctx: unknown,
        request: {
          walletId: string;
          action: string;
          succeeded: boolean;
          sourceEventId?: string;
        },
      ) {
        events.push({
          walletId: request.walletId,
          action: request.action,
          succeeded: request.succeeded,
          ...(request.sourceEventId ? { sourceEventId: request.sourceEventId } : {}),
        });
        return {
          accepted: true,
          counted: true,
          monthUtc: '2026-03',
          monthlyActiveWallets: 1,
        };
      },
    },
  };
}

async function createPublishableKey(
  apiKeys: ConsoleApiKeyService,
  input?: { allowedOrigins?: string[] },
): Promise<{ apiKeyId: string; secret: string }> {
  const created = await apiKeys.createApiKey(apiKeyCtx, {
    kind: 'publishable_key',
    name: 'tempo-web',
    environmentId,
    allowedOrigins: input?.allowedOrigins || [allowedOrigin],
    rateLimitBucket: 'default_web_v1',
    quotaBucket: 'free_registrations_v1',
  });
  return {
    apiKeyId: created.apiKey.id,
    secret: created.secret,
  };
}

function makeSourceEventId(id: string): string {
  return `sponsored-evm-call-test:${id}`;
}

function parseRecordDetails(value: string | undefined) {
  return JSON.parse(String(value || '{}')) as {
    nearAccountId?: string;
    walletAddress?: string;
    chainId?: number;
    call?: {
      to?: string;
      data?: string;
      valueWei?: string;
      selector?: string;
    };
    execution?: {
      txHash?: string | null;
      gasUsed?: string | null;
      effectiveGasPrice?: string | null;
      feeAmount?: string;
    };
  };
}

async function readJsonBody(req: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  const text = Buffer.concat(chunks).toString('utf8');
  const parsed = text ? JSON.parse(text) : {};
  return parsed && typeof parsed === 'object' && !Array.isArray(parsed)
    ? (parsed as Record<string, unknown>)
    : {};
}

async function startFakeTempoRpc(input: {
  receiptStatus: '0x1' | '0x0';
  txHash?: `0x${string}`;
  gasUsedHex?: string;
  effectiveGasPriceHex?: string;
}) {
  const requests: string[] = [];
  const resolvedTxHash = input.txHash || txHash;
  const resolvedGasUsedHex = input.gasUsedHex || gasUsedHex;
  const resolvedEffectiveGasPriceHex = input.effectiveGasPriceHex || effectiveGasPriceHex;

  const respond = (
    res: ServerResponse,
    payload: { id: unknown; result?: unknown; error?: Record<string, unknown> },
  ) => {
    res.statusCode = 200;
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({ jsonrpc: '2.0', ...payload }));
  };

  const server = http.createServer(async (req, res) => {
    if (req.method !== 'POST') {
      res.statusCode = 405;
      res.end();
      return;
    }
    const body = await readJsonBody(req);
    const method = String(body.method || '').trim();
    requests.push(method);
    switch (method) {
      case 'eth_getTransactionCount':
        respond(res, { id: body.id, result: '0x0' });
        return;
      case 'eth_getBlockByNumber':
        respond(res, {
          id: body.id,
          result: {
            number: '0x10',
            baseFeePerGas: effectiveGasPriceHex,
          },
        });
        return;
      case 'eth_maxPriorityFeePerGas':
        respond(res, { id: body.id, result: effectiveGasPriceHex });
        return;
      case 'eth_gasPrice':
        respond(res, { id: body.id, result: effectiveGasPriceHex });
        return;
      case 'eth_sendRawTransaction':
        respond(res, { id: body.id, result: resolvedTxHash });
        return;
      case 'eth_getTransactionReceipt':
        respond(res, {
          id: body.id,
          result: {
            blockNumber: '0x10',
            status: input.receiptStatus,
            gasUsed: resolvedGasUsedHex,
            effectiveGasPrice: resolvedEffectiveGasPriceHex,
          },
        });
        return;
      default:
        respond(res, {
          id: body.id,
          error: { code: -32601, message: `Unsupported RPC method: ${method}` },
        });
    }
  });

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (!address || typeof address === 'string') {
    throw new Error('Failed to bind fake Tempo RPC server');
  }

  return {
    url: `http://127.0.0.1:${address.port}`,
    requests,
    close: async () =>
      await new Promise<void>((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
      }),
  };
}

function makeRouteConfig(rpcUrl: string) {
  return {
    enabled: true,
    rpcUrl,
    chainId: 42_431,
    sponsorAddress,
    sponsorPrivateKeyHex,
    maxPriorityFeePerGasFloor: 2_000_000_000n,
    maxFeePerGasFloor: 40_000_000_000n,
  };
}

function makeLogger() {
  return {
    info() {},
    warn() {},
    error() {},
  };
}

async function publishAllowedPolicy(runtimeSnapshots: ReturnType<typeof createInMemoryConsoleRuntimeSnapshotService>) {
  await runtimeSnapshots.publishSnapshot(apiKeyCtx, {
    environmentId,
    payload: {
      policy: {},
      metadata: {},
      smartWallets: {},
      gasSponsorship: {
        status: 'resolved',
        configCount: 1,
        configs: [],
        sponsoredCallPolicies: [
          {
            policyId: 'gs_onboarding',
            policyName: 'Tempo Testnet Onboarding',
            templateId: 'tempo_testnet_onboarding',
            networkClass: 'TESTNET',
            allowedChainIds: [42_431],
            callMode: 'ALLOWLIST',
            allowedCalls: [
              {
                chainId: 42_431,
                to: contractAddress,
                selector,
              },
            ],
          },
        ],
      },
    },
  });
}

async function startSponsoredCallRouteServer(input: {
  apiKeys: ConsoleApiKeyService;
  billing: unknown;
  ledger: ReturnType<typeof createInMemoryConsoleSponsoredCallService>;
  runtimeSnapshots: ReturnType<typeof createInMemoryConsoleRuntimeSnapshotService>;
  corsOrigins?: string[];
  config: ReturnType<typeof makeRouteConfig>;
}) {
  const app = express();
  app.use(express.json({ limit: '1mb' }));
  registerSponsoredEvmCallRoute({
    router: app as unknown as any,
    apiKeys: input.apiKeys as any,
    billing: input.billing as any,
    ledger: input.ledger as any,
    runtimeSnapshots: input.runtimeSnapshots as any,
    corsOrigins: input.corsOrigins || [allowedOrigin],
    config: input.config,
    logger: makeLogger(),
  });
  return await startExpressRouter(app);
}

test.describe('sponsored evm call route', () => {
  test('in-memory ledger deduplicates by sourceEventId per org', async () => {
    const service = createInMemoryConsoleSponsoredCallService();
    const first = await service.createRecord(
      {
        orgId: 'org-a',
        actorUserId: 'system',
        roles: ['system'],
      },
      {
        environmentId,
        apiKeyId: 'pk_live_1',
        apiKeyKind: 'publishable_key',
        route: 'sponsored_evm_call_v1',
        policyId: 'gs_onboarding',
        chainFamily: 'evm',
        intentKind: 'evm_call',
        accountRef: 'near:alice.testnet',
        targetRef: `evm:42431:${contractAddress.toLowerCase()}`,
        sponsorRef: `evm:42431:${sponsorAddress.toLowerCase()}`,
        txOrExecutionRef: txHash,
        receiptStatus: 'success',
        feeUnit: 'wei',
        feeAmount: spendWeiDec,
        detailsJson: JSON.stringify({
          nearAccountId: 'alice.testnet',
          walletAddress,
          chainId: 42_431,
          call: {
            to: contractAddress,
            data: encodeTempoDripInput([tokenAddress]),
            valueWei: '0',
            selector,
          },
          execution: {
            txHash,
            gasUsed: gasUsedDec,
            effectiveGasPrice: effectiveGasPriceDec,
            feeAmount: spendWeiDec,
          },
        }),
        sourceEventId: 'source-1',
      },
    );
    const second = await service.createRecord(
      {
        orgId: 'org-a',
        actorUserId: 'system',
        roles: ['system'],
      },
      {
        environmentId,
        apiKeyId: 'pk_live_2',
        apiKeyKind: 'publishable_key',
        route: 'sponsored_evm_call_v1',
        policyId: 'gs_other',
        chainFamily: 'evm',
        intentKind: 'evm_call',
        accountRef: 'near:bob.testnet',
        targetRef: `evm:42431:${contractAddress.toLowerCase()}`,
        sponsorRef: `evm:42431:${sponsorAddress.toLowerCase()}`,
        receiptStatus: 'rpc_rejected',
        feeUnit: 'wei',
        feeAmount: '0',
        detailsJson: '{}',
        sourceEventId: 'source-1',
      },
    );
    expect(second.id).toBe(first.id);
    expect(second.apiKeyId).toBe('pk_live_1');
    expect(second.policyId).toBe('gs_onboarding');
  });

  test('executes a sponsored call and records exact spend', async () => {
    const apiKeys = createInMemoryConsoleApiKeyService();
    const ledger = createInMemoryConsoleSponsoredCallService();
    const runtimeSnapshots = createInMemoryConsoleRuntimeSnapshotService();
    await publishAllowedPolicy(runtimeSnapshots);
    const billing = makeBillingSpy();
    const key = await createPublishableKey(apiKeys);
    const rpc = await startFakeTempoRpc({ receiptStatus: '0x1' });
    const server = await startSponsoredCallRouteServer({
      apiKeys,
      billing: billing.service,
      ledger,
      runtimeSnapshots,
      config: makeRouteConfig(rpc.url),
    });
    const sourceEventId = makeSourceEventId('success');
    const callData = encodeTempoDripInput([tokenAddress]);
    try {
      const response = await fetchJson(`${server.baseUrl}/sponsorships/evm/call`, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${key.secret}`,
          origin: allowedOrigin,
          'x-tatchi-environment-id': environmentId,
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          environmentId,
          nearAccountId: 'alice.testnet',
          walletAddress,
          chainId: 42_431,
          call: {
            to: contractAddress,
            data: callData,
            gasLimit: '300000',
            value: '0',
          },
          sourceEventId,
        }),
      });
      const body = response.json || {};
      expect(response.status).toBe(200);
      expect(body.ok).toBe(true);
      expect(body.txHash).toBe(txHash);
      expect(body.policyId).toBe('gs_onboarding');
      expect(body.gasUsed).toBe(gasUsedDec);
      expect(body.effectiveGasPrice).toBe(effectiveGasPriceDec);
      expect(body.spendWei).toBe(spendWeiDec);

      const record = await ledger.getRecordBySourceEventId(apiKeyCtx, sourceEventId);
      const details = parseRecordDetails(record?.detailsJson);
      expect(record?.policyId).toBe('gs_onboarding');
      expect(record?.chainFamily).toBe('evm');
      expect(record?.intentKind).toBe('evm_call');
      expect(record?.accountRef).toBe('near:alice.testnet');
      expect(record?.targetRef).toBe(`evm:42431:${contractAddress.toLowerCase()}`);
      expect(record?.sponsorRef).toBe(`evm:42431:${sponsorAddress.toLowerCase()}`);
      expect(record?.receiptStatus).toBe('success');
      expect(record?.txOrExecutionRef).toBe(txHash);
      expect(record?.feeUnit).toBe('wei');
      expect(record?.feeAmount).toBe(spendWeiDec);
      expect(details.call?.to).toBe(contractAddress);
      expect(details.call?.selector).toBe(selector);
      expect(details.call?.data).toBe(callData);
      expect(details.call?.valueWei).toBe('0');
      expect(details.execution?.gasUsed).toBe(gasUsedDec);
      expect(details.execution?.effectiveGasPrice).toBe(effectiveGasPriceDec);

      expect(billing.events).toEqual([
        expect.objectContaining({
          walletId: 'alice.testnet',
          action: 'contract_call',
          succeeded: true,
        }),
      ]);
    } finally {
      await server.close();
      await rpc.close();
    }
  });

  test('replays idempotently for the same sourceEventId', async () => {
    const apiKeys = createInMemoryConsoleApiKeyService();
    const ledger = createInMemoryConsoleSponsoredCallService();
    const runtimeSnapshots = createInMemoryConsoleRuntimeSnapshotService();
    await publishAllowedPolicy(runtimeSnapshots);
    const billing = makeBillingSpy();
    const key = await createPublishableKey(apiKeys);
    const rpc = await startFakeTempoRpc({ receiptStatus: '0x1' });
    const server = await startSponsoredCallRouteServer({
      apiKeys,
      billing: billing.service,
      ledger,
      runtimeSnapshots,
      config: makeRouteConfig(rpc.url),
    });
    const sourceEventId = makeSourceEventId('replay');
    const requestBody = {
      environmentId,
      nearAccountId: 'alice.testnet',
      walletAddress,
      chainId: 42_431,
      call: {
        to: contractAddress,
        data: encodeTempoDripInput([tokenAddress]),
        gasLimit: '300000',
        value: '0',
      },
      sourceEventId,
    };
    try {
      const first = await fetchJson(`${server.baseUrl}/sponsorships/evm/call`, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${key.secret}`,
          origin: allowedOrigin,
          'x-tatchi-environment-id': environmentId,
          'content-type': 'application/json',
        },
        body: JSON.stringify(requestBody),
      });
      const second = await fetchJson(`${server.baseUrl}/sponsorships/evm/call`, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${key.secret}`,
          origin: allowedOrigin,
          'x-tatchi-environment-id': environmentId,
          'content-type': 'application/json',
        },
        body: JSON.stringify(requestBody),
      });
      const replayed = second.json || {};
      expect(first.status).toBe(200);
      expect(second.status).toBe(200);
      expect(replayed.replayed).toBe(true);
      expect(replayed.txHash).toBe(txHash);
    } finally {
      await server.close();
      await rpc.close();
    }
  });

  test('rejects invalid publishable key and blocked origin', async () => {
    const apiKeys = createInMemoryConsoleApiKeyService();
    const ledger = createInMemoryConsoleSponsoredCallService();
    const runtimeSnapshots = createInMemoryConsoleRuntimeSnapshotService();
    await publishAllowedPolicy(runtimeSnapshots);
    const billing = makeBillingSpy();
    const key = await createPublishableKey(apiKeys);
    const rpc = await startFakeTempoRpc({ receiptStatus: '0x1' });
    const server = await startSponsoredCallRouteServer({
      apiKeys,
      billing: billing.service,
      ledger,
      runtimeSnapshots,
      config: makeRouteConfig(rpc.url),
    });
    const requestBody = {
      environmentId,
      nearAccountId: 'alice.testnet',
      walletAddress,
      chainId: 42_431,
      call: {
        to: contractAddress,
        data: encodeTempoDripInput([tokenAddress]),
        gasLimit: '300000',
        value: '0',
      },
    };
    try {
      const invalid = await fetchJson(`${server.baseUrl}/sponsorships/evm/call`, {
        method: 'POST',
        headers: {
          authorization: 'Bearer pk_live_invalid',
          origin: allowedOrigin,
          'x-tatchi-environment-id': environmentId,
          'content-type': 'application/json',
        },
        body: JSON.stringify(requestBody),
      });
      const invalidBody = invalid.json || {};
      expect(invalid.status).toBe(401);
      expect(invalidBody.code).toBe('publishable_key_invalid');

      const blocked = await fetchJson(`${server.baseUrl}/sponsorships/evm/call`, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${key.secret}`,
          origin: blockedOrigin,
          'x-tatchi-environment-id': environmentId,
          'content-type': 'application/json',
        },
        body: JSON.stringify(requestBody),
      });
      const blockedBody = blocked.json || {};
      expect(blocked.status).toBe(403);
      expect(blockedBody.code).toBe('origin_not_allowed');
    } finally {
      await server.close();
      await rpc.close();
    }
  });

  test('rejects calls that do not match the active sponsorship policy', async () => {
    const apiKeys = createInMemoryConsoleApiKeyService();
    const ledger = createInMemoryConsoleSponsoredCallService();
    const runtimeSnapshots = createInMemoryConsoleRuntimeSnapshotService();
    await publishAllowedPolicy(runtimeSnapshots);
    const billing = makeBillingSpy();
    const key = await createPublishableKey(apiKeys);
    const rpc = await startFakeTempoRpc({ receiptStatus: '0x1' });
    const server = await startSponsoredCallRouteServer({
      apiKeys,
      billing: billing.service,
      ledger,
      runtimeSnapshots,
      config: makeRouteConfig(rpc.url),
    });
    try {
      const mismatch = await fetchJson(`${server.baseUrl}/sponsorships/evm/call`, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${key.secret}`,
          origin: allowedOrigin,
          'x-tatchi-environment-id': environmentId,
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          environmentId,
          nearAccountId: 'alice.testnet',
          walletAddress,
          chainId: 42_431,
          call: {
            to: contractAddress,
            data: '0xdeadbeef',
            gasLimit: '300000',
            value: '0',
          },
        }),
      });
      const mismatchBody = mismatch.json || {};
      expect(mismatch.status).toBe(403);
      expect(mismatchBody.code).toBe('sponsorship_policy_not_matched');
    } finally {
      await server.close();
      await rpc.close();
    }
  });

  test('records exact spend for reverted sponsored calls', async () => {
    const apiKeys = createInMemoryConsoleApiKeyService();
    const ledger = createInMemoryConsoleSponsoredCallService();
    const runtimeSnapshots = createInMemoryConsoleRuntimeSnapshotService();
    await publishAllowedPolicy(runtimeSnapshots);
    const billing = makeBillingSpy();
    const key = await createPublishableKey(apiKeys);
    const rpc = await startFakeTempoRpc({ receiptStatus: '0x0' });
    const server = await startSponsoredCallRouteServer({
      apiKeys,
      billing: billing.service,
      ledger,
      runtimeSnapshots,
      config: makeRouteConfig(rpc.url),
    });
    const sourceEventId = makeSourceEventId('reverted');
    try {
      const response = await fetchJson(`${server.baseUrl}/sponsorships/evm/call`, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${key.secret}`,
          origin: allowedOrigin,
          'x-tatchi-environment-id': environmentId,
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          environmentId,
          nearAccountId: 'alice.testnet',
          walletAddress,
          chainId: 42_431,
          call: {
            to: contractAddress,
            data: encodeTempoDripInput([tokenAddress]),
            gasLimit: '300000',
            value: '0',
          },
          sourceEventId,
        }),
      });
      const body = response.json || {};
      expect(response.status).toBe(502);
      expect(body.code).toBe('tx_reverted');

      const record = await ledger.getRecordBySourceEventId(apiKeyCtx, sourceEventId);
      const details = parseRecordDetails(record?.detailsJson);
      expect(record?.receiptStatus).toBe('reverted');
      expect(record?.txOrExecutionRef).toBe(txHash);
      expect(record?.feeAmount).toBe(spendWeiDec);
      expect(details.execution?.gasUsed).toBe(gasUsedDec);
      expect(details.execution?.effectiveGasPrice).toBe(effectiveGasPriceDec);

      expect(billing.events).toEqual([
        expect.objectContaining({
          walletId: 'alice.testnet',
          action: 'contract_call',
          succeeded: false,
        }),
      ]);
    } finally {
      await server.close();
      await rpc.close();
    }
  });

  test('requires a published runtime snapshot', async () => {
    const apiKeys = createInMemoryConsoleApiKeyService();
    const ledger = createInMemoryConsoleSponsoredCallService();
    const runtimeSnapshots = createInMemoryConsoleRuntimeSnapshotService();
    const billing = makeBillingSpy();
    const key = await createPublishableKey(apiKeys);
    const rpc = await startFakeTempoRpc({ receiptStatus: '0x1' });
    const server = await startSponsoredCallRouteServer({
      apiKeys,
      billing: billing.service,
      ledger,
      runtimeSnapshots,
      config: makeRouteConfig(rpc.url),
    });
    try {
      const response = await fetchJson(`${server.baseUrl}/sponsorships/evm/call`, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${key.secret}`,
          origin: allowedOrigin,
          'x-tatchi-environment-id': environmentId,
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          environmentId,
          nearAccountId: 'alice.testnet',
          walletAddress,
          chainId: 42_431,
          call: {
            to: contractAddress,
            data: encodeTempoDripInput([tokenAddress]),
            gasLimit: '300000',
            value: '0',
          },
        }),
      });
      const body = response.json || {};
      expect(response.status).toBe(503);
      expect(body.code).toBe('runtime_snapshot_not_found');
    } finally {
      await server.close();
      await rpc.close();
    }
  });
});
