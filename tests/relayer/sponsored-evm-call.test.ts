import type { IncomingMessage, ServerResponse } from 'node:http';
import http from 'node:http';
import expressImport from 'express';
import { expect, test } from '@playwright/test';
import {
  createInMemoryConsoleApiKeyService,
  createInMemoryConsoleBillingPrepaidReservationService,
  createPostgresConsoleBillingPrepaidReservationService,
  createPostgresConsoleBillingService,
  createInMemoryConsoleRuntimeSnapshotService,
  createInMemoryConsoleSponsorshipSpendCapService,
  ensureConsoleBillingPrepaidReservationPostgresSchema,
  ensureConsoleBillingPostgresSchema,
  type ConsoleApiKeyService,
} from '@server/router/express-adaptor';
import {
  createInMemoryConsoleSponsoredCallService,
  createPostgresConsoleSponsoredCallService,
  ensureConsoleSponsoredCallPostgresSchema,
} from '@server';
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
const alternateChainId = 11_155_111;
const alternateTokenAddress = '0x30c0000000000000000000000000000000000002' as const;
const alternateSponsorAddress = '0x4444444444444444444444444444444444444444' as const;
const alternateSponsorPrivateKeyHex =
  '0x2222222222222222222222222222222222222222222222222222222222222222' as const;
const contractAddress = '0xBB442B54c85efBa2D7B81eA52990ad638cDbA483' as const;
const selector = '0x867ae9d4' as const;
const functionSignature = 'dripTo(address,address[])';
const transferSelector = '0xa9059cbb' as const;
const transferFunctionSignature = 'transfer(address,uint256)';
const txHash = '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' as const;
const gasUsedHex = '0x5208';
const gasUsedDec = '21000';
const effectiveGasPriceHex = '0x77359400';
const effectiveGasPriceDec = '2000000000';
const spendWeiDec = '42000000000000';
const postgresUrl = String(process.env.POSTGRES_URL || '').trim();
const postgresEnabled = Boolean(postgresUrl);

type BillingEventSpy = {
  kind: 'usage' | 'sponsored_execution_debit';
  walletId: string;
  action?: string;
  succeeded?: boolean;
  amountMinor?: number;
  pricingVersion?: string | null;
  sourceEventId?: string;
};

function encodeTempoDripToInput(
  recipient: `0x${string}`,
  tokenAddresses: readonly `0x${string}`[],
): `0x${string}` {
  const encodedAddresses = tokenAddresses
    .map((address) => address.slice(2).toLowerCase().padStart(64, '0'))
    .join('');
  const recipientHex = recipient.slice(2).toLowerCase().padStart(64, '0');
  const offsetHex = (64).toString(16).padStart(64, '0');
  const lengthHex = tokenAddresses.length.toString(16).padStart(64, '0');
  return `0x${selector.slice(2)}${recipientHex}${offsetHex}${lengthHex}${encodedAddresses}` as `0x${string}`;
}

function encodeErc20TransferInput(to: `0x${string}`, amount: bigint): `0x${string}` {
  const toHex = to.slice(2).toLowerCase().padStart(64, '0');
  const amountHex = amount.toString(16).padStart(64, '0');
  return `0x${transferSelector.slice(2)}${toHex}${amountHex}` as `0x${string}`;
}

function randomNamespace(prefix: string): string {
  return `${prefix}:${Date.now()}:${Math.random().toString(16).slice(2)}`;
}

let sponsorshipPostgresSchemasReady = false;

async function ensureSponsorshipPostgresSchemas(): Promise<void> {
  if (!postgresEnabled || sponsorshipPostgresSchemasReady) return;
  await ensureConsoleBillingPostgresSchema({
    postgresUrl,
    logger: makeLogger(),
  });
  await ensureConsoleBillingPrepaidReservationPostgresSchema({
    postgresUrl,
    logger: makeLogger(),
  });
  await ensureConsoleSponsoredCallPostgresSchema({
    postgresUrl,
    logger: makeLogger(),
  });
  sponsorshipPostgresSchemasReady = true;
}

async function makeAtomicSponsorshipServices(input?: {
  initialBalanceMinor?: number;
}): Promise<{
  billing: {
    events: BillingEventSpy[];
  } & Record<string, unknown>;
	  ledger: any;
  prepaidReservations: unknown;
}> {
  if (!postgresEnabled) {
    throw new Error('POSTGRES_URL not set');
  }
  await ensureSponsorshipPostgresSchemas();
  const namespace = randomNamespace('test:sponsored-evm-call');
  const billingService = await createPostgresConsoleBillingService({
    postgresUrl,
    namespace,
    ensureSchema: false,
    logger: makeLogger(),
  });
  const prepaidReservations = await createPostgresConsoleBillingPrepaidReservationService({
    postgresUrl,
    namespace,
    ensureSchema: false,
    logger: makeLogger(),
  });
  const ledger = await createPostgresConsoleSponsoredCallService({
    postgresUrl,
    namespace,
    ensureSchema: false,
    logger: makeLogger(),
  });
  const seedBalanceMinor = Math.max(0, Math.trunc(input?.initialBalanceMinor ?? 5_000));
  if (seedBalanceMinor > 0) {
    await billingService.grantManualSupportCredit(
      {
        orgId: apiKeyCtx.orgId,
        actorUserId: 'user-platform-admin',
        roles: ['platform_admin'],
      },
      {
        amountMinor: seedBalanceMinor,
        reasonCode: 'test_seed_credit',
        note: 'Seed prepaid balance for sponsored route test',
        idempotencyKey: `seed-balance:${namespace}`,
      },
    );
  }
  const events: BillingEventSpy[] = [];
  const billing = Object.create(billingService) as {
    events: BillingEventSpy[];
    recordUsageEvent: (
      ctx: unknown,
      request: {
        walletId: string;
        action: string;
        succeeded: boolean;
        sourceEventId?: string;
      },
    ) => Promise<unknown>;
    recordSponsoredExecutionDebit: (
      ctx: unknown,
      request: {
        walletId: string;
        amountMinor: number;
        sourceEventId: string;
        pricingVersion?: string | null;
      },
    ) => Promise<unknown>;
  };
  billing.recordUsageEvent = async (ctx, request) => {
    events.push({
      kind: 'usage',
      walletId: request.walletId,
      action: request.action,
      succeeded: request.succeeded,
      ...(request.sourceEventId ? { sourceEventId: request.sourceEventId } : {}),
    });
    return await billingService.recordUsageEvent(ctx as any, request as any);
  };
  billing.recordSponsoredExecutionDebit = async (ctx, request) => {
    events.push({
      kind: 'sponsored_execution_debit',
      walletId: request.walletId,
      amountMinor: request.amountMinor,
      ...(request.pricingVersion ? { pricingVersion: request.pricingVersion } : {}),
      sourceEventId: request.sourceEventId,
    });
    return await billingService.recordSponsoredExecutionDebit(ctx as any, request as any);
  };
  billing.events = events;
  return {
    billing,
    ledger,
    prepaidReservations,
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

function makeIdempotencyKey(id: string): string {
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
    billing?: {
      sourceEventId?: string | null;
      estimatedSpendMinor?: string | null;
      settledSpendMinor?: string | null;
      pricingVersion?: string | null;
      usedEstimatedFallback?: boolean | null;
      released?: boolean | null;
    };
    policySpendCap?: {
      sourceEventId?: string | null;
      estimatedSpendMinor?: string | null;
      settledSpendMinor?: string | null;
      pricingVersion?: string | null;
      usedEstimatedFallback?: boolean | null;
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
  sendRawTransactionResult?: unknown;
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
        respond(res, {
          id: body.id,
          result:
            input.sendRawTransactionResult === undefined
              ? resolvedTxHash
              : input.sendRawTransactionResult,
        });
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
  return makeMultichainRouteConfig([
    {
      chainId: 42_431,
      rpcUrl,
      sponsorAddress,
      sponsorPrivateKeyHex,
    },
  ]);
}

function makeMultichainRouteConfig(
  executors: Array<{
    chainId: number;
    rpcUrl: string;
    sponsorAddress: `0x${string}`;
    sponsorPrivateKeyHex: `0x${string}`;
  }>,
) {
  return {
    executorsByChain: new Map(
      executors.map((executor) => [
        executor.chainId,
        {
          ...executor,
          maxPriorityFeePerGasFloor: 2_000_000_000n,
          maxFeePerGasFloor: 40_000_000_000n,
        },
      ]),
    ),
  };
}

function makeLogger() {
  return {
    debug() {},
    info() {},
    warn() {},
    error() {},
  };
}

function makePricingService(input: { estimatedMinor: number; finalizedMinor: number }) {
  const estimates: Array<Record<string, unknown>> = [];
  const finals: Array<Record<string, unknown>> = [];
  return {
    estimates,
    finals,
    service: {
      estimateSponsoredExecutionSpend: async (request: Record<string, unknown>) => {
        estimates.push(request);
        return {
          spendMinor: input.estimatedMinor,
          pricingVersion: 'pricing-test-v1',
        };
      },
      finalizeSponsoredExecutionSpend: async (request: Record<string, unknown>) => {
        finals.push(request);
        return {
          spendMinor: input.finalizedMinor,
          pricingVersion: 'pricing-test-v1',
        };
      },
    },
  };
}

async function publishAllowedPolicy(
  runtimeSnapshots: ReturnType<typeof createInMemoryConsoleRuntimeSnapshotService>,
  opts?: {
    additionalResolvedPolicies?: Record<string, unknown>[];
    projectId?: string;
    spendCap?: {
      mode: 'NONE' | 'CHAIN_TOTAL' | 'WALLET_CHAIN_TOTAL';
      period: 'WEEKLY' | 'MONTHLY';
      capsByChain: Array<{ chainId: number; capMinor: number }>;
    };
  },
) {
  await runtimeSnapshots.publishSnapshot(apiKeyCtx, {
    ...(opts?.projectId ? { projectId: opts.projectId } : {}),
    environmentId,
    payload: {
      policy: {},
      metadata: {},
      smartWallets: {},
      gasSponsorship: {
        status: 'resolved',
        policyCount: 1 + (opts?.additionalResolvedPolicies?.length || 0),
        policies: [],
        resolvedPolicies: [
          {
            kind: 'evm_call',
            policyId: 'policy_gs_onboarding',
            policyName: 'Tempo Testnet Onboarding',
            scopePolicyId: null,
            scopePolicyName: null,
            templateId: 'tempo_testnet_onboarding',
            networkClass: 'TESTNET',
            executionMode: 'evm_eoa',
            allowedChainIds: [42_431],
            allowedCalls: [
              {
                chainId: 42_431,
                to: contractAddress,
                functionSignature,
                selector,
                maxGasLimit: '1000000',
                maxValueWei: '0',
              },
            ],
            spendCap: opts?.spendCap || { mode: 'NONE', period: 'MONTHLY', capsByChain: [] },
            scopeType: 'ENVIRONMENT',
            projectId: null,
            environmentId,
          },
          ...(opts?.additionalResolvedPolicies || []),
        ],
      },
    },
  });
}

async function startSponsoredCallRouteServer(input: {
  apiKeys: ConsoleApiKeyService;
  billing: unknown;
  ledger: unknown;
  runtimeSnapshots: ReturnType<typeof createInMemoryConsoleRuntimeSnapshotService>;
  prepaidReservations?: unknown;
  sponsorship?: {
    spendCaps?: ReturnType<typeof createInMemoryConsoleSponsorshipSpendCapService>;
    prepaidReservations?: unknown;
    pricing?:
      | {
      estimateSponsoredExecutionSpend: (input: Record<string, unknown>) => Promise<{
        spendMinor: number;
        pricingVersion: string;
      }>;
      finalizeSponsoredExecutionSpend: (input: Record<string, unknown>) => Promise<{
        spendMinor: number;
        pricingVersion: string;
      }>;
      }
      | null;
  };
  corsOrigins?: string[];
  config: ReturnType<typeof makeRouteConfig>;
}) {
  const app = express();
  app.use(express.json({ limit: '1mb' }));
  const defaultPricing = makePricingService({
    estimatedMinor: 80,
    finalizedMinor: 60,
  });
  const prepaidReservations =
    input.prepaidReservations ||
    input.sponsorship?.prepaidReservations ||
    createInMemoryConsoleBillingPrepaidReservationService();
  registerSponsoredEvmCallRoute({
    router: app as unknown as any,
    apiKeys: input.apiKeys as any,
    billing: input.billing as any,
    ledger: input.ledger as any,
    runtimeSnapshots: input.runtimeSnapshots as any,
    prepaidReservations: prepaidReservations as any,
    pricing:
      (input.sponsorship && 'pricing' in input.sponsorship
        ? input.sponsorship.pricing
        : defaultPricing.service) as any,
    ...(input.sponsorship?.spendCaps ? { spendCaps: input.sponsorship.spendCaps as any } : {}),
    corsOrigins: input.corsOrigins || [allowedOrigin],
    config: input.config,
    logger: makeLogger(),
  });
  return await startExpressRouter(app);
}

test.describe('sponsored evm call route', () => {
  test.beforeEach(async () => {
    test.skip(!postgresEnabled, 'POSTGRES_URL not set');
    await ensureSponsorshipPostgresSchemas();
  });

  test('in-memory ledger deduplicates by idempotencyKey per org', async () => {
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
        policyId: 'policy_gs_onboarding',
        policyNameAtEvent: 'Tempo Testnet Onboarding',
        templateId: 'tempo_testnet_onboarding',
        chainFamily: 'evm',
        intentKind: 'evm_call',
        executorKind: 'evm_eoa',
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
            data: encodeTempoDripToInput(walletAddress, [tokenAddress]),
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
        idempotencyKey: 'source-1',
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
        policyId: 'policy_gs_other',
        templateId: null,
        chainFamily: 'evm',
        intentKind: 'evm_call',
        executorKind: 'evm_eoa',
        accountRef: 'near:bob.testnet',
        targetRef: `evm:42431:${contractAddress.toLowerCase()}`,
        sponsorRef: `evm:42431:${sponsorAddress.toLowerCase()}`,
        receiptStatus: 'rpc_rejected',
        feeUnit: 'wei',
        feeAmount: '0',
        detailsJson: '{}',
        idempotencyKey: 'source-1',
      },
    );
    expect(second.id).toBe(first.id);
    expect(second.apiKeyId).toBe('pk_live_1');
    expect(second.policyId).toBe('policy_gs_onboarding');
  });

  test('executes a sponsored call and records exact spend', async () => {
    const apiKeys = createInMemoryConsoleApiKeyService();
    const { billing, ledger, prepaidReservations } = await makeAtomicSponsorshipServices();
    const runtimeSnapshots = createInMemoryConsoleRuntimeSnapshotService();
    await publishAllowedPolicy(runtimeSnapshots);
    const key = await createPublishableKey(apiKeys);
    const rpc = await startFakeTempoRpc({ receiptStatus: '0x1' });
    const server = await startSponsoredCallRouteServer({
      apiKeys,
      billing,
      ledger,
      runtimeSnapshots,
      prepaidReservations,
      config: makeRouteConfig(rpc.url),
    });
    const idempotencyKey = makeIdempotencyKey('success');
    const callData = encodeTempoDripToInput(walletAddress, [tokenAddress]);
    try {
      const response = await fetchJson(`${server.baseUrl}/sponsorships/evm/call`, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${key.secret}`,
          origin: allowedOrigin,
          'x-seams-environment-id': environmentId,
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
          idempotencyKey,
        }),
      });
      const body = response.json || {};
      expect(response.status).toBe(200);
      expect(body.ok).toBe(true);
      expect(body.txHash).toBe(txHash);
      expect(body.policyId).toBe('policy_gs_onboarding');
      expect(body.gasUsed).toBe(gasUsedDec);
      expect(body.effectiveGasPrice).toBe(effectiveGasPriceDec);
      expect(body.spendWei).toBe(spendWeiDec);

      const record = await ledger.getRecordByIdempotencyKey(apiKeyCtx, idempotencyKey);
      const details = parseRecordDetails(record?.detailsJson);
      expect(record?.policyId).toBe('policy_gs_onboarding');
      expect(record?.chainFamily).toBe('evm');
      expect(record?.intentKind).toBe('evm_call');
      expect(record?.templateId).toBe('tempo_testnet_onboarding');
      expect(record?.executorKind).toBe('evm_eoa');
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
      expect(details.billing?.estimatedSpendMinor).toBe('80');
      expect(details.billing?.settledSpendMinor).toBe('60');
      expect(details.billing?.released).toBe(false);

      expect(billing.events).toEqual([
        {
          kind: 'sponsored_execution_debit',
          walletId: 'alice.testnet',
          amountMinor: 60,
          pricingVersion: 'pricing-test-v1',
          sourceEventId: expect.stringMatching(/^sponsored_evm_call_debit:/),
        },
      ]);
    } finally {
      await server.close();
      await rpc.close();
    }
  });

  test('enforces spend caps through the shared pricing and reservation path', async () => {
    const apiKeys = createInMemoryConsoleApiKeyService();
    const { billing, ledger, prepaidReservations } = await makeAtomicSponsorshipServices();
    const runtimeSnapshots = createInMemoryConsoleRuntimeSnapshotService();
    await publishAllowedPolicy(runtimeSnapshots, {
      spendCap: {
        mode: 'CHAIN_TOTAL',
        period: 'MONTHLY',
        capsByChain: [{ chainId: 42_431, capMinor: 100 }],
      },
    });
    const pricing = makePricingService({ estimatedMinor: 80, finalizedMinor: 60 });
    const spendCaps = createInMemoryConsoleSponsorshipSpendCapService({
      now: () => new Date('2026-03-10T12:00:00.000Z'),
    });
    const key = await createPublishableKey(apiKeys);
    const rpc = await startFakeTempoRpc({ receiptStatus: '0x1' });
    const server = await startSponsoredCallRouteServer({
      apiKeys,
      billing,
      ledger,
      runtimeSnapshots,
      prepaidReservations,
      sponsorship: {
        spendCaps,
        pricing: pricing.service,
      },
      config: makeRouteConfig(rpc.url),
    });
    const baseBody = {
      environmentId,
      nearAccountId: 'alice.testnet',
      walletAddress,
      chainId: 42_431,
      call: {
        to: contractAddress,
        data: encodeTempoDripToInput(walletAddress, [tokenAddress]),
        gasLimit: '300000',
        value: '0',
      },
    };
    try {
      const first = await fetchJson(`${server.baseUrl}/sponsorships/evm/call`, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${key.secret}`,
          origin: allowedOrigin,
          'x-seams-environment-id': environmentId,
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          ...baseBody,
          idempotencyKey: makeIdempotencyKey('spend-cap-first'),
        }),
      });
      expect(first.status).toBe(200);

      const usage = await spendCaps.getWindowUsage(apiKeyCtx, {
        environmentId,
        policyId: 'policy_gs_onboarding',
        chainId: 42_431,
        mode: 'CHAIN_TOTAL',
        period: 'MONTHLY',
        at: new Date('2026-03-10T12:00:00.000Z'),
      });
      expect(usage?.reservedMinor).toBe(0);
      expect(usage?.settledMinor).toBe(60);
      expect(usage?.availableMinor).toBe(40);

      const firstRecord = await ledger.getRecordByIdempotencyKey(
        apiKeyCtx,
        makeIdempotencyKey('spend-cap-first'),
      );
      const firstDetails = parseRecordDetails(firstRecord?.detailsJson);
      expect(firstDetails.billing?.estimatedSpendMinor).toBe('80');
      expect(firstDetails.billing?.settledSpendMinor).toBe('60');
      expect(firstDetails.billing?.pricingVersion).toBe('pricing-test-v1');
      expect(firstDetails.policySpendCap?.estimatedSpendMinor).toBe('80');
      expect(firstDetails.policySpendCap?.settledSpendMinor).toBe('60');
      expect(firstDetails.policySpendCap?.pricingVersion).toBe('pricing-test-v1');
      expect(pricing.estimates).toHaveLength(2);
      expect(pricing.finals).toHaveLength(2);
      expect(billing.events).toEqual([
        expect.objectContaining({
          kind: 'sponsored_execution_debit',
          walletId: 'alice.testnet',
          amountMinor: 60,
          pricingVersion: 'pricing-test-v1',
        }),
      ]);

      const second = await fetchJson(`${server.baseUrl}/sponsorships/evm/call`, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${key.secret}`,
          origin: allowedOrigin,
          'x-seams-environment-id': environmentId,
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          ...baseBody,
          idempotencyKey: makeIdempotencyKey('spend-cap-second'),
        }),
      });
      expect(second.status).toBe(409);
      expect(second.json?.code).toBe('spend_cap_exceeded');
      expect(rpc.requests.filter((method) => method === 'eth_sendRawTransaction')).toHaveLength(1);
    } finally {
      await server.close();
      await rpc.close();
    }
  });

  test('fails closed when spend caps are configured but pricing is unavailable', async () => {
    const apiKeys = createInMemoryConsoleApiKeyService();
    const { billing, ledger, prepaidReservations } = await makeAtomicSponsorshipServices();
    const runtimeSnapshots = createInMemoryConsoleRuntimeSnapshotService();
    await publishAllowedPolicy(runtimeSnapshots, {
      spendCap: {
        mode: 'CHAIN_TOTAL',
        period: 'MONTHLY',
        capsByChain: [{ chainId: 42_431, capMinor: 500 }],
      },
    });
    const spendCaps = createInMemoryConsoleSponsorshipSpendCapService();
    const key = await createPublishableKey(apiKeys);
    const rpc = await startFakeTempoRpc({ receiptStatus: '0x1' });
    const server = await startSponsoredCallRouteServer({
      apiKeys,
      billing,
      ledger,
      runtimeSnapshots,
      prepaidReservations,
      sponsorship: {
        spendCaps,
        pricing: null,
      },
      config: makeRouteConfig(rpc.url),
    });
    try {
      const response = await fetchJson(`${server.baseUrl}/sponsorships/evm/call`, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${key.secret}`,
          origin: allowedOrigin,
          'x-seams-environment-id': environmentId,
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          environmentId,
          nearAccountId: 'alice.testnet',
          walletAddress,
          chainId: 42_431,
          call: {
            to: contractAddress,
            data: encodeTempoDripToInput(walletAddress, [tokenAddress]),
            gasLimit: '300000',
            value: '0',
          },
          idempotencyKey: makeIdempotencyKey('spend-cap-no-pricing'),
        }),
      });
      expect(response.status).toBe(503);
      expect(response.json?.code).toBe('sponsorship_pricing_unavailable');
      expect(rpc.requests.filter((method) => method === 'eth_sendRawTransaction')).toHaveLength(0);
    } finally {
      await server.close();
      await rpc.close();
    }
  });

  test('matches a second non-Tempo EVM template using the richer allowedCalls model', async () => {
    const apiKeys = createInMemoryConsoleApiKeyService();
    const { billing, ledger, prepaidReservations } = await makeAtomicSponsorshipServices();
    const runtimeSnapshots = createInMemoryConsoleRuntimeSnapshotService();
    await publishAllowedPolicy(runtimeSnapshots, {
      additionalResolvedPolicies: [
        {
          kind: 'evm_call',
          policyId: 'policy_gs_erc20_transfer',
          policyName: 'ERC20 Transfer Sponsorship',
          scopePolicyId: null,
          scopePolicyName: null,
          templateId: 'erc20_transfer_v1',
          networkClass: 'TESTNET',
          executionMode: 'evm_eoa',
          allowedChainIds: [42_431],
          allowedCalls: [
            {
              chainId: 42_431,
              to: tokenAddress,
              functionSignature: transferFunctionSignature,
              selector: transferSelector,
              maxGasLimit: '200000',
              maxValueWei: '0',
            },
          ],
          spendCap: { mode: 'NONE', period: 'MONTHLY', capsByChain: [] },
          scopeType: 'ENVIRONMENT',
          projectId: null,
          environmentId,
        },
      ],
    });
    const key = await createPublishableKey(apiKeys);
    const rpc = await startFakeTempoRpc({ receiptStatus: '0x1' });
    const server = await startSponsoredCallRouteServer({
      apiKeys,
      billing,
      ledger,
      runtimeSnapshots,
      prepaidReservations,
      config: makeRouteConfig(rpc.url),
    });
    const idempotencyKey = makeIdempotencyKey('erc20-transfer');
    const callData = encodeErc20TransferInput(walletAddress, 123_000_000n);
    try {
      const response = await fetchJson(`${server.baseUrl}/sponsorships/evm/call`, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${key.secret}`,
          origin: allowedOrigin,
          'x-seams-environment-id': environmentId,
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          environmentId,
          nearAccountId: 'carol.testnet',
          walletAddress,
          chainId: 42_431,
          call: {
            to: tokenAddress,
            data: callData,
            gasLimit: '120000',
            value: '0',
          },
          idempotencyKey,
        }),
      });
      expect(response.status).toBe(200);
      expect(response.json?.ok).toBe(true);
      expect(response.json?.policyId).toBe('policy_gs_erc20_transfer');

      const record = await ledger.getRecordByIdempotencyKey(apiKeyCtx, idempotencyKey);
      const details = parseRecordDetails(record?.detailsJson);
      expect(record?.policyId).toBe('policy_gs_erc20_transfer');
      expect(record?.templateId).toBe('erc20_transfer_v1');
      expect(record?.targetRef).toBe(`evm:42431:${tokenAddress.toLowerCase()}`);
      expect(details.call?.to).toBe(tokenAddress);
      expect(details.call?.selector).toBe(transferSelector);
      expect(details.call?.data).toBe(callData);
    } finally {
      await server.close();
      await rpc.close();
    }
  });

  test('derives the canonical selector from functionSignature when the resolved snapshot carries a stale selector', async () => {
    const apiKeys = createInMemoryConsoleApiKeyService();
    const { billing, ledger, prepaidReservations } = await makeAtomicSponsorshipServices();
    const runtimeSnapshots = createInMemoryConsoleRuntimeSnapshotService();
    await publishAllowedPolicy(runtimeSnapshots, {
      additionalResolvedPolicies: [
        {
          kind: 'evm_call',
          policyId: 'policy_gs_erc20_transfer_stale_selector',
          policyName: 'ERC20 Transfer Sponsorship (stale selector)',
          scopePolicyId: null,
          scopePolicyName: null,
          templateId: 'erc20_transfer_stale_selector_v1',
          networkClass: 'TESTNET',
          executionMode: 'evm_eoa',
          allowedChainIds: [42_431],
          allowedCalls: [
            {
              chainId: 42_431,
              to: tokenAddress,
              functionSignature: transferFunctionSignature,
              selector: '0xdeadbeef',
              maxGasLimit: '200000',
              maxValueWei: '0',
            },
          ],
          spendCap: { mode: 'NONE', period: 'MONTHLY', capsByChain: [] },
          scopeType: 'ENVIRONMENT',
          projectId: null,
          environmentId,
        },
      ],
    });
    const key = await createPublishableKey(apiKeys);
    const rpc = await startFakeTempoRpc({ receiptStatus: '0x1' });
    const server = await startSponsoredCallRouteServer({
      apiKeys,
      billing,
      ledger,
      runtimeSnapshots,
      prepaidReservations,
      config: makeRouteConfig(rpc.url),
    });
    try {
      const response = await fetchJson(`${server.baseUrl}/sponsorships/evm/call`, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${key.secret}`,
          origin: allowedOrigin,
          'x-seams-environment-id': environmentId,
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          environmentId,
          nearAccountId: 'selector.testnet',
          walletAddress,
          chainId: 42_431,
          call: {
            to: tokenAddress,
            data: encodeErc20TransferInput(walletAddress, 777_000_000n),
            gasLimit: '120000',
            value: '0',
          },
          idempotencyKey: makeIdempotencyKey('erc20-transfer-stale-selector'),
        }),
      });
      expect(response.status).toBe(200);
      expect(response.json?.ok).toBe(true);
      expect(response.json?.policyId).toBe('policy_gs_erc20_transfer_stale_selector');
    } finally {
      await server.close();
      await rpc.close();
    }
  });

  test('routes matched sponsorships to the executor configured for the requested chain', async () => {
    const apiKeys = createInMemoryConsoleApiKeyService();
    const { billing, ledger, prepaidReservations } = await makeAtomicSponsorshipServices();
    const runtimeSnapshots = createInMemoryConsoleRuntimeSnapshotService();
    await publishAllowedPolicy(runtimeSnapshots, {
      additionalResolvedPolicies: [
        {
          kind: 'evm_call',
          policyId: 'policy_gs_multichain_transfer',
          policyName: 'Alt Chain ERC20 Transfer Sponsorship',
          scopePolicyId: null,
          scopePolicyName: null,
          templateId: 'erc20_transfer_alt_chain_v1',
          networkClass: 'TESTNET',
          executionMode: 'evm_eoa',
          allowedChainIds: [alternateChainId],
          allowedCalls: [
            {
              chainId: alternateChainId,
              to: alternateTokenAddress,
              functionSignature: transferFunctionSignature,
              selector: transferSelector,
              maxGasLimit: '200000',
              maxValueWei: '0',
            },
          ],
          spendCap: { mode: 'NONE', period: 'MONTHLY', capsByChain: [] },
          scopeType: 'ENVIRONMENT',
          projectId: null,
          environmentId,
        },
      ],
    });
    const key = await createPublishableKey(apiKeys);
    const primaryRpc = await startFakeTempoRpc({ receiptStatus: '0x1' });
    const alternateRpc = await startFakeTempoRpc({ receiptStatus: '0x1' });
    const server = await startSponsoredCallRouteServer({
      apiKeys,
      billing,
      ledger,
      runtimeSnapshots,
      prepaidReservations,
      config: makeMultichainRouteConfig([
        {
          chainId: 42_431,
          rpcUrl: primaryRpc.url,
          sponsorAddress,
          sponsorPrivateKeyHex,
        },
        {
          chainId: alternateChainId,
          rpcUrl: alternateRpc.url,
          sponsorAddress: alternateSponsorAddress,
          sponsorPrivateKeyHex: alternateSponsorPrivateKeyHex,
        },
      ]),
    });
    const idempotencyKey = makeIdempotencyKey('multichain-executor-selection');
    try {
      const response = await fetchJson(`${server.baseUrl}/sponsorships/evm/call`, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${key.secret}`,
          origin: allowedOrigin,
          'x-seams-environment-id': environmentId,
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          environmentId,
          nearAccountId: 'multichain.testnet',
          walletAddress,
          chainId: alternateChainId,
          call: {
            to: alternateTokenAddress,
            data: encodeErc20TransferInput(walletAddress, 321_000_000n),
            gasLimit: '120000',
            value: '0',
          },
          idempotencyKey,
        }),
      });

      expect(response.status).toBe(200);
      expect(response.json?.ok).toBe(true);
      expect(response.json?.policyId).toBe('policy_gs_multichain_transfer');
      expect(primaryRpc.requests.filter((method) => method === 'eth_sendRawTransaction')).toHaveLength(0);
      expect(
        alternateRpc.requests.filter((method) => method === 'eth_sendRawTransaction'),
      ).toHaveLength(1);

      const record = await ledger.getRecordByIdempotencyKey(apiKeyCtx, idempotencyKey);
      expect(record?.policyId).toBe('policy_gs_multichain_transfer');
      expect(record?.templateId).toBe('erc20_transfer_alt_chain_v1');
      expect(record?.targetRef).toBe(`evm:${alternateChainId}:${alternateTokenAddress.toLowerCase()}`);
    } finally {
      await server.close();
      await primaryRpc.close();
      await alternateRpc.close();
    }
  });

  test('rejects matched calls when no executor is configured for the matched chain', async () => {
    const apiKeys = createInMemoryConsoleApiKeyService();
    const { billing, ledger, prepaidReservations } = await makeAtomicSponsorshipServices();
    const runtimeSnapshots = createInMemoryConsoleRuntimeSnapshotService();
    await publishAllowedPolicy(runtimeSnapshots, {
      additionalResolvedPolicies: [
        {
          kind: 'evm_call',
          policyId: 'policy_gs_missing_executor',
          policyName: 'Missing Executor Sponsorship',
          scopePolicyId: null,
          scopePolicyName: null,
          templateId: 'missing_executor_v1',
          networkClass: 'TESTNET',
          executionMode: 'evm_eoa',
          allowedChainIds: [alternateChainId],
          allowedCalls: [
            {
              chainId: alternateChainId,
              to: alternateTokenAddress,
              functionSignature: transferFunctionSignature,
              selector: transferSelector,
              maxGasLimit: '200000',
              maxValueWei: '0',
            },
          ],
          spendCap: { mode: 'NONE', period: 'MONTHLY', capsByChain: [] },
          scopeType: 'ENVIRONMENT',
          projectId: null,
          environmentId,
        },
      ],
    });
    const key = await createPublishableKey(apiKeys);
    const rpc = await startFakeTempoRpc({ receiptStatus: '0x1' });
    const server = await startSponsoredCallRouteServer({
      apiKeys,
      billing,
      ledger,
      runtimeSnapshots,
      prepaidReservations,
      config: makeRouteConfig(rpc.url),
    });
    try {
      const response = await fetchJson(`${server.baseUrl}/sponsorships/evm/call`, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${key.secret}`,
          origin: allowedOrigin,
          'x-seams-environment-id': environmentId,
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          environmentId,
          nearAccountId: 'missing-executor.testnet',
          walletAddress,
          chainId: alternateChainId,
          call: {
            to: alternateTokenAddress,
            data: encodeErc20TransferInput(walletAddress, 456_000_000n),
            gasLimit: '120000',
            value: '0',
          },
          idempotencyKey: makeIdempotencyKey('missing-executor'),
        }),
      });

      expect(response.status).toBe(503);
      expect(response.json?.code).toBe('sponsor_chain_misconfigured');
      expect(rpc.requests.filter((method) => method === 'eth_sendRawTransaction')).toHaveLength(0);
    } finally {
      await server.close();
      await rpc.close();
    }
  });

  test('rejects calls that exceed allowed gas or value bounds even when selector matches', async () => {
    const apiKeys = createInMemoryConsoleApiKeyService();
    const { billing, ledger, prepaidReservations } = await makeAtomicSponsorshipServices();
    const runtimeSnapshots = createInMemoryConsoleRuntimeSnapshotService();
    await publishAllowedPolicy(runtimeSnapshots);
    const key = await createPublishableKey(apiKeys);
    const rpc = await startFakeTempoRpc({ receiptStatus: '0x1' });
    const server = await startSponsoredCallRouteServer({
      apiKeys,
      billing,
      ledger,
      runtimeSnapshots,
      prepaidReservations,
      config: makeRouteConfig(rpc.url),
    });
    try {
      const gasExceeded = await fetchJson(`${server.baseUrl}/sponsorships/evm/call`, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${key.secret}`,
          origin: allowedOrigin,
          'x-seams-environment-id': environmentId,
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          environmentId,
          nearAccountId: 'bounds.testnet',
          walletAddress,
          chainId: 42_431,
          idempotencyKey: makeIdempotencyKey('gas-bound-exceeded'),
          call: {
            to: contractAddress,
            data: encodeTempoDripToInput(walletAddress, [tokenAddress]),
            gasLimit: '1000001',
            value: '0',
          },
        }),
      });
      const valueExceeded = await fetchJson(`${server.baseUrl}/sponsorships/evm/call`, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${key.secret}`,
          origin: allowedOrigin,
          'x-seams-environment-id': environmentId,
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          environmentId,
          nearAccountId: 'bounds.testnet',
          walletAddress,
          chainId: 42_431,
          idempotencyKey: makeIdempotencyKey('value-bound-exceeded'),
          call: {
            to: contractAddress,
            data: encodeTempoDripToInput(walletAddress, [tokenAddress]),
            gasLimit: '300000',
            value: '1',
          },
        }),
      });

      expect(gasExceeded.status).toBe(403);
      expect(gasExceeded.json?.code).toBe('sponsorship_policy_gas_limit_exceeded');
      expect(gasExceeded.json?.details?.actualGasLimit).toBe('1000001');
      expect(gasExceeded.json?.details?.maxGasLimit).toBe('1000000');
      expect(valueExceeded.status).toBe(403);
      expect(valueExceeded.json?.code).toBe('sponsorship_policy_value_exceeded');
      expect(valueExceeded.json?.details?.actualValueWei).toBe('1');
      expect(valueExceeded.json?.details?.maxValueWei).toBe('0');
      expect(rpc.requests.filter((method) => method === 'eth_sendRawTransaction')).toHaveLength(0);
    } finally {
      await server.close();
      await rpc.close();
    }
  });

  test('replays idempotently for the same idempotencyKey', async () => {
    const apiKeys = createInMemoryConsoleApiKeyService();
    const { billing, ledger, prepaidReservations } = await makeAtomicSponsorshipServices();
    const runtimeSnapshots = createInMemoryConsoleRuntimeSnapshotService();
    await publishAllowedPolicy(runtimeSnapshots);
    const key = await createPublishableKey(apiKeys);
    const rpc = await startFakeTempoRpc({ receiptStatus: '0x1' });
    const server = await startSponsoredCallRouteServer({
      apiKeys,
      billing,
      ledger,
      runtimeSnapshots,
      prepaidReservations,
      config: makeRouteConfig(rpc.url),
    });
    const idempotencyKey = makeIdempotencyKey('replay');
    const requestBody = {
      environmentId,
      nearAccountId: 'alice.testnet',
      walletAddress,
      chainId: 42_431,
      call: {
        to: contractAddress,
        data: encodeTempoDripToInput(walletAddress, [tokenAddress]),
        gasLimit: '300000',
        value: '0',
      },
      idempotencyKey,
    };
    try {
      const first = await fetchJson(`${server.baseUrl}/sponsorships/evm/call`, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${key.secret}`,
          origin: allowedOrigin,
          'x-seams-environment-id': environmentId,
          'content-type': 'application/json',
        },
        body: JSON.stringify(requestBody),
      });
      const second = await fetchJson(`${server.baseUrl}/sponsorships/evm/call`, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${key.secret}`,
          origin: allowedOrigin,
          'x-seams-environment-id': environmentId,
          'content-type': 'application/json',
        },
        body: JSON.stringify(requestBody),
      });
      const replayed = second.json || {};
      expect(first.status).toBe(200);
      expect(second.status).toBe(200);
      expect(replayed.ok).toBe(true);
      expect(replayed.replayed).toBe(true);
      expect(replayed.txHash).toBe(txHash);
    } finally {
      await server.close();
      await rpc.close();
    }
  });

  test('treats identical payloads with different idempotency keys as fresh attempts', async () => {
    const apiKeys = createInMemoryConsoleApiKeyService();
    const { billing, ledger, prepaidReservations } = await makeAtomicSponsorshipServices();
    const runtimeSnapshots = createInMemoryConsoleRuntimeSnapshotService();
    await publishAllowedPolicy(runtimeSnapshots);
    const key = await createPublishableKey(apiKeys);
    const rpc = await startFakeTempoRpc({ receiptStatus: '0x1' });
    const server = await startSponsoredCallRouteServer({
      apiKeys,
      billing,
      ledger,
      runtimeSnapshots,
      prepaidReservations,
      config: makeRouteConfig(rpc.url),
    });
    const baseBody = {
      environmentId,
      nearAccountId: 'alice.testnet',
      walletAddress,
      chainId: 42_431,
      call: {
        to: contractAddress,
        data: encodeTempoDripToInput(walletAddress, [tokenAddress]),
        gasLimit: '300000',
        value: '0',
      },
    };
    try {
      const first = await fetchJson(`${server.baseUrl}/sponsorships/evm/call`, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${key.secret}`,
          origin: allowedOrigin,
          'x-seams-environment-id': environmentId,
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          ...baseBody,
          idempotencyKey: makeIdempotencyKey('fresh-attempt-1'),
        }),
      });
      const second = await fetchJson(`${server.baseUrl}/sponsorships/evm/call`, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${key.secret}`,
          origin: allowedOrigin,
          'x-seams-environment-id': environmentId,
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          ...baseBody,
          idempotencyKey: makeIdempotencyKey('fresh-attempt-2'),
        }),
      });
      expect(first.status).toBe(200);
      expect(second.status).toBe(200);
      expect((first.json || {}).replayed).toBe(false);
      expect((second.json || {}).replayed).toBe(false);
      expect(rpc.requests.filter((method) => method === 'eth_sendRawTransaction')).toHaveLength(2);
    } finally {
      await server.close();
      await rpc.close();
    }
  });

  test('rejects invalid publishable key and blocked origin', async () => {
    const apiKeys = createInMemoryConsoleApiKeyService();
    const { billing, ledger, prepaidReservations } = await makeAtomicSponsorshipServices();
    const runtimeSnapshots = createInMemoryConsoleRuntimeSnapshotService();
    await publishAllowedPolicy(runtimeSnapshots);
    const key = await createPublishableKey(apiKeys);
    const rpc = await startFakeTempoRpc({ receiptStatus: '0x1' });
    const server = await startSponsoredCallRouteServer({
      apiKeys,
      billing,
      ledger,
      runtimeSnapshots,
      prepaidReservations,
      config: makeRouteConfig(rpc.url),
    });
    const requestBody = {
      environmentId,
      nearAccountId: 'alice.testnet',
      walletAddress,
      chainId: 42_431,
      idempotencyKey: makeIdempotencyKey('invalid-auth'),
      call: {
        to: contractAddress,
        data: encodeTempoDripToInput(walletAddress, [tokenAddress]),
        gasLimit: '300000',
        value: '0',
      },
    };
    try {
      const invalid = await fetchJson(`${server.baseUrl}/sponsorships/evm/call`, {
        method: 'POST',
        headers: {
          authorization: 'Bearer pk_liveinvalid',
          origin: allowedOrigin,
          'x-seams-environment-id': environmentId,
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
          'x-seams-environment-id': environmentId,
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
    const { billing, ledger, prepaidReservations } = await makeAtomicSponsorshipServices();
    const runtimeSnapshots = createInMemoryConsoleRuntimeSnapshotService();
    await publishAllowedPolicy(runtimeSnapshots);
    const key = await createPublishableKey(apiKeys);
    const rpc = await startFakeTempoRpc({ receiptStatus: '0x1' });
    const server = await startSponsoredCallRouteServer({
      apiKeys,
      billing,
      ledger,
      runtimeSnapshots,
      prepaidReservations,
      config: makeRouteConfig(rpc.url),
    });
    try {
      const mismatch = await fetchJson(`${server.baseUrl}/sponsorships/evm/call`, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${key.secret}`,
          origin: allowedOrigin,
          'x-seams-environment-id': environmentId,
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          environmentId,
          nearAccountId: 'alice.testnet',
          walletAddress,
          chainId: 42_431,
          idempotencyKey: makeIdempotencyKey('policy-mismatch'),
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
      expect(mismatchBody.code).toBe('sponsorship_policy_selector_mismatch');
      expect(mismatchBody.details?.actualSelector).toBe('0xdeadbeef');
    } finally {
      await server.close();
      await rpc.close();
    }
  });

  test('does not enforce recipient binding for allowlisted dripTo calls', async () => {
    const apiKeys = createInMemoryConsoleApiKeyService();
    const { billing, ledger, prepaidReservations } = await makeAtomicSponsorshipServices();
    const runtimeSnapshots = createInMemoryConsoleRuntimeSnapshotService();
    await publishAllowedPolicy(runtimeSnapshots);
    const key = await createPublishableKey(apiKeys);
    const rpc = await startFakeTempoRpc({ receiptStatus: '0x1' });
    const server = await startSponsoredCallRouteServer({
      apiKeys,
      billing,
      ledger,
      runtimeSnapshots,
      prepaidReservations,
      config: makeRouteConfig(rpc.url),
    });
    try {
      const response = await fetchJson(`${server.baseUrl}/sponsorships/evm/call`, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${key.secret}`,
          origin: allowedOrigin,
          'x-seams-environment-id': environmentId,
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          environmentId,
          nearAccountId: 'alice.testnet',
          walletAddress,
          chainId: 42_431,
          idempotencyKey: makeIdempotencyKey('recipient-mismatch'),
          call: {
            to: contractAddress,
            data: encodeTempoDripToInput(
              '0x3333333333333333333333333333333333333333',
              [tokenAddress],
            ),
            gasLimit: '300000',
            value: '0',
          },
        }),
      });
      const body = response.json || {};
      expect(response.status).toBe(200);
      expect(body.ok).toBe(true);
      expect(body.replayed).toBe(false);
    } finally {
      await server.close();
      await rpc.close();
    }
  });

  test('requires an explicit idempotencyKey', async () => {
    const apiKeys = createInMemoryConsoleApiKeyService();
    const { billing, ledger, prepaidReservations } = await makeAtomicSponsorshipServices();
    const runtimeSnapshots = createInMemoryConsoleRuntimeSnapshotService();
    await publishAllowedPolicy(runtimeSnapshots);
    const key = await createPublishableKey(apiKeys);
    const rpc = await startFakeTempoRpc({ receiptStatus: '0x1' });
    const server = await startSponsoredCallRouteServer({
      apiKeys,
      billing,
      ledger,
      runtimeSnapshots,
      prepaidReservations,
      config: makeRouteConfig(rpc.url),
    });
    try {
      const response = await fetchJson(`${server.baseUrl}/sponsorships/evm/call`, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${key.secret}`,
          origin: allowedOrigin,
          'x-seams-environment-id': environmentId,
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          environmentId,
          nearAccountId: 'alice.testnet',
          walletAddress,
          chainId: 42_431,
          call: {
            to: contractAddress,
            data: encodeTempoDripToInput(walletAddress, [tokenAddress]),
            gasLimit: '300000',
            value: '0',
          },
        }),
      });
      const body = response.json || {};
      expect(response.status).toBe(400);
      expect(body.code).toBe('invalid_body');
      expect(body.message).toBe('Field idempotencyKey is required');
    } finally {
      await server.close();
      await rpc.close();
    }
  });

  test('records exact spend for reverted sponsored calls', async () => {
    const apiKeys = createInMemoryConsoleApiKeyService();
    const { billing, ledger, prepaidReservations } = await makeAtomicSponsorshipServices();
    const runtimeSnapshots = createInMemoryConsoleRuntimeSnapshotService();
    await publishAllowedPolicy(runtimeSnapshots);
    const key = await createPublishableKey(apiKeys);
    const rpc = await startFakeTempoRpc({ receiptStatus: '0x0' });
    const server = await startSponsoredCallRouteServer({
      apiKeys,
      billing,
      ledger,
      runtimeSnapshots,
      prepaidReservations,
      config: makeRouteConfig(rpc.url),
    });
    const idempotencyKey = makeIdempotencyKey('reverted');
    try {
      const response = await fetchJson(`${server.baseUrl}/sponsorships/evm/call`, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${key.secret}`,
          origin: allowedOrigin,
          'x-seams-environment-id': environmentId,
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          environmentId,
          nearAccountId: 'alice.testnet',
          walletAddress,
          chainId: 42_431,
          call: {
            to: contractAddress,
            data: encodeTempoDripToInput(walletAddress, [tokenAddress]),
            gasLimit: '300000',
            value: '0',
          },
          idempotencyKey,
        }),
      });
      const body = response.json || {};
      expect(response.status).toBe(502);
      expect(body.code).toBe('tx_reverted');

      const record = await ledger.getRecordByIdempotencyKey(apiKeyCtx, idempotencyKey);
      const details = parseRecordDetails(record?.detailsJson);
      expect(record?.receiptStatus).toBe('reverted');
      expect(record?.templateId).toBe('tempo_testnet_onboarding');
      expect(record?.executorKind).toBe('evm_eoa');
      expect(record?.txOrExecutionRef).toBe(txHash);
      expect(record?.feeAmount).toBe(spendWeiDec);
      expect(details.execution?.gasUsed).toBe(gasUsedDec);
      expect(details.execution?.effectiveGasPrice).toBe(effectiveGasPriceDec);
      expect(details.billing?.estimatedSpendMinor).toBe('80');
      expect(details.billing?.settledSpendMinor).toBe('60');
      expect(details.billing?.released).toBe(false);

      expect(billing.events).toEqual([
        {
          kind: 'sponsored_execution_debit',
          walletId: 'alice.testnet',
          amountMinor: 60,
          pricingVersion: 'pricing-test-v1',
          sourceEventId: expect.stringMatching(/^sponsored_evm_call_debit:/),
        },
      ]);
    } finally {
      await server.close();
      await rpc.close();
    }
  });

  test('does not append sponsored debits when the EVM transaction never broadcasts', async () => {
    const apiKeys = createInMemoryConsoleApiKeyService();
    const { billing, ledger, prepaidReservations } = await makeAtomicSponsorshipServices();
    const runtimeSnapshots = createInMemoryConsoleRuntimeSnapshotService();
    await publishAllowedPolicy(runtimeSnapshots);
    const key = await createPublishableKey(apiKeys);
    const rpc = await startFakeTempoRpc({
      receiptStatus: '0x1',
      sendRawTransactionResult: '0xdeadbeef',
    });
    const server = await startSponsoredCallRouteServer({
      apiKeys,
      billing,
      ledger,
      runtimeSnapshots,
      prepaidReservations,
      config: makeRouteConfig(rpc.url),
    });
    const idempotencyKey = makeIdempotencyKey('rpc-rejected-no-charge');
    try {
      const response = await fetchJson(`${server.baseUrl}/sponsorships/evm/call`, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${key.secret}`,
          origin: allowedOrigin,
          'x-seams-environment-id': environmentId,
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          environmentId,
          nearAccountId: 'alice.testnet',
          walletAddress,
          chainId: 42_431,
          call: {
            to: contractAddress,
            data: encodeTempoDripToInput(walletAddress, [tokenAddress]),
            gasLimit: '300000',
            value: '0',
          },
          idempotencyKey,
        }),
      });
      expect(response.status).toBe(502);
      expect(response.json?.ok).toBe(false);

      const record = await ledger.getRecordByIdempotencyKey(apiKeyCtx, idempotencyKey);
      const details = parseRecordDetails(record?.detailsJson);
      expect(record?.receiptStatus).toBe('rpc_rejected');
      expect(record?.billingLedgerEntryId).toBeNull();
      expect(record?.charged).toBe(false);
      expect(record?.chargedReason).toBe('released_zero_spend');
      expect(record?.settledSpendMinor).toBe(0);
      expect(details.billing?.estimatedSpendMinor).toBe('80');
      expect(details.billing?.settledSpendMinor).toBe('0');
      expect(details.billing?.released).toBe(true);
      expect(billing.events).toEqual([]);
    } finally {
      await server.close();
      await rpc.close();
    }
  });

  test('replays reverted attempts with the original failure status', async () => {
    const apiKeys = createInMemoryConsoleApiKeyService();
    const { billing, ledger, prepaidReservations } = await makeAtomicSponsorshipServices();
    const runtimeSnapshots = createInMemoryConsoleRuntimeSnapshotService();
    await publishAllowedPolicy(runtimeSnapshots);
    const key = await createPublishableKey(apiKeys);
    const rpc = await startFakeTempoRpc({ receiptStatus: '0x0' });
    const server = await startSponsoredCallRouteServer({
      apiKeys,
      billing,
      ledger,
      runtimeSnapshots,
      prepaidReservations,
      config: makeRouteConfig(rpc.url),
    });
    const requestBody = {
      environmentId,
      nearAccountId: 'alice.testnet',
      walletAddress,
      chainId: 42_431,
      idempotencyKey: makeIdempotencyKey('reverted-replay'),
      call: {
        to: contractAddress,
        data: encodeTempoDripToInput(walletAddress, [tokenAddress]),
        gasLimit: '300000',
        value: '0',
      },
    };
    try {
      const first = await fetchJson(`${server.baseUrl}/sponsorships/evm/call`, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${key.secret}`,
          origin: allowedOrigin,
          'x-seams-environment-id': environmentId,
          'content-type': 'application/json',
        },
        body: JSON.stringify(requestBody),
      });
      const second = await fetchJson(`${server.baseUrl}/sponsorships/evm/call`, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${key.secret}`,
          origin: allowedOrigin,
          'x-seams-environment-id': environmentId,
          'content-type': 'application/json',
        },
        body: JSON.stringify(requestBody),
      });
      const replayed = second.json || {};
      expect(first.status).toBe(502);
      expect(second.status).toBe(502);
      expect(replayed.ok).toBe(false);
      expect(replayed.replayed).toBe(true);
      expect(replayed.code).toBe('tx_reverted');
      expect(replayed.txHash).toBe(txHash);
      expect(replayed.receiptStatus).toBe('reverted');
    } finally {
      await server.close();
      await rpc.close();
    }
  });

  test('requires a published runtime snapshot', async () => {
    const apiKeys = createInMemoryConsoleApiKeyService();
    const { billing, ledger, prepaidReservations } = await makeAtomicSponsorshipServices();
    const runtimeSnapshots = createInMemoryConsoleRuntimeSnapshotService();
    const key = await createPublishableKey(apiKeys);
    const rpc = await startFakeTempoRpc({ receiptStatus: '0x1' });
    const server = await startSponsoredCallRouteServer({
      apiKeys,
      billing,
      ledger,
      runtimeSnapshots,
      prepaidReservations,
      config: makeRouteConfig(rpc.url),
    });
    try {
      const response = await fetchJson(`${server.baseUrl}/sponsorships/evm/call`, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${key.secret}`,
          origin: allowedOrigin,
          'x-seams-environment-id': environmentId,
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          environmentId,
          nearAccountId: 'alice.testnet',
          walletAddress,
          chainId: 42_431,
          idempotencyKey: makeIdempotencyKey('missing-snapshot'),
          call: {
            to: contractAddress,
            data: encodeTempoDripToInput(walletAddress, [tokenAddress]),
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

  test('resolves a project-scoped runtime snapshot when the route only provides environmentId', async () => {
    const apiKeys = createInMemoryConsoleApiKeyService();
    const { billing, ledger, prepaidReservations } = await makeAtomicSponsorshipServices();
    const runtimeSnapshots = createInMemoryConsoleRuntimeSnapshotService();
    await publishAllowedPolicy(runtimeSnapshots, { projectId: 'project-alpha' });
    const key = await createPublishableKey(apiKeys);
    const rpc = await startFakeTempoRpc({ receiptStatus: '0x1' });
    const server = await startSponsoredCallRouteServer({
      apiKeys,
      billing,
      ledger,
      runtimeSnapshots,
      prepaidReservations,
      config: makeRouteConfig(rpc.url),
    });
    try {
      const response = await fetchJson(`${server.baseUrl}/sponsorships/evm/call`, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${key.secret}`,
          origin: allowedOrigin,
          'x-seams-environment-id': environmentId,
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          environmentId,
          nearAccountId: 'alice.testnet',
          walletAddress,
          chainId: 42_431,
          idempotencyKey: makeIdempotencyKey('project-snapshot'),
          call: {
            to: contractAddress,
            data: encodeTempoDripToInput(walletAddress, [tokenAddress]),
            gasLimit: '300000',
            value: '0',
          },
        }),
      });
      const body = response.json || {};
      expect(response.status).toBe(200);
      expect(body.ok).toBe(true);
      expect(body.policyId).toBe('policy_gs_onboarding');
    } finally {
      await server.close();
      await rpc.close();
    }
  });
});
