import type { Request, Response, Router as ExpressRouter } from 'express';
import {
  createEvmClient,
  parseRpcHexQuantity as parseEvmRpcHexQuantity,
} from './evmRpcClient';
import type { ConsoleApiKeyService } from '../apiKeys';
import type { ConsoleBillingService } from '../billing';
import type { ConsoleBillingPrepaidReservationService } from '../billingPrepaidReservations';
import type { ConsoleObservabilityIngestionService } from '../observability';
import type { ConsoleRuntimeSnapshotService } from '../runtimeSnapshots';
import type { ConsoleSponsoredCallService } from '../sponsoredCalls';
import type { ConsoleSponsorshipSpendCapService } from '../sponsorshipSpendCaps';
import type { ConsoleWebhookService } from '../webhooks';
import {
  type ServerEip1559UnsignedTx,
  computeEip1559TxHash,
  secp256k1PrivateKey32ToPublicKey33,
  secp256k1PublicKey33ToEthereumAddress,
  signSecp256k1Recoverable,
  encodeEip1559SignedTxFromSignature65,
} from '../../core/ThresholdService/ethSignerWasm';
import type { SponsorshipSpendPricingService } from './spendCaps';
import { createRouterApiPublishableKeyAuthAdapter } from '../router/routerApiKeyAuth';
import { coerceRouterLogger, type RouterLogger } from '../../router/logger';
import { handleRouterApiSponsoredEvmCall } from '../../router/routerApiSponsoredEvmCall';
import type { RouteDefinition } from '../../router/routeDefinitions';
import { sendExpressRouteResponse } from '../../router/routeResponses';
import {
  normalizeEvmAddress,
  type SponsoredEvmCall,
} from './evm';
import { DEFAULT_SPONSORED_EVM_CALL_ROUTE } from './evmRoutes';
import type {
  SponsoredEvmCallExecutorConfig,
  SponsoredEvmChainExecutorConfig,
  SponsoredEvmExecutionAdapter,
  SponsoredEvmExecutionAdapterResolver,
  SponsoredEvmExecutionResult,
} from './evmExecutorTypes';
import { resolveSponsoredEvmCallConfigFromRecord } from './evmExecutorConfig';

export {
  DEFAULT_SPONSORED_EVM_CALL_ROUTE,
  DEFAULT_SPONSORED_EVM_CALL_ROUTE_ID,
} from './evmRoutes';

export type RegisterSponsoredEvmCallRouteArgs = {
  router: Pick<ExpressRouter, 'post' | 'options'>;
  apiKeys: ConsoleApiKeyService;
  billing: ConsoleBillingService;
  ledger: ConsoleSponsoredCallService;
  runtimeSnapshots: ConsoleRuntimeSnapshotService | null;
  spendCaps?: ConsoleSponsorshipSpendCapService | null;
  prepaidReservations?: ConsoleBillingPrepaidReservationService | null;
  pricing?: SponsorshipSpendPricingService | null;
  webhooks?: ConsoleWebhookService | null;
  observabilityIngestion?: ConsoleObservabilityIngestionService | null;
  corsOrigins: string[];
  config: SponsoredEvmCallExecutorConfig;
  route?: string;
  logger?: RouterLogger;
};

function normalizeTxHashOrThrow(value: unknown): `0x${string}` {
  const normalized = String(value || '').trim();
  if (!/^0x[0-9a-fA-F]{64}$/.test(normalized)) {
    throw new Error(`Invalid transaction hash: ${normalized || 'empty'}`);
  }
  return normalized as `0x${string}`;
}

function normalizeTxHashOrNull(value: unknown): `0x${string}` | null {
  const normalized = String(value || '').trim();
  if (!/^0x[0-9a-fA-F]{64}$/.test(normalized)) return null;
  return normalized as `0x${string}`;
}

function bytesToHex(bytes: Uint8Array): `0x${string}` {
  return `0x${Array.from(bytes)
    .map((entry) => entry.toString(16).padStart(2, '0'))
    .join('')}` as `0x${string}`;
}

function privateKeyHexToBytes(value: `0x${string}`): Uint8Array {
  return Uint8Array.from(Buffer.from(value.slice(2), 'hex'));
}

async function deriveEvmAddressFromPrivateKeyHex(
  privateKeyHex: `0x${string}`,
): Promise<`0x${string}`> {
  const publicKey33 = await secp256k1PrivateKey32ToPublicKey33(privateKeyHexToBytes(privateKeyHex));
  const addressHex = (await secp256k1PublicKey33ToEthereumAddress(publicKey33)) as `0x${string}`;
  const normalized = normalizeEvmAddress(addressHex);
  if (!normalized) {
    throw new Error('Failed to derive sponsor address from private key');
  }
  return normalized;
}

async function resolveFeeCaps(args: {
  rpcUrl: string;
  maxPriorityFeePerGasFloor: bigint;
  maxFeePerGasFloor: bigint;
}): Promise<{ maxPriorityFeePerGas: bigint; maxFeePerGas: bigint }> {
  const client = createEvmClient({ rpcUrl: args.rpcUrl });
  const [latestBlock, priorityFeeHex, gasPriceHex] = await Promise.all([
    client.getBlockByNumber({ blockTag: 'latest', timeoutMs: 6_000 }).catch(() => null),
    client.request<string>({ method: 'eth_maxPriorityFeePerGas', params: [], timeoutMs: 6_000 }).catch(
      () => null,
    ),
    client.request<string>({ method: 'eth_gasPrice', params: [], timeoutMs: 6_000 }).catch(() => null),
  ]);

  const baseFee = (() => {
    const raw = String(latestBlock?.baseFeePerGas || '').trim();
    if (!/^0x[0-9a-fA-F]+$/.test(raw)) return null;
    try {
      return parseEvmRpcHexQuantity(raw, 'baseFeePerGas');
    } catch {
      return null;
    }
  })();
  const priorityFee = (() => {
    const raw = String(priorityFeeHex || '').trim();
    if (!/^0x[0-9a-fA-F]+$/.test(raw)) return null;
    try {
      return parseEvmRpcHexQuantity(raw, 'eth_maxPriorityFeePerGas');
    } catch {
      return null;
    }
  })();
  const gasPrice = (() => {
    const raw = String(gasPriceHex || '').trim();
    if (!/^0x[0-9a-fA-F]+$/.test(raw)) return null;
    try {
      return parseEvmRpcHexQuantity(raw, 'eth_gasPrice');
    } catch {
      return null;
    }
  })();

  const resolvedPriority =
    priorityFee ??
    (gasPrice && gasPrice > 0n ? gasPrice / 10n : args.maxPriorityFeePerGasFloor);
  const maxPriorityFeePerGas =
    resolvedPriority > args.maxPriorityFeePerGasFloor
      ? resolvedPriority
      : args.maxPriorityFeePerGasFloor;
  const dynamicMaxFeePerGas =
    baseFee && baseFee > 0n
      ? baseFee * 2n + maxPriorityFeePerGas
      : gasPrice && gasPrice > 0n
        ? gasPrice * 2n
        : 0n;
  const maxFeePerGas =
    dynamicMaxFeePerGas > args.maxFeePerGasFloor ? dynamicMaxFeePerGas : args.maxFeePerGasFloor;
  return {
    maxPriorityFeePerGas:
      maxPriorityFeePerGas < maxFeePerGas ? maxPriorityFeePerGas : maxFeePerGas / 2n,
    maxFeePerGas,
  };
}

export async function executeSponsoredEvmCall(args: {
  executor: SponsoredEvmChainExecutorConfig;
  call: SponsoredEvmCall;
}): Promise<SponsoredEvmExecutionResult> {
  const client = createEvmClient({ rpcUrl: args.executor.rpcUrl });
  const nonce = await client.getTransactionCount({
    address: args.executor.sponsorAddress,
    blockTag: 'pending',
    timeoutMs: 10_000,
  });
  const feeCaps = await resolveFeeCaps({
    rpcUrl: args.executor.rpcUrl,
    maxPriorityFeePerGasFloor: args.executor.maxPriorityFeePerGasFloor,
    maxFeePerGasFloor: args.executor.maxFeePerGasFloor,
  });
  const unsignedTx: ServerEip1559UnsignedTx = {
    chainId: args.executor.chainId,
    nonce,
    maxPriorityFeePerGas: feeCaps.maxPriorityFeePerGas,
    maxFeePerGas: feeCaps.maxFeePerGas,
    gasLimit: args.call.gasLimit,
    to: args.call.to,
    value: args.call.value,
    data: args.call.data,
    accessList: [],
  };
  const digest32 = await computeEip1559TxHash(unsignedTx);
  const signature65 = await signSecp256k1Recoverable(
    digest32,
    privateKeyHexToBytes(args.executor.sponsorPrivateKeyHex),
  );
  const rawTxHex = bytesToHex(
    await encodeEip1559SignedTxFromSignature65({
      tx: unsignedTx,
      signature65,
    }),
  );
  const txHash = normalizeTxHashOrThrow(
    await client.request<string>({
      method: 'eth_sendRawTransaction',
      params: [rawTxHex],
      timeoutMs: 15_000,
    }),
  );
  await client.waitForTransactionReceipt({
    txHash,
    timeoutMs: 90_000,
    pollIntervalMs: 1_250,
    confirmations: 1,
    maxFeePerGasHint: unsignedTx.maxFeePerGas,
  });
  const receipt = await client.request<{
    status?: string | null;
    gasUsed?: string | null;
    effectiveGasPrice?: string | null;
    gasPrice?: string | null;
  } | null>({
    method: 'eth_getTransactionReceipt',
    params: [txHash],
    timeoutMs: 10_000,
  });
  if (!receipt) {
    throw new Error(`Sponsored EVM transaction ${txHash} finalized, but receipt could not be loaded`);
  }
  const gasUsed = parseEvmRpcHexQuantity(String(receipt.gasUsed || '0x0'), 'gasUsed');
  const effectiveGasPrice = parseEvmRpcHexQuantity(
    String(receipt.effectiveGasPrice || receipt.gasPrice || '0x0'),
    'effectiveGasPrice',
  );
  const execution = {
    txHash,
    gasUsed: gasUsed.toString(10),
    effectiveGasPrice: effectiveGasPrice.toString(10),
    feeAmount: (gasUsed * effectiveGasPrice).toString(10),
  };
  const status = String(receipt.status || '').trim().toLowerCase();
  if (status && status !== '0x1' && status !== '0x01') {
    const reverted = new Error(`Sponsored EVM transaction reverted (${txHash})`) as Error & {
      code?: string;
      txHash?: `0x${string}`;
      gasUsed?: string;
      effectiveGasPrice?: string;
      feeAmount?: string;
    };
    reverted.code = 'tx_reverted';
    reverted.txHash = txHash;
    reverted.gasUsed = execution.gasUsed;
    reverted.effectiveGasPrice = execution.effectiveGasPrice;
    reverted.feeAmount = execution.feeAmount;
    throw reverted;
  }
  return execution;
}

export async function resolveSponsoredEvmCallConfigFromEnv(
  env: NodeJS.ProcessEnv,
): Promise<SponsoredEvmCallExecutorConfig | null> {
  return await resolveSponsoredEvmCallConfigFromRecord({
    env: {
      SPONSORED_EVM_EXECUTORS_JSON: env.SPONSORED_EVM_EXECUTORS_JSON,
    },
    deriveSponsorAddress: deriveEvmAddressFromPrivateKeyHex,
  });
}

export function resolveSponsoredEvmExecutorForChain(
  config: SponsoredEvmCallExecutorConfig | null,
  chainId: number,
): SponsoredEvmChainExecutorConfig | null {
  if (!config) return null;
  return config.executorsByChain.get(chainId) || null;
}

class ExpressSponsoredEvmExecutionAdapter implements SponsoredEvmExecutionAdapter {
  readonly executorKind = 'evm_eoa' as const;

  readonly meta: {
    readonly chainId: number;
    readonly sponsorAddress: `0x${string}`;
  };

  constructor(
    private readonly executor: SponsoredEvmChainExecutorConfig,
    private readonly call: SponsoredEvmCall,
  ) {
    this.meta = {
      chainId: executor.chainId,
      sponsorAddress: executor.sponsorAddress,
    };
  }

  async execute(): Promise<SponsoredEvmExecutionResult> {
    return await executeSponsoredEvmCall({
      executor: this.executor,
      call: this.call,
    });
  }
}

const resolveSponsoredEvmExecutionAdapterForRoute: SponsoredEvmExecutionAdapterResolver = (
  input,
) => {
  const executor = resolveSponsoredEvmExecutorForChain(input.config, input.chainId);
  if (!executor) return null;
  return new ExpressSponsoredEvmExecutionAdapter(executor, input.call);
};

export function registerSponsoredEvmCallRoute(args: RegisterSponsoredEvmCallRouteArgs): void {
  const logger = coerceRouterLogger(args.logger || console);
  const routePath = String(args.route || '').trim() || DEFAULT_SPONSORED_EVM_CALL_ROUTE;
  const route: RouteDefinition = {
    id: 'sponsored_evm_call',
    surface: 'relay',
    method: 'POST',
    path: routePath,
    auth: {
      plane: 'api_credentials',
      credentials: ['publishable_key'],
      environmentBinding: 'required',
      originBinding: 'required',
    },
    metering: { kind: 'gas', ledger: 'evm' },
    requiredServices: ['routerApiSponsoredEvmCall'],
    summary: 'Execute a sponsored EVM call',
  };
  const publishableKeyAuth = createRouterApiPublishableKeyAuthAdapter(args.apiKeys);

  args.router.options(route.path, (_req: Request, res: Response) => {
    res.status(204).send();
  });

  args.router.post(route.path, async (req: Request, res: Response) => {
    const response = await handleRouterApiSponsoredEvmCall({
      body: req.body,
      headers: (req.headers || {}) as Record<string, string | string[] | undefined>,
      logger,
      origin: String(req.headers?.origin || req.headers?.Origin || '').trim() || undefined,
      route,
      services: {
        routerApiSponsoredEvmCall: {
          billing: args.billing,
          config: args.config,
          resolveExecutionAdapter: resolveSponsoredEvmExecutionAdapterForRoute,
          observabilityIngestion: args.observabilityIngestion || null,
          prepaidReservations: args.prepaidReservations || null,
          publishableKeyAuth,
          pricing: args.pricing || null,
          runtimeSnapshots: args.runtimeSnapshots,
          spendCaps: args.spendCaps || null,
          sponsoredCalls: args.ledger,
          webhooks: args.webhooks || null,
        },
      },
    });
    sendExpressRouteResponse(res, response);
  });
}
