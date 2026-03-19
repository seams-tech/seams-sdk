import type { Request, Response, Router as ExpressRouter } from 'express';
import { createEvmClient, parseEvmRpcHexQuantity } from '../../../client/src';
import type { ConsoleApiKeyService } from '../console/apiKeys';
import type { ConsoleBillingService } from '../console/billing';
import type { ConsoleBillingPrepaidReservationService } from '../console/billingPrepaidReservations';
import type { ConsoleObservabilityIngestionService } from '../console/observability';
import type { ConsoleRuntimeSnapshotService } from '../console/runtimeSnapshots';
import type { ConsoleSponsoredCallService } from '../console/sponsoredCalls';
import type { ConsoleSponsorshipSpendCapService } from '../console/sponsorshipSpendCaps';
import type { ConsoleWebhookService } from '../console/webhooks';
import {
  type SponsoredEvmCall,
  type ServerEip1559UnsignedTx,
  computeEip1559TxHash,
  secp256k1PrivateKey32ToPublicKey33,
  secp256k1PublicKey33ToEthereumAddress,
  signSecp256k1Recoverable,
  encodeEip1559SignedTxFromSignature65,
} from '../index';
import type { SponsorshipSpendPricingService } from './spendCaps';
import { createRelayPublishableKeyAuthAdapter } from '../router/relayApiKeyAuth';
import { coerceRouterLogger, type RouterLogger } from '../router/logger';
import { handleRelaySponsoredEvmCall } from '../router/relaySponsoredEvmCall';
import type { RouteDefinition } from '../router/routeDefinitions';
import { sendExpressRouteResponse } from '../router/routeResponses';
import {
  normalizeEvmAddress,
  normalizeHex32,
  parseOptionalPositiveInteger,
} from './evm';

const DEFAULT_SPONSORED_EVM_RPC_URL = 'https://rpc.moderato.tempo.xyz';
const DEFAULT_SPONSORED_EVM_CHAIN_ID = 42_431;
const DEFAULT_MAX_PRIORITY_FEE_PER_GAS = 2_000_000_000n;
const DEFAULT_MAX_FEE_PER_GAS = 40_000_000_000n;
export const DEFAULT_SPONSORED_EVM_CALL_ROUTE = '/sponsorships/evm/call';
export const DEFAULT_SPONSORED_EVM_CALL_ROUTE_ID = 'sponsored_evm_call_v1';

export type SponsoredEvmChainExecutorConfig = {
  chainId: number;
  rpcUrl: string;
  sponsorAddress: `0x${string}`;
  sponsorPrivateKeyHex: `0x${string}`;
  maxPriorityFeePerGasFloor: bigint;
  maxFeePerGasFloor: bigint;
};

export type SponsoredEvmCallExecutorConfig = {
  executorsByChain: ReadonlyMap<number, SponsoredEvmChainExecutorConfig>;
};

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
  config: SponsoredEvmCallExecutorConfig | null;
  route?: string;
  logger?: RouterLogger;
};

type SponsoredEvmExecution = {
  txHash: `0x${string}`;
  gasUsed: string;
  effectiveGasPrice: string;
  feeAmount: string;
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

function normalizeSponsoredEvmExecutorKind(value: unknown): 'evm_eoa' | null {
  const normalized = String(value || '').trim();
  if (!normalized) return 'evm_eoa';
  return normalized === 'evm_eoa' ? 'evm_eoa' : null;
}

function parseOptionalUnsignedBigIntLiteral(value: unknown): bigint | null {
  if (value === undefined || value === null) return null;
  const normalized = String(value).trim();
  if (!normalized) return null;
  try {
    const parsed = BigInt(normalized);
    return parsed >= 0n ? parsed : null;
  } catch {
    return null;
  }
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
}): Promise<SponsoredEvmExecution> {
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
  const raw = String(env.SPONSORED_EVM_EXECUTORS_JSON || '').trim();
  if (!raw) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null;

  const executors = new Map<number, SponsoredEvmChainExecutorConfig>();
  for (const [chainIdRaw, value] of Object.entries(parsed as Record<string, unknown>)) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) continue;
    const row = value as Record<string, unknown>;
    const kind = normalizeSponsoredEvmExecutorKind(row.kind);
    const chainId =
      parseOptionalPositiveInteger(chainIdRaw) ||
      parseOptionalPositiveInteger(row.chainId) ||
      undefined;
    const sponsorPrivateKeyHex = normalizeHex32(row.sponsorPrivateKeyHex);
    if (!kind || !chainId || !sponsorPrivateKeyHex) continue;
    if (executors.has(chainId)) return null;
    const maxPriorityFeePerGasFloor =
      parseOptionalUnsignedBigIntLiteral(row.maxPriorityFeePerGasFloor);
    if (row.maxPriorityFeePerGasFloor !== undefined && maxPriorityFeePerGasFloor === null) continue;
    const maxFeePerGasFloor =
      parseOptionalUnsignedBigIntLiteral(row.maxFeePerGasFloor);
    if (row.maxFeePerGasFloor !== undefined && maxFeePerGasFloor === null) continue;
    let sponsorAddress: `0x${string}`;
    try {
      sponsorAddress = await deriveEvmAddressFromPrivateKeyHex(sponsorPrivateKeyHex);
    } catch {
      continue;
    }
    executors.set(chainId, {
      chainId,
      rpcUrl:
        String(row.rpcUrl || '').trim() ||
        (chainId === DEFAULT_SPONSORED_EVM_CHAIN_ID ? DEFAULT_SPONSORED_EVM_RPC_URL : ''),
      sponsorAddress,
      sponsorPrivateKeyHex,
      maxPriorityFeePerGasFloor:
        maxPriorityFeePerGasFloor ?? DEFAULT_MAX_PRIORITY_FEE_PER_GAS,
      maxFeePerGasFloor:
        maxFeePerGasFloor ?? DEFAULT_MAX_FEE_PER_GAS,
    });
  }

  if (executors.size === 0) return null;
  for (const executor of executors.values()) {
    if (!executor.rpcUrl) return null;
  }
  return {
    executorsByChain: executors,
  };
}

export function resolveSponsoredEvmExecutorForChain(
  config: SponsoredEvmCallExecutorConfig | null,
  chainId: number,
): SponsoredEvmChainExecutorConfig | null {
  if (!config) return null;
  return config.executorsByChain.get(chainId) || null;
}

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
    requiredServices: ['relaySponsoredEvmCall'],
    summary: 'Execute a sponsored EVM call',
  };
  const publishableKeyAuth =
    typeof args.apiKeys.authenticatePublishableKey === 'function'
      ? createRelayPublishableKeyAuthAdapter(args.apiKeys)
      : null;

  args.router.options(route.path, (_req: Request, res: Response) => {
    res.status(204).send();
  });

  args.router.post(route.path, async (req: Request, res: Response) => {
    const response = await handleRelaySponsoredEvmCall({
      body: req.body,
      headers: (req.headers || {}) as Record<string, string | string[] | undefined>,
      logger,
      origin: String(req.headers?.origin || req.headers?.Origin || '').trim() || undefined,
      route,
      services: {
        relaySponsoredEvmCall: {
          billing: args.billing,
          config: args.config,
          corsOrigins: args.corsOrigins,
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
