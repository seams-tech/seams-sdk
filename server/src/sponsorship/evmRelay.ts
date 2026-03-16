import type { Request, Response, Router as ExpressRouter } from 'express';
import { createEvmClient, parseEvmRpcHexQuantity } from '../../../client/src';
import type { ConsoleApiKeyService } from '../console/apiKeys';
import type { ConsoleBillingService } from '../console/billing';
import type { ConsoleRuntimeSnapshotService } from '../console/runtimeSnapshots';
import type { ConsoleSponsoredCallService } from '../console/sponsoredCalls';
import {
  type SponsoredEvmCall,
  type ServerEip1559UnsignedTx,
  computeEip1559TxHash,
  signSecp256k1Recoverable,
  encodeEip1559SignedTxFromSignature65,
} from '../index';
import { createRelayPublishableKeyAuthAdapter } from '../router/relayApiKeyAuth';
import { coerceRouterLogger, type RouterLogger } from '../router/logger';
import { handleRelaySponsoredEvmCall } from '../router/relaySponsoredEvmCall';
import type { RouteDefinition } from '../router/routeDefinitions';
import { sendExpressRouteResponse } from '../router/routeResponses';
import {
  normalizeEvmAddress,
  normalizeHex32,
  parseOptionalPositiveInteger,
  parseBigIntWithFallback,
} from './evm';

const DEFAULT_SPONSORED_EVM_RPC_URL = 'https://rpc.moderato.tempo.xyz';
const DEFAULT_SPONSORED_EVM_CHAIN_ID = 42_431;
const DEFAULT_MAX_PRIORITY_FEE_PER_GAS = 2_000_000_000n;
const DEFAULT_MAX_FEE_PER_GAS = 40_000_000_000n;
export const DEFAULT_SPONSORED_EVM_CALL_ROUTE = '/sponsorships/evm/call';
export const DEFAULT_SPONSORED_EVM_CALL_ROUTE_ID = 'sponsored_evm_call_v1';

export type SponsoredEvmCallExecutorConfig = {
  enabled: boolean;
  rpcUrl: string;
  chainId: number;
  sponsorAddress: `0x${string}`;
  sponsorPrivateKeyHex: `0x${string}`;
  maxPriorityFeePerGasFloor: bigint;
  maxFeePerGasFloor: bigint;
};

export type RegisterSponsoredEvmCallRouteArgs = {
  router: Pick<ExpressRouter, 'post' | 'options'>;
  apiKeys: ConsoleApiKeyService;
  billing: ConsoleBillingService;
  ledger: ConsoleSponsoredCallService;
  runtimeSnapshots: ConsoleRuntimeSnapshotService | null;
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
  config: SponsoredEvmCallExecutorConfig;
  chainId: number;
  call: SponsoredEvmCall;
}): Promise<SponsoredEvmExecution> {
  if (args.chainId !== args.config.chainId) {
    throw new Error(`Unsupported EVM chain for sponsor executor: ${args.chainId}`);
  }
  const client = createEvmClient({ rpcUrl: args.config.rpcUrl });
  const nonce = await client.getTransactionCount({
    address: args.config.sponsorAddress,
    blockTag: 'pending',
    timeoutMs: 10_000,
  });
  const feeCaps = await resolveFeeCaps({
    rpcUrl: args.config.rpcUrl,
    maxPriorityFeePerGasFloor: args.config.maxPriorityFeePerGasFloor,
    maxFeePerGasFloor: args.config.maxFeePerGasFloor,
  });
  const unsignedTx: ServerEip1559UnsignedTx = {
    chainId: args.config.chainId,
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
    privateKeyHexToBytes(args.config.sponsorPrivateKeyHex),
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

export function resolveSponsoredEvmCallConfigFromEnv(
  env: NodeJS.ProcessEnv,
): SponsoredEvmCallExecutorConfig | null {
  const enabled =
    ['1', 'true', 'yes', 'on'].includes(
      String(env.SPONSORED_EVM_CALL_ENABLED || '').trim().toLowerCase(),
    );
  if (!enabled) return null;

  const sponsorAddress = normalizeEvmAddress(env.SPONSORED_EVM_CALL_SPONSOR_ADDRESS);
  const sponsorPrivateKeyHex = normalizeHex32(env.SPONSORED_EVM_CALL_SPONSOR_PRIVATE_KEY_HEX);
  if (!sponsorAddress || !sponsorPrivateKeyHex) return null;

  return {
    enabled: true,
    rpcUrl: String(env.SPONSORED_EVM_CALL_RPC_URL || '').trim() || DEFAULT_SPONSORED_EVM_RPC_URL,
    chainId:
      parseOptionalPositiveInteger(env.SPONSORED_EVM_CALL_CHAIN_ID) || DEFAULT_SPONSORED_EVM_CHAIN_ID,
    sponsorAddress,
    sponsorPrivateKeyHex,
    maxPriorityFeePerGasFloor: parseBigIntWithFallback(
      env.SPONSORED_EVM_CALL_MAX_PRIORITY_FEE_PER_GAS,
      DEFAULT_MAX_PRIORITY_FEE_PER_GAS,
    ),
    maxFeePerGasFloor: parseBigIntWithFallback(
      env.SPONSORED_EVM_CALL_MAX_FEE_PER_GAS,
      DEFAULT_MAX_FEE_PER_GAS,
    ),
  };
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
          publishableKeyAuth,
          runtimeSnapshots: args.runtimeSnapshots,
          sponsoredCalls: args.ledger,
        },
      },
    });
    sendExpressRouteResponse(res, response);
  });
}
