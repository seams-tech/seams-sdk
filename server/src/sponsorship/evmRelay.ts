import type { Request, Response, Router as ExpressRouter } from 'express';
import { createEvmClient, parseEvmRpcHexQuantity } from '../../../client/src';
import type { ConsoleApiKeyService } from '../console/apiKeys';
import type { ConsoleBillingService } from '../console/billing';
import type { ConsoleRuntimeSnapshotService } from '../console/runtimeSnapshots';
import type { ConsoleSponsoredCallService } from '../console/sponsoredCalls';
import {
  type SponsoredEvmCall,
  type SponsoredEvmCallRequest,
  type ServerEip1559UnsignedTx,
  computeEip1559TxHash,
  signSecp256k1Recoverable,
  encodeEip1559SignedTxFromSignature65,
} from '../index';
import {
  normalizeEvmAddress,
  normalizeHex32,
  parseOptionalPositiveInteger,
  parseBigIntWithFallback,
  parseSponsoredEvmCallRequest,
  parseResolvedSponsoredEvmCallConfigs,
  matchResolvedSponsoredEvmCallConfig,
  createSponsoredEvmSourceEventId,
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
  logger?: Pick<Console, 'info' | 'warn' | 'error'>;
};

type SponsoredEvmExecution = {
  txHash: `0x${string}`;
  gasUsed: string;
  effectiveGasPrice: string;
  feeAmount: string;
};

type SponsoredEvmCallDetails = {
  nearAccountId: string;
  walletAddress: `0x${string}`;
  chainId: number;
  call: {
    to: `0x${string}`;
    data: `0x${string}`;
    gasLimit: string;
    valueWei: string;
    selector: `0x${string}`;
  };
  execution: {
    txHash: string | null;
    gasUsed: string | null;
    effectiveGasPrice: string | null;
    feeAmount: string;
  };
};

function normalizeOrigin(value: unknown): string {
  try {
    const parsed = new URL(String(value || '').trim());
    parsed.hash = '';
    parsed.search = '';
    parsed.pathname = '/';
    return parsed.toString().replace(/\/$/, '');
  } catch {
    return '';
  }
}

function extractBearerCredential(headers: Request['headers'] | undefined): string | null {
  const raw = String(headers?.authorization || '').trim();
  if (!raw) return null;
  if (!raw.toLowerCase().startsWith('bearer ')) return null;
  const value = raw.slice('bearer '.length).trim();
  return value || null;
}

function applyCorsHeaders(res: Response, requestOrigin: string, allowedOrigins: readonly string[]): void {
  const headers: Record<string, string> = {
    'access-control-allow-methods': 'POST, OPTIONS',
    'access-control-allow-headers': 'authorization, content-type, x-tatchi-environment-id',
  };
  if (requestOrigin && allowedOrigins.includes(requestOrigin)) {
    headers['access-control-allow-origin'] = requestOrigin;
    headers.vary = 'Origin';
  }
  res.set(headers);
}

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

function buildAccountRef(nearAccountId: string): string {
  return `near:${nearAccountId}`;
}

function buildTargetRef(chainId: number, to: `0x${string}`): string {
  return `evm:${chainId}:${to.toLowerCase()}`;
}

function buildSponsorRef(chainId: number, sponsorAddress: `0x${string}`): string {
  return `evm:${chainId}:${sponsorAddress.toLowerCase()}`;
}

function buildDetailsJson(input: {
  request: SponsoredEvmCallRequest;
  selector: `0x${string}`;
  execution: {
    txHash: string | null;
    gasUsed: string | null;
    effectiveGasPrice: string | null;
    feeAmount: string;
  };
}): string {
  const details: SponsoredEvmCallDetails = {
    nearAccountId: input.request.nearAccountId,
    walletAddress: input.request.walletAddress,
    chainId: input.request.chainId,
    call: {
      to: input.request.call.to,
      data: input.request.call.data,
      gasLimit: input.request.call.gasLimit.toString(10),
      valueWei: input.request.call.value.toString(10),
      selector: input.selector,
    },
    execution: {
      txHash: input.execution.txHash,
      gasUsed: input.execution.gasUsed,
      effectiveGasPrice: input.execution.effectiveGasPrice,
      feeAmount: input.execution.feeAmount,
    },
  };
  return JSON.stringify(details);
}

function parseDetailsJson(value: string): SponsoredEvmCallDetails | null {
  try {
    const parsed = JSON.parse(value) as Record<string, unknown>;
    const nearAccountId = String(parsed.nearAccountId || '').trim();
    const walletAddress = normalizeEvmAddress(parsed.walletAddress);
    const chainId = parseOptionalPositiveInteger(parsed.chainId);
    const call =
      parsed.call && typeof parsed.call === 'object' && !Array.isArray(parsed.call)
        ? (parsed.call as Record<string, unknown>)
        : null;
    const execution =
      parsed.execution && typeof parsed.execution === 'object' && !Array.isArray(parsed.execution)
        ? (parsed.execution as Record<string, unknown>)
        : null;
    const to = normalizeEvmAddress(call?.to);
    const data = /^0x(?:[0-9a-fA-F]{2})*$/.test(String(call?.data || '').trim())
      ? (String(call?.data || '').trim() as `0x${string}`)
      : null;
    const selector = /^0x[0-9a-fA-F]{8}$/.test(String(call?.selector || '').trim())
      ? (String(call?.selector || '').trim().toLowerCase() as `0x${string}`)
      : null;
    if (!nearAccountId || !walletAddress || !chainId || !to || !data || !selector) return null;
    return {
      nearAccountId,
      walletAddress,
      chainId,
      call: {
        to,
        data,
        gasLimit: String(call?.gasLimit || '').trim() || '0',
        valueWei: String(call?.valueWei || '').trim() || '0',
        selector,
      },
      execution: {
        txHash: String(execution?.txHash || '').trim() || null,
        gasUsed: String(execution?.gasUsed || '').trim() || null,
        effectiveGasPrice: String(execution?.effectiveGasPrice || '').trim() || null,
        feeAmount: String(execution?.feeAmount || '').trim() || '0',
      },
    };
  } catch {
    return null;
  }
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
  const logger = args.logger || console;
  const route = String(args.route || '').trim() || DEFAULT_SPONSORED_EVM_CALL_ROUTE;

  args.router.options(route, (req: Request, res: Response) => {
    const origin = normalizeOrigin(req.headers?.origin);
    applyCorsHeaders(res, origin, args.corsOrigins);
    res.status(204).send();
  });

  args.router.post(route, async (req: Request, res: Response) => {
    const origin = normalizeOrigin(req.headers?.origin);
    applyCorsHeaders(res, origin, args.corsOrigins);

    if (!origin || !args.corsOrigins.includes(origin)) {
      res.status(403).json({ ok: false, code: 'origin_not_allowed', message: 'Origin is not allowed' });
      return;
    }
    if (!args.config?.enabled) {
      res.status(503).json({
        ok: false,
        code: 'sponsored_evm_call_disabled',
        message: 'Sponsored EVM execution is not configured on this server',
      });
      return;
    }
    if (!args.runtimeSnapshots) {
      res.status(503).json({
        ok: false,
        code: 'runtime_snapshots_unavailable',
        message: 'Runtime snapshots are not configured on this server',
      });
      return;
    }
    if (typeof args.apiKeys.authenticatePublishableKey !== 'function') {
      res.status(503).json({
        ok: false,
        code: 'publishable_key_auth_unavailable',
        message: 'Publishable key authentication is not configured on this server',
      });
      return;
    }

    const authorization = extractBearerCredential(req.headers);
    if (!authorization) {
      res.status(401).json({
        ok: false,
        code: 'publishable_key_missing',
        message: 'Missing publishable key',
      });
      return;
    }

    let parsedBody: SponsoredEvmCallRequest;
    try {
      const body =
        req.body && typeof req.body === 'object' && !Array.isArray(req.body)
          ? ({
              ...(req.body as Record<string, unknown>),
              environmentId:
                req.headers?.['x-tatchi-environment-id'] ||
                req.headers?.['x-environment-id'] ||
                (req.body as Record<string, unknown>).environmentId,
            } as Record<string, unknown>)
          : req.body;
      parsedBody = parseSponsoredEvmCallRequest(body);
    } catch (error: unknown) {
      res.status(400).json({
        ok: false,
        code: 'invalid_body',
        message: error instanceof Error ? error.message : 'Invalid request body',
      });
      return;
    }

    const authResult = await args.apiKeys.authenticatePublishableKey({
      secret: authorization,
      origin,
      environmentId: parsedBody.environmentId,
    });
    if (!authResult.ok) {
      res.status(authResult.status).json({
        ok: false,
        code: authResult.code,
        message: authResult.message,
      });
      return;
    }

    const sponsorshipCtx = {
      orgId: authResult.apiKey.orgId,
      actorUserId: 'sponsored-call-executor',
      roles: ['system'],
    };

    const latestSnapshot = await args.runtimeSnapshots.getLatestSnapshot(sponsorshipCtx, {
      environmentId: parsedBody.environmentId,
    });
    if (!latestSnapshot) {
      res.status(503).json({
        ok: false,
        code: 'runtime_snapshot_not_found',
        message: 'No runtime snapshot is available for this environment',
      });
      return;
    }

    const configs = parseResolvedSponsoredEvmCallConfigs(latestSnapshot.payload);
    const matched = matchResolvedSponsoredEvmCallConfig({
      configs,
      chainId: parsedBody.chainId,
      call: parsedBody.call,
    });
    if (!matched) {
      res.status(403).json({
        ok: false,
        code: 'sponsorship_policy_not_matched',
        message: 'Requested call is not sponsorable under the active policy',
      });
      return;
    }
    if (parsedBody.chainId !== args.config.chainId) {
      res.status(503).json({
        ok: false,
        code: 'sponsor_chain_misconfigured',
        message: `Sponsor executor is configured for chain ${args.config.chainId}, not ${parsedBody.chainId}`,
      });
      return;
    }

    const sourceEventId =
      parsedBody.sourceEventId ||
      createSponsoredEvmSourceEventId(
        parsedBody.nearAccountId,
        parsedBody.walletAddress,
        parsedBody.chainId,
        parsedBody.call,
      );

    const existing = await args.ledger.getRecordBySourceEventId(sponsorshipCtx, sourceEventId);
    if (existing) {
      const details = parseDetailsJson(existing.detailsJson);
      const existingFeeAmount = String(existing.feeAmount || '').trim() || '0';
      res.status(existing.receiptStatus === 'success' ? 200 : 409).json({
        ok: existing.receiptStatus === 'success',
        replayed: true,
        recordId: existing.id,
        sponsorshipConfigId: String(existing.sponsorshipConfigId || '').trim() || null,
        txHash: existing.txOrExecutionRef,
        spendWei: existingFeeAmount,
        gasUsed: details?.execution.gasUsed || null,
        effectiveGasPrice: details?.execution.effectiveGasPrice || null,
        receiptStatus: existing.receiptStatus,
        errorCode: existing.errorCode,
        message:
          existing.receiptStatus === 'success'
            ? 'Sponsored EVM call already finalized for this request'
            : existing.errorMessage || 'Sponsored EVM call already failed for this request',
      });
      return;
    }

    try {
      const execution = await executeSponsoredEvmCall({
        config: args.config,
        chainId: parsedBody.chainId,
        call: parsedBody.call,
      });
      const record = await args.ledger.createRecord(sponsorshipCtx, {
        environmentId: parsedBody.environmentId,
        apiKeyId: authResult.apiKey.id,
        apiKeyKind: 'publishable_key',
        route: DEFAULT_SPONSORED_EVM_CALL_ROUTE_ID,
        sponsorshipConfigId: matched.config.sponsorshipConfigId,
        sponsorshipConfigNameAtEvent: matched.config.sponsorshipConfigName,
        chainFamily: 'evm',
        intentKind: 'evm_call',
        accountRef: buildAccountRef(parsedBody.nearAccountId),
        targetRef: buildTargetRef(parsedBody.chainId, parsedBody.call.to),
        sponsorRef: buildSponsorRef(parsedBody.chainId, args.config.sponsorAddress),
        txOrExecutionRef: execution.txHash,
        receiptStatus: 'success',
        feeUnit: 'wei',
        feeAmount: execution.feeAmount,
        detailsJson: buildDetailsJson({
          request: parsedBody,
          selector: matched.selector,
          execution: {
            txHash: execution.txHash,
            gasUsed: execution.gasUsed,
            effectiveGasPrice: execution.effectiveGasPrice,
            feeAmount: execution.feeAmount,
          },
        }),
        sourceEventId,
      });
      await args.billing.recordUsageEvent(sponsorshipCtx, {
        walletId: parsedBody.nearAccountId,
        action: 'contract_call',
        succeeded: true,
        occurredAt: new Date().toISOString(),
        sourceEventId: `sponsored_evm_call_usage:${record.id}`,
      });
      res.status(200).json({
        ok: true,
        replayed: false,
        recordId: record.id,
        sponsorshipConfigId: matched.config.sponsorshipConfigId,
        txHash: execution.txHash,
        spendWei: execution.feeAmount,
        gasUsed: execution.gasUsed,
        effectiveGasPrice: execution.effectiveGasPrice,
      });
    } catch (error: unknown) {
      const message =
        error instanceof Error ? error.message : String(error || 'Sponsored EVM call failed');
      const errorCode =
        error && typeof error === 'object' && 'code' in error ? String((error as { code?: unknown }).code || '') : '';
      const txHash =
        error && typeof error === 'object' && 'txHash' in error
          ? normalizeTxHashOrNull((error as { txHash?: unknown }).txHash)
          : null;
      const gasUsed =
        error && typeof error === 'object' && 'gasUsed' in error
          ? String((error as { gasUsed?: unknown }).gasUsed || '').trim() || null
          : null;
      const effectiveGasPrice =
        error && typeof error === 'object' && 'effectiveGasPrice' in error
          ? String((error as { effectiveGasPrice?: unknown }).effectiveGasPrice || '').trim() || null
          : null;
      const feeAmount =
        error && typeof error === 'object' && 'feeAmount' in error
          ? String((error as { feeAmount?: unknown }).feeAmount || '').trim() || '0'
          : '0';
      const record = await args.ledger.createRecord(sponsorshipCtx, {
        environmentId: parsedBody.environmentId,
        apiKeyId: authResult.apiKey.id,
        apiKeyKind: 'publishable_key',
        route: DEFAULT_SPONSORED_EVM_CALL_ROUTE_ID,
        sponsorshipConfigId: matched.config.sponsorshipConfigId,
        sponsorshipConfigNameAtEvent: matched.config.sponsorshipConfigName,
        chainFamily: 'evm',
        intentKind: 'evm_call',
        accountRef: buildAccountRef(parsedBody.nearAccountId),
        targetRef: buildTargetRef(parsedBody.chainId, parsedBody.call.to),
        sponsorRef: buildSponsorRef(parsedBody.chainId, args.config.sponsorAddress),
        txOrExecutionRef: txHash,
        receiptStatus:
          errorCode === 'tx_reverted'
            ? 'reverted'
            : txHash
              ? 'broadcast_failed'
              : 'rpc_rejected',
        feeUnit: 'wei',
        feeAmount,
        detailsJson: buildDetailsJson({
          request: parsedBody,
          selector: matched.selector,
          execution: {
            txHash,
            gasUsed,
            effectiveGasPrice,
            feeAmount,
          },
        }),
        errorCode: errorCode || null,
        errorMessage: message,
        sourceEventId,
      });
      await args.billing.recordUsageEvent(sponsorshipCtx, {
        walletId: parsedBody.nearAccountId,
        action: 'contract_call',
        succeeded: false,
        occurredAt: new Date().toISOString(),
        sourceEventId: `sponsored_evm_call_usage:${record.id}`,
      });
      logger.error('[sponsored-evm-call] request failed', {
        environmentId: parsedBody.environmentId,
        apiKeyId: authResult.apiKey.id,
        nearAccountId: parsedBody.nearAccountId,
        walletAddress: parsedBody.walletAddress,
        txHash,
        message,
      });
      res.status(502).json({
        ok: false,
        code: errorCode || 'sponsored_evm_call_failed',
        message,
        txHash,
        recordId: record.id,
        sponsorshipConfigId: matched.config.sponsorshipConfigId,
      });
    }
  });
}
