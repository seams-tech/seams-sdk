import {
  createEvmClient,
  parseRpcHexQuantity as parseEvmRpcHexQuantity,
} from './evmRpcClient';
import {
  normalizeEvmAddress,
  type SponsoredEvmCall,
} from './evm';
import type {
  SponsoredEvmCallExecutorConfig,
  SponsoredEvmChainExecutorConfig,
  SponsoredEvmExecutionAdapter,
  SponsoredEvmExecutionAdapterResolver,
  SponsoredEvmExecutionResult,
} from './evmExecutorTypes';
import {
  resolveSponsoredEvmCallConfigFromRecord,
  type SponsoredEvmExecutorConfigEnv,
} from './evmExecutorConfig';
import {
  computeWorkerEip1559TxHash,
  encodeWorkerEip1559SignedTxFromSignature65,
  signWorkerSecp256k1Recoverable,
  type WorkerEip1559UnsignedTx,
  workerSecp256k1PrivateKey32ToPublicKey33,
  workerSecp256k1PublicKey33ToEthereumAddress,
} from './evmWorkerSignerWasm';

async function toNullOnError<T>(promise: Promise<T>): Promise<T | null> {
  try {
    return await promise;
  } catch {
    return null;
  }
}

function normalizeTxHashOrThrow(value: unknown): `0x${string}` {
  const normalized = String(value || '').trim();
  if (!/^0x[0-9a-fA-F]{64}$/.test(normalized)) {
    throw new Error(`Invalid transaction hash: ${normalized || 'empty'}`);
  }
  return normalized as `0x${string}`;
}

function bytesToHex(bytes: Uint8Array): `0x${string}` {
  return `0x${Array.from(bytes)
    .map(hexByte)
    .join('')}` as `0x${string}`;
}

function hexByte(entry: number): string {
  return entry.toString(16).padStart(2, '0');
}

function privateKeyHexToBytes(value: `0x${string}`): Uint8Array {
  const hex = value.slice(2);
  if (hex.length !== 64 || !/^[0-9a-fA-F]+$/.test(hex)) {
    throw new Error('Sponsor private key must be 32 bytes');
  }
  const out = new Uint8Array(32);
  for (let index = 0; index < out.length; index += 1) {
    out[index] = parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  }
  return out;
}

function parseOptionalRpcQuantity(value: unknown, label: string): bigint | null {
  const raw = String(value || '').trim();
  if (!/^0x[0-9a-fA-F]+$/.test(raw)) return null;
  try {
    return parseEvmRpcHexQuantity(raw, label);
  } catch {
    return null;
  }
}

function resolvePriorityFee(input: {
  readonly priorityFee: bigint | null;
  readonly gasPrice: bigint | null;
  readonly floor: bigint;
}): bigint {
  return input.priorityFee ?? (input.gasPrice && input.gasPrice > 0n ? input.gasPrice / 10n : input.floor);
}

function resolveDynamicMaxFee(input: {
  readonly baseFee: bigint | null;
  readonly gasPrice: bigint | null;
  readonly maxPriorityFeePerGas: bigint;
}): bigint {
  if (input.baseFee && input.baseFee > 0n) {
    return input.baseFee * 2n + input.maxPriorityFeePerGas;
  }
  if (input.gasPrice && input.gasPrice > 0n) return input.gasPrice * 2n;
  return 0n;
}

async function deriveEvmAddressFromWorkerPrivateKeyHex(
  privateKeyHex: `0x${string}`,
): Promise<`0x${string}`> {
  const publicKey33 = await workerSecp256k1PrivateKey32ToPublicKey33(
    privateKeyHexToBytes(privateKeyHex),
  );
  const addressHex = await workerSecp256k1PublicKey33ToEthereumAddress(publicKey33);
  const normalized = normalizeEvmAddress(addressHex);
  if (!normalized) {
    throw new Error('Failed to derive sponsor address from private key');
  }
  return normalized;
}

async function resolveWorkerFeeCaps(args: {
  readonly rpcUrl: string;
  readonly maxPriorityFeePerGasFloor: bigint;
  readonly maxFeePerGasFloor: bigint;
}): Promise<{ maxPriorityFeePerGas: bigint; maxFeePerGas: bigint }> {
  const client = createEvmClient({ rpcUrl: args.rpcUrl });
  const [latestBlock, priorityFeeHex, gasPriceHex] = await Promise.all([
    toNullOnError(client.getBlockByNumber({ blockTag: 'latest', timeoutMs: 6_000 })),
    toNullOnError(
      client.request<string>({
        method: 'eth_maxPriorityFeePerGas',
        params: [],
        timeoutMs: 6_000,
      }),
    ),
    toNullOnError(
      client.request<string>({
        method: 'eth_gasPrice',
        params: [],
        timeoutMs: 6_000,
      }),
    ),
  ]);

  const baseFee = parseOptionalRpcQuantity(latestBlock?.baseFeePerGas, 'baseFeePerGas');
  const priorityFee = parseOptionalRpcQuantity(priorityFeeHex, 'eth_maxPriorityFeePerGas');
  const gasPrice = parseOptionalRpcQuantity(gasPriceHex, 'eth_gasPrice');
  const resolvedPriority = resolvePriorityFee({
    priorityFee,
    gasPrice,
    floor: args.maxPriorityFeePerGasFloor,
  });
  const maxPriorityFeePerGas =
    resolvedPriority > args.maxPriorityFeePerGasFloor
      ? resolvedPriority
      : args.maxPriorityFeePerGasFloor;
  const dynamicMaxFeePerGas = resolveDynamicMaxFee({
    baseFee,
    gasPrice,
    maxPriorityFeePerGas,
  });
  const maxFeePerGas =
    dynamicMaxFeePerGas > args.maxFeePerGasFloor ? dynamicMaxFeePerGas : args.maxFeePerGasFloor;
  return {
    maxPriorityFeePerGas:
      maxPriorityFeePerGas < maxFeePerGas ? maxPriorityFeePerGas : maxFeePerGas / 2n,
    maxFeePerGas,
  };
}

async function executeSponsoredEvmCallInWorker(args: {
  readonly executor: SponsoredEvmChainExecutorConfig;
  readonly call: SponsoredEvmCall;
}): Promise<SponsoredEvmExecutionResult> {
  const client = createEvmClient({ rpcUrl: args.executor.rpcUrl });
  const nonce = await client.getTransactionCount({
    address: args.executor.sponsorAddress,
    blockTag: 'pending',
    timeoutMs: 10_000,
  });
  const feeCaps = await resolveWorkerFeeCaps({
    rpcUrl: args.executor.rpcUrl,
    maxPriorityFeePerGasFloor: args.executor.maxPriorityFeePerGasFloor,
    maxFeePerGasFloor: args.executor.maxFeePerGasFloor,
  });
  const unsignedTx: WorkerEip1559UnsignedTx = {
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
  const digest32 = await computeWorkerEip1559TxHash(unsignedTx);
  const signature65 = await signWorkerSecp256k1Recoverable({
    digest32,
    privateKey32: privateKeyHexToBytes(args.executor.sponsorPrivateKeyHex),
  });
  const rawTxHex = bytesToHex(
    await encodeWorkerEip1559SignedTxFromSignature65({
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

class WorkerSponsoredEvmExecutionAdapter implements SponsoredEvmExecutionAdapter {
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
    return await executeSponsoredEvmCallInWorker({
      executor: this.executor,
      call: this.call,
    });
  }
}

export async function resolveSponsoredEvmCallConfigFromWorkerEnv(
  env: SponsoredEvmExecutorConfigEnv,
): Promise<SponsoredEvmCallExecutorConfig | null> {
  return await resolveSponsoredEvmCallConfigFromRecord({
    env,
    deriveSponsorAddress: deriveEvmAddressFromWorkerPrivateKeyHex,
  });
}

export const resolveSponsoredEvmWorkerExecutionAdapter: SponsoredEvmExecutionAdapterResolver = (
  input,
) => {
  const executor = input.config.executorsByChain.get(input.chainId) || null;
  if (!executor) return null;
  return new WorkerSponsoredEvmExecutionAdapter(executor, input.call);
};
