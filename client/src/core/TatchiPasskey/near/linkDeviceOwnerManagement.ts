import type { PasskeyManagerContext } from '../interfaces';
import type { ConfirmationConfig } from '../../types/signer-worker';
import type {
  AccountSignerRecord,
  ChainAccountRecord,
  SignerOpOutboxRecord,
} from '../../indexedDB/passkeyClientDB.types';
import { executeEvmFamilyTransactionLifecycle } from '../tempo/executeEvmFamilyTransaction';
import { createEvmClient, parseRpcHexQuantity } from '../../rpcClients/evm/EvmClient';
import { bytesToHex } from '../../signingEngine/chainAdaptors/evm/bytes';
import { keccak256Bytes } from '@shared/utils/keccak';

const ADD_OWNER_SELECTOR = bytesToHex(
  keccak256Bytes(new TextEncoder().encode('addOwner(address)')).slice(0, 4),
);
const ADD_OWNER_ABI = [
  {
    type: 'function',
    name: 'addOwner',
    inputs: [{ name: 'owner', type: 'address' }],
  },
] as const;
const DEFAULT_PRIORITY_FEE_PER_GAS = 1_500_000_000n;
const DEFAULT_MAX_FEE_PER_GAS = 3_000_000_000n;
const DEFAULT_ADD_OWNER_GAS_LIMIT = 150_000n;

function normalizeAddress(value: unknown): `0x${string}` {
  const normalized = String(value || '').trim().toLowerCase();
  if (!/^0x[0-9a-f]{40}$/.test(normalized)) {
    throw new Error(`Invalid EVM address: ${String(value || '')}`);
  }
  return normalized as `0x${string}`;
}

function parseChainIdFromKey(chainIdKey: string): number {
  const match = String(chainIdKey || '')
    .trim()
    .toLowerCase()
    .match(/^([a-z0-9_-]+):([0-9]+)$/);
  if (!match) {
    throw new Error(`Invalid chainIdKey: ${String(chainIdKey || '')}`);
  }
  if (match[1] !== 'evm') {
    throw new Error(`Unsupported deployed owner-management chain: ${match[1]}`);
  }
  const chainId = Math.floor(Number(match[2]));
  if (!Number.isFinite(chainId) || chainId <= 0) {
    throw new Error(`Invalid chainId in chainIdKey: ${String(chainIdKey || '')}`);
  }
  return chainId;
}

function buildAddOwnerCalldata(ownerAddress: `0x${string}`): `0x${string}` {
  const encodedOwner = ownerAddress.slice(2).padStart(64, '0');
  return `${ADD_OWNER_SELECTOR}${encodedOwner}` as `0x${string}`;
}

function resolveRpcUrl(args: { context: PasskeyManagerContext; chainId: number }): string {
  const matching = (args.context?.configs?.network?.chains || []).filter((chain) => {
    return typeof (chain as { chainId?: unknown }).chainId === 'number' &&
      Number((chain as { chainId?: unknown }).chainId) === args.chainId;
  });
  if (matching.length === 0) {
    throw new Error(`Missing RPC configuration for EVM chainId=${String(args.chainId)}`);
  }
  const preferred = matching.find((chain) => String(chain.network || '').toLowerCase().includes('evm'));
  const selected = preferred || matching[0];
  const rpcUrl = String(selected?.rpcUrl || '').trim();
  if (!rpcUrl) {
    throw new Error(`Missing RPC URL for EVM chainId=${String(args.chainId)}`);
  }
  return rpcUrl;
}

async function resolveFeeCaps(args: {
  rpcUrl: string;
}): Promise<{ maxPriorityFeePerGas: bigint; maxFeePerGas: bigint }> {
  const client = createEvmClient({ rpcUrl: args.rpcUrl });
  const latestBlock = await client.getBlockByNumber({ blockTag: 'latest' }).catch(() => null);
  const baseFeeHex = String(latestBlock?.baseFeePerGas || '').trim();
  let baseFeePerGas: bigint | null = null;
  if (/^0x[0-9a-fA-F]+$/.test(baseFeeHex)) {
    try {
      baseFeePerGas = parseRpcHexQuantity(baseFeeHex, 'baseFeePerGas');
    } catch {
      baseFeePerGas = null;
    }
  }
  const maxPriorityFeePerGas = DEFAULT_PRIORITY_FEE_PER_GAS;
  const computedMaxFeePerGas =
    baseFeePerGas !== null
      ? baseFeePerGas * 2n + maxPriorityFeePerGas
      : DEFAULT_MAX_FEE_PER_GAS;
  return {
    maxPriorityFeePerGas,
    maxFeePerGas:
      computedMaxFeePerGas > maxPriorityFeePerGas
        ? computedMaxFeePerGas
        : DEFAULT_MAX_FEE_PER_GAS,
  };
}

export function createLocalDeployedSignerMutationRuntime(args: {
  context: PasskeyManagerContext;
  confirmationConfig?: Partial<ConfirmationConfig>;
  onEvent?: (event: {
    step: number;
    phase: string;
    status: 'progress' | 'success' | 'error';
    message?: string;
    data?: unknown;
  }) => void;
}): {
  executeDeployedAddSigner: (input: {
    nearAccountId: string;
    op: SignerOpOutboxRecord;
    signer: AccountSignerRecord;
    chainAccount: ChainAccountRecord;
    now: number;
  }) => Promise<{ txHash?: string | null }>;
} {
  return {
    executeDeployedAddSigner: async (input) => {
      const chainId = parseChainIdFromKey(input.op.chainIdKey);
      const rpcUrl = resolveRpcUrl({ context: args.context, chainId });
      const ownerAddress = normalizeAddress(input.signer.signerId);
      const smartAccountAddress = normalizeAddress(input.chainAccount.accountAddress);
      const data = buildAddOwnerCalldata(ownerAddress);
      const feeCaps = await resolveFeeCaps({ rpcUrl });

      const executed = await executeEvmFamilyTransactionLifecycle({
        capability: {
          signTempo: async (signArgs) =>
            await args.context.signingEngine.signTempo({
              nearAccountId: signArgs.nearAccountId,
              request: signArgs.request,
              confirmationConfigOverride: signArgs.options?.confirmationConfig,
              shouldAbort: signArgs.options?.shouldAbort,
              onEvent: signArgs.options?.onEvent,
            }),
          reportBroadcastAccepted: async (reportArgs) =>
            await args.context.signingEngine.reportTempoBroadcastAccepted(reportArgs),
          reportBroadcastRejected: async (reportArgs) =>
            await args.context.signingEngine.reportTempoBroadcastRejected(reportArgs),
          reportFinalized: async (reportArgs) =>
            await args.context.signingEngine.reportTempoFinalized(reportArgs),
          reportDroppedOrReplaced: async (reportArgs) =>
            await args.context.signingEngine.reportTempoDroppedOrReplaced(reportArgs),
          reconcileNonceLane: async (reportArgs) =>
            await args.context.signingEngine.reconcileTempoNonceLane(reportArgs),
        },
        chains: args.context.configs.network.chains,
        input: {
          nearAccountId: input.nearAccountId,
          request: {
            chain: 'evm',
            kind: 'eip1559',
            senderSignatureAlgorithm: 'secp256k1',
            tx: {
              chainId,
              maxPriorityFeePerGas: feeCaps.maxPriorityFeePerGas,
              maxFeePerGas: feeCaps.maxFeePerGas,
              gasLimit: DEFAULT_ADD_OWNER_GAS_LIMIT,
              to: smartAccountAddress,
              value: 0n,
              data,
              abi: ADD_OWNER_ABI,
              accessList: [],
            },
          },
          payloadExpectation: {
            to: smartAccountAddress,
            input: data,
          },
          options: {
            confirmationConfig: args.confirmationConfig,
            onEvent: args.onEvent,
          },
        },
      });

      return { txHash: executed.txHash };
    },
  };
}
