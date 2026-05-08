import type { PasskeyManagerContext } from '../interfaces';
import type { ConfirmationConfig } from '../../types/signer-worker';
import type { AccountId } from '../../types/accountIds';
import type {
  AccountSignerRecord,
  ChainAccountRecord,
  SignerOpOutboxRecord,
} from '../../indexedDB/passkeyClientDB.types';
import { IndexedDBManager } from '../../indexedDB';
import { getNearAccountIdForProfile } from '../../accountData/near/accountProjection';
import type { EvmContractAbi } from '../../signingEngine/chains/evm/types';
import { executeEvmFamilyTransactionLifecycle } from '../tempo/executeEvmFamilyTransaction';
import { createEvmClient, parseRpcHexQuantity } from '../../rpcClients/evm/EvmClient';
import type { SigningFlowEvent } from '../../types/sdkSentEvents';
import {
  getSeamsSmartAccountMethodSelector,
  SEAMS_SMART_ACCOUNT_ADD_OWNER_ABI,
  SEAMS_SMART_ACCOUNT_REMOVE_OWNER_ABI,
} from '@shared/utils/evmSmartAccountSpec';
import {
  thresholdEcdsaChainTargetFromChainFamily,
  toWalletSubjectId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';

const ADD_OWNER_SELECTOR = getSeamsSmartAccountMethodSelector('addOwner');
const REMOVE_OWNER_SELECTOR = getSeamsSmartAccountMethodSelector('removeOwner');
const ADD_OWNER_ABI = SEAMS_SMART_ACCOUNT_ADD_OWNER_ABI as EvmContractAbi;
const REMOVE_OWNER_ABI = SEAMS_SMART_ACCOUNT_REMOVE_OWNER_ABI as EvmContractAbi;
const DEFAULT_PRIORITY_FEE_PER_GAS = 1_500_000_000n;
const DEFAULT_MAX_FEE_PER_GAS = 3_000_000_000n;
const DEFAULT_ADD_OWNER_GAS_LIMIT = 150_000n;
const DEFAULT_REMOVE_OWNER_GAS_LIMIT = 150_000n;

function normalizeAddress(value: unknown): `0x${string}` {
  const normalized = String(value || '')
    .trim()
    .toLowerCase();
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

function buildRemoveOwnerCalldata(ownerAddress: `0x${string}`): `0x${string}` {
  const encodedOwner = ownerAddress.slice(2).padStart(64, '0');
  return `${REMOVE_OWNER_SELECTOR}${encodedOwner}` as `0x${string}`;
}

function resolveRpcUrl(args: { context: PasskeyManagerContext; chainId: number }): string {
  const matching = (args.context?.configs?.network?.chains || []).filter((chain) => {
    return (
      typeof (chain as { chainId?: unknown }).chainId === 'number' &&
      Number((chain as { chainId?: unknown }).chainId) === args.chainId
    );
  });
  if (matching.length === 0) {
    throw new Error(`Missing RPC configuration for EVM chainId=${String(args.chainId)}`);
  }
  const preferred = matching.find((chain) =>
    String(chain.network || '')
      .toLowerCase()
      .includes('evm'),
  );
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
    baseFeePerGas !== null ? baseFeePerGas * 2n + maxPriorityFeePerGas : DEFAULT_MAX_FEE_PER_GAS;
  return {
    maxPriorityFeePerGas,
    maxFeePerGas:
      computedMaxFeePerGas > maxPriorityFeePerGas ? computedMaxFeePerGas : DEFAULT_MAX_FEE_PER_GAS,
  };
}

export function createLocalDeployedSignerMutationRuntime(args: {
  context: PasskeyManagerContext;
  confirmationConfig?: Partial<ConfirmationConfig>;
  onEvent?: (event: SigningFlowEvent) => void;
}): {
  resolveOwnerAccountId: (input: {
    profileId: string;
    op: SignerOpOutboxRecord;
    signer: AccountSignerRecord;
    chainAccount: ChainAccountRecord;
  }) => Promise<AccountId | null>;
  executeDeployedAddSigner: (input: {
    ownerAccountId: string;
    op: SignerOpOutboxRecord;
    signer: AccountSignerRecord;
    chainAccount: ChainAccountRecord;
    now: number;
  }) => Promise<{ txHash?: string | null }>;
  executeDeployedRemoveSigner: (input: {
    ownerAccountId: string;
    op: SignerOpOutboxRecord;
    signer: AccountSignerRecord;
    chainAccount: ChainAccountRecord;
    now: number;
  }) => Promise<{ txHash?: string | null }>;
} {
  return {
    resolveOwnerAccountId: async (input) => {
      return await getNearAccountIdForProfile(IndexedDBManager.clientDB, input.profileId);
    },
    executeDeployedAddSigner: async (input) => {
      return await executeDeployedSignerMutation({
        context: args.context,
        confirmationConfig: args.confirmationConfig,
        onEvent: args.onEvent,
        nearAccountId: input.ownerAccountId,
        chainAccount: input.chainAccount,
        signerAddress: normalizeAddress(input.signer.signerId),
        buildCalldata: buildAddOwnerCalldata,
        abi: ADD_OWNER_ABI,
        gasLimit: DEFAULT_ADD_OWNER_GAS_LIMIT,
      });
    },
    executeDeployedRemoveSigner: async (input) => {
      return await executeDeployedSignerMutation({
        context: args.context,
        confirmationConfig: args.confirmationConfig,
        onEvent: args.onEvent,
        nearAccountId: input.ownerAccountId,
        chainAccount: input.chainAccount,
        signerAddress: normalizeAddress(input.signer.signerId),
        buildCalldata: buildRemoveOwnerCalldata,
        abi: REMOVE_OWNER_ABI,
        gasLimit: DEFAULT_REMOVE_OWNER_GAS_LIMIT,
      });
    },
  };
}

async function executeDeployedSignerMutation(args: {
  context: PasskeyManagerContext;
  confirmationConfig?: Partial<ConfirmationConfig>;
  onEvent?: (event: SigningFlowEvent) => void;
  nearAccountId: string;
  chainAccount: ChainAccountRecord;
  signerAddress: `0x${string}`;
  buildCalldata: (address: `0x${string}`) => `0x${string}`;
  abi: EvmContractAbi;
  gasLimit: bigint;
}): Promise<{ txHash?: string | null }> {
  const chainId = parseChainIdFromKey(args.chainAccount.chainIdKey);
  const chainTarget = thresholdEcdsaChainTargetFromChainFamily({ chain: 'evm', chainId });
  const rpcUrl = resolveRpcUrl({ context: args.context, chainId });
  const smartAccountAddress = normalizeAddress(args.chainAccount.accountAddress);
  const data = args.buildCalldata(args.signerAddress);
  const feeCaps = await resolveFeeCaps({ rpcUrl });

  const executed = await executeEvmFamilyTransactionLifecycle({
    capability: {
      signTempo: async (signArgs) =>
        await args.context.signingEngine.signTempo({
          nearAccountId: signArgs.nearAccountId,
          subjectId: signArgs.subjectId,
          request: signArgs.request,
          chainTarget: signArgs.chainTarget,
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
      nearAccountId: args.nearAccountId,
      subjectId: toWalletSubjectId(args.nearAccountId),
      chainTarget,
      request: {
        chain: 'evm',
        kind: 'eip1559',
        senderSignatureAlgorithm: 'secp256k1',
        tx: {
          chainId,
          maxPriorityFeePerGas: feeCaps.maxPriorityFeePerGas,
          maxFeePerGas: feeCaps.maxFeePerGas,
          gasLimit: args.gasLimit,
          to: smartAccountAddress,
          value: 0n,
          data,
          abi: args.abi,
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
}
