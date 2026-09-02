import type { SeamsChainConfig } from '@/core/types/seams';
import {
  buildTempoSetUserTokenRequest,
  parseTempoEvmAddress,
  readTempoFeeTokenPreference,
  validateTempoFeeToken,
} from '@/core/signingEngine/chains/tempo/feeToken';
import type {
  ExecuteEvmFamilyTransactionArgs,
  ExecuteEvmFamilyTransactionResult,
  GetTempoFeeTokenPreferenceArgs,
  SetTempoFeeTokenPreferenceArgs,
  ValidateTempoFeeTokenArgs,
} from '@/SeamsWeb/signingSurface/types';
import { resolveEvmFamilyRpcUrl } from './executeEvmFamilyTransaction';

const DEFAULT_SET_USER_TOKEN_GAS_LIMIT = 1_000_000n;

type TempoFeeTokenContext = {
  chains: readonly SeamsChainConfig[];
  execute(args: ExecuteEvmFamilyTransactionArgs): Promise<ExecuteEvmFamilyTransactionResult>;
};

function resolveTempoRpcUrl(
  chains: readonly SeamsChainConfig[],
  chainTarget: GetTempoFeeTokenPreferenceArgs['chainTarget'],
): string {
  return resolveEvmFamilyRpcUrl({ chains, chainTarget });
}

export async function getTempoFeeTokenPreference(
  chains: readonly SeamsChainConfig[],
  args: GetTempoFeeTokenPreferenceArgs,
) {
  return await readTempoFeeTokenPreference({
    rpcUrl: resolveTempoRpcUrl(chains, args.chainTarget),
    account: parseTempoEvmAddress('account address', args.account),
    ...(args.timeoutMs !== undefined ? { timeoutMs: args.timeoutMs } : {}),
  });
}

export async function validateConfiguredTempoFeeToken(
  chains: readonly SeamsChainConfig[],
  args: ValidateTempoFeeTokenArgs,
) {
  return await validateTempoFeeToken({
    rpcUrl: resolveTempoRpcUrl(chains, args.chainTarget),
    feeToken: parseTempoEvmAddress('fee token address', args.feeToken),
    ...(args.timeoutMs !== undefined ? { timeoutMs: args.timeoutMs } : {}),
  });
}

async function verifyTempoFeeTokenPreference(args: {
  rpcUrl: string;
  account: `0x${string}`;
  feeToken: `0x${string}`;
}): Promise<void> {
  const observed = await readTempoFeeTokenPreference(args);
  if (observed?.toLowerCase() === args.feeToken.toLowerCase()) return;
  throw new Error(
    `[Tempo capability] fee-token preference mismatch: expected ${args.feeToken}, received ${observed ?? 'unset'}`,
  );
}

export async function setTempoFeeTokenPreference(
  context: TempoFeeTokenContext,
  args: SetTempoFeeTokenPreferenceArgs,
): Promise<ExecuteEvmFamilyTransactionResult> {
  const rpcUrl = resolveTempoRpcUrl(context.chains, args.chainTarget);
  const account = parseTempoEvmAddress('account address', args.account);
  const feeToken = parseTempoEvmAddress('fee token address', args.feeToken);
  const validation = await validateTempoFeeToken({ rpcUrl, feeToken });
  if (validation.kind === 'invalid') {
    throw new Error(`[Tempo capability] invalid fee token: ${validation.reason}`);
  }

  const request = buildTempoSetUserTokenRequest({
    chainId: args.chainTarget.chainId,
    feeToken,
    maxPriorityFeePerGas: args.feeCaps.maxPriorityFeePerGas,
    maxFeePerGas: args.feeCaps.maxFeePerGas,
    gasLimit: args.gasLimit ?? DEFAULT_SET_USER_TOKEN_GAS_LIMIT,
  });
  return await context.execute({
    walletSession: args.walletSession,
    chainTarget: args.chainTarget,
    request,
    payloadExpectation: {
      kind: 'evm_eip1559',
      to: request.tx.to ?? null,
      input: request.tx.data ?? '0x',
    },
    ...(args.finalization ? { finalization: args.finalization } : {}),
    ...(args.options ? { options: args.options } : {}),
    postFinalizationCheck: verifyTempoFeeTokenPreference.bind(null, {
      rpcUrl,
      account,
      feeToken,
    }),
  });
}
