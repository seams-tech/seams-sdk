import { createEvmClient, parseEvmRpcHexQuantity } from '../../../client/src';
import {
  executeSponsoredEvmCall,
  resolveSponsoredEvmExecutorForChain,
  type SponsoredEvmCallExecutorConfig,
} from '../sponsorship';
import { coerceRouterLogger, type RouterLogger } from './logger';
import type { SmartAccountDeployRequest, SmartAccountDeployResult } from './relay';

const DEFAULT_EVM_SMART_ACCOUNT_DEPLOY_GAS_LIMIT = 900_000n;
const DEFAULT_EVM_SMART_ACCOUNT_DEPLOY_MIN_GAS_LIMIT = 400_000n;
const DEFAULT_EVM_SMART_ACCOUNT_DEPLOY_GAS_BUFFER_BPS = 12_500;

function normalizePositiveInteger(value: unknown, fallback: number): number {
  const parsed = Math.floor(Number(value));
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function applyBufferedGasLimit(input: {
  estimatedGas: bigint;
  minGasLimit: bigint;
  gasBufferBps: number;
}): bigint {
  const bps = BigInt(normalizePositiveInteger(input.gasBufferBps, DEFAULT_EVM_SMART_ACCOUNT_DEPLOY_GAS_BUFFER_BPS));
  const buffered = (input.estimatedGas * bps + 9_999n) / 10_000n;
  return buffered > input.minGasLimit ? buffered : input.minGasLimit;
}

function hasDeployedCode(code: unknown): boolean {
  const normalized = String(code || '').trim().toLowerCase();
  return !!normalized && normalized !== '0x' && normalized !== '0x0' && normalized !== '0x00';
}

async function readCodeAtAddress(args: {
  rpcUrl: string;
  accountAddress: `0x${string}`;
}): Promise<string | null> {
  const client = createEvmClient({ rpcUrl: args.rpcUrl });
  return await client
    .request<string>({
      method: 'eth_getCode',
      params: [args.accountAddress, 'latest'],
      timeoutMs: 10_000,
    })
    .catch(() => null);
}

async function estimateDeployGasLimit(args: {
  rpcUrl: string;
  from: `0x${string}`;
  to: `0x${string}`;
  data: `0x${string}`;
  defaultGasLimit: bigint;
  minGasLimit: bigint;
  gasBufferBps: number;
  logger: ReturnType<typeof coerceRouterLogger>;
}): Promise<bigint> {
  const client = createEvmClient({ rpcUrl: args.rpcUrl });
  try {
    const estimatedHex = await client.request<string>({
      method: 'eth_estimateGas',
      params: [
        {
          from: args.from,
          to: args.to,
          value: '0x0',
          data: args.data,
        },
      ],
      timeoutMs: 10_000,
    });
    return applyBufferedGasLimit({
      estimatedGas: parseEvmRpcHexQuantity(estimatedHex, 'eth_estimateGas'),
      minGasLimit: args.minGasLimit,
      gasBufferBps: args.gasBufferBps,
    });
  } catch (error: unknown) {
    args.logger.warn('[relay][smart-account-deploy] gas estimation failed; using fallback gas limit', {
      ...(error instanceof Error ? { error: error.message } : { error: String(error || 'unknown') }),
      fallbackGasLimit: args.defaultGasLimit.toString(10),
    });
    return args.defaultGasLimit;
  }
}

export function createEvmSmartAccountDeployHandler(input: {
  config: SponsoredEvmCallExecutorConfig | null;
  logger?: RouterLogger | null;
  defaultGasLimit?: bigint;
  minGasLimit?: bigint;
  gasBufferBps?: number;
}): (request: SmartAccountDeployRequest) => Promise<SmartAccountDeployResult> {
  const logger = coerceRouterLogger(input.logger || console);
  const defaultGasLimit =
    typeof input.defaultGasLimit === 'bigint' && input.defaultGasLimit > 0n
      ? input.defaultGasLimit
      : DEFAULT_EVM_SMART_ACCOUNT_DEPLOY_GAS_LIMIT;
  const minGasLimit =
    typeof input.minGasLimit === 'bigint' && input.minGasLimit > 0n
      ? input.minGasLimit
      : DEFAULT_EVM_SMART_ACCOUNT_DEPLOY_MIN_GAS_LIMIT;
  const gasBufferBps = normalizePositiveInteger(
    input.gasBufferBps,
    DEFAULT_EVM_SMART_ACCOUNT_DEPLOY_GAS_BUFFER_BPS,
  );

  return async (request: SmartAccountDeployRequest): Promise<SmartAccountDeployResult> => {
    if (request.chain !== 'evm') {
      return {
        ok: true,
        code: 'assumed_deployed',
        message: 'Non-EVM smart-account deployment is handled outside the EVM deploy adapter',
      };
    }
    if (request.accountModel !== 'erc4337') {
      return {
        ok: false,
        code: 'unsupported_account_model',
        message: `Unsupported smart-account model for EVM deployment: ${request.accountModel}`,
      };
    }
    const plan = request.evmDeploymentPlan;
    if (!plan) {
      return {
        ok: false,
        code: 'missing_evm_deployment_plan',
        message: 'Missing canonical EVM deployment plan for smart-account deployment',
      };
    }
    if (plan.predictedAddress.toLowerCase() !== request.accountAddress.toLowerCase()) {
      return {
        ok: false,
        code: 'deployment_plan_account_mismatch',
        message: 'Canonical EVM deployment plan does not match the requested smart-account address',
      };
    }

    const executor = resolveSponsoredEvmExecutorForChain(input.config, request.chainId);
    if (!executor) {
      return {
        ok: false,
        code: 'evm_deployment_chain_unconfigured',
        message: `No EVM deploy executor configured for chainId=${String(request.chainId)}`,
      };
    }

    const existingCode = await readCodeAtAddress({
      rpcUrl: executor.rpcUrl,
      accountAddress: plan.predictedAddress,
    });
    if (hasDeployedCode(existingCode)) {
      return {
        ok: true,
        code: 'already_deployed',
        message: 'Smart account already has deployed code at the predicted address',
      };
    }

    const gasLimit = await estimateDeployGasLimit({
      rpcUrl: executor.rpcUrl,
      from: executor.sponsorAddress,
      to: plan.factory,
      data: plan.createAccountCalldata,
      defaultGasLimit,
      minGasLimit,
      gasBufferBps,
      logger,
    });

    try {
      const execution = await executeSponsoredEvmCall({
        executor,
        call: {
          to: plan.factory,
          data: plan.createAccountCalldata,
          gasLimit,
          value: 0n,
        },
      });
      logger.info('[relay][smart-account-deploy] deployed evm smart account', {
        nearAccountId: request.nearAccountId,
        chainId: request.chainId,
        accountAddress: request.accountAddress,
        deploymentTxHash: execution.txHash,
      });
      return {
        ok: true,
        deploymentTxHash: execution.txHash,
        code: 'deployed',
      };
    } catch (error: unknown) {
      const code =
        error && typeof error === 'object' && 'code' in error
          ? String((error as { code?: unknown }).code || '').trim() || 'deployment_failed'
          : 'deployment_failed';
      const message =
        error instanceof Error ? error.message : String(error || 'Smart-account deployment failed');
      const deployedAfterFailureCode = await readCodeAtAddress({
        rpcUrl: executor.rpcUrl,
        accountAddress: plan.predictedAddress,
      });
      if (hasDeployedCode(deployedAfterFailureCode)) {
        return {
          ok: true,
          code: 'already_deployed',
          message: 'Smart account code exists at the predicted address after deployment attempt',
        };
      }
      logger.warn('[relay][smart-account-deploy] evm smart-account deployment failed', {
        nearAccountId: request.nearAccountId,
        chainId: request.chainId,
        accountAddress: request.accountAddress,
        code,
        message,
      });
      return {
        ok: false,
        code,
        message,
      };
    }
  };
}
