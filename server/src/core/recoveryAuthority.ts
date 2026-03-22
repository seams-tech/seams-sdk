import { toOptionalTrimmedString } from '@shared/utils/validation';
import { createEvmClient, parseEvmRpcHexQuantity } from '../../../client/src';
import type { AuthService } from './AuthService';
import type { AccountSignerRecord } from './AccountSignerStore';
import type { RecoveryExecutionRecord } from './RecoveryExecutionStore';
import type { SponsoredEvmCallExecutorConfig } from '../sponsorship';
import {
  SMART_ACCOUNT_RECOVERY_ADD_OWNER_ACTION,
  reconcileRecoverySessionExecutionState,
} from '../router/recoveryExecutionTracking';
import { syncCanonicalSmartAccountDeploymentManifest } from '../router/smartAccountDeploymentManifest';
import type { RecoveryAuthoritySponsorshipRuntime } from '../router/recoveryAuthoritySponsorship';
import { createSponsoredRecoveryDeployedExecutor } from './recoveryAuthoritySponsorship';

export { createSponsoredRecoveryDeployedExecutor } from './recoveryAuthoritySponsorship';

export type RecoveryAuthorityTargetMode = 'deployed' | 'undeployed';

export type RecoveryAuthorityTargetResolution =
  | RecoveryAuthorityTargetMode
  | {
      mode: RecoveryAuthorityTargetMode;
      metadataPatch?: Record<string, unknown>;
    };

export type RecoveryAuthorityDeployedExecutionResult =
  | {
      status: 'submitted' | 'confirmed' | 'skipped';
      transactionHash?: string;
      metadataPatch?: Record<string, unknown>;
    }
  | {
      status: 'failed';
      transactionHash?: string;
      errorCode?: string;
      errorMessage?: string;
      metadataPatch?: Record<string, unknown>;
    };

export type RecoveryAuthorityExecutionResult = {
  processed: number;
  confirmed: number;
  submitted: number;
  skipped: number;
  failed: number;
};

export type RecoveryAuthorityRetryResult = {
  processed: number;
  retried: number;
  skipped: number;
  failed: number;
};

type RecoveryAuthoritySignerPersistenceService = Pick<
  AuthService,
  | 'listAccountSignersByAccount'
  | 'putAccountSigner'
  | 'listRecoveryExecutionsByStatus'
  | 'recordRecoveryExecution'
  | 'getRecoverySession'
  | 'listRecoveryExecutions'
  | 'updateRecoverySessionStatus'
> &
  Partial<
    Pick<AuthService, 'getSmartAccountRecoverySubjectByAccount' | 'putSmartAccountRecoverySubject'>
  >;

function normalizeAddress(value: unknown): string {
  const normalized = toOptionalTrimmedString(value)?.toLowerCase() || '';
  return /^0x[0-9a-f]{40}$/.test(normalized) ? normalized : '';
}

function normalizeTransactionHash(value: unknown): `0x${string}` | null {
  const normalized = toOptionalTrimmedString(value);
  if (!normalized || !/^0x[0-9a-f]{64}$/i.test(normalized)) return null;
  return normalized as `0x${string}`;
}

function parseSponsoredChainId(chainIdKey: string): number | null {
  const match = String(chainIdKey || '')
    .trim()
    .toLowerCase()
    .match(/^(evm|tempo):([0-9]+)$/);
  if (!match) return null;
  const chainId = Math.floor(Number(match[2]));
  return Number.isFinite(chainId) && chainId > 0 ? chainId : null;
}

function asObject(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? ({ ...(value as Record<string, unknown>) } as Record<string, unknown>)
    : {};
}

const DEFAULT_FAILED_RECOVERY_RETRY_AFTER_MS = 5 * 60_000;
const DEFAULT_FAILED_RECOVERY_MAX_RETRIES = 3;
const NON_RETRYABLE_RECOVERY_ERROR_CODES = new Set([
  'invalid_recovery_transaction_hash',
  'invalid_submitted_recovery_target_mode',
  'missing_new_evm_owner',
  'missing_recovery_transaction_hash',
  'recovery_target_mode_unresolved',
  'sponsored_recovery_chain_unconfigured',
  'tx_reverted',
  'unsupported_recovery_chain',
]);

function normalizePositiveInteger(value: unknown): number | null {
  const normalized = Number(value);
  return Number.isFinite(normalized) && normalized > 0 ? Math.floor(normalized) : null;
}

function canRetryRecoveryExecution(input: {
  execution: RecoveryExecutionRecord;
  nowMs: number;
  retryAfterMs: number;
  maxRetryCount: number;
}): boolean {
  const metadata = asObject(input.execution.metadata);
  if (metadata.retryEligible === false) return false;
  const retryCount = normalizePositiveInteger(metadata.retryCount) || 0;
  if (retryCount >= input.maxRetryCount) return false;
  if (input.nowMs - input.execution.updatedAtMs < input.retryAfterMs) return false;
  const errorCode = toOptionalTrimmedString(input.execution.errorCode);
  if (metadata.retryEligible === true) return true;
  return !errorCode || !NON_RETRYABLE_RECOVERY_ERROR_CODES.has(errorCode);
}

function buildRetriedRecoveryExecutionMetadata(input: {
  execution: RecoveryExecutionRecord;
  nowMs: number;
}): Record<string, unknown> {
  const metadata = asObject(input.execution.metadata);
  const retryCount = normalizePositiveInteger(metadata.retryCount) || 0;
  const errorCode = toOptionalTrimmedString(input.execution.errorCode);
  const errorMessage = toOptionalTrimmedString(input.execution.errorMessage);
  return {
    ...metadata,
    retryCount: retryCount + 1,
    firstFailedAtMs: normalizePositiveInteger(metadata.firstFailedAtMs) || input.execution.updatedAtMs,
    lastFailedAtMs: input.execution.updatedAtMs,
    lastRetriedAtMs: input.nowMs,
    retryState: 'requeued',
    processedBy: 'recoveryAuthority',
    processedAtMs: input.nowMs,
    ...(errorCode ? { lastErrorCode: errorCode } : {}),
    ...(errorMessage ? { lastErrorMessage: errorMessage } : {}),
  };
}

function normalizeResolution(
  value: RecoveryAuthorityTargetResolution | null | undefined,
): { mode: RecoveryAuthorityTargetMode; metadataPatch?: Record<string, unknown> } | null {
  if (!value) return null;
  if (value === 'deployed' || value === 'undeployed') return { mode: value };
  if (value.mode !== 'deployed' && value.mode !== 'undeployed') return null;
  return {
    mode: value.mode,
    ...(value.metadataPatch ? { metadataPatch: { ...value.metadataPatch } } : {}),
  };
}

function resolveCanonicalTargetMode(
  execution: RecoveryExecutionRecord,
): { mode: RecoveryAuthorityTargetMode; metadataPatch?: Record<string, unknown> } | null {
  const metadata = asObject(execution.metadata);
  const targetMode = toOptionalTrimmedString(metadata.recoveryTargetMode);
  if (targetMode === 'deployed' || targetMode === 'undeployed') {
    return { mode: targetMode };
  }
  const linkedAccount = asObject(metadata.linkedAccount);
  if (linkedAccount.deployed === true) {
    return {
      mode: 'deployed',
      metadataPatch: {
        recoveryTargetMode: 'deployed',
      },
    };
  }
  if (linkedAccount.deployed === false) {
    return {
      mode: 'undeployed',
      metadataPatch: {
        recoveryTargetMode: 'undeployed',
      },
    };
  }
  return null;
}

function buildRecoveredSignerRecord(input: {
  existing?: AccountSignerRecord | null;
  execution: RecoveryExecutionRecord;
  newOwnerAddress: string;
  nowMs: number;
}): AccountSignerRecord {
  const linkedAccount = asObject(input.execution.metadata?.linkedAccount);
  const existing = input.existing || null;
  const mergedMetadata = {
    ...(existing?.metadata || {}),
    accountModel: toOptionalTrimmedString(linkedAccount.accountModel) || existing?.metadata?.accountModel,
    chain: toOptionalTrimmedString(linkedAccount.chain) || existing?.metadata?.chain,
    chainId:
      Number.isFinite(Number(linkedAccount.chainId)) && Number(linkedAccount.chainId) > 0
        ? Math.floor(Number(linkedAccount.chainId))
        : existing?.metadata?.chainId,
    ...(toOptionalTrimmedString(linkedAccount.factory)
      ? { factory: toOptionalTrimmedString(linkedAccount.factory) }
      : existing?.metadata?.factory
        ? { factory: existing.metadata.factory }
        : {}),
    ...(toOptionalTrimmedString(linkedAccount.entryPoint)
      ? { entryPoint: toOptionalTrimmedString(linkedAccount.entryPoint) }
      : existing?.metadata?.entryPoint
        ? { entryPoint: existing.metadata.entryPoint }
        : {}),
    ...(toOptionalTrimmedString(linkedAccount.salt)
      ? { salt: toOptionalTrimmedString(linkedAccount.salt) }
      : existing?.metadata?.salt
        ? { salt: existing.metadata.salt }
        : {}),
    ...(toOptionalTrimmedString(linkedAccount.counterfactualAddress)
      ? { counterfactualAddress: toOptionalTrimmedString(linkedAccount.counterfactualAddress) }
      : existing?.metadata?.counterfactualAddress
        ? { counterfactualAddress: existing.metadata.counterfactualAddress }
        : {}),
    ownerAddress: input.newOwnerAddress,
    recoverySessionId: input.execution.sessionId,
    recoverySource: 'email_recovery',
    recoveredAtMs: input.nowMs,
  };

  return {
    version: 'account_signer_v1',
    userId: input.execution.userId,
    chainIdKey: input.execution.chainIdKey,
    accountAddress: input.execution.accountAddress,
    signerType: existing?.signerType || 'threshold',
    signerId: input.newOwnerAddress,
    status: 'active',
    createdAtMs: existing?.createdAtMs || input.nowMs,
    updatedAtMs: input.nowMs,
    ...(existing?.removedAtMs ? {} : {}),
    metadata: mergedMetadata,
  };
}

async function activateRecoveredSigner(
  service: RecoveryAuthoritySignerPersistenceService,
  input: {
    execution: RecoveryExecutionRecord;
    newOwnerAddress: string;
    nowMs: number;
  },
): Promise<{ ok: true } | { ok: false; code: string; message: string }> {
  const listed = await service.listAccountSignersByAccount({
    chainIdKey: input.execution.chainIdKey,
    accountAddress: input.execution.accountAddress,
  });
  if (!listed.ok) return listed;
  const existing =
    listed.records.find((record) => normalizeAddress(record.signerId) === input.newOwnerAddress) || null;
  const persisted = await service.putAccountSigner(
    buildRecoveredSignerRecord({
      existing,
      execution: input.execution,
      newOwnerAddress: input.newOwnerAddress,
      nowMs: input.nowMs,
    }),
  );
  if (!persisted.ok) return persisted;
  if (
    typeof service.getSmartAccountRecoverySubjectByAccount !== 'function' ||
    typeof service.putSmartAccountRecoverySubject !== 'function'
  ) {
    return { ok: true };
  }
  const manifestService = {
    listAccountSignersByAccount: service.listAccountSignersByAccount,
    getSmartAccountRecoverySubjectByAccount: service.getSmartAccountRecoverySubjectByAccount,
    putSmartAccountRecoverySubject: service.putSmartAccountRecoverySubject,
  };
  const syncedManifest = await syncCanonicalSmartAccountDeploymentManifest({
    authService: manifestService,
    chainIdKey: input.execution.chainIdKey,
    accountAddress: input.execution.accountAddress,
    materializedAtMs: input.nowMs,
  });
  return { ok: true };
}

export function createSponsoredRecoverySubmittedConfirmer(input: {
  config: SponsoredEvmCallExecutorConfig;
  createClient?: typeof createEvmClient;
  timeoutMs?: number;
  pollIntervalMs?: number;
  confirmations?: number;
}): (args: {
  execution: RecoveryExecutionRecord;
  newOwnerAddress: string;
  transactionHash: string;
}) => Promise<RecoveryAuthorityDeployedExecutionResult> {
  const createClientImpl = input.createClient || createEvmClient;
  const timeoutMs =
    Number.isFinite(Number(input.timeoutMs)) && Number(input.timeoutMs) > 0
      ? Math.floor(Number(input.timeoutMs))
      : 90_000;
  const pollIntervalMs =
    Number.isFinite(Number(input.pollIntervalMs)) && Number(input.pollIntervalMs) > 0
      ? Math.floor(Number(input.pollIntervalMs))
      : 1_250;
  const confirmations =
    Number.isFinite(Number(input.confirmations)) && Number(input.confirmations) > 0
      ? Math.floor(Number(input.confirmations))
      : 1;
  return async (args) => {
    const checkedAtMs = Date.now();
    const chainId = parseSponsoredChainId(args.execution.chainIdKey);
    if (!chainId) {
      return {
        status: 'failed',
        transactionHash: toOptionalTrimmedString(args.transactionHash),
        errorCode: 'unsupported_recovery_chain',
        errorMessage: `Unsupported recovery chainIdKey: ${args.execution.chainIdKey}`,
      };
    }
    const executor = input.config.executorsByChain.get(chainId);
    if (!executor) {
      return {
        status: 'failed',
        transactionHash: toOptionalTrimmedString(args.transactionHash),
        errorCode: 'sponsored_recovery_chain_unconfigured',
        errorMessage: `No sponsored EVM executor configured for chain ${chainId}`,
      };
    }
    const txHash = normalizeTransactionHash(args.transactionHash);
    if (!txHash) {
      return {
        status: 'failed',
        transactionHash: toOptionalTrimmedString(args.transactionHash),
        errorCode: 'invalid_recovery_transaction_hash',
        errorMessage: 'Recovery execution is missing a valid transaction hash',
      };
    }

    const client = createClientImpl({ rpcUrl: executor.rpcUrl });
    try {
      await client.waitForTransactionReceipt({
        txHash,
        timeoutMs,
        pollIntervalMs,
        confirmations,
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
        return {
          status: 'submitted',
          transactionHash: txHash,
          metadataPatch: {
            confirmationCheckedAtMs: checkedAtMs,
            confirmationPendingReason: 'receipt_unavailable_after_wait',
          },
        };
      }
      const receiptStatus = String(receipt.status || '').trim().toLowerCase();
      const gasUsedRaw = String(receipt.gasUsed || '').trim();
      const gasPriceRaw = String(receipt.effectiveGasPrice || receipt.gasPrice || '').trim();
      const gasUsed =
        /^0x[0-9a-f]+$/i.test(gasUsedRaw) ? parseEvmRpcHexQuantity(gasUsedRaw, 'gasUsed') : null;
      const effectiveGasPrice =
        /^0x[0-9a-f]+$/i.test(gasPriceRaw)
          ? parseEvmRpcHexQuantity(gasPriceRaw, 'effectiveGasPrice')
          : null;
      const feeAmount =
        gasUsed !== null && effectiveGasPrice !== null ? gasUsed * effectiveGasPrice : null;
      const metadataPatch = {
        confirmationCheckedAtMs: checkedAtMs,
        ...(gasUsed !== null ? { sponsoredGasUsed: gasUsed.toString(10) } : {}),
        ...(effectiveGasPrice !== null
          ? { sponsoredEffectiveGasPrice: effectiveGasPrice.toString(10) }
          : {}),
        ...(feeAmount !== null ? { sponsoredFeeAmount: feeAmount.toString(10) } : {}),
      };
      if (receiptStatus && receiptStatus !== '0x1' && receiptStatus !== '0x01' && receiptStatus !== '1') {
        return {
          status: 'failed',
          transactionHash: txHash,
          errorCode: 'tx_reverted',
          errorMessage: `Sponsored recovery transaction reverted (${txHash})`,
          metadataPatch,
        };
      }
      return {
        status: 'confirmed',
        transactionHash: txHash,
        metadataPatch,
      };
    } catch (e: unknown) {
      const error = e as Error & {
        code?: string;
        finalizationBranch?: string;
        gasUsed?: string;
        effectiveGasPrice?: string;
        feeAmount?: string;
      };
      const branch = toOptionalTrimmedString(error.finalizationBranch);
      const metadataPatch = {
        confirmationCheckedAtMs: checkedAtMs,
        ...(branch ? { confirmationFinalizationBranch: branch } : {}),
        ...(toOptionalTrimmedString(error.gasUsed) ? { sponsoredGasUsed: error.gasUsed } : {}),
        ...(toOptionalTrimmedString(error.effectiveGasPrice)
          ? { sponsoredEffectiveGasPrice: error.effectiveGasPrice }
          : {}),
        ...(toOptionalTrimmedString(error.feeAmount) ? { sponsoredFeeAmount: error.feeAmount } : {}),
      };
      if (error.code === 'tx_reverted') {
        return {
          status: 'failed',
          transactionHash: txHash,
          errorCode: error.code,
          errorMessage: error.message || 'Sponsored recovery transaction reverted',
          metadataPatch,
        };
      }
      if (
        branch === 'dropped_nonce_advanced' ||
        branch === 'dropped_hash_disappeared' ||
        branch === 'underpriced_fee'
      ) {
        return {
          status: 'failed',
          transactionHash: txHash,
          errorCode: branch,
          errorMessage: error.message || 'Sponsored recovery transaction will not confirm',
          metadataPatch,
        };
      }
      return {
        status: 'submitted',
        transactionHash: txHash,
        metadataPatch: {
          ...metadataPatch,
          confirmationPendingReason: error.message || 'Confirmation still pending',
        },
      };
    }
  };
}

export async function executePendingSmartAccountRecoveryExecutions(
  service: RecoveryAuthoritySignerPersistenceService,
  input?: {
    limit?: number;
    nowMs?: number;
    sponsorship?: RecoveryAuthoritySponsorshipRuntime | null;
    executeDeployedRecovery?: (args: {
      execution: RecoveryExecutionRecord;
      newOwnerAddress: string;
    }) => Promise<RecoveryAuthorityDeployedExecutionResult>;
  },
): Promise<
  | { ok: true; result: RecoveryAuthorityExecutionResult }
  | { ok: false; code: 'invalid_args' | 'internal'; message: string }
> {
  const limitRaw = Number(input?.limit);
  const limit = Number.isFinite(limitRaw) && limitRaw > 0 ? Math.floor(limitRaw) : undefined;
  if (typeof input?.limit !== 'undefined' && typeof limit === 'undefined') {
    return { ok: false, code: 'invalid_args', message: 'limit must be a positive integer' };
  }

  const pending = await service.listRecoveryExecutionsByStatus({
    status: 'pending',
    action: SMART_ACCOUNT_RECOVERY_ADD_OWNER_ACTION,
    ...(typeof limit === 'number' ? { limit } : {}),
  });
  if (!pending.ok) return pending;

  const result: RecoveryAuthorityExecutionResult = {
    processed: 0,
    confirmed: 0,
    submitted: 0,
    skipped: 0,
    failed: 0,
  };
  const deployedRecoveryExecutor =
    typeof input?.executeDeployedRecovery === 'function'
      ? input.executeDeployedRecovery
      : input?.sponsorship
        ? createSponsoredRecoveryDeployedExecutor({
            sponsorship: input.sponsorship,
          })
        : null;

  for (const execution of pending.records) {
    result.processed += 1;
    const nowMs = Number.isFinite(Number(input?.nowMs))
      ? Math.floor(Number(input?.nowMs))
      : Date.now();
    const newOwnerAddress = normalizeAddress(execution.metadata?.newEvmOwnerAddress);
    const metadata = {
      ...(execution.metadata || {}),
      processedBy: 'recoveryAuthority',
      processedAtMs: nowMs,
    };

    const reconcile = async () => {
      await reconcileRecoverySessionExecutionState(service, { sessionId: execution.sessionId });
    };

    if (!newOwnerAddress) {
      await service.recordRecoveryExecution({
        sessionId: execution.sessionId,
        chainIdKey: execution.chainIdKey,
        accountAddress: execution.accountAddress,
        action: execution.action,
        status: 'failed',
        errorCode: 'missing_new_evm_owner',
        errorMessage: 'Recovery execution metadata is missing newEvmOwnerAddress',
        metadata,
      });
      result.failed += 1;
      await reconcile();
      continue;
    }

    const resolved = normalizeResolution(resolveCanonicalTargetMode(execution));
    if (!resolved) {
      await service.recordRecoveryExecution({
        sessionId: execution.sessionId,
        chainIdKey: execution.chainIdKey,
        accountAddress: execution.accountAddress,
        action: execution.action,
        status: 'failed',
        errorCode: 'recovery_target_mode_unresolved',
        errorMessage: 'Recovery target mode could not be resolved from canonical execution metadata',
        metadata,
      });
      result.failed += 1;
      await reconcile();
      continue;
    }

    const executionMetadata = {
      ...metadata,
      recoveryTargetMode: resolved.mode,
      ...(resolved.metadataPatch || {}),
    };

    if (resolved.mode === 'undeployed') {
      const activated = await activateRecoveredSigner(service, {
        execution,
        newOwnerAddress,
        nowMs,
      });
      if (!activated.ok) {
        await service.recordRecoveryExecution({
          sessionId: execution.sessionId,
          chainIdKey: execution.chainIdKey,
          accountAddress: execution.accountAddress,
          action: execution.action,
          status: 'failed',
          errorCode: activated.code,
          errorMessage: activated.message,
          metadata: executionMetadata,
        });
        result.failed += 1;
        await reconcile();
        continue;
      }

      await service.recordRecoveryExecution({
        sessionId: execution.sessionId,
        chainIdKey: execution.chainIdKey,
        accountAddress: execution.accountAddress,
        action: execution.action,
        status: 'confirmed',
        metadata: {
          ...executionMetadata,
          canonicalSignerActivatedAtMs: nowMs,
        },
      });
      result.confirmed += 1;
      await reconcile();
      continue;
    }

    if (!deployedRecoveryExecutor) {
      result.skipped += 1;
      continue;
    }

    try {
      const deployedResult = await deployedRecoveryExecutor({
        execution,
        newOwnerAddress,
      });
      if (deployedResult.status === 'failed') {
        await service.recordRecoveryExecution({
          sessionId: execution.sessionId,
          chainIdKey: execution.chainIdKey,
          accountAddress: execution.accountAddress,
          action: execution.action,
          status: 'failed',
          errorCode: toOptionalTrimmedString(deployedResult.errorCode) || 'recovery_execution_failed',
          errorMessage:
            toOptionalTrimmedString(deployedResult.errorMessage) ||
            'Deployed recovery execution failed',
          metadata: {
            ...executionMetadata,
            ...(deployedResult.metadataPatch || {}),
          },
        });
        result.failed += 1;
        await reconcile();
        continue;
      }

      if (deployedResult.status === 'submitted') {
        await service.recordRecoveryExecution({
          sessionId: execution.sessionId,
          chainIdKey: execution.chainIdKey,
          accountAddress: execution.accountAddress,
          action: execution.action,
          status: 'submitted',
          transactionHash: toOptionalTrimmedString(deployedResult.transactionHash),
          metadata: {
            ...executionMetadata,
            ...(deployedResult.metadataPatch || {}),
          },
        });
        result.submitted += 1;
        await reconcile();
        continue;
      }

      if (deployedResult.status === 'confirmed') {
        const activated = await activateRecoveredSigner(service, {
          execution,
          newOwnerAddress,
          nowMs,
        });
        if (!activated.ok) {
          await service.recordRecoveryExecution({
            sessionId: execution.sessionId,
            chainIdKey: execution.chainIdKey,
            accountAddress: execution.accountAddress,
            action: execution.action,
            status: 'failed',
            errorCode: activated.code,
            errorMessage: activated.message,
            metadata: {
              ...executionMetadata,
              ...(deployedResult.metadataPatch || {}),
            },
          });
          result.failed += 1;
          await reconcile();
          continue;
        }

        await service.recordRecoveryExecution({
          sessionId: execution.sessionId,
          chainIdKey: execution.chainIdKey,
          accountAddress: execution.accountAddress,
          action: execution.action,
          status: 'confirmed',
          transactionHash: toOptionalTrimmedString(deployedResult.transactionHash),
          metadata: {
            ...executionMetadata,
            canonicalSignerActivatedAtMs: nowMs,
            ...(deployedResult.metadataPatch || {}),
          },
        });
        result.confirmed += 1;
        await reconcile();
        continue;
      }

      await service.recordRecoveryExecution({
        sessionId: execution.sessionId,
        chainIdKey: execution.chainIdKey,
        accountAddress: execution.accountAddress,
        action: execution.action,
        status: 'skipped',
        transactionHash: toOptionalTrimmedString(deployedResult.transactionHash),
        metadata: {
          ...executionMetadata,
          ...(deployedResult.metadataPatch || {}),
        },
      });
      result.skipped += 1;
      await reconcile();
    } catch (e: unknown) {
      await service.recordRecoveryExecution({
        sessionId: execution.sessionId,
        chainIdKey: execution.chainIdKey,
        accountAddress: execution.accountAddress,
        action: execution.action,
        status: 'failed',
        errorCode: 'recovery_executor_threw',
        errorMessage: e instanceof Error ? e.message : 'Deployed recovery execution threw',
        metadata: executionMetadata,
      });
      result.failed += 1;
      await reconcile();
    }
  }

  return { ok: true, result };
}

export async function retryFailedSmartAccountRecoveryExecutions(
  service: RecoveryAuthoritySignerPersistenceService,
  input?: {
    limit?: number;
    nowMs?: number;
    retryAfterMs?: number;
    maxRetryCount?: number;
  },
): Promise<
  | { ok: true; result: RecoveryAuthorityRetryResult }
  | { ok: false; code: 'invalid_args' | 'internal'; message: string }
> {
  const limitRaw = Number(input?.limit);
  const limit = Number.isFinite(limitRaw) && limitRaw > 0 ? Math.floor(limitRaw) : undefined;
  if (typeof input?.limit !== 'undefined' && typeof limit === 'undefined') {
    return { ok: false, code: 'invalid_args', message: 'limit must be a positive integer' };
  }

  const retryAfterMs =
    normalizePositiveInteger(input?.retryAfterMs) || DEFAULT_FAILED_RECOVERY_RETRY_AFTER_MS;
  const maxRetryCount =
    normalizePositiveInteger(input?.maxRetryCount) || DEFAULT_FAILED_RECOVERY_MAX_RETRIES;

  const failed = await service.listRecoveryExecutionsByStatus({
    status: 'failed',
    action: SMART_ACCOUNT_RECOVERY_ADD_OWNER_ACTION,
    ...(typeof limit === 'number' ? { limit } : {}),
  });
  if (!failed.ok) return failed;

  const result: RecoveryAuthorityRetryResult = {
    processed: 0,
    retried: 0,
    skipped: 0,
    failed: 0,
  };

  for (const execution of failed.records) {
    result.processed += 1;
    const nowMs = Number.isFinite(Number(input?.nowMs))
      ? Math.floor(Number(input?.nowMs))
      : Date.now();
    if (
      !canRetryRecoveryExecution({
        execution,
        nowMs,
        retryAfterMs,
        maxRetryCount,
      })
    ) {
      result.skipped += 1;
      continue;
    }

    const retried = await service.recordRecoveryExecution({
      sessionId: execution.sessionId,
      chainIdKey: execution.chainIdKey,
      accountAddress: execution.accountAddress,
      action: execution.action,
      status: 'pending',
      metadata: buildRetriedRecoveryExecutionMetadata({
        execution,
        nowMs,
      }),
    });
    if (!retried.ok) {
      result.failed += 1;
      continue;
    }

    result.retried += 1;
    await reconcileRecoverySessionExecutionState(service, { sessionId: execution.sessionId });
  }

  return { ok: true, result };
}

export async function confirmSubmittedSmartAccountRecoveryExecutions(
  service: RecoveryAuthoritySignerPersistenceService,
  input?: {
    limit?: number;
    nowMs?: number;
    sponsorship?: RecoveryAuthoritySponsorshipRuntime | null;
    confirmSubmittedRecovery?: (args: {
      execution: RecoveryExecutionRecord;
      newOwnerAddress: string;
      transactionHash: string;
    }) => Promise<RecoveryAuthorityDeployedExecutionResult>;
  },
): Promise<
  | { ok: true; result: RecoveryAuthorityExecutionResult }
  | { ok: false; code: 'invalid_args' | 'internal'; message: string }
> {
  const limitRaw = Number(input?.limit);
  const limit = Number.isFinite(limitRaw) && limitRaw > 0 ? Math.floor(limitRaw) : undefined;
  if (typeof input?.limit !== 'undefined' && typeof limit === 'undefined') {
    return { ok: false, code: 'invalid_args', message: 'limit must be a positive integer' };
  }

  const submitted = await service.listRecoveryExecutionsByStatus({
    status: 'submitted',
    action: SMART_ACCOUNT_RECOVERY_ADD_OWNER_ACTION,
    ...(typeof limit === 'number' ? { limit } : {}),
  });
  if (!submitted.ok) return submitted;

  const result: RecoveryAuthorityExecutionResult = {
    processed: 0,
    confirmed: 0,
    submitted: 0,
    skipped: 0,
    failed: 0,
  };
  const submittedRecoveryConfirmer =
    typeof input?.confirmSubmittedRecovery === 'function'
      ? input.confirmSubmittedRecovery
      : input?.sponsorship?.config
        ? createSponsoredRecoverySubmittedConfirmer({
            config: input.sponsorship.config,
          })
        : null;

  for (const execution of submitted.records) {
    result.processed += 1;
    const nowMs = Number.isFinite(Number(input?.nowMs))
      ? Math.floor(Number(input?.nowMs))
      : Date.now();
    const newOwnerAddress = normalizeAddress(execution.metadata?.newEvmOwnerAddress);
    const txHash = normalizeTransactionHash(execution.transactionHash);
    const metadata = {
      ...(execution.metadata || {}),
      processedBy: 'recoveryAuthority',
      processedAtMs: nowMs,
      confirmationCheckedAtMs: nowMs,
    };

    const reconcile = async () => {
      await reconcileRecoverySessionExecutionState(service, { sessionId: execution.sessionId });
    };

    if (!newOwnerAddress) {
      await service.recordRecoveryExecution({
        sessionId: execution.sessionId,
        chainIdKey: execution.chainIdKey,
        accountAddress: execution.accountAddress,
        action: execution.action,
        status: 'failed',
        transactionHash: toOptionalTrimmedString(execution.transactionHash),
        errorCode: 'missing_new_evm_owner',
        errorMessage: 'Recovery execution metadata is missing newEvmOwnerAddress',
        metadata,
      });
      result.failed += 1;
      await reconcile();
      continue;
    }

    const targetMode = toOptionalTrimmedString(execution.metadata?.recoveryTargetMode);
    if (targetMode && targetMode !== 'deployed') {
      await service.recordRecoveryExecution({
        sessionId: execution.sessionId,
        chainIdKey: execution.chainIdKey,
        accountAddress: execution.accountAddress,
        action: execution.action,
        status: 'failed',
        transactionHash: toOptionalTrimmedString(execution.transactionHash),
        errorCode: 'invalid_submitted_recovery_target_mode',
        errorMessage: `Submitted recovery execution cannot be confirmed for target mode ${targetMode}`,
        metadata,
      });
      result.failed += 1;
      await reconcile();
      continue;
    }

    if (!txHash) {
      await service.recordRecoveryExecution({
        sessionId: execution.sessionId,
        chainIdKey: execution.chainIdKey,
        accountAddress: execution.accountAddress,
        action: execution.action,
        status: 'failed',
        errorCode: 'missing_recovery_transaction_hash',
        errorMessage: 'Submitted recovery execution is missing a transaction hash',
        metadata,
      });
      result.failed += 1;
      await reconcile();
      continue;
    }

    if (!submittedRecoveryConfirmer) {
      result.skipped += 1;
      continue;
    }

    try {
      const confirmation = await submittedRecoveryConfirmer({
        execution,
        newOwnerAddress,
        transactionHash: txHash,
      });
      if (confirmation.status === 'failed') {
        await service.recordRecoveryExecution({
          sessionId: execution.sessionId,
          chainIdKey: execution.chainIdKey,
          accountAddress: execution.accountAddress,
          action: execution.action,
          status: 'failed',
          transactionHash: toOptionalTrimmedString(confirmation.transactionHash) || txHash,
          errorCode:
            toOptionalTrimmedString(confirmation.errorCode) || 'recovery_confirmation_failed',
          errorMessage:
            toOptionalTrimmedString(confirmation.errorMessage) ||
            'Submitted recovery confirmation failed',
          metadata: {
            ...metadata,
            ...(confirmation.metadataPatch || {}),
          },
        });
        result.failed += 1;
        await reconcile();
        continue;
      }

      if (confirmation.status === 'submitted') {
        await service.recordRecoveryExecution({
          sessionId: execution.sessionId,
          chainIdKey: execution.chainIdKey,
          accountAddress: execution.accountAddress,
          action: execution.action,
          status: 'submitted',
          transactionHash: toOptionalTrimmedString(confirmation.transactionHash) || txHash,
          metadata: {
            ...metadata,
            ...(confirmation.metadataPatch || {}),
          },
        });
        result.submitted += 1;
        await reconcile();
        continue;
      }

      if (confirmation.status === 'confirmed') {
        const activated = await activateRecoveredSigner(service, {
          execution,
          newOwnerAddress,
          nowMs,
        });
        if (!activated.ok) {
          await service.recordRecoveryExecution({
            sessionId: execution.sessionId,
            chainIdKey: execution.chainIdKey,
            accountAddress: execution.accountAddress,
            action: execution.action,
            status: 'failed',
            transactionHash: toOptionalTrimmedString(confirmation.transactionHash) || txHash,
            errorCode: activated.code,
            errorMessage: activated.message,
            metadata: {
              ...metadata,
              ...(confirmation.metadataPatch || {}),
            },
          });
          result.failed += 1;
          await reconcile();
          continue;
        }

        await service.recordRecoveryExecution({
          sessionId: execution.sessionId,
          chainIdKey: execution.chainIdKey,
          accountAddress: execution.accountAddress,
          action: execution.action,
          status: 'confirmed',
          transactionHash: toOptionalTrimmedString(confirmation.transactionHash) || txHash,
          metadata: {
            ...metadata,
            canonicalSignerActivatedAtMs: nowMs,
            ...(confirmation.metadataPatch || {}),
          },
        });
        result.confirmed += 1;
        await reconcile();
        continue;
      }

      await service.recordRecoveryExecution({
        sessionId: execution.sessionId,
        chainIdKey: execution.chainIdKey,
        accountAddress: execution.accountAddress,
        action: execution.action,
        status: 'skipped',
        transactionHash: toOptionalTrimmedString(confirmation.transactionHash) || txHash,
        metadata: {
          ...metadata,
          ...(confirmation.metadataPatch || {}),
        },
      });
      result.skipped += 1;
      await reconcile();
    } catch (e: unknown) {
      await service.recordRecoveryExecution({
        sessionId: execution.sessionId,
        chainIdKey: execution.chainIdKey,
        accountAddress: execution.accountAddress,
        action: execution.action,
        status: 'failed',
        transactionHash: txHash,
        errorCode: 'recovery_confirmation_threw',
        errorMessage: e instanceof Error ? e.message : 'Submitted recovery confirmation threw',
        metadata,
      });
      result.failed += 1;
      await reconcile();
    }
  }

  return { ok: true, result };
}
