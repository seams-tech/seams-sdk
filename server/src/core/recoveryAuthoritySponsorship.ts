import { toOptionalTrimmedString } from '@shared/utils/validation';
import type { RecoveryExecutionRecord } from './RecoveryExecutionStore';
import type { RecoveryAuthorityDeployedExecutionResult } from './recoveryAuthority';
import {
  buildRecoveryAuthorityAuthorizationDigest,
  encodeRecoveryAuthorityCalldata,
  getRecoveryAuthorityFunctionSelector,
  getRecoveryAuthorityFunctionSignature,
  signRecoveryAuthorityAuthorization,
  type RecoveryAuthorityAuthorization,
  type RecoveryAuthorityContractMethod,
} from './recoveryAuthorityAuthorization';
import type { RecoveryAuthoritySponsorshipRuntime } from '../router/recoveryAuthoritySponsorship';
import { parseRecoveryAuthoritySponsorshipScope } from '../router/recoveryAuthoritySponsorship';
import type { RelayRuntimeSnapshotScope } from '../router/relay';
import type { ConsoleSponsoredCallReceiptStatus } from '../console/sponsoredCalls';
import {
  buildSponsoredSpendCapSourceEventId,
  executeSponsorshipAdapter,
  isSponsorshipPrepaidBalanceEnforcementError,
  isSponsorshipSpendCapEnforcementError,
  matchResolvedSponsoredEvmCallPolicy,
  parseResolvedSponsoredEvmCallPolicies,
  releaseSponsoredSpendCap,
  reserveSponsoredPrepaidBalance,
  reserveSponsoredSpendCap,
  resolveSponsoredEvmExecutionAdapter,
  settleSponsoredSpendCap,
  type SponsorshipSpendCapSettlement,
} from '../sponsorship';
import {
  emitSponsorshipBlockedObservabilityEvent,
  readSponsorshipBillingBalanceSnapshot,
} from '../router/sponsorshipBillingEvents';
import {
  logSponsorshipSpendCapRejected,
  logSponsorshipSpendCapReserved,
  logSponsorshipSpendCapSettled,
} from '../router/sponsorshipSpendCapObservability';
import {
  recordSponsoredExecution,
  type SponsorshipExecutionAssessment,
} from '../router/sponsorshipExecution';

const DEFAULT_RECOVERY_CONTRACT_METHOD: RecoveryAuthorityContractMethod = 'verifyAndRecover';
const DEFAULT_RECOVERY_AUTHORIZATION_GAS_LIMIT = 250_000n;
export const RECOVERY_AUTHORITY_SPONSORED_EVM_ROUTE_ID =
  'recovery_authority_sponsored_evm_call_v1';
const RECOVERY_AUTHORITY_SPONSORED_EVM_API_KEY_ID = 'system:recovery-authority';

type RecoverySponsoredEvmExecution = {
  txHash: `0x${string}`;
  gasUsed: string;
  effectiveGasPrice: string;
  feeAmount: string;
};

type RecoverySponsoredEvmExecutionAssessment = SponsorshipExecutionAssessment & {
  txHash: `0x${string}` | null;
  gasUsed: string | null;
  effectiveGasPrice: string | null;
};

function normalizeOptionalString(value: unknown): string | undefined {
  const normalized = String(value || '').trim();
  return normalized || undefined;
}

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

function buildAccountRef(value: string): string {
  return `near:${value}`;
}

function buildTargetRef(chainId: number, to: `0x${string}`): string {
  return `evm:${chainId}:${to.toLowerCase()}`;
}

function buildSponsorRef(chainId: number, sponsorAddress: `0x${string}`): string {
  return `evm:${chainId}:${sponsorAddress.toLowerCase()}`;
}

function resolveRecoverySponsorshipScope(
  execution: RecoveryExecutionRecord,
): RelayRuntimeSnapshotScope | null {
  const metadata = asObject(execution.metadata);
  return (
    parseRecoveryAuthoritySponsorshipScope(metadata.sponsorshipScope) ||
    parseRecoveryAuthoritySponsorshipScope(asObject(metadata.linkedAccount).sponsorshipScope)
  );
}

function buildRecoveryIdempotencyKey(execution: RecoveryExecutionRecord): string {
  return [
    'recovery-authority',
    execution.sessionId,
    execution.chainIdKey,
    execution.accountAddress.toLowerCase(),
    execution.action,
  ]
    .map((entry) => String(entry || '').trim())
    .filter(Boolean)
    .join(':');
}

async function buildRecoveryContractAuthorization(input: {
  execution: RecoveryExecutionRecord;
  chainId: number;
  accountAddress: `0x${string}`;
  newOwnerAddress: `0x${string}`;
  sponsorAddress: `0x${string}`;
  sponsorPrivateKeyHex: `0x${string}`;
  contractMethod?: RecoveryAuthorityContractMethod;
}): Promise<{
  contractMethod: RecoveryAuthorityContractMethod;
  functionSignature: string;
  selector: `0x${string}`;
  authorization: RecoveryAuthorityAuthorization;
  calldata: `0x${string}`;
}> {
  const metadata = asObject(input.execution.metadata);
  const newNearPublicKey = toOptionalTrimmedString(metadata.expectedNewNearPublicKey);
  const recoveryDeadlineEpochSeconds = Number(metadata.recoveryDeadlineEpochSeconds);
  if (!newNearPublicKey) {
    throw new Error('Recovery execution metadata is missing expectedNewNearPublicKey');
  }
  if (!Number.isFinite(recoveryDeadlineEpochSeconds) || recoveryDeadlineEpochSeconds <= 0) {
    throw new Error('Recovery execution metadata is missing recoveryDeadlineEpochSeconds');
  }

  const contractMethod = input.contractMethod || DEFAULT_RECOVERY_CONTRACT_METHOD;
  const unsignedAuthorization = buildRecoveryAuthorityAuthorizationDigest({
    contractMethod,
    chainId: input.chainId,
    verifyingContract: input.accountAddress,
    nearAccountId: input.execution.nearAccountId,
    newNearPublicKey,
    newOwnerAddress: input.newOwnerAddress,
    recoverySessionId: input.execution.sessionId,
    deadlineEpochSeconds: Math.floor(recoveryDeadlineEpochSeconds),
  });
  const authorization = await signRecoveryAuthorityAuthorization({
    authorityPrivateKeyHex: input.sponsorPrivateKeyHex,
    authorityAddress: input.sponsorAddress,
    authorization: unsignedAuthorization,
  });
  return {
    contractMethod,
    functionSignature: getRecoveryAuthorityFunctionSignature(contractMethod),
    selector: getRecoveryAuthorityFunctionSelector(contractMethod),
    calldata: encodeRecoveryAuthorityCalldata(authorization),
    authorization,
  };
}

function buildSuccessfulSponsoredEvmAssessment(
  execution: RecoverySponsoredEvmExecution,
): RecoverySponsoredEvmExecutionAssessment {
  return {
    succeeded: true,
    txOrExecutionRef: execution.txHash,
    txHash: execution.txHash,
    receiptStatus: 'success',
    feeUnit: 'wei',
    feeAmount: execution.feeAmount,
    executorKind: 'evm_eoa',
    responseCode: 'ok',
    responseMessage: 'Sponsored recovery call executed',
    recordErrorCode: null,
    recordErrorMessage: null,
    gasUsed: execution.gasUsed,
    effectiveGasPrice: execution.effectiveGasPrice,
  };
}

function buildFailedSponsoredEvmAssessment(error: unknown): RecoverySponsoredEvmExecutionAssessment {
  const responseMessage =
    error instanceof Error ? error.message : String(error || 'Sponsored recovery call failed');
  const responseCode =
    error && typeof error === 'object' && 'code' in error
      ? String((error as { code?: unknown }).code || '').trim() || 'sponsored_recovery_failed'
      : 'sponsored_recovery_failed';
  const txHash =
    error && typeof error === 'object' && 'txHash' in error
      ? normalizeTransactionHash((error as { txHash?: unknown }).txHash)
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
  const receiptStatus: ConsoleSponsoredCallReceiptStatus =
    responseCode === 'tx_reverted' ? 'reverted' : txHash ? 'broadcast_failed' : 'rpc_rejected';
  return {
    succeeded: false,
    txOrExecutionRef: txHash,
    txHash,
    receiptStatus,
    feeUnit: 'wei',
    feeAmount,
    executorKind: 'evm_eoa',
    responseCode,
    responseMessage,
    recordErrorCode: responseCode,
    recordErrorMessage: responseMessage,
    gasUsed,
    effectiveGasPrice,
  };
}

function buildMetadataPatch(input: {
  scope: RelayRuntimeSnapshotScope;
  chainId: number;
  sponsorAddress: `0x${string}`;
  contractMethod: RecoveryAuthorityContractMethod;
  functionSignature: string;
  selector: `0x${string}`;
  authorization: RecoveryAuthorityAuthorization;
  idempotencyKey: string;
  policyId: string;
  policyName: string;
  templateId: string | null;
  assessment: RecoverySponsoredEvmExecutionAssessment;
  recordId?: string;
  spendCapSettlement?: (SponsorshipSpendCapSettlement & {
    sourceEventId: string;
    estimatedSpendMinor: number;
  }) | null;
  bookkeepingError?: string;
}): Record<string, unknown> {
  return {
    sponsorshipScope: {
      orgId: input.scope.orgId,
      environmentId: input.scope.environmentId,
      ...(input.scope.projectId ? { projectId: input.scope.projectId } : {}),
    },
    sponsoredRouteId: RECOVERY_AUTHORITY_SPONSORED_EVM_ROUTE_ID,
    sponsoredApiKeyId: RECOVERY_AUTHORITY_SPONSORED_EVM_API_KEY_ID,
    sponsoredExecutorKind: input.assessment.executorKind,
    sponsoredChainId: input.chainId,
    sponsorAddress: input.sponsorAddress,
    recoveryContractMethod: input.contractMethod,
    recoveryFunctionSignature: input.functionSignature,
    sponsoredSelector: input.selector,
    recoveryAuthorityAddress: input.authorization.authorityAddress,
    recoveryAuthorizationDigest: input.authorization.digest,
    recoveryAuthorizationNonce: input.authorization.payload.nonce,
    recoveryAuthorizationDeadline: input.authorization.payload.deadline,
    recoveryAuthorizationNearAccountIdHash: input.authorization.payload.nearAccountIdHash,
    recoveryAuthorizationNewNearKeyHash: input.authorization.payload.newNearKeyHash,
    recoveryAuthorizationSessionHash: input.authorization.payload.recoverySessionHash,
    sponsoredPolicyId: input.policyId,
    sponsoredPolicyName: input.policyName,
    ...(input.templateId ? { sponsoredTemplateId: input.templateId } : {}),
    sponsoredEnvironmentId: input.scope.environmentId,
    sponsoredOrgId: input.scope.orgId,
    ...(input.scope.projectId ? { sponsoredProjectId: input.scope.projectId } : {}),
    sponsoredIdempotencyKey: input.idempotencyKey,
    sponsoredReceiptStatus: input.assessment.receiptStatus,
    ...(input.assessment.txHash ? { sponsoredTransactionHash: input.assessment.txHash } : {}),
    ...(input.assessment.gasUsed ? { sponsoredGasUsed: input.assessment.gasUsed } : {}),
    ...(input.assessment.effectiveGasPrice
      ? { sponsoredEffectiveGasPrice: input.assessment.effectiveGasPrice }
      : {}),
    sponsoredFeeAmount: input.assessment.feeAmount,
    ...(input.recordId ? { sponsoredRecordId: input.recordId } : {}),
    ...(input.spendCapSettlement
      ? {
          sponsoredSpendCap: {
            sourceEventId: input.spendCapSettlement.sourceEventId,
            estimatedSpendMinor: input.spendCapSettlement.estimatedSpendMinor,
            settledSpendMinor: input.spendCapSettlement.settledSpendMinor,
            pricingVersion: input.spendCapSettlement.pricingVersion,
            usedEstimatedFallback: input.spendCapSettlement.usedEstimatedFallback,
          },
        }
      : {}),
    ...(input.bookkeepingError ? { sponsoredBookkeepingError: input.bookkeepingError } : {}),
  };
}

function buildDetailsJson(input: {
  execution: RecoveryExecutionRecord;
  scope: RelayRuntimeSnapshotScope;
  chainId: number;
  ownerAddress: `0x${string}`;
  contractMethod: RecoveryAuthorityContractMethod;
  functionSignature: string;
  selector: `0x${string}`;
  calldata: `0x${string}`;
  authorization: RecoveryAuthorityAuthorization;
  accountAddress: `0x${string}`;
  gasLimit: bigint;
  assessment: RecoverySponsoredEvmExecutionAssessment;
  spendCapSettlement?: (SponsorshipSpendCapSettlement & {
    sourceEventId: string;
    estimatedSpendMinor: number;
  }) | null;
  prepaidSettlement?: {
    sourceEventId: string | null;
    estimatedSpendMinor: number | null;
    settledSpendMinor: number | null;
    pricingVersion: string | null;
    usedEstimatedFallback: boolean | null;
    released: boolean | null;
  };
}): string {
  return JSON.stringify({
    kind: 'recovery_authority_recover_add_owner_v1',
    recovery: {
      sessionId: input.execution.sessionId,
      nearAccountId: input.execution.nearAccountId,
      userId: input.execution.userId,
      chainIdKey: input.execution.chainIdKey,
      accountAddress: input.accountAddress,
      newOwnerAddress: input.ownerAddress,
      action: input.execution.action,
    },
    sponsorshipScope: {
      orgId: input.scope.orgId,
      environmentId: input.scope.environmentId,
      ...(input.scope.projectId ? { projectId: input.scope.projectId } : {}),
    },
    call: {
      to: input.accountAddress,
      data: input.calldata,
      gasLimit: input.gasLimit.toString(10),
      valueWei: '0',
      contractMethod: input.contractMethod,
      functionSignature: input.functionSignature,
      selector: input.selector,
    },
    authorization: input.authorization,
    execution: {
      txHash: input.assessment.txHash,
      gasUsed: input.assessment.gasUsed,
      effectiveGasPrice: input.assessment.effectiveGasPrice,
      feeAmount: input.assessment.feeAmount,
      receiptStatus: input.assessment.receiptStatus,
      responseCode: input.assessment.responseCode,
      responseMessage: input.assessment.responseMessage,
    },
    ...(input.prepaidSettlement
      ? {
          billing: input.prepaidSettlement,
        }
      : {}),
    ...(input.spendCapSettlement
      ? {
          policySpendCap: {
            sourceEventId: input.spendCapSettlement.sourceEventId,
            estimatedSpendMinor: input.spendCapSettlement.estimatedSpendMinor,
            settledSpendMinor: input.spendCapSettlement.settledSpendMinor,
            pricingVersion: input.spendCapSettlement.pricingVersion,
            usedEstimatedFallback: input.spendCapSettlement.usedEstimatedFallback,
          },
        }
      : {}),
  });
}

export function createSponsoredRecoveryDeployedExecutor(input: {
  sponsorship: RecoveryAuthoritySponsorshipRuntime;
  executeAdapter?: typeof executeSponsorshipAdapter;
  reserveSpendCap?: typeof reserveSponsoredSpendCap;
  releaseSpendCap?: typeof releaseSponsoredSpendCap;
  reservePrepaidBalance?: typeof reserveSponsoredPrepaidBalance;
  settleSpendCap?: typeof settleSponsoredSpendCap;
  recordExecution?: typeof recordSponsoredExecution;
  readBalanceSnapshot?: typeof readSponsorshipBillingBalanceSnapshot;
  emitBlockedObservabilityEvent?: typeof emitSponsorshipBlockedObservabilityEvent;
  logSpendCapReserved?: typeof logSponsorshipSpendCapReserved;
  logSpendCapRejected?: typeof logSponsorshipSpendCapRejected;
  logSpendCapSettled?: typeof logSponsorshipSpendCapSettled;
  gasLimit?: bigint;
}): (args: {
  execution: RecoveryExecutionRecord;
  newOwnerAddress: string;
}) => Promise<RecoveryAuthorityDeployedExecutionResult> {
  const executeAdapter = input.executeAdapter || executeSponsorshipAdapter;
  const reserveSpendCap = input.reserveSpendCap || reserveSponsoredSpendCap;
  const releaseSpendCap = input.releaseSpendCap || releaseSponsoredSpendCap;
  const reservePrepaidBalance = input.reservePrepaidBalance || reserveSponsoredPrepaidBalance;
  const settleSpendCap = input.settleSpendCap || settleSponsoredSpendCap;
  const recordExecution = input.recordExecution || recordSponsoredExecution;
  const readBalanceSnapshot = input.readBalanceSnapshot || readSponsorshipBillingBalanceSnapshot;
  const emitBlockedObservabilityEvent =
    input.emitBlockedObservabilityEvent || emitSponsorshipBlockedObservabilityEvent;
  const logSpendCapReserved = input.logSpendCapReserved || logSponsorshipSpendCapReserved;
  const logSpendCapRejected = input.logSpendCapRejected || logSponsorshipSpendCapRejected;
  const logSpendCapSettled = input.logSpendCapSettled || logSponsorshipSpendCapSettled;
  const gasLimit =
    typeof input.gasLimit === 'bigint' && input.gasLimit > 0n
      ? input.gasLimit
      : DEFAULT_RECOVERY_AUTHORIZATION_GAS_LIMIT;

  return async ({ execution, newOwnerAddress }) => {
    const chainId = parseSponsoredChainId(execution.chainIdKey);
    const accountAddress = normalizeAddress(execution.accountAddress);
    const ownerAddress = normalizeAddress(newOwnerAddress);
    const scope = resolveRecoverySponsorshipScope(execution);
    if (!chainId) {
      return {
        status: 'failed',
        errorCode: 'unsupported_recovery_chain',
        errorMessage: `Unsupported recovery chainIdKey: ${execution.chainIdKey}`,
      };
    }
    if (!accountAddress || !ownerAddress) {
      return {
        status: 'failed',
        errorCode: 'invalid_recovery_target',
        errorMessage: 'Recovery execution target account or owner address is invalid',
      };
    }
    if (!scope) {
      return {
        status: 'failed',
        errorCode: 'recovery_sponsorship_scope_missing',
        errorMessage: 'Recovery execution metadata is missing sponsorship scope',
      };
    }

    const sponsorshipCtx = {
      orgId: scope.orgId,
      actorUserId: 'recovery-authority',
      roles: ['system'],
    };
    const latestSnapshot = await input.sponsorship.runtimeSnapshots.getLatestSnapshot(sponsorshipCtx, {
      environmentId: scope.environmentId,
      ...(scope.projectId ? { projectId: scope.projectId } : {}),
    });
    if (!latestSnapshot) {
      return {
        status: 'failed',
        errorCode: 'runtime_snapshot_not_found',
        errorMessage: 'No runtime snapshot is available for recovery sponsorship scope',
        metadataPatch: {
          sponsorshipScope: scope,
        },
      };
    }

    const policies = parseResolvedSponsoredEvmCallPolicies(latestSnapshot.payload);
    const executorConfig = input.sponsorship.config.executorsByChain.get(chainId);
    if (!executorConfig) {
      return {
        status: 'failed',
        errorCode: 'sponsor_chain_misconfigured',
        errorMessage: `Sponsor executor is not configured for chain ${chainId}`,
        metadataPatch: {
          sponsorshipScope: scope,
        },
      };
    }
    let recoveryContractAuthorization: {
      contractMethod: RecoveryAuthorityContractMethod;
      functionSignature: string;
      selector: `0x${string}`;
      authorization: RecoveryAuthorityAuthorization;
      calldata: `0x${string}`;
    };
    try {
      recoveryContractAuthorization = await buildRecoveryContractAuthorization({
        execution,
        chainId,
        accountAddress: accountAddress as `0x${string}`,
        newOwnerAddress: ownerAddress as `0x${string}`,
        sponsorAddress: executorConfig.sponsorAddress,
        sponsorPrivateKeyHex: executorConfig.sponsorPrivateKeyHex,
      });
    } catch (error: unknown) {
      return {
        status: 'failed',
        errorCode: 'invalid_recovery_authorization',
        errorMessage:
          error instanceof Error ? error.message : 'Failed to build recovery authorization',
      };
    }

    const call = {
      to: accountAddress as `0x${string}`,
      data: recoveryContractAuthorization.calldata,
      gasLimit,
      value: 0n,
    } as const;
    const adapter = resolveSponsoredEvmExecutionAdapter({
      config: input.sponsorship.config,
      chainId,
      call,
    });
    if (!adapter) {
      return {
        status: 'failed',
        errorCode: 'sponsor_chain_misconfigured',
        errorMessage: `Sponsor executor is not configured for chain ${chainId}`,
        metadataPatch: {
          sponsorshipScope: scope,
        },
      };
    }
    const matched = matchResolvedSponsoredEvmCallPolicy({
      policies,
      chainId,
      call,
    });
    if (!matched.ok) {
      return {
        status: 'failed',
        errorCode: matched.code,
        errorMessage: `Recovery sponsorship policy mismatch: ${matched.code}`,
        metadataPatch: {
          sponsorshipScope: scope,
          recoveryContractMethod: recoveryContractAuthorization.contractMethod,
          recoveryFunctionSignature: recoveryContractAuthorization.functionSignature,
          sponsoredSelector: recoveryContractAuthorization.selector,
          sponsoredPolicyMatchCode: matched.code,
        },
      };
    }

    const subjectAccountId =
      normalizeOptionalString(execution.nearAccountId) ||
      normalizeOptionalString(execution.userId) ||
      'recovery-subject';
    const accountRef = buildAccountRef(subjectAccountId);
    const targetRef = buildTargetRef(chainId, call.to);
    const sponsorRef = buildSponsorRef(chainId, adapter.meta.sponsorAddress);
    const idempotencyKey = buildRecoveryIdempotencyKey(execution);
    const spendCapSourceEventId = buildSponsoredSpendCapSourceEventId({
      chainFamily: 'evm',
      intentKind: 'evm_call',
      idempotencyKey,
    });
    const prepaidBalanceSourceEventId = buildSponsoredSpendCapSourceEventId({
      chainFamily: 'evm',
      intentKind: 'evm_call',
      idempotencyKey,
    });
    const requestDetails = {
      recoverySessionId: execution.sessionId,
      nearAccountId: execution.nearAccountId,
      walletAddress: call.to,
      newOwnerAddress: ownerAddress,
      call: {
        to: call.to,
        data: call.data,
        gasLimit: call.gasLimit.toString(10),
        valueWei: call.value.toString(10),
        contractMethod: recoveryContractAuthorization.contractMethod,
        functionSignature: recoveryContractAuthorization.functionSignature,
        selector: recoveryContractAuthorization.selector,
      },
      authorization: recoveryContractAuthorization.authorization,
    } satisfies Record<string, unknown>;

    let spendCapReservation = null;
    let prepaidReservation = null;
    const beforeBalanceState = await readBalanceSnapshot(
      input.sponsorship.billing,
      sponsorshipCtx,
    );

    try {
      spendCapReservation = await reserveSpendCap({
        spendCap: matched.policy.spendCap,
        spendCaps: input.sponsorship.spendCaps,
        pricing: input.sponsorship.pricing,
        ctx: sponsorshipCtx,
        chainFamily: 'evm',
        intentKind: 'evm_call',
        executorKind: adapter.executorKind,
        environmentId: scope.environmentId,
        policyId: matched.policy.policyId,
        accountRef,
        targetRef,
        chainId,
        sourceEventId: spendCapSourceEventId,
        requestDetails,
      });
      if (spendCapReservation) {
        logSpendCapReserved({
          logger: input.sponsorship.logger,
          routeTag: 'recovery-authority',
          environmentId: scope.environmentId,
          policyId: matched.policy.policyId,
          idempotencyKey,
          chainFamily: 'evm',
          intentKind: 'evm_call',
          executorKind: adapter.executorKind,
          chainId,
          accountRef,
          targetRef,
          reservation: spendCapReservation,
        });
      }
    } catch (error: unknown) {
      if (isSponsorshipSpendCapEnforcementError(error)) {
        logSpendCapRejected({
          logger: input.sponsorship.logger,
          routeTag: 'recovery-authority',
          environmentId: scope.environmentId,
          policyId: matched.policy.policyId,
          idempotencyKey,
          chainFamily: 'evm',
          intentKind: 'evm_call',
          executorKind: adapter.executorKind,
          chainId,
          accountRef,
          targetRef,
          errorCode: error.code,
          errorMessage: error.message,
          errorDetails: error.details,
        });
      }
      return {
        status: 'failed',
        errorCode:
          error && typeof error === 'object' && 'code' in error
            ? String((error as { code?: unknown }).code || '').trim() || 'sponsorship_spend_cap_failed'
            : 'sponsorship_spend_cap_failed',
        errorMessage:
          error instanceof Error ? error.message : 'Failed to reserve sponsored spend cap',
        metadataPatch: {
          sponsorshipScope: scope,
          sponsoredPolicyId: matched.policy.policyId,
        },
      };
    }

    try {
      prepaidReservation = await reservePrepaidBalance({
        billing: input.sponsorship.billing,
        prepaidReservations: input.sponsorship.prepaidReservations,
        pricing: input.sponsorship.pricing,
        ctx: sponsorshipCtx,
        chainFamily: 'evm',
        intentKind: 'evm_call',
        executorKind: adapter.executorKind,
        environmentId: scope.environmentId,
        policyId: matched.policy.policyId,
        accountRef,
        targetRef,
        chainId,
        sourceEventId: prepaidBalanceSourceEventId,
        requestDetails,
      });
    } catch (error: unknown) {
      if (spendCapReservation) {
        try {
          await releaseSpendCap({
            reservation: spendCapReservation,
            spendCaps: input.sponsorship.spendCaps,
            ctx: sponsorshipCtx,
          });
        } catch (releaseError: unknown) {
          input.sponsorship.logger.warn(
            '[recovery-authority] spend-cap release after prepaid failure failed',
            {
              environmentId: scope.environmentId,
              policyId: matched.policy.policyId,
              idempotencyKey,
              error:
                releaseError instanceof Error ? releaseError.message : String(releaseError),
            },
          );
        }
      }
      if (isSponsorshipPrepaidBalanceEnforcementError(error)) {
        await emitBlockedObservabilityEvent({
          services: {
            logger: input.sponsorship.logger,
            observabilityIngestion: input.sponsorship.observabilityIngestion,
            webhooks: input.sponsorship.webhooks,
            webhookActorUserId: input.sponsorship.webhookActorUserId,
            webhookRoles: input.sponsorship.webhookRoles,
          },
          ctx: sponsorshipCtx,
          balance: beforeBalanceState,
          environmentId: scope.environmentId,
          policyId: matched.policy.policyId,
          routeId: RECOVERY_AUTHORITY_SPONSORED_EVM_ROUTE_ID,
          chainFamily: 'evm',
          intentKind: 'evm_call',
          executorKind: adapter.executorKind,
          chainId,
          accountRef,
          targetRef,
          idempotencyKey,
          sourceEventId: prepaidBalanceSourceEventId,
          error,
        });
      }
      return {
        status: 'failed',
        errorCode:
          error && typeof error === 'object' && 'code' in error
            ? String((error as { code?: unknown }).code || '').trim() || 'sponsorship_prepaid_failed'
            : 'sponsorship_prepaid_failed',
        errorMessage:
          error instanceof Error
            ? error.message
            : 'Failed to reserve sponsored prepaid balance',
        metadataPatch: {
          sponsorshipScope: scope,
          sponsoredPolicyId: matched.policy.policyId,
        },
      };
    }

    const assessment = await (async (): Promise<RecoverySponsoredEvmExecutionAssessment> => {
      try {
        return buildSuccessfulSponsoredEvmAssessment(
          (await executeAdapter(adapter)) as RecoverySponsoredEvmExecution,
        );
      } catch (error: unknown) {
        return buildFailedSponsoredEvmAssessment(error);
      }
    })();

    let spendCapSettlement: (SponsorshipSpendCapSettlement & {
      sourceEventId: string;
      estimatedSpendMinor: number;
    }) | null = null;
    try {
      const settled = await settleSpendCap({
        reservation: spendCapReservation,
        spendCaps: input.sponsorship.spendCaps,
        pricing: input.sponsorship.pricing,
        ctx: sponsorshipCtx,
        chainFamily: 'evm',
        intentKind: 'evm_call',
        executorKind: adapter.executorKind,
        environmentId: scope.environmentId,
        policyId: matched.policy.policyId,
        accountRef,
        targetRef,
        chainId,
        txOrExecutionRef: assessment.txHash,
        receiptStatus: assessment.receiptStatus,
        feeUnit: assessment.feeUnit,
        feeAmount: assessment.feeAmount,
        requestDetails,
      });
      if (settled && spendCapReservation) {
        spendCapSettlement = {
          ...settled,
          sourceEventId: spendCapReservation.sourceEventId,
          estimatedSpendMinor: spendCapReservation.estimatedSpendMinor,
        };
        logSpendCapSettled({
          logger: input.sponsorship.logger,
          routeTag: 'recovery-authority',
          environmentId: scope.environmentId,
          policyId: matched.policy.policyId,
          idempotencyKey,
          chainFamily: 'evm',
          intentKind: 'evm_call',
          executorKind: adapter.executorKind,
          chainId,
          accountRef,
          targetRef,
          reservation: spendCapReservation,
          settlement: settled,
          txOrExecutionRef: assessment.txHash,
          receiptStatus: assessment.receiptStatus,
        });
      }
    } catch (error: unknown) {
      input.sponsorship.logger.warn('[recovery-authority] spend-cap settlement failed', {
        environmentId: scope.environmentId,
        policyId: matched.policy.policyId,
        idempotencyKey,
        txHash: assessment.txHash,
        error: error instanceof Error ? error.message : String(error),
      });
    }

    try {
      const record = await recordExecution({
        billing: input.sponsorship.billing,
        billingSourceEventIdPrefix: 'recovery_authority_sponsored_evm_debit',
        context: sponsorshipCtx,
        ledger: input.sponsorship.ledger,
        buildRecord: ({ prepaidSettlement, billingLedgerEntryId }) => ({
          environmentId: scope.environmentId,
          apiKeyId: RECOVERY_AUTHORITY_SPONSORED_EVM_API_KEY_ID,
          apiKeyKind: 'secret_key',
          route: RECOVERY_AUTHORITY_SPONSORED_EVM_ROUTE_ID,
          policyId: matched.policy.policyId,
          policyNameAtEvent: matched.policy.policyName,
          templateId: matched.policy.templateId,
          chainFamily: 'evm',
          intentKind: 'evm_call',
          accountRef,
          targetRef,
          sponsorRef,
          detailsJson: buildDetailsJson({
            execution,
            scope,
            chainId,
            ownerAddress: ownerAddress as `0x${string}`,
            contractMethod: recoveryContractAuthorization.contractMethod,
            functionSignature: recoveryContractAuthorization.functionSignature,
            selector: recoveryContractAuthorization.selector,
            calldata: call.data,
            authorization: recoveryContractAuthorization.authorization,
            accountAddress: accountAddress as `0x${string}`,
            gasLimit,
            assessment,
            spendCapSettlement,
            ...(prepaidSettlement
              ? {
                  prepaidSettlement: {
                    sourceEventId: prepaidSettlement.sourceEventId,
                    estimatedSpendMinor: prepaidSettlement.estimatedSpendMinor,
                    settledSpendMinor: prepaidSettlement.settledSpendMinor,
                    pricingVersion: prepaidSettlement.pricingVersion,
                    usedEstimatedFallback: prepaidSettlement.usedEstimatedFallback,
                    released: prepaidSettlement.released,
                  },
                }
              : {}),
          }),
          estimatedSpendMinor: prepaidSettlement?.estimatedSpendMinor ?? null,
          settledSpendMinor: prepaidSettlement?.settledSpendMinor ?? null,
          pricingVersion: prepaidSettlement?.pricingVersion ?? null,
          pricingSource: prepaidSettlement ? 'sponsorship_pricing_service' : null,
          billingLedgerEntryId,
          prepaidReservationId: prepaidSettlement?.reservationId || null,
          charged: Boolean(
            prepaidSettlement &&
              !prepaidSettlement.released &&
              prepaidSettlement.settledSpendMinor > 0,
          ),
          chargedReason: prepaidSettlement
            ? prepaidSettlement.released
              ? 'released_zero_spend'
              : prepaidSettlement.settledSpendMinor > 0
                ? 'sponsored_execution_debit'
                : 'settled_zero_spend'
            : null,
          settledAt: prepaidSettlement?.settledAt || null,
          idempotencyKey,
        }),
        assessment,
        walletId: subjectAccountId,
        balanceEvents: {
          logger: input.sponsorship.logger,
          webhooks: input.sponsorship.webhooks,
          observabilityIngestion: input.sponsorship.observabilityIngestion,
          webhookActorUserId: input.sponsorship.webhookActorUserId,
          webhookRoles: input.sponsorship.webhookRoles,
        },
        prepaidSettlementInput: {
          reservation: prepaidReservation,
          prepaidReservations: input.sponsorship.prepaidReservations,
          pricing: input.sponsorship.pricing,
          ctx: sponsorshipCtx,
          chainFamily: 'evm',
          intentKind: 'evm_call',
          executorKind: adapter.executorKind,
          environmentId: scope.environmentId,
          policyId: matched.policy.policyId,
          accountRef,
          targetRef,
          chainId,
          txOrExecutionRef: assessment.txHash,
          receiptStatus: assessment.receiptStatus,
          feeUnit: assessment.feeUnit,
          feeAmount: assessment.feeAmount,
          requestDetails,
        },
      });

      if (assessment.succeeded) {
        return {
          status: 'confirmed',
          transactionHash: assessment.txHash || undefined,
          metadataPatch: buildMetadataPatch({
            scope,
            chainId,
            sponsorAddress: adapter.meta.sponsorAddress,
            contractMethod: recoveryContractAuthorization.contractMethod,
            functionSignature: recoveryContractAuthorization.functionSignature,
            selector: recoveryContractAuthorization.selector,
            authorization: recoveryContractAuthorization.authorization,
            idempotencyKey,
            policyId: matched.policy.policyId,
            policyName: matched.policy.policyName,
            templateId: matched.policy.templateId,
            assessment,
            recordId: record.id,
            spendCapSettlement,
          }),
        };
      }

      return {
        status: 'failed',
        transactionHash: assessment.txHash || undefined,
        errorCode: assessment.responseCode,
        errorMessage: assessment.responseMessage,
        metadataPatch: buildMetadataPatch({
          scope,
          chainId,
          sponsorAddress: adapter.meta.sponsorAddress,
          contractMethod: recoveryContractAuthorization.contractMethod,
          functionSignature: recoveryContractAuthorization.functionSignature,
          selector: recoveryContractAuthorization.selector,
          authorization: recoveryContractAuthorization.authorization,
          idempotencyKey,
          policyId: matched.policy.policyId,
          policyName: matched.policy.policyName,
          templateId: matched.policy.templateId,
          assessment,
          recordId: record.id,
          spendCapSettlement,
        }),
      };
    } catch (error: unknown) {
      if (assessment.succeeded && assessment.txHash) {
        return {
          status: 'submitted',
          transactionHash: assessment.txHash,
          metadataPatch: buildMetadataPatch({
            scope,
            chainId,
            sponsorAddress: adapter.meta.sponsorAddress,
            contractMethod: recoveryContractAuthorization.contractMethod,
            functionSignature: recoveryContractAuthorization.functionSignature,
            selector: recoveryContractAuthorization.selector,
            authorization: recoveryContractAuthorization.authorization,
            idempotencyKey,
            policyId: matched.policy.policyId,
            policyName: matched.policy.policyName,
            templateId: matched.policy.templateId,
            assessment,
            spendCapSettlement,
            bookkeepingError:
              error instanceof Error ? error.message : 'Failed to record sponsored recovery execution',
          }),
        };
      }
      return {
        status: 'failed',
        transactionHash: assessment.txHash || undefined,
        errorCode: assessment.responseCode,
        errorMessage:
          error instanceof Error
            ? error.message
            : assessment.responseMessage || 'Failed to record sponsored recovery execution',
        metadataPatch: buildMetadataPatch({
          scope,
          chainId,
          sponsorAddress: adapter.meta.sponsorAddress,
          contractMethod: recoveryContractAuthorization.contractMethod,
          functionSignature: recoveryContractAuthorization.functionSignature,
          selector: recoveryContractAuthorization.selector,
          authorization: recoveryContractAuthorization.authorization,
          idempotencyKey,
          policyId: matched.policy.policyId,
          policyName: matched.policy.policyName,
          templateId: matched.policy.templateId,
          assessment,
          spendCapSettlement,
          bookkeepingError:
            error instanceof Error ? error.message : 'Failed to record sponsored recovery execution',
        }),
      };
    }
  };
}
