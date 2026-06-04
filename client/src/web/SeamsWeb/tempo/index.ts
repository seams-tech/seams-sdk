import type { EvmSignedResult } from '@/core/signingEngine/chains/evm/evmAdapter';
import type { TempoSignedResult } from '@/core/signingEngine/chains/tempo/tempoAdapter';
import { toAccountId } from '@/core/types/accountIds';
import {
  thresholdEcdsaChainTargetFromRequest,
  toWalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { EcdsaBootstrapRequest } from '@/core/signingEngine/session/passkey/ecdsaBootstrap';
import type {
  ExecuteEvmFamilyTransactionArgs,
  ExecuteEvmFamilyTransactionResult,
  ReconcileTempoNonceLaneArgs,
  ReportTempoBroadcastAcceptedArgs,
  ReportTempoBroadcastRejectedArgs,
  ReportTempoDroppedOrReplacedArgs,
  ReportTempoFinalizedArgs,
  SignTempoArgs,
  TempoNonceLaneStatus,
  TempoSignerCapability,
} from '..';
import { executeEvmFamilyTransactionLifecycle } from './executeEvmFamilyTransaction';

type ChainSignerDeps = {
  getContext: () => import('../index').SeamsWebContext;
};

function toLocalBootstrapRequest(
  args: Parameters<TempoSignerCapability['bootstrapEcdsaSession']>[0],
): EcdsaBootstrapRequest {
  return {
    kind: 'reuse_warm_ecdsa_bootstrap',
    walletId: toAccountId(args.walletSession.walletId),
    chainTarget: args.chainTarget,
    source: args.source,
    relayerUrl: args.relayerUrl,
    runtimeScopeBootstrap: args.runtimeScopeBootstrap,
    ttlMs: args.ttlMs,
    remainingUses: args.remainingUses,
  };
}

export function toSerializableTempoError(
  error: unknown,
): { code?: string; message?: string; details?: unknown } | undefined {
  if (error == null) return undefined;
  if (typeof error === 'string') return { message: error };
  if (error instanceof Error) {
    const code = 'code' in error ? String((error as { code?: unknown }).code || '').trim() : '';
    return {
      ...(code ? { code } : {}),
      message: String(error.message || ''),
    };
  }
  if (typeof error === 'object') {
    const value = error as { code?: unknown; message?: unknown; details?: unknown };
    const code = String(value.code || '').trim();
    const message = String(value.message || '').trim();
    return {
      ...(code ? { code } : {}),
      ...(message ? { message } : {}),
      ...(value.details !== undefined ? { details: value.details } : {}),
    };
  }
  return { message: String(error) };
}

/**
 * Tempo signing call graph:
 * - tempo signing/bootstrap -> wallet iframe router OR runtime signing surfaces
 */
export class TempoSigner implements TempoSignerCapability {
  private readonly getContext: ChainSignerDeps['getContext'];

  constructor(deps: ChainSignerDeps) {
    this.getContext = deps.getContext;
  }

  async signTempo(args: SignTempoArgs): Promise<TempoSignedResult | EvmSignedResult> {
    const chainTarget = thresholdEcdsaChainTargetFromRequest(args.chainTarget);
    return await this.getContext().signingEngine.signTempo({
      walletSession: args.walletSession,
      request: args.request,
      chainTarget,
      confirmationConfigOverride: args.options?.confirmationConfig,
      shouldAbort: args.options?.shouldAbort,
      onEvent: args.options?.onEvent,
    });
  }

  async executeEvmFamilyTransaction(
    args: ExecuteEvmFamilyTransactionArgs,
  ): Promise<ExecuteEvmFamilyTransactionResult> {
    const chainTarget = thresholdEcdsaChainTargetFromRequest(args.chainTarget);
    return await executeEvmFamilyTransactionLifecycle({
      capability: this,
      chains: this.getContext().configs.network.chains,
      input: { ...args, chainTarget },
    });
  }

  async reportBroadcastAccepted(args: ReportTempoBroadcastAcceptedArgs): Promise<void> {
    const walletId = toWalletId(args.walletSession.walletId);
    await this.getContext().signingRuntime.services.evmFamilySigning.reportTempoBroadcastAccepted({
      walletId,
      signedResult: args.signedResult,
      ...(args.txHash ? { txHash: args.txHash } : {}),
      onEvent: args.options?.onEvent,
    });
  }

  async reportBroadcastRejected(args: ReportTempoBroadcastRejectedArgs): Promise<void> {
    const walletId = toWalletId(args.walletSession.walletId);
    await this.getContext().signingRuntime.services.evmFamilySigning.reportTempoBroadcastRejected({
      walletId,
      signedResult: args.signedResult,
      ...(args.error !== undefined ? { error: args.error } : {}),
      onEvent: args.options?.onEvent,
    });
  }

  async reportFinalized(args: ReportTempoFinalizedArgs): Promise<void> {
    const walletId = toWalletId(args.walletSession.walletId);
    await this.getContext().signingRuntime.services.evmFamilySigning.reportTempoFinalized({
      walletId,
      signedResult: args.signedResult,
      ...(args.txHash ? { txHash: args.txHash } : {}),
      ...(args.receiptStatus ? { receiptStatus: args.receiptStatus } : {}),
      onEvent: args.options?.onEvent,
    });
  }

  async reportDroppedOrReplaced(args: ReportTempoDroppedOrReplacedArgs): Promise<void> {
    const walletId = toWalletId(args.walletSession.walletId);
    await this.getContext().signingRuntime.services.evmFamilySigning.reportTempoDroppedOrReplaced({
      walletId,
      signedResult: args.signedResult,
      reason: args.reason,
      ...(args.txHash ? { txHash: args.txHash } : {}),
      onEvent: args.options?.onEvent,
    });
  }

  async reconcileNonceLane(args: ReconcileTempoNonceLaneArgs): Promise<TempoNonceLaneStatus> {
    const walletId = toWalletId(args.walletSession.walletId);
    return await this.getContext().signingRuntime.services.evmFamilySigning.reconcileTempoNonceLane({
      walletId,
      signedResult: args.signedResult,
      onEvent: args.options?.onEvent,
    });
  }

  async bootstrapEcdsaSession(args: Parameters<TempoSignerCapability['bootstrapEcdsaSession']>[0]) {
    const context = this.getContext();
    const bootstrapArgs = buildTempoBootstrapArgs(context, args);
    return await context.signingEngine.bootstrapEcdsaSession(toLocalBootstrapRequest(bootstrapArgs));
  }
}

export function buildTempoBootstrapArgs(
  context: import('../index').SeamsWebContext,
  args: Parameters<TempoSignerCapability['bootstrapEcdsaSession']>[0],
): Parameters<TempoSignerCapability['bootstrapEcdsaSession']>[0] {
  const managedRegistration =
    context.configs.registration.mode === 'managed' ? context.configs.registration : null;
  const runtimeScopeBootstrap =
    args.runtimeScopeBootstrap ||
    (managedRegistration
      ? {
          environmentId: managedRegistration.environmentId,
          publishableKey: managedRegistration.publishableKey,
        }
      : undefined);
  const chainTarget = args.chainTarget;
  if (chainTarget.kind !== 'tempo') {
    throw new Error('[SeamsWeb][tempo] bootstrapEcdsaSession requires a Tempo chainTarget');
  }
  return {
    ...args,
    ...(runtimeScopeBootstrap ? { runtimeScopeBootstrap } : {}),
  };
}
