import type { EvmSignedResult } from '../../signingEngine/chainAdaptors/evm/evmAdapter';
import type { TempoSignedResult } from '../../signingEngine/chainAdaptors/tempo/tempoAdapter';
import { toError } from '@shared/utils/errors';
import { toAccountId } from '../../types/accountIds';
import { routeWalletIframeOrLocal, type WalletIframeRouteDeps } from '../walletIframeRoute';
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
  getContext: () => import('../index').PasskeyManagerContext;
  walletIframe: WalletIframeRouteDeps;
};

function toSerializableError(
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
 * - tempo signing/bootstrap -> wallet iframe router OR SigningEngine signing surfaces
 */
export class TempoSigner implements TempoSignerCapability {
  private readonly getContext: ChainSignerDeps['getContext'];
  private readonly walletIframe: ChainSignerDeps['walletIframe'];

  constructor(deps: ChainSignerDeps) {
    this.getContext = deps.getContext;
    this.walletIframe = deps.walletIframe;
  }

  async signTempo(args: SignTempoArgs): Promise<TempoSignedResult | EvmSignedResult> {
    return await routeWalletIframeOrLocal({
      walletIframe: this.walletIframe,
      nearAccountId: args.nearAccountId,
      remote: async (router) => {
        return await router.signTempo({
          nearAccountId: args.nearAccountId,
          request: args.request,
          options: {
            confirmationConfig: args.options?.confirmationConfig,
            onEvent: args.options?.onEvent,
          },
        });
      },
      onRemoteError: async (error) => {
        throw toError(error);
      },
      local: async () => {
        return await this.getContext().signingEngine.signTempo({
          nearAccountId: args.nearAccountId,
          request: args.request,
          confirmationConfigOverride: args.options?.confirmationConfig,
          shouldAbort: args.options?.shouldAbort,
          onEvent: args.options?.onEvent,
        });
      },
    });
  }

  async executeEvmFamilyTransaction(
    args: ExecuteEvmFamilyTransactionArgs,
  ): Promise<ExecuteEvmFamilyTransactionResult> {
    return await executeEvmFamilyTransactionLifecycle({
      capability: this,
      chains: this.getContext().configs.network.chains,
      input: args,
    });
  }

  async reportBroadcastAccepted(args: ReportTempoBroadcastAcceptedArgs): Promise<void> {
    return await routeWalletIframeOrLocal({
      walletIframe: this.walletIframe,
      nearAccountId: args.nearAccountId,
      remote: async (router) => {
        await router.reportTempoBroadcastAccepted({
          nearAccountId: args.nearAccountId,
          signedResult: args.signedResult,
          ...(args.txHash ? { txHash: args.txHash } : {}),
          options: {
            onEvent: args.options?.onEvent,
          },
        });
      },
      onRemoteError: async (error) => {
        throw toError(error);
      },
      local: async () => {
        await this.getContext().signingEngine.reportTempoBroadcastAccepted({
          nearAccountId: args.nearAccountId,
          signedResult: args.signedResult,
          ...(args.txHash ? { txHash: args.txHash } : {}),
          onEvent: args.options?.onEvent,
        });
      },
    });
  }

  async reportBroadcastRejected(args: ReportTempoBroadcastRejectedArgs): Promise<void> {
    return await routeWalletIframeOrLocal({
      walletIframe: this.walletIframe,
      nearAccountId: args.nearAccountId,
      remote: async (router) => {
        await router.reportTempoBroadcastRejected({
          nearAccountId: args.nearAccountId,
          signedResult: args.signedResult,
          ...(args.error != null ? { error: toSerializableError(args.error) } : {}),
          options: {
            onEvent: args.options?.onEvent,
          },
        });
      },
      onRemoteError: async (error) => {
        throw toError(error);
      },
      local: async () => {
        await this.getContext().signingEngine.reportTempoBroadcastRejected({
          nearAccountId: args.nearAccountId,
          signedResult: args.signedResult,
          ...(args.error !== undefined ? { error: args.error } : {}),
          onEvent: args.options?.onEvent,
        });
      },
    });
  }

  async reportFinalized(args: ReportTempoFinalizedArgs): Promise<void> {
    return await routeWalletIframeOrLocal({
      walletIframe: this.walletIframe,
      nearAccountId: args.nearAccountId,
      remote: async (router) => {
        await router.reportTempoFinalized({
          nearAccountId: args.nearAccountId,
          signedResult: args.signedResult,
          ...(args.txHash ? { txHash: args.txHash } : {}),
          ...(args.receiptStatus ? { receiptStatus: args.receiptStatus } : {}),
          options: {
            onEvent: args.options?.onEvent,
          },
        });
      },
      onRemoteError: async (error) => {
        throw toError(error);
      },
      local: async () => {
        await this.getContext().signingEngine.reportTempoFinalized({
          nearAccountId: args.nearAccountId,
          signedResult: args.signedResult,
          ...(args.txHash ? { txHash: args.txHash } : {}),
          ...(args.receiptStatus ? { receiptStatus: args.receiptStatus } : {}),
          onEvent: args.options?.onEvent,
        });
      },
    });
  }

  async reportDroppedOrReplaced(args: ReportTempoDroppedOrReplacedArgs): Promise<void> {
    return await routeWalletIframeOrLocal({
      walletIframe: this.walletIframe,
      nearAccountId: args.nearAccountId,
      remote: async (router) => {
        await router.reportTempoDroppedOrReplaced({
          nearAccountId: args.nearAccountId,
          signedResult: args.signedResult,
          reason: args.reason,
          ...(args.txHash ? { txHash: args.txHash } : {}),
          options: {
            onEvent: args.options?.onEvent,
          },
        });
      },
      onRemoteError: async (error) => {
        throw toError(error);
      },
      local: async () => {
        await this.getContext().signingEngine.reportTempoDroppedOrReplaced({
          nearAccountId: args.nearAccountId,
          signedResult: args.signedResult,
          reason: args.reason,
          ...(args.txHash ? { txHash: args.txHash } : {}),
          onEvent: args.options?.onEvent,
        });
      },
    });
  }

  async reconcileNonceLane(args: ReconcileTempoNonceLaneArgs): Promise<TempoNonceLaneStatus> {
    return await routeWalletIframeOrLocal({
      walletIframe: this.walletIframe,
      nearAccountId: args.nearAccountId,
      remote: async (router) => {
        return await router.reconcileTempoNonceLane({
          nearAccountId: args.nearAccountId,
          signedResult: args.signedResult,
          options: {
            onEvent: args.options?.onEvent,
          },
        });
      },
      onRemoteError: async (error) => {
        throw toError(error);
      },
      local: async () => {
        return await this.getContext().signingEngine.reconcileTempoNonceLane({
          nearAccountId: args.nearAccountId,
          signedResult: args.signedResult,
          onEvent: args.options?.onEvent,
        });
      },
    });
  }

  async bootstrapEcdsaSession(args: Parameters<TempoSignerCapability['bootstrapEcdsaSession']>[0]) {
    const options = {
      ...(args.options || {}),
      chain: 'tempo' as const,
    };

    return await routeWalletIframeOrLocal({
      walletIframe: this.walletIframe,
      nearAccountId: args.nearAccountId,
      remote: async (router) => {
        return await router.bootstrapEcdsaSession({
          nearAccountId: args.nearAccountId,
          options,
        });
      },
      local: async () => {
        return await this.getContext().signingEngine.bootstrapEcdsaSession({
          nearAccountId: toAccountId(args.nearAccountId),
          chain: options.chain,
          relayerUrl: options.relayerUrl,
          participantIds: options.participantIds,
          sessionKind: options.sessionKind,
          ttlMs: options.ttlMs,
          remainingUses: options.remainingUses,
          smartAccount: options.smartAccount ? { ...options.smartAccount } : undefined,
        });
      },
    });
  }
}
