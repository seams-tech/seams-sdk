import type { EvmSignedResult } from '../../signingEngine/chainAdaptors/evm/evmAdapter';
import type { TempoSignedResult } from '../../signingEngine/chainAdaptors/tempo/tempoAdapter';
import { toError } from '@shared/utils/errors';
import { toAccountId } from '../../types/accountIds';
import { routeWalletIframeOrLocal, type WalletIframeRouteDeps } from '../walletIframeRoute';
import type { ReportTempoBroadcastResultArgs, SignTempoArgs, TempoSignerCapability } from '..';

type ChainSignerDeps = {
  getContext: () => import('../index').PasskeyManagerContext;
  walletIframe: WalletIframeRouteDeps;
};

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

  async reportBroadcastResult(args: ReportTempoBroadcastResultArgs): Promise<void> {
    const toSerializableError = (
      error: unknown,
    ): { code?: string; message?: string; details?: unknown } | undefined => {
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
    };

    return await routeWalletIframeOrLocal({
      walletIframe: this.walletIframe,
      nearAccountId: args.nearAccountId,
      remote: async (router) => {
        await router.reportTempoBroadcastResult({
          nearAccountId: args.nearAccountId,
          signedResult: args.signedResult,
          status: args.status,
          ...(args.txHash ? { txHash: args.txHash } : {}),
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
        await this.getContext().signingEngine.reportTempoBroadcastResult({
          nearAccountId: args.nearAccountId,
          signedResult: args.signedResult,
          status: args.status,
          ...(args.txHash ? { txHash: args.txHash } : {}),
          ...(args.error !== undefined ? { error: args.error } : {}),
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
