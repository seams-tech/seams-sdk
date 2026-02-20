import type { EvmSignedResult } from '../../signingEngine/chainAdaptors/evm/evmAdapter';
import type { TempoSignedResult } from '../../signingEngine/chainAdaptors/tempo/tempoAdapter';
import { toError } from '@shared/utils/errors';
import { toAccountId } from '../../types/accountIds';
import {
  routeWalletIframeOrLocal,
  type WalletIframeRouteDeps,
} from '../walletIframeRoute';
import type {
  SignTempoArgs,
  SignTempoWithThresholdEcdsaArgs,
  TempoSignerCapability,
} from '..';

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
            thresholdEcdsaKeyRef: args.options?.thresholdEcdsaKeyRef,
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
          thresholdEcdsaKeyRef: args.options?.thresholdEcdsaKeyRef,
          shouldAbort: args.options?.shouldAbort,
          onEvent: args.options?.onEvent,
        });
      },
    });
  }

  async signTempoWithThresholdEcdsa(
    args: SignTempoWithThresholdEcdsaArgs,
  ): Promise<TempoSignedResult | EvmSignedResult> {
    if (args.request.senderSignatureAlgorithm !== 'secp256k1') {
      throw new Error(
        '[TatchiPasskey] signTempoWithThresholdEcdsa requires senderSignatureAlgorithm=secp256k1',
      );
    }

    return await routeWalletIframeOrLocal({
      walletIframe: this.walletIframe,
      nearAccountId: args.nearAccountId,
      remote: async (router) => {
        return await router.signTempoWithThresholdEcdsa({
          nearAccountId: args.nearAccountId,
          request: args.request,
          thresholdEcdsaKeyRef: args.thresholdEcdsaKeyRef,
          options: {
            confirmationConfig: args.options?.confirmationConfig,
          },
        });
      },
      onRemoteError: async (error) => {
        throw toError(error);
      },
      local: async () => {
        return await this
          .getContext()
          .signingEngine
          .signTempoWithThresholdEcdsa({
            nearAccountId: args.nearAccountId,
            request: args.request,
            thresholdEcdsaKeyRef: args.thresholdEcdsaKeyRef,
            confirmationConfigOverride: args.options?.confirmationConfig,
          });
      },
    });
  }

  async bootstrapEcdsaSession(
    args: Parameters<TempoSignerCapability['bootstrapEcdsaSession']>[0],
  ) {
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
        return await this
          .getContext()
          .signingEngine
          .bootstrapEcdsaSession({
            nearAccountId: toAccountId(args.nearAccountId),
            chain: options.chain,
            relayerUrl: options.relayerUrl,
            participantIds: options.participantIds,
            sessionKind: options.sessionKind,
            ttlMs: options.ttlMs,
            remainingUses: options.remainingUses,
            smartAccount: options.smartAccount,
          });
      },
    });
  }
}
