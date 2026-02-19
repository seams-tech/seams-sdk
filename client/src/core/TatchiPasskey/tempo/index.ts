import type { TempoSignedResult } from '../../signing/chainAdaptors/tempo/tempoAdapter';
import { toError } from '@shared/utils/errors';
import { toAccountId } from '../../types/accountIds';
import type {
  SignTempoArgs,
  SignTempoWithThresholdEcdsaArgs,
  TempoSignerCapability,
} from '..';

type ChainSignerDeps = {
  getContext: () => import('../index').PasskeyManagerContext;
  walletIframe: Pick<
    import('../walletIframeCoordinator').WalletIframeCoordinator,
    'shouldUseWalletIframe' | 'requireRouter'
  >;
};

/**
 * Tempo signing call graph:
 * - tempo signing/bootstrap -> wallet iframe router OR WebAuthnManager signing surfaces
 */
export class TempoSigner implements TempoSignerCapability {
  private readonly getContext: ChainSignerDeps['getContext'];
  private readonly walletIframe: ChainSignerDeps['walletIframe'];

  constructor(deps: ChainSignerDeps) {
    this.getContext = deps.getContext;
    this.walletIframe = deps.walletIframe;
  }

  async signTempo(args: SignTempoArgs): Promise<TempoSignedResult> {
    if (this.walletIframe.shouldUseWalletIframe()) {
      try {
        const router = await this.walletIframe.requireRouter(args.nearAccountId);
        return await router.signTempo({
          nearAccountId: args.nearAccountId,
          request: args.request,
          options: {
            confirmationConfig: args.options?.confirmationConfig,
            thresholdEcdsaKeyRef: args.options?.thresholdEcdsaKeyRef,
            onEvent: args.options?.onEvent,
          },
        });
      } catch (error: unknown) {
        throw toError(error);
      }
    }

    return await this.getContext().webAuthnManager.signingActions.signTempo({
      nearAccountId: args.nearAccountId,
      request: args.request,
      confirmationConfigOverride: args.options?.confirmationConfig,
      thresholdEcdsaKeyRef: args.options?.thresholdEcdsaKeyRef,
      shouldAbort: args.options?.shouldAbort,
      onEvent: args.options?.onEvent,
    });
  }

  async signTempoWithThresholdEcdsa(
    args: SignTempoWithThresholdEcdsaArgs,
  ): Promise<TempoSignedResult> {
    if (args.request.senderSignatureAlgorithm !== 'secp256k1') {
      throw new Error(
        '[TatchiPasskey] signTempoWithThresholdEcdsa requires senderSignatureAlgorithm=secp256k1',
      );
    }

    if (this.walletIframe.shouldUseWalletIframe()) {
      try {
        const router = await this.walletIframe.requireRouter(args.nearAccountId);
        return await router.signTempoWithThresholdEcdsa({
          nearAccountId: args.nearAccountId,
          request: args.request,
          thresholdEcdsaKeyRef: args.thresholdEcdsaKeyRef,
          options: {
            confirmationConfig: args.options?.confirmationConfig,
          },
        });
      } catch (error: unknown) {
        throw toError(error);
      }
    }

    return await this
      .getContext()
      .webAuthnManager
      .signingActions
      .signTempoWithThresholdEcdsa({
        nearAccountId: args.nearAccountId,
        request: args.request,
        thresholdEcdsaKeyRef: args.thresholdEcdsaKeyRef,
        confirmationConfigOverride: args.options?.confirmationConfig,
      });
  }

  async bootstrapThresholdEcdsaSession(
    args: Parameters<TempoSignerCapability['bootstrapThresholdEcdsaSession']>[0],
  ) {
    const options = {
      ...(args.options || {}),
      chain: 'tempo' as const,
    };

    if (this.walletIframe.shouldUseWalletIframe()) {
      const router = await this.walletIframe.requireRouter(args.nearAccountId);
      return await router.bootstrapThresholdEcdsaSession({
        nearAccountId: args.nearAccountId,
        options,
      });
    }

    return await this
      .getContext()
      .webAuthnManager
      .thresholdSession
      .bootstrapThresholdEcdsaSessionLite({
        nearAccountId: toAccountId(args.nearAccountId),
        chain: options.chain,
        relayerUrl: options.relayerUrl,
        participantIds: options.participantIds,
        sessionKind: options.sessionKind,
        ttlMs: options.ttlMs,
        remainingUses: options.remainingUses,
        smartAccount: options.smartAccount,
      });
  }
}
