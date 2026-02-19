import type { TempoSignedResult } from '../../signing/chainAdaptors/tempo/tempoAdapter';
import { toError } from '@shared/utils/errors';
import type {
  SignTempoArgs,
  SignTempoWithThresholdEcdsaArgs,
  TempoSignerCapability,
} from '../capabilities';
import {
  bootstrapThresholdEcdsaSessionForChain,
  type ChainSignerDeps,
} from './shared';

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
    return await bootstrapThresholdEcdsaSessionForChain(
      {
        getContext: this.getContext,
        walletIframe: this.walletIframe,
      },
      args,
      'tempo',
    );
  }
}
