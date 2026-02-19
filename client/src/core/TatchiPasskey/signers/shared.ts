import { toAccountId } from '../../types/accountIds';
import type { PasskeyManagerContext } from '../index';
import type { BootstrapThresholdEcdsaSessionArgs } from '../capabilities';
import type { WalletIframeCoordinator } from '../walletIframeCoordinator';

export type ChainSignerDeps = {
  getContext: () => PasskeyManagerContext;
  walletIframe: Pick<WalletIframeCoordinator, 'shouldUseWalletIframe' | 'requireRouter'>;
};

export async function bootstrapThresholdEcdsaSessionForChain(
  deps: ChainSignerDeps,
  args: BootstrapThresholdEcdsaSessionArgs,
  forcedChain: 'evm' | 'tempo',
) {
  const options = {
    ...(args.options || {}),
    chain: forcedChain,
  };

  if (deps.walletIframe.shouldUseWalletIframe()) {
    const router = await deps.walletIframe.requireRouter(args.nearAccountId);
    return await router.bootstrapThresholdEcdsaSession({
      nearAccountId: args.nearAccountId,
      options,
    });
  }

  return await deps
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
