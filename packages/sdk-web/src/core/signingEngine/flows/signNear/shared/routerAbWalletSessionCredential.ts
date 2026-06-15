import type { RouterAbWalletSessionCredential } from '@/core/rpcClients/relayer/routerAbNormalSigning';
import type { ResolvedThresholdEd25519SessionState } from './thresholdSessionAuth';

export function routerAbWalletSessionCredentialFromResolvedThresholdSessionState(
  state: ResolvedThresholdEd25519SessionState,
): RouterAbWalletSessionCredential {
  if (state.sessionKind === 'cookie') {
    throw new Error(
      'Router A/B normal-signing requires bearer Wallet Session JWT auth; cookie Wallet Session auth is deferred',
    );
  }

  return {
    kind: 'jwt',
    walletSessionJwt: state.thresholdSessionAuthToken,
  };
}
