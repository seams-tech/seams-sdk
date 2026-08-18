import {
  walletSessionTokenForCurve,
  type ActiveWalletSessionAuthorizationProjection,
} from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import {
  createRelayerReusableWalletSessionStatusPort,
} from '@/core/rpcClients/relayer/walletSessionAuthorizationStatus';
import type { WalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { SigningSessionStatus } from '@/core/types/seams';
import {
  signingSessionStatusFromWalletSessionStatus,
  type SigningSessionStatusCheck,
  type WalletSessionStatusIdentity,
} from './walletSessionStatus';

export type CanonicalWalletSessionStatusReaderDeps = {
  readonly relayerUrl: string;
  readonly readAuthorization: (
    walletId: WalletId,
  ) => Promise<ActiveWalletSessionAuthorizationProjection | null>;
};

export function createCanonicalWalletSessionStatusReader(
  deps: CanonicalWalletSessionStatusReaderDeps,
): (args: SigningSessionStatusCheck) => Promise<SigningSessionStatus | null> {
  return async (args) => {
    const identity = args.authorization;
    const projection = await deps.readAuthorization(args.owner.walletId);
    if (!projection || !walletSessionStatusIdentityMatchesProjection(identity, projection)) {
      return null;
    }
    const walletSessionToken = walletSessionTokenForCurve(projection, 'ed25519');
    if (!walletSessionToken) return null;
    const relayerUrl = String(deps.relayerUrl || '').trim();
    if (!relayerUrl) return null;
    const status = await createRelayerReusableWalletSessionStatusPort({
      relayerUrl,
      auth: { kind: 'opaque_wallet_session', walletSessionToken },
    })
      .read(identity)
      .catch(() => null);
    return status ? signingSessionStatusFromWalletSessionStatus(status) : null;
  };
}

function walletSessionStatusIdentityMatchesProjection(
  identity: WalletSessionStatusIdentity,
  projection: ActiveWalletSessionAuthorizationProjection,
): boolean {
  return (
    identity.walletSessionId === projection.walletSessionId &&
    identity.quotaId === projection.quotaId
  );
}
