import type { AppSessionJwt } from '@shared/utils/domainIds';
import { WALLET_AUTH_METHODS } from '@shared/utils/signerDomain';
import type { ActiveWalletSessionAuthorizationProjection } from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import {
  createRelayerReusableWalletSessionStatusPort,
  type ReusableWalletSessionStatusAuth,
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
  readonly resolveAppSessionJwt: (
    projection: ActiveWalletSessionAuthorizationProjection,
  ) => Promise<AppSessionJwt | null>;
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
    const relayerUrl = String(deps.relayerUrl || '').trim();
    if (!relayerUrl) return null;
    const auth = await canonicalStatusAuthForProjection({
      projection,
      resolveAppSessionJwt: deps.resolveAppSessionJwt,
    });
    if (!auth) return null;
    const status = await createRelayerReusableWalletSessionStatusPort({
      relayerUrl,
      auth,
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

async function canonicalStatusAuthForProjection(args: {
  projection: ActiveWalletSessionAuthorizationProjection;
  resolveAppSessionJwt: CanonicalWalletSessionStatusReaderDeps['resolveAppSessionJwt'];
}): Promise<ReusableWalletSessionStatusAuth | null> {
  if (args.projection.authMethod === WALLET_AUTH_METHODS.emailOtp) {
    const appSessionJwt = await args.resolveAppSessionJwt(args.projection);
    return appSessionJwt ? { kind: 'app_session_jwt', appSessionJwt } : null;
  }
  return { kind: 'app_session_cookie' };
}
