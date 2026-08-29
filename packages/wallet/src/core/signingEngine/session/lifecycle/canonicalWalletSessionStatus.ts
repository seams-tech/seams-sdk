import type { WalletSessionAuthorizationExactActiveReadResult } from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import { createRelayerReusableWalletSessionStatusPort } from '@/core/rpcClients/relayer/walletSessionAuthorizationStatus';
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
  ) => Promise<WalletSessionAuthorizationExactActiveReadResult>;
};

export function createCanonicalWalletSessionStatusReader(
  deps: CanonicalWalletSessionStatusReaderDeps,
): (args: SigningSessionStatusCheck) => Promise<SigningSessionStatus | null> {
  return async (args) => {
    const identity = args.authorization;
    const authorization = await deps.readAuthorization(args.owner.walletId);
    switch (authorization.kind) {
      case 'missing':
      case 'corrupt':
      case 'persistence_unavailable':
      case 'upgrade_required':
        return null;
      case 'found':
        break;
      default: {
        const exhaustive: never = authorization;
        return exhaustive;
      }
    }
    if (
      !walletSessionStatusIdentityMatchesExactAuthorization(
        identity,
        args.owner.walletId,
        authorization,
      )
    ) {
      return null;
    }
    const relayerUrl = String(deps.relayerUrl || '').trim();
    if (!relayerUrl) return null;
    const status = await createRelayerReusableWalletSessionStatusPort({
      relayerUrl,
      operationCredential: authorization.operationCredential,
    })
      .read(identity)
      .catch(() => null);
    return status ? signingSessionStatusFromWalletSessionStatus(status) : null;
  };
}

function walletSessionStatusIdentityMatchesExactAuthorization(
  identity: WalletSessionStatusIdentity,
  walletId: WalletId,
  authorization: Extract<
    WalletSessionAuthorizationExactActiveReadResult,
    { readonly kind: 'found' }
  >,
): boolean {
  return (
    authorization.record.walletId === walletId &&
    authorization.record.quotaId === identity.quotaId &&
    authorization.operationCredential.walletSessionId === identity.walletSessionId
  );
}
