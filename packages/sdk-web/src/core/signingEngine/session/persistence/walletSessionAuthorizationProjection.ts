import {
  buildActiveWalletSessionAuthorizationProjection,
  type ActiveWalletSessionAuthorizationProjection,
  type WalletSessionAuthorizationRepository,
} from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import type { WalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdEcdsaSessionBootstrapResult } from '../../threshold/ecdsa/activation';
import type { WalletAuthMethod } from '@shared/utils/signerDomain';
import type { WalletAuthAuthorityRef } from '@shared/utils/walletAuthAuthority';

export type WalletSessionAuthorizationProjectionWriter = Pick<
  WalletSessionAuthorizationRepository,
  'replaceActive'
>;

export async function persistActiveWalletSessionAuthorizationFromEcdsaBootstrap(
  writer: WalletSessionAuthorizationProjectionWriter,
  args: {
    readonly walletId: WalletId;
    readonly authority: WalletAuthAuthorityRef;
    readonly authMethod: WalletAuthMethod;
    readonly bootstrap: ThresholdEcdsaSessionBootstrapResult;
  },
): Promise<ActiveWalletSessionAuthorizationProjection> {
  const session = args.bootstrap.session;
  const active = buildActiveWalletSessionAuthorizationProjection({
    walletId: args.walletId,
    authorizationSessionId: session.authorizationSessionId,
    walletSessionId: session.walletSessionId,
    quotaId: session.quotaId,
    walletSessionJwt: session.jwt,
    authMethod: args.authMethod,
    authority: args.authority,
    expiresAtMs: session.expiresAtMs,
  });
  await writer.replaceActive({
    active,
    replacedAtMs: Date.now(),
  });
  return active;
}
