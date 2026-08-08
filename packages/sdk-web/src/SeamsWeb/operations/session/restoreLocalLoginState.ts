import type { AccountId } from '@/core/types/accountIds';
import { normalizePositiveInteger } from '@shared/utils/normalize';
import { getWalletSession } from '@/SeamsWeb/operations/auth/login';
import type { LocalLoginStateWebContext } from '@/SeamsWeb/signingSurface/types';
import { toWalletId, type WalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { NearEd25519SigningKeyId } from '@shared/utils/registrationIntent';

export async function restoreLocalLoginState(args: {
  context: LocalLoginStateWebContext;
  walletId: WalletId;
  nearAccountId: AccountId;
  nearEd25519SigningKeyId: NearEd25519SigningKeyId;
  signerSlot: number;
}): Promise<{
  walletId: string;
  nearAccountId: AccountId;
  nearEd25519SigningKeyId: string;
  signerSlot: number;
  isLoggedIn: boolean;
}> {
  const walletId = args.walletId;
  const nearAccountId = args.nearAccountId;
  const nearEd25519SigningKeyId = args.nearEd25519SigningKeyId;
  const signerSlot = normalizePositiveInteger(args.signerSlot);
  if (!signerSlot) {
    throw new Error('restoreLocalLoginState requires an exact signerSlot');
  }
  if (!String(walletId).trim() || !String(nearEd25519SigningKeyId).trim()) {
    throw new Error('restoreLocalLoginState requires wallet binding fields');
  }

  await args.context.signingEngine.setLastUser(walletId, signerSlot);
  await args.context.signingEngine.restoreWalletAuthenticationState(walletId, { kind: 'cookie' });
  const session = await getWalletSession(args.context, walletId);
  const appIdentity = session.appIdentity;
  const loginWalletId = appIdentity.kind === 'resolved' ? String(appIdentity.walletId).trim() : '';
  const loginNearAccountId =
    appIdentity.kind === 'resolved' ? String(appIdentity.nearAccountId || '').trim() : '';
  if (loginWalletId && loginWalletId !== String(walletId)) {
    throw new Error('restoreLocalLoginState walletId mismatch');
  }
  if (loginNearAccountId && loginNearAccountId !== String(nearAccountId)) {
    throw new Error('restoreLocalLoginState login nearAccountId mismatch');
  }
  await args.context.signingEngine.activateAuthenticatedWalletState({
    walletId,
    nearAccountId,
    signerSlot,
    nearClient: args.context.nearClient,
  });

  return {
    walletId: String(walletId),
    nearAccountId,
    nearEd25519SigningKeyId: String(nearEd25519SigningKeyId),
    signerSlot,
    isLoggedIn:
      appIdentity.kind === 'resolved' &&
      session.authentication.kind === 'authenticated' &&
      session.authentication.walletId === appIdentity.walletId,
  };
}
