import type { AccountId } from '@/core/types/accountIds';
import { normalizePositiveInteger } from '@shared/utils/normalize';
import { getWalletSession } from '@/SeamsWeb/operations/auth/login';
import type { LocalLoginStateWebContext } from '@/SeamsWeb/signingSurface/types';
import { toWalletId, type WalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { getStoredThresholdEd25519SessionRecordForWallet } from '@/core/signingEngine/session/persistence/records';
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
  const signerSlot = normalizePositiveInteger(args.signerSlot) ?? 1;
  if (!String(walletId).trim() || !String(nearEd25519SigningKeyId).trim()) {
    throw new Error('restoreLocalLoginState requires wallet binding fields');
  }

  const record = getStoredThresholdEd25519SessionRecordForWallet(walletId);
  if (record) {
    if (String(record.nearAccountId) !== String(nearAccountId)) {
      throw new Error('restoreLocalLoginState nearAccountId mismatch');
    }
    if (String(record.nearEd25519SigningKeyId) !== nearEd25519SigningKeyId) {
      throw new Error('restoreLocalLoginState nearEd25519SigningKeyId mismatch');
    }
  }

  await args.context.signingEngine.setLastUser(walletId, signerSlot).catch(() => undefined);
  await args.context.signingEngine.updateLastLogin(walletId).catch(() => undefined);
  const { login } = await getWalletSession(args.context, walletId);
  const loginWalletId = String(login?.walletId || '').trim();
  const loginNearAccountId = String(login?.nearAccountId || '').trim();
  if (loginWalletId && loginWalletId !== String(walletId)) {
    throw new Error('restoreLocalLoginState walletId mismatch');
  }
  if (loginNearAccountId && loginNearAccountId !== String(nearAccountId)) {
    throw new Error('restoreLocalLoginState login nearAccountId mismatch');
  }
  await args.context.signingEngine
    .activateAuthenticatedWalletState({
      walletId,
      nearAccountId,
      nearClient: args.context.nearClient,
    })
    .catch(() => undefined);

  return {
    walletId: String(walletId),
    nearAccountId,
    nearEd25519SigningKeyId: String(nearEd25519SigningKeyId),
    signerSlot,
    isLoggedIn: Boolean(login?.isLoggedIn),
  };
}
