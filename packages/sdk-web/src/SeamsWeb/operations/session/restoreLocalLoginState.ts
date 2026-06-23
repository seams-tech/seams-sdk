import type { AccountId } from '@/core/types/accountIds';
import { normalizePositiveInteger } from '@shared/utils/normalize';
import { getWalletSession } from '@/SeamsWeb/operations/auth/login';
import type { LocalLoginStateWebContext } from '@/SeamsWeb/signingSurface/types';
import { toWalletId, type WalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { getStoredThresholdEd25519SessionRecordForWallet } from '@/core/signingEngine/session/persistence/records';
import type { Ed25519KeyScopeId } from '@shared/utils/registrationIntent';

export async function restoreLocalLoginState(args: {
  context: LocalLoginStateWebContext;
  walletId: WalletId;
  nearAccountId: AccountId;
  ed25519KeyScopeId: Ed25519KeyScopeId;
  signerSlot: number;
}): Promise<{
  walletId: string;
  nearAccountId: AccountId;
  ed25519KeyScopeId: string;
  signerSlot: number;
  isLoggedIn: boolean;
}> {
  const walletId = args.walletId;
  const nearAccountId = args.nearAccountId;
  const ed25519KeyScopeId = args.ed25519KeyScopeId;
  const signerSlot = normalizePositiveInteger(args.signerSlot) ?? 1;
  if (!String(walletId).trim() || !String(ed25519KeyScopeId).trim()) {
    throw new Error('restoreLocalLoginState requires wallet binding fields');
  }

  const record = getStoredThresholdEd25519SessionRecordForWallet(walletId);
  if (record) {
    if (String(record.nearAccountId) !== String(nearAccountId)) {
      throw new Error('restoreLocalLoginState nearAccountId mismatch');
    }
    if (String(record.ed25519KeyScopeId) !== ed25519KeyScopeId) {
      throw new Error('restoreLocalLoginState ed25519KeyScopeId mismatch');
    }
  }

  await args.context.signingEngine.setLastUser(nearAccountId, signerSlot).catch(() => undefined);
  await args.context.signingEngine.updateLastLogin(nearAccountId).catch(() => undefined);
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
    ed25519KeyScopeId: String(ed25519KeyScopeId),
    signerSlot,
    isLoggedIn: Boolean(login?.isLoggedIn),
  };
}
