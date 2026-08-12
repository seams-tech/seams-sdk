import type { SeamsWeb } from '@seams/sdk';

type SyncAccountResult = Awaited<ReturnType<SeamsWeb['recovery']['syncAccount']>>;

export async function recoverWalletAccount(
  seams: SeamsWeb,
  walletId: string,
): Promise<SyncAccountResult> {
  const result = await seams.recovery.syncAccount({ walletId });
  if (!result.success) {
    throw new Error(result.error);
  }

  console.log('wallet account restored', result.walletId, result.nearAccountId);
  return result;
}
