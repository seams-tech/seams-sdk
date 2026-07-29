import { useEffect } from 'react';
import type { NearProvisioningStateChangedEvent } from '@/core/types/sdkSentEvents';
import type { SeamsWeb } from '@/SeamsWeb';
import type { SeamsContextType } from '../types';

type NearProvisioningRefreshArgs = {
  seams: SeamsWeb;
  currentWalletId: string | null;
  refreshLoginState: SeamsContextType['refreshLoginState'];
  refreshAccountData: SeamsContextType['refreshAccountData'];
};

function refreshCurrentWalletAfterNearReady(
  args: NearProvisioningRefreshArgs,
  event: NearProvisioningStateChangedEvent,
): void {
  if (event.state.status !== 'near_ready') return;
  const currentWalletId = String(args.currentWalletId || '').trim();
  if (currentWalletId !== String(event.walletId)) return;

  void Promise.all([
    args.refreshLoginState(String(event.walletId)),
    args.refreshAccountData(),
  ]).catch((error: unknown) => {
    console.warn('[Registration] NEAR-ready React state refresh failed:', error);
  });
}

function subscribeToNearReady(args: NearProvisioningRefreshArgs): () => void {
  return args.seams.registration.onNearProvisioningStateChanged(
    refreshCurrentWalletAfterNearReady.bind(null, args),
  );
}

export function useNearProvisioningStateRefresh(args: NearProvisioningRefreshArgs): void {
  useEffect(subscribeToNearReady.bind(null, args), [
    args.seams,
    args.currentWalletId,
    args.refreshLoginState,
    args.refreshAccountData,
  ]);
}
