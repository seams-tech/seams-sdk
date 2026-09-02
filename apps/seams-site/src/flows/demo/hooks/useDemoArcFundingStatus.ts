import { useCallback, useEffect, useState } from 'react';

import { FRONTEND_CONFIG } from '@/config';
import { isEvmAddress, readEvmNativeBalance } from '../demoEvmHelpers';

export type DemoArcFundingStatus = 'checking' | 'needs_funding' | 'ready' | 'unknown';

/* Circle funds the Arc wallet with native testnet gas. Poll only while Arc is
   visible and still awaiting funds; once a positive balance lands, the status
   becomes stable and signing can be enabled. */
export function useDemoArcFundingStatus(args: {
  isLoggedIn: boolean;
  thresholdOwnerAddress: string | null;
  enabled: boolean;
}): { status: DemoArcFundingStatus; refresh: () => void } {
  const [status, setStatus] = useState<DemoArcFundingStatus>('checking');
  const [probeTick, setProbeTick] = useState(0);
  const refresh = useCallback(() => setProbeTick((tick) => tick + 1), []);

  useEffect(() => {
    if (!args.enabled) return;
    const address = args.thresholdOwnerAddress;
    if (!args.isLoggedIn || !address || !isEvmAddress(address)) {
      setStatus('unknown');
      return;
    }

    let cancelled = false;
    setStatus('checking');
    void readEvmNativeBalance({
      rpcUrl: FRONTEND_CONFIG.arcRpcRequestUrl,
      address,
      blockTag: 'pending',
    })
      .then((balanceWei) => {
        if (!cancelled) setStatus(balanceWei > 0n ? 'ready' : 'needs_funding');
      })
      .catch(() => {
        if (!cancelled) setStatus('unknown');
      });

    return () => {
      cancelled = true;
    };
  }, [args.enabled, args.isLoggedIn, args.thresholdOwnerAddress, probeTick]);

  useEffect(() => {
    if (!args.enabled || (status !== 'needs_funding' && status !== 'unknown')) return undefined;
    const intervalId = window.setInterval(() => {
      if (document.visibilityState !== 'hidden') refresh();
    }, 5000);
    return () => window.clearInterval(intervalId);
  }, [args.enabled, refresh, status]);

  return { status, refresh };
}
