import { useCallback, useEffect, useState } from 'react';

import { FRONTEND_CONFIG } from '@/config';
import {
  isTempoAlphaUsdFeeToken,
  readTempoTokenBalanceRaw,
  readTempoUserFeeToken,
} from '../demoEvmHelpers';

export type DemoTempoFundingStatus = 'checking' | 'needs_funding' | 'ready' | 'unknown';

/* Probes whether the Tempo signer is actually ready to pay fees: its fee
   token must be set to AlphaUSD AND hold a nonzero balance — the same pair
   that "Fund Tempo Account" (handlePrepareTempoFeeToken) establishes. Native
   gas alone is NOT readiness on Tempo, so eth_getBalance is deliberately not
   consulted here. RPC errors degrade to 'unknown' (fail open: the funding
   button stays available). `refresh` re-probes — call it after a funding
   action completes. */
export function useDemoTempoFundingStatus(args: {
  isLoggedIn: boolean;
  thresholdOwnerAddress: string | null;
}): { status: DemoTempoFundingStatus; refresh: () => void } {
  const [status, setStatus] = useState<DemoTempoFundingStatus>('checking');
  const [probeTick, setProbeTick] = useState(0);
  const refresh = useCallback(() => setProbeTick((t) => t + 1), []);

  useEffect(() => {
    const address = args.thresholdOwnerAddress;
    if (!args.isLoggedIn || !address || !address.startsWith('0x')) {
      setStatus('unknown');
      return;
    }

    let cancelled = false;
    setStatus('checking');
    void (async () => {
      try {
        const rpcUrl = FRONTEND_CONFIG.tempoRpcUrl;
        const userAddress = address as `0x${string}`;
        const feeToken = await readTempoUserFeeToken({ rpcUrl, userAddress });
        if (!feeToken || !isTempoAlphaUsdFeeToken(feeToken)) {
          if (!cancelled) setStatus('needs_funding');
          return;
        }
        const balance = await readTempoTokenBalanceRaw({
          rpcUrl,
          userAddress,
          tokenAddress: feeToken,
        });
        if (!cancelled) setStatus(balance > 0n ? 'ready' : 'needs_funding');
      } catch {
        if (!cancelled) setStatus('unknown');
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [args.isLoggedIn, args.thresholdOwnerAddress, probeTick]);

  return { status, refresh };
}

export default useDemoTempoFundingStatus;
