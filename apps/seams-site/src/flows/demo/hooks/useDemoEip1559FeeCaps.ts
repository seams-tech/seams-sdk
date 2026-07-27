import { useEffect, useState } from 'react';

import { FRONTEND_CONFIG } from '@/config';
import {
  DEFAULT_DEMO_EIP1559_FEE_CAPS,
  EIP1559_FEE_CAP_REFRESH_INTERVAL_MS,
  resolveEip1559FeeCaps,
  type Eip1559FeeCaps,
} from '../demoEvmHelpers';

/* Each `resolveEip1559FeeCaps` call costs up to three JSON-RPC round trips, and
   this hook re-runs them on an interval. Fee caps are only ever consumed by the
   chain the user is signing on, so each chain is polled only while it is the
   selected tab. Both default to enabled for callers that want the old
   fetch-everything behaviour. */
export function useDemoEip1559FeeCaps(options?: {
  tempoEnabled?: boolean;
  arcEnabled?: boolean;
}) {
  const tempoEnabled = options?.tempoEnabled ?? true;
  const arcEnabled = options?.arcEnabled ?? true;
  const [tempoEip1559FeeCaps, setTempoEip1559FeeCaps] = useState<Eip1559FeeCaps>(
    DEFAULT_DEMO_EIP1559_FEE_CAPS,
  );
  const [arcEip1559FeeCaps, setArcEip1559FeeCaps] = useState<Eip1559FeeCaps>(
    DEFAULT_DEMO_EIP1559_FEE_CAPS,
  );

  useEffect(() => {
    if (!tempoEnabled && !arcEnabled) return undefined;
    let cancelled = false;
    const refreshFeeCaps = async (): Promise<void> => {
      const [tempoCaps, arcCaps] = await Promise.all([
        tempoEnabled
          ? resolveEip1559FeeCaps(FRONTEND_CONFIG.tempoRpcUrl).catch(
              () => DEFAULT_DEMO_EIP1559_FEE_CAPS,
            )
          : Promise.resolve(null),
        arcEnabled
          ? resolveEip1559FeeCaps(FRONTEND_CONFIG.arcRpcUrl).catch(
              () => DEFAULT_DEMO_EIP1559_FEE_CAPS,
            )
          : Promise.resolve(null),
      ]);
      if (cancelled) return;
      if (tempoCaps) setTempoEip1559FeeCaps(tempoCaps);
      if (arcCaps) setArcEip1559FeeCaps(arcCaps);
    };

    void refreshFeeCaps();
    const intervalId = window.setInterval(() => {
      void refreshFeeCaps();
    }, EIP1559_FEE_CAP_REFRESH_INTERVAL_MS);

    return () => {
      cancelled = true;
      clearInterval(intervalId);
    };
  }, [tempoEnabled, arcEnabled]);

  return {
    tempoEip1559FeeCaps,
    arcEip1559FeeCaps,
  };
}
