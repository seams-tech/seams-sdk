import { useEffect, useState } from 'react';

import { FRONTEND_CONFIG } from '@/config';
import {
  DEFAULT_DEMO_EIP1559_FEE_CAPS,
  EIP1559_FEE_CAP_REFRESH_INTERVAL_MS,
  resolveEip1559FeeCaps,
  type Eip1559FeeCaps,
} from '../demoEvmHelpers';

export function useDemoEip1559FeeCaps() {
  const [tempoEip1559FeeCaps, setTempoEip1559FeeCaps] = useState<Eip1559FeeCaps>(
    DEFAULT_DEMO_EIP1559_FEE_CAPS,
  );
  const [arcEip1559FeeCaps, setArcEip1559FeeCaps] = useState<Eip1559FeeCaps>(
    DEFAULT_DEMO_EIP1559_FEE_CAPS,
  );

  useEffect(() => {
    let cancelled = false;
    const refreshFeeCaps = async (): Promise<void> => {
      const [tempoCaps, arcCaps] = await Promise.all([
        resolveEip1559FeeCaps(FRONTEND_CONFIG.tempoRpcUrl).catch(
          () => DEFAULT_DEMO_EIP1559_FEE_CAPS,
        ),
        resolveEip1559FeeCaps(FRONTEND_CONFIG.arcRpcUrl).catch(() => DEFAULT_DEMO_EIP1559_FEE_CAPS),
      ]);
      if (cancelled) return;
      setTempoEip1559FeeCaps(tempoCaps);
      setArcEip1559FeeCaps(arcCaps);
    };

    void refreshFeeCaps();
    const intervalId = window.setInterval(() => {
      void refreshFeeCaps();
    }, EIP1559_FEE_CAP_REFRESH_INTERVAL_MS);

    return () => {
      cancelled = true;
      clearInterval(intervalId);
    };
  }, []);

  return {
    tempoEip1559FeeCaps,
    arcEip1559FeeCaps,
  };
}
