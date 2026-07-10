import { useEffect, useState } from 'react';

import { FRONTEND_CONFIG } from '@/config';
import { readEvmNativeBalance } from '../demoEvmHelpers';

export type DemoGasStatus = 'checking' | 'needs_gas' | 'ready' | 'unknown';

/* Probes the threshold owner's native balance on the Tempo and Arc testnets
   so the UI can surface funding steps before the first failed sign. A zero
   balance means the account cannot pay gas; RPC errors degrade to 'unknown'
   rather than blocking the demo. */
export function useDemoThresholdGasStatus(args: {
  isLoggedIn: boolean;
  thresholdOwnerAddress: string | null;
}): { tempo: DemoGasStatus; arc: DemoGasStatus } {
  const [tempo, setTempo] = useState<DemoGasStatus>('checking');
  const [arc, setArc] = useState<DemoGasStatus>('checking');

  useEffect(() => {
    const address = args.thresholdOwnerAddress;
    if (!args.isLoggedIn || !address || !address.startsWith('0x')) {
      setTempo('unknown');
      setArc('unknown');
      return;
    }

    let cancelled = false;
    const probe = async (rpcUrl: string, set: (status: DemoGasStatus) => void) => {
      try {
        const balance = await readEvmNativeBalance({
          rpcUrl,
          address: address as `0x${string}`,
        });
        if (!cancelled) set(balance > 0n ? 'ready' : 'needs_gas');
      } catch {
        if (!cancelled) set('unknown');
      }
    };

    setTempo('checking');
    setArc('checking');
    void probe(FRONTEND_CONFIG.tempoRpcUrl, setTempo);
    void probe(FRONTEND_CONFIG.arcRpcUrl, setArc);

    return () => {
      cancelled = true;
    };
  }, [args.isLoggedIn, args.thresholdOwnerAddress]);

  return { tempo, arc };
}

export default useDemoThresholdGasStatus;
