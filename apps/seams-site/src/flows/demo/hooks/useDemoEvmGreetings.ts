import { useCallback, useEffect, useState } from 'react';
import { toast } from 'sonner';

import { FRONTEND_CONFIG } from '@/config';
import {
  ARC_GREET_SELECTOR,
  ARC_TESTNET_GREETING_CONTRACT,
  TEMPO_GREETING_CONTRACT,
  TEMPO_GREETING_SELECTOR,
  readEvmGreeting,
} from '../demoEvmHelpers';

/* `tempoEnabled` / `arcEnabled` are the selected-chain gates. A greeting is only
   ever displayed on its own tab, so the initial read is deferred until that tab
   is shown. Manual refresh (`fetchTempoGreeting` / `fetchArcGreeting`) stays
   available regardless — the gate covers only the automatic read. */
type UseDemoEvmGreetingsArgs = {
  isLoggedIn: boolean;
  tempoEnabled?: boolean;
  arcEnabled?: boolean;
};

export function useDemoEvmGreetings(args: UseDemoEvmGreetingsArgs) {
  const { isLoggedIn } = args;
  const tempoEnabled = args.tempoEnabled ?? true;
  const arcEnabled = args.arcEnabled ?? true;

  const [tempoGreeting, setTempoGreeting] = useState<string | null>(null);
  const [arcGreeting, setArcGreeting] = useState<string | null>(null);
  const [tempoGreetingLoading, setTempoGreetingLoading] = useState(false);
  const [arcGreetingLoading, setArcGreetingLoading] = useState(false);
  const [tempoGreetingError, setTempoGreetingError] = useState<string | null>(null);
  const [arcGreetingError, setArcGreetingError] = useState<string | null>(null);

  const fetchTempoGreeting = useCallback(async (opts?: { silent?: boolean }) => {
    setTempoGreetingLoading(true);
    setTempoGreetingError(null);
    try {
      const greeting = await readEvmGreeting({
        rpcUrl: FRONTEND_CONFIG.tempoRpcUrl,
        contract: TEMPO_GREETING_CONTRACT,
        selector: TEMPO_GREETING_SELECTOR,
      });
      setTempoGreeting(greeting);
      return greeting;
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      setTempoGreetingError(message);
      if (!opts?.silent) {
        toast.error(`Tempo greeting fetch failed: ${message}`);
      }
      return null;
    } finally {
      setTempoGreetingLoading(false);
    }
  }, []);

  const fetchArcGreeting = useCallback(async (opts?: { silent?: boolean }) => {
    setArcGreetingLoading(true);
    setArcGreetingError(null);
    try {
      const greeting = await readEvmGreeting({
        rpcUrl: FRONTEND_CONFIG.arcRpcRequestUrl,
        contract: ARC_TESTNET_GREETING_CONTRACT,
        selector: ARC_GREET_SELECTOR,
      });
      setArcGreeting(greeting);
      return greeting;
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      setArcGreetingError(message);
      if (!opts?.silent) {
        toast.error(`Arc greeting fetch failed: ${message}`);
      }
      return null;
    } finally {
      setArcGreetingLoading(false);
    }
  }, []);

  useEffect(() => {
    if (!isLoggedIn) return;
    if (tempoEnabled) void fetchTempoGreeting({ silent: true });
    if (arcEnabled) void fetchArcGreeting({ silent: true });
  }, [arcEnabled, fetchArcGreeting, fetchTempoGreeting, isLoggedIn, tempoEnabled]);

  return {
    tempoGreeting,
    arcGreeting,
    tempoGreetingLoading,
    arcGreetingLoading,
    tempoGreetingError,
    arcGreetingError,
    fetchTempoGreeting,
    fetchArcGreeting,
  };
}
