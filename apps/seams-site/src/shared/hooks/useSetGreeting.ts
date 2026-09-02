import { useRef, useState, useEffect } from 'react';
import { DEMO_CONTRACT_ID } from '@/shared/types';
import { useNearClient } from '@seams/wallet/react';

export interface GreetingResult {
  success: boolean;
  error?: string;
  greeting?: string;
}

interface SetGreetingHook {
  onchainGreeting: string | null;
  isLoading: boolean;
  error: string | null;
  fetchGreeting: () => Promise<GreetingResult>;
}

function parseGreeting(value: unknown): string | null {
  if (value === null || value === undefined) return null;
  if (typeof value === 'string') return value;
  throw new Error('NEAR greeting response must be a string or null');
}

/* `enabled` defers the initial NEAR view call until the caller actually shows
   NEAR data. It stays true by default so callers that always want the greeting
   need not opt in. The one-shot semantics are preserved: the fetch still runs
   at most once, just on the first render where it is enabled. */
export const useSetGreeting = (options?: { enabled?: boolean }): SetGreetingHook => {
  const enabled = options?.enabled ?? true;
  const nearClient = useNearClient();
  const [onchainGreeting, setOnchainGreeting] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Instance-level flag for this specific hook instance
  const isCurrentlyFetching = useRef<boolean>(false);
  // StrictMode-safe guard to run initial fetch once
  const didInit = useRef<boolean>(false);

  const fetchGreeting = async (): Promise<GreetingResult> => {
    // Instance-level concurrent protection
    if (isCurrentlyFetching.current) {
      return { success: false, error: 'Already fetching' };
    }

    isCurrentlyFetching.current = true;
    setIsLoading(true);
    setError(null);

    try {
      const result = await nearClient.view<Record<string, never>, unknown>({
        account: DEMO_CONTRACT_ID,
        method: 'get_greeting',
        args: {},
      });
      const greeting = parseGreeting(result);
      setOnchainGreeting(greeting);

      return { success: true, ...(greeting !== null ? { greeting } : {}) };
    } catch (err: any) {
      console.error('Error fetching greeting:', err);
      const errorMessage = err.message || 'Failed to fetch greeting';
      setError(errorMessage);

      return {
        success: false,
        error: errorMessage,
      };
    } finally {
      setIsLoading(false);
      isCurrentlyFetching.current = false;
    }
  };

  // Auto-fetch greeting on mount with protection against React StrictMode double-mounting
  useEffect(() => {
    if (!enabled) return;
    if (didInit.current) return;
    didInit.current = true;
    void fetchGreeting();
  }, [enabled]); // Runs once, on the first render where the caller enables it

  return {
    onchainGreeting,
    isLoading,
    error,
    fetchGreeting,
  };
};
