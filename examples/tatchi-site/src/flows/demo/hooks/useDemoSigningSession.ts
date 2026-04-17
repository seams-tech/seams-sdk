import { useCallback, useEffect, useState } from 'react';
import { useTatchi } from '@tatchi-xyz/sdk/react';
import { toast } from 'sonner';

type DemoSigningSessionStatus = {
  sessionId: string;
  status: 'active' | 'exhausted' | 'expired' | 'not_found' | 'unavailable';
  remainingUses?: number;
  expiresAtMs?: number;
  createdAtMs?: number;
};

type UseDemoSigningSessionArgs = {
  clockMs: number;
  isLoggedIn: boolean;
  nearAccountId?: string | null;
  tatchi: ReturnType<typeof useTatchi>['tatchi'];
};

export function useDemoSigningSession(args: UseDemoSigningSessionArgs) {
  const { clockMs, isLoggedIn, nearAccountId, tatchi } = args;

  const [unlockLoading, setUnlockLoading] = useState(false);
  const [sessionRemainingUsesInput, setSessionRemainingUsesInput] = useState(3);
  const [sessionTtlSecondsInput, setSessionTtlSecondsInput] = useState(300);
  const [sessionStatus, setSessionStatus] = useState<DemoSigningSessionStatus | null>(null);

  const refreshSessionStatus = useCallback(async () => {
    if (!nearAccountId) return;
    try {
      const sess = await tatchi.auth.getWalletSession(nearAccountId);
      setSessionStatus(sess?.signingSession || null);
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      toast.error(`Failed to fetch session status: ${message}`, { id: 'session-status' });
    }
  }, [nearAccountId, tatchi]);

  useEffect(() => {
    if (!isLoggedIn || !nearAccountId) return;
    void refreshSessionStatus();
  }, [isLoggedIn, nearAccountId, refreshSessionStatus]);

  const handleUnlockSession = useCallback(async () => {
    if (!nearAccountId) return;

    const remainingUses = Number.isFinite(sessionRemainingUsesInput)
      ? Math.max(0, Math.floor(sessionRemainingUsesInput))
      : undefined;
    const ttlSeconds = Number.isFinite(sessionTtlSecondsInput)
      ? Math.max(0, Math.floor(sessionTtlSecondsInput))
      : undefined;
    const ttlMs = typeof ttlSeconds === 'number' ? ttlSeconds * 1000 : undefined;

    setUnlockLoading(true);
    toast.loading('Logging in & creating session…', { id: 'unlock-session' });
    try {
      await tatchi.auth.unlock(nearAccountId, {
        signingSession: { ttlMs, remainingUses },
      });
      await refreshSessionStatus();
      toast.success('Session ready', { id: 'unlock-session' });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      toast.error(`Failed to create session: ${message}`, { id: 'unlock-session' });
    } finally {
      setUnlockLoading(false);
    }
  }, [
    nearAccountId,
    refreshSessionStatus,
    sessionRemainingUsesInput,
    sessionTtlSecondsInput,
    tatchi,
  ]);

  const expiresInSec =
    sessionStatus?.expiresAtMs != null
      ? Math.max(0, Math.ceil((sessionStatus.expiresAtMs - clockMs) / 1000))
      : null;

  return {
    unlockLoading,
    sessionRemainingUsesInput,
    setSessionRemainingUsesInput,
    sessionTtlSecondsInput,
    setSessionTtlSecondsInput,
    sessionStatus,
    expiresInSec,
    handleUnlockSession,
  };
}
