import { useCallback, useEffect, useState } from 'react';
import { useTatchi } from '@tatchi-xyz/sdk/react';
import { toast } from 'sonner';

export type DemoSigningSessionStatus = {
  sessionId: string;
  status: 'active' | 'exhausted' | 'expired' | 'not_found' | 'unavailable';
  authMethod?: string | null;
  retention?: string | null;
  remainingUses?: number;
  expiresAtMs?: number;
  createdAtMs?: number;
};

export type DemoWalletSessionSnapshot = {
  login: {
    isLoggedIn: boolean;
    nearAccountId?: string | null;
    authMethod?: string | null;
  };
  signingSession: DemoSigningSessionStatus | null;
  authMethod?: string | null;
  retention?: string | null;
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
  const [walletSession, setWalletSession] = useState<DemoWalletSessionSnapshot | null>(null);
  const [sessionStatusLoading, setSessionStatusLoading] = useState(false);
  const [sessionStatusError, setSessionStatusError] = useState('');

  const refreshSessionStatus = useCallback(async () => {
    if (!nearAccountId) {
      setWalletSession(null);
      setSessionStatus(null);
      setSessionStatusError('');
      return;
    }
    setSessionStatusLoading(true);
    try {
      const sess = await tatchi.auth.getWalletSession(nearAccountId);
      const snapshot: DemoWalletSessionSnapshot = {
        login: {
          isLoggedIn: sess.login.isLoggedIn,
          nearAccountId: sess.login.nearAccountId,
          authMethod: sess.login.authMethod || null,
        },
        signingSession: sess.signingSession || null,
        authMethod: sess.authMethod || null,
        retention: sess.retention || null,
      };
      setWalletSession(snapshot);
      setSessionStatus(snapshot.signingSession);
      setSessionStatusError('');
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      setSessionStatusError(message);
      toast.error(`Failed to fetch session status: ${message}`, { id: 'session-status' });
    } finally {
      setSessionStatusLoading(false);
    }
  }, [nearAccountId, tatchi]);

  useEffect(() => {
    if (!isLoggedIn || !nearAccountId) {
      setWalletSession(null);
      setSessionStatus(null);
      setSessionStatusError('');
      return;
    }
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
    walletSession,
    sessionStatus,
    sessionStatusLoading,
    sessionStatusError,
    expiresInSec,
    refreshSessionStatus,
    handleUnlockSession,
  };
}
