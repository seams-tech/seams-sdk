import { useCallback, useEffect, useState } from 'react';
import { walletSessionRefFromSession } from '@seams/sdk/advanced';
import { useSeams } from '@seams/sdk/react';
import { toast } from 'sonner';
import { resolveDemoThresholdEcdsaChainTarget } from '../demoChainTargets';

const SESSION_STATUS_AUTO_REFRESH_MS = 15_000;

export type DemoSigningSessionStatus = {
  sessionId: string;
  status: 'active' | 'exhausted' | 'expired' | 'not_found' | 'unavailable' | 'budget_unknown';
  authMethod?: string | null;
  retention?: string | null;
  availableUses?: number;
  inFlightReservedUses?: number;
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
  nonceDiagnostics?: DemoNonceDiagnostics | null;
};

export type DemoNonceDiagnostics = {
  leaseCount: number;
  laneCount: number;
  metrics?: {
    oldestLeaseAgeMs?: number;
    oldestInFlightLeaseAgeMs?: number;
    staleInFlightLeaseCount?: number;
    staleInFlightLaneCount?: number;
  };
  leasesByState?: Record<string, number>;
  lanes?: Array<{
    family: string;
    accountId?: string;
    networkKey: string;
    chain?: string;
    chainId?: number;
    leaseCount: number;
    states?: Record<string, number>;
  }>;
  near?: {
    hasContext: boolean;
    reservedNonceCount: number;
    activeAccountId?: string;
    activePublicKey?: string;
    lastReservedNonce?: string;
  };
};

type UseDemoSigningSessionArgs = {
  clockMs: number;
  isLoggedIn: boolean;
  walletId?: string | null;
  seams: ReturnType<typeof useSeams>['seams'];
};

export function useDemoSigningSession(args: UseDemoSigningSessionArgs) {
  const { clockMs, isLoggedIn, walletId, seams } = args;

  const [unlockLoading, setUnlockLoading] = useState(false);
  const [sessionRemainingUsesInput, setSessionRemainingUsesInput] = useState(3);
  const [sessionTtlSecondsInput, setSessionTtlSecondsInput] = useState(300);
  const [sessionStatus, setSessionStatus] = useState<DemoSigningSessionStatus | null>(null);
  const [walletSession, setWalletSession] = useState<DemoWalletSessionSnapshot | null>(null);
  const [sessionStatusLoading, setSessionStatusLoading] = useState(false);
  const [sessionStatusError, setSessionStatusError] = useState('');

  const refreshSessionStatus = useCallback(
    async (opts?: { silent?: boolean }) => {
      if (!walletId) {
        setWalletSession(null);
        setSessionStatus(null);
        setSessionStatusError('');
        return;
      }
      if (!opts?.silent) setSessionStatusLoading(true);
      try {
        const sess = await seams.auth.getWalletSession(walletId);
        const snapshot: DemoWalletSessionSnapshot = {
          login: {
            isLoggedIn: sess.login.isLoggedIn,
            nearAccountId: sess.login.nearAccountId,
            authMethod: sess.login.authMethod || null,
          },
          signingSession: sess.signingSession || null,
          authMethod: sess.authMethod || null,
          retention: sess.retention || null,
          nonceDiagnostics: sess.nonceDiagnostics || null,
        };
        setWalletSession(snapshot);
        setSessionStatus(snapshot.signingSession);
        setSessionStatusError('');
      } catch (error: unknown) {
        const message = error instanceof Error ? error.message : String(error);
        setSessionStatusError(message);
        if (!opts?.silent) {
          toast.error(`Failed to fetch session status: ${message}`, { id: 'session-status' });
        }
      } finally {
        if (!opts?.silent) setSessionStatusLoading(false);
      }
    },
    [seams, walletId],
  );

  useEffect(() => {
    if (!isLoggedIn || !walletId) {
      setWalletSession(null);
      setSessionStatus(null);
      setSessionStatusError('');
      return;
    }
    void refreshSessionStatus();
  }, [isLoggedIn, refreshSessionStatus, walletId]);

  useEffect(() => {
    if (!isLoggedIn || !walletId) return undefined;
    const id = window.setInterval(() => {
      if (document.visibilityState === 'hidden') return;
      void refreshSessionStatus({ silent: true });
    }, SESSION_STATUS_AUTO_REFRESH_MS);
    return () => window.clearInterval(id);
  }, [isLoggedIn, refreshSessionStatus, walletId]);

  const handleUnlockSession = useCallback(async () => {
    if (!walletId) return;

    const remainingUses = Number.isFinite(sessionRemainingUsesInput)
      ? Math.max(0, Math.floor(sessionRemainingUsesInput))
      : undefined;
    const ttlSeconds = Number.isFinite(sessionTtlSecondsInput)
      ? Math.max(0, Math.floor(sessionTtlSecondsInput))
      : undefined;
    const ttlMs = typeof ttlSeconds === 'number' ? ttlSeconds * 1000 : undefined;

    setUnlockLoading(true);
    toast.loading('Creating signing session…', { id: 'unlock-session' });
    try {
      const currentSession = await seams.auth.getWalletSession(walletId);
      const authMethod =
        currentSession.authMethod ||
        currentSession.signingSession?.authMethod ||
        currentSession.login.authMethod ||
        '';

      if (authMethod === 'email_otp') {
        if (currentSession.retention === 'single_use') {
          throw new Error('Email OTP per-operation policy does not support reusable sessions');
        }
        const challenge = await seams.auth.requestEmailOtpSigningSessionChallenge({
          walletSession: walletSessionRefFromSession({
            walletId,
            walletSessionUserId: walletId,
          }),
          chainTarget: resolveDemoThresholdEcdsaChainTarget('tempo'),
        });
        const emailHint = String(challenge.emailHint || '').trim();
        const otpCode = String(
          window.prompt(
            emailHint
              ? `Enter the 6-digit code sent to ${emailHint} to create a signing session.`
              : 'Enter the 6-digit email code to create a signing session.',
          ) || '',
        ).trim();
        if (!/^\d{6}$/.test(otpCode)) {
          throw new Error('Email OTP signing session requires a 6-digit code');
        }
        await seams.auth.refreshEmailOtpSigningSession({
          walletSession: walletSessionRefFromSession({
            walletId,
            walletSessionUserId: walletId,
          }),
          chainTarget: resolveDemoThresholdEcdsaChainTarget('tempo'),
          challengeId: challenge.challengeId,
          otpCode,
          ...(typeof ttlMs === 'number' ? { ttlMs } : {}),
          ...(typeof remainingUses === 'number' ? { remainingUses } : {}),
        });
      } else {
        await seams.auth.unlock(walletId, {
          signingSession: { ttlMs, remainingUses },
        });
      }
      await refreshSessionStatus();
      toast.success('Session ready', { id: 'unlock-session' });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      toast.error(`Failed to create session: ${message}`, { id: 'unlock-session' });
    } finally {
      setUnlockLoading(false);
    }
  }, [
    refreshSessionStatus,
    sessionRemainingUsesInput,
    sessionTtlSecondsInput,
    seams,
    walletSession,
    walletId,
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
