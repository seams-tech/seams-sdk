import { useCallback, useEffect, useRef, useState } from 'react';
import { useSeams } from '@seams/sdk/react';
import { toast } from 'sonner';
import {
  DEMO_SIGNING_SESSION_EXPIRY_MESSAGE,
  DEMO_SIGNING_SESSION_MISSING_MESSAGE,
  DemoWalletSessionLifecycleController,
  demoSigningSessionExpiryKey,
  parseDemoSigningSessionExpiredEvent,
  type DemoExactSessionState,
  type DemoSigningSessionExpiredEvent,
  type DemoSigningSessionStatusSource,
  type DemoWalletSessionLifecycleAction,
} from '../demoWalletSessionLifecycle';

const SESSION_STATUS_POLL_MS = 60_000;

export type DemoWalletSessionLifecycleReadiness =
  | { readonly kind: 'initializing' }
  | { readonly kind: 'ready' }
  | { readonly kind: 'initialization_failed' };

export function useDemoWalletSessionLifecycle(): DemoWalletSessionLifecycleReadiness {
  const { seams } = useSeams();
  const controllerRef = useRef(new DemoWalletSessionLifecycleController());
  const checkInFlightRef = useRef(false);
  const [readiness, setReadiness] = useState<DemoWalletSessionLifecycleReadiness>({
    kind: 'initializing',
  });

  const applyLifecycleAction = useCallback(
    async (action: DemoWalletSessionLifecycleAction): Promise<void> => {
      await applyDemoWalletSessionLifecycleAction({
        seams,
        controller: controllerRef.current,
        initialAction: action,
      });
    },
    [seams],
  );

  const observeExactState = useCallback(
    async (state: DemoExactSessionState, source: DemoSigningSessionStatusSource): Promise<void> =>
      await observeExactSessionState({
        controller: controllerRef.current,
        state,
        source,
        applyLifecycleAction,
      }),
    [applyLifecycleAction],
  );

  const checkExactSession = useCallback(
    async (source: DemoSigningSessionStatusSource): Promise<void> => {
      if (checkInFlightRef.current) return;
      checkInFlightRef.current = true;
      try {
        const state = await seams.getWalletIframeExactSessionState();
        await observeExactState(state, source);
      } catch {
        // A failed background check does not change wallet state.
      } finally {
        checkInFlightRef.current = false;
      }
    },
    [observeExactState, seams],
  );

  const handleExpiredEvent = useCallback(
    (value: unknown): void => {
      const event: DemoSigningSessionExpiredEvent | null =
        parseDemoSigningSessionExpiredEvent(value);
      if (event === null) return;
      const action = controllerRef.current.observeExpiredEvent(event);
      void applyLifecycleAction(action).catch(reportBackgroundLifecycleFailure);
    },
    [applyLifecycleAction],
  );

  const checkOnVisibility = useCallback((): void => {
    if (document.visibilityState === 'visible') void checkExactSession('visibility');
  }, [checkExactSession]);

  const checkOnFocus = useCallback((): void => {
    void checkExactSession('focus');
  }, [checkExactSession]);

  const checkOnPoll = useCallback((): void => {
    if (document.visibilityState === 'visible') void checkExactSession('poll');
  }, [checkExactSession]);

  useEffect(() => {
    const lifecycle = { disposed: false };
    setReadiness({ kind: 'initializing' });
    void initializeExactWalletSession({
      seams,
      lifecycle,
      observeExactState,
      setReadiness,
    });
    return disposeExactWalletSessionInitialization.bind(null, lifecycle);
  }, [observeExactState, seams]);

  useEffect(() => seams.onSdkLifecycleEvent(handleExpiredEvent), [handleExpiredEvent, seams]);

  useEffect(() => {
    document.addEventListener('visibilitychange', checkOnVisibility);
    window.addEventListener('focus', checkOnFocus);
    const pollId = window.setInterval(checkOnPoll, SESSION_STATUS_POLL_MS);
    return function removeDemoSessionLifecycleListeners(): void {
      document.removeEventListener('visibilitychange', checkOnVisibility);
      window.removeEventListener('focus', checkOnFocus);
      window.clearInterval(pollId);
    };
  }, [checkOnFocus, checkOnPoll, checkOnVisibility]);

  return readiness;
}

async function initializeExactWalletSession(args: {
  readonly seams: ReturnType<typeof useSeams>['seams'];
  readonly lifecycle: { disposed: boolean };
  readonly observeExactState: (
    state: DemoExactSessionState,
    source: DemoSigningSessionStatusSource,
  ) => Promise<void>;
  readonly setReadiness: (readiness: DemoWalletSessionLifecycleReadiness) => void;
}): Promise<void> {
  try {
    const state = await args.seams.initWalletIframe();
    if (args.lifecycle.disposed) return;
    await args.observeExactState(state, 'restore');
    if (!args.lifecycle.disposed) args.setReadiness({ kind: 'ready' });
  } catch (error: unknown) {
    if (!args.lifecycle.disposed) args.setReadiness({ kind: 'initialization_failed' });
    reportBackgroundLifecycleFailure(error);
  }
}

async function observeExactSessionState(args: {
  readonly controller: DemoWalletSessionLifecycleController;
  readonly state: DemoExactSessionState;
  readonly source: DemoSigningSessionStatusSource;
  readonly applyLifecycleAction: (action: DemoWalletSessionLifecycleAction) => Promise<void>;
}): Promise<void> {
  const action = args.controller.observeExactState(args.state, args.source);
  await args.applyLifecycleAction(action);
}

async function applyDemoWalletSessionLifecycleAction(args: {
  readonly seams: ReturnType<typeof useSeams>['seams'];
  readonly controller: DemoWalletSessionLifecycleController;
  readonly initialAction: DemoWalletSessionLifecycleAction;
}): Promise<void> {
  let action = args.initialAction;
  while (true) {
    switch (action.kind) {
      case 'preserve_unlocked':
        return;
      case 'lock_missing_session': {
        try {
          const result = await args.seams.lockWalletIframeMissingSession(action.identity);
          if (result.kind === 'stale_session') {
            args.controller.releaseMissingSessionLock(action.identity.walletId);
            action = args.controller.observeExactState(result.current, 'poll');
            continue;
          }
          args.controller.confirmMissingSessionLocked(action.identity.walletId);
          toast.error(DEMO_SIGNING_SESSION_MISSING_MESSAGE, {
            id: `demo-session-missing:${encodeURIComponent(action.identity.walletId)}`,
          });
        } catch (error: unknown) {
          args.controller.releaseMissingSessionLock(action.identity.walletId);
          throw error;
        }
        return;
      }
      case 'lock_expired': {
        try {
          const result = await args.seams.lockWalletIframeExactSession(action.identity);
          if (result.kind === 'stale_session') {
            args.controller.releaseExpiredSessionLock(action.identity);
            action = args.controller.observeExactState(result.current, 'poll');
            continue;
          }
          args.controller.confirmExpiredSessionLocked(action.identity);
          const toastId = demoSigningSessionExpiryKey(
            String(action.identity.walletId),
            String(action.identity.walletSessionId),
          );
          toast.error(DEMO_SIGNING_SESSION_EXPIRY_MESSAGE, {
            id: `demo-session-expired:${toastId}`,
          });
        } catch (error: unknown) {
          args.controller.releaseExpiredSessionLock(action.identity);
          throw error;
        }
        return;
      }
      default:
        return assertNeverLifecycleAction(action);
    }
  }
}

function reportBackgroundLifecycleFailure(error: unknown): void {
  console.error('[demo] Wallet Session lifecycle handling failed', error);
}

function disposeExactWalletSessionInitialization(lifecycle: { disposed: boolean }): void {
  lifecycle.disposed = true;
}

function assertNeverLifecycleAction(value: never): never {
  throw new Error(`Unhandled demo Wallet Session lifecycle action: ${String(value)}`);
}
