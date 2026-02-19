import { useMemo } from 'react';
import type { TatchiPasskey } from '@/core/TatchiPasskey';
import type {
  AuthCapability,
  RecoveryCapability,
  RegistrationCapability,
} from '@/core/TatchiPasskey';
import {
  LoginPhase,
  LoginStatus,
  type LoginHooksOptions,
  type LoginSSEvent,
  RegistrationPhase,
  RegistrationStatus,
  type RegistrationHooksOptions,
  type RegistrationSSEEvent,
  SyncAccountPhase,
  SyncAccountStatus,
  type SyncAccountHooksOptions,
  type SyncAccountSSEEvent,
} from '@/core/types/sdkSentEvents';

export function useTatchiWithSdkFlow(args: {
  tatchi: TatchiPasskey;
  beginSdkFlow: (kind: 'login' | 'register' | 'sync', accountId?: string) => number;
  appendSdkEventMessage: (seq: number, message: string) => void;
  endSdkFlow: (kind: 'login' | 'register' | 'sync', seq: number, status: 'success' | 'error', error?: string) => void;
  hostSetTheme?: (theme: 'light' | 'dark') => void;
}): TatchiPasskey {
  const { tatchi, beginSdkFlow, appendSdkEventMessage, endSdkFlow, hostSetTheme } = args;

  return useMemo(() => {
    /**
     * We use a `Proxy` to instrument a few core flow entrypoints (login/register/sync)
     * while preserving the full `TatchiPasskey` API surface.
     *
     * This lets *all* callers (not just PasskeyAuthMenu) use `ctx.tatchi.*` directly and
     * still have `sdkFlow` update as events stream in.
    */
    type LoginFn = AuthCapability['login'];
    type RegisterPasskeyFn = RegistrationCapability['registerPasskey'];
    type SyncAccountFn = RecoveryCapability['syncAccount'];
    type SetThemeFn = TatchiPasskey['setTheme'];

    const loginWithSdkFlow: LoginFn = async (
      nearAccountId: string,
      options?: LoginHooksOptions,
    ) => {
      const seq = beginSdkFlow('login', nearAccountId);
      const wrappedOptions: LoginHooksOptions = {
        ...options,
        onEvent: (event: LoginSSEvent) => {
          appendSdkEventMessage(seq, event.message);
          if (event.phase === LoginPhase.STEP_4_LOGIN_COMPLETE && event.status === LoginStatus.SUCCESS) {
            endSdkFlow('login', seq, 'success');
          } else if (event.phase === LoginPhase.LOGIN_ERROR || event.status === LoginStatus.ERROR) {
            const error = 'error' in event ? event.error : event.message;
            endSdkFlow('login', seq, 'error', error || event.message);
          }
          options?.onEvent?.(event);
        },
        onError: (error: Error) => {
          appendSdkEventMessage(seq, error.message);
          endSdkFlow('login', seq, 'error', error.message);
          options?.onError?.(error);
        },
      };

      return await tatchi.auth.login(nearAccountId, wrappedOptions);
    };

    const registerPasskeyWithSdkFlow: RegisterPasskeyFn = async (
      nearAccountId: string,
      options?: RegistrationHooksOptions,
    ) => {
      const seq = beginSdkFlow('register', nearAccountId);
      const wrappedOptions: RegistrationHooksOptions = {
        ...options,
        onEvent: (event: RegistrationSSEEvent) => {
          appendSdkEventMessage(seq, event.message);
          if (
            event.phase === RegistrationPhase.STEP_9_REGISTRATION_COMPLETE &&
            event.status === RegistrationStatus.SUCCESS
          ) {
            endSdkFlow('register', seq, 'success');
          } else if (event.phase === RegistrationPhase.REGISTRATION_ERROR || event.status === RegistrationStatus.ERROR) {
            const error = 'error' in event ? event.error : event.message;
            endSdkFlow('register', seq, 'error', error || event.message);
          }
          options?.onEvent?.(event);
        },
        onError: (error: Error) => {
          appendSdkEventMessage(seq, error.message);
          endSdkFlow('register', seq, 'error', error.message);
          options?.onError?.(error);
        },
      };

      return await tatchi.registration.registerPasskey(nearAccountId, wrappedOptions);
    };

    const syncAccountWithSdkFlow: SyncAccountFn = async (args) => {
      const accountId = String(args?.accountId || '').trim();
      const seq = beginSdkFlow('sync', accountId || undefined);
      const wrappedOptions: SyncAccountHooksOptions = {
        ...args?.options,
        onEvent: (event: SyncAccountSSEEvent) => {
          appendSdkEventMessage(seq, event.message);
          if (event.phase === SyncAccountPhase.STEP_5_SYNC_ACCOUNT_COMPLETE && event.status === SyncAccountStatus.SUCCESS) {
            endSdkFlow('sync', seq, 'success');
          } else if (event.phase === SyncAccountPhase.ERROR || event.status === SyncAccountStatus.ERROR) {
            const error = 'error' in event ? event.error : event.message;
            endSdkFlow('sync', seq, 'error', error || event.message);
          }
          (args?.options as SyncAccountHooksOptions | undefined)?.onEvent?.(event);
        },
        onError: (error: Error) => {
          appendSdkEventMessage(seq, error.message);
          endSdkFlow('sync', seq, 'error', error.message);
          (args?.options as SyncAccountHooksOptions | undefined)?.onError?.(error);
        },
      };

      return await tatchi.recovery.syncAccount({
        ...(args?.accountId ? { accountId: args.accountId } : {}),
        options: wrappedOptions,
      });
    };

    const setThemeWithHost: SetThemeFn = (next) => {
      try {
        hostSetTheme?.(next);
      } catch {}
      tatchi.setTheme(next);
    };

    return new Proxy(tatchi, {
      get(target, prop, receiver) {
        if (prop === 'auth') {
          const auth = Reflect.get(target as object, prop, receiver) as AuthCapability;
          return {
            login: loginWithSdkFlow,
            logout: () => auth.logout(),
            getSession: (...args: Parameters<AuthCapability['getSession']>) => auth.getSession(...args),
            hasPasskeyCredential: (...args: Parameters<AuthCapability['hasPasskeyCredential']>) =>
              auth.hasPasskeyCredential(...args),
            getRecentLogins: (...args: Parameters<AuthCapability['getRecentLogins']>) => auth.getRecentLogins(...args),
          } as AuthCapability;
        }

        if (prop === 'registration') {
          const registration = Reflect.get(target as object, prop, receiver) as RegistrationCapability;
          return {
            registerPasskey: registerPasskeyWithSdkFlow,
            registerPasskeyInternal: (...args: Parameters<RegistrationCapability['registerPasskeyInternal']>) =>
              registration.registerPasskeyInternal(...args),
          } as RegistrationCapability;
        }

        if (prop === 'recovery') {
          const recovery = Reflect.get(target as object, prop, receiver) as RecoveryCapability;
          return {
            getRecoveryEmails: (...args: Parameters<RecoveryCapability['getRecoveryEmails']>) =>
              recovery.getRecoveryEmails(...args),
            setRecoveryEmails: (...args: Parameters<RecoveryCapability['setRecoveryEmails']>) =>
              recovery.setRecoveryEmails(...args),
            syncAccount: syncAccountWithSdkFlow,
            startEmailRecovery: (...args: Parameters<RecoveryCapability['startEmailRecovery']>) =>
              recovery.startEmailRecovery(...args),
            finalizeEmailRecovery: (...args: Parameters<RecoveryCapability['finalizeEmailRecovery']>) =>
              recovery.finalizeEmailRecovery(...args),
            cancelEmailRecovery: (...args: Parameters<RecoveryCapability['cancelEmailRecovery']>) =>
              recovery.cancelEmailRecovery(...args),
            startDevice2LinkingFlow: (...args: Parameters<RecoveryCapability['startDevice2LinkingFlow']>) =>
              recovery.startDevice2LinkingFlow(...args),
            stopDevice2LinkingFlow: (...args: Parameters<RecoveryCapability['stopDevice2LinkingFlow']>) =>
              recovery.stopDevice2LinkingFlow(...args),
            linkDeviceWithScannedQRData: (...args: Parameters<RecoveryCapability['linkDeviceWithScannedQRData']>) =>
              recovery.linkDeviceWithScannedQRData(...args),
          } as RecoveryCapability;
        }

        if (prop === 'setTheme') {
          return setThemeWithHost;
        }

        const value: unknown = Reflect.get(target as object, prop, receiver);
        // For non-wrapped methods, bind to preserve `this` on the class instance.
        if (typeof value === 'function') return (value as (...args: unknown[]) => unknown).bind(target);
        return value;
      },
    });
  }, [appendSdkEventMessage, beginSdkFlow, endSdkFlow, hostSetTheme, tatchi]);
}

export default useTatchiWithSdkFlow;
