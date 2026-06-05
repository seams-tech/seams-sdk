import { useMemo } from 'react';
import type { SeamsWeb } from '@/web/SeamsWeb';
import type {
  AuthCapability,
  RecoveryCapability,
  RegistrationCapability,
} from '@/web/SeamsWeb';
import {
  type LoginHooksOptions,
  UnlockEventPhase,
  type UnlockFlowEvent,
  RegistrationEventPhase,
  type RegistrationHooksOptions,
  type RegistrationFlowEvent,
  AccountSyncEventPhase,
  type AccountSyncFlowEvent,
  type SyncAccountHooksOptions,
} from '@/core/types/sdkSentEvents';

export function useSeamsWithSdkFlow(args: {
  seams: SeamsWeb;
  beginSdkFlow: (kind: 'login' | 'register' | 'sync', accountId?: string) => number;
  appendSdkEventMessage: (seq: number, message: string) => void;
  endSdkFlow: (
    kind: 'login' | 'register' | 'sync',
    seq: number,
    status: 'success' | 'error',
    error?: string,
  ) => void;
  hostSetTheme?: (theme: 'light' | 'dark') => void;
}): SeamsWeb {
  const { seams, beginSdkFlow, appendSdkEventMessage, endSdkFlow, hostSetTheme } = args;

  return useMemo(() => {
    /**
     * We use a `Proxy` to instrument a few core flow entrypoints (login/register/sync)
     * while preserving the full `SeamsWeb` API surface.
     *
     * This lets *all* callers (not just PasskeyAuthMenu) use `ctx.seams.*` directly and
     * still have `sdkFlow` update as events stream in.
     */
    type LoginFn = AuthCapability['unlock'];
    type RegisterWalletFn = RegistrationCapability['registerWallet'];
    type RegisterWithEmailOtpFn = RegistrationCapability['registerWithEmailOtp'];
    type AddWalletSignerFn = RegistrationCapability['addWalletSigner'];
    type RegisterPasskeyFn = RegistrationCapability['registerPasskey'];
    type SyncAccountFn = RecoveryCapability['syncAccount'];
    type SetThemeFn = SeamsWeb['setTheme'];

    const loginWithSdkFlow: LoginFn = async (
      nearAccountId: string,
      options?: LoginHooksOptions,
    ) => {
      const seq = beginSdkFlow('login', nearAccountId);
      const wrappedOptions: LoginHooksOptions = {
        ...options,
        onEvent: (event: UnlockFlowEvent) => {
          appendSdkEventMessage(seq, event.message);
          if (event.phase === UnlockEventPhase.STEP_07_COMPLETED && event.status === 'succeeded') {
            endSdkFlow('login', seq, 'success');
          } else if (
            event.phase === UnlockEventPhase.FAILED ||
            event.phase === UnlockEventPhase.CANCELLED ||
            event.status === 'failed' ||
            event.status === 'cancelled'
          ) {
            const error = event.error?.message || event.message;
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

      return await seams.auth.unlock(nearAccountId, wrappedOptions);
    };

    const registerPasskeyWithSdkFlow: RegisterPasskeyFn = async (
      nearAccountId: string,
      options?: RegistrationHooksOptions,
    ) => {
      const seq = beginSdkFlow('register', nearAccountId);
      const wrappedOptions: RegistrationHooksOptions = {
        ...options,
        onEvent: (event: RegistrationFlowEvent) => {
          appendSdkEventMessage(seq, event.message);
          if (
            event.phase === RegistrationEventPhase.STEP_11_COMPLETED &&
            event.status === 'succeeded'
          ) {
            endSdkFlow('register', seq, 'success');
          } else if (
            event.phase === RegistrationEventPhase.FAILED ||
            event.phase === RegistrationEventPhase.CANCELLED ||
            event.status === 'failed' ||
            event.status === 'cancelled'
          ) {
            const error = event.error?.message || event.message;
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

      return await seams.registration.registerPasskey(nearAccountId, wrappedOptions);
    };

    const registerWalletWithSdkFlow: RegisterWalletFn = async (registerWalletArgs) => {
      const nearAccountId =
        registerWalletArgs.signerSelection.mode === 'ed25519_only' ||
        registerWalletArgs.signerSelection.mode === 'ed25519_and_ecdsa'
          ? registerWalletArgs.signerSelection.ed25519.nearAccountId
          : undefined;
      const seq = beginSdkFlow('register', nearAccountId);
      const options = registerWalletArgs.options;
      const wrappedOptions: RegistrationHooksOptions = {
        ...options,
        onEvent: (event: RegistrationFlowEvent) => {
          appendSdkEventMessage(seq, event.message);
          if (
            event.phase === RegistrationEventPhase.STEP_11_COMPLETED &&
            event.status === 'succeeded'
          ) {
            endSdkFlow('register', seq, 'success');
          } else if (
            event.phase === RegistrationEventPhase.FAILED ||
            event.phase === RegistrationEventPhase.CANCELLED ||
            event.status === 'failed' ||
            event.status === 'cancelled'
          ) {
            const error = event.error?.message || event.message;
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

      return await seams.registration.registerWallet({
        ...registerWalletArgs,
        options: wrappedOptions,
      });
    };
    const registerWithEmailOtpWithSdkFlow: RegisterWithEmailOtpFn = async (registerWalletArgs) =>
      await registerWalletWithSdkFlow(registerWalletArgs);

    const addWalletSignerWithSdkFlow: AddWalletSignerFn = async (addSignerArgs) => {
      const walletId = String(addSignerArgs.walletId || '').trim();
      const seq = beginSdkFlow('register', walletId || undefined);
      const options = addSignerArgs.options;
      const wrappedOptions: RegistrationHooksOptions = {
        ...options,
        onEvent: (event: RegistrationFlowEvent) => {
          appendSdkEventMessage(seq, event.message);
          if (
            event.phase === RegistrationEventPhase.STEP_11_COMPLETED &&
            event.status === 'succeeded'
          ) {
            endSdkFlow('register', seq, 'success');
          } else if (
            event.phase === RegistrationEventPhase.FAILED ||
            event.phase === RegistrationEventPhase.CANCELLED ||
            event.status === 'failed' ||
            event.status === 'cancelled'
          ) {
            const error = event.error?.message || event.message;
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

      return await seams.registration.addWalletSigner({
        ...addSignerArgs,
        options: wrappedOptions,
      });
    };

    const syncAccountWithSdkFlow: SyncAccountFn = async (args) => {
      const accountId = String(args?.accountId || '').trim();
      const seq = beginSdkFlow('sync', accountId || undefined);
      const wrappedOptions: SyncAccountHooksOptions = {
        ...args?.options,
        onEvent: (event: AccountSyncFlowEvent) => {
          appendSdkEventMessage(seq, event.message);
          if (
            event.phase === AccountSyncEventPhase.STEP_06_COMPLETED &&
            event.status === 'succeeded'
          ) {
            endSdkFlow('sync', seq, 'success');
          } else if (
            event.phase === AccountSyncEventPhase.FAILED ||
            event.phase === AccountSyncEventPhase.CANCELLED ||
            event.status === 'failed' ||
            event.status === 'cancelled'
          ) {
            const error = event.error?.message || event.message;
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

      return await seams.recovery.syncAccount({
        ...(args?.accountId ? { accountId: args.accountId } : {}),
        options: wrappedOptions,
      });
    };

    const setThemeWithHost: SetThemeFn = (next) => {
      try {
        hostSetTheme?.(next);
      } catch {}
      seams.setTheme(next);
    };

    return new Proxy(seams, {
      get(target, prop, receiver) {
        if (prop === 'auth') {
          const auth = Reflect.get(target as object, prop, receiver) as AuthCapability;
          return {
            ...auth,
            unlock: loginWithSdkFlow,
            lock: () => auth.lock(),
            getWalletSession: (...args: Parameters<AuthCapability['getWalletSession']>) =>
              auth.getWalletSession(...args),
            hasPasskeyCredential: (...args: Parameters<AuthCapability['hasPasskeyCredential']>) =>
              auth.hasPasskeyCredential(...args),
            getRecentUnlocks: (...args: Parameters<AuthCapability['getRecentUnlocks']>) =>
              auth.getRecentUnlocks(...args),
          } as AuthCapability;
        }

        if (prop === 'registration') {
          const registration = Reflect.get(
            target as object,
            prop,
            receiver,
          ) as RegistrationCapability;
          return {
            addWalletSigner: addWalletSignerWithSdkFlow,
            registerWallet: registerWalletWithSdkFlow,
            registerWithEmailOtp: registerWithEmailOtpWithSdkFlow,
            registerPasskey: registerPasskeyWithSdkFlow,
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
            finalizeEmailRecovery: (
              ...args: Parameters<RecoveryCapability['finalizeEmailRecovery']>
            ) => recovery.finalizeEmailRecovery(...args),
            cancelEmailRecovery: (...args: Parameters<RecoveryCapability['cancelEmailRecovery']>) =>
              recovery.cancelEmailRecovery(...args),
            acknowledgeEmailOtpRecoveryCodeBackup: (
              ...args: Parameters<RecoveryCapability['acknowledgeEmailOtpRecoveryCodeBackup']>
            ) => recovery.acknowledgeEmailOtpRecoveryCodeBackup(...args),
            getEmailOtpRecoveryCodeStatus: (
              ...args: Parameters<RecoveryCapability['getEmailOtpRecoveryCodeStatus']>
            ) => recovery.getEmailOtpRecoveryCodeStatus(...args),
          } satisfies RecoveryCapability;
        }

        if (prop === 'setTheme') {
          return setThemeWithHost;
        }

        const value: unknown = Reflect.get(target as object, prop, receiver);
        // For non-wrapped methods, bind to preserve `this` on the class instance.
        if (typeof value === 'function')
          return (value as (...args: unknown[]) => unknown).bind(target);
        return value;
      },
    });
  }, [appendSdkEventMessage, beginSdkFlow, endSdkFlow, hostSetTheme, seams]);
}

export default useSeamsWithSdkFlow;
