import { useCallback, useMemo } from 'react';
import type { Dispatch, SetStateAction } from 'react';
import { LoginPhase, LoginStatus } from '@/core/types/sdkSentEvents';
import type {
  AccountInputState,
  LoginState,
  RegistrationResult,
  TatchiContextType,
} from '../types';
import type { ThemeName } from '@/core/types/tatchi';
import type { RecoveryCapability } from '@/core/TatchiPasskey';
import { useSDKFlowRuntime } from './useSDKFlowRuntime';
import { useTatchiWithSdkFlow } from './useTatchiWithSdkFlow';
import { isWalletSessionReadyForUi } from './walletSessionReadiness';

export function useTatchiContextValue(args: {
  tatchi: TatchiContextType['tatchi'];
  loginState: LoginState;
  setLoginState: Dispatch<SetStateAction<LoginState>>;
  walletIframeConnected: boolean;
  refreshLoginState: TatchiContextType['refreshLoginState'];
  accountInputState: AccountInputState;
  setInputUsername: TatchiContextType['setInputUsername'];
  refreshAccountData: TatchiContextType['refreshAccountData'];
  hostSetTheme?: (theme: ThemeName) => void;
}): TatchiContextType {
  const {
    tatchi,
    loginState,
    setLoginState,
    walletIframeConnected,
    refreshLoginState,
    accountInputState,
    setInputUsername,
    refreshAccountData,
    hostSetTheme,
  } = args;

  const { sdkFlow, beginSdkFlow, appendSdkEventMessage, endSdkFlow } = useSDKFlowRuntime();
  const tatchiWithSdkFlow = useTatchiWithSdkFlow({
    tatchi,
    beginSdkFlow,
    appendSdkEventMessage,
    endSdkFlow,
    hostSetTheme,
  });

  const lock: TatchiContextType['lock'] = useCallback(() => {
    try {
      void tatchi.auth.lock().catch((error) => {
        console.warn('Wallet lock warning:', error);
      });
    } catch (error) {
      console.warn('Wallet lock warning:', error);
    }

    setLoginState((prevState) => ({
      ...prevState,
      isLoggedIn: false,
      nearAccountId: null,
      nearPublicKey: null,
      thresholdEcdsaEthereumAddress: null,
      thresholdEcdsaGroupPublicKeyB64u: null,
    }));
  }, [setLoginState, tatchi]);

  const startDevice2LinkingFlow: TatchiContextType['startDevice2LinkingFlow'] = useCallback(
    async (args) => {
      const request: Parameters<RecoveryCapability['startDevice2LinkingFlow']>[0] = args ?? {};
      return await tatchiWithSdkFlow.recovery.startDevice2LinkingFlow(request);
    },
    [tatchiWithSdkFlow],
  );

  const stopDevice2LinkingFlow: TatchiContextType['stopDevice2LinkingFlow'] =
    useCallback(async () => {
      await tatchi.recovery.stopDevice2LinkingFlow();
    }, [tatchi]);

  const unlock: TatchiContextType['unlock'] = useCallback(
    async (nearAccountId, options) => {
      return tatchiWithSdkFlow.auth.unlock(nearAccountId, {
        ...options,
        onEvent: async (event) => {
          if (
            event.phase === LoginPhase.STEP_4_LOGIN_COMPLETE &&
            event.status === LoginStatus.SUCCESS
          ) {
            const session = await tatchi.auth.getWalletSession(nearAccountId);
            const { login } = session;
            const isLoggedIn = isWalletSessionReadyForUi({
              session,
              signerMode: tatchi.configs?.signing.mode,
            });
            setLoginState((prevState) => ({
              ...prevState,
              isLoggedIn,
              nearAccountId: isLoggedIn ? login.nearAccountId || null : null,
              nearPublicKey: isLoggedIn ? login.publicKey || null : null,
              thresholdEcdsaEthereumAddress: isLoggedIn
                ? login.thresholdEcdsaEthereumAddress || null
                : null,
              thresholdEcdsaGroupPublicKeyB64u: isLoggedIn
                ? login.thresholdEcdsaGroupPublicKeyB64u || null
                : null,
            }));
          }
          return options?.onEvent?.(event);
        },
        onError: (error) => {
          lock();
          return options?.onError?.(error);
        },
      });
    },
    [lock, setLoginState, tatchi, tatchiWithSdkFlow],
  );

  const registerPasskey: TatchiContextType['registerPasskey'] = useCallback(
    async (nearAccountId, options) => {
      const result: RegistrationResult = await tatchiWithSdkFlow.registration.registerPasskey(
        nearAccountId,
        {
          ...options,
          onError: (error) => {
            lock();
            return options?.onError?.(error);
          },
        },
      );

      if (result?.success) {
        await refreshLoginState(nearAccountId);
      }
      return result;
    },
    [lock, refreshLoginState, tatchiWithSdkFlow],
  );

  const executeAction: TatchiContextType['executeAction'] = useCallback(
    (args) => {
      return tatchi.near.executeAction({ ...args, options: { ...(args.options || {}) } });
    },
    [tatchi],
  );

  const signNEP413Message: TatchiContextType['signNEP413Message'] = useCallback(
    (args) => {
      return tatchi.near.signNEP413Message({ ...args, options: { ...(args.options || {}) } });
    },
    [tatchi],
  );

  const signDelegateAction: TatchiContextType['signDelegateAction'] = useCallback(
    (args) => {
      return tatchi.near.signDelegateAction({ ...args, options: { ...(args.options || {}) } });
    },
    [tatchi],
  );

  const getWalletSession: TatchiContextType['getWalletSession'] = useCallback(
    (nearAccountId?: string) => {
      return tatchi.auth.getWalletSession(nearAccountId);
    },
    [tatchi],
  );

  const setConfirmBehavior: TatchiContextType['setConfirmBehavior'] = useCallback(
    (behavior) => {
      tatchi.setConfirmBehavior(behavior);
    },
    [tatchi],
  );

  const setConfirmationConfig: TatchiContextType['setConfirmationConfig'] = useCallback(
    (config) => {
      tatchi.setConfirmationConfig(config);
    },
    [tatchi],
  );

  const getConfirmationConfig: TatchiContextType['getConfirmationConfig'] = useCallback(() => {
    return tatchi.getConfirmationConfig();
  }, [tatchi]);

  const viewAccessKeyList: TatchiContextType['viewAccessKeyList'] = useCallback(
    (accountId: string) => {
      return tatchi.viewAccessKeyList(accountId);
    },
    [tatchi],
  );

  return useMemo(
    () => ({
      tatchi: tatchiWithSdkFlow,
      sdkFlow,
      registerPasskey,
      unlock,
      lock,
      startDevice2LinkingFlow,
      stopDevice2LinkingFlow,
      executeAction,
      signNEP413Message,
      signDelegateAction,
      getWalletSession,
      refreshLoginState,
      loginState,
      walletIframeConnected,
      accountInputState,
      setInputUsername,
      refreshAccountData,
      setConfirmBehavior,
      setConfirmationConfig,
      getConfirmationConfig,
      viewAccessKeyList,
      themeCapabilities: {
        canSetHostTheme: typeof hostSetTheme === 'function',
      },
    }),
    [
      tatchiWithSdkFlow,
      sdkFlow,
      registerPasskey,
      unlock,
      lock,
      startDevice2LinkingFlow,
      stopDevice2LinkingFlow,
      executeAction,
      signNEP413Message,
      signDelegateAction,
      getWalletSession,
      refreshLoginState,
      loginState,
      walletIframeConnected,
      accountInputState,
      setInputUsername,
      refreshAccountData,
      setConfirmBehavior,
      setConfirmationConfig,
      getConfirmationConfig,
      viewAccessKeyList,
      hostSetTheme,
    ],
  );
}
