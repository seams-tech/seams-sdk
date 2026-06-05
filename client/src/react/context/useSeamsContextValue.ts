import { useCallback, useMemo } from 'react';
import type { Dispatch, SetStateAction } from 'react';
import { UnlockEventPhase } from '@/core/types/sdkSentEvents';
import type {
  AccountInputState,
  LoginState,
  RegistrationResult,
  SeamsContextType,
} from '../types';
import type { ThemeName } from '@/core/types/seams';
import type { DevicesCapability } from '@/web/SeamsWeb';
import { useSDKFlowRuntime } from './useSDKFlowRuntime';
import { useSeamsWithSdkFlow } from './useSeamsWithSdkFlow';
import { isWalletSessionReadyForUi } from './walletSessionReadiness';

export function useSeamsContextValue(args: {
  seams: SeamsContextType['seams'];
  loginState: LoginState;
  setLoginState: Dispatch<SetStateAction<LoginState>>;
  walletIframeConnected: boolean;
  refreshLoginState: SeamsContextType['refreshLoginState'];
  accountInputState: AccountInputState;
  setInputUsername: SeamsContextType['setInputUsername'];
  refreshAccountData: SeamsContextType['refreshAccountData'];
  hostSetTheme?: (theme: ThemeName) => void;
}): SeamsContextType {
  const {
    seams,
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
  const seamsWithSdkFlow = useSeamsWithSdkFlow({
    seams,
    beginSdkFlow,
    appendSdkEventMessage,
    endSdkFlow,
    hostSetTheme,
  });

  const lock: SeamsContextType['lock'] = useCallback(() => {
    try {
      void seams.auth.lock().catch((error) => {
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
      thresholdEcdsaPublicKeyB64u: null,
    }));
  }, [setLoginState, seams]);

  const startDevice2LinkingFlow: SeamsContextType['startDevice2LinkingFlow'] = useCallback(
    async (args) => {
      const request: Parameters<DevicesCapability['startDevice2LinkingFlow']>[0] = args ?? {};
      return await seamsWithSdkFlow.devices.startDevice2LinkingFlow(request);
    },
    [seamsWithSdkFlow],
  );

  const stopDevice2LinkingFlow: SeamsContextType['stopDevice2LinkingFlow'] =
    useCallback(async () => {
      await seams.devices.stopDevice2LinkingFlow();
    }, [seams]);

  const unlock: SeamsContextType['unlock'] = useCallback(
    async (nearAccountId, options) => {
      return seamsWithSdkFlow.auth.unlock(nearAccountId, {
        ...options,
        onEvent: async (event) => {
          if (event.phase === UnlockEventPhase.STEP_07_COMPLETED && event.status === 'succeeded') {
            const session = await seams.auth.getWalletSession(nearAccountId);
            const { login } = session;
            const isLoggedIn = isWalletSessionReadyForUi({ session });
            setLoginState((prevState) => ({
              ...prevState,
              isLoggedIn,
              nearAccountId: isLoggedIn ? login.nearAccountId || null : null,
              nearPublicKey: isLoggedIn ? login.publicKey || null : null,
              authMethod: isLoggedIn ? session.authMethod || login.authMethod || null : null,
              thresholdEcdsaEthereumAddress: isLoggedIn
                ? login.thresholdEcdsaEthereumAddress || null
                : null,
              thresholdEcdsaPublicKeyB64u: isLoggedIn
                ? login.thresholdEcdsaPublicKeyB64u || null
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
    [lock, setLoginState, seams, seamsWithSdkFlow],
  );

  const registerPasskey: SeamsContextType['registerPasskey'] = useCallback(
    async (nearAccountId, options) => {
      const result: RegistrationResult = await seamsWithSdkFlow.registration.registerPasskey(
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
        await refreshAccountData();
      }
      return result;
    },
    [lock, refreshAccountData, refreshLoginState, seamsWithSdkFlow],
  );

  const registerWallet: SeamsContextType['registerWallet'] = useCallback(
    async (args) => {
      const result = await seamsWithSdkFlow.registration.registerWallet({
        ...args,
        options: {
          ...args.options,
          onError: (error) => {
            lock();
            return args.options?.onError?.(error);
          },
        },
      });
      const nearAccountId =
        args.signerSelection.mode === 'ed25519_only' ||
        args.signerSelection.mode === 'ed25519_and_ecdsa'
          ? args.signerSelection.ed25519.nearAccountId
          : '';
      if (result?.success && nearAccountId) {
        await refreshLoginState(nearAccountId);
        await refreshAccountData();
      }
      return result;
    },
    [lock, refreshAccountData, refreshLoginState, seamsWithSdkFlow],
  );

  const addWalletSigner: SeamsContextType['addWalletSigner'] = useCallback(
    async (args) => {
      return await seamsWithSdkFlow.registration.addWalletSigner(args);
    },
    [seamsWithSdkFlow],
  );

  const executeAction: SeamsContextType['executeAction'] = useCallback(
    (args) => {
      return seams.near.executeAction({ ...args, options: { ...(args.options || {}) } });
    },
    [seams],
  );

  const signNEP413Message: SeamsContextType['signNEP413Message'] = useCallback(
    (args) => {
      return seams.near.signNEP413Message({ ...args, options: { ...(args.options || {}) } });
    },
    [seams],
  );

  const signDelegateAction: SeamsContextType['signDelegateAction'] = useCallback(
    (args) => {
      return seams.near.signDelegateAction({ ...args, options: { ...(args.options || {}) } });
    },
    [seams],
  );

  const getWalletSession: SeamsContextType['getWalletSession'] = useCallback(
    (walletId?: string) => {
      return seams.auth.getWalletSession(walletId);
    },
    [seams],
  );

  const setConfirmBehavior: SeamsContextType['setConfirmBehavior'] = useCallback(
    (behavior) => {
      seams.preferences.setConfirmBehavior(behavior);
    },
    [seams],
  );

  const setConfirmationConfig: SeamsContextType['setConfirmationConfig'] = useCallback(
    (config) => {
      seams.preferences.setConfirmationConfig(config);
    },
    [seams],
  );

  const getConfirmationConfig: SeamsContextType['getConfirmationConfig'] = useCallback(() => {
    return seams.preferences.getConfirmationConfig();
  }, [seams]);

  const viewAccessKeyList: SeamsContextType['viewAccessKeyList'] = useCallback(
    (accountId: string) => {
      return seams.devices.viewAccessKeyList(accountId);
    },
    [seams],
  );

  return useMemo(
    () => ({
      seams: seamsWithSdkFlow,
      sdkFlow,
      addWalletSigner,
      registerWallet,
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
      seamsWithSdkFlow,
      sdkFlow,
      addWalletSigner,
      registerWallet,
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
