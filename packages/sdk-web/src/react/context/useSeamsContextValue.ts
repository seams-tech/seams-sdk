import { useCallback, useMemo } from 'react';
import type { Dispatch, SetStateAction } from 'react';
import { UnlockEventPhase } from '@/core/types/sdkSentEvents';
import type { AccountInputState, LoginState, RegistrationResult, SeamsContextType } from '../types';
import type { ThemeMode } from '@/core/types/seams';
import type { DevicesCapability } from '@/SeamsWeb';
import { buildNoCurrentWalletAuthMethod } from '@shared/utils/walletCapabilityBindings';
import { useSDKFlowRuntime } from './useSDKFlowRuntime';
import { useSeamsWithSdkFlow } from './useSeamsWithSdkFlow';

/**
 * Refactor 94C. The registration response is authoritative for wallet
 * identity, so React marks the wallet logged in from it directly rather than
 * waiting for a round trip that would only restate what the response already
 * said. Measured: the two refreshes below ran serially after registration
 * returned and were excluded from the timing summary, so they were invisible
 * perceived latency.
 */
function hydrateLoginStateFromRegistrationResult(args: {
  result: RegistrationResult;
  setLoginState: Dispatch<SetStateAction<LoginState>>;
}): void {
  const result = args.result;
  if (!result.success) return;
  const walletId = String(result.walletId || '').trim();
  if (!walletId) return;
  const nearCapability = result.capabilities.find((capability) => capability.kind === 'near_ed25519');
  const ecdsaCapability = result.capabilities.find(
    (capability) => capability.kind === 'evm_family_ecdsa',
  );
  args.setLoginState((previous) => ({
    ...previous,
    isLoggedIn: true,
    walletId,
    /* NEAR identity is absent on the ECDSA-ready result and arrives with the
       background refresh once deferred provisioning settles; never invent it. */
    nearPublicKey: nearCapability?.operationalPublicKey ?? previous.nearPublicKey ?? null,
    nearAccountId: nearCapability
      ? String(nearCapability.nearAccountId)
      : (previous.nearAccountId ?? null),
    authMethods: previous.authMethods,
    currentAuthMethod: previous.currentAuthMethod,
    thresholdEcdsaEthereumAddress:
      ecdsaCapability?.thresholdEcdsaEthereumAddress ??
      previous.thresholdEcdsaEthereumAddress ??
      null,
    thresholdEcdsaPublicKeyB64u:
      ecdsaCapability?.thresholdEcdsaPublicKeyB64u ??
      previous.thresholdEcdsaPublicKeyB64u ??
      null,
  }));
}

/**
 * Runs both refreshes concurrently and is never awaited by registration: the
 * wallet is already usable from the hydrated response, and these only reconcile
 * auth-method bindings and account data. Failure leaves the hydrated state.
 */
function refreshReactStateAfterRegistration(args: {
  walletId: string;
  refreshLoginState: SeamsContextType['refreshLoginState'];
  refreshAccountData: SeamsContextType['refreshAccountData'];
}): void {
  console.info('[Registration] progress', {
    stage: 'react_context_background_refresh_started',
    walletId: args.walletId,
  });
  void Promise.all([
    args.refreshLoginState(args.walletId),
    args.refreshAccountData(),
  ]).then(
    () => {
      console.info('[Registration] progress', {
        stage: 'react_context_background_refresh_completed',
        walletId: args.walletId,
      });
    },
    (error: unknown) => {
      console.warn('[Registration] background React state refresh failed:', error);
    },
  );
}

export function useSeamsContextValue(args: {
  seams: SeamsContextType['seams'];
  loginState: LoginState;
  setLoginState: Dispatch<SetStateAction<LoginState>>;
  walletIframeConnected: boolean;
  refreshLoginState: SeamsContextType['refreshLoginState'];
  accountInputState: AccountInputState;
  setInputUsername: SeamsContextType['setInputUsername'];
  refreshAccountData: SeamsContextType['refreshAccountData'];
  hostSetTheme?: (theme: ThemeMode) => void;
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
      walletId: null,
      nearAccountId: null,
      nearPublicKey: null,
      currentAuthMethod: buildNoCurrentWalletAuthMethod(),
      authMethods: [],
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
    async (walletId, options) => {
      return seamsWithSdkFlow.auth.unlock(walletId, {
        ...options,
        onEvent: async (event) => {
          if (event.phase === UnlockEventPhase.STEP_07_COMPLETED && event.status === 'succeeded') {
            await refreshLoginState(walletId);
            await refreshAccountData();
          }
          return options?.onEvent?.(event);
        },
        onError: (error) => {
          lock();
          return options?.onError?.(error);
        },
      });
    },
    [lock, refreshAccountData, refreshLoginState, seamsWithSdkFlow],
  );

  const registerPasskey: SeamsContextType['registerPasskey'] = useCallback(
    async (options) => {
      const result: RegistrationResult = await seamsWithSdkFlow.registration.registerPasskey({
        ...options,
        onError: (error) => {
          lock();
          return options?.onError?.(error);
        },
      });

      const walletId = result?.success ? String(result.walletId || '').trim() : '';
      if (result?.success && walletId) {
        console.info('[Registration] progress', {
          stage: 'react_context_register_passkey_returned',
          walletId,
        });
        hydrateLoginStateFromRegistrationResult({ result, setLoginState });
        refreshReactStateAfterRegistration({
          walletId,
          refreshLoginState,
          refreshAccountData,
        });
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
      const walletId = result?.success ? String(result.walletId || '') : '';
      if (result?.success && walletId) {
        console.info('[Registration] progress', {
          stage: 'react_context_register_wallet_returned',
          walletId,
        });
        hydrateLoginStateFromRegistrationResult({ result, setLoginState });
        refreshReactStateAfterRegistration({
          walletId,
          refreshLoginState,
          refreshAccountData,
        });
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
    (args) => {
      return seams.devices.viewAccessKeyList(args);
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
