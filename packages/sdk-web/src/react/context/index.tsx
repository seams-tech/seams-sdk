import { createContext, useContext, useEffect, useMemo, useState } from 'react';
import { useNearClient } from '../hooks/useNearClient';
import { useAccountInput } from '../hooks/useAccountInput';
import { useEagerPrewarm } from './useEagerPrewarm';
import { useLoginStateRefresher } from './useLoginStateRefresher';
import { useSeamsContextValue } from './useSeamsContextValue';
import { useWalletIframeLifecycle } from './useWalletIframeLifecycle';
import { getOrCreateSeamsManager } from './seamsManagerSingleton';
import { buildNoCurrentWalletAuthMethod } from '@shared/utils/walletCapabilityBindings';
import type {
  SeamsContextType,
  SeamsContextProviderProps,
  LoginState,
  AccountInputState,
} from '../types';

const SeamsContext = createContext<SeamsContextType | undefined>(undefined);

export const SeamsContextProvider: React.FC<SeamsContextProviderProps> = ({
  children,
  config,
  theme,
  eager,
}) => {
  const [loginState, setLoginState] = useState<LoginState>({
    isLoggedIn: false,
    walletId: null,
    nearAccountId: null,
    nearPublicKey: null,
    currentAuthMethod: buildNoCurrentWalletAuthMethod(),
    authMethods: [],
    thresholdEcdsaEthereumAddress: null,
    thresholdEcdsaPublicKeyB64u: null,
  });
  const [walletIframeConnected, setWalletIframeConnected] = useState<boolean>(false);

  const nearClient = useNearClient();
  const seams = useMemo(() => getOrCreateSeamsManager(config, nearClient), [config, nearClient]);

  useEagerPrewarm(seams, eager);

  useWalletIframeLifecycle({
    seams,
    setWalletIframeConnected,
    setLoginState,
  });

  const hasExplicitAccountDomainOverride = Boolean(
    typeof config?.relayerAccount === 'string' && String(config.relayerAccount).trim(),
  );

  const accountInputHook = useAccountInput({
    seams,
    // If the host app didn't explicitly provide a relayer account id/domain, allow the hook to
    // best-effort discover it from the relay `/healthz` endpoint (prevents postfix mismatches).
    ...(hasExplicitAccountDomainOverride
      ? { accountDomain: seams.configs.network.relayer.accountId }
      : {}),
    currentWalletId: loginState.walletId,
    isLoggedIn: loginState.isLoggedIn,
  });

  const {
    inputUsername,
    lastLoggedInUsername,
    lastLoggedInDomain,
    targetAccountId,
    displayPostfix,
    isUsingExistingAccount,
    accountExists,
    indexDBAccounts,
    indexDBAccountOptions,
    setInputUsername,
    refreshAccountData,
  } = accountInputHook;

  const accountInputState: AccountInputState = useMemo(
    () => ({
      inputUsername,
      lastLoggedInUsername,
      lastLoggedInDomain,
      targetAccountId,
      displayPostfix,
      isUsingExistingAccount,
      accountExists,
      indexDBAccounts,
      indexDBAccountOptions,
    }),
    [
      inputUsername,
      lastLoggedInUsername,
      lastLoggedInDomain,
      targetAccountId,
      displayPostfix,
      isUsingExistingAccount,
      accountExists,
      indexDBAccounts,
      indexDBAccountOptions,
    ],
  );

  const refreshLoginState = useLoginStateRefresher({
    seams,
    walletIframeConnected,
    setLoginState,
    setInputUsername,
  });

  useEffect(() => {
    if (!theme?.theme) return;
    seams.setTheme(theme.theme);
  }, [seams, theme?.theme]);

  const value = useSeamsContextValue({
    seams,
    loginState,
    setLoginState,
    walletIframeConnected,
    refreshLoginState,
    accountInputState,
    setInputUsername,
    refreshAccountData,
    hostSetTheme: theme?.setTheme,
  });

  return <SeamsContext.Provider value={value}>{children}</SeamsContext.Provider>;
};

export const useSeams = () => {
  const context = useContext(SeamsContext);
  if (context === undefined) {
    throw new Error('useSeams must be used within a SeamsContextProvider');
  }
  return context;
};

// Re-export types for convenience
export type { SeamsContextType, RegistrationResult, LoginResult } from '../types';
