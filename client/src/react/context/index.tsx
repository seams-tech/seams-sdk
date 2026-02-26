import {
  createContext,
  useContext,
  useEffect,
  useMemo,
  useState,
} from 'react';
import { useNearClient } from '../hooks/useNearClient';
import { useAccountInput } from '../hooks/useAccountInput';
import { useEagerPrewarm } from './useEagerPrewarm';
import { useLoginStateRefresher } from './useLoginStateRefresher';
import { useTatchiContextValue } from './useTatchiContextValue';
import { useWalletIframeLifecycle } from './useWalletIframeLifecycle';
import { getOrCreateTatchiManager } from './tatchiManagerSingleton';
import type {
  TatchiContextType,
  TatchiContextProviderProps,
  LoginState,
  AccountInputState,
} from '../types';

const TatchiContext = createContext<TatchiContextType | undefined>(undefined);

export const TatchiContextProvider: React.FC<TatchiContextProviderProps> = ({
  children,
  config,
  theme,
  eager,
}) => {
  const [loginState, setLoginState] = useState<LoginState>({
    isLoggedIn: false,
    nearAccountId: null,
    nearPublicKey: null,
    thresholdEcdsaEthereumAddress: null,
    thresholdEcdsaGroupPublicKeyB64u: null,
  });
  const [walletIframeConnected, setWalletIframeConnected] = useState<boolean>(false);

  const nearClient = useNearClient();
  const tatchi = useMemo(() => getOrCreateTatchiManager(config, nearClient), [config, nearClient]);

  useEagerPrewarm(tatchi, eager);

  useWalletIframeLifecycle({
    tatchi,
    setWalletIframeConnected,
    setLoginState,
  });

  const hasExplicitAccountDomainOverride = Boolean(
    (typeof config?.relayerAccount === 'string' && String(config.relayerAccount).trim())
  );

  const accountInputHook = useAccountInput({
    tatchi,
    // If the host app didn't explicitly provide a relayer account id/domain, allow the hook to
    // best-effort discover it from the relay `/healthz` endpoint (prevents postfix mismatches).
    ...(hasExplicitAccountDomainOverride ? { accountDomain: tatchi.configs.relayerAccount } : {}),
    currentNearAccountId: loginState.nearAccountId,
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
    setInputUsername,
    refreshAccountData,
  } = accountInputHook;

  const accountInputState: AccountInputState = useMemo(() => ({
    inputUsername,
    lastLoggedInUsername,
    lastLoggedInDomain,
    targetAccountId,
    displayPostfix,
    isUsingExistingAccount,
    accountExists,
    indexDBAccounts,
  }), [
    inputUsername,
    lastLoggedInUsername,
    lastLoggedInDomain,
    targetAccountId,
    displayPostfix,
    isUsingExistingAccount,
    accountExists,
    indexDBAccounts,
  ]);

  const refreshLoginState = useLoginStateRefresher({
    tatchi,
    walletIframeConnected,
    setLoginState,
  });

  useEffect(() => {
    if (!theme?.theme) return;
    tatchi.setTheme(theme.theme);
  }, [tatchi, theme?.theme]);

  const value = useTatchiContextValue({
    tatchi,
    loginState,
    setLoginState,
    walletIframeConnected,
    refreshLoginState,
    accountInputState,
    setInputUsername,
    refreshAccountData,
    hostSetTheme: theme?.setTheme,
  });

  return <TatchiContext.Provider value={value}>{children}</TatchiContext.Provider>;
};

export const useTatchi = () => {
  const context = useContext(TatchiContext);
  if (context === undefined) {
    throw new Error('useTatchi must be used within a TatchiContextProvider');
  }
  return context;
};

// Re-export types for convenience
export type {
  TatchiContextType,
  RegistrationResult,
  LoginResult,
} from '../types';
