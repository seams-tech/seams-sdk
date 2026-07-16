import { createContext, useContext, useEffect, useMemo, useRef, useState } from 'react';
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
    // best-effort discover it from the Router API `/healthz` endpoint (prevents postfix mismatches).
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
    targetWalletId,
    displayPostfix,
    isUsingExistingAccount,
    accountExists,
    passkeyCredentialExists,
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
      targetWalletId,
      displayPostfix,
      isUsingExistingAccount,
      accountExists,
      passkeyCredentialExists,
      indexDBAccounts,
      indexDBAccountOptions,
    }),
    [
      inputUsername,
      lastLoggedInUsername,
      lastLoggedInDomain,
      targetAccountId,
      targetWalletId,
      displayPostfix,
      isUsingExistingAccount,
      accountExists,
      passkeyCredentialExists,
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

  /* This effect is a sync channel for the provider's own theme input, not an
     override channel. Parent effects run after child effects, so a redundant
     push here would clobber `seams.setAppearance` calls children make during
     mount (e.g. a demo theme switcher) — the manager was already constructed
     with `config.appearance`, so skip until the provider's input diverges from
     what the manager already has. */
  const lastAppearancePushKeyRef = useRef<string | null>(null);
  useEffect(() => {
    const nextAppearance = theme?.appearance
      ? theme.appearance
      : theme?.theme
        ? {
            theme: {
              id: 'react-provider',
              mode: theme.theme,
              colors: {},
            },
          }
        : null;
    if (!nextAppearance) return;
    const key = JSON.stringify(nextAppearance);
    if (lastAppearancePushKeyRef.current === key) return;
    if (
      lastAppearancePushKeyRef.current === null &&
      theme?.appearance &&
      key === JSON.stringify(config.appearance ?? null)
    ) {
      lastAppearancePushKeyRef.current = key;
      return;
    }
    lastAppearancePushKeyRef.current = key;
    seams.setAppearance(nextAppearance);
  }, [seams, config.appearance, theme?.appearance, theme?.theme]);

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
