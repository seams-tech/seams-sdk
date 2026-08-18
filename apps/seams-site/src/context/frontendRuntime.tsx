import React from 'react';
import { SeamsWebProvider } from '@seams/wallet/react/provider';
import type { SeamsWebProviderProps } from '@seams/wallet/react/provider';
import type { SeamsConfigsInput } from '@seams/wallet/react';
import {
  FRONTEND_CONFIG,
  buildSeamsSdkConfig,
  getFrontendDeployment,
  type FrontendConfig,
  type FrontendDeployment,
  type FrontendNetwork,
} from '@/config';
import {
  resolveFrontendRuntimeTransition,
  resolveInitialFrontendNetwork,
} from './frontendRuntimeState';

const NETWORK_STORAGE_KEY = 'seams.production.console.network.v1';
const DASHBOARD_UI_STATE_KEY = 'seams-dashboard-ui-state-v1';
const DASHBOARD_UI_QUERY_KEYS = [
  'db_sb',
  'db_groups',
  'db_org',
  'db_project',
  'db_env',
  'db_acct',
] as const;

export type FrontendRuntimeState = {
  selectedNetwork: FrontendNetwork;
  deployment: FrontendDeployment;
  availableNetworks: FrontendConfig['availableNetworks'];
  selectNetwork: (network: FrontendNetwork) => void;
};

function readStoredNetwork(config: FrontendConfig): FrontendNetwork {
  if (typeof window === 'undefined') return config.defaultNetwork;
  let value = '';
  try {
    value = String(window.localStorage.getItem(NETWORK_STORAGE_KEY) || '').trim();
  } catch {}
  return resolveInitialFrontendNetwork({
    availableNetworks: config.availableNetworks,
    defaultNetwork: config.defaultNetwork,
    storedValue: value,
  });
}

const initialNetwork = readStoredNetwork(FRONTEND_CONFIG);
const defaultDeployment = getFrontendDeployment(FRONTEND_CONFIG, initialNetwork);
let activeDeployment = defaultDeployment;

function clearNetworkScopedBrowserState(): void {
  if (typeof window === 'undefined') return;
  try {
    window.localStorage.removeItem(DASHBOARD_UI_STATE_KEY);
  } catch {}
  const params = new URLSearchParams(window.location.search);
  let changed = false;
  for (const key of DASHBOARD_UI_QUERY_KEYS) {
    if (!params.has(key)) continue;
    params.delete(key);
    changed = true;
  }
  if (changed) {
    const search = params.toString();
    window.history.replaceState(
      {},
      '',
      `${window.location.pathname}${search ? `?${search}` : ''}${window.location.hash}`,
    );
  }
}

export function getActiveFrontendDeployment(): FrontendDeployment {
  return activeDeployment;
}

export function activateFrontendNetwork(network: FrontendNetwork): FrontendDeployment {
  const nextDeployment = getFrontendDeployment(FRONTEND_CONFIG, network);
  activeDeployment = nextDeployment;
  return nextDeployment;
}

export function setActiveFrontendNetwork(network: FrontendNetwork): FrontendDeployment {
  const previousNetwork = activeDeployment.network;
  const transition = resolveFrontendRuntimeTransition({
    currentActiveNetwork: previousNetwork,
    requestedNetwork: network,
    persistedNetwork: previousNetwork,
    source: 'console',
  });
  const nextDeployment = activateFrontendNetwork(network);
  if (previousNetwork === nextDeployment.network) return nextDeployment;
  clearNetworkScopedBrowserState();
  if (typeof window !== 'undefined') {
    try {
      window.localStorage.setItem(NETWORK_STORAGE_KEY, transition.persistedNetwork);
    } catch {}
  }
  return nextDeployment;
}

const FrontendRuntimeContext = React.createContext<FrontendRuntimeState>({
  selectedNetwork: initialNetwork,
  deployment: defaultDeployment,
  availableNetworks: FRONTEND_CONFIG.availableNetworks,
  selectNetwork: setActiveFrontendNetwork,
});

export function FrontendRuntimeProvider({
  children,
}: {
  children: React.ReactNode;
}): React.JSX.Element {
  const [selectedNetwork, setSelectedNetwork] = React.useState<FrontendNetwork>(initialNetwork);

  const selectNetwork = React.useCallback((network: FrontendNetwork) => {
    const nextDeployment = setActiveFrontendNetwork(network);
    setSelectedNetwork(nextDeployment.network);
  }, []);

  const deployment = getFrontendDeployment(FRONTEND_CONFIG, selectedNetwork);
  const value = React.useMemo<FrontendRuntimeState>(
    () => ({
      selectedNetwork,
      deployment,
      availableNetworks: FRONTEND_CONFIG.availableNetworks,
      selectNetwork,
    }),
    [deployment, selectNetwork, selectedNetwork],
  );

  return (
    <FrontendRuntimeContext.Provider value={value}>{children}</FrontendRuntimeContext.Provider>
  );
}

export function useFrontendRuntime(): FrontendRuntimeState {
  return React.useContext(FrontendRuntimeContext);
}

type FrontendSdkProviderProps = {
  children: React.ReactNode;
  network?: FrontendNetwork;
  theme?: SeamsWebProviderProps['theme'];
  eager?: boolean;
  appearance?: SeamsConfigsInput['appearance'];
};

export function FrontendSdkProvider({
  children,
  network,
  theme,
  eager,
  appearance,
}: FrontendSdkProviderProps): React.JSX.Element {
  const runtime = useFrontendRuntime();
  const activeNetwork = network || runtime.selectedNetwork;
  const deployment = getFrontendDeployment(FRONTEND_CONFIG, activeNetwork);
  activateFrontendNetwork(deployment.network);
  const sdkConfig = React.useMemo(
    () => ({
      ...buildSeamsSdkConfig(deployment),
      ...(appearance ? { appearance } : {}),
    }),
    [appearance, deployment],
  );
  return (
    <SeamsWebProvider eager={eager} theme={theme} config={sdkConfig}>
      {children}
    </SeamsWebProvider>
  );
}
