export type FrontendNetwork = 'testnet' | 'mainnet';

export type FrontendRuntimeTransition = {
  activeNetwork: FrontendNetwork;
  persistedNetwork: FrontendNetwork;
  reload: boolean;
};

type FrontendRuntimeTransitionInput = {
  currentActiveNetwork: FrontendNetwork;
  requestedNetwork: FrontendNetwork;
  persistedNetwork: FrontendNetwork;
  source: 'console' | 'public';
};

type InitialFrontendNetworkInput = {
  availableNetworks: readonly FrontendNetwork[];
  defaultNetwork: FrontendNetwork;
  storedValue: string;
};

function isFrontendNetwork(value: string): value is FrontendNetwork {
  return value === 'testnet' || value === 'mainnet';
}

export function resolveInitialFrontendNetwork({
  availableNetworks,
  defaultNetwork,
  storedValue,
}: InitialFrontendNetworkInput): FrontendNetwork {
  const normalizedValue = storedValue.trim();
  return isFrontendNetwork(normalizedValue) && availableNetworks.includes(normalizedValue)
    ? normalizedValue
    : defaultNetwork;
}

export function resolveFrontendRuntimeTransition({
  currentActiveNetwork,
  requestedNetwork,
  persistedNetwork,
  source,
}: FrontendRuntimeTransitionInput): FrontendRuntimeTransition {
  if (source === 'public') {
    return {
      activeNetwork: requestedNetwork,
      persistedNetwork,
      reload: false,
    };
  }

  const changed = currentActiveNetwork !== requestedNetwork;
  return {
    activeNetwork: requestedNetwork,
    persistedNetwork: changed ? requestedNetwork : persistedNetwork,
    reload: changed,
  };
}
