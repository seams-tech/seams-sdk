import React from 'react';

// Console-owned runtime state. This replaces the seams-site frontendRuntime
// for the extracted Console application: deployment endpoints and network
// selection only — no SeamsWebProvider, no Wallet SDK configuration.

export type ConsoleNetwork = 'testnet' | 'mainnet';

export type ConsoleDeployment = {
  readonly network: ConsoleNetwork;
  readonly consoleBaseUrl: string;
  readonly relayerUrl: string;
  readonly walletOrigin: string;
};

const NETWORK_STORAGE_KEY = 'seams.production.console.network.v1';

function trimmedEnv(value: unknown): string {
  return String(value ?? '').trim();
}

function windowOrigin(): string {
  return typeof window === 'undefined' ? '' : window.location.origin;
}

function deploymentFor(network: ConsoleNetwork): ConsoleDeployment {
  const env = import.meta.env;
  const prefix = network === 'mainnet' ? 'MAINNET_' : 'TESTNET_';
  const relayerUrl =
    trimmedEnv(env[`VITE_${prefix}RELAYER_URL`]) || trimmedEnv(env.VITE_RELAYER_URL) || windowOrigin();
  const consoleBaseUrl =
    trimmedEnv(env[`VITE_${prefix}CONSOLE_BASE_URL`]) ||
    trimmedEnv(env.VITE_CONSOLE_BASE_URL) ||
    relayerUrl;
  const walletOrigin =
    trimmedEnv(env[`VITE_${prefix}WALLET_ORIGIN`]) || trimmedEnv(env.VITE_WALLET_ORIGIN) || relayerUrl;
  return { network, consoleBaseUrl, relayerUrl, walletOrigin };
}

function availableNetworks(): readonly ConsoleNetwork[] {
  const env = import.meta.env;
  return trimmedEnv(env.VITE_MAINNET_CONSOLE_BASE_URL) || trimmedEnv(env.VITE_MAINNET_RELAYER_URL)
    ? (['testnet', 'mainnet'] as const)
    : (['testnet'] as const);
}

function readStoredNetwork(): ConsoleNetwork {
  if (typeof window === 'undefined') return 'testnet';
  let value = '';
  try {
    value = String(window.localStorage.getItem(NETWORK_STORAGE_KEY) || '').trim();
  } catch {}
  const networks = availableNetworks();
  return networks.includes(value as ConsoleNetwork) ? (value as ConsoleNetwork) : 'testnet';
}

let activeDeployment: ConsoleDeployment = deploymentFor(readStoredNetwork());

export function getActiveFrontendDeployment(): ConsoleDeployment {
  return activeDeployment;
}

export type ConsoleRuntimeState = {
  readonly selectedNetwork: ConsoleNetwork;
  readonly deployment: ConsoleDeployment;
  readonly availableNetworks: readonly ConsoleNetwork[];
  readonly selectNetwork: (network: ConsoleNetwork) => void;
};

const listeners = new Set<() => void>();

function selectNetwork(network: ConsoleNetwork): void {
  if (!availableNetworks().includes(network)) return;
  activeDeployment = deploymentFor(network);
  try {
    window.localStorage.setItem(NETWORK_STORAGE_KEY, network);
  } catch {}
  for (const listener of listeners) listener();
}

export function useFrontendRuntime(): ConsoleRuntimeState {
  const [, forceRender] = React.useReducer((count: number) => count + 1, 0);
  React.useEffect(() => {
    listeners.add(forceRender);
    return () => {
      listeners.delete(forceRender);
    };
  }, []);
  return {
    selectedNetwork: activeDeployment.network,
    deployment: activeDeployment,
    availableNetworks: availableNetworks(),
    selectNetwork,
  };
}
