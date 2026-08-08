import { expect, test } from '@playwright/test';
import {
  resolveFrontendRuntimeTransition,
  resolveInitialFrontendNetwork,
} from '../../apps/seams-site/src/context/frontendRuntimeState';

const productionNetworks = ['testnet', 'mainnet'] as const;

test('persisted production mainnet is the initial dashboard network without a boot reload', () => {
  const initialNetwork = resolveInitialFrontendNetwork({
    availableNetworks: productionNetworks,
    defaultNetwork: 'testnet',
    storedValue: ' mainnet ',
  });

  expect(initialNetwork).toBe('mainnet');
  expect(
    resolveFrontendRuntimeTransition({
      currentActiveNetwork: initialNetwork,
      requestedNetwork: initialNetwork,
      persistedNetwork: initialNetwork,
      source: 'console',
    }),
  ).toEqual({
    activeNetwork: 'mainnet',
    persistedNetwork: 'mainnet',
    reload: false,
  });
});

test('a console network change persists and reloads once', () => {
  const changed = resolveFrontendRuntimeTransition({
    currentActiveNetwork: 'testnet',
    requestedNetwork: 'mainnet',
    persistedNetwork: 'testnet',
    source: 'console',
  });

  expect(changed).toEqual({
    activeNetwork: 'mainnet',
    persistedNetwork: 'mainnet',
    reload: true,
  });

  expect(
    resolveFrontendRuntimeTransition({
      currentActiveNetwork: changed.activeNetwork,
      requestedNetwork: changed.activeNetwork,
      persistedNetwork: changed.persistedNetwork,
      source: 'console',
    }).reload,
  ).toBe(false);
});

test('public testnet activation leaves the persisted console preference unchanged', () => {
  expect(
    resolveFrontendRuntimeTransition({
      currentActiveNetwork: 'mainnet',
      requestedNetwork: 'testnet',
      persistedNetwork: 'mainnet',
      source: 'public',
    }),
  ).toEqual({
    activeNetwork: 'testnet',
    persistedNetwork: 'mainnet',
    reload: false,
  });
});
