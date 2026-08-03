import { expect, test } from '@playwright/test';
import {
  CAPABILITY_KINDS,
  EVM_ECDSA_MPC_OPERATION_KINDS,
  NEAR_ED25519_MPC_OPERATION_KINDS,
  VAULT_OPERATION_KINDS,
} from '@shared/authorization/capabilityKinds';
import { PASSKEY_MANAGER_DEFAULT_CONFIGS } from '@/core/config/defaultConfigs';
import type { SeamsConfigsReadonly } from '@/core/types/seams';
import { thresholdEcdsaChainTargetFromChainFamily } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  BrowserCapabilityUnavailableError,
  requireBrowserCapabilityOperation,
  selectBrowserCapabilityOperation,
} from '@/SeamsWeb/publicApi/capabilitySelection';

const CONFIGURED_EVM_TARGET = thresholdEcdsaChainTargetFromChainFamily({
  chain: 'evm',
  chainId: 5042002,
  networkSlug: 'arc-testnet',
});

const UNCONFIGURED_EVM_TARGET = thresholdEcdsaChainTargetFromChainFamily({
  chain: 'evm',
  chainId: 8453,
  networkSlug: 'base-mainnet',
});

const ENABLED_NEAR_CONFIGS: SeamsConfigsReadonly = {
  ...PASSKEY_MANAGER_DEFAULT_CONFIGS,
  signing: {
    ...PASSKEY_MANAGER_DEFAULT_CONFIGS.signing,
    routerAb: {
      normalSigning: {
        mode: 'enabled',
        signingWorkerId: 'near-signing-worker',
      },
    },
  },
};

test('browser capability selection gates NEAR signing while keeping export independent', () => {
  const signingRequest = {
    capabilityKind: CAPABILITY_KINDS.nearEd25519MpcSigning,
    operationKind: NEAR_ED25519_MPC_OPERATION_KINDS.signTransaction,
  } as const;
  const exportRequest = {
    capabilityKind: CAPABILITY_KINDS.nearEd25519MpcSigning,
    operationKind: NEAR_ED25519_MPC_OPERATION_KINDS.exportKey,
  } as const;

  expect(selectBrowserCapabilityOperation(PASSKEY_MANAGER_DEFAULT_CONFIGS, signingRequest)).toEqual(
    {
      kind: 'disabled',
      operation: signingRequest,
      reason: 'router_ab_normal_signing_disabled',
    },
  );
  expect(selectBrowserCapabilityOperation(ENABLED_NEAR_CONFIGS, signingRequest)).toEqual({
    kind: 'selected',
    operation: signingRequest,
  });
  expect(selectBrowserCapabilityOperation(PASSKEY_MANAGER_DEFAULT_CONFIGS, exportRequest)).toEqual({
    kind: 'selected',
    operation: exportRequest,
  });
});

test('browser capability selection requires an exact configured ECDSA target', () => {
  const operation = {
    capabilityKind: CAPABILITY_KINDS.evmEcdsaMpcSigning,
    operationKind: EVM_ECDSA_MPC_OPERATION_KINDS.signTransaction,
  } as const;

  expect(
    selectBrowserCapabilityOperation(PASSKEY_MANAGER_DEFAULT_CONFIGS, {
      ...operation,
      chainTarget: CONFIGURED_EVM_TARGET,
    }),
  ).toEqual({
    kind: 'selected',
    operation,
  });
  expect(
    selectBrowserCapabilityOperation(PASSKEY_MANAGER_DEFAULT_CONFIGS, {
      ...operation,
      chainTarget: UNCONFIGURED_EVM_TARGET,
    }),
  ).toEqual({
    kind: 'disabled',
    operation,
    reason: 'ecdsa_target_not_configured',
  });
});

test('browser capability selection reports undeployed vault operations', () => {
  const operation = {
    capabilityKind: CAPABILITY_KINDS.vaultAccess,
    operationKind: VAULT_OPERATION_KINDS.proxyUse,
  } as const;

  expect(selectBrowserCapabilityOperation(PASSKEY_MANAGER_DEFAULT_CONFIGS, operation)).toEqual({
    kind: 'disabled',
    operation,
    reason: 'capability_not_deployed',
  });
});

test('required browser capability selection throws the typed unavailable error', () => {
  const request = {
    capabilityKind: CAPABILITY_KINDS.nearEd25519MpcSigning,
    operationKind: NEAR_ED25519_MPC_OPERATION_KINDS.signNep413Message,
  } as const;

  expect(() => requireBrowserCapabilityOperation(PASSKEY_MANAGER_DEFAULT_CONFIGS, request)).toThrow(
    BrowserCapabilityUnavailableError,
  );
  try {
    requireBrowserCapabilityOperation(PASSKEY_MANAGER_DEFAULT_CONFIGS, request);
  } catch (error: unknown) {
    expect(error).toBeInstanceOf(BrowserCapabilityUnavailableError);
    if (!(error instanceof BrowserCapabilityUnavailableError)) return;
    expect(error.code).toBe('browser_capability_unavailable');
    expect(error.selection).toEqual({
      kind: 'disabled',
      operation: request,
      reason: 'router_ab_normal_signing_disabled',
    });
  }
});
