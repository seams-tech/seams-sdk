import {
  CAPABILITY_KINDS,
  EVM_ECDSA_MPC_OPERATION_KINDS,
  NEAR_ED25519_MPC_OPERATION_KINDS,
  buildEvmEcdsaMpcOperationRef,
  buildNearEd25519MpcOperationRef,
  buildVaultOperationRef,
  type CapabilityOperationRef,
} from '@shared/authorization/capabilityKinds';
import type { SeamsConfigsReadonly } from '@/core/types/seams';
import {
  configuredThresholdEcdsaChainTargets,
  thresholdEcdsaChainTargetsEqual,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';

type NearBrowserCapabilityOperation = Extract<
  CapabilityOperationRef,
  { readonly capabilityKind: typeof CAPABILITY_KINDS.nearEd25519MpcSigning }
>;

type EvmBrowserCapabilityOperation = Extract<
  CapabilityOperationRef,
  { readonly capabilityKind: typeof CAPABILITY_KINDS.evmEcdsaMpcSigning }
>;

type VaultBrowserCapabilityOperation = Extract<
  CapabilityOperationRef,
  { readonly capabilityKind: typeof CAPABILITY_KINDS.vaultAccess }
>;

export type BrowserCapabilitySelectionRequest =
  | (NearBrowserCapabilityOperation & { readonly chainTarget?: never })
  | (EvmBrowserCapabilityOperation & { readonly chainTarget: ThresholdEcdsaChainTarget })
  | (VaultBrowserCapabilityOperation & { readonly chainTarget?: never });

export type BrowserCapabilityUnavailableReason =
  | 'router_ab_normal_signing_disabled'
  | 'ecdsa_target_not_configured'
  | 'capability_not_deployed';

export type BrowserCapabilitySelectionResult =
  | {
      readonly kind: 'selected';
      readonly operation: CapabilityOperationRef;
      readonly reason?: never;
    }
  | {
      readonly kind: 'disabled';
      readonly operation: CapabilityOperationRef;
      readonly reason: BrowserCapabilityUnavailableReason;
    };

export type BrowserCapabilityUnavailableSelection = Extract<
  BrowserCapabilitySelectionResult,
  { readonly kind: 'disabled' }
>;

export class BrowserCapabilityUnavailableError extends Error {
  readonly code = 'browser_capability_unavailable';
  readonly selection: BrowserCapabilityUnavailableSelection;

  constructor(selection: BrowserCapabilityUnavailableSelection) {
    super(
      `Browser capability ${selection.operation.capabilityKind} is unavailable for ${selection.operation.operationKind}: ${selection.reason}`,
    );
    this.name = 'BrowserCapabilityUnavailableError';
    this.selection = selection;
  }
}

function selected(operation: CapabilityOperationRef): BrowserCapabilitySelectionResult {
  return { kind: 'selected', operation };
}

function disabled(
  operation: CapabilityOperationRef,
  reason: BrowserCapabilityUnavailableReason,
): BrowserCapabilitySelectionResult {
  return { kind: 'disabled', operation, reason };
}

function selectNearBrowserCapabilityOperation(
  configs: SeamsConfigsReadonly,
  request: NearBrowserCapabilityOperation,
): BrowserCapabilitySelectionResult {
  switch (request.operationKind) {
    case NEAR_ED25519_MPC_OPERATION_KINDS.signTransaction:
    case NEAR_ED25519_MPC_OPERATION_KINDS.signDelegateAction:
    case NEAR_ED25519_MPC_OPERATION_KINDS.signNep413Message: {
      const operation = buildNearEd25519MpcOperationRef(request.operationKind);
      return configs.signing.routerAb.normalSigning.mode === 'enabled'
        ? selected(operation)
        : disabled(operation, 'router_ab_normal_signing_disabled');
    }
    case NEAR_ED25519_MPC_OPERATION_KINDS.exportKey:
      return selected(buildNearEd25519MpcOperationRef(request.operationKind));
  }
}

function selectEvmBrowserCapabilityOperation(
  configs: SeamsConfigsReadonly,
  request: EvmBrowserCapabilityOperation & {
    readonly chainTarget: ThresholdEcdsaChainTarget;
  },
): BrowserCapabilitySelectionResult {
  const targetIsConfigured = configuredThresholdEcdsaChainTargets(configs.network.chains).some(
    (configuredTarget) => thresholdEcdsaChainTargetsEqual(configuredTarget, request.chainTarget),
  );
  switch (request.operationKind) {
    case EVM_ECDSA_MPC_OPERATION_KINDS.signTransaction:
    case EVM_ECDSA_MPC_OPERATION_KINDS.exportKey: {
      const operation = buildEvmEcdsaMpcOperationRef(request.operationKind);
      return targetIsConfigured
        ? selected(operation)
        : disabled(operation, 'ecdsa_target_not_configured');
    }
  }
}

export function selectBrowserCapabilityOperation(
  configs: SeamsConfigsReadonly,
  request: BrowserCapabilitySelectionRequest,
): BrowserCapabilitySelectionResult {
  switch (request.capabilityKind) {
    case CAPABILITY_KINDS.vaultAccess:
      return disabled(buildVaultOperationRef(request.operationKind), 'capability_not_deployed');
    case CAPABILITY_KINDS.nearEd25519MpcSigning:
      return selectNearBrowserCapabilityOperation(configs, request);
    case CAPABILITY_KINDS.evmEcdsaMpcSigning:
      return selectEvmBrowserCapabilityOperation(configs, request);
  }
}

export function requireBrowserCapabilityOperation(
  configs: SeamsConfigsReadonly,
  request: BrowserCapabilitySelectionRequest,
): CapabilityOperationRef {
  const selection = selectBrowserCapabilityOperation(configs, request);
  switch (selection.kind) {
    case 'selected':
      return selection.operation;
    case 'disabled':
      throw new BrowserCapabilityUnavailableError(selection);
  }
}
