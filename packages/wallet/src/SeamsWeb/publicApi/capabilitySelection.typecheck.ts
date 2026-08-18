import {
  CAPABILITY_KINDS,
  EVM_ECDSA_MPC_OPERATION_KINDS,
  NEAR_ED25519_MPC_OPERATION_KINDS,
  VAULT_OPERATION_KINDS,
} from '@shared/authorization/capabilityKinds';
import type { SeamsConfigsReadonly } from '@/core/types/seams';
import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  BrowserCapabilityUnavailableError,
  selectBrowserCapabilityOperation,
} from './capabilitySelection';

declare const configs: SeamsConfigsReadonly;
declare const chainTarget: ThresholdEcdsaChainTarget;

selectBrowserCapabilityOperation(configs, {
  capabilityKind: CAPABILITY_KINDS.nearEd25519MpcSigning,
  operationKind: NEAR_ED25519_MPC_OPERATION_KINDS.signTransaction,
});

selectBrowserCapabilityOperation(configs, {
  capabilityKind: CAPABILITY_KINDS.evmEcdsaMpcSigning,
  operationKind: EVM_ECDSA_MPC_OPERATION_KINDS.exportKey,
  chainTarget,
});

selectBrowserCapabilityOperation(configs, {
  capabilityKind: CAPABILITY_KINDS.vaultAccess,
  operationKind: VAULT_OPERATION_KINDS.proxyUse,
});

// @ts-expect-error EVM capability selection requires an exact configured target.
selectBrowserCapabilityOperation(configs, {
  capabilityKind: CAPABILITY_KINDS.evmEcdsaMpcSigning,
  operationKind: EVM_ECDSA_MPC_OPERATION_KINDS.signTransaction,
  chainTarget: undefined,
});

// @ts-expect-error NEAR capability operations cannot carry an ECDSA target.
selectBrowserCapabilityOperation(configs, {
  capabilityKind: CAPABILITY_KINDS.nearEd25519MpcSigning,
  operationKind: NEAR_ED25519_MPC_OPERATION_KINDS.exportKey,
  chainTarget,
});

selectBrowserCapabilityOperation(configs, {
  // @ts-expect-error Capability operations must use the closed capability vocabulary.
  capabilityKind: 'custom_signer',
  // @ts-expect-error Capability operations must use the closed operation vocabulary.
  operationKind: 'custom.sign',
});

declare const unavailable: ConstructorParameters<typeof BrowserCapabilityUnavailableError>[0];
unavailable.reason;

export {};
