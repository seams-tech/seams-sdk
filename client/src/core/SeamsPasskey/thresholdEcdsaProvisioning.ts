import type { ThresholdEcdsaActivationChain } from '../signingEngine/SigningEngine';
import { chainFamilyFromNetwork } from '../config/chains';
import type { SeamsChainConfig } from '../types/seams';
import type {
  EcdsaSignerProvisioningDefaults,
  EcdsaSignerProvisioningPolicy,
} from '../types/ecdsaSignerProvisioningDefaults';

export type ThresholdEcdsaProvisionTarget = {
  chain: ThresholdEcdsaActivationChain;
  options: EcdsaSignerProvisioningPolicy;
};

function normalizeChainId(value: unknown): number | null {
  const chainId = Math.floor(Number(value));
  if (!Number.isSafeInteger(chainId) || chainId < 0) return null;
  return chainId;
}

export function requireThresholdEcdsaProvisionChainId(args: {
  chain: ThresholdEcdsaActivationChain;
  chains: readonly SeamsChainConfig[];
  explicitChainId?: number;
  smartAccount?: { chainId: number };
}): number {
  const explicit = normalizeChainId(args.explicitChainId);
  if (explicit !== null) return explicit;
  const smartAccountChainId = normalizeChainId(args.smartAccount?.chainId);
  if (smartAccountChainId !== null) return smartAccountChainId;
  const configured = args.chains.find((chain) => chainFamilyFromNetwork(chain.network) === args.chain);
  const configuredChainId = normalizeChainId((configured as { chainId?: unknown } | undefined)?.chainId);
  if (configuredChainId !== null) return configuredChainId;
  throw new Error(
    `[threshold-ecdsa] missing numeric chainId for ${args.chain} provisioning target`,
  );
}

export function listThresholdEcdsaProvisionTargets(
  signerOptions: EcdsaSignerProvisioningDefaults,
): ThresholdEcdsaProvisionTarget[] {
  const targets: ThresholdEcdsaProvisionTarget[] = [];
  if (signerOptions.tempo.enabled) {
    targets.push({ chain: 'tempo', options: signerOptions.tempo });
  }
  if (signerOptions.evm.enabled) {
    targets.push({ chain: 'evm', options: signerOptions.evm });
  }
  return targets;
}

export function toSmartAccountBootstrapInput(
  chain: ThresholdEcdsaActivationChain,
  smartAccount: EcdsaSignerProvisioningPolicy['smartAccount'] | undefined,
):
  | {
      chainId: number;
      factory?: string;
      entryPoint?: string;
      salt?: string;
      counterfactualAddress?: string;
    }
  | undefined {
  void chain;
  if (!smartAccount) return undefined;
  return { ...smartAccount };
}

export function toRegistrationSmartAccountTarget(
  chain: ThresholdEcdsaActivationChain,
  smartAccount: EcdsaSignerProvisioningPolicy['smartAccount'] | undefined,
):
  | {
      chain: ThresholdEcdsaActivationChain;
      chain_id: number;
      factory?: string;
      entry_point?: string;
      salt?: string;
      counterfactual_address?: string;
    }
  | undefined {
  if (!smartAccount) return undefined;
  return {
    chain,
    chain_id: smartAccount.chainId,
    ...(smartAccount.factory ? { factory: smartAccount.factory } : {}),
    ...(smartAccount.entryPoint ? { entry_point: smartAccount.entryPoint } : {}),
    ...(smartAccount.salt ? { salt: smartAccount.salt } : {}),
    ...(smartAccount.counterfactualAddress
      ? { counterfactual_address: smartAccount.counterfactualAddress }
      : {}),
  };
}
