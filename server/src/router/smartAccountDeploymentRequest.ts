import {
  smartAccountChainTargetFromParts,
  smartAccountChainTargetFromValue,
  type SmartAccountChainTarget,
} from '../core/smartAccountChainTarget';

function parseNonEmptyString(value: unknown): string {
  return String(value || '').trim();
}

export function parseSmartAccountDeploymentManifestRequest(body: Record<string, unknown>): {
  chainTarget: SmartAccountChainTarget | null;
  accountAddress: string;
} {
  const chainTarget =
    smartAccountChainTargetFromValue(body.chainTarget) ||
    smartAccountChainTargetFromParts({
      chain: body.chain,
      chainId: body.chain_id ?? body.chainId,
      namespace: body.namespace,
      networkSlug: body.network_slug ?? body.networkSlug,
    });
  return {
    chainTarget,
    accountAddress: parseNonEmptyString(body.account_address ?? body.accountAddress),
  };
}

export function parseSmartAccountDeploymentObservationRequest(body: Record<string, unknown>): {
  chainTarget: SmartAccountChainTarget | null;
  accountAddress: string;
  accountModel: string;
  deploymentTxHash: string;
  counterfactualAddress: string;
} {
  return {
    ...parseSmartAccountDeploymentManifestRequest(body),
    accountModel: parseNonEmptyString(body.account_model ?? body.accountModel),
    deploymentTxHash: parseNonEmptyString(body.deployment_tx_hash ?? body.deploymentTxHash),
    counterfactualAddress: parseNonEmptyString(
      body.counterfactual_address ?? body.counterfactualAddress,
    ),
  };
}
