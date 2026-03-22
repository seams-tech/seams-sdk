function parseChain(value: unknown): 'evm' | 'tempo' | null {
  const normalized = String(value || '')
    .trim()
    .toLowerCase();
  if (normalized === 'evm' || normalized === 'tempo') return normalized;
  return null;
}

function parsePositiveInteger(value: unknown): number | null {
  const normalized = Math.floor(Number(value));
  if (!Number.isFinite(normalized) || normalized <= 0) return null;
  return normalized;
}

function parseNonEmptyString(value: unknown): string {
  return String(value || '').trim();
}

export function parseSmartAccountDeploymentManifestRequest(body: Record<string, unknown>): {
  chain: 'evm' | 'tempo' | null;
  chainId: number | null;
  accountAddress: string;
} {
  return {
    chain: parseChain(body.chain),
    chainId: parsePositiveInteger(body.chain_id ?? body.chainId),
    accountAddress: parseNonEmptyString(body.account_address ?? body.accountAddress),
  };
}

export function parseSmartAccountDeploymentObservationRequest(body: Record<string, unknown>): {
  chain: 'evm' | 'tempo' | null;
  chainId: number | null;
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
