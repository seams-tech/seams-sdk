import { joinNormalizedUrl, normalizeOptionalNonEmptyString } from '@shared/utils/normalize';
import type { SmartAccountDeployerInput } from './ensureSmartAccountDeployed';

const DEFAULT_SMART_ACCOUNT_DEPLOYMENT_OBSERVE_ROUTE = '/smart-account/deployment/observe';

export type ReportSmartAccountDeploymentObservationInput = SmartAccountDeployerInput & {
  relayerUrl: string;
  thresholdSessionJwt: string;
  deploymentTxHash?: string;
};

export async function reportSmartAccountDeploymentObservation(
  input: ReportSmartAccountDeploymentObservationInput,
): Promise<
  | { ok: true }
  | { ok: false; code: string; message: string }
> {
  const relayerUrl = String(input.relayerUrl || '').trim();
  const thresholdSessionJwt = String(input.thresholdSessionJwt || '').trim();
  const deploymentTxHash = normalizeOptionalNonEmptyString(input.deploymentTxHash);
  if (!relayerUrl || !thresholdSessionJwt || !deploymentTxHash) {
    return {
      ok: false,
      code: 'missing_transport',
      message: 'Missing relayer transport or deployment transaction hash',
    };
  }

  try {
    const response = await fetch(
      joinNormalizedUrl(relayerUrl, DEFAULT_SMART_ACCOUNT_DEPLOYMENT_OBSERVE_ROUTE),
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${thresholdSessionJwt}`,
        },
        credentials: 'omit',
        body: JSON.stringify({
          chain: input.chain,
          chain_id: input.chainId,
          account_address: String(input.account.accountAddress || '').trim(),
          account_model: String(input.account.accountModel || '').trim(),
          counterfactual_address: String(input.account.counterfactualAddress || '').trim(),
          deployment_tx_hash: deploymentTxHash,
        }),
      },
    );
    const json = (await response.json().catch(() => null)) as Record<string, unknown> | null;
    if (!response.ok || json?.ok !== true) {
      return {
        ok: false,
        code:
          normalizeOptionalNonEmptyString(json?.code || json?.error || `http_${response.status}`) ||
          `http_${response.status}`,
        message:
          normalizeOptionalNonEmptyString(json?.message || json?.error || response.statusText) ||
          'Failed to report smart-account deployment observation',
      };
    }
    return { ok: true };
  } catch (error: unknown) {
    return {
      ok: false,
      code: 'request_failed',
      message:
        normalizeOptionalNonEmptyString((error as { message?: unknown })?.message || error) ||
        'Failed to report smart-account deployment observation',
    };
  }
}
