import type { TatchiConfigsReadonly } from '@/core/types/tatchi';
import { joinNormalizedUrl, normalizeOptionalNonEmptyString } from '@shared/utils/normalize';
import { normalizeSmartAccountDeploymentAttempts } from './smartAccountNormalization';
import type {
  SmartAccountDeployerInput,
  SmartAccountDeployerResult,
} from './ensureSmartAccountDeployed';

function resolveSmartAccountDeployEndpoint(configs: TatchiConfigsReadonly): string {
  const relayerUrl = String(configs.network.relayer?.url || '').trim();
  if (!relayerUrl) {
    throw new Error('[deployment] missing relayer url (configs.network.relayer.url)');
  }
  const routeRaw = String(
    configs.network.relayer?.routes?.smartAccountDeploy || '/smart-account/deploy',
  ).trim();
  const route = routeRaw.startsWith('/') ? routeRaw : `/${routeRaw}`;
  return joinNormalizedUrl(relayerUrl, route);
}

export function resolveSmartAccountDeploymentMode(
  configs: TatchiConfigsReadonly,
): 'observe' | 'enforce' {
  return configs.network.relayer?.smartAccountDeployment?.mode === 'enforce'
    ? 'enforce'
    : 'observe';
}

export function resolveSmartAccountDeploymentMaxAttempts(configs: TatchiConfigsReadonly): number {
  return normalizeSmartAccountDeploymentAttempts(
    configs.network.relayer?.smartAccountDeployment?.maxAttempts,
    2,
  );
}

export async function deploySmartAccountForChain(
  configs: TatchiConfigsReadonly,
  input: SmartAccountDeployerInput,
): Promise<SmartAccountDeployerResult> {
  const endpoint = resolveSmartAccountDeployEndpoint(configs);
  const body = {
    nearAccountId: String(input.nearAccountId || '').trim(),
    chain: input.chain,
    chainId: input.chainId,
    accountAddress: String(input.account.accountAddress || '').trim(),
    accountModel: String(input.account.accountModel || '').trim(),
    counterfactualAddress: String(input.account.counterfactualAddress || '').trim(),
    ...(input.account.factory ? { factory: String(input.account.factory).trim() } : {}),
    ...(input.account.entryPoint ? { entryPoint: String(input.account.entryPoint).trim() } : {}),
    ...(input.account.salt ? { salt: String(input.account.salt).trim() } : {}),
  };

  let json: Record<string, unknown> | null = null;
  try {
    const response = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    json = (await response.json().catch(() => null)) as Record<string, unknown> | null;

    const resultOk =
      (json && json.ok === true) || (json && json.success === true) || (!json && response.ok);
    if (!response.ok || !resultOk) {
      const code = normalizeOptionalNonEmptyString(
        json?.code || json?.errorCode || json?.statusCode || `http_${response.status}`,
      );
      const message =
        normalizeOptionalNonEmptyString(
          json?.message || json?.error || response.statusText || 'deployment failed',
        ) || 'deployment failed';
      return {
        ok: false,
        ...(code ? { code } : {}),
        message,
      };
    }

    const deploymentTxHash = normalizeOptionalNonEmptyString(
      json?.deploymentTxHash || json?.txHash || json?.transactionHash || json?.hash,
    );
    return {
      ok: true,
      ...(deploymentTxHash ? { deploymentTxHash } : {}),
    };
  } catch (error: unknown) {
    const message =
      normalizeOptionalNonEmptyString((error as { message?: unknown })?.message || error) ||
      'deployment request failed';
    return {
      ok: false,
      code: 'request_failed',
      message,
    };
  }
}
