import type { SeamsConfigsReadonly } from '@/core/types/seams';
import { joinNormalizedUrl, normalizeOptionalNonEmptyString } from '@shared/utils/normalize';
import { normalizeSmartAccountDeploymentAttempts } from './smartAccountNormalization';
import type {
  SmartAccountDeployerInput,
  SmartAccountDeployerResult,
} from './ensureSmartAccountDeployed';

const DEFAULT_SMART_ACCOUNT_DEPLOYMENT_MANIFEST_ROUTE = '/smart-account/deployment/manifest';

export type SmartAccountDeploymentTransport = {
  relayerUrl: string;
  thresholdSessionAuthToken: string;
};

function resolveSmartAccountDeployEndpoint(configs: SeamsConfigsReadonly): string {
  const relayerUrl = String(configs.network.relayer?.url || '').trim();
  if (!relayerUrl) {
    throw new Error('[deployment] missing relayer url (configs.network.relayer.url)');
  }
  const routeRaw = String(configs.network.relayer?.routes?.smartAccountDeploy || '').trim();
  if (!routeRaw) {
    throw new Error(
      '[deployment] no smart-account deploy endpoint configured; built-in relay routers do not expose one',
    );
  }
  const route = routeRaw.startsWith('/') ? routeRaw : `/${routeRaw}`;
  return joinNormalizedUrl(relayerUrl, route);
}

export function resolveSmartAccountDeploymentMode(
  configs: SeamsConfigsReadonly,
): 'observe' | 'enforce' {
  return configs.network.relayer?.smartAccountDeployment?.mode === 'enforce'
    ? 'enforce'
    : 'observe';
}

export function resolveSmartAccountDeploymentMaxAttempts(configs: SeamsConfigsReadonly): number {
  return normalizeSmartAccountDeploymentAttempts(
    configs.network.relayer?.smartAccountDeployment?.maxAttempts,
    2,
  );
}

async function fetchCanonicalSmartAccountDeploymentManifest(input: {
  transport: SmartAccountDeploymentTransport;
  chainTarget: SmartAccountDeployerInput['chainTarget'];
  accountAddress: string;
}): Promise<
  | { ok: true; manifest: Record<string, unknown>; evmDeploymentPlan?: Record<string, unknown> }
  | { ok: false; code: string; message: string }
> {
  const relayerUrl = String(input.transport.relayerUrl || '').trim();
  const thresholdSessionAuthToken = String(input.transport.thresholdSessionAuthToken || '').trim();
  const accountAddress = String(input.accountAddress || '').trim();
  if (!relayerUrl || !thresholdSessionAuthToken || !accountAddress) {
    return {
      ok: false,
      code: 'missing_transport',
      message: 'Missing relay transport or smart-account deployment key',
    };
  }

  try {
    const response = await fetch(
      joinNormalizedUrl(relayerUrl, DEFAULT_SMART_ACCOUNT_DEPLOYMENT_MANIFEST_ROUTE),
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${thresholdSessionAuthToken}`,
        },
        credentials: 'omit',
        body: JSON.stringify({
          chainTarget: input.chainTarget,
          account_address: accountAddress,
        }),
      },
    );
    const json = (await response.json().catch(() => null)) as Record<string, unknown> | null;
    const manifest =
      json?.manifest && typeof json.manifest === 'object' && !Array.isArray(json.manifest)
        ? (json.manifest as Record<string, unknown>)
        : null;
    const evmDeploymentPlan =
      json?.evmDeploymentPlan &&
      typeof json.evmDeploymentPlan === 'object' &&
      !Array.isArray(json.evmDeploymentPlan)
        ? (json.evmDeploymentPlan as Record<string, unknown>)
        : null;
    if (!response.ok || json?.ok !== true || !manifest) {
      return {
        ok: false,
        code:
          normalizeOptionalNonEmptyString(json?.code || json?.error || `http_${response.status}`) ||
          `http_${response.status}`,
        message:
          normalizeOptionalNonEmptyString(json?.message || json?.error || response.statusText) ||
          'Failed to fetch canonical smart-account deployment manifest',
      };
    }
    return {
      ok: true,
      manifest,
      ...(evmDeploymentPlan ? { evmDeploymentPlan } : {}),
    };
  } catch (error: unknown) {
    return {
      ok: false,
      code: 'request_failed',
      message:
        normalizeOptionalNonEmptyString((error as { message?: unknown })?.message || error) ||
        'Failed to fetch canonical smart-account deployment manifest',
    };
  }
}

export async function deploySmartAccountForChain(
  configs: SeamsConfigsReadonly,
  input: SmartAccountDeployerInput,
  transport: SmartAccountDeploymentTransport,
): Promise<SmartAccountDeployerResult> {
  const endpoint = resolveSmartAccountDeployEndpoint(configs);
  const manifest = await fetchCanonicalSmartAccountDeploymentManifest({
    transport,
    chainTarget: input.chainTarget,
    accountAddress: String(input.account.accountAddress || '').trim(),
  });
  if (!manifest.ok) {
    return {
      ok: false,
      code: manifest.code,
      message: manifest.message,
    };
  }
  const body = {
    nearAccountId: String(input.nearAccountId || '').trim(),
    chainTarget: input.chainTarget,
    accountAddress: String(input.account.accountAddress || '').trim(),
    accountModel: String(input.account.accountModel || '').trim(),
    deploymentManifest: manifest.manifest,
    ...(manifest.evmDeploymentPlan ? { evmDeploymentPlan: manifest.evmDeploymentPlan } : {}),
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
