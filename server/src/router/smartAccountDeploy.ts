import type {
  RelayRouterOptions,
  SmartAccountDeployRequest,
  SmartAccountDeployResult,
  SmartAccountDeploymentChain,
} from './relay';

type ParseOk = { ok: true; request: SmartAccountDeployRequest };
type ParseErr = { ok: false; message: string };

function asObject(input: unknown): Record<string, unknown> | null {
  return input && typeof input === 'object' && !Array.isArray(input)
    ? (input as Record<string, unknown>)
    : null;
}

function toRequiredString(value: unknown, field: string): string {
  const normalized = String(value || '').trim();
  if (!normalized) throw new Error(`Missing or invalid ${field}`);
  return normalized;
}

function toOptionalString(value: unknown): string | undefined {
  const normalized = String(value || '').trim();
  return normalized || undefined;
}

function toRequiredChainIdNumber(value: unknown): number {
  if (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0) {
    return value;
  }
  const raw = String(value || '').trim();
  if (!/^\d+$/.test(raw)) {
    throw new Error('Missing or invalid chainId');
  }
  const parsed = Number(raw);
  if (!Number.isSafeInteger(parsed) || parsed < 0) {
    throw new Error('Missing or invalid chainId');
  }
  return parsed;
}

function parseChain(value: unknown): SmartAccountDeploymentChain {
  const normalized = String(value || '')
    .trim()
    .toLowerCase();
  if (normalized !== 'evm' && normalized !== 'tempo') {
    throw new Error('Missing or invalid chain (expected "evm" or "tempo")');
  }
  return normalized;
}

export function parseSmartAccountDeployRequest(body: unknown): ParseOk | ParseErr {
  const obj = asObject(body);
  if (!obj) return { ok: false, message: 'JSON body required' };

  try {
    return {
      ok: true,
      request: {
        nearAccountId: toRequiredString(obj.nearAccountId, 'nearAccountId'),
        chain: parseChain(obj.chain),
        chainId: toRequiredChainIdNumber(obj.chainId),
        accountAddress: toRequiredString(obj.accountAddress, 'accountAddress'),
        accountModel: toRequiredString(obj.accountModel, 'accountModel'),
        counterfactualAddress: toOptionalString(obj.counterfactualAddress),
        factory: toOptionalString(obj.factory),
        entryPoint: toOptionalString(obj.entryPoint),
        salt: toOptionalString(obj.salt),
      },
    };
  } catch (error: unknown) {
    const message =
      error && typeof error === 'object' && 'message' in error
        ? String((error as { message?: unknown }).message || 'Invalid request body')
        : 'Invalid request body';
    return { ok: false, message };
  }
}

export async function executeSmartAccountDeploy(
  opts: RelayRouterOptions,
  request: SmartAccountDeployRequest,
): Promise<SmartAccountDeployResult> {
  const deploy = opts.smartAccountDeploy;
  if (typeof deploy !== 'function') {
    return {
      ok: true,
      code: 'assumed_deployed',
      message: 'No smartAccountDeploy handler configured; assuming deployment is handled upstream',
    };
  }

  const result = await deploy(request);
  const obj = asObject(result);
  if (!obj) {
    return {
      ok: false,
      code: 'invalid_result',
      message: 'smartAccountDeploy returned a non-object result',
    };
  }

  const ok = obj.ok === true;
  const deploymentTxHash = toOptionalString(obj.deploymentTxHash);
  const code = toOptionalString(obj.code);
  const message = toOptionalString(obj.message);

  if (ok) {
    return {
      ok: true,
      ...(deploymentTxHash ? { deploymentTxHash } : {}),
      ...(code ? { code } : {}),
      ...(message ? { message } : {}),
    };
  }

  return {
    ok: false,
    ...(code ? { code } : { code: 'deployment_failed' }),
    ...(message ? { message } : { message: 'deployment failed' }),
  };
}
