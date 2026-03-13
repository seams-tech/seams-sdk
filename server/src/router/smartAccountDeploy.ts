import type {
  RelayRouterOptions,
  SmartAccountDeployRequest,
  SmartAccountDeployResult,
} from './relay';

function asObject(input: unknown): Record<string, unknown> | null {
  return input && typeof input === 'object' && !Array.isArray(input)
    ? (input as Record<string, unknown>)
    : null;
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
  const deploymentTxHash = normalizeOptionalString(obj.deploymentTxHash);
  const code = normalizeOptionalString(obj.code);
  const message = normalizeOptionalString(obj.message);

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

function normalizeOptionalString(value: unknown): string | undefined {
  const normalized = String(value || '').trim();
  return normalized || undefined;
}
