import type { CloudflareRelayContext } from '../createCloudflareRouter';
import { executeSmartAccountDeploy, parseSmartAccountDeployRequest } from '../../smartAccountDeploy';
import { json, readJson } from '../http';

export async function handleSmartAccountDeploy(ctx: CloudflareRelayContext): Promise<Response | null> {
  if (ctx.method !== 'POST' || ctx.pathname !== '/smart-account/deploy') return null;

  const body = await readJson(ctx.request);
  const parsed = parseSmartAccountDeployRequest(body);
  if (!parsed.ok) {
    return json(
      {
        ok: false,
        code: 'invalid_body',
        message: parsed.message,
      },
      { status: 400 },
    );
  }

  try {
    const result = await executeSmartAccountDeploy(ctx.opts, parsed.request);
    return json(result, { status: result.ok ? 200 : 400 });
  } catch (error: unknown) {
    const message =
      error && typeof error === 'object' && 'message' in error
        ? String((error as { message?: unknown }).message || 'internal error')
        : 'internal error';
    return json(
      {
        ok: false,
        code: 'internal',
        message,
      },
      { status: 500 },
    );
  }
}
