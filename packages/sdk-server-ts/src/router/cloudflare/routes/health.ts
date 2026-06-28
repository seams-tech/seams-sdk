import { buildCorsOrigins } from '../../../core/SessionService';
import type { CloudflareRouterApiContext } from '../createCloudflareRouter';
import { json } from '../http';

export async function handleHealth(ctx: CloudflareRouterApiContext): Promise<Response | null> {
  if (!ctx.opts.healthz || ctx.method !== 'GET' || ctx.pathname !== '/healthz') return null;

  // Surface simple CORS info for diagnostics (normalized)
  const allowed = buildCorsOrigins(...(ctx.opts.corsOrigins || []));
  const corsAllowed = allowed === '*' ? '*' : allowed;
  const thresholdConfigured = Boolean(ctx.opts.threshold);

  return json(
    {
      ok: true,
      relayerAccount: ctx.service.getConfiguredRelayerAccount?.() ?? null,
      thresholdEd25519: { configured: thresholdConfigured },
      cors: { allowedOrigins: corsAllowed },
    },
    { status: 200 },
  );
}

export async function handleReady(ctx: CloudflareRouterApiContext): Promise<Response | null> {
  if (!ctx.opts.readyz || ctx.method !== 'GET' || ctx.pathname !== '/readyz') return null;

  const allowed = buildCorsOrigins(...(ctx.opts.corsOrigins || []));
  const corsAllowed = allowed === '*' ? '*' : allowed;

  const thresholdConfigured = Boolean(ctx.opts.threshold);

  try {
    if (ctx.opts.readyCheck) {
      await ctx.opts.readyCheck();
    }
    await ctx.service.getRelayerAccount();
    return json(
      {
        ok: true,
        thresholdEd25519: { configured: thresholdConfigured },
        cors: { allowedOrigins: corsAllowed },
      },
      { status: 200 },
    );
  } catch (error: unknown) {
    return json(
      {
        ok: false,
        code: 'relayer_unavailable',
        message: error instanceof Error ? error.message : String(error),
        thresholdEd25519: { configured: thresholdConfigured },
        cors: { allowedOrigins: corsAllowed },
      },
      { status: 503 },
    );
  }
}
