import type { CloudflareRelayContext } from '../createCloudflareRouter';
import { json, readJson } from '../http';
import {
  RelayBootstrapGrantError,
  parseRelayBootstrapGrantIssueBody,
} from '../../bootstrapGrantBroker';
import { extractBearerCredential } from '../../relayApiKeyAuth';

export async function handleBootstrapGrant(ctx: CloudflareRelayContext): Promise<Response | null> {
  if (ctx.method !== 'POST' || ctx.pathname !== '/v1/registration/bootstrap-grants') return null;

  const broker = ctx.opts.bootstrapGrantBroker;
  if (!broker) {
    return json(
      {
        ok: false,
        code: 'bootstrap_grants_not_configured',
        message: 'Managed bootstrap grants are not configured on this server',
      },
      { status: 503 },
    );
  }

  const publishableKey = extractBearerCredential(ctx.request.headers);
  if (!publishableKey) {
    return json(
      {
        ok: false,
        code: 'publishable_key_missing',
        message: 'Missing publishable key',
      },
      { status: 401 },
    );
  }

  try {
    const parsedBody = parseRelayBootstrapGrantIssueBody(await readJson(ctx.request));
    const result = await broker.issueGrant({
      publishableKey,
      origin: String(ctx.request.headers.get('origin') || ctx.request.headers.get('Origin') || '').trim(),
      ...parsedBody,
    });
    if (!result.ok) {
      ctx.logger.warn('[relay][bootstrap-grants] denied', {
        code: result.code,
        status: result.status,
        environmentId: parsedBody.environmentId,
      });
      return json(
        {
          ok: false,
          code: result.code,
          message: result.message,
          ...(result.payment ? { payment: result.payment } : {}),
        },
        { status: result.status },
      );
    }
    ctx.logger.info('[relay][bootstrap-grants] issued', {
      environmentId: parsedBody.environmentId,
      mode: result.grant.mode,
    });
    return json({ ok: true, grant: result.grant }, { status: 200 });
  } catch (error: unknown) {
    if (error instanceof RelayBootstrapGrantError) {
      return json(
        {
          ok: false,
          code: error.code,
          message: error.message,
        },
        { status: error.status },
      );
    }
    return json(
      {
        ok: false,
        code: 'internal',
        message: error instanceof Error ? error.message : String(error),
      },
      { status: 500 },
    );
  }
}
