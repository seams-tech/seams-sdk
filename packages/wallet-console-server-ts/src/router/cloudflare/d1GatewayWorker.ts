import type { CfExecutionContext, CfScheduledEvent } from '@seams/wallet-server/cloud-host';
import {
  handleSplitGatewayRequest,
  runRouterAbPrewarmScheduled,
  type CloudflareD1GatewayEnv,
} from './d1RouterApiStagingWorker';

// The split Wallet Gateway entrypoint (R105 Phase 4). Bindings: SIGNER_DB,
// MPC_ROUTER, SIGNING_WORKER, and the private WALLET_CONSOLE service binding.
// No CONSOLE_DB, no /console/* routes, no Console cron; deploying this
// entrypoint IS the gateway half of the cutover.

async function fetch(
  request: Request,
  env: CloudflareD1GatewayEnv,
  ctx: CfExecutionContext,
): Promise<Response> {
  return await handleSplitGatewayRequest(request, env, ctx);
}

async function scheduled(
  event: CfScheduledEvent,
  env: CloudflareD1GatewayEnv,
  _ctx: CfExecutionContext,
): Promise<void> {
  await runRouterAbPrewarmScheduled(event, env);
}

export default { fetch, scheduled };
