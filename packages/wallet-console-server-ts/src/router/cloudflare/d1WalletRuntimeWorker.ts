import type { CfExecutionContext } from '@seams/wallet-server/cloud-host';
import {
  handleSplitGatewayWalletRuntimeRequest,
  type CloudflareD1GatewayEnv,
} from './d1RouterApiStagingWorker';

async function fetch(
  request: Request,
  env: CloudflareD1GatewayEnv,
  _ctx: CfExecutionContext,
): Promise<Response> {
  const response = await handleSplitGatewayWalletRuntimeRequest(request, env);
  return response ?? new Response('Not found', { status: 404 });
}

export default { fetch };
