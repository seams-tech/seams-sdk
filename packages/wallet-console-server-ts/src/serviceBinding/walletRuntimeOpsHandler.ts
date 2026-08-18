import type { ExecuteSignedDelegateRequest } from '@seams/wallet-server/cloud-host';
import {
  WALLET_RUNTIME_OP_PATHS_V1,
  WALLET_RUNTIME_OPS_BASE_PATH_V1,
  WALLET_RUNTIME_SERVICE_ORIGIN_V1,
  type WalletRuntimeOps,
} from './walletRuntimeOps';

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

async function readObject(request: Request): Promise<Record<string, unknown> | null> {
  const body: unknown = await request.json().catch(() => null);
  if (!body || typeof body !== 'object' || Array.isArray(body)) return null;
  return body as Record<string, unknown>;
}

function parseExecuteSignedDelegateRequest(
  body: Record<string, unknown>,
): ExecuteSignedDelegateRequest | null {
  const hash = String(body.hash || '').trim();
  const signedDelegate = body.signedDelegate;
  if (
    !hash ||
    !signedDelegate ||
    typeof signedDelegate !== 'object' ||
    Array.isArray(signedDelegate)
  ) {
    return null;
  }
  return {
    hash,
    signedDelegate: signedDelegate as ExecuteSignedDelegateRequest['signedDelegate'],
    ...(body.policy && typeof body.policy === 'object' && !Array.isArray(body.policy)
      ? { policy: body.policy as ExecuteSignedDelegateRequest['policy'] }
      : {}),
  };
}

export function createWalletRuntimeOpsHandler(
  resolveOps: () => Promise<WalletRuntimeOps>,
): (request: Request) => Promise<Response | null> {
  return async function handleWalletRuntimeOperation(request: Request): Promise<Response | null> {
    const url = new URL(request.url);
    if (!url.pathname.startsWith(WALLET_RUNTIME_OPS_BASE_PATH_V1)) return null;
    if (url.origin !== WALLET_RUNTIME_SERVICE_ORIGIN_V1) return null;
    if (request.method !== 'POST') return json({ ok: false, code: 'method_not_allowed' }, 405);
    const ops = await resolveOps();
    if (url.pathname === WALLET_RUNTIME_OP_PATHS_V1.relayerAccount) {
      return json(await ops.getRelayerAccount());
    }
    if (url.pathname === WALLET_RUNTIME_OP_PATHS_V1.executeSignedDelegate) {
      const body = await readObject(request);
      const input = body ? parseExecuteSignedDelegateRequest(body) : null;
      if (!input) return json({ ok: false, code: 'invalid_body' }, 400);
      return json({ result: await ops.executeSignedDelegate(input) });
    }
    return json({ ok: false, code: 'not_found' }, 404);
  };
}
