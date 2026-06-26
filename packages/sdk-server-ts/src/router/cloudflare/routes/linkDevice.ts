import type { CloudflareRelayContext } from '../createCloudflareRouter';
import { json } from '../http';

const LINK_DEVICE_REFACTOR_84_MESSAGE =
  'Linked-device lane creation is disabled until refactor 84 lands';

function linkDeviceUnsupportedBody(): { ok: false; code: 'unsupported'; message: string } {
  return {
    ok: false,
    code: 'unsupported',
    message: LINK_DEVICE_REFACTOR_84_MESSAGE,
  };
}

function isLinkDeviceRoute(ctx: CloudflareRelayContext): boolean {
  if (ctx.method === 'GET' && ctx.pathname.startsWith('/link-device/session/')) return true;
  if (ctx.method !== 'POST') return false;
  return (
    ctx.pathname === '/link-device/session' ||
    ctx.pathname === '/link-device/session/claim' ||
    ctx.pathname === '/link-device/prepare' ||
    ctx.pathname === '/link-device/ecdsa/respond'
  );
}

export async function handleLinkDevice(ctx: CloudflareRelayContext): Promise<Response | null> {
  if (!isLinkDeviceRoute(ctx)) return null;
  return json(linkDeviceUnsupportedBody(), { status: 410 });
}
