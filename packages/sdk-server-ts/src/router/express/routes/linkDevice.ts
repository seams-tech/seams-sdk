import type { Router as ExpressRouter } from 'express';
import type { ExpressRelayContext } from '../createRelayRouter';

const LINK_DEVICE_REFACTOR_84_MESSAGE =
  'Linked-device lane creation is disabled until refactor 84 lands';

function linkDeviceUnsupportedBody(): { ok: false; code: 'unsupported'; message: string } {
  return {
    ok: false,
    code: 'unsupported',
    message: LINK_DEVICE_REFACTOR_84_MESSAGE,
  };
}

function respondLinkDeviceUnsupported(res: any): void {
  res.status(410).json(linkDeviceUnsupportedBody());
}

export function registerLinkDeviceRoutes(router: ExpressRouter, _ctx: ExpressRelayContext): void {
  router.get('/link-device/session/:sessionId', async (_req: any, res: any) => {
    respondLinkDeviceUnsupported(res);
  });

  router.post('/link-device/session', async (_req: any, res: any) => {
    respondLinkDeviceUnsupported(res);
  });

  router.post('/link-device/session/claim', async (_req: any, res: any) => {
    respondLinkDeviceUnsupported(res);
  });

  router.post('/link-device/prepare', async (_req: any, res: any) => {
    respondLinkDeviceUnsupported(res);
  });

  router.post('/link-device/ecdsa/respond', async (_req: any, res: any) => {
    respondLinkDeviceUnsupported(res);
  });
}
