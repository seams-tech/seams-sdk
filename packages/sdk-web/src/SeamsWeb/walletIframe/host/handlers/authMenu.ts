import type { HandlerDeps, HandlerMap, Req } from './walletIframeHandler.types';
import { respondOkResult } from './shared';
import {
  parseHostedAuthMenuCancelPayload,
  parseHostedAuthMenuExternalAuthResolution,
  parseHostedAuthMenuOpenRequest,
} from '../../shared/messages';
import { AuthMenuController } from '../auth-menu/controller';

export function createHostedAuthMenuHandlers(
  deps: HandlerDeps,
  controller = new AuthMenuController({
    getSeamsWeb: deps.getSeamsWeb,
    getAppearance: () => deps.getSeamsWeb().configs.ui.appearance,
    send: deps.post,
  }),
): HandlerMap {
  return {
    PM_OPEN_AUTH_MENU: async (req: Req<'PM_OPEN_AUTH_MENU'>) => {
      const payload = parseHostedAuthMenuOpenRequest(req.payload);
      if (!payload) throw new Error('Hosted auth-menu open request is invalid');
      const outcome = await controller.open({ request: payload, requestId: req.requestId });
      respondOkResult(deps, req.requestId, outcome);
    },
    PM_CANCEL_AUTH_MENU: async (req: Req<'PM_CANCEL_AUTH_MENU'>) => {
      const payload = parseHostedAuthMenuCancelPayload(req.payload);
      if (!payload) throw new Error('Hosted auth-menu cancellation is invalid');
      const cancelled = controller.cancel(payload);
      respondOkResult(deps, req.requestId, { cancelled });
    },
    PM_RESOLVE_AUTH_MENU_EXTERNAL_AUTH: async (req: Req<'PM_RESOLVE_AUTH_MENU_EXTERNAL_AUTH'>) => {
      const payload = parseHostedAuthMenuExternalAuthResolution(req.payload);
      if (!payload) throw new Error('Hosted auth-menu external-auth resolution is invalid');
      const accepted = controller.resolveExternalAuth(payload);
      respondOkResult(deps, req.requestId, { accepted });
    },
  };
}

export function createAuthMenuController(deps: HandlerDeps): AuthMenuController {
  return new AuthMenuController({
    getSeamsWeb: deps.getSeamsWeb,
    getAppearance: () => deps.getSeamsWeb().configs.ui.appearance,
    send: deps.post,
  });
}
