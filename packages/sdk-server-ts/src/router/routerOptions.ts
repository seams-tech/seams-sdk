import type { ThresholdRouterApiAuthService } from './authServicePort';
import type { RouterApiOptions } from './routerApi';

export function resolveThresholdOption(
  service: ThresholdRouterApiAuthService,
  opts: RouterApiOptions,
): RouterApiOptions['threshold'] {
  // Preserve "explicit null disables threshold" semantics:
  // - `opts.threshold === null` => disabled
  // - `opts.threshold === undefined` => auto-wire from AuthService config
  return opts.threshold !== undefined ? opts.threshold : service.getThresholdSigningService();
}
