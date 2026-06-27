import type { ThresholdRelayAuthService } from './authServicePort';
import type { RelayRouterOptions } from './relay';

export function resolveThresholdOption(
  service: ThresholdRelayAuthService,
  opts: RelayRouterOptions,
): RelayRouterOptions['threshold'] {
  // Preserve "explicit null disables threshold" semantics:
  // - `opts.threshold === null` => disabled
  // - `opts.threshold === undefined` => auto-wire from AuthService config
  return opts.threshold !== undefined ? opts.threshold : service.getThresholdSigningService();
}
