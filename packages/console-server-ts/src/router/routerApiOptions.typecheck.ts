import type { ConsoleRouterApiSignedDelegateRouteOptions } from './routeExtensions';
import type { SignedDelegateRouterApiAuthService } from './routerApiSignedDelegate';

declare const signedDelegateAuthService: SignedDelegateRouterApiAuthService;

const signedDelegateRoute: ConsoleRouterApiSignedDelegateRouteOptions = {
  route: '/signed-delegate',
  authService: signedDelegateAuthService,
  billing: null,
  ledger: null,
  runtimeSnapshots: null,
  publishableKeyAuth: null,
  observabilityIngestion: null,
  prepaidReservations: null,
  pricing: null,
  spendCaps: null,
  webhooks: null,
};

// @ts-expect-error Signed delegate extension route capability requires its auth service.
const signedDelegateRouteWithoutAuthService: ConsoleRouterApiSignedDelegateRouteOptions = {
  route: '/signed-delegate',
  billing: null,
  ledger: null,
  runtimeSnapshots: null,
  publishableKeyAuth: null,
  observabilityIngestion: null,
  prepaidReservations: null,
  pricing: null,
  spendCaps: null,
  webhooks: null,
};

void signedDelegateRoute;
void signedDelegateRouteWithoutAuthService;

export {};
