import { authLaneToRouteAuth, buildEmailOtpRoutePlan } from './authLane';
import type { EmailOtpAuthLane } from './authLane';

declare const authLane: EmailOtpAuthLane;

const routeAuth = authLaneToRouteAuth(authLane);
void routeAuth;

// @ts-expect-error route-auth projection requires a concrete Email OTP auth lane.
authLaneToRouteAuth(undefined);

// @ts-expect-error route planning requires a concrete Email OTP auth lane.
buildEmailOtpRoutePlan({ routeFamily: 'login' });

export {};
