import { authLaneAppSessionJwt, authLaneToRouteAuth } from './authLane';
import type { EmailOtpAuthLane } from './authLane';

declare const authLane: EmailOtpAuthLane;

const routeAuth = authLaneToRouteAuth(authLane);
void routeAuth;

const appSessionJwt = authLaneAppSessionJwt(authLane);
void appSessionJwt;

// @ts-expect-error route-auth projection requires a concrete Email OTP auth lane.
authLaneToRouteAuth(undefined);

// @ts-expect-error app-session JWT projection requires a concrete Email OTP auth lane.
authLaneAppSessionJwt(undefined);

export {};
