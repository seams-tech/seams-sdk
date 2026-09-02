import { buildEmailOtpRoutePlan } from './authLane';
import type { EmailOtpAuthLane } from './authLane';

declare const authLane: EmailOtpAuthLane;

const operationCredential = authLane.operationCredential;
void operationCredential;

// @ts-expect-error route planning requires a concrete Email OTP auth lane.
buildEmailOtpRoutePlan({ routeFamily: 'login' });

export {};
