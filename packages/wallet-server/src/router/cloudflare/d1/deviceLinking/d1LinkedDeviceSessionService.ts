import type {
  LinkedDeviceOwnerAuthorizationPortV1,
  LinkedDeviceEmailOtpBaseFactorReaderV1,
  LinkedDeviceSessionServiceV1,
} from '../../../../core/deviceLinking/linkedDeviceSession';
import { LinkedDeviceSessionServiceV1 as CoreLinkedDeviceSessionServiceV1 } from '../../../../core/deviceLinking/linkedDeviceSession';
import type { D1LinkedDeviceSessionStoreV1 } from './d1LinkedDeviceSessionStore';

export type D1LinkedDeviceSessionServiceOptionsV1 = {
  readonly sessionStore: D1LinkedDeviceSessionStoreV1;
  readonly ownerAuthorization: LinkedDeviceOwnerAuthorizationPortV1;
  /**
   * Resolves the wallet's active verified base Email OTP factor at approval
   * time. Left unwired, `email_otp` approvals are refused fail-closed.
   */
  readonly emailOtpBaseFactors?: LinkedDeviceEmailOtpBaseFactorReaderV1;
};

export type D1LinkedDeviceSessionServiceCompositionV1 = {
  readonly sessionService: LinkedDeviceSessionServiceV1;
  readonly sessionStore: D1LinkedDeviceSessionStoreV1;
};

export function createD1LinkedDeviceSessionServiceV1(
  options: D1LinkedDeviceSessionServiceOptionsV1,
): D1LinkedDeviceSessionServiceCompositionV1 {
  const sessionService = new CoreLinkedDeviceSessionServiceV1({
    store: options.sessionStore,
    authorization: options.ownerAuthorization,
    ...(options.emailOtpBaseFactors === undefined
      ? {}
      : { emailOtpBaseFactors: options.emailOtpBaseFactors }),
  });
  return { sessionService, sessionStore: options.sessionStore };
}
