import type {
  LinkedDeviceOwnerAuthorizationPortV1,
  LinkedDeviceSessionServiceV1,
} from '../../../../core/deviceLinking/linkedDeviceSession';
import { LinkedDeviceSessionServiceV1 as CoreLinkedDeviceSessionServiceV1 } from '../../../../core/deviceLinking/linkedDeviceSession';
import type {
  LinkedOwnerEmailOtpBaseFactorReaderV1,
  LinkedOwnerEnrollmentCeremonyReaderV1,
} from '../../../../core/deviceLinking/linkedOwnerEnrollmentProvenance';
import type { D1DatabaseLike } from '../../../../storage/tenantRoute';
import {
  D1LinkedDeviceSessionStoreV1,
  type D1LinkedDeviceSessionScopeV1,
} from './d1LinkedDeviceSessionStore';

export type D1LinkedDeviceSessionServiceOptionsV1 = {
  readonly database: D1DatabaseLike;
  readonly scope: D1LinkedDeviceSessionScopeV1;
  readonly ownerAuthorization: LinkedDeviceOwnerAuthorizationPortV1;
  /**
   * Reads back the add-auth-method ceremony an approval names, so its
   * provenance is checked against the server's own record before the approval
   * digest seals it.
   */
  readonly ownerEnrollmentCeremonies: LinkedOwnerEnrollmentCeremonyReaderV1;
  /**
   * Resolves the wallet's active verified base Email OTP factor at approval
   * time. Left unwired, `email_otp` approvals are refused fail-closed.
   */
  readonly emailOtpBaseFactors?: LinkedOwnerEmailOtpBaseFactorReaderV1;
  readonly nowV1: () => number;
};

export type D1LinkedDeviceSessionServiceCompositionV1 = {
  readonly sessionService: LinkedDeviceSessionServiceV1;
  readonly sessionStore: D1LinkedDeviceSessionStoreV1;
};

export function createD1LinkedDeviceSessionServiceV1(
  options: D1LinkedDeviceSessionServiceOptionsV1,
): D1LinkedDeviceSessionServiceCompositionV1 {
  const sessionStore = new D1LinkedDeviceSessionStoreV1({
    database: options.database,
    scope: options.scope,
    now: options.nowV1,
  });
  const sessionService = new CoreLinkedDeviceSessionServiceV1({
    store: sessionStore,
    authorization: options.ownerAuthorization,
    ownerEnrollmentCeremonies: options.ownerEnrollmentCeremonies,
    ...(options.emailOtpBaseFactors === undefined
      ? {}
      : { emailOtpBaseFactors: options.emailOtpBaseFactors }),
  });
  return { sessionService, sessionStore };
}
