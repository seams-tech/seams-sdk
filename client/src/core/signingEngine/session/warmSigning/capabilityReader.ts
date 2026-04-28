import type { WarmSessionStatusResult } from '../../touchConfirm';
import {
  createWarmSessionCapabilityReaderCore,
  type WarmSessionCapabilityReaderCoreDeps,
} from './capabilityReaderCore';
import {
  createWarmSessionStatusReader,
  type WarmSessionStatusReaderDeps,
} from './statusReader';
import type { WarmSessionCapabilityReader } from './types';

export type WarmSessionCapabilityReaderFactoryDeps = Pick<
  WarmSessionCapabilityReaderCoreDeps,
  'touchConfirm' | 'signingSessionSeal'
> &
  Omit<WarmSessionStatusReaderDeps, 'getEmailOtpWarmSessionStatus'> & {
    getEmailOtpWarmSessionStatus?: (sessionId: string) => Promise<WarmSessionStatusResult>;
  };

export function createWarmSessionCapabilityReader(
  deps: WarmSessionCapabilityReaderFactoryDeps = {},
): WarmSessionCapabilityReader {
  const getEmailOtpWarmSessionStatus =
    deps.getEmailOtpWarmSessionStatus ||
    (async (sessionId: string): Promise<WarmSessionStatusResult> => {
      if (typeof deps.touchConfirm?.getWarmSessionStatus === 'function') {
        return await deps.touchConfirm.getWarmSessionStatus({ sessionId });
      }
      return {
        ok: false,
        code: 'not_found',
        message: 'Email OTP warm-session status reader is unavailable',
      };
    });
  const statusReader = createWarmSessionStatusReader({
    touchConfirm: deps.touchConfirm,
    signingSessionCoordinator: deps.signingSessionCoordinator,
    getEmailOtpWarmSessionStatus,
    listThresholdEcdsaSessionRecordsForLookup: deps.listThresholdEcdsaSessionRecordsForLookup,
  });
  return createWarmSessionCapabilityReaderCore({
    touchConfirm: deps.touchConfirm,
    statusReader,
    signingSessionSeal: deps.signingSessionSeal,
  });
}
