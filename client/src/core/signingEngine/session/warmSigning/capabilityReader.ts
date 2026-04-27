import type { AccountId } from '@/core/types/accountIds';
import type { ThresholdEcdsaActivationChain } from '../../orchestration/thresholdActivation';
import type { WarmSessionStatusResult } from '../../touchConfirm';
import {
  createWarmSessionCapabilityResolver,
  type WarmSessionCapabilityResolverDeps,
} from './capabilityResolver';
import {
  createWarmSessionSealedRefreshRestorer,
  type WarmSessionSealedRefreshRestorerDeps,
} from './sealedRefreshRestorer';
import {
  createWarmSessionStatusReader,
  type WarmSessionStatusReaderDeps,
} from './statusReader';
import type { WarmSessionCapabilityReader } from './types';

export type WarmSessionCapabilityReaderFactoryDeps = Pick<
  WarmSessionCapabilityResolverDeps,
  'touchConfirm' | 'signingSessionSeal'
> &
  Omit<WarmSessionStatusReaderDeps, 'getEmailOtpWarmSessionStatus'> &
  Pick<
    WarmSessionSealedRefreshRestorerDeps,
    | 'signingSessionSealedStore'
    | 'rehydrateEmailOtpEcdsaSigningSessionFromSealedRecord'
    | 'onSealedRestore'
  > & {
    getEmailOtpWarmSessionStatus?: (sessionId: string) => Promise<WarmSessionStatusResult>;
    clearEcdsaEphemeralMaterial?: (args: {
      nearAccountId: AccountId;
      chain: ThresholdEcdsaActivationChain;
      thresholdSessionId?: string;
      source?: 'email_otp';
    }) => Promise<void>;
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
  const sealedRefreshRestorer = createWarmSessionSealedRefreshRestorer({
    signingSessionSealedStore: deps.signingSessionSealedStore,
    rehydrateEmailOtpEcdsaSigningSessionFromSealedRecord:
      deps.rehydrateEmailOtpEcdsaSigningSessionFromSealedRecord,
    getEmailOtpWarmSessionStatus,
    clearEcdsaEphemeralMaterial:
      deps.clearEcdsaEphemeralMaterial ||
      (async () => {
        return;
      }),
    onSealedRestore: deps.onSealedRestore,
  });
  return createWarmSessionCapabilityResolver({
    touchConfirm: deps.touchConfirm,
    statusReader,
    sealedRefreshRestorer,
    signingSessionSeal: deps.signingSessionSeal,
  });
}
