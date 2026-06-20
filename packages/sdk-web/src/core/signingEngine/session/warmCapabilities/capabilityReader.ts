import type { WarmSessionStatusResult } from '../../uiConfirm/uiConfirm.types';
import {
  createWarmSessionCapabilityReaderCore,
  type WarmSessionCapabilityReaderSeal,
} from './capabilityReaderCore';
import {
  createWarmSessionStatusReader,
  type WarmSessionStatusReaderDeps,
} from './statusReader';
import {
  normalizeWarmSessionReadPorts,
  type WarmSessionReadPorts,
  type WarmSessionReadPortsInput,
} from './readModel';
import type { WarmSessionCapabilityReader } from './types';

export type WarmSessionCapabilityReaderSealInput = {
  keyVersion: string;
  shamirPrimeB64u: string;
} | null;

export type WarmSessionCapabilityReaderTouchConfirmInput = Exclude<
  WarmSessionReadPortsInput,
  undefined
>;

export type WarmCapabilityReaderPortsConfigured = {
  runtimeStatus: 'configured';
  touchConfirm: WarmSessionReadPorts | null;
  getEmailOtpWarmSessionStatus: (sessionId: string) => Promise<WarmSessionStatusResult>;
};

export type WarmCapabilityReaderPortsNoRuntimeStatus = {
  runtimeStatus: 'no_runtime_status';
  touchConfirm: null;
  getEmailOtpWarmSessionStatus: (sessionId: string) => Promise<WarmSessionStatusResult>;
};

export type WarmCapabilityReaderPorts =
  | WarmCapabilityReaderPortsConfigured
  | WarmCapabilityReaderPortsNoRuntimeStatus;

export type WarmSessionCapabilityReaderFactoryDeps = Omit<
  WarmSessionStatusReaderDeps,
  'getEmailOtpWarmSessionStatus' | 'touchConfirm'
> & {
  touchConfirm: WarmSessionCapabilityReaderTouchConfirmInput;
  signingSessionSeal: WarmSessionCapabilityReaderSealInput;
  getEmailOtpWarmSessionStatus: ((sessionId: string) => Promise<WarmSessionStatusResult>) | null;
};

const UNCONFIGURED_WARM_SESSION_CAPABILITY_READER_DEPS: WarmSessionCapabilityReaderFactoryDeps = {
  touchConfirm: null,
  signingSessionSeal: null,
  getEmailOtpWarmSessionStatus: null,
};

function unavailableEmailOtpWarmSessionStatus(): WarmSessionStatusResult {
  return {
    ok: false,
    code: 'not_found',
    message: 'Email OTP warm-session status reader is unavailable',
  };
}

export function normalizeWarmCapabilityReaderPorts(
  deps: Pick<WarmSessionCapabilityReaderFactoryDeps, 'touchConfirm' | 'getEmailOtpWarmSessionStatus'>,
): WarmCapabilityReaderPorts {
  const touchConfirm = normalizeWarmSessionReadPorts(deps.touchConfirm);
  const getEmailOtpWarmSessionStatus = deps.getEmailOtpWarmSessionStatus;
  if (getEmailOtpWarmSessionStatus) {
    return {
      runtimeStatus: 'configured',
      touchConfirm,
      getEmailOtpWarmSessionStatus,
    };
  }
  if (touchConfirm?.statusPort === 'single' || touchConfirm?.statusPort === 'single_and_batch') {
    return {
      runtimeStatus: 'configured',
      touchConfirm,
      getEmailOtpWarmSessionStatus: async (sessionId: string) =>
        await touchConfirm.getWarmSessionStatus({ sessionId }),
    };
  }
  if (touchConfirm) {
    return {
      runtimeStatus: 'configured',
      touchConfirm,
      getEmailOtpWarmSessionStatus: async () => unavailableEmailOtpWarmSessionStatus(),
    };
  }
  return {
    runtimeStatus: 'no_runtime_status',
    touchConfirm: null,
    getEmailOtpWarmSessionStatus: async () => unavailableEmailOtpWarmSessionStatus(),
  };
}

export function normalizeWarmSessionCapabilityReaderSeal(
  sealInput: WarmSessionCapabilityReaderSealInput,
): WarmSessionCapabilityReaderSeal {
  const keyVersion = String(sealInput?.keyVersion || '').trim();
  const shamirPrimeB64u = String(sealInput?.shamirPrimeB64u || '').trim();
  if (!keyVersion || !shamirPrimeB64u) {
    return { seal: 'unconfigured' };
  }
  return {
    seal: 'configured',
    keyVersion,
    shamirPrimeB64u,
  };
}

export function createWarmSessionCapabilityReader(
  deps: WarmSessionCapabilityReaderFactoryDeps = UNCONFIGURED_WARM_SESSION_CAPABILITY_READER_DEPS,
): WarmSessionCapabilityReader {
  const ports = normalizeWarmCapabilityReaderPorts(deps);
  const statusReader = createWarmSessionStatusReader({
    touchConfirm: ports.touchConfirm,
    getEmailOtpWarmSessionStatus: ports.getEmailOtpWarmSessionStatus,
    getThresholdEcdsaSessionRecordByThresholdSessionId:
      deps.getThresholdEcdsaSessionRecordByThresholdSessionId,
  });
  return createWarmSessionCapabilityReaderCore({
    touchConfirm: ports.touchConfirm,
    statusReader,
    signingSessionSeal: normalizeWarmSessionCapabilityReaderSeal(deps.signingSessionSeal),
  });
}
