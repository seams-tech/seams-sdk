import type { WarmSessionStatusResult } from '../../uiConfirm/uiConfirm.types';
import {
  createWarmSessionCapabilityReaderCore,
  type WarmSessionCapabilityReaderSeal,
} from './capabilityReaderCore';
import { createWarmSessionStatusReader, type WarmSessionStatusReaderDeps } from './statusReader';
import {
  normalizeWarmSessionReadPorts,
  type WarmSessionReadPorts,
  type WarmSessionReadPortsInput,
} from './readModel';
import type { WarmSessionCapabilityReader } from './types';
import type { ExactEcdsaWalletSessionAuthorizationResolver } from '../material/ecdsaSigningCapability';
import type { WalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ExactNearEd25519WalletSessionAuthorization } from '../material/nearEd25519YaoSigningPreparation';
import type { EmailOtpWarmMaterialTarget } from '../../workerManager/workerTypes';
import type {
  ActiveEcdsaCapabilityRuntimeForChainResolver,
  ActiveEcdsaCapabilityRuntimeResolver,
} from '../material/activeEcdsaCapabilityRuntime';

export type WarmSessionCapabilityReaderSealInput = {
  groupId: string;
} | null;

export type WarmSessionCapabilityReaderTouchConfirmInput = Exclude<
  WarmSessionReadPortsInput,
  undefined
>;

export type WarmCapabilityReaderPortsConfigured = {
  runtimeStatus: 'configured';
  touchConfirm: WarmSessionReadPorts | null;
  getEmailOtpWarmSessionStatus: (
    target: EmailOtpWarmMaterialTarget,
  ) => Promise<WarmSessionStatusResult>;
};

export type WarmCapabilityReaderPortsNoRuntimeStatus = {
  runtimeStatus: 'no_runtime_status';
  touchConfirm: null;
  getEmailOtpWarmSessionStatus: (
    target: EmailOtpWarmMaterialTarget,
  ) => Promise<WarmSessionStatusResult>;
};

export type WarmCapabilityReaderPorts =
  | WarmCapabilityReaderPortsConfigured
  | WarmCapabilityReaderPortsNoRuntimeStatus;

export type WarmSessionCapabilityReaderFactoryDeps = Omit<
  WarmSessionStatusReaderDeps,
  'getEmailOtpWarmSessionStatus' | 'touchConfirm'
> & {
  resolveActiveEcdsaCapabilityRuntime: ActiveEcdsaCapabilityRuntimeResolver;
  resolveActiveEcdsaCapabilityRuntimeForChain: ActiveEcdsaCapabilityRuntimeForChainResolver;
  touchConfirm: WarmSessionCapabilityReaderTouchConfirmInput;
  signingSessionSeal: WarmSessionCapabilityReaderSealInput;
  getEmailOtpWarmSessionStatus:
    | ((target: EmailOtpWarmMaterialTarget) => Promise<WarmSessionStatusResult>)
    | null;
  resolveActiveEcdsaWalletSessionAuthorization?: ExactEcdsaWalletSessionAuthorizationResolver;
  resolveActiveEd25519WalletSessionAuthorization?: (
    walletId: WalletId,
  ) => Promise<ExactNearEd25519WalletSessionAuthorization | null>;
};

function unavailableEmailOtpWarmSessionStatus(): WarmSessionStatusResult {
  return {
    ok: false,
    code: 'not_found',
    message: 'Email OTP warm-session status reader is unavailable',
  };
}

export function normalizeWarmCapabilityReaderPorts(
  deps: Pick<
    WarmSessionCapabilityReaderFactoryDeps,
    'touchConfirm' | 'getEmailOtpWarmSessionStatus'
  >,
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
      getEmailOtpWarmSessionStatus: async (target: EmailOtpWarmMaterialTarget) =>
        await touchConfirm.getWarmSessionStatus({ thresholdSessionId: target.thresholdSessionId }),
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
  const groupId = String(sealInput?.groupId || '').trim();
  if (!groupId) {
    return { seal: 'unconfigured' };
  }
  return {
    seal: 'configured',
    groupId,
  };
}

export function createWarmSessionCapabilityReader(
  deps: WarmSessionCapabilityReaderFactoryDeps,
): WarmSessionCapabilityReader {
  const ports = normalizeWarmCapabilityReaderPorts(deps);
  const statusReader = createWarmSessionStatusReader({
    touchConfirm: ports.touchConfirm,
    getEmailOtpWarmSessionStatus: ports.getEmailOtpWarmSessionStatus,
  });
  return createWarmSessionCapabilityReaderCore({
    resolveActiveEcdsaCapabilityRuntime: deps.resolveActiveEcdsaCapabilityRuntime,
    resolveActiveEcdsaCapabilityRuntimeForChain:
      deps.resolveActiveEcdsaCapabilityRuntimeForChain,
    statusReader,
    signingSessionSeal: normalizeWarmSessionCapabilityReaderSeal(deps.signingSessionSeal),
    ...(deps.resolveActiveEcdsaWalletSessionAuthorization
      ? {
          resolveActiveEcdsaWalletSessionAuthorization:
            deps.resolveActiveEcdsaWalletSessionAuthorization,
        }
      : {}),
    ...(deps.resolveActiveEd25519WalletSessionAuthorization
      ? {
          resolveActiveEd25519WalletSessionAuthorization:
            deps.resolveActiveEd25519WalletSessionAuthorization,
        }
      : {}),
  });
}
