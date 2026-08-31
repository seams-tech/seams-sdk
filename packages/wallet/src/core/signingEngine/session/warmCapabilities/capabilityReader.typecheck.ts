import type { WarmSessionStatusResult } from '../../uiConfirm/uiConfirm.types';
import type {
  WarmSessionCapabilityReaderFactoryDeps,
  WarmCapabilityReaderPortsConfigured,
  WarmCapabilityReaderPortsNoRuntimeStatus,
} from './capabilityReader';
import type { WarmSessionCapabilityReaderSeal } from './capabilityReaderCore';
import type { WarmSessionReadPorts } from './readModel';
import type { EmailOtpWarmMaterialTarget } from '../../workerManager/workerTypes';
import type {
  ActiveEcdsaCapabilityRuntimeForChainResolver,
  ActiveEcdsaCapabilityRuntimeResolver,
} from '../material/activeEcdsaCapabilityRuntime';

declare const touchConfirm: WarmSessionReadPorts;
declare const getEmailOtpWarmSessionStatus: (
  target: EmailOtpWarmMaterialTarget,
) => Promise<WarmSessionStatusResult>;
declare const resolveActiveEcdsaCapabilityRuntime: ActiveEcdsaCapabilityRuntimeResolver;
declare const resolveActiveEcdsaCapabilityRuntimeForChain: ActiveEcdsaCapabilityRuntimeForChainResolver;

const configuredPorts: WarmCapabilityReaderPortsConfigured = {
  runtimeStatus: 'configured',
  touchConfirm,
  getEmailOtpWarmSessionStatus,
};
void configuredPorts;

// @ts-expect-error configured capability-reader ports require an Email OTP status reader.
const configuredPortsWithoutStatusReader: WarmCapabilityReaderPortsConfigured = {
  runtimeStatus: 'configured',
  touchConfirm,
};
void configuredPortsWithoutStatusReader;

const noRuntimeStatusPorts: WarmCapabilityReaderPortsNoRuntimeStatus = {
  runtimeStatus: 'no_runtime_status',
  touchConfirm: null,
  getEmailOtpWarmSessionStatus,
};
void noRuntimeStatusPorts;

const noRuntimeStatusPortsWithTouchConfirm: WarmCapabilityReaderPortsNoRuntimeStatus = {
  runtimeStatus: 'no_runtime_status',
  // @ts-expect-error no_runtime_status ports do not carry touch-confirm readers.
  touchConfirm,
  getEmailOtpWarmSessionStatus,
};
void noRuntimeStatusPortsWithTouchConfirm;

const factoryDeps: WarmSessionCapabilityReaderFactoryDeps = {
  resolveActiveEcdsaCapabilityRuntime,
  resolveActiveEcdsaCapabilityRuntimeForChain,
  touchConfirm,
  signingSessionSeal: {
    groupId: 'rfc2409-group2',
  },
  getEmailOtpWarmSessionStatus,
};
void factoryDeps;

// @ts-expect-error capability-reader factory deps require an explicit touch-confirm port or null.
const factoryDepsWithoutTouchConfirm: WarmSessionCapabilityReaderFactoryDeps = {
  signingSessionSeal: null,
  getEmailOtpWarmSessionStatus,
};
void factoryDepsWithoutTouchConfirm;

// @ts-expect-error capability-reader factory deps require an explicit Email OTP status reader or null.
const factoryDepsWithoutEmailOtpStatus: WarmSessionCapabilityReaderFactoryDeps = {
  touchConfirm,
  signingSessionSeal: null,
};
void factoryDepsWithoutEmailOtpStatus;

const factoryDepsWithNullPorts: WarmSessionCapabilityReaderFactoryDeps = {
  resolveActiveEcdsaCapabilityRuntime,
  resolveActiveEcdsaCapabilityRuntimeForChain,
  touchConfirm: null,
  signingSessionSeal: null,
  getEmailOtpWarmSessionStatus: null,
};
void factoryDepsWithNullPorts;

const configuredSeal: WarmSessionCapabilityReaderSeal = {
  seal: 'configured',
  groupId: 'rfc2409-group2',
};
void configuredSeal;

// @ts-expect-error configured seal fallback requires the public group ID.
const configuredSealWithoutGroup: WarmSessionCapabilityReaderSeal = {
  seal: 'configured',
};
void configuredSealWithoutGroup;

// @ts-expect-error unconfigured seal fallback rejects partial protocol state.
const unconfiguredSealWithGroup: WarmSessionCapabilityReaderSeal = {
  seal: 'unconfigured',
  groupId: 'rfc2409-group2',
};
void unconfiguredSealWithGroup;

export {};
