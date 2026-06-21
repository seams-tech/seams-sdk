import type { WarmSessionStatusResult } from '../../uiConfirm/uiConfirm.types';
import type {
  WarmSessionCapabilityReaderFactoryDeps,
  WarmCapabilityReaderPortsConfigured,
  WarmCapabilityReaderPortsNoRuntimeStatus,
} from './capabilityReader';
import type { WarmSessionCapabilityReaderSeal } from './capabilityReaderCore';
import type { WarmSessionReadPorts } from './readModel';
import { parseSigningSessionSealKeyVersion } from '../keyMaterialBrands';

declare const touchConfirm: WarmSessionReadPorts;
declare const getEmailOtpWarmSessionStatus: (
  sessionId: string,
) => Promise<WarmSessionStatusResult>;
const signingSessionSealKeyVersion = parseSigningSessionSealKeyVersion(
  'signing-session-seal-kek-test-r1',
);

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
  touchConfirm,
  signingSessionSeal: {
    signingSessionSealKeyVersion,
    shamirPrimeB64u: 'prime-b64u',
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
  touchConfirm: null,
  signingSessionSeal: null,
  getEmailOtpWarmSessionStatus: null,
};
void factoryDepsWithNullPorts;

const configuredSeal: WarmSessionCapabilityReaderSeal = {
  seal: 'configured',
  signingSessionSealKeyVersion,
  shamirPrimeB64u: 'prime-b64u',
};
void configuredSeal;

const configuredSealWithRawKeyVersion: WarmSessionCapabilityReaderSeal = {
  seal: 'configured',
  // @ts-expect-error configured seal fallback requires a branded seal key version.
  signingSessionSealKeyVersion: 'signing-session-seal-kek-test-r1',
  shamirPrimeB64u: 'prime-b64u',
};
void configuredSealWithRawKeyVersion;

// @ts-expect-error configured seal fallback requires the Shamir prime.
const configuredSealWithoutPrime: WarmSessionCapabilityReaderSeal = {
  seal: 'configured',
  signingSessionSealKeyVersion,
};
void configuredSealWithoutPrime;

// @ts-expect-error unconfigured seal fallback rejects partial key material.
const unconfiguredSealWithKey: WarmSessionCapabilityReaderSeal = {
  seal: 'unconfigured',
  signingSessionSealKeyVersion,
};
void unconfiguredSealWithKey;

export {};
