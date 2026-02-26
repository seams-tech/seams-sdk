import type { EvmSigningRequest } from '../chainAdaptors/evm/types';
import type { EvmSignedResult } from '../chainAdaptors/evm/evmAdapter';
import type { TempoSigningRequest } from '../chainAdaptors/tempo/types';
import type { TempoSignedResult } from '../chainAdaptors/tempo/tempoAdapter';
import type { ConfirmationConfig } from '@/core/types/signer-worker';
import {
  reportEvmFamilyBroadcastResult,
  signEvmFamily,
  type EvmFamilyBroadcastResultArgs,
  type EvmFamilySigningDeps,
} from './evmSigning';

export type TempoSigningDeps = EvmFamilySigningDeps;
export type ReportTempoBroadcastResultArgs = EvmFamilyBroadcastResultArgs;

export async function signTempo(
  deps: TempoSigningDeps,
  args: {
    nearAccountId: string;
    request: TempoSigningRequest | EvmSigningRequest;
    confirmationConfigOverride?: Partial<ConfirmationConfig>;
    shouldAbort?: () => boolean;
    onEvent?: (event: {
      step: number;
      phase: string;
      status: 'progress' | 'success' | 'error';
      message?: string;
      data?: unknown;
    }) => void;
  },
): Promise<TempoSignedResult | EvmSignedResult> {
  return await signEvmFamily(deps, args);
}

export async function reportTempoBroadcastResult(
  deps: TempoSigningDeps,
  args: ReportTempoBroadcastResultArgs,
): Promise<void> {
  await reportEvmFamilyBroadcastResult(deps, args);
}
