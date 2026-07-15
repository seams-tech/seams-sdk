import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  DurableSealedSessionPort,
  VolatileWarmMaterialPort,
} from '../../uiConfirm/uiConfirm.types';
import {
  formatMissingWarmPrfMaterialError,
  formatWarmSessionClaimUnavailableError,
  reportWarmSessionAvailabilityFailure,
} from '../warmCapabilities/readModel';

export type WarmSessionClaimPorts =
  | Partial<Pick<VolatileWarmMaterialPort, 'getWarmSessionStatus' | 'claimWarmSessionMaterial'>>
  | undefined;

export type PasskeyWarmSessionRecoveryPorts = Partial<
  Pick<
    VolatileWarmMaterialPort & DurableSealedSessionPort,
    'getWarmSessionStatus' | 'claimWarmSessionMaterial' | 'restorePersistedSessionForSigning'
  >
>;

export async function claimWarmSessionPrfFirst(args: {
  touchConfirm: WarmSessionClaimPorts;
  thresholdSessionId: string;
  errorContext: string;
  uses?: number;
  consume?: boolean;
  curve?: 'ed25519' | 'ecdsa';
  chain?: 'near';
  chainTarget?: ThresholdEcdsaChainTarget;
  restoreBeforeClaim?: () => Promise<void>;
}): Promise<string> {
  const thresholdSessionId = String(args.thresholdSessionId || '').trim();
  const errorContext = String(args.errorContext || 'threshold session operation').trim();
  if (!thresholdSessionId) {
    throw new Error(`Missing threshold sessionId for ${errorContext}`);
  }
  if (!args.touchConfirm || typeof args.touchConfirm.claimWarmSessionMaterial !== 'function') {
    throw new Error('[WarmSessionStore] touchConfirm warm-session claim operations are required');
  }

  const readDiagnosticClaimCode = async (): Promise<string | undefined> => {
    if (typeof args.touchConfirm?.getWarmSessionStatus !== 'function') return undefined;
    const status = await args.touchConfirm
      .getWarmSessionStatus({ sessionId: thresholdSessionId })
      .catch(() => null);
    if (!status || status.ok) return undefined;
    return status.code === 'not_found' ? 'missing' : String(status.code || '').trim() || undefined;
  };

  await args.restoreBeforeClaim?.();

  const claimedMaterial = await args.touchConfirm.claimWarmSessionMaterial({
    sessionId: thresholdSessionId,
    uses: args.uses,
    ...(typeof args.consume === 'boolean' ? { consume: args.consume } : {}),
    ...(args.curve ? { curve: args.curve } : {}),
    ...(args.chain ? { chain: args.chain } : {}),
    ...(args.chainTarget ? { chainTarget: args.chainTarget } : {}),
  });
  if (!claimedMaterial.ok) {
    if (
      claimedMaterial.code !== 'not_found' &&
      claimedMaterial.code !== 'expired' &&
      claimedMaterial.code !== 'exhausted'
    ) {
      reportWarmSessionAvailabilityFailure({
        operation: 'claim',
        sessionId: thresholdSessionId,
        code: claimedMaterial.code,
      });
      throw formatWarmSessionClaimUnavailableError({
        errorContext,
        code: claimedMaterial.code,
      });
    }
    throw formatMissingWarmPrfMaterialError({
      errorContext,
      code: claimedMaterial.code === 'not_found' ? 'missing' : claimedMaterial.code,
    });
  }

  const prfFirstB64u = String(claimedMaterial.prfFirstB64u || '').trim();
  if (prfFirstB64u) {
    return prfFirstB64u;
  }

  const diagnosticCode = await readDiagnosticClaimCode();
  if (
    diagnosticCode &&
    diagnosticCode !== 'missing' &&
    diagnosticCode !== 'expired' &&
    diagnosticCode !== 'exhausted'
  ) {
    reportWarmSessionAvailabilityFailure({
      operation: 'claim',
      sessionId: thresholdSessionId,
      code: diagnosticCode,
    });
    throw formatWarmSessionClaimUnavailableError({
      errorContext,
      code: diagnosticCode,
    });
  }
  throw formatMissingWarmPrfMaterialError({
    errorContext,
    code: diagnosticCode,
  });
}
