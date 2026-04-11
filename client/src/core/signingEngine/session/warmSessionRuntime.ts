import type { ThresholdSessionSealTransportAuthMaterial } from '../api/thresholdLifecycle/thresholdSessionStore';
import type {
  WarmSessionSealPersister,
  WarmSessionMaterialClaimer,
  WarmSessionStatusReader,
} from '../touchConfirm';
import {
  formatMissingWarmPrfMaterialError,
  formatWarmSessionClaimUnavailableError,
  reportWarmSessionAvailabilityFailure,
} from './warmSessionReadModel';

export type WarmSessionRuntimePorts =
  | Partial<
      Pick<
        WarmSessionStatusReader & WarmSessionMaterialClaimer & WarmSessionSealPersister,
        'getWarmSessionStatus' | 'claimWarmSessionMaterial' | 'sealAndPersistWarmSessionMaterial'
      >
    >
  | undefined;

export async function claimWarmSessionPrfFirst(args: {
  touchConfirm: WarmSessionRuntimePorts;
  thresholdSessionId: string;
  errorContext: string;
  uses?: number;
}): Promise<string> {
  const thresholdSessionId = String(args.thresholdSessionId || '').trim();
  const errorContext = String(args.errorContext || 'threshold session operation').trim();
  if (!thresholdSessionId) {
    throw new Error(`Missing threshold sessionId for ${errorContext}`);
  }
  if (!args.touchConfirm || typeof args.touchConfirm.claimWarmSessionMaterial !== 'function') {
    throw new Error('[WarmSessionManager] touchConfirm warm-session claim operations are required');
  }

  const readDiagnosticClaimCode = async (): Promise<string | undefined> => {
    if (typeof args.touchConfirm?.getWarmSessionStatus !== 'function') return undefined;
    const status = await args.touchConfirm.getWarmSessionStatus({ sessionId: thresholdSessionId }).catch(() => null);
    if (!status || status.ok) return undefined;
    return status.code === 'not_found' ? 'missing' : String(status.code || '').trim() || undefined;
  };

  const claimedMaterial = await args.touchConfirm.claimWarmSessionMaterial({
    sessionId: thresholdSessionId,
    uses: args.uses,
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

export async function ensureEcdsaPrfSealPersisted(args: {
  touchConfirm: WarmSessionRuntimePorts;
  thresholdSessionId: string;
  required?: boolean;
  errorContext?: string;
  sealPersistInFlightBySessionId: Map<string, Promise<void>>;
  resolveSealTransport: (thresholdSessionId: string) => ThresholdSessionSealTransportAuthMaterial | null;
}): Promise<void> {
  const thresholdSessionId = String(args.thresholdSessionId || '').trim();
  if (!thresholdSessionId) return;
  let persistPromise = args.sealPersistInFlightBySessionId.get(thresholdSessionId);
  if (!persistPromise) {
    persistPromise = (async (): Promise<void> => {
      const errorContext = String(args.errorContext || 'threshold session seal persistence').trim();
      const sealTransport = args.resolveSealTransport(thresholdSessionId);
      const persistFn = args.touchConfirm?.sealAndPersistWarmSessionMaterial;
      if (typeof persistFn === 'function' && sealTransport) {
        const persisted = await persistFn({
          sessionId: thresholdSessionId,
          transport: {
            relayerUrl: sealTransport.relayerUrl,
            ...(sealTransport.thresholdSessionJwt
              ? { thresholdSessionJwt: sealTransport.thresholdSessionJwt }
              : {}),
            ...(sealTransport.keyVersion ? { keyVersion: sealTransport.keyVersion } : {}),
            ...(sealTransport.shamirPrimeB64u
              ? { shamirPrimeB64u: sealTransport.shamirPrimeB64u }
              : {}),
          },
        });
        if (!persisted.ok && persisted.code !== 'not_enabled' && args.required) {
          throw new Error(
            `[WarmSessionManager] ${errorContext} failed (${persisted.code}): ${persisted.message}`,
          );
        }
        if (persisted.ok) return;
      }

      if (typeof args.touchConfirm?.getWarmSessionStatus === 'function') {
        await args.touchConfirm.getWarmSessionStatus({ sessionId: thresholdSessionId }).catch(() => undefined);
      }
    })();
    args.sealPersistInFlightBySessionId.set(thresholdSessionId, persistPromise);
    void persistPromise.then(
      () => {
        if (args.sealPersistInFlightBySessionId.get(thresholdSessionId) === persistPromise) {
          args.sealPersistInFlightBySessionId.delete(thresholdSessionId);
        }
      },
      () => {
        if (args.sealPersistInFlightBySessionId.get(thresholdSessionId) === persistPromise) {
          args.sealPersistInFlightBySessionId.delete(thresholdSessionId);
        }
      },
    );
  }
  await persistPromise;
}
