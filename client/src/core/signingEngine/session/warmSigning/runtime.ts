import type { ThresholdSessionSealTransportAuthMaterial } from '../../api/thresholdLifecycle/thresholdSessionStore';
import type { ThresholdEcdsaChainTarget } from '../signingSession/ecdsaChainTarget';
import type {
  WarmSessionSealPersister,
  WarmSessionMaterialClaimer,
  WarmSessionStatusReader,
} from '../../touchConfirm';
import {
  formatMissingWarmPrfMaterialError,
  formatWarmSessionClaimUnavailableError,
  reportWarmSessionAvailabilityFailure,
} from './readModel';

export type WarmSessionRuntimePorts =
  | Partial<
      Pick<
        WarmSessionStatusReader & WarmSessionMaterialClaimer & WarmSessionSealPersister,
        | 'getWarmSessionStatus'
        | 'claimWarmSessionMaterial'
        | 'sealAndPersistWarmSessionMaterial'
        | 'persistSigningSessionSealForThresholdSession'
      >
    >
  | undefined;

export async function claimWarmSessionPrfFirst(args: {
  touchConfirm: WarmSessionRuntimePorts;
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

export async function ensureEcdsaPrfSealPersisted(args: {
  touchConfirm: WarmSessionRuntimePorts;
  chainTarget: ThresholdEcdsaChainTarget;
  thresholdSessionId: string;
  required?: boolean;
  errorContext?: string;
  sealPersistInFlightBySessionId: Map<string, Promise<void>>;
  resolveSealTransport: (
    args: {
      thresholdSessionId: string;
      chainTarget: ThresholdEcdsaChainTarget;
    },
  ) => ThresholdSessionSealTransportAuthMaterial | null;
}): Promise<void> {
  const thresholdSessionId = String(args.thresholdSessionId || '').trim();
  if (!thresholdSessionId) return;
  const persistKey = `${thresholdSessionId}:${JSON.stringify(args.chainTarget)}`;
  let persistPromise = args.sealPersistInFlightBySessionId.get(persistKey);
  if (!persistPromise) {
    persistPromise = (async (): Promise<void> => {
      const errorContext = String(args.errorContext || 'threshold session seal persistence').trim();
      const sealTransport = args.resolveSealTransport({
        thresholdSessionId,
        chainTarget: args.chainTarget,
      });
      if (sealTransport && sealTransport.curve !== 'ecdsa') {
        throw new Error('[WarmSessionStore] ECDSA seal persistence received non-ECDSA transport');
      }
      const exactPersistFn = args.touchConfirm?.persistSigningSessionSealForThresholdSession;
      if (typeof exactPersistFn === 'function' && sealTransport) {
        // Use the high-level persist boundary after the ECDSA record exists; it
        // writes both the server seal and the local exact-purpose restore record.
        const persisted = await exactPersistFn({
          sessionId: thresholdSessionId,
          transport: {
            curve: sealTransport.curve,
            chainTarget: sealTransport.chainTarget,
            relayerUrl: sealTransport.relayerUrl,
            ...(sealTransport.walletSigningSessionId
              ? { walletSigningSessionId: sealTransport.walletSigningSessionId }
              : {}),
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
            `[WarmSessionStore] ${errorContext} failed (${persisted.code}): ${persisted.message}`,
          );
        }
        if (persisted.ok) return;
      }
      const persistFn = args.touchConfirm?.sealAndPersistWarmSessionMaterial;
      if (typeof persistFn === 'function' && sealTransport) {
        const persisted = await persistFn({
          sessionId: thresholdSessionId,
          transport: {
            curve: sealTransport.curve,
            chainTarget: sealTransport.chainTarget,
            relayerUrl: sealTransport.relayerUrl,
            ...(sealTransport.walletSigningSessionId
              ? { walletSigningSessionId: sealTransport.walletSigningSessionId }
              : {}),
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
            `[WarmSessionStore] ${errorContext} failed (${persisted.code}): ${persisted.message}`,
          );
        }
      }
    })();
    args.sealPersistInFlightBySessionId.set(persistKey, persistPromise);
    void persistPromise.then(
      () => {
        if (args.sealPersistInFlightBySessionId.get(persistKey) === persistPromise) {
          args.sealPersistInFlightBySessionId.delete(persistKey);
        }
      },
      () => {
        if (args.sealPersistInFlightBySessionId.get(persistKey) === persistPromise) {
          args.sealPersistInFlightBySessionId.delete(persistKey);
        }
      },
    );
  }
  await persistPromise;
}
