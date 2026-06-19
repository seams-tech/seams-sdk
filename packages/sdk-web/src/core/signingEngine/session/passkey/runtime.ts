import type { ThresholdSessionSealTransportAuthMaterial } from '../persistence/records';
import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  WarmSessionSealPersister,
  WarmSessionStatusReader,
} from '../../uiConfirm/types';

export type WarmSessionSealPersistPorts =
  | Partial<
      Pick<
        WarmSessionStatusReader & WarmSessionSealPersister,
        | 'getWarmSessionStatus'
        | 'sealAndPersistWarmSessionMaterial'
        | 'persistSigningSessionSealForThresholdSession'
      >
    >
  | undefined;

export async function ensureEcdsaPrfSealPersisted(args: {
  touchConfirm: WarmSessionSealPersistPorts;
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
            ...(sealTransport.walletId ? { walletId: sealTransport.walletId } : {}),
            chainTarget: sealTransport.chainTarget,
            relayerUrl: sealTransport.relayerUrl,
            ...(sealTransport.walletSigningSessionId
              ? { walletSigningSessionId: sealTransport.walletSigningSessionId }
              : {}),
            ...(sealTransport.walletSessionJwt
              ? { walletSessionJwt: sealTransport.walletSessionJwt }
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
            ...(sealTransport.walletId ? { walletId: sealTransport.walletId } : {}),
            chainTarget: sealTransport.chainTarget,
            relayerUrl: sealTransport.relayerUrl,
            ...(sealTransport.walletSigningSessionId
              ? { walletSigningSessionId: sealTransport.walletSigningSessionId }
              : {}),
            ...(sealTransport.walletSessionJwt
              ? { walletSessionJwt: sealTransport.walletSessionJwt }
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
