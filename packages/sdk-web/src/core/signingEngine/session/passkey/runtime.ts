import type { ThresholdSessionSealTransportAuthMaterial } from '../persistence/records';
import {
  thresholdEcdsaChainTargetKey,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ExactEcdsaSigningLaneIdentity } from '../identity/exactSigningLaneIdentity';
import type { ActiveEvmFamilyWalletSessionAuthorization } from '../../flows/signEvmFamily/ecdsaSigningCapability';
import type {
  WarmSessionSealPersister,
} from '../../uiConfirm/uiConfirm.types';

export type WarmSessionSealPersistPorts =
  | Partial<
      Pick<
        WarmSessionSealPersister,
        'sealAndPersistWarmSessionMaterial' | 'persistSigningSessionSealForThresholdSession'
      >
    >
  | undefined;

export async function ensureEcdsaPrfSealPersisted(args: {
  touchConfirm: WarmSessionSealPersistPorts;
  lane: ExactEcdsaSigningLaneIdentity;
  authorization: ActiveEvmFamilyWalletSessionAuthorization;
  required?: boolean;
  errorContext?: string;
  sealPersistInFlightBySessionId: Map<string, Promise<void>>;
  resolveSealTransport: (args: {
    lane: ExactEcdsaSigningLaneIdentity;
    authorization: ActiveEvmFamilyWalletSessionAuthorization;
  }) => Promise<ThresholdSessionSealTransportAuthMaterial | null>;
}): Promise<void> {
  const materialActivationId = String(
    args.lane.signer.materialActivation.activationId,
  ).trim();
  if (!materialActivationId) return;
  const persistKey = `${materialActivationId}:${thresholdEcdsaChainTargetKey(args.lane.signer.chainTarget)}`;
  let persistPromise = args.sealPersistInFlightBySessionId.get(persistKey);
  if (!persistPromise) {
    persistPromise = (async (): Promise<void> => {
      const errorContext = String(args.errorContext || 'threshold session seal persistence').trim();
      const sealTransport = await args.resolveSealTransport({
        lane: args.lane,
        authorization: args.authorization,
      });
      if (sealTransport && sealTransport.curve !== 'ecdsa') {
        throw new Error('[WarmSessionStore] ECDSA seal persistence received non-ECDSA transport');
      }
      const exactPersistFn = args.touchConfirm?.persistSigningSessionSealForThresholdSession;
      if (typeof exactPersistFn === 'function' && sealTransport) {
        // Use the high-level persist boundary after the ECDSA record exists; it
        // writes both the server seal and the local exact-purpose restore record.
        const persisted = await exactPersistFn({
          sessionId: materialActivationId,
          transport: {
            curve: sealTransport.curve,
            ...(sealTransport.walletId ? { walletId: sealTransport.walletId } : {}),
            chainTarget: sealTransport.chainTarget,
            relayerUrl: sealTransport.relayerUrl,
            ...(sealTransport.signingGrantId
              ? { signingGrantId: sealTransport.signingGrantId }
              : {}),
            ...(sealTransport.walletSessionJwt
              ? { walletSessionJwt: sealTransport.walletSessionJwt }
              : {}),
            ...(sealTransport.signingSessionSealKeyVersion
              ? { signingSessionSealKeyVersion: sealTransport.signingSessionSealKeyVersion }
              : {}),
            ...(sealTransport.groupId
              ? { groupId: sealTransport.groupId }
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
          sessionId: materialActivationId,
          transport: {
            curve: sealTransport.curve,
            ...(sealTransport.walletId ? { walletId: sealTransport.walletId } : {}),
            chainTarget: sealTransport.chainTarget,
            relayerUrl: sealTransport.relayerUrl,
            ...(sealTransport.signingGrantId
              ? { signingGrantId: sealTransport.signingGrantId }
              : {}),
            ...(sealTransport.walletSessionJwt
              ? { walletSessionJwt: sealTransport.walletSessionJwt }
              : {}),
            ...(sealTransport.signingSessionSealKeyVersion
              ? { signingSessionSealKeyVersion: sealTransport.signingSessionSealKeyVersion }
              : {}),
            ...(sealTransport.groupId
              ? { groupId: sealTransport.groupId }
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
