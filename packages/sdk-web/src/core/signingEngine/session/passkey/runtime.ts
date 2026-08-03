import type { EcdsaSealTransportAuthMaterial } from '../persistence/sealedSessionTransportAuth';
import {
  thresholdEcdsaChainTargetKey,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ExactEcdsaSigningLaneIdentity } from '../identity/exactSigningLaneIdentity';
import type { ActiveEvmFamilyWalletSessionAuthorization } from '../material/ecdsaSigningCapability';
import type {
  WarmSessionSealPersister,
} from '../../uiConfirm/uiConfirm.types';

export type WarmSessionSealPersistPorts = Pick<
  WarmSessionSealPersister,
  'persistSigningSessionSealForThresholdSession'
>;

export async function ensureEcdsaPrfSealPersisted(args: {
  sealPersistence: WarmSessionSealPersistPorts;
  lane: ExactEcdsaSigningLaneIdentity;
  authorization: ActiveEvmFamilyWalletSessionAuthorization;
  thresholdSessionId: string;
  required?: boolean;
  errorContext?: string;
  sealPersistInFlightByMaterialActivation: Map<string, Promise<void>>;
  resolveSealTransport: (args: {
    lane: ExactEcdsaSigningLaneIdentity;
    authorization: ActiveEvmFamilyWalletSessionAuthorization;
  }) => Promise<EcdsaSealTransportAuthMaterial | null>;
}): Promise<void> {
  const materialActivationId = String(
    args.lane.signer.materialActivation.activationId,
  ).trim();
  if (!materialActivationId) return;
  const persistKey = `${materialActivationId}:${thresholdEcdsaChainTargetKey(args.lane.signer.chainTarget)}`;
  let persistPromise = args.sealPersistInFlightByMaterialActivation.get(persistKey);
  if (!persistPromise) {
    persistPromise = (async (): Promise<void> => {
      const errorContext = String(args.errorContext || 'threshold session seal persistence').trim();
      const sealTransport = await args.resolveSealTransport({
        lane: args.lane,
        authorization: args.authorization,
      });
      if (sealTransport) {
        const persisted =
          await args.sealPersistence.persistSigningSessionSealForThresholdSession({
          thresholdSessionId: args.thresholdSessionId,
          transport: {
            curve: sealTransport.curve,
            ...(sealTransport.walletId ? { walletId: sealTransport.walletId } : {}),
            chainTarget: sealTransport.chainTarget,
            relayerUrl: sealTransport.relayerUrl,
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
    })();
    args.sealPersistInFlightByMaterialActivation.set(persistKey, persistPromise);
    void persistPromise.then(
      () => {
        if (args.sealPersistInFlightByMaterialActivation.get(persistKey) === persistPromise) {
          args.sealPersistInFlightByMaterialActivation.delete(persistKey);
        }
      },
      () => {
        if (args.sealPersistInFlightByMaterialActivation.get(persistKey) === persistPromise) {
          args.sealPersistInFlightByMaterialActivation.delete(persistKey);
        }
      },
    );
  }
  await persistPromise;
}
