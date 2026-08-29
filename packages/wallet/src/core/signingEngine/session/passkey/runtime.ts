import type { EcdsaSealTransportAuthMaterial } from '../persistence/sealedSessionTransportAuth';
import {
  thresholdEcdsaChainTargetKey,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ExactEcdsaSigningLaneIdentity } from '../identity/exactSigningLaneIdentity';
import type { ExactEvmFamilyWalletSessionAuthorization } from '../material/ecdsaSigningCapability';
import type { SealedSigningSessionEcdsaRestoreMetadata } from '@shared/utils/signingSessionSeal';
import type {
  WarmSessionSealPersister,
} from '../../uiConfirm/uiConfirm.types';

export type WarmSessionSealPersistPorts = Pick<
  WarmSessionSealPersister,
  'persistSigningSessionSealForThresholdSession'
>;

function walletIdForEcdsaSealTransport(args: {
  transport: EcdsaSealTransportAuthMaterial;
  lane: ExactEcdsaSigningLaneIdentity;
  restoreMetadata: Exclude<
    SealedSigningSessionEcdsaRestoreMetadata,
    { source: 'email_otp' }
  >;
}): string {
  const restoreWalletId = String(args.restoreMetadata.authority.walletId).trim();
  const laneWalletId = String(args.lane.signer.walletId).trim();
  const transportWalletId = String(args.transport.walletId).trim();
  if (
    !restoreWalletId ||
    !laneWalletId ||
    !transportWalletId ||
    laneWalletId !== restoreWalletId ||
    transportWalletId !== restoreWalletId
  ) {
    throw new Error(
      '[WarmSessionStore] ECDSA seal transport wallet does not match restore metadata',
    );
  }
  return transportWalletId;
}

export async function ensureEcdsaPrfSealPersisted(args: {
  sealPersistence: WarmSessionSealPersistPorts;
  lane: ExactEcdsaSigningLaneIdentity;
  authorization: ExactEvmFamilyWalletSessionAuthorization;
  thresholdSessionId: string;
  restoreMetadata: Exclude<
    SealedSigningSessionEcdsaRestoreMetadata,
    { source: 'email_otp' }
  >;
  required?: boolean;
  errorContext?: string;
  sealPersistInFlightByMaterialActivation: Map<string, Promise<void>>;
  resolveSealTransport: (args: {
    lane: ExactEcdsaSigningLaneIdentity;
    authorization: ExactEvmFamilyWalletSessionAuthorization;
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
        const walletId = walletIdForEcdsaSealTransport({
          transport: sealTransport,
          lane: args.lane,
          restoreMetadata: args.restoreMetadata,
        });
        const persisted =
          await args.sealPersistence.persistSigningSessionSealForThresholdSession({
          thresholdSessionId: args.thresholdSessionId,
          transport: {
            curve: sealTransport.curve,
            authMethod: 'passkey',
            walletId,
            chainTarget: sealTransport.chainTarget,
            relayerUrl: sealTransport.relayerUrl,
            ...(sealTransport.walletSessionToken
              ? { walletSessionToken: sealTransport.walletSessionToken }
              : {}),
            ...(sealTransport.signingSessionSealKeyVersion
              ? { signingSessionSealKeyVersion: sealTransport.signingSessionSealKeyVersion }
              : {}),
            ...(sealTransport.groupId
              ? { groupId: sealTransport.groupId }
              : {}),
            ecdsaRestore: args.restoreMetadata,
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
