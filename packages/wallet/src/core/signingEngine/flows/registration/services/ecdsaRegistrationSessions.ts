import type {
  WalletRegistrationEcdsaDerivationRespondBootstrap,
  WalletRegistrationEcdsaWalletKey,
} from '@/core/rpcClients/relayer/walletRegistration';
import {
  thresholdEcdsaChainTargetKey,
  toWalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { FinalizeRouterAbEcdsaRegistrationActivationResultV1 } from '@/core/signingEngine/routerAb/ecdsaDerivation/clientCeremony';
import { buildEcdsaRoleLocalPublicFacts } from '@/core/signingEngine/session/persistence/ecdsaRoleLocalRecords';
import {
  parseEcdsaRoleLocalPersistedMaterialRef,
  type EcdsaRoleLocalPersistedMaterialRef,
} from '@/core/signingEngine/session/keyMaterialBrands';
import type { StoreWalletEcdsaWalletKey } from '../accountLifecycle';

export type FinalizeWalletRegistrationEcdsaFamilySession = {
  chainTargets: readonly [
    WalletRegistrationEcdsaWalletKey['chainTarget'],
    ...WalletRegistrationEcdsaWalletKey['chainTarget'][],
  ];
  authority: FinalizeRouterAbEcdsaRegistrationActivationResultV1['authority'];
  bootstrap: Pick<
    WalletRegistrationEcdsaDerivationRespondBootstrap,
    'applicationBindingDigestB64u'
  >;
  roleLocalMaterial: FinalizeRouterAbEcdsaRegistrationActivationResultV1['roleLocalMaterial'];
  materialActivation: FinalizeRouterAbEcdsaRegistrationActivationResultV1['materialActivation'];
  clientPublicFacts: FinalizeRouterAbEcdsaRegistrationActivationResultV1['publicFacts'];
  publicCapability: FinalizeRouterAbEcdsaRegistrationActivationResultV1['publicCapability'];
};

export type FinalizeWalletRegistrationEcdsaSessionsInput = {
  walletId: string;
  session: FinalizeWalletRegistrationEcdsaFamilySession;
  walletKeys: readonly [WalletRegistrationEcdsaWalletKey, ...WalletRegistrationEcdsaWalletKey[]];
};

function sessionTargetsMatchWalletKeys(args: {
  session: FinalizeWalletRegistrationEcdsaFamilySession;
  walletKeys: FinalizeWalletRegistrationEcdsaSessionsInput['walletKeys'];
}): boolean {
  if (args.session.chainTargets.length !== args.walletKeys.length) return false;
  return args.walletKeys.every((walletKey, index) => {
    const sessionTarget = args.session.chainTargets[index];
    return (
      sessionTarget !== undefined &&
      thresholdEcdsaChainTargetKey(sessionTarget) ===
        thresholdEcdsaChainTargetKey(walletKey.chainTarget)
    );
  });
}

function storeWalletEcdsaKeyWithRoleLocalMaterial(args: {
  walletKey: WalletRegistrationEcdsaWalletKey;
  publicFacts: ReturnType<typeof buildEcdsaRoleLocalPublicFacts>;
  materialRef: EcdsaRoleLocalPersistedMaterialRef;
}): StoreWalletEcdsaWalletKey {
  const walletKey = args.walletKey;
  return {
    keyScope: walletKey.keyScope,
    chainTarget: walletKey.chainTarget,
    walletId: walletKey.walletId,
    evmFamilySigningKeySlotId: walletKey.evmFamilySigningKeySlotId,
    keyHandle: walletKey.keyHandle,
    ecdsaThresholdKeyId: walletKey.ecdsaThresholdKeyId,
    signingRootId: walletKey.signingRootId,
    signingRootVersion: walletKey.signingRootVersion,
    thresholdEcdsaPublicKeyB64u: walletKey.thresholdEcdsaPublicKeyB64u,
    thresholdOwnerAddress: walletKey.thresholdOwnerAddress,
    relayerKeyId: walletKey.relayerKeyId,
    relayerVerifyingShareB64u: walletKey.relayerVerifyingShareB64u,
    participantIds: walletKey.participantIds,
    publicCapability: walletKey.publicCapability,
    roleLocalMaterialRef: args.materialRef,
    ecdsaRoleLocalPublicFacts: args.publicFacts,
  };
}

export async function finalizeWalletRegistrationEcdsaSessions(
  input: FinalizeWalletRegistrationEcdsaSessionsInput,
): Promise<readonly [StoreWalletEcdsaWalletKey, ...StoreWalletEcdsaWalletKey[]]> {
  if (!sessionTargetsMatchWalletKeys({ session: input.session, walletKeys: input.walletKeys })) {
    throw new Error(
      '[SigningEngine] strict ECDSA registration requires one family activation projected to every wallet target',
    );
  }
  const walletId = toWalletId(input.walletId);
  if (input.session.authority.walletId !== walletId) {
    throw new Error(
      '[SigningEngine] strict ECDSA registration authority does not match the target wallet',
    );
  }
  const workerHandle = input.session.roleLocalMaterial;
  const materialRef = parseEcdsaRoleLocalPersistedMaterialRef({
    kind: 'ecdsa_role_local_persisted_material_ref_v1',
    durableMaterialRef: workerHandle.durableMaterialRef,
    bindingDigest: workerHandle.bindingDigest,
    materialActivation: input.session.materialActivation,
  });
  const storedWalletKeys = input.walletKeys.map((walletKey) => {
    const publicFacts = buildEcdsaRoleLocalPublicFacts({
      walletId,
      chainTarget: walletKey.chainTarget,
      keyHandle: walletKey.keyHandle,
      ecdsaThresholdKeyId: walletKey.ecdsaThresholdKeyId,
      signingRootId: walletKey.signingRootId,
      signingRootVersion: walletKey.signingRootVersion,
      applicationBindingDigestB64u: input.session.bootstrap.applicationBindingDigestB64u,
      clientParticipantId: 1,
      relayerParticipantId: 2,
      participantIds: walletKey.participantIds,
      contextBinding32B64u: input.session.clientPublicFacts.contextBinding32B64u,
      derivationClientSharePublicKey33B64u:
        input.session.clientPublicFacts.derivationClientSharePublicKey33B64u,
      relayerPublicKey33B64u: input.session.clientPublicFacts.relayerPublicKey33B64u,
      groupPublicKey33B64u: input.session.clientPublicFacts.groupPublicKey33B64u,
      ethereumAddress: input.session.clientPublicFacts.ethereumAddress,
      publicCapability: input.session.publicCapability,
    });
    return storeWalletEcdsaKeyWithRoleLocalMaterial({ walletKey, publicFacts, materialRef });
  });
  const [firstStoredWalletKey, ...remainingStoredWalletKeys] = storedWalletKeys;
  if (!firstStoredWalletKey) {
    throw new Error('[SigningEngine] strict ECDSA registration did not persist any wallet keys');
  }
  return [firstStoredWalletKey, ...remainingStoredWalletKeys];
}
