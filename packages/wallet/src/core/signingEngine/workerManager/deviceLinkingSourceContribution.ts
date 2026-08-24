import type {
  LinkedDeviceEd25519SourceContributionPreparationV1,
  LinkedDeviceEd25519SourceContributionV1,
  LinkedDeviceEcdsaSourceContributionPreparationV1,
  LinkedDeviceEcdsaSourceContributionV1,
  LinkedDeviceEcdsaSourceDerivationV1,
} from '@shared/device-linking/sourceContribution';
import type { LinkedDeviceOwnerSourceLaneV1 } from '@shared/device-linking/contracts';
import { parseLinkedDeviceEd25519SourcePreservingReservationV1 } from '@shared/device-linking/sourceContribution';
import type { MpcMaterialActivationRef, WalletKeyId } from '@shared/utils/domainIds';
import { mpcMaterialActivationRefsEqual } from '@shared/utils/domainIds';
import { base64UrlEncode } from '@shared/utils/base64';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import { parseEcdsaThresholdKeyId } from '../session/keyMaterialBrands';
import { deriveRouterAbEd25519YaoApplicationBindingDigestV1 } from '@shared/utils/routerAbEd25519Yao';
import type { ActiveEcdsaCapabilityManifest } from '../session/material/ecdsaCapabilityManifest';
import { prepareLinkedDeviceEcdsaSourceContributionWasm } from '../threshold/crypto/ecdsaDerivationClientWasm';
import { openEd25519YaoLaneWorkerSourceFromUnlockedCapabilityV1 } from '../threshold/crypto/ed25519YaoLaneWasm';
import type { WorkerOperationContext } from './executeWorkerOperation';
import type {
  DeviceLinkingEd25519SourceContributionPortV1,
  DeviceLinkingSourceContributionPortV1,
} from '@/SeamsWeb/operations/devices/deviceLinkingPorts';
import type { LinkSessionAuthenticationV1 } from '@/SeamsWeb/operations/devices/deviceLinkingPorts';

export type DeviceLinkingEcdsaSourceContributionMetadataV1 = {
  readonly walletKeyId: WalletKeyId;
  readonly sourceDerivation: LinkedDeviceEcdsaSourceDerivationV1;
};

export type DeviceLinkingEcdsaSourceContributionMetadataReaderV1 = (input: {
  readonly preparation: LinkedDeviceEcdsaSourceContributionPreparationV1;
}) => Promise<DeviceLinkingEcdsaSourceContributionMetadataV1>;

/**
 * The source lane and manifest are read independently by the active browser
 * surface. The activation is the join key; callers must not select a sibling
 * owner lane or a replacement manifest when the exact activation is absent.
 */
export type DeviceLinkingEcdsaSourceContributionMetadataContextV1 = {
  readonly readActiveOwnerSourceLaneV1: (input: {
    readonly materialActivation: MpcMaterialActivationRef;
  }) => Promise<LinkedDeviceOwnerSourceLaneV1>;
  readonly readActiveEcdsaCapabilityManifestV1: (input: {
    readonly materialActivation: MpcMaterialActivationRef;
  }) => Promise<ActiveEcdsaCapabilityManifest>;
};

export function createDeviceLinkingEcdsaSourceContributionMetadataReaderV1(
  context: DeviceLinkingEcdsaSourceContributionMetadataContextV1,
): DeviceLinkingEcdsaSourceContributionMetadataReaderV1 {
  return async ({ preparation }) => {
    const sourceActivation = preparation.source.activation;
    const [ownerLane, manifest] = await Promise.all([
      context.readActiveOwnerSourceLaneV1({ materialActivation: sourceActivation }),
      context.readActiveEcdsaCapabilityManifestV1({ materialActivation: sourceActivation }),
    ]);
    assertExactEcdsaSourceMetadataContextV1({
      sourceActivation,
      ownerLane,
      manifest,
    });
    return {
      walletKeyId: ownerLane.walletKey.walletKeyId,
      sourceDerivation: {
        applicationBindingDigestB64u: parseDigestB64u(
          manifest.durableMaterial.routerAbEcdsaDerivationNormalSigning.scope.context
            .application_binding_digest_b64u,
        ),
        clientShareRetryCounter:
          manifest.durableMaterial.routerAbEcdsaDerivationNormalSigning.scope.public_identity
            .client_share_retry_counter,
        ecdsaThresholdKeyId: parseEcdsaThresholdKeyId(
          manifest.durableMaterial.roleLocalBinding.ecdsaThresholdKeyId,
        ),
        sourceNormalSigning: manifest.durableMaterial.routerAbEcdsaDerivationNormalSigning,
      },
    };
  };
}

function assertExactEcdsaSourceMetadataContextV1(input: {
  readonly sourceActivation: MpcMaterialActivationRef;
  readonly ownerLane: LinkedDeviceOwnerSourceLaneV1;
  readonly manifest: ActiveEcdsaCapabilityManifest;
}): void {
  if (input.ownerLane.keyFamily !== 'ecdsa_secp256k1') {
    throw new Error('ECDSA source metadata resolved a non-ECDSA owner lane');
  }
  if (!mpcMaterialActivationRefsEqual(input.ownerLane.materialActivation, input.sourceActivation)) {
    throw new Error('ECDSA owner source lane activation does not match preparation');
  }
  if (
    !mpcMaterialActivationRefsEqual(
      input.manifest.activation.materialActivation,
      input.sourceActivation,
    )
  ) {
    throw new Error('ECDSA capability manifest activation does not match preparation');
  }
  if (input.manifest.signer.walletId !== input.ownerLane.walletKey.walletId) {
    throw new Error('ECDSA source owner lane and capability manifest wallet identities differ');
  }
  if (
    String(input.ownerLane.walletKey.thresholdPublicKey33B64u) !==
    String(input.manifest.signer.registeredPublicFacts.publicKeyB64u)
  ) {
    throw new Error('ECDSA source owner lane and capability manifest public keys differ');
  }
  if (
    input.ownerLane.walletKey.evmAddress !==
    input.manifest.signer.registeredPublicFacts.thresholdOwnerAddress
  ) {
    throw new Error('ECDSA source owner lane and capability manifest addresses differ');
  }
}

export type DeviceLinkingSourceContributionPortFactoryInputV1 = {
  readonly workerContext: WorkerOperationContext;
  readonly ed25519: DeviceLinkingEd25519SourceContributionPortV1;
  readonly readEcdsaMetadataV1: DeviceLinkingEcdsaSourceContributionMetadataReaderV1;
};

export type DeviceLinkingEd25519SourceContributionPortFactoryInputV1 = {
  readonly workerContext: WorkerOperationContext;
  readonly executeSourcePreservingV1: (input: {
    readonly linkSessionId: LinkedDeviceEd25519SourceContributionPreparationV1['linkSessionId'];
    readonly sourceBinding: LinkedDeviceEd25519SourceContributionPreparationV1['sourceBinding'];
    readonly targetRequestJson: string;
    readonly participantIds: readonly [number, number];
    readonly authentication: LinkSessionAuthenticationV1;
  }) => Promise<unknown>;
};

export function createDeviceLinkingEd25519SourceContributionPortV1(
  input: DeviceLinkingEd25519SourceContributionPortFactoryInputV1,
): DeviceLinkingEd25519SourceContributionPortV1 {
  return {
    produceSourceContributionV1: async ({ preparation, capability, authentication }) => {
      const source = await openEd25519YaoLaneWorkerSourceFromUnlockedCapabilityV1({
        workerCtx: input.workerContext,
        capability,
        applicationBindingDigestB64u: await applicationBindingDigestB64uV1(
          preparation.applicationBinding,
        ),
        walletKeyId: String(preparation.walletKeyId),
        enrollmentId: String(preparation.enrollmentId),
        revocationEpoch: preparation.sourceRevocationEpoch,
        registeredPublicKeyB64u: preparation.sourceRegisteredPublicKeyB64u,
      });
      try {
        const prepared = await source.prepareSourcePreservingRegistration({
          targetAdmission: preparation.targetAdmission,
          applicationBinding: preparation.applicationBinding,
          participantIds: preparation.participantIds,
          expectedRegisteredPublicKeyB64u: preparation.sourceRegisteredPublicKeyB64u,
          targetClientRecipientPublicKeyB64u: preparation.targetClientRecipientPublicKeyB64u,
        });
        const reservation = parseLinkedDeviceEd25519SourcePreservingReservationV1(
          await input.executeSourcePreservingV1({
            linkSessionId: preparation.linkSessionId,
            sourceBinding: preparation.sourceBinding,
            targetRequestJson: prepared.requestJson,
            participantIds: preparation.participantIds,
            authentication,
          }),
        );
        return {
          kind: 'linked_device_ed25519_source_contribution_v1',
          keyFamily: 'ed25519',
          linkSessionId: preparation.linkSessionId,
          enrollmentId: preparation.enrollmentId,
          sourceAuthorityId: preparation.sourceAuthorityId,
          walletKeyId: preparation.walletKeyId,
          targetDeviceId: preparation.targetDeviceId,
          targetFactorVerificationDigestB64u: preparation.targetFactorVerificationDigestB64u,
          targetMaterialActivation: preparation.targetMaterialActivation,
          targetClientRecipientPublicKeyB64u: preparation.targetClientRecipientPublicKeyB64u,
          targetSigningWorkerRecipientPublicKeyB64u:
            preparation.targetSigningWorkerRecipientPublicKeyB64u,
          sourceRegisteredPublicKeyB64u: preparation.sourceRegisteredPublicKeyB64u,
          sourceBinding: preparation.sourceBinding,
          reservationId: reservation.reservationId,
          targetBinding: preparation.targetAdmission.binding,
          activationReceipt: reservation.activationReceipt,
          participantIds: reservation.participantIds,
          deriver_a_client_package: reservation.deriver_a_client_package,
          deriver_b_client_package: reservation.deriver_b_client_package,
        };
      } finally {
        await source.discard();
      }
    },
  };
}

export function createDeviceLinkingSourceContributionPortV1(
  input: DeviceLinkingSourceContributionPortFactoryInputV1,
): DeviceLinkingSourceContributionPortV1 {
  return {
    ed25519: input.ed25519,
    ecdsa: {
      produceSourceContributionV1: async ({ preparation }) =>
        await produceEcdsaSourceContributionV1({
          workerContext: input.workerContext,
          readMetadataV1: input.readEcdsaMetadataV1,
          preparation,
        }),
    },
  };
}

async function produceEcdsaSourceContributionV1(input: {
  readonly workerContext: WorkerOperationContext;
  readonly readMetadataV1: DeviceLinkingEcdsaSourceContributionMetadataReaderV1;
  readonly preparation: LinkedDeviceEcdsaSourceContributionPreparationV1;
}): Promise<LinkedDeviceEcdsaSourceContributionV1> {
  const metadata = await input.readMetadataV1({ preparation: input.preparation });
  const prepared = await prepareLinkedDeviceEcdsaSourceContributionWasm({
    preparation: input.preparation,
    workerCtx: input.workerContext,
  });
  return {
    kind: 'linked_device_ecdsa_source_contribution_v1',
    keyFamily: 'ecdsa_secp256k1',
    linkSessionId: input.preparation.linkSessionId,
    enrollmentId: input.preparation.enrollmentId,
    sourceAuthorityId: input.preparation.sourceAuthorityId,
    walletKeyId: metadata.walletKeyId,
    targetDeviceId: input.preparation.target.targetDeviceId,
    targetFactorVerificationDigestB64u: input.preparation.target.targetFactorVerificationDigestB64u,
    sourceSigner: input.preparation.source,
    sourceDerivation: metadata.sourceDerivation,
    target: input.preparation.target,
    package: prepared.package,
  };
}

async function applicationBindingDigestB64uV1(
  applicationBinding: LinkedDeviceEd25519SourceContributionPreparationV1['applicationBinding'],
): Promise<string> {
  return base64UrlEncode(
    Uint8Array.from(await deriveRouterAbEd25519YaoApplicationBindingDigestV1(applicationBinding)),
  );
}
