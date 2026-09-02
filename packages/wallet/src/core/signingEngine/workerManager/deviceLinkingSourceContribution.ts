import type {
  LinkedDeviceEd25519SourceContributionPreparationV1,
  LinkedDeviceEd25519SourceContributionV1,
  LinkedDeviceEcdsaSourceContributionPreparationV1,
  LinkedDeviceEcdsaSourceContributionV1,
  LinkedDeviceEcdsaSourceDerivationV1,
} from '@shared/device-linking/sourceContribution';
import type { LinkedDeviceOwnerAuthorizationSourceV1 } from '@shared/device-linking/contracts';
import { parseLinkedDeviceEd25519SourcePreservingReservationV1 } from '@shared/device-linking/sourceContribution';
import type { MpcMaterialActivationRef, WalletKeyId } from '@shared/utils/domainIds';
import { mpcMaterialActivationRefsEqual, parseWalletKeyId } from '@shared/utils/domainIds';
import { deriveEvmFamilySigningKeySlotId } from '@shared/signing-lanes';
import { base64UrlEncode } from '@shared/utils/base64';
import { parseDigestB64u, type DigestB64u } from '@shared/utils/canonicalPrimitives';
import { parseEcdsaThresholdKeyId } from '../session/keyMaterialBrands';
import { deriveRouterAbEd25519YaoApplicationBindingDigestV1 } from '@shared/utils/routerAbEd25519Yao';
import type { ActiveEcdsaCapabilityManifest } from '../session/material/ecdsaCapabilityManifest';
import { prepareLinkedDeviceEcdsaSourceContributionWasm } from '../threshold/crypto/ecdsaDerivationClientWasm';
import { openEd25519YaoLaneWorkerSourceFromUnlockedCapabilityV1 } from '../threshold/crypto/ed25519YaoLaneWasm';
import type { WorkerOperationContext } from './executeWorkerOperation';
import type { UnlockedWalletEd25519ExportRootCapabilityV1 } from './workerTypes';

export type DeviceLinkingSourceRequestAuthenticationV1 = {
  readonly kind: 'link_session_authenticated_request_v1';
  readonly source: LinkedDeviceOwnerAuthorizationSourceV1;
  readonly proofDigestB64u: DigestB64u;
};

export type DeviceLinkingEd25519SourceContributionRuntimePortV1 = {
  produceSourceContributionV1(input: {
    readonly preparation: LinkedDeviceEd25519SourceContributionPreparationV1;
    readonly capability: UnlockedWalletEd25519ExportRootCapabilityV1;
    readonly authentication: DeviceLinkingSourceRequestAuthenticationV1;
  }): Promise<LinkedDeviceEd25519SourceContributionV1>;
};

export type DeviceLinkingEcdsaSourceContributionRuntimePortV1 = {
  produceSourceContributionV1(input: {
    readonly preparation: LinkedDeviceEcdsaSourceContributionPreparationV1;
  }): Promise<LinkedDeviceEcdsaSourceContributionV1>;
};

export type DeviceLinkingSourceContributionRuntimePortV1 = {
  readonly ed25519: DeviceLinkingEd25519SourceContributionRuntimePortV1;
  readonly ecdsa: DeviceLinkingEcdsaSourceContributionRuntimePortV1;
};

export type DeviceLinkingEcdsaSourceContributionMetadataV1 = {
  readonly walletKeyId: WalletKeyId;
  readonly sourceDerivation: LinkedDeviceEcdsaSourceDerivationV1;
};

export type DeviceLinkingEcdsaSourceContributionMetadataReaderV1 = (input: {
  readonly preparation: LinkedDeviceEcdsaSourceContributionPreparationV1;
}) => Promise<DeviceLinkingEcdsaSourceContributionMetadataV1>;

export type DeviceLinkingEcdsaSourceContributionMetadataContextV1 = {
  readonly readActiveEcdsaCapabilityManifestV1: (input: {
    readonly materialActivation: MpcMaterialActivationRef;
  }) => Promise<ActiveEcdsaCapabilityManifest>;
};

export function createDeviceLinkingEcdsaSourceContributionMetadataReaderV1(
  context: DeviceLinkingEcdsaSourceContributionMetadataContextV1,
): DeviceLinkingEcdsaSourceContributionMetadataReaderV1 {
  return async ({ preparation }) => {
    const sourceActivation = preparation.source.activation;
    const manifest = await context.readActiveEcdsaCapabilityManifestV1({
      materialActivation: sourceActivation,
    });
    assertExactEcdsaSourceMetadataContextV1({
      sourceActivation,
      manifest,
    });
    return {
      walletKeyId: walletKeyIdForActiveManifestV1(manifest),
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
  readonly manifest: ActiveEcdsaCapabilityManifest;
}): void {
  if (
    !mpcMaterialActivationRefsEqual(
      input.manifest.activation.materialActivation,
      input.sourceActivation,
    )
  ) {
    throw new Error('ECDSA capability manifest activation does not match preparation');
  }
}

function walletKeyIdForActiveManifestV1(manifest: ActiveEcdsaCapabilityManifest): WalletKeyId {
  const signingKeySlotId = deriveEvmFamilySigningKeySlotId({
    walletId: manifest.signer.walletId,
    signingRootId: manifest.signer.signingRootId,
    signingRootVersion: manifest.signer.signingRootVersion,
  });
  const parsed = parseWalletKeyId(
    `wallet-key:ecdsa:${manifest.signer.walletId}:${signingKeySlotId}`,
  );
  if (!parsed.ok) throw new Error(`ECDSA source wallet key identity: ${parsed.error.message}`);
  return parsed.value;
}

export type DeviceLinkingSourceContributionPortFactoryInputV1 = {
  readonly workerContext: WorkerOperationContext;
  readonly ed25519: DeviceLinkingEd25519SourceContributionRuntimePortV1;
  readonly readEcdsaMetadataV1: DeviceLinkingEcdsaSourceContributionMetadataReaderV1;
};

export type DeviceLinkingEd25519SourceContributionPortFactoryInputV1 = {
  readonly workerContext: WorkerOperationContext;
  readonly executeSourcePreservingV1: (input: {
    readonly linkSessionId: LinkedDeviceEd25519SourceContributionPreparationV1['linkSessionId'];
    readonly sourceBinding: LinkedDeviceEd25519SourceContributionPreparationV1['sourceBinding'];
    readonly targetRequestJson: string;
    readonly participantIds: readonly [number, number];
    readonly authentication: DeviceLinkingSourceRequestAuthenticationV1;
  }) => Promise<unknown>;
};

export function createDeviceLinkingEd25519SourceContributionPortV1(
  input: DeviceLinkingEd25519SourceContributionPortFactoryInputV1,
): DeviceLinkingEd25519SourceContributionRuntimePortV1 {
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
): DeviceLinkingSourceContributionRuntimePortV1 {
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
