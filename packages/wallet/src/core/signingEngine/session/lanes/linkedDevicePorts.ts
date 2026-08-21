import type {
  LaneProtocolCommitReceiptV1,
  RotatableSigningLaneJobV1,
} from '@shared/signing-lanes/rotation';
import type { DigestB64u } from '@shared/utils/canonicalPrimitives';
import type { MpcMaterialActivationRef } from '@shared/utils/domainIds';
import type { LaneSealedHolderRecordV1 } from '@/core/indexedDB/seamsWalletDB/laneHolderMaterialStore';
import type {
  RouterAbEcdsaSigningWorkerExportShareBindingV1,
  RouterAbEcdsaSigningWorkerExportShareEnvelopeV1,
} from '@shared/utils/routerAbEcdsaDerivation';

/** Opaque worker-owned holder material handles used by linked signing flows. */
export type DeviceLinkingHolderSigningMaterialHandleV1 =
  | {
      readonly kind: 'device_linking_holder_signing_material_handle_v1';
      readonly handleId: string;
      readonly keyFamily: 'ed25519';
    }
  | {
      readonly kind: 'device_linking_holder_signing_material_handle_v1';
      readonly handleId: string;
      readonly keyFamily: 'ecdsa_secp256k1';
    };

export type DeviceLinkingEd25519SigningShareV1 = {
  readonly clientCommitments: {
    readonly hiding: string;
    readonly binding: string;
  };
  readonly clientVerifyingShareB64u: string;
  readonly clientSignatureShareB64u: string;
};

export type DeviceLinkingEcdsaExportRecipientV1 = {
  readonly kind: 'device_linking_ecdsa_export_recipient_v1';
  readonly recipientHandleId: string;
  readonly recipientIdentity: string;
  readonly recipientPublicKeyB64u: string;
};

export type DeviceLinkingEcdsaExportPublicFactsV1 = {
  readonly walletId: string;
  readonly walletKeyId: string;
  readonly enrollmentId: string;
  readonly operationId: string;
  readonly laneId: string;
  readonly laneShareEpoch: string;
  readonly targetMaterialActivationId: string;
  readonly ecdsaThresholdKeyId: string;
  readonly thresholdPublicKey33B64u: string;
  readonly evmAddress: string;
  readonly targetHolderPublicCommitment33B64u: string;
  readonly targetServerPublicCommitment33B64u: string;
  readonly publicIdentityDigestB64u: string;
};

export type DeviceLinkingEcdsaExportArtifactV1 = {
  readonly publicKeyHex: string;
  readonly privateKeyHex: string;
  readonly ethereumAddress: string;
};

export type DeviceLinkingHolderSigningMaterialPortV1 = {
  openPersistedHolderSigningMaterialV1(input: {
    readonly factorSecret: ArrayBuffer;
    readonly job: RotatableSigningLaneJobV1;
    readonly protocolCommitReceipt: LaneProtocolCommitReceiptV1;
    readonly materialActivation: MpcMaterialActivationRef;
    readonly holderRecord: LaneSealedHolderRecordV1;
  }): Promise<DeviceLinkingHolderSigningMaterialHandleV1>;
  createEd25519HolderSigningShareV1(input: {
    readonly handle: Extract<
      DeviceLinkingHolderSigningMaterialHandleV1,
      { readonly keyFamily: 'ed25519' }
    >;
    readonly admittedDigestB64u: DigestB64u;
    readonly signingWorkerCommitments: {
      readonly hiding: string;
      readonly binding: string;
    };
    readonly signingWorkerVerifyingShareB64u: string;
  }): Promise<DeviceLinkingEd25519SigningShareV1>;
  prepareEcdsaExportRecipientV1(input: {
    readonly handle: Extract<
      DeviceLinkingHolderSigningMaterialHandleV1,
      { readonly keyFamily: 'ecdsa_secp256k1' }
    >;
    readonly operationId: string;
  }): Promise<DeviceLinkingEcdsaExportRecipientV1>;
  finalizeEcdsaExportV1(input: {
    readonly handle: Extract<
      DeviceLinkingHolderSigningMaterialHandleV1,
      { readonly keyFamily: 'ecdsa_secp256k1' }
    >;
    readonly recipientHandleId: string;
    readonly signingWorkerExport: RouterAbEcdsaSigningWorkerExportShareEnvelopeV1;
    readonly expectedBinding: RouterAbEcdsaSigningWorkerExportShareBindingV1;
    readonly expectedPublicFacts: DeviceLinkingEcdsaExportPublicFactsV1;
  }): Promise<DeviceLinkingEcdsaExportArtifactV1>;
  discardHolderSigningMaterialV1(input: {
    readonly handle: DeviceLinkingHolderSigningMaterialHandleV1;
  }): Promise<void>;
};
