import type {
  LaneProtocolCommitReceiptV1,
  RotatableSigningLaneJobV1,
} from '@shared/signing-lanes/rotation';
import type { DigestB64u } from '@shared/utils/canonicalPrimitives';
import type { MpcMaterialActivationRef } from '@shared/utils/domainIds';
import type { LaneSealedHolderRecordV1 } from '@/core/indexedDB/seamsWalletDB/laneHolderMaterialStore';

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
  discardHolderSigningMaterialV1(input: {
    readonly handle: DeviceLinkingHolderSigningMaterialHandleV1;
  }): Promise<void>;
};
