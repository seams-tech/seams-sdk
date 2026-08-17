import type {
  LaneEnrollmentId,
  LaneOperationId,
  LaneShareEpoch,
  SigningLaneId,
  WalletKeyId,
} from '@shared/signing-lanes';
import type { DigestB64u } from '@shared/utils/canonicalPrimitives';
import type { MpcMaterialActivationId, WalletId } from '@shared/utils/domainIds';

export type SigningWorkerLaneMaterialIdentityV1<
  TKeyFamily extends 'ed25519' | 'ecdsa_secp256k1' =
    | 'ed25519'
    | 'ecdsa_secp256k1',
> = {
  readonly operationId: LaneOperationId;
  readonly enrollmentId: LaneEnrollmentId;
  readonly walletId: WalletId;
  readonly walletKeyId: WalletKeyId;
  readonly targetLaneId: SigningLaneId;
  readonly targetLaneShareEpoch: LaneShareEpoch;
  readonly targetMaterialActivationId: MpcMaterialActivationId;
  readonly keyFamily: TKeyFamily;
  readonly holderParticipantBindingDigestB64u: DigestB64u;
  readonly signingWorkerParticipantBindingDigestB64u: DigestB64u;
  readonly holderRecipientKeyDigestB64u: DigestB64u;
  readonly serverRecipientKeyDigestB64u: DigestB64u;
  readonly transcriptHashB64u: DigestB64u;
  readonly protocolCommitReceiptDigestB64u: DigestB64u;
};

export type EcdsaSigningWorkerLaneMaterialIdentityV1 =
  SigningWorkerLaneMaterialIdentityV1<'ecdsa_secp256k1'>;
