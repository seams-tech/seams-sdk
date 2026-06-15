import type { LaneShareEpoch, SigningLaneId, WalletKeyId } from '@shared/signing-lanes';
import type { WalletId } from '@shared/utils/domainIds';

export type PasskeyHolderShareEnvelopeRecord = {
  kind: 'passkey_holder_share_envelope_v1';
  walletId: WalletId;
  walletKeyId: WalletKeyId;
  laneId: SigningLaneId;
  laneShareEpoch: LaneShareEpoch;
  rpId: string;
  credentialIdB64u: string;
  passkeyEnvelopeVersion: string;
  passkeyKekVersion: string;
  nonceB64u: string;
  sealedHolderShareB64u: string;
  aadHashB64u: string;
  status: 'active' | 'retired' | 'revoked';
  createdAtMs: number;
  updatedAtMs: number;
};
