import type { LaneShareEpoch, SigningLaneId, WalletKeyId } from '@shared/signing-lanes';
import type { WalletId } from '@shared/utils/domainIds';

declare const passkeyEnvelopeIdBrand: unique symbol;

export type PasskeyEnvelopeId = string & {
  readonly [passkeyEnvelopeIdBrand]: 'PasskeyEnvelopeId';
};

export type PasskeyDeviceEnvelopeIndexRecord = {
  kind: 'passkey_device_envelope_index_v1';
  walletId: WalletId;
  walletKeyId: WalletKeyId;
  laneId: SigningLaneId;
  laneShareEpoch: LaneShareEpoch;
  credentialIdB64u: string;
  rpId: string;
  deviceLabel: string;
  envelopeId: PasskeyEnvelopeId;
  status: 'active' | 'retired' | 'revoked';
  createdAtMs: number;
  updatedAtMs: number;
};
