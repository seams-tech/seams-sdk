import type { WalletId } from '@shared/utils/domainIds';
import type { LaneShareEpoch, SigningLaneId, WalletKeyId } from '@shared/signing-lanes';
import type { PasskeyHolderShareEnvelopeRecord } from './holderShareEnvelope';

declare const walletId: WalletId;
declare const walletKeyId: WalletKeyId;
declare const laneId: SigningLaneId;
declare const laneShareEpoch: LaneShareEpoch;

const envelope: PasskeyHolderShareEnvelopeRecord = {
  kind: 'passkey_holder_share_envelope_v1',
  walletId,
  walletKeyId,
  laneId,
  laneShareEpoch,
  rpId: 'example.localhost',
  credentialIdB64u: 'credential',
  passkeyEnvelopeVersion: 'v1',
  passkeyKekVersion: 'v1',
  nonceB64u: 'nonce',
  sealedHolderShareB64u: 'ciphertext',
  aadHashB64u: 'aad',
  status: 'active',
  createdAtMs: 1,
  updatedAtMs: 1,
};
void envelope;

const invalidEnvelope: PasskeyHolderShareEnvelopeRecord = {
  kind: 'passkey_holder_share_envelope_v1',
  walletId,
  walletKeyId,
  laneId,
  laneShareEpoch,
  rpId: 'example.localhost',
  credentialIdB64u: 'credential',
  passkeyEnvelopeVersion: 'v1',
  passkeyKekVersion: 'v1',
  nonceB64u: 'nonce',
  sealedHolderShareB64u: 'ciphertext',
  aadHashB64u: 'aad',
  status: 'active',
  createdAtMs: 1,
  updatedAtMs: 1,
  // @ts-expect-error Passkey envelopes must not contain PRF output plaintext.
  passkeyPrfOutputB64u: 'prf',
};
void invalidEnvelope;

export {};
