import type { LaneShareEpoch, SigningLaneId, WalletKeyId } from '../signing-lanes/ids';
import type {
  PasskeyEnvelopeId,
  WalletId,
  WebAuthnCredentialIdB64u,
  WebAuthnRpId,
} from '../utils/domainIds';
import type { PasskeyCustodyEnvelopeLifecycle } from './custodyEnvelope';
import type { PasskeyCustodySecretKind } from './custodySecretBinding';

/**
 * Public listing row for credential management: which credential protects which
 * lane, and under which envelope. It holds no ciphertext, so listing a wallet's
 * passkeys never moves sealed custody material.
 */
export type PasskeyDeviceEnvelopeIndexRecord = {
  kind: 'passkey_device_envelope_index_v1';
  walletId: WalletId;
  walletKeyId: WalletKeyId;
  laneId: SigningLaneId;
  laneShareEpoch: LaneShareEpoch;
  custodySecretKind: PasskeyCustodySecretKind;
  credentialIdB64u: WebAuthnCredentialIdB64u;
  rpId: WebAuthnRpId;
  deviceLabel: string;
  envelopeId: PasskeyEnvelopeId;
  lifecycle: PasskeyCustodyEnvelopeLifecycle;
  createdAtMs: number;
  updatedAtMs: number;
};
