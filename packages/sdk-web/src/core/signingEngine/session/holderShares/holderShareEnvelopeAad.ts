import { alphabetizeStringify, sha256BytesUtf8 } from '@shared/utils/digests';
import { base64UrlEncode } from '@shared/utils/encoders';
import type { LaneShareEpoch, SigningLaneId, WalletKeyId } from '@shared/signing-lanes';
import type { WalletId } from '@shared/utils/domainIds';

export type SealedHolderShareEnvelopeAad = {
  kind: 'sealed_holder_share_envelope_aad_v1';
  walletId: WalletId;
  walletKeyId: WalletKeyId;
  laneId: SigningLaneId;
  laneShareEpoch: LaneShareEpoch;
  holderShareCommitmentB64u: string;
  envelopeKind: string;
  envelopeVersion: string;
};

export async function computeSealedHolderShareEnvelopeAadHash(
  aad: SealedHolderShareEnvelopeAad,
): Promise<string> {
  return base64UrlEncode(await sha256BytesUtf8(alphabetizeStringify(aad)));
}
