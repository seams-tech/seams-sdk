import { base64UrlEncode } from '../utils/base64';
import { alphabetizeStringify, sha256BytesUtf8 } from '../utils/digests';

export async function computeThresholdEd25519RecoveryExportInitChallengeB64u(input: {
  nearAccountId: string;
  rpId: string;
  relayerKeyId: string;
  keyVersion: string;
  recoveryPublicKey: string;
}): Promise<string> {
  const json = alphabetizeStringify({
    version: 'threshold_ed25519_export_init_v1',
    artifactKind: 'near-ed25519-option-b-v1',
    nearAccountId: input.nearAccountId,
    rpId: input.rpId,
    relayerKeyId: input.relayerKeyId,
    keyVersion: input.keyVersion,
    recoveryPublicKey: input.recoveryPublicKey,
  });
  const digest = await sha256BytesUtf8(json);
  return base64UrlEncode(digest);
}
