import { base64UrlDecode, base64UrlEncode } from '@shared/utils/base64';
import { getPrfFirstB64uFromCredential } from '../../webauthnAuth/credentials/credentialExtensions';

const PASSKEY_THRESHOLD_ECDSA_CLIENT_ROOT_INFO_V1 =
  'seams/passkey/threshold-ecdsa-client-root/v1';

async function hkdfSha256B64u(args: { inputKeyMaterialB64u: string; info: string }): Promise<string> {
  const inputKeyMaterial = base64UrlDecode(args.inputKeyMaterialB64u);
  const salt = new Uint8Array(32);
  try {
    if (inputKeyMaterial.length !== 32) {
      throw new Error('passkey PRF.first must decode to 32 bytes');
    }
    const key = await crypto.subtle.importKey('raw', inputKeyMaterial, 'HKDF', false, [
      'deriveBits',
    ]);
    const derived = await crypto.subtle.deriveBits(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt,
        info: new TextEncoder().encode(args.info),
      },
      key,
      256,
    );
    return base64UrlEncode(derived);
  } finally {
    inputKeyMaterial.fill(0);
    salt.fill(0);
  }
}

export async function derivePasskeyThresholdEcdsaClientRootShare32B64uFromPrfFirst(
  prfFirstB64u: string,
): Promise<string> {
  const normalized = String(prfFirstB64u || '').trim();
  if (!normalized) {
    throw new Error('Missing PRF.first for passkey threshold ECDSA client root');
  }
  return await hkdfSha256B64u({
    inputKeyMaterialB64u: normalized,
    info: PASSKEY_THRESHOLD_ECDSA_CLIENT_ROOT_INFO_V1,
  });
}

export async function derivePasskeyThresholdEcdsaClientRootShare32B64uFromCredential(
  credential: unknown,
): Promise<string> {
  const prfFirstB64u = getPrfFirstB64uFromCredential(credential);
  if (!prfFirstB64u) {
    throw new Error('Missing PRF.first for passkey threshold ECDSA client root');
  }
  return await derivePasskeyThresholdEcdsaClientRootShare32B64uFromPrfFirst(prfFirstB64u);
}
