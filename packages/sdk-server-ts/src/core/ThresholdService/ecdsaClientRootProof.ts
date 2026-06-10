import { base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';
import type { EcdsaClientRootPublicKey33B64u } from '@shared/threshold/ecdsaHssRoleLocalBootstrap';
import type { EcdsaHssClientRootProof } from '../types';
import { verifySecp256k1RecoverableSignatureAgainstPublicKey33 } from './ethSignerWasm';

export type EcdsaClientRootProofVerificationResult =
  | { ok: true; clientRootPublicKey33B64u: EcdsaClientRootPublicKey33B64u }
  | { ok: false; code: 'unauthorized'; message: 'Invalid client root proof' };

export async function verifyEcdsaClientRootProof(
  proof: EcdsaHssClientRootProof,
): Promise<EcdsaClientRootProofVerificationResult> {
  try {
    const recovered33 = await verifySecp256k1RecoverableSignatureAgainstPublicKey33(
      base64UrlDecode(proof.digest32B64u),
      base64UrlDecode(proof.signature65B64u),
      base64UrlDecode(proof.clientRootPublicKey33B64u),
    );
    if (base64UrlEncode(recovered33) !== proof.clientRootPublicKey33B64u) {
      return { ok: false, code: 'unauthorized', message: 'Invalid client root proof' };
    }
    return { ok: true, clientRootPublicKey33B64u: proof.clientRootPublicKey33B64u };
  } catch {
    return { ok: false, code: 'unauthorized', message: 'Invalid client root proof' };
  }
}
