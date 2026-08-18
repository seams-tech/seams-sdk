import * as ed25519 from '@noble/ed25519';
import {
  computeLinkedDevicePublicKeyDigestV1,
  encodeLinkedDeviceRequestProofV1,
  parseLinkedDeviceRequestProofV1,
  type LinkedDeviceRequestProofV1,
} from '../../../packages/wallet-server/src/core/deviceLinking/requestProof';
import type { LinkDeviceSessionId } from '../../../packages/shared-ts/src/signing-lanes/ids';
import { base64UrlEncode } from '../../../packages/shared-ts/src/utils/base64';
import { parseDigestB64u } from '../../../packages/shared-ts/src/utils/canonicalPrimitives';
import { sha256Bytes } from '../../../packages/shared-ts/src/utils/digests';

export type SignedDeviceRequestProofFixtureV1 = {
  readonly secretKey: Uint8Array;
  readonly publicKey: Uint8Array;
  readonly proof: LinkedDeviceRequestProofV1;
};

export async function buildSignedDeviceRequestProofFixtureV1(input: {
  readonly linkSessionId: LinkDeviceSessionId;
  readonly canonicalPath: string;
  readonly bodyText: string;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
  readonly nonceByte: number;
  readonly method?: 'GET' | 'POST';
}): Promise<SignedDeviceRequestProofFixtureV1> {
  const secretKey = new Uint8Array(32).fill(9);
  const publicKey = await ed25519.getPublicKeyAsync(secretKey);
  const publicKeyB64u = base64UrlEncode(publicKey);
  const bodyDigestB64u = parseDigestB64u(
    base64UrlEncode(await sha256Bytes(new TextEncoder().encode(input.bodyText))),
  );
  const unsigned: LinkedDeviceRequestProofV1 = {
    kind: 'linked_device_request_proof_v1',
    linkSessionId: input.linkSessionId,
    devicePublicKeyDigestB64u: await computeLinkedDevicePublicKeyDigestV1(publicKeyB64u),
    requestNonceB64u: base64UrlEncode(new Uint8Array(32).fill(input.nonceByte)),
    method: input.method ?? 'POST',
    canonicalPath: input.canonicalPath,
    bodyDigestB64u,
    issuedAtMs: input.issuedAtMs,
    expiresAtMs: input.expiresAtMs,
    signatureB64u: base64UrlEncode(new Uint8Array(64)),
  };
  const signature = await ed25519.signAsync(encodeLinkedDeviceRequestProofV1(unsigned), secretKey);
  return {
    secretKey,
    publicKey,
    proof: parseLinkedDeviceRequestProofV1({ ...unsigned, signatureB64u: base64UrlEncode(signature) }),
  };
}
