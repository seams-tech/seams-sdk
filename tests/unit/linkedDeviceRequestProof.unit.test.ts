import { expect, test } from '@playwright/test';
import {
  computeLinkedDevicePublicKeyDigestV1,
  LinkedDeviceRequestProofVerifierV1,
  type LinkedDeviceRequestProofNonceStoreV1,
  type LinkedDeviceRequestProofV1,
} from '../../packages/sdk-server-ts/src/core/deviceLinking/requestProof';
import { parseLinkDeviceSessionId } from '@shared/signing-lanes/ids';
import { base64UrlEncode } from '@shared/utils/base64';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import { buildSignedDeviceRequestProofFixtureV1 } from './helpers/deviceRequestProof.fixtures';

const linkSessionId = parseLinkDeviceSessionId('link-session:proof').value;
const nowMs = 1_000;

test('authenticates an Ed25519 proof once and rejects nonce replay', async () => {
  const fixture = await buildSignedDeviceRequestProofFixtureV1({
    linkSessionId,
    canonicalPath: '/wallet/device-linking/v1/sessions',
    bodyText: '{"ok":true}',
    issuedAtMs: 950,
    expiresAtMs: 1_050,
    nonceByte: 3,
  });
  const { proof } = fixture;
  const nonceStore = memoryNonceStore();
  const verifier = new LinkedDeviceRequestProofVerifierV1({ nonceStore });
  const input = verificationInput(proof, fixture.publicKey);

  const authorized = await verifier.verifyV1(input);
  expect(authorized.kind).toBe('authorized');
  const replayed = await verifier.verifyV1(input);
  expect(replayed).toMatchObject({ kind: 'denied', code: 'replayed' });
});

test('binds the signature to method, pathname, body, session, and device key', async () => {
  const fixture = await buildSignedDeviceRequestProofFixtureV1({
    linkSessionId,
    canonicalPath: '/wallet/device-linking/v1/sessions',
    bodyText: '{"ok":true}',
    issuedAtMs: 950,
    expiresAtMs: 1_050,
    nonceByte: 3,
  });
  const { proof } = fixture;
  const verifier = new LinkedDeviceRequestProofVerifierV1({ nonceStore: memoryNonceStore() });
  const valid = verificationInput(proof, fixture.publicKey);

  const pathTamper = await verifier.verifyV1({
    ...valid,
    expectedCanonicalPath: '/wallet/device-linking/v1/sessions/link-session:other/cancel',
  });
  expect(pathTamper).toMatchObject({ kind: 'denied', code: 'invalid' });
  const bodyTamper = await verifier.verifyV1({
    ...valid,
    expectedBodyDigestB64u: parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(2))),
  });
  expect(bodyTamper).toMatchObject({ kind: 'denied', code: 'invalid' });
  const keyTamper = await verifier.verifyV1({
    ...valid,
    expectedDevicePublicKeyDigestB64u: parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(2))),
  });
  expect(keyTamper).toMatchObject({ kind: 'denied', code: 'invalid' });
  const authorized = await verifier.verifyV1(valid);
  expect(authorized.kind).toBe('authorized');
});

test('rejects expired proofs before consuming their nonce and verifies public-create key binding', async () => {
  const expiredFixture = await buildSignedDeviceRequestProofFixtureV1({
    linkSessionId,
    canonicalPath: '/wallet/device-linking/v1/sessions',
    bodyText: '{"ok":true}',
    issuedAtMs: 900,
    expiresAtMs: 1_000,
    nonceByte: 4,
  });
  const { publicKey } = expiredFixture;
  const expired = expiredFixture.proof;
  const nonceStore = memoryNonceStore();
  const verifier = new LinkedDeviceRequestProofVerifierV1({ nonceStore });
  const expiredResult = await verifier.verifyV1(verificationInput(expired, publicKey));
  expect(expiredResult).toMatchObject({ kind: 'denied', code: 'expired' });
  expect(nonceStore.consumed).toHaveLength(0);

  const createProof = (
    await buildSignedDeviceRequestProofFixtureV1({
      linkSessionId,
      canonicalPath: '/wallet/device-linking/v1/sessions',
      bodyText: '{"ok":true}',
      issuedAtMs: 950,
      expiresAtMs: 1_050,
      nonceByte: 3,
    })
  ).proof;
  const createResult = await verifier.verifyPublicCreateV1({
    proof: createProof,
    devicePublicKeyB64u: base64UrlEncode(publicKey),
    devicePublicKeyDigestB64u: await computeLinkedDevicePublicKeyDigestV1(base64UrlEncode(publicKey)),
    linkSessionId,
    method: 'POST',
    canonicalPath: '/wallet/device-linking/v1/sessions',
    bodyDigestB64u: verificationInput(createProof, publicKey).expectedBodyDigestB64u,
    nowMs,
  });
  expect(createResult.kind).toBe('authorized');
});

function verificationInput(
  proof: LinkedDeviceRequestProofV1,
  publicKey: Uint8Array,
): Parameters<LinkedDeviceRequestProofVerifierV1['verifyV1']>[0] {
  return {
    proof,
    expectedDevicePublicKeyB64u: base64UrlEncode(publicKey),
    expectedDevicePublicKeyDigestB64u: proof.devicePublicKeyDigestB64u,
    expectedLinkSessionId: proof.linkSessionId,
    expectedMethod: proof.method,
    expectedCanonicalPath: proof.canonicalPath,
    expectedBodyDigestB64u: proof.bodyDigestB64u,
    nowMs,
  };
}

function memoryNonceStore(): LinkedDeviceRequestProofNonceStoreV1 & { readonly consumed: string[] } {
  const seen = new Set<string>();
  const consumed: string[] = [];
  return {
    consumed,
    async consumeRequestProofNonceV1(input) {
      const key = `${String(input.linkSessionId)}:${input.requestNonceB64u}`;
      if (seen.has(key)) return { outcome: 'already_used' };
      seen.add(key);
      consumed.push(key);
      return { outcome: 'consumed' };
    },
  };
}
