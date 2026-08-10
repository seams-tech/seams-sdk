import { expect, test } from '@playwright/test';
import {
  buildLinkedDeviceSessionClaimV1,
  buildDisplayingQrLinkedDeviceSessionState,
  encodeLinkedDeviceRequestProofV1,
  parseLinkedDeviceSessionClaimV1,
  parseLinkedDeviceSessionProjectionV1,
} from '../../packages/shared-ts/src/device-linking';
import type {
  LinkedDeviceRequestProofV1,
  LinkedDeviceSessionProjectionV1,
} from '../../packages/shared-ts/src/device-linking';
import { encodeLinkedDeviceRequestProofV1 as encodeServerLinkedDeviceRequestProofV1 } from '../../packages/sdk-server-ts/src/core/deviceLinking/requestProof';
import { base64UrlDecode, base64UrlEncode } from '../../packages/shared-ts/src/utils/base64';
import { createDeviceLinkingAuthenticatedSessionTransportV1 } from '../../packages/sdk-web/src/SeamsWeb/operations/devices/deviceLinkingHttpTransport';
import type { DeviceLinkingKeyMaterialPortV1 } from '../../packages/sdk-web/src/SeamsWeb/operations/devices/deviceLinkingPorts';
import type { HttpTransport } from '../../packages/sdk-web/src/core/platform/http';
import { buildR103DeviceLinkFixture } from './helpers/deviceLinkContracts.fixtures';

function responseBody(fixture: ReturnType<typeof buildR103DeviceLinkFixture>): {
  readonly ok: true;
  readonly outcome: 'applied';
  readonly session: LinkedDeviceSessionProjectionV1;
} {
  return {
    ok: true,
    outcome: 'applied',
    session: {
      kind: 'linked_device_session_projection_v1',
      linkSessionId: fixture.payload.linkSessionId,
      qrPayload: fixture.payload,
      revision: 1,
      createdAtMs: fixture.payload.issuedAtMs,
      updatedAtMs: fixture.payload.issuedAtMs,
      state: buildDisplayingQrLinkedDeviceSessionState({
        linkSessionId: fixture.payload.linkSessionId,
        expiresAtMs: fixture.payload.expiresAtMs,
      }),
    },
  };
}

test.describe('R103 authenticated linked-device browser transport', () => {
  test('binds each request to the exact server proof bytes and fresh nonce', async () => {
    const fixture = buildR103DeviceLinkFixture();
    const calls: Array<{
      readonly method: 'GET' | 'POST';
      readonly url: string;
      readonly proof: Record<string, unknown>;
      readonly body?: unknown;
    }> = [];
    const http: HttpTransport = {
      kind: 'http_transport',
      async request(input) {
        const encodedProof = input.headers?.['x-seams-linked-device-proof-v1'];
        if (!encodedProof) throw new Error('proof header missing');
        const proof = JSON.parse(new TextDecoder().decode(base64UrlDecode(encodedProof))) as Record<
          string,
          unknown
        >;
        calls.push({
          method: input.method,
          url: input.url,
          proof,
          ...(input.body === undefined ? {} : { body: input.body }),
        });
        return { ok: true, value: { status: 200, body: responseBody(fixture) } };
      },
    };
    const signatures: Array<Record<string, unknown>> = [];
    const keyMaterial: DeviceLinkingKeyMaterialPortV1 = {
      async createBootstrapKeyMaterialV1() {
        return {
          handle: { kind: 'device_linking_key_material_handle_v1', handleId: 'worker-slot-r103' },
          linkPublicKeyB64u: fixture.payload.linkPublicKeyB64u,
          devicePublicKeyB64u: fixture.payload.devicePublicKeyB64u,
        };
      },
      async signDeviceSessionRequestV1(input) {
        signatures.push(input);
        return { signatureB64u: base64UrlEncode(new Uint8Array(64).fill(9)) };
      },
    };
    const transport = createDeviceLinkingAuthenticatedSessionTransportV1({
      http,
      relayerUrl: 'https://relay.example.test/',
      keyMaterial,
      keyMaterialHandle: {
        kind: 'device_linking_key_material_handle_v1',
        handleId: 'worker-slot-r103',
      },
      devicePublicKeyB64u: fixture.payload.devicePublicKeyB64u,
      nowMs: () => 2_000,
      pollIntervalMs: 10_000,
    });

    await transport.createUnclaimedSessionV1({
      payload: fixture.payload,
      state: buildDisplayingQrLinkedDeviceSessionState({
        linkSessionId: fixture.payload.linkSessionId,
        expiresAtMs: fixture.payload.expiresAtMs,
      }),
    });
    await transport.getSessionV1({ linkSessionId: fixture.payload.linkSessionId });

    expect(calls).toHaveLength(2);
    expect(signatures).toHaveLength(2);
    expect(calls[0]?.url).toBe(`https://relay.example.test/wallet/device-linking/v1/sessions`);
    expect(calls[1]?.method).toBe('GET');
    expect(calls[0]?.proof.requestNonceB64u).not.toBe(calls[1]?.proof.requestNonceB64u);
    for (const call of calls) {
      const proof = call.proof;
      const normalized: LinkedDeviceRequestProofV1 = {
        kind: proof.kind,
        linkSessionId: proof.linkSessionId,
        devicePublicKeyDigestB64u: proof.devicePublicKeyDigestB64u,
        requestNonceB64u: proof.requestNonceB64u,
        method: proof.method,
        canonicalPath: proof.canonicalPath,
        bodyDigestB64u: proof.bodyDigestB64u,
        issuedAtMs: proof.issuedAtMs,
        expiresAtMs: proof.expiresAtMs,
        signatureB64u: proof.signatureB64u,
      };
      expect(encodeLinkedDeviceRequestProofV1(normalized)).toEqual(
        encodeServerLinkedDeviceRequestProofV1(normalized),
      );
      expect(base64UrlDecode(String(proof.requestNonceB64u))).toHaveLength(32);
    }
    expect(signatures[0]?.challengeB64u).toBe(calls[0]?.proof.requestNonceB64u);
    expect(signatures[1]?.challengeB64u).toBe(calls[1]?.proof.requestNonceB64u);
  });

  test('parses strict session projections and owner response DTOs without key material crossing', async () => {
    const fixture = buildR103DeviceLinkFixture();
    const projection = parseLinkedDeviceSessionProjectionV1(responseBody(fixture).session);
    expect(projection.deviceId).toBeUndefined();
    const claim = parseLinkedDeviceSessionClaimV1(
      buildLinkedDeviceSessionClaimV1({
        linkSessionId: fixture.payload.linkSessionId,
        walletId: fixture.approval.walletId,
        enrollmentId: fixture.approval.enrollmentId,
        deviceId: fixture.approval.deviceId,
        devicePublicKeyB64u: fixture.payload.devicePublicKeyB64u,
        claimedAtMs: 2_000,
        claimExpiresAtMs: 9_000,
      }),
    );
    expect(claim.deviceId).toBe(fixture.approval.deviceId);
    expect(JSON.stringify(projection)).not.toContain('private');
  });
});
