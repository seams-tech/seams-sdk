import { expect, test } from '@playwright/test';
import {
  buildLinkedDeviceSessionClaimV1,
  buildDisplayingQrLinkedDeviceSessionState,
  parseLinkedDeviceSessionClaimV1,
  parseLinkedDeviceSessionProjectionV1,
} from '../../packages/shared-ts/src/device-linking';
import type { LinkedDeviceSessionProjectionV1 } from '../../packages/shared-ts/src/device-linking';
import { base64UrlDecode, base64UrlEncode } from '../../packages/shared-ts/src/utils/base64';
import { createDeviceLinkingAuthenticatedSessionTransportV1 } from '../../packages/wallet/src/SeamsWeb/operations/devices/deviceLinkingHttpTransport';
import type { DeviceLinkingKeyMaterialPortV1 } from '../../packages/wallet/src/SeamsWeb/operations/devices/deviceLinkingPorts';
import type { HttpTransport } from '../../packages/wallet/src/core/platform/http';
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
  test('binds each request to exact canonical proof fields and a fresh nonce', async () => {
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
      async prepareTargetHolderRegistrationsV1() {
        throw new Error('target holder preparation is outside this transport test');
      },
      async openAndSealTargetHolderDeliveryV1() {
        throw new Error('holder delivery is outside this transport test');
      },
      async discardKeyMaterialV1() {
        return;
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

  test('treats an unsealed custody transfer as pending without an HTTP error', async () => {
    const fixture = buildR103DeviceLinkFixture();
    let requestedPath = '';
    const http: HttpTransport = {
      kind: 'http_transport',
      async request(input) {
        requestedPath = new URL(input.url).pathname;
        return { ok: true, value: { status: 204, body: null } };
      },
    };
    const keyMaterial: DeviceLinkingKeyMaterialPortV1 = {
      async createBootstrapKeyMaterialV1() {
        throw new Error('bootstrap is outside this transport test');
      },
      async prepareTargetHolderRegistrationsV1() {
        throw new Error('target holder preparation is outside this transport test');
      },
      async openAndSealTargetHolderDeliveryV1() {
        throw new Error('holder delivery is outside this transport test');
      },
      async discardKeyMaterialV1() {},
      async signDeviceSessionRequestV1() {
        return { signatureB64u: base64UrlEncode(new Uint8Array(64).fill(9)) };
      },
    };
    const transport = createDeviceLinkingAuthenticatedSessionTransportV1({
      http,
      relayerUrl: 'https://relay.example.test',
      keyMaterial,
      keyMaterialHandle: {
        kind: 'device_linking_key_material_handle_v1',
        handleId: 'worker-slot-r103',
      },
      devicePublicKeyB64u: fixture.payload.devicePublicKeyB64u,
      nowMs: () => 2_000,
      pollIntervalMs: 10_000,
    });

    await expect(
      transport.getCustodyTransferPackageV1({ linkSessionId: fixture.payload.linkSessionId }),
    ).resolves.toBeNull();
    expect(requestedPath).toBe(
      `/wallet/device-linking/v1/sessions/${fixture.payload.linkSessionId}/custody-transfer`,
    );
  });

  test('does not schedule an orphan poll after bootstrap failure', async () => {
    const fixture = buildR103DeviceLinkFixture();
    let requests = 0;
    const http: HttpTransport = {
      kind: 'http_transport',
      async request() {
        requests += 1;
        return { ok: false, message: 'bootstrap unavailable' };
      },
    };
    const keyMaterial: DeviceLinkingKeyMaterialPortV1 = {
      async createBootstrapKeyMaterialV1() {
        throw new Error('bootstrap is outside this transport test');
      },
      async prepareTargetHolderRegistrationsV1() {
        throw new Error('target holder preparation is outside this transport test');
      },
      async openAndSealTargetHolderDeliveryV1() {
        throw new Error('holder delivery is outside this transport test');
      },
      async discardKeyMaterialV1() {},
      async signDeviceSessionRequestV1() {
        return { signatureB64u: base64UrlEncode(new Uint8Array(64).fill(9)) };
      },
    };
    const transport = createDeviceLinkingAuthenticatedSessionTransportV1({
      http,
      relayerUrl: 'https://relay.example.test',
      keyMaterial,
      keyMaterialHandle: {
        kind: 'device_linking_key_material_handle_v1',
        handleId: 'worker-slot-r103',
      },
      devicePublicKeyB64u: fixture.payload.devicePublicKeyB64u,
      nowMs: () => 2_000,
      pollIntervalMs: 5,
    });

    await expect(
      transport.subscribeSessionV1({
        linkSessionId: fixture.payload.linkSessionId,
        onEvent: () => undefined,
      }),
    ).rejects.toThrow('bootstrap unavailable');
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(requests).toBe(1);
  });

  test('single-flights session polls and retries transient failures with backoff', async () => {
    const fixture = buildR103DeviceLinkFixture();
    let requests = 0;
    let inFlight = 0;
    let maxInFlight = 0;
    const http: HttpTransport = {
      async request() {
        const requestNumber = requests++;
        inFlight += 1;
        maxInFlight = Math.max(maxInFlight, inFlight);
        await new Promise((resolve) => setTimeout(resolve, requestNumber === 0 ? 10 : 0));
        inFlight -= 1;
        if (requestNumber === 1) return { ok: false, message: 'temporary outage' };
        const revision = requestNumber >= 2 ? 2 : 1;
        return {
          ok: true,
          value: {
            status: 200,
            body: {
              ...responseBody(fixture),
              session: {
                ...responseBody(fixture).session,
                revision,
                updatedAtMs: responseBody(fixture).session.updatedAtMs + revision,
              },
            },
          },
        };
      },
    };
    const keyMaterial: DeviceLinkingKeyMaterialPortV1 = {
      async createBootstrapKeyMaterialV1() {
        throw new Error('bootstrap is outside this transport test');
      },
      async prepareTargetHolderRegistrationsV1() {
        throw new Error('target holder preparation is outside this transport test');
      },
      async openAndSealTargetHolderDeliveryV1() {
        throw new Error('holder delivery is outside this transport test');
      },
      async discardKeyMaterialV1() {},
      async signDeviceSessionRequestV1() {
        return { signatureB64u: base64UrlEncode(new Uint8Array(64).fill(9)) };
      },
    };
    const transport = createDeviceLinkingAuthenticatedSessionTransportV1({
      http,
      relayerUrl: 'https://relay.example.test',
      keyMaterial,
      keyMaterialHandle: {
        kind: 'device_linking_key_material_handle_v1',
        handleId: 'worker-slot-r103',
      },
      devicePublicKeyB64u: fixture.payload.devicePublicKeyB64u,
      nowMs: () => 2_000,
      pollIntervalMs: 1,
    });
    const events: number[] = [];
    const subscription = await transport.subscribeSessionV1({
      linkSessionId: fixture.payload.linkSessionId,
      onEvent: (event) => events.push(event.state.state === 'displaying_qr' ? 1 : 2),
    });
    await expect.poll(() => events.length, { timeout: 1_000 }).toBe(2);
    await subscription.close();

    expect(requests).toBeGreaterThanOrEqual(3);
    expect(maxInFlight).toBe(1);
    expect(events).toHaveLength(2);
  });
});
