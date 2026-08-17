import { expect, test } from '@playwright/test';
import {
  parseLinkedDeviceLocalPresenceAssertionV1,
  verifyLinkedDeviceLocalPresenceV1,
  type LinkedDeviceLocalPresenceAssertionV1,
} from '../../packages/sdk-server-ts/src/router/auth/linkedDeviceLocalPresenceVerifier';
import { base64UrlEncode } from '../../packages/shared-ts/src/utils/base64';

function digest(fill: number): string {
  return base64UrlEncode(new Uint8Array(32).fill(fill));
}

function assertion(credentialId = 'credential-1'): LinkedDeviceLocalPresenceAssertionV1 {
  const encoded = base64UrlEncode(new TextEncoder().encode(credentialId));
  return {
    kind: 'linked_device_local_presence_assertion_v1',
    authorizedOperationId: 'authorized-operation:1',
    deviceId: 'device:2',
    enrollmentId: 'enrollment:2',
    credentialIdB64u: encoded,
    intentDigestB64u: digest(1),
    challengeDigestB64u: digest(2),
    issuedAtMs: 100,
    expiresAtMs: 1_000,
    assertion: {
      id: encoded,
      rawId: encoded,
      type: 'public-key',
      authenticatorAttachment: null,
      response: {
        clientDataJSON: base64UrlEncode(
          new TextEncoder().encode(
            JSON.stringify({
              challenge: digest(2),
              origin: 'https://example.localhost',
              type: 'webauthn.get',
            }),
          ),
        ),
        authenticatorData: base64UrlEncode(new Uint8Array([1, 2, 3])),
        signature: base64UrlEncode(new Uint8Array([4, 5, 6])),
        userHandle: null,
      },
      clientExtensionResults: null,
    },
  };
}

test.describe('R103 linked-device local presence boundary', () => {
  test('parses and verifies exact operation/device/enrollment/credential bindings', async () => {
    const raw = assertion();
    const calls: string[] = [];
    const result = await verifyLinkedDeviceLocalPresenceV1({
      assertion: raw,
      nowMs: () => 200,
      verifier: {
        async verify(input) {
          calls.push(
            `${input.authorizedOperationId}:${input.deviceId}:${input.enrollmentId}:${input.intentDigestB64u}:${input.challengeDigestB64u}`,
          );
          return { kind: 'verified', verifiedAtMs: 201 };
        },
      },
    });

    expect(result.kind).toBe('verified');
    if (result.kind === 'verified') {
      expect(result.evidence).toMatchObject({
        authorizedOperationId: raw.authorizedOperationId,
        deviceId: raw.deviceId,
        enrollmentId: raw.enrollmentId,
        intentDigestB64u: raw.intentDigestB64u,
        verifiedAtMs: 201,
      });
      expect(result.evidence).toHaveProperty('assertionDigestB64u');
      expect(result.evidence).not.toHaveProperty('assertion');
    }
    expect(calls).toEqual([
      `authorized-operation:1:device:2:enrollment:2:${digest(1)}:${digest(2)}`,
    ]);
  });

  test('rejects a substituted credential before calling the verifier', async () => {
    const raw = assertion('credential-1');
    const parsed = parseLinkedDeviceLocalPresenceAssertionV1({
      ...raw,
      credentialIdB64u: base64UrlEncode(new TextEncoder().encode('credential-2')),
    });
    expect(parsed).toBeNull();
  });

  test('rejects malformed, expired, and refused assertions', async () => {
    expect(
      await verifyLinkedDeviceLocalPresenceV1({
        assertion: { ...assertion(), intentDigestB64u: 'bad' },
        verifier: { verify: async () => ({ kind: 'verified', verifiedAtMs: 200 }) },
      }),
    ).toEqual({ kind: 'refused', reason: 'assertion_malformed' });

    expect(
      await verifyLinkedDeviceLocalPresenceV1({
        assertion: assertion(),
        nowMs: () => 1_000,
        verifier: { verify: async () => ({ kind: 'verified', verifiedAtMs: 1_000 }) },
      }),
    ).toEqual({ kind: 'refused', reason: 'assertion_time_invalid' });

    expect(
      await verifyLinkedDeviceLocalPresenceV1({
        assertion: assertion(),
        nowMs: () => 200,
        verifier: {
          verify: async () => ({ kind: 'refused', reason: 'assertion_binding_mismatch' }),
        },
      }),
    ).toEqual({ kind: 'refused', reason: 'assertion_binding_mismatch' });
  });
});
