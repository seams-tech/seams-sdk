import { expect, test } from '@playwright/test';
import {
  D1LinkedDeviceOperatorRecoveryProviderV1,
  LINKED_DEVICE_OPERATOR_SECRET_HEADER_V1,
} from '../../packages/sdk-server-ts/src/router/cloudflare/d1/deviceLinking/d1LinkedDeviceOperatorRecoveryProvider';
import { base64UrlEncode } from '../../packages/shared-ts/src/utils/base64';
import { parseDigestB64u } from '../../packages/shared-ts/src/utils/canonicalPrimitives';
import { sha256Bytes } from '../../packages/shared-ts/src/utils/digests';

test('authenticates the exact operator secret before reading and binds the request', async () => {
  const secret = 'operator-recovery-test-secret';
  const body = JSON.stringify({
    kind: 'linked_device_session_operator_recovery_request_v1',
    requestedAtMs: 2_000,
  });
  const digest = parseDigestB64u(
    base64UrlEncode(await sha256Bytes(new TextEncoder().encode(body))),
  );
  const provider = new D1LinkedDeviceOperatorRecoveryProviderV1({
    operatorSecret: secret,
    ttlMs: 10_000,
  });

  const result = await provider.authenticateOperatorRecoveryRequestV1({
    request: new Request('https://sign.seams.sh/wallet/device-linking/v1/operator-recovery', {
      method: 'POST',
      headers: {
        [LINKED_DEVICE_OPERATOR_SECRET_HEADER_V1]: secret,
        'content-type': 'application/json',
      },
      body,
    }),
    method: 'POST',
    pathname: '/wallet/device-linking/v1/operator-recovery',
    bodyDigestB64u: digest,
    requestedAtMs: 2_000,
  });

  expect(result).toEqual({
    kind: 'authorized',
    body: JSON.parse(body),
    binding: {
      kind: 'linked_device_operator_request_binding_v1',
      method: 'POST',
      pathname: '/wallet/device-linking/v1/operator-recovery',
      bodyDigestB64u: digest,
      expiresAtMs: 12_000,
    },
  });
});

test('rejects a wrong secret without parsing an invalid request body', async () => {
  const provider = new D1LinkedDeviceOperatorRecoveryProviderV1({
    operatorSecret: 'operator-recovery-test-secret',
  });
  const result = await provider.authenticateOperatorRecoveryRequestV1({
    request: new Request('https://sign.seams.sh/operator-recovery', {
      method: 'POST',
      headers: { [LINKED_DEVICE_OPERATOR_SECRET_HEADER_V1]: 'wrong-secret' },
      body: '{invalid-json',
    }),
    method: 'POST',
    pathname: '/operator-recovery',
    bodyDigestB64u: parseDigestB64u(base64UrlEncode(new Uint8Array(32))),
    requestedAtMs: 2_000,
  });

  expect(result).toEqual({
    kind: 'denied',
    code: 'unauthorized',
    message: 'operator recovery authentication failed',
  });
});

test('requires a nonempty secret and short TTL', () => {
  expect(() => new D1LinkedDeviceOperatorRecoveryProviderV1({ operatorSecret: '' })).toThrow(
    'operator recovery secret',
  );
  expect(
    () =>
      new D1LinkedDeviceOperatorRecoveryProviderV1({
        operatorSecret: 'secret',
        ttlMs: 300_001,
      }),
  ).toThrow('operator recovery TTL');
});
