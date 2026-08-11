import { expect, test } from '@playwright/test';
import type { LinkedDeviceManagementTargetV1 } from '../../packages/sdk-server-ts/src/core/deviceLinking/linkedDeviceManagement';
import { D1LinkedDeviceLocalStateInvalidationV1 } from '../../packages/sdk-server-ts/src/router/cloudflare/d1/deviceLinking/d1LinkedDeviceLocalStateInvalidation';
import { buildR103DeviceLinkFixture } from './helpers/deviceLinkContracts.fixtures';
import {
  parseLinkedDeviceEnrollmentId,
  parseLinkedDeviceId,
} from '../../packages/shared-ts/src/signing-lanes/ids';
import { parseWalletId } from '../../packages/shared-ts/src/utils/domainIds';
import { parseDigestB64u } from '../../packages/shared-ts/src/utils/canonicalPrimitives';
import { base64UrlEncode } from '../../packages/shared-ts/src/utils/base64';

test('confirms exact revoked D1 state and replays idempotently', async () => {
  const fixture = buildR103DeviceLinkFixture();
  const walletId = parseWalletId(String(fixture.approval.walletId));
  const enrollmentId = parseLinkedDeviceEnrollmentId(String(fixture.approval.enrollmentId));
  const deviceId = parseLinkedDeviceId(String(fixture.approval.deviceId));
  if (!walletId.ok || !enrollmentId.ok || !deviceId.ok) throw new Error('fixture identity invalid');
  const aggregateDigest = parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(4)));
  const target = {
    summary: {
      walletId: walletId.value,
      enrollmentId: enrollmentId.value,
      deviceId: deviceId.value,
    },
    enrollment: {
      value: {
        manifest: { walletId: walletId.value, enrollmentId: enrollmentId.value },
        lifecycle: {
          state: 'revoked',
          manifestDigestB64u: aggregateDigest,
          aggregateRevocationReceiptDigestB64u: aggregateDigest,
          revokedAtMs: 2_000,
        },
      },
    },
    products: [
      {
        state: 'revoked',
        walletId: walletId.value,
        enrollmentId: enrollmentId.value,
        revocationEpoch: 1,
        revocationReceiptDigestB64u: aggregateDigest,
      },
    ],
  } as unknown as LinkedDeviceManagementTargetV1;
  const projection = {
    getLinkedDeviceV1: async () => target,
  };
  const invalidation = new D1LinkedDeviceLocalStateInvalidationV1({ projection });
  const input = {
    walletId: walletId.value,
    enrollmentId: enrollmentId.value,
    deviceId: deviceId.value,
    revocationEpoch: 1,
    aggregateReceiptDigestB64u: aggregateDigest,
    requestedAtMs: 2_000,
  } as const;

  await expect(invalidation.invalidateLinkedDeviceStateV1(input)).resolves.toEqual({
    kind: 'replayed',
  });
  await expect(invalidation.invalidateLinkedDeviceStateV1(input)).resolves.toEqual({
    kind: 'replayed',
  });
  await expect(
    invalidation.invalidateLinkedDeviceStateV1({
      ...input,
      aggregateReceiptDigestB64u: parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(5))),
    }),
  ).resolves.toEqual({ kind: 'conflict' });
});
