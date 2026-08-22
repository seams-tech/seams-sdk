import { expect, test } from '@playwright/test';
import {
  buildLinkedDeviceSessionClaimV1,
  parseQrLinkedDeviceSessionPayloadV5,
  parseQrLinkedDeviceSessionTextV5,
  serializeQrLinkedDeviceSessionPayloadV5,
} from '@shared/device-linking/parsers';
import {
  computeLinkedDeviceApprovalDigestV1,
  computeLinkedDeviceSessionClaimDigestV1,
} from '@shared/device-linking/digests';
import { buildR103DeviceLinkFixture } from './helpers/deviceLinkContracts.fixtures';
import { parseLinkedDeviceSessionStateV1 } from '../../packages/wallet-server/src/core/deviceLinking/linkedDeviceSession';

test.describe('R103E link-session contracts', () => {
  test('round-trips the QR payload through its strict wire parser', () => {
    const fixture = buildR103DeviceLinkFixture();
    const serialized = serializeQrLinkedDeviceSessionPayloadV5(fixture.payload);

    expect(parseQrLinkedDeviceSessionPayloadV5(fixture.payload)).toEqual(fixture.payload);
    expect(parseQrLinkedDeviceSessionTextV5(serialized)).toEqual(fixture.payload);
    expect(new TextEncoder().encode(serialized).byteLength).toBeLessThan(240);
    expect(() =>
      parseQrLinkedDeviceSessionPayloadV5({ ...fixture.payload, walletId: 'wallet:leak' }),
    ).toThrow(/walletId/);
    expect(() =>
      parseQrLinkedDeviceSessionPayloadV5({
        ...fixture.payload,
        expiresAtMs: fixture.payload.issuedAtMs,
      }),
    ).toThrow(/expiresAtMs/);
  });

  test('binds claim and approval digests to the exact transcript values', async () => {
    const fixture = buildR103DeviceLinkFixture();
    const claim = buildLinkedDeviceSessionClaimV1({
      linkSessionId: fixture.payload.linkSessionId,
      walletId: fixture.approval.walletId,
      enrollmentId: fixture.approval.enrollmentId,
      deviceId: fixture.approval.deviceId,
      devicePublicKeyB64u: fixture.payload.devicePublicKeyB64u,
      targetFactor: fixture.approval.targetFactor,
      claimedAtMs: 1_500,
      claimExpiresAtMs: fixture.payload.expiresAtMs,
    });
    const claimDigest = await computeLinkedDeviceSessionClaimDigestV1(claim);
    const approvalDigest = await computeLinkedDeviceApprovalDigestV1(fixture.approval);

    expect(claimDigest).toBe(await computeLinkedDeviceSessionClaimDigestV1(claim));
    expect(approvalDigest).toBe(await computeLinkedDeviceApprovalDigestV1(fixture.approval));
    expect(await computeLinkedDeviceApprovalDigestV1({
      ...fixture.approval,
      expiresAtMs: fixture.approval.expiresAtMs - 1,
    })).not.toBe(approvalDigest);
  });

  test('accepts only the linear lifecycle states and rejects committed cancellation facts', () => {
    const fixture = buildR103DeviceLinkFixture();
    const authorityId = 'authority:r103';
    const states: readonly unknown[] = [
      { state: 'displaying_qr' },
      { state: 'claimed', deviceId: String(fixture.approval.deviceId) },
      { state: 'awaiting_target_factor', deviceId: String(fixture.approval.deviceId) },
      { state: 'provisioning', deviceId: String(fixture.approval.deviceId) },
      {
        state: 'authority_pending_local_install',
        deviceId: String(fixture.approval.deviceId),
        authorityId,
        packageSetDigestB64u: String(fixture.packageSetDigestB64u),
      },
      {
        state: 'active',
        deviceId: String(fixture.approval.deviceId),
        authorityId,
        activatedAtMs: 9_000,
      },
      {
        state: 'failed_before_commit',
        error: { kind: 'package_preparation_failed', reason: 'worker-unavailable' },
      },
      { state: 'cancelled', cancelledAtMs: 3_000 },
      { state: 'expired', expiredAtMs: 3_000 },
    ];

    for (const state of states) expect(parseLinkedDeviceSessionStateV1(state)).toEqual(state);
    expect(() =>
      parseLinkedDeviceSessionStateV1({
        state: 'authority_pending_local_install',
        deviceId: String(fixture.approval.deviceId),
        authorityId,
        packageSetDigestB64u: String(fixture.packageSetDigestB64u),
        cancelledAtMs: 3_000,
      }),
    ).toThrow();
  });
});
