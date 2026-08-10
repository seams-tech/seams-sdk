import { expect, test } from '@playwright/test';
import {
  buildActiveLinkedDeviceSessionState,
  buildCancelledUnclaimedLinkedDeviceSessionState,
  computeLinkedDeviceApprovalDigestV1,
  computeLinkedDeviceSessionClaimDigestV1,
  parseLinkedDeviceApprovalV1,
  parseLinkedDeviceEnrollmentReceiptV1,
  parseLinkedDeviceEnrollmentTranscriptV1,
  parseLinkedDeviceSessionState,
  parseLinkedDeviceSessionTransportRequestV1,
  parseQrLinkedDeviceSessionPayloadV4,
} from '../../packages/shared-ts/src/device-linking';
import { buildR103DeviceLinkFixture } from './helpers/deviceLinkContracts.fixtures';

test.describe('R103 shared linked-device contracts', () => {
  test('round-trips QR, approval, transcript, and receipt projections through strict parsers', async () => {
    const fixture = buildR103DeviceLinkFixture();

    expect(parseQrLinkedDeviceSessionPayloadV4(fixture.payload)).toEqual(fixture.payload);
    expect(parseLinkedDeviceApprovalV1(fixture.approval)).toEqual(fixture.approval);
    expect(parseLinkedDeviceEnrollmentTranscriptV1(fixture.transcript)).toEqual(fixture.transcript);
    expect(parseLinkedDeviceEnrollmentReceiptV1(fixture.receipt)).toEqual(fixture.receipt);

    const claimDigest = await computeLinkedDeviceSessionClaimDigestV1({
      kind: 'linked_device_session_claim_v1',
      linkSessionId: fixture.payload.linkSessionId,
      walletId: fixture.approval.walletId,
      enrollmentId: fixture.approval.enrollmentId,
      deviceId: fixture.approval.deviceId,
      devicePublicKeyB64u: fixture.payload.devicePublicKeyB64u,
      claimedAtMs: 1_500,
      claimExpiresAtMs: 9_000,
    });
    const approvalDigest = await computeLinkedDeviceApprovalDigestV1(fixture.approval);
    expect(claimDigest).toBe('FgZvqK0Fekq89xChB3UoQBKz0nlTcbBvkxXAa6v6_EA');
    expect(approvalDigest).toBe('ibcErM2M3FJ-1VBJ2YH35qnTwaOAnUjqKKT8CLc4kjc');
  });

  test('rejects dormant QR permissions, unknown fields, non-canonical keys, and invalid expiry', () => {
    const fixture = buildR103DeviceLinkFixture();

    expect(() =>
      parseQrLinkedDeviceSessionPayloadV4({
        ...fixture.payload,
        requestedPermission: {
          kind: 'scoped_signing',
          administrationScope: 'no_account_admin',
          mandatePolicyDigest: 'retired',
        },
      }),
    ).toThrow();
    expect(() =>
      parseQrLinkedDeviceSessionPayloadV4({ ...fixture.payload, walletId: 'wallet:leak' }),
    ).toThrow(/walletId/);
    expect(() =>
      parseQrLinkedDeviceSessionPayloadV4({
        ...fixture.payload,
        linkPublicKeyB64u: `${fixture.payload.linkPublicKeyB64u}=`,
      }),
    ).toThrow(/base64url/);
    expect(() =>
      parseQrLinkedDeviceSessionPayloadV4({
        ...fixture.payload,
        expiresAtMs: fixture.payload.issuedAtMs,
      }),
    ).toThrow(/expiresAtMs/);
  });

  test('keeps wallet identity out of unclaimed states and splits cancellation branches', () => {
    const fixture = buildR103DeviceLinkFixture();
    const active = buildActiveLinkedDeviceSessionState({
      linkSessionId: fixture.payload.linkSessionId,
      walletId: fixture.approval.walletId,
      enrollmentId: fixture.approval.enrollmentId,
      activatedAtMs: 10_000,
    });
    const cancelled = buildCancelledUnclaimedLinkedDeviceSessionState({
      linkSessionId: fixture.payload.linkSessionId,
      cancelledAtMs: 3_000,
    });
    expect(parseLinkedDeviceSessionState(active)).toEqual(active);
    expect(parseLinkedDeviceSessionState(cancelled)).toEqual(cancelled);
    expect(() =>
      parseLinkedDeviceSessionState({ ...cancelled, walletId: fixture.approval.walletId }),
    ).toThrow(/walletId/);

    expect(
      parseLinkedDeviceSessionTransportRequestV1({
        kind: 'linked_device_session_cancel_unclaimed_request_v1',
        linkSessionId: fixture.payload.linkSessionId,
        reason: 'user_cancelled',
        requestedAtMs: 3_000,
      }),
    ).toMatchObject({ kind: 'linked_device_session_cancel_unclaimed_request_v1' });
    expect(() =>
      parseLinkedDeviceSessionTransportRequestV1({
        kind: 'linked_device_session_cancel_unclaimed_request_v1',
        linkSessionId: fixture.payload.linkSessionId,
        reason: 'user_cancelled',
        requestedAtMs: 3_000,
        deviceId: fixture.approval.deviceId,
      }),
    ).toThrow(/deviceId/);
  });
});
