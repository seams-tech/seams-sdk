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
import {
  parseMpcWalletSigningQuotaId,
  parseWalletSessionAuthorizationId,
  parseWalletSessionId,
} from '@shared/authorization/capabilityKinds';
import { parseWalletAuthorityId } from '@shared/utils/domainIds';
import {
  buildActiveWalletSessionV1,
  parseStoredExactWalletSessionAuthorizationRowV6,
  toStoredExactWalletSessionAuthorizationRowV6,
} from '../../packages/wallet/src/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import {
  parseLinkedDeviceApprovalResultV1,
  parseActiveWalletSessionV1,
  parseLinkSessionProjectionV1,
  parseLinkSessionStateV1,
  parseLinkSessionTransportEventV1,
  parseWalletSessionOperationCredentialV1,
} from '../../packages/shared-ts/src/device-linking/parsers';

test.describe('R103E link-session contracts', () => {
  test('parses only high-entropy opaque operation credentials with their session binding', () => {
    const token = `wst_${'a'.repeat(43)}`;
    const credential = parseWalletSessionOperationCredentialV1({
      kind: 'opaque_wallet_session_operation_credential_v1',
      token,
      walletSessionId: 'wallet-session:credential-parser',
    });
    expect(credential).toEqual({
      kind: 'opaque_wallet_session_operation_credential_v1',
      token,
      walletSessionId: 'wallet-session:credential-parser',
    });
    expect(() =>
      parseWalletSessionOperationCredentialV1({
        kind: 'opaque_wallet_session_operation_credential_v1',
        token: 'wst_short',
        walletSessionId: 'wallet-session:credential-parser',
      }),
    ).toThrow();
    expect(() =>
      parseWalletSessionOperationCredentialV1({ kind: credential.kind, token }),
    ).toThrow();
    expect(() =>
      parseWalletSessionOperationCredentialV1({
        kind: 'signed_wallet_session_operation_credential_v1',
        token,
        walletSessionId: 'wallet-session:credential-parser',
      }),
    ).toThrow();
    expect(() =>
      parseWalletSessionOperationCredentialV1({
        kind: credential.kind,
        token,
        walletSessionId: 'wallet-session:credential-parser',
        signature: 'legacy-signed-credential',
      }),
    ).toThrow();
  });

  test('round-trips the opaque operation credential in the exact V6 session row', () => {
    const fixture = buildR103DeviceLinkFixture();
    const walletSessionId = parseWalletSessionId('wallet-session:persisted-credential');
    const authorizationId = parseWalletSessionAuthorizationId('authorization:persisted-credential');
    const quotaId = parseMpcWalletSigningQuotaId('quota:persisted-credential');
    const authorityId = parseWalletAuthorityId('authority:persisted-credential');
    if (!walletSessionId.ok || !authorizationId.ok || !quotaId.ok || !authorityId.ok) {
      throw new Error('R103 persistence identifiers are invalid');
    }
    const record = buildActiveWalletSessionV1({
      walletId: fixture.approval.walletId,
      authorityId: authorityId.value,
      authMethodId: fixture.sourceWalletAuthMethodId,
      authorizationId: authorizationId.value,
      quotaId: quotaId.value,
      authorityDigestB64u: fixture.packageSetDigestB64u,
      authorityRevocationEpoch: 0,
      capabilitySubjects: [
        {
          kind: 'sign',
          keyFamily: 'ed25519',
          materialActivation: fixture.sourceMaterialActivation,
        },
      ],
      issuedAtMs: 2_100,
      expiresAtMs: 10_000,
    });
    const operationCredential = parseWalletSessionOperationCredentialV1({
      kind: 'opaque_wallet_session_operation_credential_v1',
      token: `wst_${'b'.repeat(43)}`,
      walletSessionId: walletSessionId.value,
    });
    const stored = toStoredExactWalletSessionAuthorizationRowV6(record, operationCredential);

    expect(stored.wallet_session_id).toBe(walletSessionId.value);
    expect(stored.wallet_session_id).not.toBe(record.authorizationId);
    expect(stored.record.quotaId).toBe(quotaId.value);
    expect(
      parseStoredExactWalletSessionAuthorizationRowV6(
        JSON.parse(JSON.stringify(stored)),
      ),
    ).toEqual({ record, operationCredential, physicalKey: walletSessionId.value });
    expect(
      parseStoredExactWalletSessionAuthorizationRowV6({
        ...stored,
        wallet_session_id: record.authorizationId,
      }),
    ).toBeNull();
    const withoutQuota = Object.fromEntries(
      Object.entries(record).filter(([field]) => field !== 'quotaId'),
    );
    expect(() => parseActiveWalletSessionV1(withoutQuota)).toThrow(/quotaId/);
  });

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
      targetFactor: fixture.payload.targetFactor,
      sessionRevision: 2,
      claimedAtMs: 1_500,
      claimExpiresAtMs: fixture.payload.expiresAtMs,
    });
    const claimDigest = await computeLinkedDeviceSessionClaimDigestV1(claim);
    const approvalDigest = await computeLinkedDeviceApprovalDigestV1(fixture.approval);

    expect(claimDigest).toBe(await computeLinkedDeviceSessionClaimDigestV1(claim));
    expect(approvalDigest).toBe(await computeLinkedDeviceApprovalDigestV1(fixture.approval));
    expect(
      await computeLinkedDeviceApprovalDigestV1({
        ...fixture.approval,
        expiresAtMs: fixture.approval.expiresAtMs - 1,
      }),
    ).not.toBe(approvalDigest);
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

    for (const state of states) expect(parseLinkSessionStateV1(state)).toEqual(state);
    expect(() =>
      parseLinkSessionStateV1({
        state: 'authority_pending_local_install',
        deviceId: String(fixture.approval.deviceId),
        authorityId,
        packageSetDigestB64u: String(fixture.packageSetDigestB64u),
        cancelledAtMs: 3_000,
      }),
    ).toThrow();
  });

  test('parses the browser projection and event at the strict shared boundary', () => {
    const fixture = buildR103DeviceLinkFixture();
    const projection = parseLinkSessionProjectionV1({
      kind: 'linked_device_session_projection_v1',
      linkSessionId: fixture.payload.linkSessionId,
      qrPayload: fixture.payload,
      revision: 1,
      createdAtMs: fixture.payload.issuedAtMs,
      updatedAtMs: fixture.payload.issuedAtMs,
      state: {
        state: 'claimed',
        deviceId: String(fixture.approval.deviceId),
      },
    });
    expect(projection.state).toEqual({
      state: 'claimed',
      deviceId: fixture.approval.deviceId,
    });
    expect(
      parseLinkSessionTransportEventV1({
        kind: 'linked_device_session_event_v1',
        linkSessionId: fixture.payload.linkSessionId,
        state: {
          state: 'authority_pending_local_install',
          deviceId: String(fixture.approval.deviceId),
          authorityId: 'authority:r103',
          packageSetDigestB64u: String(fixture.packageSetDigestB64u),
        },
        emittedAtMs: fixture.payload.issuedAtMs,
      }).state,
    ).toEqual({
      state: 'authority_pending_local_install',
      deviceId: fixture.approval.deviceId,
      authorityId: 'authority:r103',
      packageSetDigestB64u: fixture.packageSetDigestB64u,
    });
    expect(() =>
      parseLinkSessionStateV1({
        state: 'authority_pending_local_install',
        deviceId: String(fixture.approval.deviceId),
        authorityId: 'authority:r103',
        packageSetDigestB64u: String(fixture.packageSetDigestB64u),
        cancelledAtMs: 3_000,
      }),
    ).toThrow();
  });

  test('parses approval responses through the compact linear session state', () => {
    const fixture = buildR103DeviceLinkFixture();
    const pending = {
      state: 'awaiting_target_factor' as const,
      deviceId: String(fixture.approval.deviceId),
    };

    expect(parseLinkedDeviceApprovalResultV1({ outcome: 'pending', state: pending })).toEqual({
      outcome: 'pending',
      state: pending,
    });
    expect(
      parseLinkedDeviceApprovalResultV1({
        outcome: 'replayed',
        replay: { state: 'pending', session: pending },
      }),
    ).toEqual({
      outcome: 'replayed',
      replay: { state: 'pending', session: pending },
    });
  });
});
