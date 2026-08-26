import { buildLinkedDeviceSessionClaimV1 } from '../../../packages/shared-ts/src/device-linking/parsers';
import {
  computeLinkedDeviceApprovalDigestV1,
  computeLinkedDeviceSessionClaimDigestV1,
} from '../../../packages/shared-ts/src/device-linking/digests';
import {
  parseLinkedDeviceSessionRecordV1,
  type LinkedDeviceSessionRecordV1,
} from '../../../packages/wallet-server/src/core/deviceLinking/linkedDeviceSession';
import { parseWalletAuthorityId } from '../../../packages/shared-ts/src/utils/domainIds';
import {
  buildR103EcdsaSourceContributionPreparationV1,
  buildR103EcdsaSourceContributionV1,
  type R103DeviceLinkFixture,
} from './deviceLinkContracts.fixtures';

export async function buildR103ActiveLinkedDeviceSessionRecordV1(
  fixture: R103DeviceLinkFixture,
): Promise<Extract<LinkedDeviceSessionRecordV1, { readonly state: { readonly state: 'active' } }>> {
  const authorityId = parseWalletAuthorityId('authority:r103');
  if (!authorityId.ok) throw new Error(authorityId.error.message);
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
  const sourceContributionPreparation = buildR103EcdsaSourceContributionPreparationV1(fixture);
  const sourceContribution = buildR103EcdsaSourceContributionV1(fixture);
  const approval = { ...fixture.approval, sourceContribution: [sourceContribution] as const };
  const approvalDigest = await computeLinkedDeviceApprovalDigestV1(approval);
  const record = parseLinkedDeviceSessionRecordV1({
    version: 'linked_device_session_v1',
    linkSessionId: fixture.payload.linkSessionId,
    qrPayload: fixture.payload,
    state: {
      state: 'active',
      deviceId: fixture.approval.deviceId,
      authorityId: authorityId.value,
      activatedAtMs: 9_000,
    },
    revision: 4,
    claimTranscript: {
      digestB64u: await computeLinkedDeviceSessionClaimDigestV1(claim),
      value: claim,
    },
    approvalTranscript: {
      digestB64u: approvalDigest,
      value: approval,
      sourceSignerManifest: fixture.sourceSignerManifest,
      sourceKeyManifestDigestsB64u: { ed25519: fixture.packageSetDigestB64u },
      sourceAuthorityDigestB64u: fixture.sourceAuthorityDigestB64u,
    },
    targetFactor: fixture.approval.targetFactor,
    authorityId: authorityId.value,
    packageSetDigestB64u: fixture.packageSetDigestB64u,
    sourceContributionPreparation,
    sourceContributionTranscript: {
      digestB64u: approvalDigest,
      value: approval,
      sourceSignerManifest: fixture.sourceSignerManifest,
      sourceKeyManifestDigestsB64u: { ed25519: fixture.packageSetDigestB64u },
      sourceAuthorityDigestB64u: fixture.sourceAuthorityDigestB64u,
    },
    createdAtMs: fixture.payload.issuedAtMs,
    updatedAtMs: 9_000,
  });
  if (!isActiveSessionRecord(record)) {
    throw new Error('R103 active session fixture did not produce an active record');
  }
  return record;
}

function isActiveSessionRecord(
  record: LinkedDeviceSessionRecordV1,
): record is Extract<
  LinkedDeviceSessionRecordV1,
  { readonly state: { readonly state: 'active' } }
> {
  return record.state.state === 'active';
}

export function buildR103UnclaimedLinkedDeviceSessionRecordV1(
  fixture: R103DeviceLinkFixture,
): LinkedDeviceSessionRecordV1 {
  return parseLinkedDeviceSessionRecordV1({
    version: 'linked_device_session_v1',
    linkSessionId: fixture.payload.linkSessionId,
    qrPayload: fixture.payload,
    state: { state: 'displaying_qr' },
    revision: 1,
    createdAtMs: fixture.payload.issuedAtMs,
    updatedAtMs: fixture.payload.issuedAtMs,
  });
}

export async function buildR103AwaitingTargetPasskeySessionRecordV1(
  fixture: R103DeviceLinkFixture,
  overrides: {
    readonly state?: Extract<
      LinkedDeviceSessionRecordV1['state'],
      { readonly state: 'awaiting_target_factor' | 'provisioning' }
    >;
    readonly revision?: number;
    readonly credentialDeadlineMs?: number;
    readonly updatedAtMs?: number;
  } = {},
): Promise<LinkedDeviceSessionRecordV1> {
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
  return parseLinkedDeviceSessionRecordV1({
    version: 'linked_device_session_v1',
    linkSessionId: fixture.payload.linkSessionId,
    qrPayload: fixture.payload,
    state: overrides.state ?? {
      state: 'awaiting_target_factor',
      deviceId: fixture.approval.deviceId,
    },
    revision: overrides.revision ?? 3,
    claimTranscript: {
      digestB64u: await computeLinkedDeviceSessionClaimDigestV1(claim),
      value: claim,
    },
    approvalTranscript: {
      digestB64u: await computeLinkedDeviceApprovalDigestV1(fixture.approval),
      value: fixture.approval,
      sourceSignerManifest: fixture.sourceSignerManifest,
      sourceKeyManifestDigestsB64u: { ed25519: fixture.packageSetDigestB64u },
      sourceAuthorityDigestB64u: fixture.sourceAuthorityDigestB64u,
    },
    targetFactor: fixture.approval.targetFactor,
    createdAtMs: fixture.payload.issuedAtMs,
    updatedAtMs: overrides.updatedAtMs ?? fixture.payload.issuedAtMs + 1,
  });
}
