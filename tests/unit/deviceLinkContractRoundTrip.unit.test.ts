import { expect, test } from '@playwright/test';
import {
  buildLinkedDeviceApprovalV1,
  buildLinkedDeviceEnrollmentTranscriptV1,
  buildLinkedDeviceTargetPreparationV1,
  parseLinkedDeviceApprovalV1,
  parseLinkedDeviceEnrollmentTranscriptV1,
  parseLinkedDeviceTargetPreparationV1,
} from '../../packages/shared-ts/src/device-linking/parsers';
import {
  buildR103DeviceLinkFixture,
  buildR103OwnerEnrollmentCeremonyV1,
  buildR103TargetCredentialFixture,
} from './helpers/deviceLinkContracts.fixtures';

/**
 * Anything a builder produces, its parser must accept.
 *
 * The builders spread their arguments and return without parsing, so the two
 * halves can drift: a field can be added to the type, required by the builder's
 * argument type, and covered by the digest encoder, while the parser's
 * exact-record allow-list never learns about it. That is not hypothetical —
 * `ownerEnrollment` shipped that way and closed the approval path entirely,
 * because every other test held the builder's output and never re-read it.
 *
 * These round-trips are the standing guard. They fail on the next field added
 * to one side only, which is the whole point.
 */
const fixture = buildR103DeviceLinkFixture();

test('an approval survives its own parser', () => {
  const built = buildLinkedDeviceApprovalV1({
    linkSessionId: fixture.approval.linkSessionId,
    walletId: fixture.approval.walletId,
    enrollmentId: fixture.approval.enrollmentId,
    deviceId: fixture.approval.deviceId,
    linkPublicKeyB64u: fixture.approval.linkPublicKeyB64u,
    devicePublicKeyB64u: fixture.approval.devicePublicKeyB64u,
    permission: fixture.approval.permission,
    ownerAuthorization: fixture.approval.ownerAuthorization,
    ownerEnrollment: fixture.approval.ownerEnrollment,
    policyDigestB64u: fixture.approval.policyDigestB64u,
    operationId: fixture.approval.operationId,
    idempotencyKey: fixture.approval.idempotencyKey,
    orderedKeyBindings: fixture.approval.orderedKeyBindings,
    protocolVersions: fixture.approval.protocolVersions,
    approvedAtMs: fixture.approval.approvedAtMs,
    expiresAtMs: fixture.approval.expiresAtMs,
  });
  expect(parseLinkedDeviceApprovalV1(JSON.parse(JSON.stringify(built)))).toEqual(built);
});

test('an enrollment transcript survives its own parser', () => {
  const built = buildLinkedDeviceEnrollmentTranscriptV1({
    linkSessionId: fixture.approval.linkSessionId,
    walletId: fixture.approval.walletId,
    enrollmentId: fixture.approval.enrollmentId,
    deviceId: fixture.approval.deviceId,
    linkPublicKeyB64u: fixture.approval.linkPublicKeyB64u,
    devicePublicKeyB64u: fixture.approval.devicePublicKeyB64u,
    permission: fixture.approval.permission,
    ownerAuthorization: fixture.approval.ownerAuthorization,
    ownerEnrollment: fixture.approval.ownerEnrollment,
    policyDigestB64u: fixture.approval.policyDigestB64u,
    operationId: fixture.approval.operationId,
    idempotencyKey: fixture.approval.idempotencyKey,
    orderedKeyBindings: fixture.approval.orderedKeyBindings,
    protocolVersions: fixture.approval.protocolVersions,
    approvedAtMs: fixture.approval.approvedAtMs,
    expiresAtMs: fixture.approval.expiresAtMs,
  });
  expect(parseLinkedDeviceEnrollmentTranscriptV1(JSON.parse(JSON.stringify(built)))).toEqual(built);
});

test('a target preparation survives its own parser', async () => {
  const ownerEnrollment = buildR103OwnerEnrollmentCeremonyV1();
  const { preparation } = await buildR103TargetCredentialFixture(fixture);
  const built = buildLinkedDeviceTargetPreparationV1({
    linkSessionId: fixture.approval.linkSessionId,
    walletId: fixture.approval.walletId,
    enrollmentId: fixture.approval.enrollmentId,
    deviceId: fixture.approval.deviceId,
    ownerEnrollment,
    orderedChildren: preparation.orderedChildren,
    issuedAtMs: preparation.issuedAtMs,
    expiresAtMs: preparation.expiresAtMs,
  });
  expect(parseLinkedDeviceTargetPreparationV1(JSON.parse(JSON.stringify(built)))).toEqual(built);
});
