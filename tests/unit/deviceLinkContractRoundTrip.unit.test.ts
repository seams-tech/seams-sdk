import { expect, test } from '@playwright/test';
import {
  buildLinkedDeviceApprovalV1,
  buildLinkedDeviceTargetPreparationV1,
  parseLinkedDeviceApprovalV1,
  parseLinkedDeviceTargetPreparationV1,
} from '../../packages/shared-ts/src/device-linking/parsers';
import { buildR103DeviceLinkFixture } from './helpers/deviceLinkContracts.fixtures';
import { buildPasskeyTargetPreparationFixtureV1 } from './helpers/linkedDeviceTargetPreparation.fixtures';

/**
 * Anything a builder produces, its parser must accept.
 *
 * The builders spread their arguments and return without parsing, so the two
 * halves can drift: a field can be added to the type, required by the builder's
 * argument type, and covered by the digest encoder, while the parser's
 * exact-record allow-list never learns about it.
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
    targetFactor: fixture.approval.targetFactor,
    ownerAuthorization: fixture.approval.ownerAuthorization,
    orderedOwnerSourceLaneHints: fixture.approval.orderedOwnerSourceLaneHints,
    approvedAtMs: fixture.approval.approvedAtMs,
    expiresAtMs: fixture.approval.expiresAtMs,
  });
  expect(parseLinkedDeviceApprovalV1(JSON.parse(JSON.stringify(built)))).toEqual(built);
});

test('a target preparation survives its own builder and parser', () => {
  const preparation = buildPasskeyTargetPreparationFixtureV1();
  const { kind: _kind, ...builderArgs } = preparation;
  void _kind;
  const built = buildLinkedDeviceTargetPreparationV1(builderArgs);
  expect(parseLinkedDeviceTargetPreparationV1(JSON.parse(JSON.stringify(built)))).toEqual(built);
});
