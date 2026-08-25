import { expect, test } from '@playwright/test';
import {
  buildLinkedDeviceApprovalV1,
  buildLinkedDeviceTargetPreparationV1,
  parseLinkedDeviceApprovalV1,
  parseLinkedDeviceTargetPreparationV1,
} from '../../packages/shared-ts/src/device-linking/parsers';
import { base64UrlEncode } from '../../packages/shared-ts/src/utils/base64';
import { parseLinkedDeviceEcdsaSourceContributionPreparationV1 } from '../../packages/shared-ts/src/device-linking/sourceContribution';
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

test('the ECDSA source contribution preparation keeps the Rust wire shape', () => {
  const preparation = buildEcdsaSourceContributionPreparationFixture();
  const parsed = parseLinkedDeviceEcdsaSourceContributionPreparationV1(
    JSON.parse(JSON.stringify(preparation)),
  );
  expect(JSON.parse(JSON.stringify(parsed))).toEqual(preparation);

  expect(() =>
    parseLinkedDeviceEcdsaSourceContributionPreparationV1({
      ...preparation,
      target: { ...preparation.target, sourceMaterialActivation: preparation.target.activation },
    }),
  ).toThrow(/unknown or missing fields/);
});

function buildEcdsaSourceContributionPreparationFixture() {
  const compressedPublicKey = base64UrlEncode(new Uint8Array([2, ...new Array(32).fill(1)]));
  const recipientPublicKey = base64UrlEncode(new Uint8Array(32).fill(2));
  const secondRecipientPublicKey = base64UrlEncode(new Uint8Array(32).fill(3));
  const digest = base64UrlEncode(new Uint8Array(32).fill(4));
  const activation = (suffix: string) => ({
    kind: 'mpc_material_activation_ref' as const,
    activationId: `activation:${suffix}`,
    capability: 'capability:source',
    materialOwner: 'owner:wallet',
    keyBinding: `key-binding:${suffix}`,
    lifecycleBinding: `lifecycle:${suffix}`,
    signingWorker: 'worker:source',
  });

  return {
    linkSessionId: 'link-session:r103-ecdsa',
    enrollmentId: 'enrollment:r103-ecdsa',
    sourceAuthorityId: 'authority:r103-ecdsa',
    source: {
      activation: activation('source'),
      clientPublicKey33B64u: compressedPublicKey,
      relayerPublicKey33B64u: compressedPublicKey,
      thresholdPublicKey33B64u: compressedPublicKey,
      thresholdEthereumAddress20B64u: base64UrlEncode(new Uint8Array(20).fill(5)),
    },
    target: {
      activation: activation('target'),
      targetDeviceId: 'device:r103-ecdsa',
      targetFactorVerificationDigestB64u: digest,
      clientRecipientPublicKeyB64u: recipientPublicKey,
      signingWorkerRecipientPublicKeyB64u: secondRecipientPublicKey,
    },
  };
}
