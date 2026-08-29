import { expect, test } from '@playwright/test';
import {
  computeLinkedDevicePasskeyTargetConfigurationDigestV1,
  computeLinkedDeviceTargetPreparationDigestV1,
} from '../../packages/shared-ts/src/device-linking/digests';
import {
  parseLinkedDeviceTargetPreparationRequestV1,
  parseLinkedDeviceTargetPreparationV1,
} from '../../packages/shared-ts/src/device-linking/parsers';
import {
  buildEmailOtpTargetPreparationFixtureV1,
  buildPasskeyTargetPreparationFixtureV1,
} from './helpers/linkedDeviceTargetPreparation.fixtures';
import { parseWebAuthnRpId } from '../../packages/shared-ts/src/utils/domainIds';
import { base64UrlEncode } from '../../packages/shared-ts/src/utils/base64';
import { normalizeLinkedDevicePasskeyTargetConfigurationV1 } from '../../packages/wallet-server/src/router/cloudflare/d1/auth/d1RouterApiAuthConfig';

test('passkey target preparation round-trips its server-owned creation options', async () => {
  const preparation = buildPasskeyTargetPreparationFixtureV1();
  const roundTripped = parseLinkedDeviceTargetPreparationV1(
    JSON.parse(JSON.stringify(preparation)),
  );
  expect(roundTripped).toEqual(preparation);

  const digest = await computeLinkedDeviceTargetPreparationDigestV1(preparation);
  const changedOptions = parseLinkedDeviceTargetPreparationV1({
    ...preparation,
    passkeyCreationOptions: {
      ...preparation.passkeyCreationOptions,
      challengeB64u: 'different-target-preparation-challenge',
    },
  });
  await expect(computeLinkedDeviceTargetPreparationDigestV1(changedOptions)).resolves.not.toEqual(
    digest,
  );
});

test('target preparation authenticates and digests the worker delivery recipient', async () => {
  const preparation = buildPasskeyTargetPreparationFixtureV1();
  const request = parseLinkedDeviceTargetPreparationRequestV1({
    kind: 'linked_device_target_preparation_request_v1',
    linkSessionId: preparation.linkSessionId,
    deliveryRecipientPublicKey65B64u: preparation.deliveryRecipientPublicKey65B64u,
  });
  expect(request.deliveryRecipientPublicKey65B64u).toBe(
    preparation.deliveryRecipientPublicKey65B64u,
  );

  const originalDigest = await computeLinkedDeviceTargetPreparationDigestV1(preparation);
  const changedRecipient = base64UrlEncode(
    Uint8Array.from({ length: 65 }, (_, index) => (index === 0 ? 4 : 5)),
  );
  const changedPreparation = parseLinkedDeviceTargetPreparationV1({
    ...preparation,
    deliveryRecipientPublicKey65B64u: changedRecipient,
  });
  await expect(computeLinkedDeviceTargetPreparationDigestV1(changedPreparation)).resolves.not.toBe(
    originalDigest,
  );
});

test('target preparation rejects malformed delivery recipients at the boundary', () => {
  const preparation = buildPasskeyTargetPreparationFixtureV1();
  expect(() =>
    parseLinkedDeviceTargetPreparationRequestV1({
      kind: 'linked_device_target_preparation_request_v1',
      linkSessionId: preparation.linkSessionId,
      deliveryRecipientPublicKey65B64u: base64UrlEncode(new Uint8Array(65)),
    }),
  ).toThrow(/uncompressed SEC1 P-256 point/);
});

test('passkey target configuration digest binds both managed RP and origin', async () => {
  const preparation = buildPasskeyTargetPreparationFixtureV1();
  const configuration = {
    rpId: preparation.passkeyCreationOptions.rpId,
    expectedOrigin: 'https://wallet.example.test',
  };
  const digest = await computeLinkedDevicePasskeyTargetConfigurationDigestV1(configuration);
  const changedOrigin = await computeLinkedDevicePasskeyTargetConfigurationDigestV1({
    ...configuration,
    expectedOrigin: 'https://app.example.test',
  });
  const changedRpIdResult = parseWebAuthnRpId('app.example.test');
  if (!changedRpIdResult.ok) throw new Error(changedRpIdResult.error.message);
  const changedRpId = await computeLinkedDevicePasskeyTargetConfigurationDigestV1({
    ...configuration,
    rpId: changedRpIdResult.value,
  });

  expect(digest).not.toBe(changedOrigin);
  expect(digest).not.toBe(changedRpId);
});

test('admitted request origin must be canonical and inside the managed RP', () => {
  expect(
    normalizeLinkedDevicePasskeyTargetConfigurationV1({
      expectedOrigin: 'https://wallet.example.test',
      targetPasskeyRpId: 'wallet.example.test',
    }),
  ).toEqual({
    rpId: 'wallet.example.test',
    expectedOrigin: 'https://wallet.example.test',
  });
  expect(() =>
    normalizeLinkedDevicePasskeyTargetConfigurationV1({
      expectedOrigin: 'https://attacker.example.test',
      targetPasskeyRpId: 'wallet.example.test',
    }),
  ).toThrow(/outside the configured RP ID/);
});

test('Email OTP target preparation rejects passkey creation options', () => {
  const preparation = buildEmailOtpTargetPreparationFixtureV1();
  expect(() =>
    parseLinkedDeviceTargetPreparationV1({
      ...preparation,
      passkeyCreationOptions: {},
    }),
  ).toThrow(/passkeyCreationOptions/);
});

test('passkey target preparation rejects private creation material', () => {
  const preparation = buildPasskeyTargetPreparationFixtureV1();
  expect(() =>
    parseLinkedDeviceTargetPreparationV1({
      ...preparation,
      passkeyCreationOptions: {
        ...preparation.passkeyCreationOptions,
        user: {
          ...preparation.passkeyCreationOptions.user,
          privateKey: 'must-stay-local',
        },
      },
    }),
  ).toThrow(/passkeyCreationOptions\.user/);
});
