import { expect, test } from '@playwright/test';
import { computeLinkedDeviceTargetPreparationDigestV1 } from '../../packages/shared-ts/src/device-linking/digests';
import { parseLinkedDeviceTargetPreparationV1 } from '../../packages/shared-ts/src/device-linking/parsers';
import {
  buildEmailOtpTargetPreparationFixtureV1,
  buildPasskeyTargetPreparationFixtureV1,
} from './helpers/linkedDeviceTargetPreparation.fixtures';

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
