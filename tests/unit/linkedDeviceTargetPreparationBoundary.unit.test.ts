import { expect, test } from '@playwright/test';
import {
  computeLinkedDevicePasskeyTargetConfigurationDigestV1,
  computeLinkedDeviceTargetPreparationDigestV1,
} from '../../packages/shared-ts/src/device-linking/digests';
import { parseLinkedDeviceTargetPreparationV1 } from '../../packages/shared-ts/src/device-linking/parsers';
import {
  buildEmailOtpTargetPreparationFixtureV1,
  buildPasskeyTargetPreparationFixtureV1,
} from './helpers/linkedDeviceTargetPreparation.fixtures';
import { parseWebAuthnRpId } from '../../packages/shared-ts/src/utils/domainIds';
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

test('server composition requires a canonical origin inside the managed RP', () => {
  expect(
    normalizeLinkedDevicePasskeyTargetConfigurationV1({
      targetPasskeyOrigin: 'https://wallet.example.test',
      targetPasskeyRpId: 'wallet.example.test',
    }),
  ).toEqual({
    rpId: 'wallet.example.test',
    expectedOrigin: 'https://wallet.example.test',
  });
  expect(() =>
    normalizeLinkedDevicePasskeyTargetConfigurationV1({
      targetPasskeyOrigin: 'https://attacker.example.test',
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
