import { expect, test } from '@playwright/test';
import {
  parseLinkedDeviceOwnerEnrollmentCeremonyV1,
  parseLinkedDeviceTargetPreparationV1,
} from '../../packages/shared-ts/src/device-linking/parsers';
import {
  buildR103DeviceLinkFixture,
  buildR103TargetCredentialFixture,
} from './helpers/deviceLinkContracts.fixtures';

/**
 * Refactor 103 Phase 8 folds the canonical owner add-auth-method ceremony into
 * the linked-device target preparation, so Device 2's single WebAuthn creation
 * *is* that ceremony's registration. Device 2 has no owner authority and
 * cannot start one; Device 1 does, during approval, and its identity arrives
 * here.
 */
function ceremony(overrides: Record<string, unknown> = {}) {
  return {
    kind: 'linked_device_owner_enrollment_ceremony_v1',
    addAuthMethodCeremonyId: 'add-auth-method-ceremony:r103p8',
    registration: {
      kind: 'webauthn_add_auth_method_registration_v1',
      challengeB64u: 'Y2hhbGxlbmdl',
      rpId: 'wallet.example.localhost',
    },
    ...overrides,
  };
}

test('a preparation without the owner ceremony still parses', async () => {
  // Absence is the signal that Device 1 has not started the ceremony yet. It
  // is what tells Device 2 to keep waiting rather than create a passkey no
  // ceremony can finalize.
  const preparation = (await buildR103TargetCredentialFixture(buildR103DeviceLinkFixture())).preparation;
  const parsed = parseLinkedDeviceTargetPreparationV1(preparation);
  expect('ownerEnrollment' in parsed).toBe(false);
});

test('a preparation carrying the owner ceremony round-trips it', async () => {
  const preparation = {
    ...(await buildR103TargetCredentialFixture(buildR103DeviceLinkFixture())).preparation,
    ownerEnrollment: ceremony(),
  };
  const parsed = parseLinkedDeviceTargetPreparationV1(preparation);
  expect(parsed.ownerEnrollment).toEqual(ceremony());
  expect(parseLinkedDeviceTargetPreparationV1(parsed)).toEqual(parsed);
});

test('the ceremony must name itself and its add-auth-method ceremony', () => {
  expect(() =>
    parseLinkedDeviceOwnerEnrollmentCeremonyV1(ceremony({ kind: 'something_else' })),
  ).toThrow(/kind is invalid/);
  expect(() =>
    parseLinkedDeviceOwnerEnrollmentCeremonyV1(ceremony({ addAuthMethodCeremonyId: '' })),
  ).toThrow(/addAuthMethodCeremonyId/);
  expect(() =>
    parseLinkedDeviceOwnerEnrollmentCeremonyV1(ceremony({ registration: 'not-an-object' })),
  ).toThrow(/registration must be an object/);
});

test('nothing rides along beside the ceremony', async () => {
  // The registration options stay opaque on purpose — re-validating their
  // shape here would fork the canonical add-passkey contract — so the
  // surrounding envelope is what this boundary keeps exact.
  expect(() =>
    parseLinkedDeviceOwnerEnrollmentCeremonyV1(ceremony({ walletId: 'alice.testnet' })),
  ).toThrow(/LinkedDeviceOwnerEnrollmentCeremonyV1/);

  const smuggled = {
    ...(await buildR103TargetCredentialFixture(buildR103DeviceLinkFixture())).preparation,
    ownerEnrollment: ceremony(),
    addAuthMethodCeremonyId: 'smuggled',
  };
  expect(() => parseLinkedDeviceTargetPreparationV1(smuggled)).toThrow(
    /LinkedDeviceTargetPreparationV1/,
  );
});

test('a preparation still requires every field the R102 children need', async () => {
  const preparation = (await buildR103TargetCredentialFixture(buildR103DeviceLinkFixture())).preparation;
  for (const omitted of ['challengeB64u', 'rpId', 'orderedChildren', 'deviceId'] as const) {
    const { [omitted]: _dropped, ...rest } = preparation;
    expect(() => parseLinkedDeviceTargetPreparationV1(rest)).toThrow(
      new RegExp(`${omitted} is required`),
    );
  }
});
