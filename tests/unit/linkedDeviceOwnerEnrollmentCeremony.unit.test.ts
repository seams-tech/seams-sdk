import { expect, test } from '@playwright/test';
import {
  parseLinkedDeviceOwnerEnrollmentCeremonyV1,
  parseLinkedDeviceTargetPreparationV1,
} from '../../packages/shared-ts/src/device-linking/parsers';
import {
  buildR103DeviceLinkFixture,
  buildR103OwnerEnrollmentCeremonyV1,
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
  return { ...buildR103OwnerEnrollmentCeremonyV1(), ...overrides };
}

test('a preparation without the owner ceremony does not exist', async () => {
  // A preparation is minted from the approval that started the ceremony, so
  // "not started yet" is the absence of the whole record rather than a
  // preparation Device 2 could act on but never finalize.
  const { ownerEnrollment: _dropped, ...rest } = (
    await buildR103TargetCredentialFixture(buildR103DeviceLinkFixture())
  ).preparation;
  expect(() => parseLinkedDeviceTargetPreparationV1(rest)).toThrow(/ownerEnrollment/);
});

test('a preparation carrying the owner ceremony round-trips it', async () => {
  const preparation = (await buildR103TargetCredentialFixture(buildR103DeviceLinkFixture()))
    .preparation;
  const parsed = parseLinkedDeviceTargetPreparationV1(preparation);
  expect(parsed.ownerEnrollment).toEqual(preparation.ownerEnrollment);
  expect(parseLinkedDeviceTargetPreparationV1(parsed)).toEqual(parsed);
});

test('a preparation may not outlive the ceremony it will be finalized by', async () => {
  const preparation = (await buildR103TargetCredentialFixture(buildR103DeviceLinkFixture()))
    .preparation;
  expect(() =>
    parseLinkedDeviceTargetPreparationV1({
      ...preparation,
      expiresAtMs: preparation.ownerEnrollment.expiresAtMs + 1,
    }),
  ).toThrow(/must not outlive its owner enrollment ceremony/);
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
  ).toThrow(/must be an object/);
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
  for (const omitted of ['ownerEnrollment', 'orderedChildren', 'deviceId'] as const) {
    const { [omitted]: _dropped, ...rest } = preparation;
    expect(() => parseLinkedDeviceTargetPreparationV1(rest)).toThrow(
      new RegExp(`${omitted} is required`),
    );
  }
});
