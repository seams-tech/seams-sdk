import { expect, test } from '@playwright/test';
import { admitLinkedOwnerEnrollmentProvenanceV1 } from '../../packages/wallet-server/src/core/deviceLinking/linkedOwnerEnrollmentProvenance';
import type { LinkedOwnerEnrollmentCeremonyReaderV1 } from '../../packages/wallet-server/src/core/deviceLinking/linkedOwnerEnrollmentProvenance';
import {
  buildR103DeviceLinkFixture,
  buildR103OwnerEnrollmentCeremonyV1,
} from './helpers/deviceLinkContracts.fixtures';

/**
 * The approval digest makes the ceremony immutable once the approval is
 * accepted. Device 1 assembles the approval body, so without a provenance check
 * the digest would faithfully seal a ceremony belonging to another wallet, or
 * registration options that never came from any ceremony at all. These own that
 * distinction.
 */
const NOW_MS = 1_800_000_000_000;

function approval() {
  return buildR103DeviceLinkFixture().approval;
}

function ceremonies(
  stored: unknown,
): LinkedOwnerEnrollmentCeremonyReaderV1 {
  return {
    getAddAuthMethodCeremony: async () => stored as never,
  };
}

function storedCeremonyFor(
  value: ReturnType<typeof approval>,
  overrides: Record<string, unknown> = {},
) {
  return {
    kind: 'passkey',
    addAuthMethodCeremonyId: value.ownerEnrollment.addAuthMethodCeremonyId,
    intent: { walletId: value.walletId },
    digestB64u: 'digest',
    orgId: 'org',
    expiresAtMs: value.ownerEnrollment.expiresAtMs,
    auth: { kind: 'webauthn_assertion', rpId: 'wallet.example.test', credentialIdB64u: 'cred' },
    passkeyRegistration: {
      rpId: String(value.ownerEnrollment.registration.rpId),
      challengeB64u: value.ownerEnrollment.registration.challengeB64u,
      options: value.ownerEnrollment.registration,
    },
    custodyEnvelope: {},
    ...overrides,
  };
}

test('admits the approval whose ceremony the server itself minted', async () => {
  const value = approval();
  expect(
    await admitLinkedOwnerEnrollmentProvenanceV1({
      approval: value,
      ceremonies: ceremonies(storedCeremonyFor(value)),
      requestedAtMs: NOW_MS,
    }),
  ).toEqual({ ok: true });
});

test('refuses a ceremony the server never minted', async () => {
  const value = approval();
  expect(
    await admitLinkedOwnerEnrollmentProvenanceV1({
      approval: value,
      ceremonies: ceremonies(null),
      requestedAtMs: NOW_MS,
    }),
  ).toEqual({ ok: false, reason: 'ceremony_not_found' });
});

test('refuses a ceremony belonging to another wallet', async () => {
  const value = approval();
  expect(
    await admitLinkedOwnerEnrollmentProvenanceV1({
      approval: value,
      ceremonies: ceremonies(
        storedCeremonyFor(value, { intent: { walletId: 'someone-else.testnet' } }),
      ),
      requestedAtMs: NOW_MS,
    }),
  ).toEqual({ ok: false, reason: 'ceremony_belongs_to_another_wallet' });
});

test('refuses registration options that were never the ceremony’s', async () => {
  // The digest would seal these faithfully; only re-reading the server's own
  // record catches that they are not what it handed out.
  const value = approval();
  const substituted = buildR103OwnerEnrollmentCeremonyV1({
    addAuthMethodCeremonyId: value.ownerEnrollment.addAuthMethodCeremonyId,
    rpId: 'attacker.example.test',
    expiresAtMs: value.ownerEnrollment.expiresAtMs,
  });
  const stored = storedCeremonyFor(value);
  expect(
    await admitLinkedOwnerEnrollmentProvenanceV1({
      approval: { ...value, ownerEnrollment: substituted },
      ceremonies: ceremonies(stored),
      requestedAtMs: NOW_MS,
    }),
  ).toEqual({ ok: false, reason: 'ceremony_relying_party_does_not_match' });
});

test('refuses an expiry the approval chose for itself', async () => {
  const value = approval();
  expect(
    await admitLinkedOwnerEnrollmentProvenanceV1({
      approval: value,
      ceremonies: ceremonies(
        storedCeremonyFor(value, { expiresAtMs: value.ownerEnrollment.expiresAtMs - 1 }),
      ),
      requestedAtMs: NOW_MS,
    }),
  ).toEqual({ ok: false, reason: 'ceremony_expiry_does_not_match' });
});

test('refuses an email-otp ceremony standing in for a passkey one', async () => {
  const value = approval();
  expect(
    await admitLinkedOwnerEnrollmentProvenanceV1({
      approval: value,
      ceremonies: ceremonies(storedCeremonyFor(value, { kind: 'email_otp' })),
      requestedAtMs: NOW_MS,
    }),
  ).toEqual({ ok: false, reason: 'ceremony_is_not_a_passkey_ceremony' });
});

test('refuses a ceremony that has already expired', async () => {
  const value = approval();
  expect(
    await admitLinkedOwnerEnrollmentProvenanceV1({
      approval: value,
      ceremonies: ceremonies(storedCeremonyFor(value)),
      requestedAtMs: value.ownerEnrollment.expiresAtMs,
    }),
  ).toEqual({ ok: false, reason: 'ceremony_expired' });
});
