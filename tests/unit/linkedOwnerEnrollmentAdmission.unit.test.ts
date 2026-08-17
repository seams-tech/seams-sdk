import { expect, test } from '@playwright/test';
import { admitLinkedOwnerEnrollmentFinalizeV1 } from '../../packages/sdk-server-ts/src/core/deviceLinking/linkedOwnerEnrollmentAdmission';
import type { LinkedDeviceSessionRecordV1 } from '../../packages/sdk-server-ts/src/core/deviceLinking/linkedDeviceSession';
import type { LinkedDeviceTargetPreparationV1 } from '../../packages/shared-ts/src/device-linking/contracts';
import { parseLinkedDeviceTargetPreparationV1 } from '../../packages/shared-ts/src/device-linking/parsers';
import { parseDigestB64u } from '../../packages/shared-ts/src/utils/canonicalPrimitives';
import { base64UrlEncode } from '../../packages/shared-ts/src/utils/base64';
import {
  buildR103DeviceLinkFixture,
  buildR103OwnerEnrollmentCeremonyV1,
  buildR103TargetCredentialFixture,
} from './helpers/deviceLinkContracts.fixtures';

/**
 * The canonical add-auth-method finalize is owner-authenticated. Device 2's
 * arrives authenticated only by its link session, so the server has to prove
 * the named ceremony is the one Device 1 started *for this enrollment*. These
 * own that proof: without it a linked device could finalize a ceremony it was
 * never approved for.
 */
const CEREMONY_ID = 'add-auth-method-ceremony:r103p8';
const NOW_MS = 1_800_000_000_000;
const MANIFEST_DIGEST = parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(7)));

async function preparation(
  overrides: Partial<Record<string, unknown>> = {},
): Promise<LinkedDeviceTargetPreparationV1> {
  const base = (await buildR103TargetCredentialFixture(buildR103DeviceLinkFixture()))
    .preparation;
  return parseLinkedDeviceTargetPreparationV1({
    ...base,
    issuedAtMs: NOW_MS - 1_000,
    expiresAtMs: NOW_MS + 60_000,
    ownerEnrollment: buildR103OwnerEnrollmentCeremonyV1({
      addAuthMethodCeremonyId: CEREMONY_ID,
      expiresAtMs: NOW_MS + 120_000,
    }),
    ...overrides,
  });
}

/**
 * A session already device-authenticated for this link session, parked at a
 * state that carries the verified key manifest.
 */
function session(
  prepared: LinkedDeviceTargetPreparationV1,
  overrides: { readonly state?: LinkedDeviceSessionRecordV1['state']; readonly claim?: unknown } = {},
): LinkedDeviceSessionRecordV1 {
  const claim = {
    kind: 'linked_device_session_claim_v1' as const,
    linkSessionId: prepared.linkSessionId,
    walletId: prepared.walletId,
    enrollmentId: prepared.enrollmentId,
    deviceId: prepared.deviceId,
    devicePublicKeyB64u: 'device-public-key',
    claimedAtMs: NOW_MS - 5_000,
    claimExpiresAtMs: NOW_MS + 60_000,
  };
  return {
    linkSessionId: prepared.linkSessionId,
    state: overrides.state ?? {
      state: 'provisioning',
      linkSessionId: prepared.linkSessionId,
      walletId: prepared.walletId,
      enrollmentId: prepared.enrollmentId,
      keyManifestDigestB64u: MANIFEST_DIGEST,
    },
    claimTranscript:
      overrides.claim === null ? undefined : { value: overrides.claim ?? claim },
  } as unknown as LinkedDeviceSessionRecordV1;
}

test('admits the ceremony Device 1 started for this exact enrollment', async () => {
  const prepared = await preparation();
  const result = admitLinkedOwnerEnrollmentFinalizeV1({
    session: session(prepared),
    preparation: prepared,
    addAuthMethodCeremonyId: CEREMONY_ID,
    requestedAtMs: NOW_MS,
  });

  expect(result).toEqual({
    ok: true,
    admission: {
      walletId: prepared.walletId,
      enrollmentId: prepared.enrollmentId,
      deviceId: prepared.deviceId,
      keyManifestDigestB64u: MANIFEST_DIGEST,
      addAuthMethodCeremonyId: CEREMONY_ID,
    },
  });
});

test('refuses a ceremony this enrollment was never approved for', async () => {
  const prepared = await preparation();
  expect(
    admitLinkedOwnerEnrollmentFinalizeV1({
      session: session(prepared),
      preparation: prepared,
      addAuthMethodCeremonyId: 'add-auth-method-ceremony:someone-else',
      requestedAtMs: NOW_MS,
    }),
  ).toEqual({ ok: false, reason: 'ceremony_does_not_match_enrollment' });
});

test('refuses before the key manifest exists', async () => {
  const prepared = await preparation();
  // `awaiting_target_passkey` precedes the R102 commit, so there is no
  // manifest for the new owner credential to be bound to.
  expect(
    admitLinkedOwnerEnrollmentFinalizeV1({
      session: session(prepared, {
        state: {
          state: 'awaiting_target_passkey',
          linkSessionId: prepared.linkSessionId,
          walletId: prepared.walletId,
          enrollmentId: prepared.enrollmentId,
          credentialDeadlineMs: NOW_MS + 60_000,
        },
      }),
      preparation: prepared,
      addAuthMethodCeremonyId: CEREMONY_ID,
      requestedAtMs: NOW_MS,
    }),
  ).toEqual({ ok: false, reason: 'session_has_no_key_manifest' });
});

test('refuses an unclaimed session', async () => {
  const prepared = await preparation();
  expect(
    admitLinkedOwnerEnrollmentFinalizeV1({
      session: session(prepared, { claim: null }),
      preparation: prepared,
      addAuthMethodCeremonyId: CEREMONY_ID,
      requestedAtMs: NOW_MS,
    }),
  ).toEqual({ ok: false, reason: 'session_not_claimed' });
});

test('refuses a preparation belonging to another wallet, enrollment, or device', async () => {
  const prepared = await preparation();
  for (const claim of [
    { walletId: 'bob.testnet' },
    { enrollmentId: 'enrollment:other' },
    { deviceId: 'device:other' },
  ]) {
    const mismatched = session(prepared, {
      claim: {
        kind: 'linked_device_session_claim_v1',
        linkSessionId: prepared.linkSessionId,
        walletId: prepared.walletId,
        enrollmentId: prepared.enrollmentId,
        deviceId: prepared.deviceId,
        devicePublicKeyB64u: 'device-public-key',
        claimedAtMs: NOW_MS - 5_000,
        claimExpiresAtMs: NOW_MS + 60_000,
        ...claim,
      },
    });
    const result = admitLinkedOwnerEnrollmentFinalizeV1({
      session: mismatched,
      preparation: prepared,
      addAuthMethodCeremonyId: CEREMONY_ID,
      requestedAtMs: NOW_MS,
    });
    expect(result.ok).toBe(false);
  }
});

test('refuses an expired preparation', async () => {
  const prepared = await preparation();
  expect(
    admitLinkedOwnerEnrollmentFinalizeV1({
      session: session(prepared),
      preparation: prepared,
      addAuthMethodCeremonyId: CEREMONY_ID,
      requestedAtMs: prepared.expiresAtMs,
    }),
  ).toEqual({ ok: false, reason: 'preparation_expired' });
});
