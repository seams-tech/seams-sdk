import { expect, test } from '@playwright/test';
import {
  buildPasskeyCredentialObservationRecord,
  parsePasskeyCredentialObservationRecord,
  parseWebAuthnBackupFlags,
  resolveCrossDeviceCustodyReadiness,
  type EnvelopeRevision,
} from '@shared/passkey-custody';
import type {
  PasskeyEnvelopeId,
  WebAuthnCredentialIdB64u,
  WebAuthnRpId,
} from '@shared/utils/domainIds';

const RP_ID = 'wallet.example.localhost' as WebAuthnRpId;
const CREDENTIAL_ID = 'Y3JlZGVudGlhbC0x' as WebAuthnCredentialIdB64u;
const ENVELOPE_ID = 'passkey-envelope-1' as PasskeyEnvelopeId;
const REVISION = 1 as unknown as EnvelopeRevision;

/** Authenticator data is 32 bytes of RP ID hash, then the flags byte. */
function authenticatorData(flags: number): Uint8Array {
  const bytes = new Uint8Array(37);
  bytes[32] = flags;
  return bytes;
}

function observation(overrides: Record<string, unknown> = {}) {
  return {
    kind: 'passkey_credential_observation_v1',
    rpId: RP_ID,
    credentialIdB64u: CREDENTIAL_ID,
    prfSupported: true,
    backupEligible: true,
    backupState: true,
    observedAtMs: 1_000,
    ...overrides,
  };
}

test('backup flags are read from the authenticator data flags byte', () => {
  expect(parseWebAuthnBackupFlags(authenticatorData(0x00))).toEqual({
    backupEligible: false,
    backupState: false,
  });
  // BE set, BS clear: eligible for backup but not backed up yet.
  expect(parseWebAuthnBackupFlags(authenticatorData(0x08))).toEqual({
    backupEligible: true,
    backupState: false,
  });
  expect(parseWebAuthnBackupFlags(authenticatorData(0x18))).toEqual({
    backupEligible: true,
    backupState: true,
  });
  // User-presence and user-verified bits must not be mistaken for backup flags.
  expect(parseWebAuthnBackupFlags(authenticatorData(0x05))).toEqual({
    backupEligible: false,
    backupState: false,
  });
});

test('backup state without eligibility is rejected as malformed', () => {
  expect(() => parseWebAuthnBackupFlags(authenticatorData(0x10))).toThrow(
    /backup state without backup eligibility/,
  );
});

test('authenticator data shorter than its flags byte is rejected', () => {
  expect(() => parseWebAuthnBackupFlags(new Uint8Array(32))).toThrow(/too short/);
});

test('a fully backed-up credential is still not cross-device ready without an envelope', () => {
  const record = parsePasskeyCredentialObservationRecord(observation());
  expect(record.backupEligible).toBe(true);
  expect(record.backupState).toBe(true);

  // The strongest possible backup signals, and readiness is still withheld:
  // only a real PRF result sealing a server-held envelope proves portability.
  expect(
    resolveCrossDeviceCustodyReadiness({
      prfSupported: record.prfSupported,
      activeSealedEnvelope: null,
    }),
  ).toEqual({ state: 'not_ready', reason: 'no_sealed_envelope' });
});

test('a sealed envelope makes custody cross-device ready', () => {
  expect(
    resolveCrossDeviceCustodyReadiness({
      prfSupported: true,
      activeSealedEnvelope: { envelopeId: ENVELOPE_ID, envelopeRevision: REVISION },
    }),
  ).toEqual({ state: 'ready', sealedEnvelopeId: ENVELOPE_ID, envelopeRevision: REVISION });
});

test('a credential without PRF support is never ready, sealed envelope or not', () => {
  expect(
    resolveCrossDeviceCustodyReadiness({
      prfSupported: false,
      activeSealedEnvelope: { envelopeId: ENVELOPE_ID, envelopeRevision: REVISION },
    }),
  ).toEqual({ state: 'not_ready', reason: 'prf_unsupported' });
});

test('observations reject secret material and unknown fields', () => {
  expect(() =>
    parsePasskeyCredentialObservationRecord(observation({ prfFirstB64u: 'prf' })),
  ).toThrow(/must never carry plaintext custody material/);

  expect(() => parsePasskeyCredentialObservationRecord(observation({ deviceLabel: 'x' }))).toThrow(
    /is not part of/,
  );

  expect(() =>
    parsePasskeyCredentialObservationRecord(observation({ backupEligible: 'yes' })),
  ).toThrow(/backupEligible must be a boolean/);
});

test('an observation round-trips through its builder and parser', () => {
  const built = buildPasskeyCredentialObservationRecord({
    rpId: RP_ID,
    credentialIdB64u: CREDENTIAL_ID,
    prfSupported: true,
    backupEligible: false,
    backupState: false,
    observedAtMs: 2_000,
  });
  expect(parsePasskeyCredentialObservationRecord(built)).toEqual(built);
});
