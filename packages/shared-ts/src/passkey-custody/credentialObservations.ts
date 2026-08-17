import type { PasskeyEnvelopeId, WebAuthnCredentialIdB64u, WebAuthnRpId } from '../utils/domainIds';
import type { EnvelopeRevision } from './primitives';
import { parseUnixMs, rejectUnknownFields, requireRecord } from './primitives';

/**
 * Advisory credential metadata observed at registration.
 *
 * WebAuthn's backup-eligibility (BE) and backup-state (BS) flags describe how a
 * provider may sync a credential. They do NOT prove that the provider will
 * return the same PRF result on another device, so nothing in this module may
 * be used to conclude that cross-device custody works. That conclusion has one
 * source: an actual PRF result has sealed a server-held envelope.
 */
export type PasskeyCredentialObservationRecord = {
  kind: 'passkey_credential_observation_v1';
  rpId: WebAuthnRpId;
  credentialIdB64u: WebAuthnCredentialIdB64u;
  /** Whether the credential returned a usable PRF result when it was created. */
  prfSupported: boolean;
  /** WebAuthn BE flag: the provider may back this credential up. Advisory. */
  backupEligible: boolean;
  /** WebAuthn BS flag: the provider reports it is backed up now. Advisory. */
  backupState: boolean;
  observedAtMs: number;
};

/**
 * Whether this wallet's custody can be opened on another device.
 *
 * `ready` is reachable only by presenting the active server-held envelope that
 * a real PRF result sealed. Backup flags are not an input to this type, by
 * construction: there is no branch they could satisfy.
 */
export type CrossDeviceCustodyReadiness =
  | {
      state: 'ready';
      sealedEnvelopeId: PasskeyEnvelopeId;
      envelopeRevision: EnvelopeRevision;
    }
  | {
      state: 'not_ready';
      reason: 'prf_unsupported' | 'no_sealed_envelope';
    };

export function buildPasskeyCredentialObservationRecord(args: {
  rpId: WebAuthnRpId;
  credentialIdB64u: WebAuthnCredentialIdB64u;
  prfSupported: boolean;
  backupEligible: boolean;
  backupState: boolean;
  observedAtMs: number;
}): PasskeyCredentialObservationRecord {
  return {
    kind: 'passkey_credential_observation_v1',
    rpId: args.rpId,
    credentialIdB64u: args.credentialIdB64u,
    prfSupported: args.prfSupported,
    backupEligible: args.backupEligible,
    backupState: args.backupState,
    observedAtMs: args.observedAtMs,
  };
}

const OBSERVATION_FIELDS = [
  'kind',
  'rpId',
  'credentialIdB64u',
  'prfSupported',
  'backupEligible',
  'backupState',
  'observedAtMs',
] as const;

function requireBoolean(value: unknown, label: string): boolean {
  if (typeof value !== 'boolean') throw new Error(`${label} must be a boolean`);
  return value;
}

export function parsePasskeyCredentialObservationRecord(
  raw: unknown,
  label = 'passkeyCredentialObservation',
): PasskeyCredentialObservationRecord {
  const record = requireRecord(raw, label);
  if (record.kind !== 'passkey_credential_observation_v1') {
    throw new Error(`${label}.kind must be passkey_credential_observation_v1`);
  }
  rejectUnknownFields(record, OBSERVATION_FIELDS, label);
  if (typeof record.rpId !== 'string' || !record.rpId) {
    throw new Error(`${label}.rpId is required`);
  }
  if (typeof record.credentialIdB64u !== 'string' || !record.credentialIdB64u) {
    throw new Error(`${label}.credentialIdB64u is required`);
  }
  return buildPasskeyCredentialObservationRecord({
    rpId: record.rpId as WebAuthnRpId,
    credentialIdB64u: record.credentialIdB64u as WebAuthnCredentialIdB64u,
    prfSupported: requireBoolean(record.prfSupported, `${label}.prfSupported`),
    backupEligible: requireBoolean(record.backupEligible, `${label}.backupEligible`),
    backupState: requireBoolean(record.backupState, `${label}.backupState`),
    observedAtMs: parseUnixMs(record.observedAtMs, `${label}.observedAtMs`),
  });
}

// WebAuthn authenticator-data flag bits. Only the backup flags are read here;
// user presence and verification are the assertion verifier's concern.
const AUTHENTICATOR_DATA_FLAGS_OFFSET = 32;
const BACKUP_ELIGIBLE_FLAG = 0x08;
const BACKUP_STATE_FLAG = 0x10;

export type WebAuthnBackupFlags = {
  backupEligible: boolean;
  backupState: boolean;
};

/**
 * Reads the BE and BS flags from raw authenticator data.
 *
 * A credential reporting backed-up state is still not evidence of cross-device
 * PRF continuity — see `resolveCrossDeviceCustodyReadiness`.
 */
export function parseWebAuthnBackupFlags(authenticatorData: Uint8Array): WebAuthnBackupFlags {
  if (authenticatorData.length <= AUTHENTICATOR_DATA_FLAGS_OFFSET) {
    throw new Error('authenticatorData is too short to contain its flags byte');
  }
  const flags = authenticatorData[AUTHENTICATOR_DATA_FLAGS_OFFSET];
  const backupEligible = (flags & BACKUP_ELIGIBLE_FLAG) !== 0;
  const backupState = (flags & BACKUP_STATE_FLAG) !== 0;
  // BS without BE is malformed per the WebAuthn spec: a credential cannot be
  // backed up unless it is eligible to be.
  if (backupState && !backupEligible) {
    throw new Error('authenticatorData reports backup state without backup eligibility');
  }
  return { backupEligible, backupState };
}

/**
 * Resolves cross-device custody readiness.
 *
 * Note the inputs: PRF support, and the active sealed envelope — never the
 * backup flags. Registration may observe a backup-eligible, backed-up
 * credential and this still returns `not_ready` until a PRF result has actually
 * sealed a server-held envelope.
 */
export function resolveCrossDeviceCustodyReadiness(args: {
  prfSupported: boolean;
  activeSealedEnvelope: {
    envelopeId: PasskeyEnvelopeId;
    envelopeRevision: EnvelopeRevision;
  } | null;
}): CrossDeviceCustodyReadiness {
  if (!args.prfSupported) return { state: 'not_ready', reason: 'prf_unsupported' };
  if (args.activeSealedEnvelope === null) {
    return { state: 'not_ready', reason: 'no_sealed_envelope' };
  }
  return {
    state: 'ready',
    sealedEnvelopeId: args.activeSealedEnvelope.envelopeId,
    envelopeRevision: args.activeSealedEnvelope.envelopeRevision,
  };
}
