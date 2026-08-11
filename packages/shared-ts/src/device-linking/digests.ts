import { base64UrlDecode, base64UrlEncode } from '../utils/base64';
import { parseDigestB64u, type DigestB64u } from '../utils/canonicalPrimitives';
import { sha256Bytes } from '../utils/digests';
import type {
  LinkedDeviceApprovalV1,
  LinkedDeviceEnrollmentKeyBindingV1,
  LinkedDeviceOwnerAuthorizationSourceV1,
  LinkedDeviceProtocolVersionV1,
  LinkedDeviceSessionClaimV1,
  LinkedDeviceTargetCredentialRegistrationV1,
  LinkedDeviceTargetPreparationChildV1,
  LinkedDeviceTargetPreparationV1,
} from './contracts';
import type { AuthorizedOperationId } from '../authorization/capabilityKinds';
import type { LinkedDeviceEnrollmentId, LinkedDeviceId } from '../signing-lanes/ids';
import type { WebAuthnCredentialIdB64u } from '../utils/domainIds';

const CLAIM_DOMAIN = 'seams/linked-device/session-claim/v1';
const APPROVAL_DOMAIN = 'seams/linked-device/owner-approval/v1';
const TARGET_PREPARATION_DOMAIN = 'seams/linked-device/target-preparation/v1';
const LOCAL_PRESENCE_DOMAIN = 'seams/linked-device/local-presence/v1';
const TEXT_ENCODER = new TextEncoder();

function concat(parts: readonly Uint8Array[]): Uint8Array {
  let length = 0;
  for (const part of parts) length += part.length;
  const output = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
}

function u32(value: number, label: string): Uint8Array {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffffffff) {
    throw new Error(`${label} must be a non-negative u32`);
  }
  return Uint8Array.from([
    (value >>> 24) & 0xff,
    (value >>> 16) & 0xff,
    (value >>> 8) & 0xff,
    value & 0xff,
  ]);
}

function u64(value: number, label: string): Uint8Array {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(`${label} must be a non-negative safe integer`);
  }
  let remaining = BigInt(value);
  const output = new Uint8Array(8);
  for (let index = 7; index >= 0; index -= 1) {
    output[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return output;
}

function lp32(value: Uint8Array, label: string): Uint8Array {
  return concat([u32(value.length, `${label}.length`), value]);
}

function text(value: string, label: string): Uint8Array {
  if (typeof value !== 'string') throw new Error(`${label} must be a string`);
  return lp32(TEXT_ENCODER.encode(value), label);
}

function rawDigest(value: DigestB64u, label: string): Uint8Array {
  try {
    const decoded = base64UrlDecode(parseDigestB64u(value));
    if (decoded.length !== 32) throw new Error('must decode to 32 bytes');
    return decoded;
  } catch (error) {
    throw new Error(`${label} ${error instanceof Error ? error.message : 'is invalid'}`);
  }
}

function rawPublicKey(value: string, label: string): Uint8Array {
  try {
    const decoded = base64UrlDecode(value);
    if (decoded.length === 0 || base64UrlEncode(decoded) !== value) {
      throw new Error('must be canonical base64url');
    }
    return decoded;
  } catch (error) {
    throw new Error(`${label} ${error instanceof Error ? error.message : 'is invalid'}`);
  }
}

function encodeOwnerAuthorization(value: LinkedDeviceOwnerAuthorizationSourceV1): Uint8Array {
  if (value.kind === 'wallet_session') {
    return concat([
      text(value.kind, 'ownerAuthorization.kind'),
      text(value.walletSessionId, 'ownerAuthorization.walletSessionId'),
      text(value.authorizationId, 'ownerAuthorization.authorizationId'),
    ]);
  }
  return concat([
    text(value.kind, 'ownerAuthorization.kind'),
    text(value.evidenceSetId, 'ownerAuthorization.evidenceSetId'),
  ]);
}

function encodeKeyBinding(value: LinkedDeviceEnrollmentKeyBindingV1): Uint8Array {
  return concat([
    text(value.walletKeyId, 'keyBinding.walletKeyId'),
    text(value.keyFamily, 'keyBinding.keyFamily'),
    text(value.sourceLaneId, 'keyBinding.sourceLaneId'),
    text(value.sourceLaneShareEpoch, 'keyBinding.sourceLaneShareEpoch'),
    u64(value.sourceRevocationEpoch, 'keyBinding.sourceRevocationEpoch'),
    text(value.sourceHolderParticipantId, 'keyBinding.sourceHolderParticipantId'),
    text(value.sourceSigningWorkerParticipantId, 'keyBinding.sourceSigningWorkerParticipantId'),
    text(value.targetLaneId, 'keyBinding.targetLaneId'),
    text(value.targetLaneShareEpoch, 'keyBinding.targetLaneShareEpoch'),
  ]);
}

function encodeProtocolVersion(value: LinkedDeviceProtocolVersionV1): Uint8Array {
  return concat([
    text(value.keyFamily, 'protocolVersion.keyFamily'),
    text(value.version, 'protocolVersion.version'),
  ]);
}

function encodeTargetPreparationChild(value: LinkedDeviceTargetPreparationChildV1): Uint8Array {
  return concat([
    text(value.kind, 'targetPreparationChild.kind'),
    text(value.operationId, 'targetPreparationChild.operationId'),
    text(value.walletKeyId, 'targetPreparationChild.walletKeyId'),
    text(value.keyFamily, 'targetPreparationChild.keyFamily'),
    text(value.targetLaneId, 'targetPreparationChild.targetLaneId'),
    text(value.targetLaneShareEpoch, 'targetPreparationChild.targetLaneShareEpoch'),
    text(value.targetMaterialActivationId, 'targetPreparationChild.targetMaterialActivationId'),
    text(value.targetHolderParticipantId, 'targetPreparationChild.targetHolderParticipantId'),
  ]);
}

export function encodeLinkedDeviceSessionClaimV1(value: LinkedDeviceSessionClaimV1): Uint8Array {
  return concat([
    text(CLAIM_DOMAIN, 'domain'),
    text(value.kind, 'kind'),
    text(value.linkSessionId, 'linkSessionId'),
    text(value.walletId, 'walletId'),
    text(value.enrollmentId, 'enrollmentId'),
    text(value.deviceId, 'deviceId'),
    lp32(rawPublicKey(value.devicePublicKeyB64u, 'devicePublicKeyB64u'), 'devicePublicKeyB64u'),
    u64(value.claimedAtMs, 'claimedAtMs'),
    u64(value.claimExpiresAtMs, 'claimExpiresAtMs'),
  ]);
}

export async function computeLinkedDeviceSessionClaimDigestV1(
  value: LinkedDeviceSessionClaimV1,
): Promise<DigestB64u> {
  return parseDigestB64u(
    base64UrlEncode(await sha256Bytes(encodeLinkedDeviceSessionClaimV1(value))),
  );
}

export function encodeLinkedDeviceApprovalV1(value: LinkedDeviceApprovalV1): Uint8Array {
  const orderedKeyBindings = value.orderedKeyBindings.map(encodeKeyBinding);
  const protocolVersions = value.protocolVersions.map(encodeProtocolVersion);
  return concat([
    text(APPROVAL_DOMAIN, 'domain'),
    text(value.kind, 'kind'),
    text(value.linkSessionId, 'linkSessionId'),
    text(value.walletId, 'walletId'),
    text(value.enrollmentId, 'enrollmentId'),
    text(value.deviceId, 'deviceId'),
    lp32(rawPublicKey(value.linkPublicKeyB64u, 'linkPublicKeyB64u'), 'linkPublicKeyB64u'),
    lp32(rawPublicKey(value.devicePublicKeyB64u, 'devicePublicKeyB64u'), 'devicePublicKeyB64u'),
    text(value.permission.kind, 'permission.kind'),
    text(value.permission.administrationScope, 'permission.administrationScope'),
    text(value.permission.localUserPresence, 'permission.localUserPresence'),
    lp32(encodeOwnerAuthorization(value.ownerAuthorization), 'ownerAuthorization'),
    rawDigest(value.policyDigestB64u, 'policyDigestB64u'),
    text(value.operationId, 'operationId'),
    text(value.idempotencyKey, 'idempotencyKey'),
    u32(orderedKeyBindings.length, 'orderedKeyBindings'),
    ...orderedKeyBindings.map((entry) => lp32(entry, 'orderedKeyBindings.item')),
    u32(protocolVersions.length, 'protocolVersions'),
    ...protocolVersions.map((entry) => lp32(entry, 'protocolVersions.item')),
    u64(value.approvedAtMs, 'approvedAtMs'),
    u64(value.expiresAtMs, 'expiresAtMs'),
  ]);
}

export async function computeLinkedDeviceApprovalDigestV1(
  value: LinkedDeviceApprovalV1,
): Promise<DigestB64u> {
  return parseDigestB64u(base64UrlEncode(await sha256Bytes(encodeLinkedDeviceApprovalV1(value))));
}

export function encodeLinkedDeviceTargetPreparationV1(
  value: LinkedDeviceTargetPreparationV1,
): Uint8Array {
  const children = value.orderedChildren.map(encodeTargetPreparationChild);
  return concat([
    text(TARGET_PREPARATION_DOMAIN, 'domain'),
    text(value.kind, 'kind'),
    text(value.linkSessionId, 'linkSessionId'),
    text(value.walletId, 'walletId'),
    text(value.enrollmentId, 'enrollmentId'),
    text(value.deviceId, 'deviceId'),
    text(value.rpId, 'rpId'),
    lp32(rawPublicKey(value.userHandleB64u, 'userHandleB64u'), 'userHandleB64u'),
    rawDigest(value.challengeB64u, 'challengeB64u'),
    u32(children.length, 'orderedChildren'),
    ...children.map((entry) => lp32(entry, 'orderedChildren.item')),
    u64(value.issuedAtMs, 'issuedAtMs'),
    u64(value.expiresAtMs, 'expiresAtMs'),
  ]);
}

export async function computeLinkedDeviceTargetPreparationDigestV1(
  value: LinkedDeviceTargetPreparationV1,
): Promise<DigestB64u> {
  return parseDigestB64u(
    base64UrlEncode(await sha256Bytes(encodeLinkedDeviceTargetPreparationV1(value))),
  );
}

export type LinkedDeviceLocalPresenceChallengeV1 = {
  readonly authorizedOperationId: AuthorizedOperationId;
  readonly deviceId: LinkedDeviceId;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly credentialIdB64u: WebAuthnCredentialIdB64u;
  readonly intentDigestB64u: DigestB64u;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
};

export function encodeLinkedDeviceLocalPresenceChallengeV1(
  value: LinkedDeviceLocalPresenceChallengeV1,
): Uint8Array {
  if (value.issuedAtMs >= value.expiresAtMs) {
    throw new Error('linked-device local presence must expire after issuance');
  }
  return concat([
    text(LOCAL_PRESENCE_DOMAIN, 'domain'),
    text(value.authorizedOperationId, 'authorizedOperationId'),
    text(value.deviceId, 'deviceId'),
    text(value.enrollmentId, 'enrollmentId'),
    lp32(rawPublicKey(value.credentialIdB64u, 'credentialIdB64u'), 'credentialIdB64u'),
    rawDigest(value.intentDigestB64u, 'intentDigestB64u'),
    u64(value.issuedAtMs, 'issuedAtMs'),
    u64(value.expiresAtMs, 'expiresAtMs'),
  ]);
}

export async function computeLinkedDeviceLocalPresenceChallengeDigestV1(
  value: LinkedDeviceLocalPresenceChallengeV1,
): Promise<DigestB64u> {
  return parseDigestB64u(
    base64UrlEncode(await sha256Bytes(encodeLinkedDeviceLocalPresenceChallengeV1(value))),
  );
}

export async function assertLinkedDeviceTargetCredentialRegistrationMatchesPreparationV1(input: {
  readonly preparation: LinkedDeviceTargetPreparationV1;
  readonly registration: LinkedDeviceTargetCredentialRegistrationV1;
}): Promise<void> {
  const { preparation, registration } = input;
  if (
    registration.linkSessionId !== preparation.linkSessionId ||
    registration.walletId !== preparation.walletId ||
    registration.enrollmentId !== preparation.enrollmentId ||
    registration.deviceId !== preparation.deviceId ||
    registration.targetPreparationDigestB64u !==
      (await computeLinkedDeviceTargetPreparationDigestV1(preparation)) ||
    registration.orderedHolderRegistrations.length !== preparation.orderedChildren.length
  ) {
    throw new Error('linked-device target registration differs from its preparation');
  }
  for (let index = 0; index < preparation.orderedChildren.length; index += 1) {
    const expected = preparation.orderedChildren[index];
    const actual = registration.orderedHolderRegistrations[index];
    if (
      !expected ||
      !actual ||
      actual.operationId !== expected.operationId ||
      actual.walletKeyId !== expected.walletKeyId ||
      actual.keyFamily !== expected.keyFamily ||
      actual.targetLaneId !== expected.targetLaneId ||
      actual.targetLaneShareEpoch !== expected.targetLaneShareEpoch ||
      actual.targetMaterialActivationId !== expected.targetMaterialActivationId ||
      actual.holderParticipant.participantId !== expected.targetHolderParticipantId
    ) {
      throw new Error(`linked-device holder registration ${index} differs from its R102 child`);
    }
  }
}
