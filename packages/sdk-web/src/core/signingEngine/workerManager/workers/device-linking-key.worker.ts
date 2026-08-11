import {
  parseLinkedDeviceTargetPreparationV1,
  parseLinkedDeviceProvisioningChildV1,
  encodeLinkedDeviceRequestProofV1,
  LINKED_DEVICE_REQUEST_PROOF_MAX_TTL_MS_V1,
  LINKED_DEVICE_REQUEST_PROOF_NONCE_BYTES_V1,
  LINKED_DEVICE_REQUEST_PROOF_SIGNATURE_BYTES_V1,
  parseLinkDevicePublicKeyB64u,
  type LinkedDeviceRequestProofV1,
  type LinkedDeviceProvisioningChildV1,
  type LinkedDeviceTargetHolderRegistrationV1,
  type LinkedDeviceTargetPreparationV1,
  type LinkedDeviceWebAuthnRegistrationV1,
  type LinkDevicePublicKeyB64u,
} from '@shared/device-linking';
import {
  buildEcdsaLaneHolderShareBinding,
  buildEd25519LaneHolderShareBinding,
  buildPasskeyEnvelopeFactor,
  parseEd25519PublicKeyB64u,
  parseSecp256k1CompressedPublicKeyB64u,
} from '@shared/passkey-custody';
import { buildLaneHolderParticipantRecordWithDigestV1 } from '@shared/signing-lanes/participantDigest';
import {
  parseHpkePublicKeyB64u,
  parseLaneCustodyBindingDigestB64u,
  parseLaneHolderCustodyBindingId,
  parseSigningWorkerRecipientKeyDigestB64u,
  type LaneHolderParticipantRecordV1,
} from '@shared/signing-lanes/participants';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/base64';
import { parseDigestB64u, type DigestB64u } from '@shared/utils/canonicalPrimitives';
import { parseWebAuthnCredentialIdB64u } from '@shared/utils/domainIds';
import { parseLinkDeviceSessionId, type LinkDeviceSessionId } from '@shared/signing-lanes/ids';
import initEd25519YaoClient, {
  WasmLaneCustodySealV1,
  WasmLaneHolderRecipientV1,
} from '../../../../../../../crates/router-ab-ed25519-yao-client/pkg/router_ab_ed25519_yao_client.js';
import { resolveWasmUrl } from '@/core/walletRuntimePaths/wasm-loader';

/**
 * The worker is the only owner of these key objects. The browser receives
 * public bytes and an opaque slot id; private CryptoKeys are non-extractable
 * and never appear in a structured-clone message.
 */
type DeviceLinkingTargetMaterialV1 =
  | { readonly state: 'unprepared' }
  | {
      readonly state: 'prepared';
      readonly preparation: LinkedDeviceTargetPreparationV1;
      readonly credentialIdB64u: LinkedDeviceWebAuthnRegistrationV1['credentialIdB64u'];
      readonly factorSecret: Uint8Array;
      readonly recipients: Map<string, DeviceLinkingPreparedRecipientV1>;
    };

type DeviceLinkingPreparedRecipientV1 =
  | {
      readonly state: 'open';
      readonly recipient: DeviceLinkingLaneRecipientV1;
      readonly holderParticipant: LaneHolderParticipantRecordV1;
    }
  | {
      readonly state: 'sealed';
      readonly deliveryJson: string;
      readonly holderParticipant: LaneHolderParticipantRecordV1;
      readonly output: ReturnType<typeof sealedHolderOutput>;
    };

type DeviceLinkingKeySlotV1 = {
  readonly identityPrivateKey: CryptoKey;
  readonly linkPrivateKey: CryptoKey;
  readonly devicePublicKeyB64u: LinkDevicePublicKeyB64u;
  readonly linkPublicKeyB64u: LinkDevicePublicKeyB64u;
  targetMaterial: DeviceLinkingTargetMaterialV1;
};

type DeviceLinkingKeyWorkerRequestV1 =
  | { readonly kind: 'device_linking_key_material_create_v1' }
  | {
      readonly kind: 'device_linking_target_holder_open_seal_v1';
      readonly handleId: string;
      readonly delivery: LinkedDeviceProvisioningChildV1;
    }
  | {
      readonly kind: 'device_linking_request_sign_v1';
      readonly handleId: string;
      readonly linkSessionId: LinkDeviceSessionId;
      readonly method: 'GET' | 'POST';
      readonly canonicalPath: string;
      readonly bodyDigestB64u: DigestB64u;
      readonly devicePublicKeyDigestB64u: DigestB64u;
      readonly challengeB64u: string;
      readonly issuedAtMs: number;
      readonly expiresAtMs: number;
    }
  | {
      readonly kind: 'device_linking_target_holders_prepare_v1';
      readonly handleId: string;
      readonly preparation: LinkedDeviceTargetPreparationV1;
      readonly credentialIdB64u: LinkedDeviceWebAuthnRegistrationV1['credentialIdB64u'];
      readonly factorSecret: ArrayBuffer;
    }
  | {
      readonly kind: 'device_linking_key_material_discard_v1';
      readonly handleId: string;
    };

type DeviceLinkingKeyWorkerResponseV1 =
  | {
      readonly handleId: string;
      readonly linkPublicKeyB64u: LinkDevicePublicKeyB64u;
      readonly devicePublicKeyB64u: LinkDevicePublicKeyB64u;
    }
  | {
      readonly sealedHolderMaterialB64u: string;
      readonly sealedHolderRecordDigestB64u: DigestB64u;
      readonly verifiedHolderCiphertextDigestSetB64u: DigestB64u;
    }
  | {
      readonly orderedHolderRegistrations: readonly [
        LinkedDeviceTargetHolderRegistrationV1,
        ...LinkedDeviceTargetHolderRegistrationV1[],
      ];
    }
  | { readonly signatureB64u: string };

type DeviceLinkingKeyWorkerFrameV1 = {
  readonly id: string;
  readonly request: unknown;
};

export type DeviceLinkingKeyWorkerScopeV1 = {
  postMessage(message: unknown): void;
  addEventListener(type: 'message', listener: (event: MessageEvent) => void): void;
  removeEventListener(type: 'message', listener: (event: MessageEvent) => void): void;
};

export type InstalledDeviceLinkingKeyWorkerV1 = {
  close(): Promise<void>;
};

export type DeviceLinkingLaneRecipientV1 = {
  hpke_public_key_b64u(): string;
  hpke_public_key_digest_b64u(): string;
  open_and_seal(
    custody: DeviceLinkingLaneCustodySealV1,
    jobJson: string,
    receiptJson: string,
    holderPackageJson: string,
    nonce12: Uint8Array,
  ): unknown;
  destroy(): void;
  free(): void;
};

export type DeviceLinkingLaneCustodySealV1 = {
  free(): void;
};

export type DeviceLinkingLaneRecipientFactoryV1 = {
  createRecipient(input: {
    readonly operationId: string;
    readonly keyMaterial: Uint8Array;
  }): DeviceLinkingLaneRecipientV1 | Promise<DeviceLinkingLaneRecipientV1>;
  createCustodySeal(input: {
    readonly factorSecret: Uint8Array;
    readonly envelopeBindingJson: string;
    readonly custodyBindingId: string;
    readonly custodyBindingDigestB64u: string;
  }): DeviceLinkingLaneCustodySealV1 | Promise<DeviceLinkingLaneCustodySealV1>;
};

const keySlots = new Map<string, DeviceLinkingKeySlotV1>();
const laneRecipientWasmUrl = resolveWasmUrl(
  'router_ab_ed25519_yao_client_bg.wasm',
  'Ed25519 Yao Client',
);
let laneRecipientInitPromise: Promise<void> | null = null;

async function initializeLaneRecipientWasm(): Promise<void> {
  if (!laneRecipientInitPromise) {
    laneRecipientInitPromise = initEd25519YaoClient({
      module_or_path: laneRecipientWasmUrl,
    }).then(
      () => undefined,
      (error: unknown) => {
        laneRecipientInitPromise = null;
        throw error;
      },
    );
  }
  return await laneRecipientInitPromise;
}

const productionLaneRecipientFactory: DeviceLinkingLaneRecipientFactoryV1 = {
  async createRecipient(input) {
    await initializeLaneRecipientWasm();
    return new WasmLaneHolderRecipientV1(input.operationId, input.keyMaterial);
  },
  async createCustodySeal(input) {
    await initializeLaneRecipientWasm();
    return new WasmLaneCustodySealV1(
      'passkey',
      input.factorSecret,
      input.envelopeBindingJson,
      input.custodyBindingId,
      input.custodyBindingDigestB64u,
    );
  },
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function requireRecord(value: unknown, label: string): Record<string, unknown> {
  if (!isRecord(value)) throw new Error(`${label} must be an object`);
  return value;
}

function exactRecord(
  value: unknown,
  fields: readonly string[],
  label: string,
): Record<string, unknown> {
  const record = requireRecord(value, label);
  const expected = new Set(fields);
  for (const key of Object.keys(record)) {
    if (!expected.has(key)) throw new Error(`${label}.${key} is not supported`);
  }
  for (const key of fields) {
    if (!(key in record)) throw new Error(`${label}.${key} is required`);
  }
  return record;
}

function requireNonEmptyString(value: unknown, label: string): string {
  if (typeof value !== 'string' || value.length === 0 || value.trim() !== value) {
    throw new Error(`${label} is required`);
  }
  return value;
}

function parseHandleId(value: unknown): string {
  const handleId = requireNonEmptyString(value, 'handleId');
  if (handleId.length > 256) throw new Error('handleId is too long');
  return handleId;
}

function createHandleId(): string {
  if (!globalThis.crypto || typeof globalThis.crypto.getRandomValues !== 'function') {
    throw new Error('secure randomness is unavailable for device-linking worker');
  }
  const bytes = globalThis.crypto.getRandomValues(new Uint8Array(24));
  const handleId = `device-linking-key-${base64UrlEncode(bytes)}`;
  bytes.fill(0);
  return handleId;
}

function parseFixedBase64Url(value: unknown, length: number, label: string): string {
  const encoded = requireNonEmptyString(value, label);
  if (!/^[A-Za-z0-9_-]+$/.test(encoded)) throw new Error(`${label} is invalid`);
  let bytes: Uint8Array;
  try {
    bytes = base64UrlDecode(encoded);
  } catch {
    throw new Error(`${label} is invalid`);
  }
  if (bytes.length !== length || base64UrlEncode(bytes) !== encoded) {
    bytes.fill(0);
    throw new Error(`${label} must be canonical base64url`);
  }
  bytes.fill(0);
  return encoded;
}

function parseCanonicalBase64Url(value: unknown, label: string): string {
  const encoded = requireNonEmptyString(value, label);
  if (!/^[A-Za-z0-9_-]+$/.test(encoded)) throw new Error(`${label} is invalid`);
  let bytes: Uint8Array;
  try {
    bytes = base64UrlDecode(encoded);
  } catch {
    throw new Error(`${label} is invalid`);
  }
  try {
    if (bytes.length === 0 || base64UrlEncode(bytes) !== encoded) {
      throw new Error(`${label} must be canonical base64url`);
    }
    return encoded;
  } finally {
    bytes.fill(0);
  }
}

function parseDigest(value: unknown, label: string): DigestB64u {
  try {
    return parseDigestB64u(value);
  } catch (error) {
    throw new Error(`${label} ${error instanceof Error ? error.message : 'is invalid'}`);
  }
}

function parseSessionId(value: unknown): LinkDeviceSessionId {
  const parsed = parseLinkDeviceSessionId(value);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

function parseCanonicalPath(value: unknown): string {
  const path = requireNonEmptyString(value, 'canonicalPath');
  if (!path.startsWith('/') || path.includes('?') || path.includes('#')) {
    throw new Error('canonicalPath is invalid');
  }
  return path;
}

function parseTimestamp(value: unknown, label: string): number {
  if (!Number.isSafeInteger(value) || Number(value) <= 0) {
    throw new Error(`${label} is invalid`);
  }
  return Number(value);
}

function parseSignRequest(value: unknown): {
  readonly handleId: string;
  readonly linkSessionId: LinkDeviceSessionId;
  readonly method: 'GET' | 'POST';
  readonly canonicalPath: string;
  readonly bodyDigestB64u: DigestB64u;
  readonly devicePublicKeyDigestB64u: DigestB64u;
  readonly challengeB64u: string;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
} {
  const record = exactRecord(
    value,
    [
      'kind',
      'handleId',
      'linkSessionId',
      'method',
      'canonicalPath',
      'bodyDigestB64u',
      'devicePublicKeyDigestB64u',
      'challengeB64u',
      'issuedAtMs',
      'expiresAtMs',
    ],
    'device-linking sign request',
  );
  if (record.kind !== 'device_linking_request_sign_v1') {
    throw new Error('device-linking sign request kind is invalid');
  }
  const issuedAtMs = parseTimestamp(record.issuedAtMs, 'issuedAtMs');
  const expiresAtMs = parseTimestamp(record.expiresAtMs, 'expiresAtMs');
  if (expiresAtMs <= issuedAtMs) throw new Error('expiresAtMs must be after issuedAtMs');
  if (expiresAtMs - issuedAtMs > LINKED_DEVICE_REQUEST_PROOF_MAX_TTL_MS_V1) {
    throw new Error('request proof lifetime exceeds the maximum');
  }
  if (record.method !== 'GET' && record.method !== 'POST') throw new Error('method is invalid');
  return {
    handleId: parseHandleId(record.handleId),
    linkSessionId: parseSessionId(record.linkSessionId),
    method: record.method,
    canonicalPath: parseCanonicalPath(record.canonicalPath),
    bodyDigestB64u: parseDigest(record.bodyDigestB64u, 'bodyDigestB64u'),
    devicePublicKeyDigestB64u: parseDigest(
      record.devicePublicKeyDigestB64u,
      'devicePublicKeyDigestB64u',
    ),
    challengeB64u: parseFixedBase64Url(
      record.challengeB64u,
      LINKED_DEVICE_REQUEST_PROOF_NONCE_BYTES_V1,
      'challengeB64u',
    ),
    issuedAtMs,
    expiresAtMs,
  };
}

function requireCryptoKeyPair(value: CryptoKey | CryptoKeyPair, label: string): CryptoKeyPair {
  if (
    typeof value !== 'object' ||
    value === null ||
    !('publicKey' in value) ||
    !('privateKey' in value)
  ) {
    throw new Error(`${label} did not produce a key pair`);
  }
  return value;
}

function parseFrame(value: unknown): DeviceLinkingKeyWorkerFrameV1 {
  const frame = exactRecord(value, ['id', 'request'], 'device-linking worker frame');
  return {
    id: requireNonEmptyString(frame.id, 'device-linking worker frame.id'),
    request: frame.request,
  };
}

function parseRequest(value: unknown): DeviceLinkingKeyWorkerRequestV1 {
  const record = requireRecord(value, 'device-linking worker request');
  if (record.kind === 'device_linking_key_material_create_v1') {
    exactRecord(record, ['kind'], 'device-linking create request');
    return { kind: 'device_linking_key_material_create_v1' };
  }
  if (record.kind === 'device_linking_key_material_discard_v1') {
    const parsed = exactRecord(record, ['kind', 'handleId'], 'device-linking discard request');
    return {
      kind: 'device_linking_key_material_discard_v1',
      handleId: parseHandleId(parsed.handleId),
    };
  }
  if (record.kind === 'device_linking_request_sign_v1') {
    const parsed = parseSignRequest(record);
    return { kind: 'device_linking_request_sign_v1', ...parsed };
  }
  if (record.kind === 'device_linking_target_holders_prepare_v1') {
    const transferredSecret =
      record.factorSecret instanceof ArrayBuffer ? new Uint8Array(record.factorSecret) : null;
    try {
      const parsed = exactRecord(
        record,
        ['kind', 'handleId', 'preparation', 'credentialIdB64u', 'factorSecret'],
        'device-linking target holder request',
      );
      if (!(parsed.factorSecret instanceof ArrayBuffer) || parsed.factorSecret.byteLength !== 32) {
        throw new Error('device-linking target holder factorSecret must be 32 bytes');
      }
      const credentialId = parseWebAuthnCredentialIdB64u(parsed.credentialIdB64u);
      if (!credentialId.ok) throw new Error(credentialId.error.message);
      return {
        kind: 'device_linking_target_holders_prepare_v1',
        handleId: parseHandleId(parsed.handleId),
        preparation: parseLinkedDeviceTargetPreparationV1(parsed.preparation),
        credentialIdB64u: credentialId.value,
        factorSecret: parsed.factorSecret,
      };
    } catch (error) {
      transferredSecret?.fill(0);
      throw error;
    }
  }
  if (record.kind === 'device_linking_target_holder_open_seal_v1') {
    const parsed = exactRecord(
      record,
      ['kind', 'handleId', 'delivery'],
      'device-linking target holder open request',
    );
    return {
      kind: 'device_linking_target_holder_open_seal_v1',
      handleId: parseHandleId(parsed.handleId),
      delivery: parseLinkedDeviceProvisioningChildV1(parsed.delivery),
    };
  }
  throw new Error('device-linking worker request kind is unsupported');
}

async function generateKeySlot(): Promise<{
  readonly slot: DeviceLinkingKeySlotV1;
  readonly result: Extract<DeviceLinkingKeyWorkerResponseV1, { readonly handleId: string }>;
}> {
  const identityPair = requireCryptoKeyPair(
    await globalThis.crypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']),
    'Ed25519 identity',
  );
  const linkPair = requireCryptoKeyPair(
    await globalThis.crypto.subtle.generateKey({ name: 'X25519' }, false, ['deriveBits']),
    'X25519 link',
  );
  const identityPublicBytes = new Uint8Array(
    await globalThis.crypto.subtle.exportKey('raw', identityPair.publicKey),
  );
  const linkPublicBytes = new Uint8Array(
    await globalThis.crypto.subtle.exportKey('raw', linkPair.publicKey),
  );
  try {
    if (identityPublicBytes.length !== 32 || linkPublicBytes.length !== 32) {
      throw new Error('device-linking worker returned an invalid public key length');
    }
    const devicePublicKeyB64u = parseLinkDevicePublicKeyB64u(base64UrlEncode(identityPublicBytes));
    const linkPublicKeyB64u = parseLinkDevicePublicKeyB64u(base64UrlEncode(linkPublicBytes));
    const handleId = createHandleId();
    const slot: DeviceLinkingKeySlotV1 = {
      identityPrivateKey: identityPair.privateKey,
      linkPrivateKey: linkPair.privateKey,
      devicePublicKeyB64u,
      linkPublicKeyB64u,
      targetMaterial: { state: 'unprepared' },
    };
    return {
      slot,
      result: { handleId, linkPublicKeyB64u, devicePublicKeyB64u },
    };
  } finally {
    identityPublicBytes.fill(0);
    linkPublicBytes.fill(0);
  }
}

function randomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  globalThis.crypto.getRandomValues(bytes);
  return bytes;
}

function requiredParsed<T>(
  result:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
): T {
  if (result.ok) return result.value;
  throw new Error(result.error.message);
}

async function prepareTargetHolders(
  request: Extract<
    DeviceLinkingKeyWorkerRequestV1,
    { readonly kind: 'device_linking_target_holders_prepare_v1' }
  >,
  recipientFactory: DeviceLinkingLaneRecipientFactoryV1,
): Promise<{
  readonly orderedHolderRegistrations: readonly [
    LinkedDeviceTargetHolderRegistrationV1,
    ...LinkedDeviceTargetHolderRegistrationV1[],
  ];
}> {
  const slot = keySlots.get(request.handleId);
  if (!slot) {
    new Uint8Array(request.factorSecret).fill(0);
    throw new Error('device-linking key handle is unknown or discarded');
  }
  if (slot.targetMaterial.state !== 'unprepared') {
    new Uint8Array(request.factorSecret).fill(0);
    throw new Error('device-linking target holders are already prepared');
  }
  const recipients = new Map<string, DeviceLinkingPreparedRecipientV1>();
  const registrations: LinkedDeviceTargetHolderRegistrationV1[] = [];
  try {
    for (const child of request.preparation.orderedChildren) {
      const recipientKeyMaterial = randomBytes(32);
      let recipient: DeviceLinkingLaneRecipientV1;
      try {
        recipient = await recipientFactory.createRecipient({
          operationId: child.operationId,
          keyMaterial: recipientKeyMaterial,
        });
      } finally {
        recipientKeyMaterial.fill(0);
      }
      const custodyIdBytes = randomBytes(24);
      const custodyDigestBytes = randomBytes(32);
      try {
        const custodyBindingId = requiredParsed(
          parseLaneHolderCustodyBindingId(
            `linked-device-lane-custody-${base64UrlEncode(custodyIdBytes)}`,
          ),
        );
        const custodyBindingDigestB64u = requiredParsed(
          parseLaneCustodyBindingDigestB64u(base64UrlEncode(custodyDigestBytes)),
        );
        const hpkePublicKeyB64u = requiredParsed(
          parseHpkePublicKeyB64u(recipient.hpke_public_key_b64u()),
        );
        const hpkePublicKeyDigestB64u = requiredParsed(
          parseSigningWorkerRecipientKeyDigestB64u(recipient.hpke_public_key_digest_b64u()),
        );
        const holderParticipant = await buildLaneHolderParticipantRecordWithDigestV1({
          participantId: child.targetHolderParticipantId,
          custody: {
            kind: 'lane_holder_custody_identity_v1',
            custodyBindingId,
            custodyBindingDigestB64u,
          },
          hpkePublicKeyB64u,
          hpkePublicKeyDigestB64u,
        });
        recipients.set(String(child.operationId), {
          state: 'open',
          recipient,
          holderParticipant,
        });
        registrations.push({
          kind: 'linked_device_target_holder_registration_v1',
          operationId: child.operationId,
          walletKeyId: child.walletKeyId,
          keyFamily: child.keyFamily,
          targetLaneId: child.targetLaneId,
          targetLaneShareEpoch: child.targetLaneShareEpoch,
          targetMaterialActivationId: child.targetMaterialActivationId,
          holderParticipant,
        });
      } catch (error) {
        recipient.destroy();
        recipient.free();
        throw error;
      } finally {
        custodyIdBytes.fill(0);
        custodyDigestBytes.fill(0);
      }
    }
    const first = registrations[0];
    if (!first) throw new Error('device-linking target preparation has no children');
    if (keySlots.get(request.handleId) !== slot) {
      new Uint8Array(request.factorSecret).fill(0);
      throw new Error('device-linking key handle was discarded during target preparation');
    }
    const retainedFactorSecret = new Uint8Array(new Uint8Array(request.factorSecret));
    new Uint8Array(request.factorSecret).fill(0);
    const orderedHolderRegistrations = [first, ...registrations.slice(1)] as const;
    slot.targetMaterial = {
      state: 'prepared',
      preparation: request.preparation,
      credentialIdB64u: request.credentialIdB64u,
      factorSecret: retainedFactorSecret,
      recipients,
    };
    return { orderedHolderRegistrations };
  } catch (error) {
    new Uint8Array(request.factorSecret).fill(0);
    for (const prepared of recipients.values()) {
      if (prepared.state === 'open') {
        prepared.recipient.destroy();
        prepared.recipient.free();
      }
    }
    throw error;
  }
}

function destroySlot(slot: DeviceLinkingKeySlotV1): void {
  if (slot.targetMaterial.state !== 'prepared') return;
  slot.targetMaterial.factorSecret.fill(0);
  for (const prepared of slot.targetMaterial.recipients.values()) {
    if (prepared.state === 'open') {
      prepared.recipient.destroy();
      prepared.recipient.free();
    }
  }
  slot.targetMaterial = { state: 'unprepared' };
}

function assertDeliveryMatchesPreparedTarget(
  target: Extract<DeviceLinkingTargetMaterialV1, { readonly state: 'prepared' }>,
  delivery: LinkedDeviceProvisioningChildV1,
  prepared: DeviceLinkingPreparedRecipientV1,
): void {
  const job = delivery.job;
  const child = target.preparation.orderedChildren.find(
    (candidate) => candidate.operationId === job.operationId,
  );
  if (
    !child ||
    String(job.enrollmentId) !== String(target.preparation.enrollmentId) ||
    job.walletId !== target.preparation.walletId ||
    job.walletKeyId !== child.walletKeyId ||
    job.keyFamily !== child.keyFamily ||
    job.target.laneId !== child.targetLaneId ||
    job.target.laneShareEpoch !== child.targetLaneShareEpoch ||
    job.targetMaterialActivationId !== child.targetMaterialActivationId ||
    job.targetHolder.participantId !== child.targetHolderParticipantId ||
    job.targetHolder.participantId !== prepared.holderParticipant.participantId ||
    job.targetHolder.custodyBindingId !== prepared.holderParticipant.custodyBindingId ||
    job.targetHolder.custodyBindingDigestB64u !==
      prepared.holderParticipant.custodyBindingDigestB64u ||
    job.targetHolder.hpkePublicKeyB64u !== prepared.holderParticipant.hpkePublicKeyB64u ||
    job.targetHolder.hpkePublicKeyDigestB64u !==
      prepared.holderParticipant.hpkePublicKeyDigestB64u ||
    job.targetHolder.participantBindingDigestB64u !==
      prepared.holderParticipant.participantBindingDigestB64u ||
    job.target.operation !== 'create_lane' ||
    job.target.laneKind !== 'linked_device' ||
    job.authorization.kind !== 'linked_device_enrollment' ||
    job.authorization.linkedDeviceEnrollmentId !== target.preparation.enrollmentId
  ) {
    throw new Error('device-linking holder delivery changed its prepared R102 child');
  }
}

function envelopeBindingJson(
  target: Extract<DeviceLinkingTargetMaterialV1, { readonly state: 'prepared' }>,
  delivery: LinkedDeviceProvisioningChildV1,
  holderParticipant: LaneHolderParticipantRecordV1,
): string {
  const job = delivery.job;
  const factor = buildPasskeyEnvelopeFactor({
    rpId: target.preparation.rpId,
    credentialIdB64u: target.credentialIdB64u,
  });
  switch (job.kind) {
    case 'ed25519_yao_lane_job_v1':
      return JSON.stringify({
        walletId: job.walletId,
        envelopeId: holderParticipant.custodyBindingId,
        factor,
        envelopeRevision: 1,
        binding: buildEd25519LaneHolderShareBinding({
          walletKeyId: job.walletKeyId,
          laneId: job.target.laneId,
          laneShareEpoch: job.target.laneShareEpoch,
          nearEd25519SigningKeyId: job.nearEd25519SigningKeyId,
          registeredPublicKeyB64u: parseEd25519PublicKeyB64u(job.registeredPublicKeyB64u),
          participantBindingDigestB64u: holderParticipant.participantBindingDigestB64u,
        }),
      });
    case 'ecdsa_additive_lane_job_v1': {
      const thresholdSession = job.targetCapability.orderedThresholdSessions[0];
      return JSON.stringify({
        walletId: job.walletId,
        envelopeId: holderParticipant.custodyBindingId,
        factor,
        envelopeRevision: 1,
        binding: buildEcdsaLaneHolderShareBinding({
          walletKeyId: job.walletKeyId,
          laneId: job.target.laneId,
          laneShareEpoch: job.target.laneShareEpoch,
          evmFamilySigningKeySlotId: job.evmFamilySigningKeySlotId,
          thresholdSessionId: thresholdSession.thresholdSessionId,
          thresholdPublicKey33B64u: parseSecp256k1CompressedPublicKeyB64u(
            job.thresholdPublicKey33B64u,
          ),
        }),
      });
    }
    default:
      job satisfies never;
      throw new Error('device-linking holder delivery curve is unsupported');
  }
}

function sealedHolderOutput(value: unknown): {
  readonly sealedHolderMaterialB64u: string;
  readonly sealedHolderRecordDigestB64u: DigestB64u;
  readonly verifiedHolderCiphertextDigestSetB64u: DigestB64u;
} {
  const record = exactRecord(
    value,
    [
      'sealedHolderMaterialB64u',
      'sealedHolderRecordDigestB64u',
      'verifiedHolderCiphertextDigestSetB64u',
    ],
    'device-linking sealed holder output',
  );
  return {
    sealedHolderMaterialB64u: parseCanonicalBase64Url(
      record.sealedHolderMaterialB64u,
      'sealedHolderMaterialB64u',
    ),
    sealedHolderRecordDigestB64u: parseDigest(
      record.sealedHolderRecordDigestB64u,
      'sealedHolderRecordDigestB64u',
    ),
    verifiedHolderCiphertextDigestSetB64u: parseDigest(
      record.verifiedHolderCiphertextDigestSetB64u,
      'verifiedHolderCiphertextDigestSetB64u',
    ),
  };
}

async function openAndSealTargetHolder(
  request: Extract<
    DeviceLinkingKeyWorkerRequestV1,
    { readonly kind: 'device_linking_target_holder_open_seal_v1' }
  >,
  recipientFactory: DeviceLinkingLaneRecipientFactoryV1,
): Promise<ReturnType<typeof sealedHolderOutput>> {
  const slot = keySlots.get(request.handleId);
  if (!slot || slot.targetMaterial.state !== 'prepared') {
    throw new Error('device-linking target holder material is unavailable');
  }
  const key = String(request.delivery.job.operationId);
  const prepared = slot.targetMaterial.recipients.get(key);
  if (!prepared) throw new Error('device-linking target holder recipient is unknown or consumed');
  assertDeliveryMatchesPreparedTarget(slot.targetMaterial, request.delivery, prepared);
  const deliveryJson = JSON.stringify(request.delivery);
  if (prepared.state === 'sealed') {
    if (prepared.deliveryJson !== deliveryJson) {
      throw new Error('device-linking sealed holder replay changed its exact delivery');
    }
    return prepared.output;
  }
  let custody: DeviceLinkingLaneCustodySealV1 | undefined;
  let nonce: Uint8Array | undefined;
  try {
    custody = await recipientFactory.createCustodySeal({
      factorSecret: slot.targetMaterial.factorSecret,
      envelopeBindingJson: envelopeBindingJson(
        slot.targetMaterial,
        request.delivery,
        prepared.holderParticipant,
      ),
      custodyBindingId: prepared.holderParticipant.custodyBindingId,
      custodyBindingDigestB64u: prepared.holderParticipant.custodyBindingDigestB64u,
    });
    nonce = randomBytes(12);
    const output = sealedHolderOutput(
      prepared.recipient.open_and_seal(
        custody,
        JSON.stringify(request.delivery.job),
        JSON.stringify(request.delivery.protocolCommitReceipt),
        JSON.stringify(request.delivery.holderPackage),
        nonce,
      ),
    );
    if (
      output.verifiedHolderCiphertextDigestSetB64u !==
      request.delivery.protocolCommitReceipt.targetHolderCiphertextDigestSetB64u
    ) {
      throw new Error('device-linking holder package changed its committed ciphertext digest');
    }
    slot.targetMaterial.recipients.set(key, {
      state: 'sealed',
      deliveryJson,
      holderParticipant: prepared.holderParticipant,
      output,
    });
    return output;
  } finally {
    if (slot.targetMaterial.recipients.get(key) === prepared && prepared.state === 'open') {
      slot.targetMaterial.recipients.delete(key);
    }
    nonce?.fill(0);
    custody?.free();
    prepared.recipient.destroy();
    prepared.recipient.free();
  }
}

async function signRequest(
  request: Extract<
    DeviceLinkingKeyWorkerRequestV1,
    { readonly kind: 'device_linking_request_sign_v1' }
  >,
): Promise<{ readonly signatureB64u: string }> {
  const slot = keySlots.get(request.handleId);
  if (!slot) throw new Error('device-linking key handle is unknown or discarded');
  const zeroSignature = new Uint8Array(LINKED_DEVICE_REQUEST_PROOF_SIGNATURE_BYTES_V1);
  const proof: LinkedDeviceRequestProofV1 = {
    kind: 'linked_device_request_proof_v1',
    linkSessionId: request.linkSessionId,
    devicePublicKeyDigestB64u: request.devicePublicKeyDigestB64u,
    requestNonceB64u: request.challengeB64u,
    method: request.method,
    canonicalPath: request.canonicalPath,
    bodyDigestB64u: request.bodyDigestB64u,
    issuedAtMs: request.issuedAtMs,
    expiresAtMs: request.expiresAtMs,
    signatureB64u: base64UrlEncode(zeroSignature),
  };
  let canonicalBytes: Uint8Array | undefined;
  let signatureBytes: Uint8Array | undefined;
  try {
    canonicalBytes = encodeLinkedDeviceRequestProofV1(proof);
    signatureBytes = new Uint8Array(
      await globalThis.crypto.subtle.sign('Ed25519', slot.identityPrivateKey, canonicalBytes),
    );
    if (signatureBytes.length !== LINKED_DEVICE_REQUEST_PROOF_SIGNATURE_BYTES_V1) {
      throw new Error('device-linking worker returned an invalid signature length');
    }
    return { signatureB64u: base64UrlEncode(signatureBytes) };
  } finally {
    zeroSignature.fill(0);
    canonicalBytes?.fill(0);
    signatureBytes?.fill(0);
  }
}

async function handleRequest(
  rawRequest: unknown,
  recipientFactory: DeviceLinkingLaneRecipientFactoryV1,
): Promise<DeviceLinkingKeyWorkerResponseV1 | undefined> {
  const request = parseRequest(rawRequest);
  switch (request.kind) {
    case 'device_linking_key_material_create_v1': {
      const generated = await generateKeySlot();
      keySlots.set(generated.result.handleId, generated.slot);
      return generated.result;
    }
    case 'device_linking_request_sign_v1':
      return await signRequest(request);
    case 'device_linking_target_holders_prepare_v1':
      return await prepareTargetHolders(request, recipientFactory);
    case 'device_linking_target_holder_open_seal_v1':
      return await openAndSealTargetHolder(request, recipientFactory);
    case 'device_linking_key_material_discard_v1':
      {
        const slot = keySlots.get(request.handleId);
        if (slot) destroySlot(slot);
        keySlots.delete(request.handleId);
      }
      return undefined;
    default:
      request satisfies never;
      throw new Error('device-linking worker request kind is unsupported');
  }
}

function workerError(error: unknown): string {
  if (error instanceof Error && error.message.trim()) return error.message;
  if (typeof error === 'string' && error.trim()) return error;
  return 'device-linking worker request failed';
}

export function installDeviceLinkingKeyWorkerV1(
  scope: DeviceLinkingKeyWorkerScopeV1,
  recipientFactory: DeviceLinkingLaneRecipientFactoryV1 = productionLaneRecipientFactory,
): InstalledDeviceLinkingKeyWorkerV1 {
  let closed = false;
  let queue: Promise<void> = Promise.resolve();
  const onMessage = (event: MessageEvent): void => {
    queue = queue
      .catch(() => undefined)
      .then(async () => {
        if (closed) return;
        let id: string | undefined;
        try {
          const frame = parseFrame(event.data);
          id = frame.id;
          const result = await handleRequest(frame.request, recipientFactory);
          if (closed) return;
          scope.postMessage({ id, ok: true, result });
        } catch (error) {
          if (!closed && id) scope.postMessage({ id, ok: false, error: workerError(error) });
        }
      });
  };
  scope.addEventListener('message', onMessage);
  return {
    async close(): Promise<void> {
      if (closed) return await queue;
      closed = true;
      scope.removeEventListener('message', onMessage);
      queue = queue
        .catch(() => undefined)
        .then(() => {
          for (const slot of keySlots.values()) destroySlot(slot);
          keySlots.clear();
        });
      await queue;
    },
  };
}

if (typeof self !== 'undefined') {
  installDeviceLinkingKeyWorkerV1(self);
}
