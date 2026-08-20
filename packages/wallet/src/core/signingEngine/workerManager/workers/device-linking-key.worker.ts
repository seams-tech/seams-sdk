import {
  encodeLinkedDeviceRequestProofV1,
  computeLinkedDeviceTargetPreparationDigestV1,
  LINKED_DEVICE_REQUEST_PROOF_MAX_TTL_MS_V1,
  LINKED_DEVICE_REQUEST_PROOF_NONCE_BYTES_V1,
  LINKED_DEVICE_REQUEST_PROOF_SIGNATURE_BYTES_V1,
  parseLinkDevicePublicKeyB64u,
  parseLinkedDeviceProvisioningChildV1,
  parseLinkedDeviceTargetPreparationV1,
  parseLinkedDeviceEmailOtpVerificationResultV1,
  parseLinkedDeviceEmailOtpFactorReleaseEnvelopeV1,
  type LinkedDeviceProvisioningChildV1,
  type LinkedDeviceRequestProofV1,
  type LinkedDeviceTargetHolderRegistrationV1,
  type LinkedDeviceTargetPreparationChildV1,
  type LinkedDeviceTargetPreparationV1,
  type LinkedDeviceEmailOtpVerificationResultV1,
  type LinkedDeviceEmailOtpFactorReleaseEnvelopeV1,
  type LinkDevicePublicKeyB64u,
} from '@shared/device-linking';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/base64';
import { parseDigestB64u, type DigestB64u } from '@shared/utils/canonicalPrimitives';
import {
  mpcMaterialActivationRefsEqual,
  parseMpcMaterialActivationRef,
  parseWalletId,
  parseWebAuthnCredentialIdB64u,
  type MpcMaterialActivationRef,
  type WalletId,
} from '@shared/utils/domainIds';
import {
  parseLinkedDeviceEnrollmentId,
  parseLinkedDeviceId,
  parseLinkDeviceSessionId,
  type LinkedDeviceEnrollmentId,
  type LinkedDeviceId,
  type LinkDeviceSessionId,
} from '@shared/signing-lanes/ids';
import type {
  LaneProtocolCommitReceiptV1,
  RotatableSigningLaneJobV1,
} from '@shared/signing-lanes/rotation';
import {
  buildEd25519LaneHolderShareBinding,
  buildEcdsaLaneHolderShareBinding,
  buildPasskeyEnvelopeFactor,
  buildEmailOtpEnvelopeFactor,
  parseEd25519PublicKeyB64u,
  parseSecp256k1CompressedPublicKeyB64u,
  type PasskeyCustodySecretBinding,
  type WalletCustodyEnvelopeFactor,
  parsePasskeyCustodyEnvelopeRecord,
  type PasskeyCustodyEnvelopeRecord,
} from '@shared/passkey-custody';
import initNearSigner, {
  ed25519_yao_client_root_transfer_recipient_v1,
  passkey_custody_open_ed25519_yao_client_root_from_linked_device_v1,
  passkey_custody_seal_ed25519_yao_client_root_under_factor_v1,
  type WasmEd25519YaoClientRootTransferRecipientV1,
} from '../../../../../../../wasm/near_signer/pkg/wasm_signer_worker.js';
import {
  buildLaneHolderCustodyIdentityV1,
  buildLaneHolderParticipantRecordV1,
  parseHpkePublicKeyB64u,
  parseLaneCustodyBindingDigestB64u,
  parseLaneHolderCustodyBindingId,
  parseSigningWorkerRecipientKeyDigestB64u,
  type LaneHolderParticipantRecordV1,
} from '@shared/signing-lanes/participants';
import { computeLaneHolderParticipantBindingDigestV1 } from '@shared/signing-lanes/participantDigest';
import {
  parseLaneProtocolCommitReceiptV1,
  parseRotatableSigningLaneJobV1,
} from '@shared/signing-lanes/rotationParsers';
import {
  parseLaneSealedHolderRecordV1,
  type LaneSealedHolderRecordV1,
} from '@/core/indexedDB/seamsWalletDB/laneHolderMaterialStore';
import {
  isAttachLinkedHolderToPresignPort,
  type OpaqueEcdsaPresignAuthorityRequestV1,
  type OpaqueEcdsaPresignAuthorityResponseV1,
} from '../ecdsaClientWorkerChannels';
import { parseEcdsaClientPresignPoolIdentity } from '../ecdsaPresignPoolIdentity';
import initEd25519YaoClient, {
  WasmLaneCustodySealV1,
  WasmLaneHolderRecipientV1,
  WasmLaneHolderSigningMaterialV1,
} from '../../../../../../../crates/router-ab-ed25519-yao-client/pkg/router_ab_ed25519_yao_client.js';
import { resolveWasmUrl } from '@/core/walletRuntimePaths/wasm-loader';
import {
  OpaqueEcdsaPresignAuthorityV1,
  type OpaqueEcdsaPresignSessionV1,
} from './opaqueEcdsaPresignAuthority';

/**
 * The worker is the only owner of these key objects. The browser receives
 * public bytes and an opaque slot id; private CryptoKeys are non-extractable
 * and never appear in a structured-clone message.
 */
type EmailOtpActivationPreparedChildV1 = {
  readonly child: LinkedDeviceTargetPreparationChildV1;
  readonly participant: LaneHolderParticipantRecordV1;
};

type DeviceLinkingEmailOtpActivationStateV1 = {
  readonly walletId: WalletId;
  readonly linkSessionId: LinkDeviceSessionId;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly deviceId: LinkedDeviceId;
  readonly targetPreparationDigestB64u: DigestB64u;
  readonly orderedChildren: readonly [
    EmailOtpActivationPreparedChildV1,
    ...EmailOtpActivationPreparedChildV1[],
  ];
  readonly factorSecret: Uint8Array;
};

type DeviceLinkingKeySlotV1 = {
  readonly identityPrivateKey: CryptoKey;
  readonly linkPrivateKey: CryptoKey;
  readonly devicePublicKeyB64u: LinkDevicePublicKeyB64u;
  readonly linkPublicKeyB64u: LinkDevicePublicKeyB64u;
  readonly emailOtpReleasePrivateKey: CryptoKey;
  readonly emailOtpReleasePublicKey65B64u: string;
  emailOtpExportRootRecipient: WasmEd25519YaoClientRootTransferRecipientV1 | null;
  emailOtpActivation: DeviceLinkingEmailOtpActivationStateV1 | null;
};

type DeviceLinkingEmailOtpExportRootPreparationV1 =
  | {
      readonly kind: 'required';
      readonly transferBindingJson: string;
      readonly ephemeralPublicKeyB64u: string;
      readonly nonceB64u: string;
      readonly sealedExportRootB64u: string;
      readonly bindingDigestB64u: string;
      readonly ciphertextDigestB64u: string;
      readonly replacementEnvelopeBindingJson: string;
    }
  | {
      readonly kind: 'not_required';
    };

type DeviceLinkingKeyWorkerRequestV1 =
  | { readonly kind: 'device_linking_key_material_create_v1' }
  | {
      readonly kind: 'device_linking_email_otp_export_root_recipient_create_v1';
      readonly handleId: string;
    }
  | {
      readonly kind: 'device_linking_target_holders_prepare_v1';
      readonly handleId: string;
      readonly preparation: LinkedDeviceTargetPreparationV1;
      readonly credentialIdB64u: string;
      readonly factorSecret: ArrayBuffer;
    }
  | {
      readonly kind: 'device_linking_email_otp_target_prepare_v1';
      readonly handleId: string;
      readonly preparation: LinkedDeviceTargetPreparationV1;
      readonly verification: LinkedDeviceEmailOtpVerificationResultV1;
      readonly exportRoot: DeviceLinkingEmailOtpExportRootPreparationV1;
    }
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
      readonly kind: 'device_linking_holder_signing_material_open_v1';
      readonly factorSecret: ArrayBuffer;
      readonly job: RotatableSigningLaneJobV1;
      readonly protocolCommitReceipt: LaneProtocolCommitReceiptV1;
      readonly materialActivation: MpcMaterialActivationRef;
      readonly holderRecord: LaneSealedHolderRecordV1;
    }
  | {
      readonly kind: 'device_linking_email_otp_holder_signing_material_batch_open_v1';
      readonly handleId: string;
      readonly walletId: WalletId;
      readonly linkSessionId: LinkDeviceSessionId;
      readonly enrollmentId: LinkedDeviceEnrollmentId;
      readonly deviceId: LinkedDeviceId;
      readonly targetPreparationDigestB64u: DigestB64u;
      readonly orderedChildren: readonly [
        DeviceLinkingEmailOtpHolderSigningMaterialChildV1,
        ...DeviceLinkingEmailOtpHolderSigningMaterialChildV1[],
      ];
    }
  | {
      readonly kind: 'device_linking_email_otp_factor_release_holder_signing_material_batch_open_v1';
      readonly handleId: string;
      readonly walletId: WalletId;
      readonly enrollmentId: LinkedDeviceEnrollmentId;
      readonly expectedChallengeId: string;
      readonly factorRelease: LinkedDeviceEmailOtpFactorReleaseEnvelopeV1;
      readonly orderedChildren: readonly [
        DeviceLinkingEmailOtpHolderSigningMaterialChildV1,
        ...DeviceLinkingEmailOtpHolderSigningMaterialChildV1[],
      ];
    }
  | {
      readonly kind: 'device_linking_holder_signing_material_discard_v1';
      readonly handleId: string;
    }
  | {
      readonly kind: 'device_linking_holder_ed25519_sign_v1';
      readonly handleId: string;
      readonly admittedDigestB64u: DigestB64u;
      readonly signingWorkerCommitments: {
        readonly hiding: string;
        readonly binding: string;
      };
      readonly signingWorkerVerifyingShareB64u: string;
    }
  | {
      readonly kind: 'device_linking_key_material_discard_v1';
      readonly handleId: string;
    };

type DeviceLinkingHolderSigningMaterialHandleResultV1 = {
  readonly handleId: string;
  readonly keyFamily: 'ed25519' | 'ecdsa_secp256k1';
};

type DeviceLinkingHolderSigningMaterialBatchResultV1 = {
  readonly holderSigningMaterialHandles: readonly [
    DeviceLinkingHolderSigningMaterialHandleResultV1,
    ...DeviceLinkingHolderSigningMaterialHandleResultV1[],
  ];
};

type DeviceLinkingKeyWorkerResponseV1 =
  | {
      readonly handleId: string;
      readonly linkPublicKeyB64u: LinkDevicePublicKeyB64u;
      readonly devicePublicKeyB64u: LinkDevicePublicKeyB64u;
      readonly emailOtpReleasePublicKey65B64u: string;
    }
  | { readonly recipientPublicKeyB64u: string }
  | {
      readonly handleId: string;
      readonly keyFamily: 'ed25519' | 'ecdsa_secp256k1';
    }
  | {
      readonly clientCommitments: {
        readonly hiding: string;
        readonly binding: string;
      };
      readonly clientVerifyingShareB64u: string;
      readonly clientSignatureShareB64u: string;
    }
  | {
      readonly orderedHolderRegistrations: readonly [
        LinkedDeviceTargetHolderRegistrationV1,
        ...LinkedDeviceTargetHolderRegistrationV1[],
      ];
    }
  | {
      readonly emailOtpPrepared: true;
      readonly orderedHolderRegistrations: readonly [
        LinkedDeviceTargetHolderRegistrationV1,
        ...LinkedDeviceTargetHolderRegistrationV1[],
      ];
      readonly exportRootRequirement:
        | {
            readonly kind: 'required';
            readonly resealedExportRootEnvelope: {
              readonly nonceB64u: string;
              readonly sealedExportRootB64u: string;
              readonly aadHashB64u: string;
              readonly ciphertextDigestB64u: string;
            };
          }
        | {
            readonly kind: 'not_required';
          };
    }
  | {
      readonly sealedHolderMaterialB64u: string;
      readonly sealedHolderRecordDigestB64u: string;
      readonly verifiedHolderCiphertextDigestSetB64u: string;
    }
  | DeviceLinkingHolderSigningMaterialBatchResultV1
  | { readonly signatureB64u: string };

type DeviceLinkingKeyWorkerFrameV1 = {
  readonly id: string;
  readonly request: unknown;
};

type EmailOtpTargetPreparationV1 = Extract<
  LinkedDeviceTargetPreparationV1,
  { readonly targetFactor: { readonly kind: 'email_otp' } }
>;

function isEmailOtpTargetPreparation(
  preparation: LinkedDeviceTargetPreparationV1,
): preparation is EmailOtpTargetPreparationV1 {
  return (
    preparation.targetFactor.kind === 'email_otp' &&
    preparation.ownerEnrollment.kind === 'linked_device_email_otp_owner_enrollment_v1'
  );
}

export type DeviceLinkingKeyWorkerScopeV1 = {
  postMessage(message: unknown): void;
  addEventListener(type: 'message', listener: (event: MessageEvent) => void): void;
  removeEventListener(type: 'message', listener: (event: MessageEvent) => void): void;
};

export type InstalledDeviceLinkingKeyWorkerV1 = {
  close(): Promise<void>;
};

export type DeviceLinkingLaneSigningMaterialV1 = {
  key_family(): string;
  create_ed25519_signing_share(
    admittedDigest: Uint8Array,
    signingWorkerCommitmentsJson: string,
    signingWorkerVerifyingShare: Uint8Array,
  ): DeviceLinkingEd25519SigningShareOutputV1;
  create_ecdsa_presign_session(
    groupPublicKey33: Uint8Array,
    sessionId: string,
  ): OpaqueEcdsaPresignSessionV1;
  destroy(): void;
  free(): void;
};

export type DeviceLinkingEd25519SigningShareOutputV1 = {
  client_commitments_json(): string;
  client_verifying_share(): Uint8Array;
  client_signature_share_b64u(): string;
  free(): void;
};

type DeviceLinkingHolderSigningMaterialSlotV1 = {
  readonly material: DeviceLinkingLaneSigningMaterialV1;
  readonly job: RotatableSigningLaneJobV1;
  readonly protocolCommitReceipt: LaneProtocolCommitReceiptV1;
  readonly materialActivation: MpcMaterialActivationRef;
};

export type DeviceLinkingHolderSigningMaterialFactoryV1 = {
  openSigningMaterial(input: {
    readonly factorSecret: Uint8Array;
    readonly sealedHolderMaterialB64u: string;
    readonly expectedRecordDigestB64u: string;
    readonly expectedHolderCiphertextDigestSetB64u: string;
    readonly jobJson: string;
    readonly receiptJson: string;
  }): DeviceLinkingLaneSigningMaterialV1 | Promise<DeviceLinkingLaneSigningMaterialV1>;
};

type DeviceLinkingEmailOtpHolderSigningMaterialChildV1 = {
  readonly job: RotatableSigningLaneJobV1;
  readonly protocolCommitReceipt: LaneProtocolCommitReceiptV1;
  readonly materialActivation: MpcMaterialActivationRef;
  readonly holderRecord: LaneSealedHolderRecordV1;
};

const keySlots = new Map<string, DeviceLinkingKeySlotV1>();
const holderSigningMaterialSlots = new Map<string, DeviceLinkingHolderSigningMaterialSlotV1>();
type PreparedTargetHolderV1 = {
  readonly child: LinkedDeviceTargetPreparationChildV1;
  readonly participant: LaneHolderParticipantRecordV1;
  readonly recipient: WasmLaneHolderRecipientV1;
};

type PreparedTargetHolderGroupV1 = {
  readonly walletId: LinkedDeviceTargetPreparationV1['walletId'];
  readonly factor: WalletCustodyEnvelopeFactor;
  readonly factorSecret: Uint8Array;
  readonly holdersByOperationId: Map<string, PreparedTargetHolderV1>;
};

const preparedTargetHolderGroups = new Map<string, PreparedTargetHolderGroupV1>();
let linkedHolderPresignPort: MessagePort | null = null;
const linkedHolderOpaquePresignAuthority = new OpaqueEcdsaPresignAuthorityV1();
const laneRecipientWasmUrl = resolveWasmUrl(
  'router_ab_ed25519_yao_client_bg.wasm',
  'Ed25519 Yao Client',
);
let laneRecipientInitPromise: Promise<void> | null = null;
const nearSignerWasmUrl = resolveWasmUrl('wasm_signer_worker_bg.wasm', 'NEAR Signer');
let nearSignerInitPromise: Promise<void> | null = null;

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

async function initializeNearSignerWasm(): Promise<void> {
  if (!nearSignerInitPromise) {
    nearSignerInitPromise = initNearSigner({ module_or_path: nearSignerWasmUrl }).then(
      () => undefined,
      (error: unknown) => {
        nearSignerInitPromise = null;
        throw error;
      },
    );
  }
  return await nearSignerInitPromise;
}

const productionHolderSigningMaterialFactory: DeviceLinkingHolderSigningMaterialFactoryV1 = {
  async openSigningMaterial(input) {
    await initializeLaneRecipientWasm();
    return new WasmLaneHolderSigningMaterialV1(
      input.factorSecret,
      input.sealedHolderMaterialB64u,
      input.expectedRecordDigestB64u,
      input.expectedHolderCiphertextDigestSetB64u,
      input.jobJson,
      input.receiptJson,
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

function createHolderSigningMaterialHandleId(): string {
  if (!globalThis.crypto || typeof globalThis.crypto.getRandomValues !== 'function') {
    throw new Error('secure randomness is unavailable for linked holder material');
  }
  const bytes = globalThis.crypto.getRandomValues(new Uint8Array(24));
  const handleId = `linked-holder-signing-${base64UrlEncode(bytes)}`;
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

function parseMaterialActivation(value: unknown): MpcMaterialActivationRef {
  const parsed = parseMpcMaterialActivationRef(value);
  if (parsed.ok) return parsed.value;
  throw new Error(parsed.error.message);
}

function parseEd25519Commitments(value: unknown): {
  readonly hiding: string;
  readonly binding: string;
} {
  const record = exactRecord(value, ['hiding', 'binding'], 'Ed25519 commitments');
  return {
    hiding: requireNonEmptyString(record.hiding, 'Ed25519 commitments.hiding'),
    binding: requireNonEmptyString(record.binding, 'Ed25519 commitments.binding'),
  };
}

function nonEmptyTupleV1<T>(first: T, rest: readonly T[]): readonly [T, ...T[]] {
  return [first, ...rest];
}

function parseEmailOtpHolderSigningMaterialBatchChildren(
  value: unknown,
): readonly [
  DeviceLinkingEmailOtpHolderSigningMaterialChildV1,
  ...DeviceLinkingEmailOtpHolderSigningMaterialChildV1[],
] {
  if (!Array.isArray(value) || value.length === 0) {
    throw new Error('device-linking Email OTP holder signing material batch is empty');
  }
  const children: DeviceLinkingEmailOtpHolderSigningMaterialChildV1[] = [];
  for (let index = 0; index < value.length; index += 1) {
    const record = exactRecord(
      value[index],
      ['job', 'protocolCommitReceipt', 'materialActivation', 'holderRecord'],
      `device-linking Email OTP holder signing material child ${index}`,
    );
    children.push({
      job: parseRotatableSigningLaneJobV1(
        record.job,
        `device-linking Email OTP holder signing material child ${index}.job`,
      ),
      protocolCommitReceipt: parseLaneProtocolCommitReceiptV1(
        record.protocolCommitReceipt,
        `device-linking Email OTP holder signing material child ${index}.protocolCommitReceipt`,
      ),
      materialActivation: parseMaterialActivation(record.materialActivation),
      holderRecord: parseLaneSealedHolderRecordV1(record.holderRecord),
    });
  }
  const first = children[0];
  if (!first) {
    throw new Error('device-linking Email OTP holder signing material batch is empty');
  }
  return nonEmptyTupleV1(first, children.slice(1));
}

function parseEmailOtpExportRootPreparation(
  value: unknown,
): DeviceLinkingEmailOtpExportRootPreparationV1 {
  const record = requireRecord(value, 'device-linking Email OTP export-root preparation');
  if (record.kind === 'not_required') {
    exactRecord(
      record,
      ['kind'],
      'device-linking Email OTP export-root preparation without a root',
    );
    return { kind: 'not_required' };
  }
  const parsed = exactRecord(
    record,
    [
      'kind',
      'transferBindingJson',
      'ephemeralPublicKeyB64u',
      'nonceB64u',
      'sealedExportRootB64u',
      'bindingDigestB64u',
      'ciphertextDigestB64u',
      'replacementEnvelopeBindingJson',
    ],
    'device-linking Email OTP export-root preparation',
  );
  if (parsed.kind !== 'required') {
    throw new Error('device-linking Email OTP export-root preparation kind is invalid');
  }
  return {
    kind: 'required',
    transferBindingJson: requireNonEmptyString(
      parsed.transferBindingJson,
      'transferBindingJson',
    ),
    ephemeralPublicKeyB64u: requireNonEmptyString(
      parsed.ephemeralPublicKeyB64u,
      'ephemeralPublicKeyB64u',
    ),
    nonceB64u: requireNonEmptyString(parsed.nonceB64u, 'nonceB64u'),
    sealedExportRootB64u: requireNonEmptyString(
      parsed.sealedExportRootB64u,
      'sealedExportRootB64u',
    ),
    bindingDigestB64u: requireNonEmptyString(parsed.bindingDigestB64u, 'bindingDigestB64u'),
    ciphertextDigestB64u: requireNonEmptyString(
      parsed.ciphertextDigestB64u,
      'ciphertextDigestB64u',
    ),
    replacementEnvelopeBindingJson: requireNonEmptyString(
      parsed.replacementEnvelopeBindingJson,
      'replacementEnvelopeBindingJson',
    ),
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
  if (record.kind === 'device_linking_email_otp_export_root_recipient_create_v1') {
    const parsed = exactRecord(
      record,
      ['kind', 'handleId'],
      'device-linking Email OTP export-root recipient create request',
    );
    return {
      kind: 'device_linking_email_otp_export_root_recipient_create_v1',
      handleId: parseHandleId(parsed.handleId),
    };
  }
  if (record.kind === 'device_linking_target_holders_prepare_v1') {
    const factorSecret =
      record.factorSecret instanceof ArrayBuffer ? new Uint8Array(record.factorSecret) : null;
    try {
      const parsed = exactRecord(
        record,
        ['kind', 'handleId', 'preparation', 'credentialIdB64u', 'factorSecret'],
        'device-linking target holders prepare request',
      );
      if (!(parsed.factorSecret instanceof ArrayBuffer) || parsed.factorSecret.byteLength !== 32) {
        throw new Error('device-linking target holder factorSecret must be 32 bytes');
      }
      return {
        kind: 'device_linking_target_holders_prepare_v1',
        handleId: parseHandleId(parsed.handleId),
        preparation: parseLinkedDeviceTargetPreparationV1(parsed.preparation),
        credentialIdB64u: requireNonEmptyString(parsed.credentialIdB64u, 'credentialIdB64u'),
        factorSecret: parsed.factorSecret,
      };
    } catch (error) {
      factorSecret?.fill(0);
      throw error;
    }
  }
  if (record.kind === 'device_linking_email_otp_target_prepare_v1') {
    const parsed = exactRecord(
      record,
      [
        'kind',
        'handleId',
        'preparation',
        'verification',
        'exportRoot',
      ],
      'device-linking Email OTP target prepare request',
    );
    return {
      kind: 'device_linking_email_otp_target_prepare_v1',
      handleId: parseHandleId(parsed.handleId),
      preparation: parseLinkedDeviceTargetPreparationV1(parsed.preparation),
      verification: parseLinkedDeviceEmailOtpVerificationResultV1(parsed.verification),
      exportRoot: parseEmailOtpExportRootPreparation(parsed.exportRoot),
    };
  }
  if (record.kind === 'device_linking_target_holder_open_seal_v1') {
    const parsed = exactRecord(
      record,
      ['kind', 'handleId', 'delivery'],
      'device-linking target holder open-and-seal request',
    );
    return {
      kind: 'device_linking_target_holder_open_seal_v1',
      handleId: parseHandleId(parsed.handleId),
      delivery: parseLinkedDeviceProvisioningChildV1(parsed.delivery),
    };
  }
  if (record.kind === 'device_linking_holder_signing_material_discard_v1') {
    const parsed = exactRecord(
      record,
      ['kind', 'handleId'],
      'device-linking holder signing material discard request',
    );
    return {
      kind: 'device_linking_holder_signing_material_discard_v1',
      handleId: parseHandleId(parsed.handleId),
    };
  }
  if (record.kind === 'device_linking_holder_ed25519_sign_v1') {
    const parsed = exactRecord(
      record,
      [
        'kind',
        'handleId',
        'admittedDigestB64u',
        'signingWorkerCommitments',
        'signingWorkerVerifyingShareB64u',
      ],
      'device-linking Ed25519 holder signing request',
    );
    return {
      kind: 'device_linking_holder_ed25519_sign_v1',
      handleId: parseHandleId(parsed.handleId),
      admittedDigestB64u: parseDigest(parsed.admittedDigestB64u, 'admittedDigestB64u'),
      signingWorkerCommitments: parseEd25519Commitments(parsed.signingWorkerCommitments),
      signingWorkerVerifyingShareB64u: parseFixedBase64Url(
        parsed.signingWorkerVerifyingShareB64u,
        32,
        'signingWorkerVerifyingShareB64u',
      ),
    };
  }
  if (record.kind === 'device_linking_request_sign_v1') {
    const parsed = parseSignRequest(record);
    return { kind: 'device_linking_request_sign_v1', ...parsed };
  }
  if (record.kind === 'device_linking_holder_signing_material_open_v1') {
    const transferredSecret =
      record.factorSecret instanceof ArrayBuffer ? new Uint8Array(record.factorSecret) : null;
    try {
      const parsed = exactRecord(
        record,
        [
          'kind',
          'factorSecret',
          'job',
          'protocolCommitReceipt',
          'materialActivation',
          'holderRecord',
        ],
        'device-linking holder signing material open request',
      );
      if (!(parsed.factorSecret instanceof ArrayBuffer) || parsed.factorSecret.byteLength !== 32) {
        throw new Error('device-linking holder signing material factorSecret must be 32 bytes');
      }
      return {
        kind: 'device_linking_holder_signing_material_open_v1',
        factorSecret: parsed.factorSecret,
        job: parseRotatableSigningLaneJobV1(
          parsed.job,
          'device-linking holder signing material job',
        ),
        protocolCommitReceipt: parseLaneProtocolCommitReceiptV1(
          parsed.protocolCommitReceipt,
          'device-linking holder signing material protocol receipt',
        ),
        materialActivation: parseMaterialActivation(parsed.materialActivation),
        holderRecord: parseLaneSealedHolderRecordV1(parsed.holderRecord),
      };
    } catch (error) {
      transferredSecret?.fill(0);
      throw error;
    }
  }
  if (record.kind === 'device_linking_email_otp_holder_signing_material_batch_open_v1') {
    const parsed = exactRecord(
      record,
      [
        'kind',
        'handleId',
        'walletId',
        'linkSessionId',
        'enrollmentId',
        'deviceId',
        'targetPreparationDigestB64u',
        'orderedChildren',
      ],
      'device-linking Email OTP holder signing material batch open request',
    );
    const walletId = parseWalletId(parsed.walletId);
    if (!walletId.ok) throw new Error(walletId.error.message);
    const linkSessionId = parseLinkDeviceSessionId(parsed.linkSessionId);
    if (!linkSessionId.ok) throw new Error(linkSessionId.error.message);
    const enrollmentId = parseLinkedDeviceEnrollmentId(parsed.enrollmentId);
    if (!enrollmentId.ok) throw new Error(enrollmentId.error.message);
    const deviceId = parseLinkedDeviceId(parsed.deviceId);
    if (!deviceId.ok) throw new Error(deviceId.error.message);
    return {
      kind: 'device_linking_email_otp_holder_signing_material_batch_open_v1',
      handleId: parseHandleId(parsed.handleId),
      walletId: walletId.value,
      linkSessionId: linkSessionId.value,
      enrollmentId: enrollmentId.value,
      deviceId: deviceId.value,
      targetPreparationDigestB64u: parseDigest(
        parsed.targetPreparationDigestB64u,
        'targetPreparationDigestB64u',
      ),
      orderedChildren: parseEmailOtpHolderSigningMaterialBatchChildren(parsed.orderedChildren),
    };
  }
  if (
    record.kind === 'device_linking_email_otp_factor_release_holder_signing_material_batch_open_v1'
  ) {
    const parsed = exactRecord(
      record,
      [
        'kind',
        'handleId',
        'walletId',
        'enrollmentId',
        'expectedChallengeId',
        'factorRelease',
        'orderedChildren',
      ],
      'device-linking Email OTP factor release holder signing material batch open request',
    );
    const walletId = parseWalletId(parsed.walletId);
    if (!walletId.ok) throw new Error(walletId.error.message);
    const enrollmentId = parseLinkedDeviceEnrollmentId(parsed.enrollmentId);
    if (!enrollmentId.ok) throw new Error(enrollmentId.error.message);
    return {
      kind: 'device_linking_email_otp_factor_release_holder_signing_material_batch_open_v1',
      handleId: parseHandleId(parsed.handleId),
      walletId: walletId.value,
      enrollmentId: enrollmentId.value,
      expectedChallengeId: requireNonEmptyString(parsed.expectedChallengeId, 'expectedChallengeId'),
      factorRelease: parseLinkedDeviceEmailOtpFactorReleaseEnvelopeV1(parsed.factorRelease),
      orderedChildren: parseEmailOtpHolderSigningMaterialBatchChildren(parsed.orderedChildren),
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
  const emailOtpReleasePair = requireCryptoKeyPair(
    await globalThis.crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, [
      'deriveBits',
    ]),
    'Email OTP factor release',
  );
  const identityPublicBytes = new Uint8Array(
    await globalThis.crypto.subtle.exportKey('raw', identityPair.publicKey),
  );
  const linkPublicBytes = new Uint8Array(
    await globalThis.crypto.subtle.exportKey('raw', linkPair.publicKey),
  );
  const emailOtpReleasePublicBytes = new Uint8Array(
    await globalThis.crypto.subtle.exportKey('raw', emailOtpReleasePair.publicKey),
  );
  try {
    if (
      identityPublicBytes.length !== 32 ||
      linkPublicBytes.length !== 32 ||
      emailOtpReleasePublicBytes.length !== 65 ||
      emailOtpReleasePublicBytes[0] !== 4
    ) {
      throw new Error('device-linking worker returned an invalid public key length');
    }
    const devicePublicKeyB64u = parseLinkDevicePublicKeyB64u(base64UrlEncode(identityPublicBytes));
    const linkPublicKeyB64u = parseLinkDevicePublicKeyB64u(base64UrlEncode(linkPublicBytes));
    const emailOtpReleasePublicKey65B64u = base64UrlEncode(emailOtpReleasePublicBytes);
    const handleId = createHandleId();
    const slot: DeviceLinkingKeySlotV1 = {
      identityPrivateKey: identityPair.privateKey,
      linkPrivateKey: linkPair.privateKey,
      devicePublicKeyB64u,
      linkPublicKeyB64u,
      emailOtpReleasePrivateKey: emailOtpReleasePair.privateKey,
      emailOtpReleasePublicKey65B64u,
      emailOtpExportRootRecipient: null,
      emailOtpActivation: null,
    };
    return {
      slot,
      result: {
        handleId,
        linkPublicKeyB64u,
        devicePublicKeyB64u,
        emailOtpReleasePublicKey65B64u,
      },
    };
  } finally {
    identityPublicBytes.fill(0);
    linkPublicBytes.fill(0);
    emailOtpReleasePublicBytes.fill(0);
  }
}

function assertProtocolReceiptMatchesJob(
  job: RotatableSigningLaneJobV1,
  receipt: LaneProtocolCommitReceiptV1,
): void {
  if (
    String(receipt.operationId) !== String(job.operationId) ||
    String(receipt.enrollmentId) !== String(job.enrollmentId) ||
    String(receipt.walletId) !== String(job.walletId) ||
    String(receipt.walletKeyId) !== String(job.walletKeyId) ||
    receipt.keyFamily !== job.keyFamily ||
    String(receipt.sourceLaneId) !== String(job.source.laneId) ||
    String(receipt.sourceLaneShareEpoch) !== String(job.source.laneShareEpoch) ||
    receipt.sourceRevocationEpoch !== job.source.revocationEpoch ||
    !mpcMaterialActivationRefsEqual(
      receipt.sourceMaterialActivation,
      job.source.materialActivation,
    ) ||
    String(receipt.targetLaneId) !== String(job.target.laneId) ||
    String(receipt.targetLaneShareEpoch) !== String(job.target.laneShareEpoch) ||
    String(receipt.targetMaterialActivationId) !== String(job.targetMaterialActivationId) ||
    receipt.holderRecipientKeyDigestB64u !== job.targetHolder.hpkePublicKeyDigestB64u ||
    receipt.serverRecipientKeyDigestB64u !== job.targetSigningWorker.hpkePublicKeyDigestB64u
  ) {
    throw new Error('linked holder protocol receipt does not match its persisted R102 job');
  }
}

function assertTargetMaterialActivationMatchesJob(
  job: RotatableSigningLaneJobV1,
  materialActivation: MpcMaterialActivationRef,
): void {
  const source = job.source.materialActivation;
  if (
    String(materialActivation.activationId) !== String(job.targetMaterialActivationId) ||
    materialActivation.capability !== source.capability ||
    materialActivation.materialOwner !== source.materialOwner ||
    materialActivation.keyBinding !== source.keyBinding ||
    materialActivation.lifecycleBinding !== source.lifecycleBinding ||
    String(materialActivation.signingWorker) !== String(job.targetSigningWorker.participantId)
  ) {
    throw new Error('linked holder material activation does not match its persisted R102 job');
  }
}

function assertHolderRecordMatchesPersistedJob(input: {
  readonly job: RotatableSigningLaneJobV1;
  readonly receipt: LaneProtocolCommitReceiptV1;
  readonly materialActivation: MpcMaterialActivationRef;
  readonly record: LaneSealedHolderRecordV1;
}): void {
  const { job, receipt, record } = input;
  assertProtocolReceiptMatchesJob(job, receipt);
  assertTargetMaterialActivationMatchesJob(job, input.materialActivation);
  if (
    String(record.operationId) !== String(job.operationId) ||
    String(record.enrollmentId) !== String(job.enrollmentId) ||
    String(record.walletId) !== String(job.walletId) ||
    String(record.walletKeyId) !== String(job.walletKeyId) ||
    String(record.laneId) !== String(job.target.laneId) ||
    String(record.laneShareEpoch) !== String(job.target.laneShareEpoch) ||
    String(record.targetMaterialActivationId) !== String(job.targetMaterialActivationId) ||
    record.holderParticipantBindingDigestB64u !== job.targetHolder.participantBindingDigestB64u ||
    String(record.custodyBindingId) !== String(job.targetHolder.custodyBindingId) ||
    record.holderRecipientKeyDigestB64u !== receipt.holderRecipientKeyDigestB64u ||
    record.holderCiphertextDigestSetB64u !== receipt.targetHolderCiphertextDigestSetB64u ||
    record.transcriptHashB64u !== receipt.transcriptHashB64u
  ) {
    throw new Error('sealed holder record does not match its persisted R102 child');
  }
}

async function openHolderSigningMaterialWithFactorSecret(input: {
  readonly factorSecret: Uint8Array;
  readonly job: RotatableSigningLaneJobV1;
  readonly protocolCommitReceipt: LaneProtocolCommitReceiptV1;
  readonly materialActivation: MpcMaterialActivationRef;
  readonly holderRecord: LaneSealedHolderRecordV1;
  readonly signingMaterialFactory: DeviceLinkingHolderSigningMaterialFactoryV1;
}): Promise<{
  readonly handleId: string;
  readonly keyFamily: 'ed25519' | 'ecdsa_secp256k1';
}> {
  let material: DeviceLinkingLaneSigningMaterialV1 | undefined;
  try {
    assertHolderRecordMatchesPersistedJob({
      job: input.job,
      receipt: input.protocolCommitReceipt,
      materialActivation: input.materialActivation,
      record: input.holderRecord,
    });
    material = await input.signingMaterialFactory.openSigningMaterial({
      factorSecret: input.factorSecret,
      sealedHolderMaterialB64u: input.holderRecord.sealedHolderMaterialB64u,
      expectedRecordDigestB64u: input.holderRecord.sealedHolderRecordDigestB64u,
      expectedHolderCiphertextDigestSetB64u: input.holderRecord.holderCiphertextDigestSetB64u,
      jobJson: JSON.stringify(input.job),
      receiptJson: JSON.stringify(input.protocolCommitReceipt),
    });
    const keyFamily = material.key_family();
    if (keyFamily !== input.job.keyFamily) {
      throw new Error('reopened holder material changed its persisted key family');
    }
    const handleId = createHolderSigningMaterialHandleId();
    holderSigningMaterialSlots.set(handleId, {
      material,
      job: input.job,
      protocolCommitReceipt: input.protocolCommitReceipt,
      materialActivation: input.materialActivation,
    });
    material = undefined;
    return { handleId, keyFamily };
  } finally {
    material?.destroy();
    material?.free();
  }
}

async function openPersistedHolderSigningMaterial(
  request: Extract<
    DeviceLinkingKeyWorkerRequestV1,
    { readonly kind: 'device_linking_holder_signing_material_open_v1' }
  >,
  signingMaterialFactory: DeviceLinkingHolderSigningMaterialFactoryV1,
): Promise<{
  readonly handleId: string;
  readonly keyFamily: 'ed25519' | 'ecdsa_secp256k1';
}> {
  const factorSecret = new Uint8Array(request.factorSecret);
  try {
    return await openHolderSigningMaterialWithFactorSecret({
      factorSecret,
      job: request.job,
      protocolCommitReceipt: request.protocolCommitReceipt,
      materialActivation: request.materialActivation,
      holderRecord: request.holderRecord,
      signingMaterialFactory,
    });
  } finally {
    factorSecret.fill(0);
  }
}

function assertEmailOtpActivationBatchMatches(input: {
  readonly request: Extract<
    DeviceLinkingKeyWorkerRequestV1,
    { readonly kind: 'device_linking_email_otp_holder_signing_material_batch_open_v1' }
  >;
  readonly activation: DeviceLinkingEmailOtpActivationStateV1;
}): void {
  const { request, activation } = input;
  if (
    String(request.walletId) !== String(activation.walletId) ||
    String(request.linkSessionId) !== String(activation.linkSessionId) ||
    String(request.enrollmentId) !== String(activation.enrollmentId) ||
    String(request.deviceId) !== String(activation.deviceId) ||
    request.targetPreparationDigestB64u !== activation.targetPreparationDigestB64u ||
    request.orderedChildren.length !== activation.orderedChildren.length
  ) {
    throw new Error('device-linking Email OTP holder batch changed its activation binding');
  }
  const operationIds = new Set<string>();
  for (let index = 0; index < request.orderedChildren.length; index += 1) {
    const supplied = request.orderedChildren[index];
    const expected = activation.orderedChildren[index];
    if (!supplied || !expected) {
      throw new Error('device-linking Email OTP holder batch changed its child order');
    }
    const job = supplied.job;
    const operationId = String(job.operationId);
    if (operationIds.has(operationId)) {
      throw new Error('device-linking Email OTP holder batch repeats an operation');
    }
    operationIds.add(operationId);
    if (
      String(job.operationId) !== String(expected.child.operationId) ||
      String(job.enrollmentId) !== String(activation.enrollmentId) ||
      String(job.walletId) !== String(activation.walletId) ||
      String(job.walletKeyId) !== String(expected.child.walletKeyId) ||
      job.keyFamily !== expected.child.keyFamily ||
      String(job.target.laneId) !== String(expected.child.targetLaneId) ||
      String(job.target.laneShareEpoch) !== String(expected.child.targetLaneShareEpoch) ||
      String(job.targetMaterialActivationId) !==
        String(expected.child.targetMaterialActivationId) ||
      String(job.targetHolder.participantId) !== String(expected.participant.participantId) ||
      String(job.targetHolder.custodyBindingId) !== String(expected.participant.custodyBindingId) ||
      job.targetHolder.custodyBindingDigestB64u !== expected.participant.custodyBindingDigestB64u ||
      job.targetHolder.hpkePublicKeyB64u !== expected.participant.hpkePublicKeyB64u ||
      job.targetHolder.hpkePublicKeyDigestB64u !== expected.participant.hpkePublicKeyDigestB64u ||
      job.targetHolder.participantBindingDigestB64u !==
        expected.participant.participantBindingDigestB64u
    ) {
      throw new Error('device-linking Email OTP holder batch changed its prepared target identity');
    }
    assertHolderRecordMatchesPersistedJob({
      job,
      receipt: supplied.protocolCommitReceipt,
      materialActivation: supplied.materialActivation,
      record: supplied.holderRecord,
    });
  }
}

async function openPersistedEmailOtpHolderSigningMaterials(
  request: Extract<
    DeviceLinkingKeyWorkerRequestV1,
    { readonly kind: 'device_linking_email_otp_holder_signing_material_batch_open_v1' }
  >,
  signingMaterialFactory: DeviceLinkingHolderSigningMaterialFactoryV1,
): Promise<DeviceLinkingHolderSigningMaterialBatchResultV1> {
  const slot = keySlots.get(request.handleId);
  if (!slot) throw new Error('device-linking key handle is unknown or discarded');
  const activation = slot.emailOtpActivation;
  if (!activation) {
    throw new Error('device-linking Email OTP activation material is unavailable');
  }
  slot.emailOtpActivation = null;
  const factorSecret = activation.factorSecret;
  const opened: DeviceLinkingHolderSigningMaterialHandleResultV1[] = [];
  try {
    assertEmailOtpActivationBatchMatches({ request, activation });
    for (const child of request.orderedChildren) {
      const childFactorSecret = factorSecret.slice();
      try {
        opened.push(
          await openHolderSigningMaterialWithFactorSecret({
            factorSecret: childFactorSecret,
            job: child.job,
            protocolCommitReceipt: child.protocolCommitReceipt,
            materialActivation: child.materialActivation,
            holderRecord: child.holderRecord,
            signingMaterialFactory,
          }),
        );
      } finally {
        childFactorSecret.fill(0);
      }
    }
    const first = opened[0];
    if (!first) throw new Error('device-linking Email OTP holder batch is empty');
    destroyPreparedTargetHolderGroup(request.handleId);
    return {
      holderSigningMaterialHandles: nonEmptyTupleV1(first, opened.slice(1)),
    };
  } catch (error) {
    for (const holderHandle of opened) discardHolderSigningMaterial(holderHandle.handleId);
    destroyPreparedTargetHolderGroup(request.handleId);
    throw error;
  } finally {
    factorSecret.fill(0);
  }
}

async function openPersistedEmailOtpHolderSigningMaterialsFromFactorRelease(
  request: Extract<
    DeviceLinkingKeyWorkerRequestV1,
    {
      readonly kind: 'device_linking_email_otp_factor_release_holder_signing_material_batch_open_v1';
    }
  >,
  signingMaterialFactory: DeviceLinkingHolderSigningMaterialFactoryV1,
): Promise<DeviceLinkingHolderSigningMaterialBatchResultV1> {
  const slot = keySlots.get(request.handleId);
  if (!slot) throw new Error('device-linking key handle is unknown or discarded');
  let factorSecret: Uint8Array | null = null;
  const opened: DeviceLinkingHolderSigningMaterialHandleResultV1[] = [];
  try {
    const operationIds = new Set<string>();
    for (const child of request.orderedChildren) {
      const operationId = String(child.job.operationId);
      if (operationIds.has(operationId)) {
        throw new Error('device-linking Email OTP factor release batch repeats an operation');
      }
      operationIds.add(operationId);
      if (
        String(child.job.walletId) !== String(request.walletId) ||
        child.job.authorization.kind !== 'linked_device_enrollment' ||
        String(child.job.authorization.linkedDeviceEnrollmentId) !== String(request.enrollmentId) ||
        child.job.target.laneKind !== 'linked_device'
      ) {
        throw new Error('device-linking Email OTP factor release batch changed its wallet binding');
      }
      assertHolderRecordMatchesPersistedJob({
        job: child.job,
        receipt: child.protocolCommitReceipt,
        materialActivation: child.materialActivation,
        record: child.holderRecord,
      });
    }
    factorSecret = await decryptEmailOtpFactorReleaseEnvelope({
      slot,
      walletId: String(request.walletId),
      factorRelease: request.factorRelease,
      expectedChallengeId: request.expectedChallengeId,
    });
    for (const child of request.orderedChildren) {
      const childFactorSecret = factorSecret.slice();
      try {
        opened.push(
          await openHolderSigningMaterialWithFactorSecret({
            factorSecret: childFactorSecret,
            job: child.job,
            protocolCommitReceipt: child.protocolCommitReceipt,
            materialActivation: child.materialActivation,
            holderRecord: child.holderRecord,
            signingMaterialFactory,
          }),
        );
      } finally {
        childFactorSecret.fill(0);
      }
    }
    const first = opened[0];
    if (!first) throw new Error('device-linking Email OTP factor release batch is empty');
    return {
      holderSigningMaterialHandles: nonEmptyTupleV1(first, opened.slice(1)),
    };
  } catch (error) {
    for (const holderHandle of opened) discardHolderSigningMaterial(holderHandle.handleId);
    throw error;
  } finally {
    factorSecret?.fill(0);
    discardKeyMaterialSlot(request.handleId);
  }
}

function discardHolderSigningMaterial(handleId: string): void {
  const slot = holderSigningMaterialSlots.get(handleId);
  if (!slot) return;
  holderSigningMaterialSlots.delete(handleId);
  slot.material.destroy();
  slot.material.free();
}

function discardKeyMaterialSlot(handleId: string): void {
  destroyPreparedTargetHolderGroup(handleId);
  const slot = keySlots.get(handleId);
  if (slot) {
    destroyEmailOtpActivation(slot);
    slot.emailOtpExportRootRecipient?.free();
    slot.emailOtpExportRootRecipient = null;
  }
  keySlots.delete(handleId);
}

function createEd25519HolderSigningShare(
  request: Extract<
    DeviceLinkingKeyWorkerRequestV1,
    { readonly kind: 'device_linking_holder_ed25519_sign_v1' }
  >,
): {
  readonly clientCommitments: { readonly hiding: string; readonly binding: string };
  readonly clientVerifyingShareB64u: string;
  readonly clientSignatureShareB64u: string;
} {
  const slot = holderSigningMaterialSlots.get(request.handleId);
  if (!slot || slot.job.keyFamily !== 'ed25519') {
    throw new Error('Ed25519 holder signing material is unknown, discarded, or cross-curve');
  }
  if (
    request.signingWorkerVerifyingShareB64u !==
    slot.protocolCommitReceipt.targetServerPublicCommitmentB64u
  ) {
    throw new Error('SigningWorker verifying share does not match the persisted R102 receipt');
  }
  const admittedDigest = base64UrlDecode(request.admittedDigestB64u);
  const signingWorkerVerifyingShare = base64UrlDecode(request.signingWorkerVerifyingShareB64u);
  let output: DeviceLinkingEd25519SigningShareOutputV1 | undefined;
  let clientVerifyingShare: Uint8Array | undefined;
  try {
    output = slot.material.create_ed25519_signing_share(
      admittedDigest,
      JSON.stringify(request.signingWorkerCommitments),
      signingWorkerVerifyingShare,
    );
    clientVerifyingShare = output.client_verifying_share();
    if (
      clientVerifyingShare.length !== 32 ||
      base64UrlEncode(clientVerifyingShare) !==
        slot.protocolCommitReceipt.targetHolderPublicCommitmentB64u
    ) {
      throw new Error('holder verifying share does not match the persisted R102 receipt');
    }
    return {
      clientCommitments: parseEd25519Commitments(JSON.parse(output.client_commitments_json())),
      clientVerifyingShareB64u: base64UrlEncode(clientVerifyingShare),
      clientSignatureShareB64u: parseFixedBase64Url(
        output.client_signature_share_b64u(),
        32,
        'clientSignatureShareB64u',
      ),
    };
  } finally {
    admittedDigest.fill(0);
    signingWorkerVerifyingShare.fill(0);
    clientVerifyingShare?.fill(0);
    output?.free();
  }
}

type LinkedHolderOpaquePresignRequestV1 =
  | Extract<
      OpaqueEcdsaPresignAuthorityRequestV1,
      {
        readonly kind: 'opaque_ecdsa_presign_session_init_v1';
        readonly authority: { readonly kind: 'linked_holder_signing_material' };
      }
    >
  | Extract<
      OpaqueEcdsaPresignAuthorityRequestV1,
      { readonly kind: 'opaque_ecdsa_presign_session_step_v1' }
    >
  | Extract<
      OpaqueEcdsaPresignAuthorityRequestV1,
      { readonly kind: 'opaque_ecdsa_presign_session_abort_v1' }
    >
  | Extract<
      OpaqueEcdsaPresignAuthorityRequestV1,
      { readonly kind: 'opaque_ecdsa_online_compute_v1' }
    >
  | Extract<
      OpaqueEcdsaPresignAuthorityRequestV1,
      { readonly kind: 'opaque_ecdsa_presign_material_destroy_v1' }
    >;

function linkedHolderPresignError(
  requestId: string,
  error: unknown,
): OpaqueEcdsaPresignAuthorityResponseV1 {
  return {
    kind: 'opaque_ecdsa_presign_authority_result_v1',
    requestId,
    ok: false,
    error: workerError(error),
  };
}

function requireLinkedHolderPresignRequest(value: unknown): LinkedHolderOpaquePresignRequestV1 {
  const record = requireRecord(value, 'linked holder ECDSA presign request');
  if (typeof record.requestId !== 'string' || !record.requestId.trim()) {
    throw new Error('linked holder ECDSA presign requestId is required');
  }
  switch (record.kind) {
    case 'opaque_ecdsa_presign_session_init_v1': {
      exactRecord(
        record,
        [
          'kind',
          'requestId',
          'sessionId',
          'authority',
          'poolIdentity',
          'groupPublicKey33',
          'materialExpiresAtMs',
        ],
        'linked holder ECDSA presign init request',
      );
      const authority = exactRecord(
        record.authority,
        ['kind', 'holderHandleId'],
        'linked holder ECDSA presign authority',
      );
      if (
        authority.kind !== 'linked_holder_signing_material' ||
        typeof authority.holderHandleId !== 'string' ||
        !authority.holderHandleId.trim()
      ) {
        throw new Error('linked holder ECDSA presign authority is invalid');
      }
      if (
        !(record.groupPublicKey33 instanceof ArrayBuffer) ||
        record.groupPublicKey33.byteLength !== 33
      ) {
        throw new Error('linked holder ECDSA presign groupPublicKey33 must be 33 bytes');
      }
      const materialExpiresAtMs = Number(record.materialExpiresAtMs);
      if (!Number.isSafeInteger(materialExpiresAtMs) || materialExpiresAtMs <= Date.now()) {
        throw new Error('linked holder ECDSA presign material expiry must be in the future');
      }
      return {
        kind: record.kind,
        requestId: record.requestId,
        sessionId: requireLinkedHolderString(record.sessionId, 'sessionId'),
        authority: {
          kind: authority.kind,
          holderHandleId: authority.holderHandleId,
        },
        poolIdentity: parseEcdsaClientPresignPoolIdentity(record.poolIdentity),
        groupPublicKey33: record.groupPublicKey33,
        materialExpiresAtMs,
      };
    }
    case 'opaque_ecdsa_presign_session_step_v1': {
      exactRecord(
        record,
        ['kind', 'requestId', 'sessionId', 'stage', 'incomingMessages'],
        'linked holder ECDSA presign step request',
      );
      if (record.stage !== 'triples' && record.stage !== 'presign') {
        throw new Error('linked holder ECDSA presign stage is invalid');
      }
      if (
        !Array.isArray(record.incomingMessages) ||
        !record.incomingMessages.every(isArrayBuffer)
      ) {
        throw new Error('linked holder ECDSA presign messages must be ArrayBuffers');
      }
      return {
        kind: record.kind,
        requestId: record.requestId,
        sessionId: requireLinkedHolderString(record.sessionId, 'sessionId'),
        stage: record.stage,
        incomingMessages: record.incomingMessages,
      };
    }
    case 'opaque_ecdsa_presign_session_abort_v1':
      exactRecord(
        record,
        ['kind', 'requestId', 'sessionId'],
        'linked holder ECDSA presign abort request',
      );
      return {
        kind: record.kind,
        requestId: record.requestId,
        sessionId: requireLinkedHolderString(record.sessionId, 'sessionId'),
      };
    case 'opaque_ecdsa_online_compute_v1':
      return {
        kind: record.kind,
        requestId: record.requestId,
        materialHandle: requireLinkedHolderString(record.materialHandle, 'materialHandle'),
        groupPublicKey33: requireLinkedHolderBuffer(
          record.groupPublicKey33,
          33,
          'groupPublicKey33',
        ),
        expectedPresignBigR33: requireLinkedHolderBuffer(
          record.expectedPresignBigR33,
          33,
          'expectedPresignBigR33',
        ),
        digest32: requireLinkedHolderBuffer(record.digest32, 32, 'digest32'),
        clientRerandomizationContribution32: requireLinkedHolderBuffer(
          record.clientRerandomizationContribution32,
          32,
          'clientRerandomizationContribution32',
        ),
        signingWorkerRerandomizationContribution32: requireLinkedHolderBuffer(
          record.signingWorkerRerandomizationContribution32,
          32,
          'signingWorkerRerandomizationContribution32',
        ),
      };
    case 'opaque_ecdsa_presign_material_destroy_v1':
      return {
        kind: record.kind,
        requestId: record.requestId,
        materialHandle: requireLinkedHolderString(record.materialHandle, 'materialHandle'),
      };
    default:
      throw new Error('linked holder ECDSA presign request kind is invalid');
  }
}

function requireLinkedHolderString(value: unknown, label: string): string {
  if (typeof value !== 'string' || !value.trim()) throw new Error(`${label} is required`);
  return value;
}

function requireLinkedHolderBuffer(value: unknown, length: number, label: string): ArrayBuffer {
  if (!(value instanceof ArrayBuffer) || value.byteLength !== length) {
    throw new Error(`${label} must be a ${length}-byte ArrayBuffer`);
  }
  return value;
}

function isArrayBuffer(value: unknown): value is ArrayBuffer {
  return value instanceof ArrayBuffer;
}

function createLinkedHolderEcdsaPresignSession(
  request: Extract<
    LinkedHolderOpaquePresignRequestV1,
    { readonly kind: 'opaque_ecdsa_presign_session_init_v1' }
  >,
): OpaqueEcdsaPresignSessionV1 {
  const slot = holderSigningMaterialSlots.get(request.authority.holderHandleId);
  if (!slot || slot.job.keyFamily !== 'ecdsa_secp256k1') {
    throw new Error('ECDSA holder signing material is unknown, discarded, or cross-curve');
  }
  const pool = request.poolIdentity;
  if (
    pool.walletId !== slot.job.walletId ||
    pool.materialActivationId !== slot.materialActivation.activationId ||
    pool.capability !== slot.materialActivation.capability ||
    pool.keyBinding !== slot.materialActivation.keyBinding ||
    String(slot.materialActivation.signingWorker) !==
      String(slot.job.targetSigningWorker.participantId)
  ) {
    throw new Error('ECDSA presign pool changed the linked holder activation identity');
  }
  const requestedGroupKey = new Uint8Array(request.groupPublicKey33).slice();
  const persistedGroupKey = base64UrlDecode(slot.job.thresholdPublicKey33B64u);
  try {
    if (
      persistedGroupKey.length !== 33 ||
      requestedGroupKey.length !== 33 ||
      !requestedGroupKey.every((byte, index) => byte === persistedGroupKey[index])
    ) {
      throw new Error('ECDSA presign group key changed the persisted R102 child');
    }
    return slot.material.create_ecdsa_presign_session(requestedGroupKey, request.sessionId);
  } finally {
    requestedGroupKey.fill(0);
    persistedGroupKey.fill(0);
  }
}

async function handleLinkedHolderPresignRequest(event: MessageEvent<unknown>): Promise<void> {
  if (!linkedHolderPresignPort) return;
  let requestId = '';
  try {
    const request = requireLinkedHolderPresignRequest(event.data);
    requestId = request.requestId;
    let result: Extract<OpaqueEcdsaPresignAuthorityResponseV1, { readonly ok: true }>['result'];
    switch (request.kind) {
      case 'opaque_ecdsa_presign_session_init_v1':
        result = {
          kind: 'progress',
          progress: await linkedHolderOpaquePresignAuthority.initialize({
            presignSessionId: request.sessionId,
            session: createLinkedHolderEcdsaPresignSession(request),
            groupPublicKey33: new Uint8Array(request.groupPublicKey33),
            expiresAtMs: request.materialExpiresAtMs,
            poolIdentity: request.poolIdentity,
          }),
        };
        break;
      case 'opaque_ecdsa_presign_session_step_v1':
        result = {
          kind: 'progress',
          progress: await linkedHolderOpaquePresignAuthority.step({
            presignSessionId: request.sessionId,
            stage: request.stage,
            incomingMessages: request.incomingMessages,
          }),
        };
        break;
      case 'opaque_ecdsa_presign_session_abort_v1':
        result = {
          kind: 'aborted',
          sessionId: (await linkedHolderOpaquePresignAuthority.abort(request.sessionId)).sessionId,
        };
        break;
      case 'opaque_ecdsa_online_compute_v1': {
        const signatureShare32 =
          await linkedHolderOpaquePresignAuthority.computeSignatureShare(request);
        result = { kind: 'online_share', signatureShare32 };
        break;
      }
      case 'opaque_ecdsa_presign_material_destroy_v1':
        await linkedHolderOpaquePresignAuthority.destroyMaterial(request.materialHandle);
        result = { kind: 'material_destroyed', materialHandle: request.materialHandle };
        break;
    }
    linkedHolderPresignPort.postMessage({
      kind: 'opaque_ecdsa_presign_authority_result_v1',
      requestId,
      ok: true,
      result,
    } satisfies OpaqueEcdsaPresignAuthorityResponseV1);
  } catch (error) {
    if (requestId) linkedHolderPresignPort.postMessage(linkedHolderPresignError(requestId, error));
  }
}

function enqueueLinkedHolderPresignRequest(event: MessageEvent<unknown>): void {
  void handleLinkedHolderPresignRequest(event);
}

function attachLinkedHolderPresignPort(port: MessagePort): void {
  linkedHolderPresignPort?.close();
  linkedHolderOpaquePresignAuthority.close();
  linkedHolderPresignPort = port;
  port.onmessage = enqueueLinkedHolderPresignRequest;
  port.start();
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

function secureRandomBytes(length: number, label: string): Uint8Array {
  if (!globalThis.crypto || typeof globalThis.crypto.getRandomValues !== 'function') {
    throw new Error(`secure randomness is unavailable for ${label}`);
  }
  const bytes = new Uint8Array(length);
  do {
    globalThis.crypto.getRandomValues(bytes);
  } while (bytes.every((byte) => byte === 0));
  return bytes;
}

function requiredDomainValue<T>(
  parsed:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
): T {
  if (parsed.ok) return parsed.value;
  throw new Error(parsed.error.message);
}

function createTargetCustodyBindingId() {
  const random = secureRandomBytes(24, 'linked-device lane custody binding');
  try {
    return requiredDomainValue(
      parseLaneHolderCustodyBindingId(`linked-device-lane-custody-${base64UrlEncode(random)}`),
    );
  } finally {
    random.fill(0);
  }
}

async function computeTargetCustodyBindingDigest(input: {
  readonly custodyBindingId: string;
  readonly preparation: LinkedDeviceTargetPreparationV1;
  readonly child: LinkedDeviceTargetPreparationChildV1;
  readonly factorBindingId: string;
}) {
  const canonical = new TextEncoder().encode(
    JSON.stringify([
      'seams/linked-device/lane-custody-binding/v1',
      input.custodyBindingId,
      input.preparation.walletId,
      input.preparation.enrollmentId,
      input.child.operationId,
      input.child.walletKeyId,
      input.child.targetLaneId,
      input.child.targetLaneShareEpoch,
      input.child.targetMaterialActivationId,
      input.factorBindingId,
    ]),
  );
  try {
    const digest = new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', canonical));
    try {
      return requiredDomainValue(parseLaneCustodyBindingDigestB64u(base64UrlEncode(digest)));
    } finally {
      digest.fill(0);
    }
  } finally {
    canonical.fill(0);
  }
}

function destroyPreparedTargetHolder(holder: PreparedTargetHolderV1): void {
  holder.recipient.destroy();
  holder.recipient.free();
}

function destroyPreparedTargetHolderGroup(handleId: string): void {
  const group = preparedTargetHolderGroups.get(handleId);
  if (!group) return;
  preparedTargetHolderGroups.delete(handleId);
  for (const holder of group.holdersByOperationId.values()) {
    destroyPreparedTargetHolder(holder);
  }
  group.holdersByOperationId.clear();
  group.factorSecret.fill(0);
}

function destroyEmailOtpActivation(slot: DeviceLinkingKeySlotV1): void {
  const activation = slot.emailOtpActivation;
  if (!activation) return;
  slot.emailOtpActivation = null;
  activation.factorSecret.fill(0);
}

async function createPreparedTargetHolder(input: {
  readonly preparation: LinkedDeviceTargetPreparationV1;
  readonly child: LinkedDeviceTargetPreparationChildV1;
  readonly factorBindingId: string;
}): Promise<PreparedTargetHolderV1> {
  const recipientKeyMaterial = secureRandomBytes(32, 'linked-device lane recipient');
  let recipient: WasmLaneHolderRecipientV1;
  try {
    recipient = new WasmLaneHolderRecipientV1(
      String(input.child.operationId),
      recipientKeyMaterial,
    );
  } finally {
    recipientKeyMaterial.fill(0);
  }
  try {
    const custodyBindingId = createTargetCustodyBindingId();
    const custodyBindingDigestB64u = await computeTargetCustodyBindingDigest({
      custodyBindingId,
      preparation: input.preparation,
      child: input.child,
      factorBindingId: input.factorBindingId,
    });
    const hpkePublicKeyB64u = requiredDomainValue(
      parseHpkePublicKeyB64u(recipient.hpke_public_key_b64u()),
    );
    const hpkePublicKeyDigestB64u = requiredDomainValue(
      parseSigningWorkerRecipientKeyDigestB64u(recipient.hpke_public_key_digest_b64u()),
    );
    const custody = buildLaneHolderCustodyIdentityV1({
      custodyBindingId,
      custodyBindingDigestB64u,
    });
    const participantBindingDigestB64u = await computeLaneHolderParticipantBindingDigestV1({
      participantId: input.child.targetHolderParticipantId,
      custody,
      hpkePublicKeyB64u,
      hpkePublicKeyDigestB64u,
    });
    return {
      child: input.child,
      recipient,
      participant: buildLaneHolderParticipantRecordV1({
        participantId: input.child.targetHolderParticipantId,
        custody,
        hpkePublicKeyB64u,
        hpkePublicKeyDigestB64u,
        participantBindingDigestB64u,
      }),
    };
  } catch (error) {
    recipient.destroy();
    recipient.free();
    throw error;
  }
}

async function prepareTargetHolders(
  request: Extract<
    DeviceLinkingKeyWorkerRequestV1,
    { readonly kind: 'device_linking_target_holders_prepare_v1' }
  >,
): Promise<
  Extract<DeviceLinkingKeyWorkerResponseV1, { readonly orderedHolderRegistrations: unknown }>
> {
  if (!keySlots.has(request.handleId)) {
    new Uint8Array(request.factorSecret).fill(0);
    throw new Error('device-linking key handle is unknown or discarded');
  }
  if (preparedTargetHolderGroups.has(request.handleId)) {
    new Uint8Array(request.factorSecret).fill(0);
    throw new Error('device-linking target holders are already prepared');
  }
  if (
    request.preparation.targetFactor.kind !== 'passkey_prf' ||
    request.preparation.ownerEnrollment.kind !== 'linked_device_passkey_owner_enrollment_v1'
  ) {
    new Uint8Array(request.factorSecret).fill(0);
    throw new Error('passkey holder preparation requires a Passkey target preparation');
  }
  await initializeLaneRecipientWasm();
  const credentialIdB64u = requiredDomainValue(
    parseWebAuthnCredentialIdB64u(request.credentialIdB64u),
  );
  const factorSecret = new Uint8Array(request.factorSecret);
  const holdersByOperationId = new Map<string, PreparedTargetHolderV1>();
  try {
    const registrations: LinkedDeviceTargetHolderRegistrationV1[] = [];
    for (const child of request.preparation.orderedChildren) {
      const operationId = String(child.operationId);
      if (holdersByOperationId.has(operationId)) {
        throw new Error('device-linking target preparation repeats an operation');
      }
      const holder = await createPreparedTargetHolder({
        preparation: request.preparation,
        child,
        factorBindingId: credentialIdB64u,
      });
      holdersByOperationId.set(operationId, holder);
      registrations.push({
        kind: 'linked_device_target_holder_registration_v1',
        operationId: child.operationId,
        walletKeyId: child.walletKeyId,
        keyFamily: child.keyFamily,
        targetLaneId: child.targetLaneId,
        targetLaneShareEpoch: child.targetLaneShareEpoch,
        targetMaterialActivationId: child.targetMaterialActivationId,
        holderParticipant: holder.participant,
      });
    }
    const first = registrations[0];
    if (!first) throw new Error('device-linking target preparation has no holders');
    preparedTargetHolderGroups.set(request.handleId, {
      walletId: request.preparation.walletId,
      factor: buildPasskeyEnvelopeFactor({
        rpId: request.preparation.ownerEnrollment.registration.rpId,
        credentialIdB64u,
      }),
      factorSecret,
      holdersByOperationId,
    });
    return {
      orderedHolderRegistrations: [first, ...registrations.slice(1)],
    };
  } catch (error) {
    for (const holder of holdersByOperationId.values()) {
      destroyPreparedTargetHolder(holder);
    }
    factorSecret.fill(0);
    throw error;
  }
}

async function createEmailOtpEd25519ExportRootRecipient(
  handleId: string,
): Promise<{ readonly recipientPublicKeyB64u: string }> {
  const slot = keySlots.get(handleId);
  if (!slot) throw new Error('device-linking key handle is unknown or discarded');
  if (slot.emailOtpExportRootRecipient) {
    throw new Error('device-linking Email OTP export-root recipient is already active');
  }
  await initializeNearSignerWasm();
  const recipient = ed25519_yao_client_root_transfer_recipient_v1();
  slot.emailOtpExportRootRecipient = recipient;
  return { recipientPublicKeyB64u: recipient.public_key_b64u() };
}

const EMAIL_OTP_FACTOR_RELEASE_AAD_PREFIX = 'seams/email-otp/factor-release/v1';

async function decryptEmailOtpFactorReleaseEnvelope(input: {
  readonly slot: DeviceLinkingKeySlotV1;
  readonly walletId: string;
  readonly factorRelease: LinkedDeviceEmailOtpFactorReleaseEnvelopeV1;
  readonly expectedChallengeId?: string;
}): Promise<Uint8Array> {
  const release = input.factorRelease;
  if (
    input.expectedChallengeId !== undefined &&
    input.expectedChallengeId !== release.challengeId
  ) {
    throw new Error('Email OTP factor release challenge does not match the submitted challenge');
  }
  let serverPublicKey: Uint8Array | null = null;
  let nonce: Uint8Array | null = null;
  let ciphertext: Uint8Array | null = null;
  let sharedSecret: Uint8Array | null = null;
  let aad: Uint8Array | null = null;
  let factorSecret: Uint8Array | null = null;
  try {
    serverPublicKey = base64UrlDecode(release.serverEphemeralPublicKey65B64u);
    nonce = base64UrlDecode(release.nonce12B64u);
    ciphertext = base64UrlDecode(release.ciphertextB64u);
    const importedServerKey = await globalThis.crypto.subtle.importKey(
      'raw',
      serverPublicKey,
      { name: 'ECDH', namedCurve: 'P-256' },
      false,
      [],
    );
    sharedSecret = new Uint8Array(
      await globalThis.crypto.subtle.deriveBits(
        { name: 'ECDH', public: importedServerKey },
        input.slot.emailOtpReleasePrivateKey,
        256,
      ),
    );
    const aesKey = await globalThis.crypto.subtle.importKey(
      'raw',
      sharedSecret,
      { name: 'AES-GCM' },
      false,
      ['decrypt'],
    );
    aad = new TextEncoder().encode(
      `${EMAIL_OTP_FACTOR_RELEASE_AAD_PREFIX}\0${input.walletId}\0${release.enrollmentId}\0${release.enrollmentSealKeyVersion}\0${release.challengeId}`,
    );
    factorSecret = new Uint8Array(
      await globalThis.crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: 128 },
        aesKey,
        ciphertext,
      ),
    );
    if (factorSecret.length !== 32) {
      throw new Error('Email OTP factor release plaintext must contain exactly 32 bytes');
    }
    const owned = factorSecret;
    factorSecret = null;
    return owned;
  } finally {
    serverPublicKey?.fill(0);
    nonce?.fill(0);
    ciphertext?.fill(0);
    sharedSecret?.fill(0);
    aad?.fill(0);
    factorSecret?.fill(0);
  }
}

async function decryptEmailOtpFactorRelease(input: {
  readonly slot: DeviceLinkingKeySlotV1;
  readonly walletId: string;
  readonly verification: LinkedDeviceEmailOtpVerificationResultV1;
}): Promise<Uint8Array> {
  return await decryptEmailOtpFactorReleaseEnvelope({
    slot: input.slot,
    walletId: input.walletId,
    factorRelease: input.verification.factorRelease,
  });
}

async function assertEmailOtpVerificationMatchesPreparation(input: {
  readonly preparation: EmailOtpTargetPreparationV1;
  readonly verification: LinkedDeviceEmailOtpVerificationResultV1;
}): Promise<DigestB64u> {
  const grant = input.verification.verificationGrant;
  const preparationDigest = await computeLinkedDeviceTargetPreparationDigestV1(input.preparation);
  if (
    grant.linkSessionId !== input.preparation.linkSessionId ||
    grant.walletId !== input.preparation.walletId ||
    grant.enrollmentId !== input.preparation.enrollmentId ||
    grant.deviceId !== input.preparation.deviceId ||
    grant.targetPreparationDigestB64u !== preparationDigest ||
    grant.baseWalletAuthMethodId !== input.preparation.ownerEnrollment.baseWalletAuthMethodId ||
    grant.challengeId !== input.verification.factorRelease.challengeId ||
    grant.expiresAtMs <= Date.now()
  ) {
    throw new Error('Email OTP verification grant does not match target preparation');
  }
  return preparationDigest;
}

async function prepareEmailOtpHolderGroup(input: {
  readonly handleId: string;
  readonly preparation: EmailOtpTargetPreparationV1;
  readonly factor: Extract<WalletCustodyEnvelopeFactor, { readonly kind: 'email_otp' }>;
  readonly factorSecret: Uint8Array;
}): Promise<
  readonly [LinkedDeviceTargetHolderRegistrationV1, ...LinkedDeviceTargetHolderRegistrationV1[]]
> {
  await initializeLaneRecipientWasm();
  const holdersByOperationId = new Map<string, PreparedTargetHolderV1>();
  try {
    const registrations: LinkedDeviceTargetHolderRegistrationV1[] = [];
    const factorBindingId = `${input.factor.enrollmentId}:${input.factor.enrollmentSealKeyVersion}`;
    for (const child of input.preparation.orderedChildren) {
      const operationId = String(child.operationId);
      if (holdersByOperationId.has(operationId)) {
        throw new Error('device-linking target preparation repeats an operation');
      }
      const holder = await createPreparedTargetHolder({
        preparation: input.preparation,
        child,
        factorBindingId,
      });
      holdersByOperationId.set(operationId, holder);
      registrations.push({
        kind: 'linked_device_target_holder_registration_v1',
        operationId: child.operationId,
        walletKeyId: child.walletKeyId,
        keyFamily: child.keyFamily,
        targetLaneId: child.targetLaneId,
        targetLaneShareEpoch: child.targetLaneShareEpoch,
        targetMaterialActivationId: child.targetMaterialActivationId,
        holderParticipant: holder.participant,
      });
    }
    const first = registrations[0];
    if (!first) throw new Error('device-linking target preparation has no holders');
    preparedTargetHolderGroups.set(input.handleId, {
      walletId: input.preparation.walletId,
      factor: input.factor,
      factorSecret: input.factorSecret,
      holdersByOperationId,
    });
    return [first, ...registrations.slice(1)];
  } catch (error) {
    for (const holder of holdersByOperationId.values()) destroyPreparedTargetHolder(holder);
    input.factorSecret.fill(0);
    throw error;
  }
}

function buildEmailOtpActivationState(input: {
  readonly handleId: string;
  readonly preparation: EmailOtpTargetPreparationV1;
  readonly targetPreparationDigestB64u: DigestB64u;
  readonly factorSecret: Uint8Array;
}): DeviceLinkingEmailOtpActivationStateV1 {
  const group = preparedTargetHolderGroups.get(input.handleId);
  if (!group) throw new Error('device-linking Email OTP target holders are not prepared');
  const orderedChildren: EmailOtpActivationPreparedChildV1[] = [];
  for (const child of input.preparation.orderedChildren) {
    const holder = group.holdersByOperationId.get(String(child.operationId));
    if (!holder) {
      throw new Error('device-linking Email OTP target holder preparation changed');
    }
    orderedChildren.push({ child: holder.child, participant: holder.participant });
  }
  const first = orderedChildren[0];
  if (!first) throw new Error('device-linking Email OTP target preparation has no holders');
  return {
    walletId: input.preparation.walletId,
    linkSessionId: input.preparation.linkSessionId,
    enrollmentId: input.preparation.enrollmentId,
    deviceId: input.preparation.deviceId,
    targetPreparationDigestB64u: input.targetPreparationDigestB64u,
    orderedChildren: nonEmptyTupleV1(first, orderedChildren.slice(1)),
    factorSecret: input.factorSecret.slice(),
  };
}

async function prepareEmailOtpTarget(
  request: Extract<
    DeviceLinkingKeyWorkerRequestV1,
    { readonly kind: 'device_linking_email_otp_target_prepare_v1' }
  >,
): Promise<Extract<DeviceLinkingKeyWorkerResponseV1, { readonly emailOtpPrepared: true }>> {
  const slot = keySlots.get(request.handleId);
  if (!slot) throw new Error('device-linking key handle is unknown or discarded');
  if (preparedTargetHolderGroups.has(request.handleId)) {
    throw new Error('device-linking target holders are already prepared');
  }
  if (slot.emailOtpActivation) {
    throw new Error('device-linking Email OTP activation is already prepared');
  }
  if (!isEmailOtpTargetPreparation(request.preparation)) {
    throw new Error('Email OTP preparation requires an Email OTP target preparation');
  }
  const recipient =
    request.exportRoot.kind === 'required' ? slot.emailOtpExportRootRecipient : null;
  if (request.exportRoot.kind === 'required') {
    if (!recipient) {
      throw new Error('device-linking Email OTP export-root recipient is unavailable');
    }
    slot.emailOtpExportRootRecipient = null;
  }
  let factorSecret: Uint8Array | null = null;
  let transferredRoot: ReturnType<
    typeof passkey_custody_open_ed25519_yao_client_root_from_linked_device_v1
  > | null = null;
  try {
    const targetPreparationDigestB64u = await assertEmailOtpVerificationMatchesPreparation({
      preparation: request.preparation,
      verification: request.verification,
    });
    const factor = buildEmailOtpEnvelopeFactor({
      enrollmentId: request.verification.factorRelease.enrollmentId,
      enrollmentSealKeyVersion: request.verification.factorRelease.enrollmentSealKeyVersion,
    });
    if (factor.kind !== 'email_otp') {
      throw new Error('Email OTP envelope factor builder returned the wrong factor kind');
    }
    factorSecret = await decryptEmailOtpFactorRelease({
      slot,
      walletId: String(request.preparation.walletId),
      verification: request.verification,
    });
    const orderedHolderRegistrations = await prepareEmailOtpHolderGroup({
      handleId: request.handleId,
      preparation: request.preparation,
      factor,
      factorSecret,
    });
    let exportRootRequirement:
      | {
          readonly kind: 'required';
          readonly resealedExportRootEnvelope: {
            readonly nonceB64u: string;
            readonly sealedExportRootB64u: string;
            readonly aadHashB64u: string;
            readonly ciphertextDigestB64u: string;
          };
        }
      | { readonly kind: 'not_required' };
    if (request.exportRoot.kind === 'required') {
      if (!recipient) throw new Error('device-linking Email OTP export-root recipient is missing');
      await initializeNearSignerWasm();
      transferredRoot = passkey_custody_open_ed25519_yao_client_root_from_linked_device_v1(
        recipient,
        request.exportRoot.transferBindingJson,
        request.exportRoot.ephemeralPublicKeyB64u,
        base64UrlDecode(request.exportRoot.nonceB64u),
        request.exportRoot.sealedExportRootB64u,
        request.exportRoot.bindingDigestB64u,
        request.exportRoot.ciphertextDigestB64u,
      );
      const resealed = passkey_custody_seal_ed25519_yao_client_root_under_factor_v1(
        transferredRoot,
        factorSecret,
        request.exportRoot.replacementEnvelopeBindingJson,
      ) as Record<string, unknown>;
      exportRootRequirement = {
        kind: 'required',
        resealedExportRootEnvelope: {
          nonceB64u: requireNonEmptyString(resealed.nonceB64u, 'resealed nonceB64u'),
          sealedExportRootB64u: requireNonEmptyString(
            resealed.sealedExportRootB64u,
            'resealed sealedExportRootB64u',
          ),
          aadHashB64u: requireNonEmptyString(
            resealed.aadHashB64u,
            'resealed aadHashB64u',
          ),
          ciphertextDigestB64u: requireNonEmptyString(
            resealed.ciphertextDigestB64u,
            'resealed ciphertextDigestB64u',
          ),
        },
      };
    } else {
      exportRootRequirement = { kind: 'not_required' };
    }
    const response = {
      emailOtpPrepared: true as const,
      orderedHolderRegistrations,
      exportRootRequirement,
    };
    const activation = buildEmailOtpActivationState({
      handleId: request.handleId,
      preparation: request.preparation,
      targetPreparationDigestB64u,
      factorSecret,
    });
    slot.emailOtpActivation = activation;
    return response;
  } catch (error) {
    destroyPreparedTargetHolderGroup(request.handleId);
    throw error;
  } finally {
    transferredRoot?.free();
    recipient?.free();
    if (factorSecret && !preparedTargetHolderGroups.has(request.handleId)) {
      factorSecret.fill(0);
    }
  }
}

function assertDeliveryMatchesPreparedHolder(
  delivery: LinkedDeviceProvisioningChildV1,
  group: PreparedTargetHolderGroupV1,
  holder: PreparedTargetHolderV1,
): void {
  const job = delivery.job;
  const child = holder.child;
  const participant = holder.participant;
  if (
    job.walletId !== group.walletId ||
    job.operationId !== child.operationId ||
    job.walletKeyId !== child.walletKeyId ||
    job.keyFamily !== child.keyFamily ||
    job.target.laneId !== child.targetLaneId ||
    job.target.laneShareEpoch !== child.targetLaneShareEpoch ||
    job.targetMaterialActivationId !== child.targetMaterialActivationId ||
    job.targetHolder.participantId !== participant.participantId ||
    job.targetHolder.custodyBindingId !== participant.custodyBindingId ||
    job.targetHolder.custodyBindingDigestB64u !== participant.custodyBindingDigestB64u ||
    job.targetHolder.hpkePublicKeyB64u !== participant.hpkePublicKeyB64u ||
    job.targetHolder.hpkePublicKeyDigestB64u !== participant.hpkePublicKeyDigestB64u ||
    job.targetHolder.participantBindingDigestB64u !== participant.participantBindingDigestB64u
  ) {
    throw new Error('device-linking holder delivery changed its prepared target identity');
  }
}

function laneCustodyBindingForJob(job: RotatableSigningLaneJobV1): PasskeyCustodySecretBinding {
  if (job.kind === 'ed25519_yao_lane_job_v1') {
    return buildEd25519LaneHolderShareBinding({
      walletKeyId: job.walletKeyId,
      laneId: job.target.laneId,
      laneShareEpoch: job.target.laneShareEpoch,
      nearEd25519SigningKeyId: job.nearEd25519SigningKeyId,
      registeredPublicKeyB64u: parseEd25519PublicKeyB64u(job.registeredPublicKeyB64u),
      participantBindingDigestB64u: job.targetHolder.participantBindingDigestB64u,
    });
  }
  const thresholdSession = job.targetCapability.orderedThresholdSessions[0];
  return buildEcdsaLaneHolderShareBinding({
    walletKeyId: job.walletKeyId,
    laneId: job.target.laneId,
    laneShareEpoch: job.target.laneShareEpoch,
    evmFamilySigningKeySlotId: job.evmFamilySigningKeySlotId,
    thresholdSessionId: thresholdSession.thresholdSessionId,
    thresholdPublicKey33B64u: parseSecp256k1CompressedPublicKeyB64u(job.thresholdPublicKey33B64u),
  });
}

function parseTargetSealOutput(
  value: unknown,
): Extract<DeviceLinkingKeyWorkerResponseV1, { readonly sealedHolderMaterialB64u: string }> {
  const record = exactRecord(
    value,
    [
      'sealedHolderMaterialB64u',
      'sealedHolderRecordDigestB64u',
      'verifiedHolderCiphertextDigestSetB64u',
    ],
    'device-linking target holder seal output',
  );
  return {
    sealedHolderMaterialB64u: requireNonEmptyString(
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

function openAndSealTargetHolder(
  request: Extract<
    DeviceLinkingKeyWorkerRequestV1,
    { readonly kind: 'device_linking_target_holder_open_seal_v1' }
  >,
): Extract<DeviceLinkingKeyWorkerResponseV1, { readonly sealedHolderMaterialB64u: string }> {
  const group = preparedTargetHolderGroups.get(request.handleId);
  if (!group) throw new Error('device-linking target holders are not prepared');
  const operationId = String(request.delivery.job.operationId);
  const holder = group.holdersByOperationId.get(operationId);
  if (!holder) throw new Error('device-linking target holder is unknown or consumed');
  assertDeliveryMatchesPreparedHolder(request.delivery, group, holder);
  const envelopeBinding = {
    walletId: group.walletId,
    envelopeId: holder.participant.custodyBindingId,
    factor: group.factor,
    envelopeRevision: 1,
    binding: laneCustodyBindingForJob(request.delivery.job),
  };
  const custody = new WasmLaneCustodySealV1(
    group.factor.kind,
    group.factorSecret,
    JSON.stringify(envelopeBinding),
    String(holder.participant.custodyBindingId),
    String(holder.participant.custodyBindingDigestB64u),
  );
  const nonce = secureRandomBytes(12, 'linked-device lane custody seal');
  group.holdersByOperationId.delete(operationId);
  try {
    return parseTargetSealOutput(
      holder.recipient.open_and_seal(
        custody,
        JSON.stringify(request.delivery.job),
        JSON.stringify(request.delivery.protocolCommitReceipt),
        JSON.stringify(request.delivery.holderPackage),
        nonce,
      ),
    );
  } finally {
    nonce.fill(0);
    custody.free();
    destroyPreparedTargetHolder(holder);
    if (group.holdersByOperationId.size === 0) {
      preparedTargetHolderGroups.delete(request.handleId);
      group.factorSecret.fill(0);
    }
  }
}

async function handleRequest(
  rawRequest: unknown,
  signingMaterialFactory: DeviceLinkingHolderSigningMaterialFactoryV1,
): Promise<DeviceLinkingKeyWorkerResponseV1 | undefined> {
  const request = parseRequest(rawRequest);
  switch (request.kind) {
    case 'device_linking_key_material_create_v1': {
      const generated = await generateKeySlot();
      keySlots.set(generated.result.handleId, generated.slot);
      return generated.result;
    }
    case 'device_linking_email_otp_export_root_recipient_create_v1':
      return await createEmailOtpEd25519ExportRootRecipient(request.handleId);
    case 'device_linking_target_holders_prepare_v1':
      return await prepareTargetHolders(request);
    case 'device_linking_email_otp_target_prepare_v1':
      return await prepareEmailOtpTarget(request);
    case 'device_linking_target_holder_open_seal_v1':
      return openAndSealTargetHolder(request);
    case 'device_linking_request_sign_v1':
      return await signRequest(request);
    case 'device_linking_holder_signing_material_open_v1':
      return await openPersistedHolderSigningMaterial(request, signingMaterialFactory);
    case 'device_linking_email_otp_holder_signing_material_batch_open_v1':
      return await openPersistedEmailOtpHolderSigningMaterials(request, signingMaterialFactory);
    case 'device_linking_email_otp_factor_release_holder_signing_material_batch_open_v1':
      return await openPersistedEmailOtpHolderSigningMaterialsFromFactorRelease(
        request,
        signingMaterialFactory,
      );
    case 'device_linking_holder_ed25519_sign_v1':
      return createEd25519HolderSigningShare(request);
    case 'device_linking_holder_signing_material_discard_v1':
      discardHolderSigningMaterial(request.handleId);
      return undefined;
    case 'device_linking_key_material_discard_v1':
      discardKeyMaterialSlot(request.handleId);
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
  signingMaterialFactory: DeviceLinkingHolderSigningMaterialFactoryV1 = productionHolderSigningMaterialFactory,
): InstalledDeviceLinkingKeyWorkerV1 {
  let closed = false;
  let queue: Promise<void> = Promise.resolve();
  const onMessage = (event: MessageEvent): void => {
    if (isAttachLinkedHolderToPresignPort(event.data)) {
      attachLinkedHolderPresignPort(event.data.port);
      return;
    }
    queue = queue
      .catch(() => undefined)
      .then(async () => {
        if (closed) return;
        let id: string | undefined;
        try {
          const frame = parseFrame(event.data);
          id = frame.id;
          const result = await handleRequest(frame.request, signingMaterialFactory);
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
          linkedHolderPresignPort?.close();
          linkedHolderPresignPort = null;
          linkedHolderOpaquePresignAuthority.close();
          for (const handleId of preparedTargetHolderGroups.keys()) {
            destroyPreparedTargetHolderGroup(handleId);
          }
          for (const slot of keySlots.values()) {
            destroyEmailOtpActivation(slot);
            slot.emailOtpExportRootRecipient?.free();
            slot.emailOtpExportRootRecipient = null;
          }
          keySlots.clear();
          for (const handleId of holderSigningMaterialSlots.keys()) {
            discardHolderSigningMaterial(handleId);
          }
        });
      await queue;
    },
  };
}

if (typeof self !== 'undefined') {
  installDeviceLinkingKeyWorkerV1(self);
}
