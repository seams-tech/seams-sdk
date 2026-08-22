import {
  encodeLinkedDeviceRequestProofV1,
  LINKED_DEVICE_REQUEST_PROOF_MAX_TTL_MS_V1,
  LINKED_DEVICE_REQUEST_PROOF_NONCE_BYTES_V1,
  LINKED_DEVICE_REQUEST_PROOF_SIGNATURE_BYTES_V1,
  parseLinkDevicePublicKeyB64u,
  parseLinkedDeviceEmailOtpFactorReleaseEnvelopeV1,
  parseLinkedDeviceEmailOtpVerificationGrantV1,
  type LinkedDeviceRequestProofV1,
  type LinkedDeviceEmailOtpFactorReleaseEnvelopeV1,
  type LinkedDeviceEmailOtpVerificationGrantV1,
  type LinkDevicePublicKeyB64u,
  type CommittedAuthorityPackagesV1,
  type CommittedEd25519SignerPackageV1,
  type CommittedEcdsaSignerPackageV1,
  type OrdinarySignerMaterialRecipientRequirementV1,
  type OrdinarySignerMaterialRecipientRequestV1,
} from '@shared/device-linking';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/base64';
import { alphabetizeStringify, sha256Bytes, sha256BytesUtf8 } from '@shared/utils/digests';
import { parseDigestB64u, type DigestB64u } from '@shared/utils/canonicalPrimitives';
import {
  mpcMaterialActivationRefsEqual,
  parseWalletAuthMethodId,
  parseWalletId,
  type MpcMaterialActivationRef,
  type WalletAuthMethodId,
  type WalletId,
} from '@shared/utils/domainIds';
import { routerAbMpcMaterialActivationRefFromWire } from '@shared/utils/routerAbNormalSigningIdentity';
import { parseRouterAbEd25519YaoActivationPublicReceiptV1 } from '@shared/utils/routerAbEd25519Yao';
import {
  parseLinkedDeviceEnrollmentId,
  parseLinkedDeviceId,
  parseLinkDeviceSessionId,
  type LinkedDeviceEnrollmentId,
  type LinkedDeviceId,
  type LinkDeviceSessionId,
} from '@shared/signing-lanes/ids';
import initNearSigner, {
  ed25519_yao_client_root_transfer_recipient_v1,
  type WasmEd25519YaoClientRootTransferRecipientV1,
} from '../../../../../../../wasm/near_signer/pkg/wasm_signer_worker.js';
import type { WalletAuthoritySignerMaterialRecordV1 } from '@/core/indexedDB';
import initEd25519YaoClient, {
  WasmOrdinaryEd25519ActivationClientMaterialV1,
} from '../../../../../../../crates/router-ab-ed25519-yao-client/pkg/router_ab_ed25519_yao_client.js';
import { resolveWasmUrl } from '@/core/walletRuntimePaths/wasm-loader';
import {
  assertOrdinaryExportRootResealingMatchesCommittedV1,
  parseOrdinaryMaterialWorkerPrivateRequestV1,
  parseOrdinaryMaterialWorkerRequestV1,
  type DeviceLinkingOrdinaryMaterialWorkerPrivateRequestV1,
  type DeviceLinkingOrdinarySignerMaterialRecipientInputV1,
  type DeviceLinkingOrdinarySignerMaterialRecipientPreparationV1,
  type DeviceLinkingOrdinarySignerMaterialRecipientInputTupleV1,
  type DeviceLinkingOrdinaryMaterialSealerV1,
  type DeviceLinkingOrdinaryMaterialWorkerRequestV1,
  type DeviceLinkingOrdinaryTargetFactorBindingV1,
  type DeviceLinkingOrdinarySignerMaterialReservationPreparationV1,
  type SealedLocalAuthorityMaterialSetV1,
} from '@/SeamsWeb/operations/devices/deviceLinkingOrdinaryMaterialWorker';

/**
 * The worker is the only owner of these key objects. The browser receives
 * public bytes and an opaque slot id; private CryptoKeys are non-extractable
 * and never appear in a structured-clone message.
 */
type DeviceLinkingKeySlotV1 = {
  readonly identityPrivateKey: CryptoKey;
  readonly linkPrivateKey: CryptoKey;
  readonly devicePublicKeyB64u: LinkDevicePublicKeyB64u;
  readonly linkPublicKeyB64u: LinkDevicePublicKeyB64u;
  readonly emailOtpReleasePrivateKey: CryptoKey;
  readonly emailOtpReleasePublicKey65B64u: string;
  emailOtpFactorReleaseChallengeId: string | null;
  emailOtpExportRootRecipient: WasmEd25519YaoClientRootTransferRecipientV1 | null;
  ordinaryMaterialRecipientPreparation: DeviceLinkingOrdinarySignerMaterialRecipientPreparationStateV1 | null;
  ordinaryMaterial: DeviceLinkingOrdinaryMaterialStateV1 | null;
};

type DeviceLinkingOrdinarySignerMaterialRecipientPreparationStateV1 =
  DeviceLinkingOrdinarySignerMaterialRecipientPreparationV1 & {
    readonly requirements: readonly [
      OrdinarySignerMaterialRecipientRequirementV1,
      ...OrdinarySignerMaterialRecipientRequirementV1[],
    ];
  };

type DeviceLinkingOrdinaryMaterialStateV1 = {
  readonly targetFactor: DeviceLinkingOrdinaryTargetFactorBindingV1;
  readonly preparations: readonly [
    DeviceLinkingOrdinarySignerMaterialReservationPreparationV1,
    ...DeviceLinkingOrdinarySignerMaterialReservationPreparationV1[],
  ];
  readonly recipientInputs: DeviceLinkingOrdinarySignerMaterialRecipientInputTupleV1;
  readonly factorSecret: Uint8Array;
};

type DeviceLinkingKeyWorkerRequestV1 =
  | { readonly kind: 'device_linking_key_material_create_v1' }
  | DeviceLinkingOrdinaryMaterialWorkerRequestV1
  | DeviceLinkingOrdinaryMaterialWorkerPrivateRequestV1
  | {
      readonly kind: 'device_linking_email_otp_export_root_recipient_create_v1';
      readonly handleId: string;
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
      readonly kind: 'device_linking_email_otp_factor_release_open_v1';
      readonly handleId: string;
      readonly walletId: WalletId;
      readonly linkSessionId: LinkDeviceSessionId;
      readonly enrollmentId: LinkedDeviceEnrollmentId;
      readonly deviceId: LinkedDeviceId;
      readonly walletAuthMethodId: WalletAuthMethodId;
      readonly baseWalletAuthMethodId: WalletAuthMethodId;
      readonly targetPreparationDigestB64u: DigestB64u;
      readonly expectedChallengeId: string;
      readonly verificationGrant: LinkedDeviceEmailOtpVerificationGrantV1;
      readonly factorRelease: LinkedDeviceEmailOtpFactorReleaseEnvelopeV1;
    }
  | {
      readonly kind: 'device_linking_key_material_discard_v1';
      readonly handleId: string;
    };

type DeviceLinkingKeyWorkerResponseV1 =
  | SealedLocalAuthorityMaterialSetV1
  | (DeviceLinkingOrdinarySignerMaterialRecipientPreparationV1 & {
      readonly kind: 'device_linking_ordinary_signer_material_recipient_preparation_v1';
    })
  | {
      readonly kind: 'device_linking_ordinary_signer_material_preparation_v1';
      readonly targetFactor: DeviceLinkingOrdinaryTargetFactorBindingV1;
      readonly preparations: readonly [
        DeviceLinkingOrdinarySignerMaterialReservationPreparationV1,
        ...DeviceLinkingOrdinarySignerMaterialReservationPreparationV1[],
      ];
    }
  | {
      readonly kind: 'device_linking_email_otp_factor_release_result_v1';
      readonly verificationGrant: LinkedDeviceEmailOtpVerificationGrantV1;
      readonly factorSecret: ArrayBuffer;
    }
  | {
      readonly handleId: string;
      readonly linkPublicKeyB64u: LinkDevicePublicKeyB64u;
      readonly devicePublicKeyB64u: LinkDevicePublicKeyB64u;
      readonly emailOtpReleasePublicKey65B64u: string;
    }
  | { readonly recipientPublicKeyB64u: string }
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

const keySlots = new Map<string, DeviceLinkingKeySlotV1>();
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

const productionOrdinaryMaterialSealer: DeviceLinkingOrdinaryMaterialSealerV1 = {
  async sealCommittedAuthorityPackagesV1(input) {
    if (input.preparations.length !== input.recipientInputs.length) {
      throw new Error('ordinary material recipient inputs do not match preparations');
    }
    const exportRoot = assertOrdinaryExportRootResealingMatchesCommittedV1({
      committed: input.committed,
      resealedExportRoot: input.resealedExportRoot,
    });
    const signerMaterials: WalletAuthoritySignerMaterialRecordV1[] = [];
    for (const preparation of input.preparations) {
      const packageValue = ordinarySignerPackageForPreparation(input.committed, preparation);
      const recipientInput = ordinaryRecipientInputForPreparation(
        input.preparations,
        input.recipientInputs,
        preparation,
      );
      const material = await openOrdinarySignerMaterial({
        preparation,
        packageValue,
        recipientInput,
      });
      try {
        const sealed = await sealOrdinaryWorkerMaterial({
          factorSecret: input.factorSecret,
          aad: ordinaryMaterialSealAad({
            committed: input.committed,
            targetFactor: input.targetFactor,
            materialActivation: packageValue.package.materialActivation,
            keyFamily: packageValue.keyFamily,
          }),
          material,
        });
        signerMaterials.push({
          kind: 'wallet_authority_signer_material_v1',
          authorityId: input.committed.authority.authorityId,
          walletAuthMethodId: input.committed.authMethod.walletAuthMethodId,
          activationId: packageValue.package.materialActivation.activationId,
          keyFamily: packageValue.keyFamily,
          materialActivation: packageValue.package.materialActivation,
          sealedMaterialB64u: sealed.sealedMaterialB64u,
          sealedMaterialDigestB64u: sealed.sealedMaterialDigestB64u,
        });
      } finally {
        material.fill(0);
      }
    }
    const firstSignerMaterial = signerMaterials[0];
    if (!firstSignerMaterial) throw new Error('ordinary signer material set is empty');
    const installedRecordSetDigestB64u = parseDigestB64u(
      base64UrlEncode(
        await sha256BytesUtf8(
          alphabetizeStringify({
            domain: 'seams/wallet/ordinary-authority-material-set/v1',
            signerMaterials,
            exportRoot,
          }),
        ),
      ),
    );
    return {
      signerMaterials: [firstSignerMaterial, ...signerMaterials.slice(1)],
      exportRoot,
      installedRecordSetDigestB64u,
    };
  },
};

type OrdinarySignerPackageForWorkerV1 =
  | {
      readonly keyFamily: 'ed25519';
      readonly package: CommittedEd25519SignerPackageV1;
    }
  | {
      readonly keyFamily: 'ecdsa_secp256k1';
      readonly package: CommittedEcdsaSignerPackageV1;
    };

function ordinarySignerPackageForPreparation(
  committed: CommittedAuthorityPackagesV1,
  preparation: DeviceLinkingOrdinarySignerMaterialReservationPreparationV1,
): OrdinarySignerPackageForWorkerV1 {
  if ('kind' in preparation) {
    if (!committed.signerPackages.ed25519) {
      throw new Error('ordinary Ed25519 signer package is missing');
    }
    const packageValue = committed.signerPackages.ed25519;
    const activation = preparation.targetMaterialActivation;
    if (!mpcMaterialActivationRefsEqual(activation, packageValue.materialActivation)) {
      throw new Error('ordinary Ed25519 signer package activation reference changed');
    }
    if (
      packageValue.participantIds[0] !== preparation.participantIds[0] ||
      packageValue.participantIds[1] !== preparation.participantIds[1]
    ) {
      throw new Error('ordinary Ed25519 signer package participant ids changed');
    }
    return { keyFamily: 'ed25519', package: packageValue };
  }
  if (!committed.signerPackages.ecdsa) {
    throw new Error('ordinary ECDSA signer package is missing');
  }
  const packageValue = committed.signerPackages.ecdsa;
  assertEcdsaPreparationMatchesPackage(preparation, packageValue);
  return { keyFamily: 'ecdsa_secp256k1', package: packageValue };
}

function ordinaryRecipientInputForPreparation(
  preparations: readonly DeviceLinkingOrdinarySignerMaterialReservationPreparationV1[],
  inputs: readonly DeviceLinkingOrdinarySignerMaterialRecipientInputV1[],
  preparation: DeviceLinkingOrdinarySignerMaterialReservationPreparationV1,
): DeviceLinkingOrdinarySignerMaterialRecipientInputV1 {
  const index = preparations.indexOf(preparation);
  const input = inputs[index];
  if (!input) throw new Error('ordinary signer material recipient input is missing');
  const expectedKind =
    'kind' in preparation
      ? 'ordinary_ed25519_signer_material_recipient_input_v1'
      : 'ordinary_ecdsa_signer_material_recipient_input_v1';
  if (input.kind !== expectedKind) {
    throw new Error('ordinary signer material recipient input family changed');
  }
  return input;
}

async function openOrdinarySignerMaterial(input: {
  readonly preparation: DeviceLinkingOrdinarySignerMaterialReservationPreparationV1;
  readonly packageValue: OrdinarySignerPackageForWorkerV1;
  readonly recipientInput: DeviceLinkingOrdinarySignerMaterialRecipientInputV1;
}): Promise<Uint8Array> {
  if (
    'kind' in input.preparation &&
    input.packageValue.keyFamily === 'ed25519' &&
    input.recipientInput.kind === 'ordinary_ed25519_signer_material_recipient_input_v1'
  ) {
    await initializeLaneRecipientWasm();
    const recipientPrivateKey = new Uint8Array(input.recipientInput.recipientPrivateKey);
    let material: WasmOrdinaryEd25519ActivationClientMaterialV1 | null = null;
    try {
      material = new WasmOrdinaryEd25519ActivationClientMaterialV1(
        JSON.stringify(input.preparation.targetAdmission.binding),
        JSON.stringify(input.packageValue.package.deriver_a_client_package),
        JSON.stringify(input.packageValue.package.deriver_b_client_package),
        recipientPrivateKey,
        JSON.stringify(input.preparation.participantIds),
        JSON.stringify(
          parseRouterAbEd25519YaoActivationPublicReceiptV1(
            input.packageValue.package.activationReceipt,
          ),
        ),
      );
      return new Uint8Array(material.take_client_material());
    } finally {
      recipientPrivateKey.fill(0);
      material?.destroy();
      material?.free();
    }
  }
  if (
    !('kind' in input.preparation) &&
    input.packageValue.keyFamily === 'ecdsa_secp256k1' &&
    input.recipientInput.kind === 'ordinary_ecdsa_signer_material_recipient_input_v1'
  ) {
    const recipientPrivateKey = new Uint8Array(input.recipientInput.clientEphemeralPrivateKey);
    try {
      return await openLinkedDeviceEcdsaTargetClientShare({
        envelope: input.packageValue.package.encryptedTargetClientShare,
        recipientPrivateKey,
      });
    } finally {
      recipientPrivateKey.fill(0);
    }
  }
  throw new Error('ordinary signer material preparation and package family differ');
}

function assertEcdsaPreparationMatchesPackage(
  preparation: Exclude<
    DeviceLinkingOrdinarySignerMaterialReservationPreparationV1,
    { readonly kind: string }
  >,
  packageValue: CommittedEcdsaSignerPackageV1,
): void {
  const binding = packageValue.activationReceipt.binding;
  if (
    preparation.linkSessionId !== binding.linkSessionId ||
    preparation.enrollmentId !== binding.enrollmentId ||
    preparation.sourceAuthorityId !== binding.sourceAuthorityId ||
    !sameEcdsaSourceSignerIdentity(preparation.source, binding.source) ||
    !sameEcdsaTargetRecipientPreparation(preparation.target, binding.target) ||
    !mpcMaterialActivationRefsEqual(preparation.target.activation, packageValue.materialActivation) ||
    packageValue.encryptedTargetClientShare.recipientPublicKeyB64u !==
      preparation.target.clientRecipientPublicKeyB64u
  ) {
    throw new Error('ordinary ECDSA signer package differs from its source preparation');
  }
}

function sameEcdsaSourceSignerIdentity(
  left: Exclude<
    DeviceLinkingOrdinarySignerMaterialReservationPreparationV1,
    { readonly kind: string }
  >['source'],
  right: CommittedEcdsaSignerPackageV1['activationReceipt']['binding']['source'],
): boolean {
  return (
    mpcMaterialActivationRefsEqual(left.activation, right.activation) &&
    left.clientPublicKey33B64u === right.clientPublicKey33B64u &&
    left.relayerPublicKey33B64u === right.relayerPublicKey33B64u &&
    left.thresholdPublicKey33B64u === right.thresholdPublicKey33B64u &&
    left.thresholdEthereumAddress20B64u === right.thresholdEthereumAddress20B64u
  );
}

function sameEcdsaTargetRecipientPreparation(
  left: Exclude<
    DeviceLinkingOrdinarySignerMaterialReservationPreparationV1,
    { readonly kind: string }
  >['target'],
  right: CommittedEcdsaSignerPackageV1['activationReceipt']['binding']['target'],
): boolean {
  return (
    mpcMaterialActivationRefsEqual(left.activation, right.activation) &&
    String(left.targetDeviceId) === String(right.targetDeviceId) &&
    left.targetFactorVerificationDigestB64u === right.targetFactorVerificationDigestB64u &&
    left.clientRecipientPublicKeyB64u === right.clientRecipientPublicKeyB64u &&
    left.signingWorkerRecipientPublicKeyB64u === right.signingWorkerRecipientPublicKeyB64u
  );
}

const LINKED_DEVICE_ECDSA_SOURCE_CONTRIBUTION_HPKE_INFO_V1 =
  new TextEncoder().encode(
    'seams/linked-device/ecdsa-source-contribution/hpke-x25519-hkdf-sha256-aes256gcm/v1',
  );
const HPKE_VERSION_V1 = new TextEncoder().encode('HPKE-v1');
const HPKE_KEM_SUITE_ID_V1 = concatBytes(new TextEncoder().encode('KEM'), uint16Bytes(0x0020));
const HPKE_SUITE_ID_V1 = concatBytes(
  new TextEncoder().encode('HPKE'),
  uint16Bytes(0x0020),
  uint16Bytes(0x0001),
  uint16Bytes(0x0002),
);

async function openLinkedDeviceEcdsaTargetClientShare(input: {
  readonly envelope: CommittedEcdsaSignerPackageV1['encryptedTargetClientShare'];
  readonly recipientPrivateKey: Uint8Array;
}): Promise<Uint8Array> {
  if (input.recipientPrivateKey.length !== 32) {
    throw new Error('ECDSA client recipient private key must be 32 bytes');
  }
  const encappedKey = base64UrlDecode(input.envelope.encappedKeyB64u);
  const recipientPublicKey = base64UrlDecode(input.envelope.recipientPublicKeyB64u);
  const bindingDigest = base64UrlDecode(input.envelope.bindingDigestB64u);
  const ciphertext = base64UrlDecode(input.envelope.ciphertextB64u);
  let privatePkcs8: Uint8Array | null = null;
  let sharedSecret: Uint8Array | null = null;
  let kemSharedSecret: Uint8Array | null = null;
  let secret: Uint8Array | null = null;
  let key: CryptoKey | null = null;
  try {
    privatePkcs8 = x25519PrivateKeyPkcs8(input.recipientPrivateKey);
    const privateKey = await globalThis.crypto.subtle.importKey(
      'pkcs8',
      privatePkcs8,
      { name: 'X25519' },
      false,
      ['deriveBits'],
    );
    const encappedPublicKey = await globalThis.crypto.subtle.importKey(
      'raw',
      encappedKey,
      { name: 'X25519' },
      false,
      [],
    );
    sharedSecret = new Uint8Array(
      await globalThis.crypto.subtle.deriveBits(
        { name: 'X25519', public: encappedPublicKey },
        privateKey,
        256,
      ),
    );
    const kemContext = concatBytes(encappedKey, recipientPublicKey);
    const eaePrk = await hpkeLabeledExtract(
      HPKE_KEM_SUITE_ID_V1,
      'eae_prk',
      sharedSecret,
    );
    kemSharedSecret = await hpkeLabeledExpand(
      HPKE_KEM_SUITE_ID_V1,
      eaePrk,
      'shared_secret',
      kemContext,
      32,
    );
    const pskIdHash = await hpkeLabeledExtract(HPKE_SUITE_ID_V1, 'psk_id_hash', new Uint8Array(0));
    const infoHash = await hpkeLabeledExtract(
      HPKE_SUITE_ID_V1,
      'info_hash',
      LINKED_DEVICE_ECDSA_SOURCE_CONTRIBUTION_HPKE_INFO_V1,
    );
    const keyScheduleContext = concatBytes(new Uint8Array([0]), pskIdHash, infoHash);
    secret = await hpkeLabeledExtract(
      HPKE_SUITE_ID_V1,
      'secret',
      new Uint8Array(0),
      kemSharedSecret,
    );
    const encryptionKey = await hpkeLabeledExpand(
      HPKE_SUITE_ID_V1,
      secret,
      'key',
      keyScheduleContext,
      32,
    );
    const baseNonce = await hpkeLabeledExpand(
      HPKE_SUITE_ID_V1,
      secret,
      'base_nonce',
      keyScheduleContext,
      12,
    );
    key = await globalThis.crypto.subtle.importKey(
      'raw',
      encryptionKey,
      { name: 'AES-GCM' },
      false,
      ['decrypt'],
    );
    const plaintext = new Uint8Array(
      await globalThis.crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: baseNonce, additionalData: bindingDigest, tagLength: 128 },
        key,
        ciphertext,
      ),
    );
    if (plaintext.length !== 32) {
      plaintext.fill(0);
      throw new Error('ECDSA target client share must be 32 bytes');
    }
    return plaintext;
  } finally {
    encappedKey.fill(0);
    recipientPublicKey.fill(0);
    bindingDigest.fill(0);
    ciphertext.fill(0);
    privatePkcs8?.fill(0);
    sharedSecret?.fill(0);
    kemSharedSecret?.fill(0);
    secret?.fill(0);
  }
}

async function hpkeLabeledExtract(
  suiteId: Uint8Array,
  label: string,
  input: Uint8Array,
  salt: Uint8Array = new Uint8Array(0),
): Promise<Uint8Array> {
  return await hmacSha256(
    salt.length === 0 ? new Uint8Array(32) : salt,
    concatBytes(HPKE_VERSION_V1, suiteId, new TextEncoder().encode(label), input),
  );
}

async function hpkeLabeledExpand(
  suiteId: Uint8Array,
  prk: Uint8Array,
  label: string,
  info: Uint8Array,
  length: number,
): Promise<Uint8Array> {
  const labeledInfo = concatBytes(
    uint16Bytes(length),
    HPKE_VERSION_V1,
    suiteId,
    new TextEncoder().encode(label),
    info,
  );
  return await hkdfExpand(prk, labeledInfo, length);
}

async function hkdfExpand(prk: Uint8Array, info: Uint8Array, length: number): Promise<Uint8Array> {
  const output = new Uint8Array(length);
  let previous = new Uint8Array(0);
  try {
    for (let counter = 1, offset = 0; offset < length; counter += 1) {
      const block = await hmacSha256(prk, concatBytes(previous, info, new Uint8Array([counter])));
      const copied = Math.min(block.length, length - offset);
      output.set(block.subarray(0, copied), offset);
      offset += copied;
      previous.fill(0);
      previous = block;
    }
    return output;
  } catch (error) {
    output.fill(0);
    throw error;
  } finally {
    previous.fill(0);
  }
}

async function hmacSha256(keyBytes: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  const key = await globalThis.crypto.subtle.importKey(
    'raw',
    keyBytes,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  return new Uint8Array(await globalThis.crypto.subtle.sign('HMAC', key, data));
}

function x25519PrivateKeyPkcs8(privateKey: Uint8Array): Uint8Array {
  return concatBytes(
    Uint8Array.from([
      0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04,
      0x20,
    ]),
    privateKey,
  );
}

function uint16Bytes(value: number): Uint8Array {
  return new Uint8Array([(value >>> 8) & 0xff, value & 0xff]);
}

function concatBytes(...parts: readonly Uint8Array[]): Uint8Array {
  const total = parts.reduce((length, part) => length + part.length, 0);
  const output = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
}

async function sealOrdinaryWorkerMaterial(input: {
  readonly factorSecret: Uint8Array;
  readonly aad: string;
  readonly material: Uint8Array;
}): Promise<{
  readonly sealedMaterialB64u: string;
  readonly sealedMaterialDigestB64u: DigestB64u;
}> {
  if (input.factorSecret.byteLength !== 32 || input.material.byteLength === 0) {
    throw new Error('ordinary signer material sealing inputs are invalid');
  }
  const encoder = new TextEncoder();
  const aad = encoder.encode(input.aad);
  const salt = await sha256Bytes(aad);
  const factorKey = await globalThis.crypto.subtle.importKey(
    'raw',
    input.factorSecret,
    { name: 'HKDF' },
    false,
    ['deriveKey'],
  );
  const sealKey = await globalThis.crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt,
      info: encoder.encode('seams/wallet/ordinary-authority-material-seal/v1'),
    },
    factorKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt'],
  );
  const nonce = secureRandomBytes(12, 'ordinary signer material seal');
  let ciphertext: Uint8Array | null = null;
  try {
    ciphertext = new Uint8Array(
      await globalThis.crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: nonce, additionalData: aad },
        sealKey,
        input.material,
      ),
    );
    const sealed = new Uint8Array(nonce.length + ciphertext.length);
    sealed.set(nonce);
    sealed.set(ciphertext, nonce.length);
    const sealedMaterialB64u = base64UrlEncode(sealed);
    const sealedMaterialDigestB64u = parseDigestB64u(base64UrlEncode(await sha256Bytes(sealed)));
    sealed.fill(0);
    return { sealedMaterialB64u, sealedMaterialDigestB64u };
  } finally {
    nonce.fill(0);
    ciphertext?.fill(0);
    aad.fill(0);
    salt.fill(0);
  }
}

function ordinaryMaterialSealAad(input: {
  readonly committed: CommittedAuthorityPackagesV1;
  readonly targetFactor: DeviceLinkingOrdinaryTargetFactorBindingV1;
  readonly materialActivation: MpcMaterialActivationRef;
  readonly keyFamily: 'ed25519' | 'ecdsa_secp256k1';
}): string {
  return alphabetizeStringify({
    domain: 'seams/wallet/ordinary-authority-material-seal-aad/v1',
    authorityId: String(input.committed.authority.authorityId),
    walletId: String(input.committed.authority.walletId),
    walletAuthMethodId: String(input.committed.authMethod.walletAuthMethodId),
    packageSetDigestB64u: String(input.committed.packageSetDigestB64u),
    targetFactor: input.targetFactor,
    keyFamily: input.keyFamily,
    materialActivation: input.materialActivation,
  });
}

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
  if (record.kind === 'device_linking_ordinary_signer_material_prepare_private_v1') {
    const factorSecret =
      record.factorSecret instanceof ArrayBuffer ? new Uint8Array(record.factorSecret) : null;
    try {
      return parseOrdinaryMaterialWorkerPrivateRequestV1(record);
    } catch (error) {
      factorSecret?.fill(0);
      zeroizeRawOrdinaryRecipientInputs(record.recipientInputs);
      throw error;
    }
  }
  if (
    record.kind === 'device_linking_ordinary_signer_material_recipient_prepare_v1' ||
    record.kind === 'device_linking_ordinary_signer_material_seal_v1'
  ) {
    const factorSecret =
      record.factorSecret instanceof ArrayBuffer ? new Uint8Array(record.factorSecret) : null;
    try {
      return parseOrdinaryMaterialWorkerRequestV1(record);
    } catch (error) {
      factorSecret?.fill(0);
      throw error;
    }
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
  if (record.kind === 'device_linking_request_sign_v1') {
    const parsed = parseSignRequest(record);
    return { kind: 'device_linking_request_sign_v1', ...parsed };
  }
  if (record.kind === 'device_linking_email_otp_factor_release_open_v1') {
    const parsed = exactRecord(
      record,
      [
        'kind',
        'handleId',
        'walletId',
        'linkSessionId',
        'enrollmentId',
        'deviceId',
        'walletAuthMethodId',
        'baseWalletAuthMethodId',
        'targetPreparationDigestB64u',
        'expectedChallengeId',
        'verificationGrant',
        'factorRelease',
      ],
      'device-linking Email OTP factor release open request',
    );
    const walletId = parseWalletId(parsed.walletId);
    if (!walletId.ok) throw new Error(walletId.error.message);
    const linkSessionId = parseLinkDeviceSessionId(parsed.linkSessionId);
    if (!linkSessionId.ok) throw new Error(linkSessionId.error.message);
    const enrollmentId = parseLinkedDeviceEnrollmentId(parsed.enrollmentId);
    if (!enrollmentId.ok) throw new Error(enrollmentId.error.message);
    const deviceId = parseLinkedDeviceId(parsed.deviceId);
    if (!deviceId.ok) throw new Error(deviceId.error.message);
    const walletAuthMethodId = parseWalletAuthMethodId(parsed.walletAuthMethodId);
    if (!walletAuthMethodId.ok) throw new Error(walletAuthMethodId.error.message);
    const baseWalletAuthMethodId = parseWalletAuthMethodId(parsed.baseWalletAuthMethodId);
    if (!baseWalletAuthMethodId.ok) throw new Error(baseWalletAuthMethodId.error.message);
    return {
      kind: 'device_linking_email_otp_factor_release_open_v1',
      handleId: parseHandleId(parsed.handleId),
      walletId: walletId.value,
      linkSessionId: linkSessionId.value,
      enrollmentId: enrollmentId.value,
      deviceId: deviceId.value,
      walletAuthMethodId: walletAuthMethodId.value,
      baseWalletAuthMethodId: baseWalletAuthMethodId.value,
      targetPreparationDigestB64u: parseDigest(
        parsed.targetPreparationDigestB64u,
        'targetPreparationDigestB64u',
      ),
      expectedChallengeId: requireNonEmptyString(parsed.expectedChallengeId, 'expectedChallengeId'),
      verificationGrant: parseLinkedDeviceEmailOtpVerificationGrantV1(parsed.verificationGrant),
      factorRelease: parseLinkedDeviceEmailOtpFactorReleaseEnvelopeV1(parsed.factorRelease),
    };
  }
  throw new Error('device-linking worker request kind is unsupported');
}

function zeroizeRawOrdinaryRecipientInputs(value: unknown): void {
  if (!Array.isArray(value)) return;
  for (const entry of value) {
    if (!isRecord(entry)) continue;
    const privateKey =
      entry.recipientPrivateKey instanceof ArrayBuffer
        ? entry.recipientPrivateKey
        : entry.clientEphemeralPrivateKey instanceof ArrayBuffer
          ? entry.clientEphemeralPrivateKey
          : null;
    if (privateKey) new Uint8Array(privateKey).fill(0);
  }
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
      emailOtpFactorReleaseChallengeId: null,
      emailOtpExportRootRecipient: null,
      ordinaryMaterialRecipientPreparation: null,
      ordinaryMaterial: null,
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

function responseTransferables(
  result: DeviceLinkingKeyWorkerResponseV1 | undefined,
): Transferable[] | undefined {
  if (
    result &&
    'kind' in result &&
    result.kind === 'device_linking_email_otp_factor_release_result_v1'
  ) {
    return [result.factorSecret];
  }
  if (
    result &&
    'kind' in result &&
    result.kind === 'device_linking_ordinary_signer_material_recipient_preparation_v1'
  ) {
    return result.recipientInputs.map((input) =>
      input.kind === 'ordinary_ed25519_signer_material_recipient_input_v1'
        ? input.recipientPrivateKey
        : input.clientEphemeralPrivateKey,
    );
  }
  if (
    result &&
    'warmSessionFactorSecret' in result &&
    result.warmSessionFactorSecret instanceof ArrayBuffer
  ) {
    return [result.warmSessionFactorSecret];
  }
  return undefined;
}

function postWorkerResponse(
  scope: DeviceLinkingKeyWorkerScopeV1,
  message: unknown,
  transfer: Transferable[] | undefined,
): void {
  if (transfer) {
    Reflect.apply(scope.postMessage, scope, [message, transfer]);
    return;
  }
  scope.postMessage(message);
}

async function openEmailOtpFactorRelease(
  request: Extract<
    DeviceLinkingKeyWorkerRequestV1,
    { readonly kind: 'device_linking_email_otp_factor_release_open_v1' }
  >,
): Promise<{
  readonly kind: 'device_linking_email_otp_factor_release_result_v1';
  readonly verificationGrant: LinkedDeviceEmailOtpVerificationGrantV1;
  readonly factorSecret: ArrayBuffer;
}> {
  const slot = keySlots.get(request.handleId);
  if (!slot) throw new Error('device-linking key handle is unknown or discarded');
  assertEmailOtpFactorReleaseBinding(request);
  if (slot.emailOtpFactorReleaseChallengeId !== null) {
    throw new Error('device-linking Email OTP factor release has already been consumed');
  }
  const factorSecret = await decryptEmailOtpFactorReleaseEnvelope({
    slot,
    walletId: String(request.walletId),
    factorRelease: request.factorRelease,
    expectedChallengeId: request.expectedChallengeId,
  });
  slot.emailOtpFactorReleaseChallengeId = request.expectedChallengeId;
  try {
    return {
      kind: 'device_linking_email_otp_factor_release_result_v1',
      verificationGrant: request.verificationGrant,
      factorSecret: factorSecret.slice().buffer,
    };
  } finally {
    factorSecret.fill(0);
  }
}

function assertEmailOtpFactorReleaseBinding(
  request: Extract<
    DeviceLinkingKeyWorkerRequestV1,
    { readonly kind: 'device_linking_email_otp_factor_release_open_v1' }
  >,
): void {
  const grant = request.verificationGrant;
  if (
    String(grant.walletId) !== String(request.walletId) ||
    String(grant.linkSessionId) !== String(request.linkSessionId) ||
    String(grant.enrollmentId) !== String(request.enrollmentId) ||
    String(grant.deviceId) !== String(request.deviceId) ||
    String(grant.baseWalletAuthMethodId) !== String(request.baseWalletAuthMethodId) ||
    grant.targetPreparationDigestB64u !== request.targetPreparationDigestB64u ||
    grant.challengeId !== request.expectedChallengeId ||
    request.factorRelease.challengeId !== request.expectedChallengeId
  ) {
    throw new Error('device-linking Email OTP factor release identity binding changed');
  }
  const nowMs = Date.now();
  if (grant.issuedAtMs > nowMs || grant.expiresAtMs <= nowMs) {
    throw new Error('device-linking Email OTP factor release grant is expired');
  }
}

function discardKeyMaterialSlot(handleId: string): void {
  const slot = keySlots.get(handleId);
  if (slot) {
    destroyOrdinaryRecipientPreparation(slot);
    destroyOrdinaryMaterial(slot);
    slot.emailOtpExportRootRecipient?.free();
    slot.emailOtpExportRootRecipient = null;
  }
  keySlots.delete(handleId);
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

async function createX25519RecipientPair(): Promise<{
  readonly privateKey: Uint8Array;
  readonly publicKey: Uint8Array;
}> {
  const pair = requireCryptoKeyPair(
    await globalThis.crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']),
    'ordinary signer material recipient',
  );
  const publicKey = new Uint8Array(await globalThis.crypto.subtle.exportKey('raw', pair.publicKey));
  const privatePkcs8 = new Uint8Array(
    await globalThis.crypto.subtle.exportKey('pkcs8', pair.privateKey),
  );
  try {
    const privateKey = extractX25519PrivateKey(privatePkcs8);
    return { privateKey, publicKey };
  } finally {
    privatePkcs8.fill(0);
  }
}

function extractX25519PrivateKey(pkcs8: Uint8Array): Uint8Array {
  // RFC 8410's fixed PKCS#8 wrapper for a 32-byte X25519 scalar.
  const prefix = Uint8Array.from([
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20,
  ]);
  if (pkcs8.length !== prefix.length + 32) {
    throw new Error('ordinary signer material recipient private key encoding is invalid');
  }
  for (let index = 0; index < prefix.length; index += 1) {
    if (pkcs8[index] !== prefix[index]) {
      throw new Error('ordinary signer material recipient private key encoding is invalid');
    }
  }
  return pkcs8.slice(prefix.length);
}

function x25519PublicKeyString(publicKey: Uint8Array): string {
  let hex = '';
  for (const byte of publicKey) hex += byte.toString(16).padStart(2, '0');
  return `x25519:${hex}`;
}

async function createOrdinarySignerMaterialRecipientPreparation(
  request: Extract<
    DeviceLinkingKeyWorkerRequestV1,
    { readonly kind: 'device_linking_ordinary_signer_material_recipient_prepare_v1' }
  >,
): Promise<
  DeviceLinkingOrdinarySignerMaterialRecipientPreparationV1 & {
    readonly kind: 'device_linking_ordinary_signer_material_recipient_preparation_v1';
  }
> {
  const slot = keySlots.get(request.handleId);
  if (!slot) throw new Error('device-linking key handle is unknown or discarded');
  const existing = slot.ordinaryMaterialRecipientPreparation;
  if (existing) {
    if (JSON.stringify(existing.requirements) !== JSON.stringify(request.requirements)) {
      throw new Error('ordinary recipient requirements conflict with the existing preparation');
    }
    return cloneOrdinaryRecipientPreparation(existing);
  }
  const recipientRequests: OrdinarySignerMaterialRecipientRequestV1[] = [];
  const recipientInputs: DeviceLinkingOrdinarySignerMaterialRecipientInputV1[] = [];
  try {
    for (const requirement of request.requirements) {
      const pair = await createX25519RecipientPair();
      const privateKey = pair.privateKey.buffer.slice(0);
      if (requirement.keyFamily === 'ed25519') {
        recipientRequests.push({
          kind: 'ordinary_ed25519_signer_material_recipient_request_v1',
          keyFamily: 'ed25519',
          walletKeyId: requirement.walletKeyId,
          recipientPublicKeyB64u: base64UrlEncode(pair.publicKey),
        });
        recipientInputs.push({
          kind: 'ordinary_ed25519_signer_material_recipient_input_v1',
          keyFamily: 'ed25519',
          walletKeyId: requirement.walletKeyId,
          recipientPrivateKey: privateKey,
        });
      } else {
        recipientRequests.push({
          kind: 'ordinary_ecdsa_signer_material_recipient_request_v1',
          keyFamily: 'ecdsa_secp256k1',
          walletKeyId: requirement.walletKeyId,
          clientEphemeralPublicKey: x25519PublicKeyString(pair.publicKey),
        });
        recipientInputs.push({
          kind: 'ordinary_ecdsa_signer_material_recipient_input_v1',
          keyFamily: 'ecdsa_secp256k1',
          walletKeyId: requirement.walletKeyId,
          clientEphemeralPrivateKey: privateKey,
        });
      }
      pair.privateKey.fill(0);
      pair.publicKey.fill(0);
    }
    const firstRequest = recipientRequests[0];
    const firstInput = recipientInputs[0];
    if (!firstRequest || !firstInput) throw new Error('ordinary recipient requirements are empty');
    const state: DeviceLinkingOrdinarySignerMaterialRecipientPreparationStateV1 = {
      requirements: request.requirements,
      recipientRequests: [firstRequest, ...recipientRequests.slice(1)],
      recipientInputs: [firstInput, ...recipientInputs.slice(1)],
    };
    slot.ordinaryMaterialRecipientPreparation = state;
    return cloneOrdinaryRecipientPreparation(state);
  } catch (error) {
    destroyOrdinaryRecipientInputs(recipientInputs);
    throw error;
  }
}

function cloneOrdinaryRecipientPreparation(
  state: DeviceLinkingOrdinarySignerMaterialRecipientPreparationStateV1,
): DeviceLinkingOrdinarySignerMaterialRecipientPreparationV1 & {
  readonly kind: 'device_linking_ordinary_signer_material_recipient_preparation_v1';
} {
  return {
    kind: 'device_linking_ordinary_signer_material_recipient_preparation_v1',
    recipientRequests: state.recipientRequests,
    recipientInputs: cloneOrdinaryRecipientInputTuple(state.recipientInputs),
  };
}

async function prepareOrdinarySignerMaterial(
  request: DeviceLinkingOrdinaryMaterialWorkerPrivateRequestV1,
): Promise<{
  readonly kind: 'device_linking_ordinary_signer_material_preparation_v1';
  readonly targetFactor: DeviceLinkingOrdinaryTargetFactorBindingV1;
  readonly preparations: readonly [
    DeviceLinkingOrdinarySignerMaterialReservationPreparationV1,
    ...DeviceLinkingOrdinarySignerMaterialReservationPreparationV1[],
  ];
}> {
  const slot = keySlots.get(request.handleId);
  if (!slot) {
    new Uint8Array(request.factorSecret).fill(0);
    destroyOrdinaryRecipientInputs(request.recipientInputs);
    throw new Error('device-linking key handle is unknown or discarded');
  }
  const factorSecret = new Uint8Array(request.factorSecret);
  try {
    const recipientPreparation = slot.ordinaryMaterialRecipientPreparation;
    if (!recipientPreparation) {
      throw new Error('ordinary signer material recipient preparation is unavailable');
    }
    assertOrdinaryRecipientPreparationMatchesRequest(recipientPreparation, request);
    const existing = slot.ordinaryMaterial;
    if (existing) {
      if (
        JSON.stringify(existing.targetFactor) !== JSON.stringify(request.targetFactor) ||
        JSON.stringify(existing.preparations) !== JSON.stringify(request.preparations)
      ) {
        throw new Error(
          'ordinary signer material preparation conflicts with the existing activation reference',
        );
      }
      return {
        kind: 'device_linking_ordinary_signer_material_preparation_v1',
        targetFactor: existing.targetFactor,
        preparations: existing.preparations,
      };
    }
    const clonedRecipientInputs = cloneOrdinaryRecipientInputTuple(
      recipientPreparation.recipientInputs,
    );
    slot.ordinaryMaterial = {
      targetFactor: request.targetFactor,
      preparations: request.preparations,
      recipientInputs: clonedRecipientInputs,
      factorSecret,
    };
    return {
      kind: 'device_linking_ordinary_signer_material_preparation_v1',
      targetFactor: request.targetFactor,
      preparations: request.preparations,
    };
  } catch (error) {
    factorSecret.fill(0);
    throw error;
  } finally {
    new Uint8Array(request.factorSecret).fill(0);
    destroyOrdinaryRecipientInputs(request.recipientInputs);
  }
}

function assertOrdinaryRecipientPreparationMatchesRequest(
  prepared: DeviceLinkingOrdinarySignerMaterialRecipientPreparationStateV1,
  request: DeviceLinkingOrdinaryMaterialWorkerPrivateRequestV1,
): void {
  if (JSON.stringify(prepared.recipientRequests) !== JSON.stringify(request.recipientRequests)) {
    throw new Error('ordinary signer material recipient request changed before preparation');
  }
  if (prepared.recipientInputs.length !== request.recipientInputs.length) {
    throw new Error('ordinary signer material recipient input count changed before preparation');
  }
  for (const expected of prepared.recipientInputs) {
    const actual = request.recipientInputs.find(
      (input) =>
        input.keyFamily === expected.keyFamily && input.walletKeyId === expected.walletKeyId,
    );
    if (!actual || !sameBytes(recipientPrivateBytes(expected), recipientPrivateBytes(actual))) {
      throw new Error('ordinary signer material recipient input changed before preparation');
    }
  }
}

function recipientPrivateBytes(
  input: DeviceLinkingOrdinarySignerMaterialRecipientInputV1,
): Uint8Array {
  return new Uint8Array(
    input.kind === 'ordinary_ed25519_signer_material_recipient_input_v1'
      ? input.recipientPrivateKey
      : input.clientEphemeralPrivateKey,
  );
}

function sameBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= left[index]! ^ right[index]!;
  }
  return difference === 0;
}

async function sealCommittedOrdinarySignerMaterial(
  request: Extract<
    DeviceLinkingKeyWorkerRequestV1,
    { readonly kind: 'device_linking_ordinary_signer_material_seal_v1' }
  >,
  sealer: DeviceLinkingOrdinaryMaterialSealerV1,
): Promise<SealedLocalAuthorityMaterialSetV1> {
  const slot = keySlots.get(request.handleId);
  if (!slot) throw new Error('device-linking key handle is unknown or discarded');
  const prepared = slot.ordinaryMaterial;
  if (!prepared) {
    throw new Error('ordinary signer material preparation is unavailable');
  }
  if (JSON.stringify(prepared.targetFactor) !== JSON.stringify(request.targetFactor)) {
    throw new Error('ordinary signer material target factor binding changed');
  }
  assertOrdinaryMaterialCommitMatchesPreparation({
    committed: request.committed,
    preparations: prepared.preparations,
    targetFactor: prepared.targetFactor,
  });
  return await sealer.sealCommittedAuthorityPackagesV1({
    committed: request.committed,
    targetFactor: prepared.targetFactor,
    resealedExportRoot: request.resealedExportRoot,
    preparations: prepared.preparations,
    recipientInputs: prepared.recipientInputs,
    factorSecret: prepared.factorSecret,
  });
}

function assertOrdinaryMaterialCommitMatchesPreparation(input: {
  readonly committed: CommittedAuthorityPackagesV1;
  readonly preparations: readonly [
    DeviceLinkingOrdinarySignerMaterialReservationPreparationV1,
    ...DeviceLinkingOrdinarySignerMaterialReservationPreparationV1[],
  ];
  readonly targetFactor: DeviceLinkingOrdinaryTargetFactorBindingV1;
}): void {
  if (input.committed.authMethod.walletAuthMethodId !== input.targetFactor.walletAuthMethodId) {
    throw new Error('ordinary signer material auth method binding changed');
  }
  if (input.preparations.length !== input.committed.signerPackages.keyFamilies.length) {
    throw new Error('ordinary signer material family count changed before commit');
  }
  for (let index = 0; index < input.committed.signerPackages.keyFamilies.length; index += 1) {
    const family = input.committed.signerPackages.keyFamilies[index];
    const preparation = input.preparations[index];
    if (!preparation) {
      throw new Error(`ordinary signer material ${family} preparation is missing`);
    }
    if (family === 'ed25519') {
      if (!('kind' in preparation) || !input.committed.signerPackages.ed25519) {
        throw new Error('ordinary Ed25519 signer material package family changed');
      }
      const packageValue = input.committed.signerPackages.ed25519;
      if (!mpcMaterialActivationRefsEqual(preparation.targetMaterialActivation, packageValue.materialActivation)) {
        throw new Error('ordinary Ed25519 signer material activation reference changed');
      }
      if (
        packageValue.participantIds[0] !== preparation.participantIds[0] ||
        packageValue.participantIds[1] !== preparation.participantIds[1]
      ) {
        throw new Error('ordinary Ed25519 signer material participant ids changed');
      }
      const receipt = parseRouterAbEd25519YaoActivationPublicReceiptV1(
        packageValue.activationReceipt,
      );
      const receiptActivation = routerAbMpcMaterialActivationRefFromWire(
        receipt.material_activation,
      );
      if (!mpcMaterialActivationRefsEqual(receiptActivation, packageValue.materialActivation)) {
        throw new Error('ordinary Ed25519 activation receipt reference changed');
      }
      continue;
    }
    if ('kind' in preparation || !input.committed.signerPackages.ecdsa) {
      throw new Error('ordinary ECDSA signer material package family changed');
    }
    assertEcdsaPreparationMatchesPackage(
      preparation,
      input.committed.signerPackages.ecdsa,
    );
  }
}

function destroyOrdinaryMaterial(slot: DeviceLinkingKeySlotV1): void {
  slot.ordinaryMaterial?.factorSecret.fill(0);
  if (slot.ordinaryMaterial) {
    destroyOrdinaryRecipientInputs(slot.ordinaryMaterial.recipientInputs);
  }
  slot.ordinaryMaterial = null;
}

function destroyOrdinaryRecipientPreparation(slot: DeviceLinkingKeySlotV1): void {
  if (!slot.ordinaryMaterialRecipientPreparation) return;
  destroyOrdinaryRecipientInputs(slot.ordinaryMaterialRecipientPreparation.recipientInputs);
  slot.ordinaryMaterialRecipientPreparation = null;
}

function cloneOrdinaryRecipientInput(
  input: DeviceLinkingOrdinarySignerMaterialRecipientInputV1,
): DeviceLinkingOrdinarySignerMaterialRecipientInputV1 {
  if (input.kind === 'ordinary_ed25519_signer_material_recipient_input_v1') {
    return {
      kind: input.kind,
      keyFamily: input.keyFamily,
      walletKeyId: input.walletKeyId,
      recipientPrivateKey: input.recipientPrivateKey.slice(0),
    };
  }
  return {
    kind: input.kind,
    keyFamily: input.keyFamily,
    walletKeyId: input.walletKeyId,
    clientEphemeralPrivateKey: input.clientEphemeralPrivateKey.slice(0),
  };
}

function cloneOrdinaryRecipientInputTuple(
  inputs: readonly DeviceLinkingOrdinarySignerMaterialRecipientInputV1[],
): DeviceLinkingOrdinarySignerMaterialRecipientInputTupleV1 {
  const cloned = inputs.map(cloneOrdinaryRecipientInput);
  const first = cloned[0];
  if (!first) throw new Error('ordinary signer material recipient inputs are empty');
  return [first, ...cloned.slice(1)];
}

function destroyOrdinaryRecipientInputs(
  inputs: readonly DeviceLinkingOrdinarySignerMaterialRecipientInputV1[],
): void {
  for (const input of inputs) {
    if (input.kind === 'ordinary_ed25519_signer_material_recipient_input_v1') {
      new Uint8Array(input.recipientPrivateKey).fill(0);
    } else {
      new Uint8Array(input.clientEphemeralPrivateKey).fill(0);
    }
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
  readonly expectedChallengeId: string;
}): Promise<Uint8Array> {
  const release = input.factorRelease;
  if (input.expectedChallengeId !== release.challengeId) {
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

async function handleRequest(
  rawRequest: unknown,
  ordinaryMaterialSealer: DeviceLinkingOrdinaryMaterialSealerV1,
): Promise<DeviceLinkingKeyWorkerResponseV1 | undefined> {
  const request = parseRequest(rawRequest);
  switch (request.kind) {
    case 'device_linking_key_material_create_v1': {
      const generated = await generateKeySlot();
      keySlots.set(generated.result.handleId, generated.slot);
      return generated.result;
    }
    case 'device_linking_ordinary_signer_material_recipient_prepare_v1':
      return await createOrdinarySignerMaterialRecipientPreparation(request);
    case 'device_linking_ordinary_signer_material_prepare_private_v1':
      return await prepareOrdinarySignerMaterial(request);
    case 'device_linking_ordinary_signer_material_seal_v1':
      return await sealCommittedOrdinarySignerMaterial(request, ordinaryMaterialSealer);
    case 'device_linking_email_otp_export_root_recipient_create_v1':
      return await createEmailOtpEd25519ExportRootRecipient(request.handleId);
    case 'device_linking_request_sign_v1':
      return await signRequest(request);
    case 'device_linking_email_otp_factor_release_open_v1':
      return await openEmailOtpFactorRelease(request);
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
  ordinaryMaterialSealer: DeviceLinkingOrdinaryMaterialSealerV1 = productionOrdinaryMaterialSealer,
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
          const result = await handleRequest(frame.request, ordinaryMaterialSealer);
          if (closed) return;
          postWorkerResponse(scope, { id, ok: true, result }, responseTransferables(result));
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
          for (const slot of keySlots.values()) {
            destroyOrdinaryRecipientPreparation(slot);
            destroyOrdinaryMaterial(slot);
            slot.emailOtpExportRootRecipient?.free();
            slot.emailOtpExportRootRecipient = null;
          }
          keySlots.clear();
        });
      await queue;
    },
  };
}

if (typeof self !== 'undefined') {
  installDeviceLinkingKeyWorkerV1(self);
}
