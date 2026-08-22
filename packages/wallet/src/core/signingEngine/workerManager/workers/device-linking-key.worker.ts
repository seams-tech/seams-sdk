import {
  parseRouterAbEcdsaSigningWorkerExportShareEnvelopeV1,
  type RouterAbEcdsaSigningWorkerExportShareBindingV1,
  type RouterAbEcdsaSigningWorkerExportShareEnvelopeV1,
} from '@shared/utils/routerAbEcdsaDerivation';
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
  parseMpcMaterialActivationRef,
  parseWalletAuthMethodId,
  parseWalletId,
  type MpcMaterialActivationRef,
  type WalletAuthMethodId,
  type WalletId,
} from '@shared/utils/domainIds';
import { routerAbMpcMaterialActivationRefFromWire } from '@shared/utils/routerAbNormalSigningIdentity';
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
import initNearSigner, {
  ed25519_yao_client_root_transfer_recipient_v1,
  type WasmEd25519YaoClientRootTransferRecipientV1,
} from '../../../../../../../wasm/near_signer/pkg/wasm_signer_worker.js';
import {
  parseLaneProtocolCommitReceiptV1,
  parseRotatableSigningLaneJobV1,
} from '@shared/signing-lanes/rotationParsers';
import {
  parseLaneSealedHolderRecordV1,
  type LaneSealedHolderRecordV1,
} from '@/core/indexedDB/seamsWalletDB/laneHolderMaterialStore';
import type { WalletAuthoritySignerMaterialRecordV1 } from '@/core/indexedDB';
import {
  isAttachLinkedHolderToPresignPort,
  type OpaqueEcdsaPresignAuthorityRequestV1,
  type OpaqueEcdsaPresignAuthorityResponseV1,
} from '../ecdsaClientWorkerChannels';
import { parseEcdsaClientPresignPoolIdentity } from '../ecdsaPresignPoolIdentity';
import initEd25519YaoClient, {
  WasmLaneHolderRecipientV1,
  WasmLaneHolderSigningMaterialV1,
  WasmOrdinaryEd25519ActivationClientMaterialV1,
} from '../../../../../../../crates/router-ab-ed25519-yao-client/pkg/router_ab_ed25519_yao_client.js';
import initEcdsaClient, {
  RouterAbEcdsaClientCeremonyV1,
  type WasmOrdinaryEcdsaClientMaterialV1,
} from '../../../../../../../wasm/router_ab_ecdsa_client/pkg/router_ab_ecdsa_client.js';
import { resolveWasmUrl } from '@/core/walletRuntimePaths/wasm-loader';
import {
  OpaqueEcdsaPresignAuthorityV1,
  type OpaqueEcdsaPresignSessionV1,
} from './opaqueEcdsaPresignAuthority';
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
      readonly kind: 'device_linking_holder_signing_material_open_v1';
      readonly factorSecret: ArrayBuffer;
      readonly job: RotatableSigningLaneJobV1;
      readonly protocolCommitReceipt: LaneProtocolCommitReceiptV1;
      readonly materialActivation: MpcMaterialActivationRef;
      readonly holderRecord: LaneSealedHolderRecordV1;
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
      readonly kind: 'device_linking_holder_ecdsa_export_recipient_prepare_v1';
      readonly handleId: string;
      readonly operationId: string;
    }
  | {
      readonly kind: 'device_linking_holder_ecdsa_export_finalize_v1';
      readonly handleId: string;
      readonly recipientHandleId: string;
      readonly signingWorkerExport: RouterAbEcdsaSigningWorkerExportShareEnvelopeV1;
      readonly expectedBinding: RouterAbEcdsaSigningWorkerExportShareBindingV1;
      readonly expectedPublicFacts: DeviceLinkingEcdsaExportPublicFactsV1;
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

type DeviceLinkingEcdsaExportPublicFactsV1 = {
  readonly walletId: string;
  readonly walletKeyId: string;
  readonly enrollmentId: string;
  readonly operationId: string;
  readonly laneId: string;
  readonly laneShareEpoch: string;
  readonly targetMaterialActivationId: string;
  readonly ecdsaThresholdKeyId: string;
  readonly thresholdPublicKey33B64u: string;
  readonly evmAddress: string;
  readonly targetHolderPublicCommitment33B64u: string;
  readonly targetServerPublicCommitment33B64u: string;
  readonly publicIdentityDigestB64u: string;
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
  | {
      readonly recipientHandleId: string;
      readonly recipientIdentity: string;
      readonly recipientPublicKeyB64u: string;
    }
  | {
      readonly publicKeyHex: string;
      readonly privateKeyHex: string;
      readonly ethereumAddress: string;
    }
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
  finalize_ecdsa_export(
    recipient: WasmLaneHolderRecipientV1,
    signingWorkerExportJson: string,
    expectedBindingJson: string,
    expectedPublicFactsJson: string,
  ): string;
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

const keySlots = new Map<string, DeviceLinkingKeySlotV1>();
const holderSigningMaterialSlots = new Map<string, DeviceLinkingHolderSigningMaterialSlotV1>();
type PreparedEcdsaExportRecipientV1 = {
  readonly holderHandleId: string;
  readonly recipient: WasmLaneHolderRecipientV1;
};
const preparedEcdsaExportRecipients = new Map<string, PreparedEcdsaExportRecipientV1>();
let linkedHolderPresignPort: MessagePort | null = null;
const linkedHolderOpaquePresignAuthority = new OpaqueEcdsaPresignAuthorityV1();
const laneRecipientWasmUrl = resolveWasmUrl(
  'router_ab_ed25519_yao_client_bg.wasm',
  'Ed25519 Yao Client',
);
let laneRecipientInitPromise: Promise<void> | null = null;
const ordinaryEcdsaWasmUrl = resolveWasmUrl(
  'router_ab_ecdsa_client_bg.wasm',
  'ECDSA derivation client',
);
let ordinaryEcdsaInitPromise: Promise<void> | null = null;
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

async function initializeOrdinaryEcdsaWasm(): Promise<void> {
  if (!ordinaryEcdsaInitPromise) {
    ordinaryEcdsaInitPromise = initEcdsaClient({ module_or_path: ordinaryEcdsaWasmUrl }).then(
      () => undefined,
      (error: unknown) => {
        ordinaryEcdsaInitPromise = null;
        throw error;
      },
    );
  }
  return await ordinaryEcdsaInitPromise;
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
  if (preparation.kind === 'ordinary_ed25519_signer_material_reservation_preparation_v1') {
    if (!committed.signerPackages.ed25519) {
      throw new Error('ordinary Ed25519 signer package is missing');
    }
    return { keyFamily: 'ed25519', package: committed.signerPackages.ed25519 };
  }
  if (!committed.signerPackages.ecdsa) {
    throw new Error('ordinary ECDSA signer package is missing');
  }
  return { keyFamily: 'ecdsa_secp256k1', package: committed.signerPackages.ecdsa };
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
    preparation.kind === 'ordinary_ed25519_signer_material_reservation_preparation_v1'
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
    input.preparation.kind === 'ordinary_ed25519_signer_material_reservation_preparation_v1' &&
    input.packageValue.keyFamily === 'ed25519' &&
    input.recipientInput.kind === 'ordinary_ed25519_signer_material_recipient_input_v1'
  ) {
    await initializeLaneRecipientWasm();
    const recipientPrivateKey = new Uint8Array(input.recipientInput.recipientPrivateKey);
    let material: WasmOrdinaryEd25519ActivationClientMaterialV1 | null = null;
    try {
      material = new WasmOrdinaryEd25519ActivationClientMaterialV1(
        JSON.stringify(input.preparation.activationRequest),
        JSON.stringify(input.packageValue.package.deriver_a_client_package),
        JSON.stringify(input.packageValue.package.deriver_b_client_package),
        recipientPrivateKey,
      );
      return new Uint8Array(material.take_client_material());
    } finally {
      recipientPrivateKey.fill(0);
      material?.destroy();
      material?.free();
    }
  }
  if (
    input.preparation.kind === 'ordinary_ecdsa_signer_material_reservation_preparation_v1' &&
    input.packageValue.keyFamily === 'ecdsa_secp256k1' &&
    input.recipientInput.kind === 'ordinary_ecdsa_signer_material_recipient_input_v1'
  ) {
    await initializeOrdinaryEcdsaWasm();
    const recipientPrivateKey = new Uint8Array(input.recipientInput.clientEphemeralPrivateKey);
    let ceremony: RouterAbEcdsaClientCeremonyV1 | null = null;
    let material: WasmOrdinaryEcdsaClientMaterialV1 | null = null;
    try {
      ceremony = RouterAbEcdsaClientCeremonyV1.fromRecipientPrivateKey(recipientPrivateKey);
      material = ceremony.open_committed_role_envelopes(
        JSON.stringify({
          registrationRequest: input.preparation.registrationRequest,
          materialActivationId: input.packageValue.package.materialActivation.activationId,
          deriverAClientPackage: input.packageValue.package.deriver_a_client_package,
          deriverBClientPackage: input.packageValue.package.deriver_b_client_package,
        }),
      );
      if (material.activation_id() !== input.packageValue.package.materialActivation.activationId) {
        throw new Error('ECDSA ordinary signer material activation id changed');
      }
      return new Uint8Array(material.take_client_material());
    } finally {
      recipientPrivateKey.fill(0);
      material?.destroy();
      material?.free();
      ceremony?.close();
      ceremony?.free();
    }
  }
  throw new Error('ordinary signer material preparation and package family differ');
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

function createHolderSigningMaterialHandleId(): string {
  if (!globalThis.crypto || typeof globalThis.crypto.getRandomValues !== 'function') {
    throw new Error('secure randomness is unavailable for linked holder material');
  }
  const bytes = globalThis.crypto.getRandomValues(new Uint8Array(24));
  const handleId = `linked-holder-signing-${base64UrlEncode(bytes)}`;
  bytes.fill(0);
  return handleId;
}

function createEcdsaExportRecipientHandleId(): string {
  const bytes = secureRandomBytes(24, 'linked holder ECDSA export recipient');
  const handleId = `linked-holder-ecdsa-export-${base64UrlEncode(bytes)}`;
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
  if (record.kind === 'device_linking_holder_ecdsa_export_recipient_prepare_v1') {
    const parsed = exactRecord(
      record,
      ['kind', 'handleId', 'operationId'],
      'device-linking ECDSA export recipient prepare request',
    );
    return {
      kind: 'device_linking_holder_ecdsa_export_recipient_prepare_v1',
      handleId: parseHandleId(parsed.handleId),
      operationId: requireNonEmptyString(parsed.operationId, 'operationId'),
    };
  }
  if (record.kind === 'device_linking_holder_ecdsa_export_finalize_v1') {
    const parsed = exactRecord(
      record,
      [
        'kind',
        'handleId',
        'recipientHandleId',
        'signingWorkerExport',
        'expectedBinding',
        'expectedPublicFacts',
      ],
      'device-linking ECDSA export finalize request',
    );
    const signingWorkerExport = parseRouterAbEcdsaSigningWorkerExportShareEnvelopeV1(
      parsed.signingWorkerExport,
    );
    if (JSON.stringify(parsed.expectedBinding) !== JSON.stringify(signingWorkerExport.binding)) {
      throw new Error('device-linking ECDSA export binding does not match its envelope');
    }
    return {
      kind: 'device_linking_holder_ecdsa_export_finalize_v1',
      handleId: parseHandleId(parsed.handleId),
      recipientHandleId: parseHandleId(parsed.recipientHandleId),
      signingWorkerExport,
      expectedBinding: signingWorkerExport.binding,
      expectedPublicFacts: parseEcdsaExportPublicFacts(parsed.expectedPublicFacts),
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

function parseEcdsaExportPublicFacts(value: unknown): DeviceLinkingEcdsaExportPublicFactsV1 {
  const record = exactRecord(
    value,
    [
      'walletId',
      'walletKeyId',
      'enrollmentId',
      'operationId',
      'laneId',
      'laneShareEpoch',
      'targetMaterialActivationId',
      'ecdsaThresholdKeyId',
      'thresholdPublicKey33B64u',
      'evmAddress',
      'targetHolderPublicCommitment33B64u',
      'targetServerPublicCommitment33B64u',
      'publicIdentityDigestB64u',
    ],
    'device-linking ECDSA export public facts',
  );
  const evmAddress = requireNonEmptyString(record.evmAddress, 'evmAddress');
  if (!/^0x[0-9a-f]{40}$/.test(evmAddress)) throw new Error('evmAddress is invalid');
  return {
    walletId: requireNonEmptyString(record.walletId, 'walletId'),
    walletKeyId: requireNonEmptyString(record.walletKeyId, 'walletKeyId'),
    enrollmentId: requireNonEmptyString(record.enrollmentId, 'enrollmentId'),
    operationId: requireNonEmptyString(record.operationId, 'operationId'),
    laneId: requireNonEmptyString(record.laneId, 'laneId'),
    laneShareEpoch: requireNonEmptyString(record.laneShareEpoch, 'laneShareEpoch'),
    targetMaterialActivationId: requireNonEmptyString(
      record.targetMaterialActivationId,
      'targetMaterialActivationId',
    ),
    ecdsaThresholdKeyId: requireNonEmptyString(record.ecdsaThresholdKeyId, 'ecdsaThresholdKeyId'),
    thresholdPublicKey33B64u: parseFixedBase64Url(
      record.thresholdPublicKey33B64u,
      33,
      'thresholdPublicKey33B64u',
    ),
    evmAddress,
    targetHolderPublicCommitment33B64u: parseFixedBase64Url(
      record.targetHolderPublicCommitment33B64u,
      33,
      'targetHolderPublicCommitment33B64u',
    ),
    targetServerPublicCommitment33B64u: parseFixedBase64Url(
      record.targetServerPublicCommitment33B64u,
      33,
      'targetServerPublicCommitment33B64u',
    ),
    publicIdentityDigestB64u: parseFixedBase64Url(
      record.publicIdentityDigestB64u,
      32,
      'publicIdentityDigestB64u',
    ),
  };
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

function discardHolderSigningMaterial(handleId: string): void {
  for (const [recipientHandleId, prepared] of preparedEcdsaExportRecipients) {
    if (prepared.holderHandleId !== handleId) continue;
    preparedEcdsaExportRecipients.delete(recipientHandleId);
    prepared.recipient.destroy();
    prepared.recipient.free();
  }
  const slot = holderSigningMaterialSlots.get(handleId);
  if (!slot) return;
  holderSigningMaterialSlots.delete(handleId);
  slot.material.destroy();
  slot.material.free();
}

async function prepareEcdsaExportRecipient(
  request: Extract<
    DeviceLinkingKeyWorkerRequestV1,
    { readonly kind: 'device_linking_holder_ecdsa_export_recipient_prepare_v1' }
  >,
): Promise<{
  readonly recipientHandleId: string;
  readonly recipientIdentity: string;
  readonly recipientPublicKeyB64u: string;
}> {
  const slot = holderSigningMaterialSlots.get(request.handleId);
  if (!slot || slot.job.keyFamily !== 'ecdsa_secp256k1') {
    throw new Error('ECDSA holder signing material is unknown, discarded, or cross-curve');
  }
  await initializeLaneRecipientWasm();
  const recipientKeyMaterial = secureRandomBytes(32, 'linked holder ECDSA export recipient');
  let recipient: WasmLaneHolderRecipientV1 | undefined;
  try {
    recipient = new WasmLaneHolderRecipientV1(request.operationId, recipientKeyMaterial);
    const recipientHandleId = createEcdsaExportRecipientHandleId();
    const recipientPublicKeyB64u = parseFixedBase64Url(
      recipient.hpke_public_key_b64u(),
      32,
      'recipientPublicKeyB64u',
    );
    preparedEcdsaExportRecipients.set(recipientHandleId, {
      holderHandleId: request.handleId,
      recipient,
    });
    recipient = undefined;
    return {
      recipientHandleId,
      recipientIdentity: request.operationId,
      recipientPublicKeyB64u,
    };
  } finally {
    recipientKeyMaterial.fill(0);
    recipient?.destroy();
    recipient?.free();
  }
}

function finalizeEcdsaExport(
  request: Extract<
    DeviceLinkingKeyWorkerRequestV1,
    { readonly kind: 'device_linking_holder_ecdsa_export_finalize_v1' }
  >,
): {
  readonly publicKeyHex: string;
  readonly privateKeyHex: string;
  readonly ethereumAddress: string;
} {
  const slot = holderSigningMaterialSlots.get(request.handleId);
  const prepared = preparedEcdsaExportRecipients.get(request.recipientHandleId);
  if (!slot || slot.job.keyFamily !== 'ecdsa_secp256k1') {
    throw new Error('ECDSA holder signing material is unknown, discarded, or cross-curve');
  }
  if (!prepared || prepared.holderHandleId !== request.handleId) {
    throw new Error('ECDSA export recipient is unknown, consumed, or belongs to another lane');
  }
  preparedEcdsaExportRecipients.delete(request.recipientHandleId);
  try {
    const expectedBinding = encodeEcdsaClientProtocolExportBinding(request.expectedBinding);
    const signingWorkerExport = encodeEcdsaClientProtocolExportEnvelope(
      request.signingWorkerExport,
    );
    const rawArtifact = slot.material.finalize_ecdsa_export(
      prepared.recipient,
      JSON.stringify(signingWorkerExport),
      JSON.stringify(expectedBinding),
      JSON.stringify(request.expectedPublicFacts),
    );
    const artifact = exactRecord(
      JSON.parse(rawArtifact),
      ['publicKeyHex', 'privateKeyHex', 'ethereumAddress'],
      'device-linking ECDSA export artifact',
    );
    const publicKeyHex = requireNonEmptyString(artifact.publicKeyHex, 'publicKeyHex');
    const privateKeyHex = requireNonEmptyString(artifact.privateKeyHex, 'privateKeyHex');
    const ethereumAddress = requireNonEmptyString(artifact.ethereumAddress, 'ethereumAddress');
    if (!/^0x[0-9a-f]{66}$/.test(publicKeyHex)) throw new Error('publicKeyHex is invalid');
    if (!/^0x[0-9a-f]{64}$/.test(privateKeyHex)) throw new Error('privateKeyHex is invalid');
    if (!/^0x[0-9a-f]{40}$/.test(ethereumAddress)) throw new Error('ethereumAddress is invalid');
    return { publicKeyHex, privateKeyHex, ethereumAddress };
  } finally {
    prepared.recipient.destroy();
    prepared.recipient.free();
  }
}

function encodeEcdsaClientProtocolMaterialActivation(
  activation: RouterAbEcdsaSigningWorkerExportShareBindingV1['material_activation'],
): {
  readonly kind: 'mpc_material_activation_ref';
  readonly activationId: string;
  readonly capability: string;
  readonly materialOwner: string;
  readonly keyBinding: string;
  readonly lifecycleBinding: string;
  readonly signingWorker: string;
} {
  return {
    kind: activation.kind,
    activationId: activation.activation_id,
    capability: activation.capability,
    materialOwner: activation.material_owner,
    keyBinding: activation.key_binding,
    lifecycleBinding: activation.lifecycle_binding,
    signingWorker: activation.signing_worker,
  };
}

function encodeEcdsaClientProtocolExportBinding(
  binding: RouterAbEcdsaSigningWorkerExportShareBindingV1,
): object {
  return {
    wallet_id: binding.wallet_id,
    key_handle: binding.key_handle,
    ecdsa_threshold_key_id: binding.ecdsa_threshold_key_id,
    signing_root_id: binding.signing_root_id,
    signing_root_version: binding.signing_root_version,
    activation_epoch: binding.activation_epoch,
    signing_worker_id: binding.signing_worker_id,
    context_binding_b64u: binding.context_binding_b64u,
    threshold_public_key33_b64u: binding.threshold_public_key33_b64u,
    export_request_digest_b64u: binding.export_request_digest_b64u,
    export_authorization_digest_b64u: binding.export_authorization_digest_b64u,
    export_nonce: binding.export_nonce,
    authorization_kind: binding.authorization_kind,
    authorization_id: binding.authorization_id,
    material_activation: encodeEcdsaClientProtocolMaterialActivation(binding.material_activation),
    lifecycle_id: binding.lifecycle_id,
    recipient_identity: binding.recipient_identity,
    recipient_public_key: binding.recipient_public_key,
    expires_at_ms: binding.expires_at_ms,
  };
}

function encodeEcdsaClientProtocolExportEnvelope(
  envelope: RouterAbEcdsaSigningWorkerExportShareEnvelopeV1,
): object {
  return {
    version: envelope.version,
    algorithm: envelope.algorithm,
    binding: encodeEcdsaClientProtocolExportBinding(envelope.binding),
    ciphertext_and_tag: envelope.ciphertext_and_tag,
  };
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
  for (const family of input.committed.signerPackages.keyFamilies) {
    const preparation = input.preparations.find((entry) =>
      family === 'ed25519'
        ? entry.kind === 'ordinary_ed25519_signer_material_reservation_preparation_v1'
        : entry.kind === 'ordinary_ecdsa_signer_material_reservation_preparation_v1',
    );
    const packageValue =
      family === 'ed25519'
        ? input.committed.signerPackages.ed25519
        : input.committed.signerPackages.ecdsa;
    if (!preparation || !packageValue) {
      throw new Error(`ordinary signer material ${family} preparation is missing`);
    }
    const activation =
      preparation.kind === 'ordinary_ed25519_signer_material_reservation_preparation_v1'
        ? routerAbMpcMaterialActivationRefFromWire(
            preparation.activationRequest.binding.material_activation,
          )
        : preparation.materialActivation;
    if (!mpcMaterialActivationRefsEqual(activation, packageValue.materialActivation)) {
      throw new Error(`ordinary signer material ${family} activation reference changed`);
    }
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
  signingMaterialFactory: DeviceLinkingHolderSigningMaterialFactoryV1,
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
    case 'device_linking_holder_signing_material_open_v1':
      return await openPersistedHolderSigningMaterial(request, signingMaterialFactory);
    case 'device_linking_email_otp_factor_release_open_v1':
      return await openEmailOtpFactorRelease(request);
    case 'device_linking_holder_ed25519_sign_v1':
      return createEd25519HolderSigningShare(request);
    case 'device_linking_holder_ecdsa_export_recipient_prepare_v1':
      return await prepareEcdsaExportRecipient(request);
    case 'device_linking_holder_ecdsa_export_finalize_v1':
      return finalizeEcdsaExport(request);
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
  ordinaryMaterialSealer: DeviceLinkingOrdinaryMaterialSealerV1 = productionOrdinaryMaterialSealer,
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
          const result = await handleRequest(
            frame.request,
            signingMaterialFactory,
            ordinaryMaterialSealer,
          );
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
          linkedHolderPresignPort?.close();
          linkedHolderPresignPort = null;
          linkedHolderOpaquePresignAuthority.close();
          for (const slot of keySlots.values()) {
            destroyOrdinaryRecipientPreparation(slot);
            destroyOrdinaryMaterial(slot);
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
