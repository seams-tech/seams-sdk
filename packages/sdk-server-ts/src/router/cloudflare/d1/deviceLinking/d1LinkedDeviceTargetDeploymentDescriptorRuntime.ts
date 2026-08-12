import type {
  LinkedDeviceTargetDeploymentDescriptorRequestV1,
  LinkedDeviceTargetDeploymentDescriptorSignerV1,
  LinkedDeviceTargetDeploymentDescriptorVerifierV1,
  LinkedDeviceTargetDeploymentDescriptorSigningKeyId,
  LinkedDeviceTargetDeploymentDescriptorV1,
} from '@shared/device-linking/targetDeploymentDescriptor';
import type {
  EcdsaTargetCapabilityBindingV1,
  LaneTargetSigningWorkerV1,
} from '@shared/signing-lanes/rotation';
import { parseEcdsaTargetCapabilityBindingV1 } from '@shared/signing-lanes/rotationParsers';
import { buildSigningWorkerParticipantRecordWithDigestV1 } from '@shared/signing-lanes/participantDigest';
import {
  buildSigningWorkerRecipientIdentityV1,
  parseHpkePublicKeyB64u,
  parseLaneParticipantBindingDigestB64u,
  parseSigningWorkerParticipantId,
  parseSigningWorkerRecipientKeyDigestB64u,
  parseSigningWorkerRecipientKeyId,
} from '@shared/signing-lanes/participants';
import {
  parseEd25519YaoSuiteId,
  parseWalletKeyId,
  type ThresholdEcdsaChainTarget,
} from '@shared/signing-lanes/ids';
import { parseThresholdEcdsaSessionId } from '@shared/utils/domainIds';
import type { DigestB64u } from '@shared/utils/canonicalPrimitives';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/base64';
import { sha256Bytes } from '@shared/utils/digests';
import type { D1DatabaseLike } from '../../../../storage/tenantRoute';
import type { D1LinkedDeviceSessionScopeV1 } from './d1LinkedDeviceSessionStore';
import {
  D1LinkedDeviceTargetDeploymentDescriptorProviderV1,
  type LinkedDeviceTargetDeploymentDescriptorProviderV1,
  type LinkedDeviceTargetEcdsaCapabilityAllocatorV1,
} from './d1LinkedDeviceTargetDeploymentDescriptorProvider';
import { D1WalletStore } from '../../../../core/d1WalletStore';
import type { WalletEcdsaSignerRecord } from '../../../../core/WalletStore';
import { deriveEvmFamilySigningKeySlotId } from '@shared/signing-lanes/evmFamilySigningKeySlotId';

const DESCRIPTOR_SIGNING_KEY_ID =
  'linked-device-target-deployment-descriptor-hmac-sha512-v1' as LinkedDeviceTargetDeploymentDescriptorSigningKeyId;
const HMAC_SHA512_BYTES = 64;
const MIN_DESCRIPTOR_SECRET_BYTES = 32;

export type LinkedDeviceTargetSigningWorkerConfigV1 = {
  readonly participantId: string;
  readonly participantBindingDigestB64u: string;
  readonly recipientKeyId: string;
  readonly hpkePublicKeyB64u: string;
  readonly hpkePublicKeyDigestB64u: string;
};

export type D1LinkedDeviceTargetDeploymentDescriptorRuntimeOptionsV1 = {
  readonly database: D1DatabaseLike;
  readonly scope: D1LinkedDeviceSessionScopeV1;
  readonly targetSigningWorker: LinkedDeviceTargetSigningWorkerConfigV1;
  readonly descriptorHmacSecret: string;
  readonly ed25519: {
    readonly yaoSuiteId: string;
    readonly circuitDigestB64u: string;
  };
  /** Test and alternate storage adapters may supply the same authoritative read port. */
  readonly ecdsaSource?: LinkedDeviceEcdsaSourceReaderV1;
};

export type LinkedDeviceEcdsaSourceReaderV1 = {
  listEcdsaSignersForWallet(input: {
    readonly walletId: string;
  }): Promise<readonly WalletEcdsaSignerRecord[]>;
};

export type D1LinkedDeviceTargetDeploymentDescriptorRuntimeV1 = {
  readonly targetSigningWorker: LaneTargetSigningWorkerV1;
  readonly descriptorSigner: LinkedDeviceTargetDeploymentDescriptorSignerV1;
  readonly descriptorVerifier: LinkedDeviceTargetDeploymentDescriptorVerifierV1;
  readonly ecdsaCapabilityAllocator: LinkedDeviceTargetEcdsaCapabilityAllocatorV1;
  readonly provider: LinkedDeviceTargetDeploymentDescriptorProviderV1;
};

export async function createD1LinkedDeviceTargetDeploymentDescriptorRuntimeV1(
  options: D1LinkedDeviceTargetDeploymentDescriptorRuntimeOptionsV1,
): Promise<D1LinkedDeviceTargetDeploymentDescriptorRuntimeV1> {
  const targetSigningWorker = await assertLinkedDeviceTargetSigningWorkerBindingV1(
    buildLinkedDeviceTargetSigningWorkerV1(options.targetSigningWorker),
  );
  const descriptorSigner = createLinkedDeviceTargetDeploymentDescriptorSignerV1({
    descriptorHmacSecret: options.descriptorHmacSecret,
  });
  const descriptorVerifier = createLinkedDeviceTargetDeploymentDescriptorVerifierV1({
    descriptorHmacSecret: options.descriptorHmacSecret,
  });
  const source =
    options.ecdsaSource ??
    new D1WalletStore({
      database: options.database,
      namespace: options.scope.namespace,
      orgId: options.scope.orgId,
      projectId: options.scope.projectId,
      envId: options.scope.envId,
    });
  const ecdsaCapabilityAllocator = new D1LinkedDeviceEcdsaTargetCapabilityAllocatorV1({
    source,
    targetSigningWorker,
    descriptorHmacSecret: options.descriptorHmacSecret,
  });
  const provider = new D1LinkedDeviceTargetDeploymentDescriptorProviderV1({
    database: options.database,
    scope: options.scope,
    targetSigningWorker,
    descriptorSigner,
    descriptorVerifier,
    ecdsaCapabilityAllocator,
    ed25519: {
      yaoSuiteId: parseRequired(parseEd25519YaoSuiteId(options.ed25519.yaoSuiteId), 'yaoSuiteId'),
      circuitDigestB64u: parseDigestB64u(options.ed25519.circuitDigestB64u),
    },
  });
  return {
    targetSigningWorker,
    descriptorSigner,
    descriptorVerifier,
    ecdsaCapabilityAllocator,
    provider,
  };
}

export function createLinkedDeviceTargetDeploymentDescriptorSignerV1(input: {
  readonly descriptorHmacSecret: string;
}): LinkedDeviceTargetDeploymentDescriptorSignerV1 {
  const secret = normalizeDescriptorHmacSecret(input.descriptorHmacSecret);
  return new HmacLinkedDeviceTargetDeploymentDescriptorSignerV1(secret);
}

export function createLinkedDeviceTargetDeploymentDescriptorVerifierV1(input: {
  readonly descriptorHmacSecret: string;
}): LinkedDeviceTargetDeploymentDescriptorVerifierV1 {
  const secret = normalizeDescriptorHmacSecret(input.descriptorHmacSecret);
  return new HmacLinkedDeviceTargetDeploymentDescriptorVerifierV1(secret);
}

export class D1LinkedDeviceEcdsaTargetCapabilityAllocatorV1 implements LinkedDeviceTargetEcdsaCapabilityAllocatorV1 {
  private readonly source: LinkedDeviceEcdsaSourceReaderV1;
  private readonly targetSigningWorker: LaneTargetSigningWorkerV1;
  private readonly descriptorHmacSecret: string;

  constructor(input: {
    readonly source: LinkedDeviceEcdsaSourceReaderV1;
    readonly targetSigningWorker: LaneTargetSigningWorkerV1;
    readonly descriptorHmacSecret: string;
  }) {
    this.source = input.source;
    this.targetSigningWorker = input.targetSigningWorker;
    this.descriptorHmacSecret = normalizeDescriptorHmacSecret(input.descriptorHmacSecret);
  }

  async allocateEcdsaTargetCapabilityV1(input: {
    readonly request: Extract<
      LinkedDeviceTargetDeploymentDescriptorRequestV1,
      { readonly keyFamily: 'ecdsa_secp256k1' }
    >;
    readonly issuedAtMs: number;
    readonly expiresAtMs: number;
  }): Promise<EcdsaTargetCapabilityBindingV1> {
    const sourceSigners = await this.source.listEcdsaSignersForWallet({
      walletId: String(input.request.walletId),
    });
    const matchingSigners = sourceSigners.filter(
      (signer) => walletKeyIdForEcdsaSigner(signer) === String(input.request.walletKeyId),
    );
    if (matchingSigners.length === 0) {
      throw new Error('authoritative ECDSA wallet key is unavailable for target descriptor');
    }
    const source = requireConsistentEcdsaWalletKey(matchingSigners);
    const orderedSigners = [...matchingSigners].sort((left, right) =>
      left.chainTargetKey.localeCompare(right.chainTargetKey),
    );
    const manifestId = await deriveTargetManifestIdV1({
      secret: this.descriptorHmacSecret,
      request: input.request,
      ecdsaThresholdKeyId: String(source.walletKey.ecdsaThresholdKeyId),
      targetParticipantBindingDigestB64u: String(
        this.targetSigningWorker.participantBindingDigestB64u,
      ),
    });
    const orderedThresholdSessions = await Promise.all(
      orderedSigners.map((signer) =>
        deriveTargetThresholdSessionV1({
          secret: this.descriptorHmacSecret,
          request: input.request,
          chainTargetKey: signer.chainTargetKey,
          chainTarget: normalizeThresholdEcdsaChainTarget(signer.chainTarget),
          ecdsaThresholdKeyId: String(source.walletKey.ecdsaThresholdKeyId),
          targetParticipantBindingDigestB64u: String(
            this.targetSigningWorker.participantBindingDigestB64u,
          ),
        }),
      ),
    );
    const capability = parseEcdsaTargetCapabilityBindingV1(
      {
        manifestId,
        manifestRevision: 1,
        ecdsaThresholdKeyId: source.walletKey.ecdsaThresholdKeyId,
        orderedThresholdSessions,
      },
      'target ECDSA capability',
    );
    return capability;
  }
}

class HmacLinkedDeviceTargetDeploymentDescriptorSignerV1 implements LinkedDeviceTargetDeploymentDescriptorSignerV1 {
  readonly signingKeyId = DESCRIPTOR_SIGNING_KEY_ID;
  private readonly secret: string;

  constructor(secret: string) {
    this.secret = secret;
  }

  async signTargetDeploymentDescriptorV1(input: {
    readonly encodedPayload: Uint8Array;
    readonly descriptorDigestB64u: DigestB64u;
    readonly request: LinkedDeviceTargetDeploymentDescriptorRequestV1;
  }): Promise<string> {
    await assertDescriptorPayloadDigestV1(input.encodedPayload, input.descriptorDigestB64u);
    return await hmacSha512B64u(this.secret, input.encodedPayload);
  }
}

class HmacLinkedDeviceTargetDeploymentDescriptorVerifierV1 implements LinkedDeviceTargetDeploymentDescriptorVerifierV1 {
  private readonly secret: string;

  constructor(secret: string) {
    this.secret = secret;
  }

  async verifyTargetDeploymentDescriptorV1(input: {
    readonly descriptor: import('@shared/device-linking/targetDeploymentDescriptor').LinkedDeviceTargetDeploymentDescriptorV1;
    readonly encodedPayload: Uint8Array;
    readonly descriptorDigestB64u: DigestB64u;
  }): Promise<boolean> {
    if (input.descriptor.signingKeyId !== DESCRIPTOR_SIGNING_KEY_ID) return false;
    if (input.descriptor.descriptorDigestB64u !== input.descriptorDigestB64u) return false;
    try {
      await assertDescriptorPayloadDigestV1(input.encodedPayload, input.descriptorDigestB64u);
      const signature = parseHmacSignature(input.descriptor.signatureB64u);
      const key = await importHmacKey(this.secret, ['verify']);
      return await crypto.subtle.verify(
        { name: 'HMAC' },
        key,
        toArrayBuffer(signature),
        toArrayBuffer(input.encodedPayload),
      );
    } catch {
      return false;
    }
  }
}

export function buildLinkedDeviceTargetSigningWorkerV1(
  input: LinkedDeviceTargetSigningWorkerConfigV1,
): LaneTargetSigningWorkerV1 {
  const participantId = parseRequired(
    parseSigningWorkerParticipantId(input.participantId),
    'targetSigningWorker.participantId',
  );
  const recipientKeyId = parseRequired(
    parseSigningWorkerRecipientKeyId(input.recipientKeyId),
    'targetSigningWorker.recipientKeyId',
  );
  const hpkePublicKeyB64u = parseRequired(
    parseHpkePublicKeyB64u(input.hpkePublicKeyB64u),
    'targetSigningWorker.hpkePublicKeyB64u',
  );
  const hpkePublicKeyDigestB64u = parseRequired(
    parseSigningWorkerRecipientKeyDigestB64u(input.hpkePublicKeyDigestB64u),
    'targetSigningWorker.hpkePublicKeyDigestB64u',
  );
  const participantBindingDigestB64u = parseRequired(
    parseLaneParticipantBindingDigestB64u(input.participantBindingDigestB64u),
    'targetSigningWorker.participantBindingDigestB64u',
  );
  const record = {
    participantId,
    participantBindingDigestB64u,
    ...buildSigningWorkerRecipientIdentityV1({
      recipientKeyId,
      hpkePublicKeyB64u,
      hpkePublicKeyDigestB64u,
    }),
  };
  return {
    participantId: record.participantId,
    participantBindingDigestB64u: record.participantBindingDigestB64u,
    recipientKeyId: record.recipientKeyId,
    hpkePublicKeyB64u: record.hpkePublicKeyB64u,
    hpkePublicKeyDigestB64u: record.hpkePublicKeyDigestB64u,
  };
}

/** Validates config-bound worker digests when the deployment loader can await WebCrypto. */
export async function assertLinkedDeviceTargetSigningWorkerBindingV1(
  worker: LaneTargetSigningWorkerV1,
): Promise<LaneTargetSigningWorkerV1> {
  const hpkeDigest = parseDigestB64u(
    base64UrlEncode(await sha256Bytes(base64UrlDecode(worker.hpkePublicKeyB64u))),
  );
  if (hpkeDigest !== worker.hpkePublicKeyDigestB64u) {
    throw new Error('targetSigningWorker.hpkePublicKeyDigestB64u does not match its key');
  }
  const computed = await buildSigningWorkerParticipantRecordWithDigestV1({
    participantId: worker.participantId,
    recipient: buildSigningWorkerRecipientIdentityV1({
      recipientKeyId: worker.recipientKeyId,
      hpkePublicKeyB64u: worker.hpkePublicKeyB64u,
      hpkePublicKeyDigestB64u: worker.hpkePublicKeyDigestB64u,
    }),
  });
  if (computed.participantBindingDigestB64u !== worker.participantBindingDigestB64u) {
    throw new Error('targetSigningWorker.participantBindingDigestB64u does not match its binding');
  }
  return worker;
}

function walletKeyIdForEcdsaSigner(signer: WalletEcdsaSignerRecord): string {
  const slot = deriveEvmFamilySigningKeySlotId({
    walletId: signer.walletId,
    signingRootId: signer.walletKey.signingRootId,
    signingRootVersion: signer.walletKey.signingRootVersion,
  });
  return String(
    parseRequired(parseWalletKeyId(`wallet-key:ecdsa:${signer.walletId}:${slot}`), 'wallet key id'),
  );
}

function normalizeThresholdEcdsaChainTarget(
  target: WalletEcdsaSignerRecord['chainTarget'],
): ThresholdEcdsaChainTarget {
  if (!target.networkSlug) {
    throw new Error('authoritative ECDSA chain target is missing networkSlug');
  }
  return {
    ...target,
    networkSlug: target.networkSlug,
  };
}

function requireConsistentEcdsaWalletKey(
  signers: readonly WalletEcdsaSignerRecord[],
): WalletEcdsaSignerRecord {
  const first = signers[0];
  if (!first) throw new Error('ECDSA wallet key signer set is empty');
  for (const signer of signers.slice(1)) {
    if (
      signer.walletKey.keyHandle !== first.walletKey.keyHandle ||
      signer.walletKey.ecdsaThresholdKeyId !== first.walletKey.ecdsaThresholdKeyId ||
      signer.walletKey.signingRootId !== first.walletKey.signingRootId ||
      signer.walletKey.signingRootVersion !== first.walletKey.signingRootVersion ||
      signer.walletKey.publicCapability.material_activation.activation_id !==
        first.walletKey.publicCapability.material_activation.activation_id
    ) {
      throw new Error('ECDSA wallet key signer records disagree on authoritative aggregation');
    }
  }
  return first;
}

async function deriveTargetManifestIdV1(input: {
  readonly secret: string;
  readonly request: Extract<
    LinkedDeviceTargetDeploymentDescriptorRequestV1,
    { readonly keyFamily: 'ecdsa_secp256k1' }
  >;
  readonly ecdsaThresholdKeyId: string;
  readonly targetParticipantBindingDigestB64u: string;
}): Promise<string> {
  const context = [
    'seams/linked-device/target-ecdsa-manifest/v1',
    String(input.request.linkSessionId),
    String(input.request.walletId),
    String(input.request.walletKeyId),
    String(input.request.enrollmentId),
    String(input.request.deviceId),
    String(input.request.operationId),
    String(input.request.childIndex),
    String(input.request.targetLaneId),
    String(input.request.targetLaneShareEpoch),
    String(input.request.targetMaterialActivationId),
    input.request.targetPreparationDigestB64u,
    input.request.registrationDigestB64u,
    input.request.credentialIdB64u,
    input.ecdsaThresholdKeyId,
    input.targetParticipantBindingDigestB64u,
  ].join('\u0000');
  const digest = await hmacSha512(input.secret, context);
  return `linked-device-target-ecdsa-manifest:${base64UrlEncode(digest.slice(0, 24))}`;
}

async function deriveTargetThresholdSessionV1(input: {
  readonly secret: string;
  readonly request: Extract<
    LinkedDeviceTargetDeploymentDescriptorRequestV1,
    { readonly keyFamily: 'ecdsa_secp256k1' }
  >;
  readonly chainTargetKey: string;
  readonly chainTarget: ThresholdEcdsaChainTarget;
  readonly ecdsaThresholdKeyId: string;
  readonly targetParticipantBindingDigestB64u: string;
}): Promise<EcdsaTargetCapabilityBindingV1['orderedThresholdSessions'][number]> {
  const context = [
    'seams/linked-device/target-ecdsa-threshold-session/v1',
    String(input.request.linkSessionId),
    String(input.request.walletId),
    String(input.request.walletKeyId),
    String(input.request.operationId),
    String(input.request.childIndex),
    input.request.targetPreparationDigestB64u,
    input.request.registrationDigestB64u,
    input.chainTargetKey,
    input.ecdsaThresholdKeyId,
    input.targetParticipantBindingDigestB64u,
  ].join('\u0000');
  const digest = await hmacSha512(input.secret, context);
  const thresholdSessionId = parseRequired(
    parseThresholdEcdsaSessionId(
      `linked-device-target-ecdsa-session:${base64UrlEncode(digest.slice(0, 24))}`,
    ),
    'target ECDSA threshold session id',
  );
  return {
    chainTarget: input.chainTarget,
    thresholdSessionId,
    participantBindingDigestB64u: parseDigestB64u(input.targetParticipantBindingDigestB64u),
  };
}

async function assertDescriptorPayloadDigestV1(
  encodedPayload: Uint8Array,
  descriptorDigestB64u: DigestB64u,
): Promise<void> {
  const expected = parseDigestB64u(base64UrlEncode(await sha256Bytes(encodedPayload)));
  if (expected !== descriptorDigestB64u) {
    throw new Error('target deployment descriptor payload digest is invalid');
  }
}

async function hmacSha512B64u(secret: string, payload: Uint8Array): Promise<string> {
  return base64UrlEncode(await hmacSha512Bytes(secret, payload));
}

async function hmacSha512(secret: string, context: string): Promise<Uint8Array> {
  return hmacSha512Bytes(secret, new TextEncoder().encode(context));
}

async function hmacSha512Bytes(secret: string, payload: Uint8Array): Promise<Uint8Array> {
  const key = await importHmacKey(secret, ['sign']);
  const mac = await crypto.subtle.sign('HMAC', key, toArrayBuffer(payload));
  const bytes = new Uint8Array(mac);
  if (bytes.length !== HMAC_SHA512_BYTES) throw new Error('descriptor HMAC has an invalid length');
  return bytes;
}

async function importHmacKey(
  secret: string,
  usages: readonly ('sign' | 'verify')[],
): Promise<CryptoKey> {
  if (typeof crypto === 'undefined' || !crypto.subtle) {
    throw new Error('WebCrypto (crypto.subtle) is unavailable for target descriptor HMAC');
  }
  return await crypto.subtle.importKey(
    'raw',
    toArrayBuffer(new TextEncoder().encode(secret)),
    { name: 'HMAC', hash: 'SHA-512' },
    false,
    [...usages],
  );
}

function parseHmacSignature(raw: string): Uint8Array {
  const signature = base64UrlDecode(raw);
  if (signature.length !== HMAC_SHA512_BYTES || base64UrlEncode(signature) !== raw) {
    throw new Error('target deployment descriptor signature is invalid');
  }
  return signature;
}

function normalizeDescriptorHmacSecret(raw: string): string {
  if (typeof raw !== 'string' || raw.trim() !== raw || raw.length === 0) {
    throw new Error('descriptorHmacSecret is required');
  }
  if (new TextEncoder().encode(raw).length < MIN_DESCRIPTOR_SECRET_BYTES) {
    throw new Error('descriptorHmacSecret must be at least 32 UTF-8 bytes');
  }
  return raw;
}

function parseRequired<T>(
  result:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
  label: string,
): T {
  if (result.ok) return result.value;
  throw new Error(`${label}: ${result.error.message}`);
}

function toArrayBuffer(value: Uint8Array): ArrayBuffer {
  return value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength) as ArrayBuffer;
}
