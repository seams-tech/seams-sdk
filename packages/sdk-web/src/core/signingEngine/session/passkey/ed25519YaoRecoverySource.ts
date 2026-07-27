import { inferNearChainIdKey } from '@/core/accountData/near/accountRefs';
import type { AccountKeyMaterialStorePort } from '@/core/indexedDB/accountKeyMaterial';
import { buildEnvelopeAAD, KEY_PAYLOAD_ENC_VERSION } from '@/core/indexedDB/keyMaterialEnvelope';
import type { KeyMaterialRecord } from '@/core/indexedDB/keyMaterial.types';
import type { AccountId } from '@/core/types/accountIds';
import type { RouterAbEd25519YaoActivationEntropyV1 } from '@/core/signingEngine/threshold/ed25519/yaoClient';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/base64';
import { alphabetizeStringify, sha256BytesUtf8 } from '@shared/utils/digests';
import { parseMpcMaterialOwnerRef, type MpcMaterialOwnerRef } from '@shared/utils/domainIds';
import type { RouterAbEd25519YaoRecoveryAdmissionRequestV1 } from '@shared/utils/routerAbEd25519Yao';
import {
  parseWalletAuthAuthorityRef,
  type WalletAuthAuthorityRef,
} from '@shared/utils/walletAuthAuthority';

export const ED25519_YAO_RECOVERY_SOURCE_KEY_KIND =
  'router_ab_ed25519_yao_recovery_source_v1' as const;

const RECOVERY_SOURCE_SCHEMA_VERSION = 1;
const RECOVERY_SOURCE_ALGORITHM = 'aes-256-gcm-hkdf-sha256-prf-v1';
const RECOVERY_SOURCE_AAD_KIND = 'near_ed25519_yao_recovery_source_aad_v1';
const RECOVERY_SOURCE_HKDF_INFO = 'seams/near-ed25519-yao/recovery-source/v1';
const ACTIVATION_ENTROPY_BYTES = 96;
const SECRET_BYTES = 32;
const AES_GCM_IV_BYTES = 12;

export type Ed25519YaoRecoverySourceBindingV1 = {
  kind: typeof RECOVERY_SOURCE_AAD_KIND;
  recoveryId: string;
  admissionRequestDigestB64u: string;
  authority: WalletAuthAuthorityRef;
  materialOwner: MpcMaterialOwnerRef;
};

export type Ed25519YaoRecoverySourceIdentityV1 = {
  walletId: string;
  nearAccountId: AccountId;
  nearEd25519SigningKeyId: string;
  signerSlot: number;
  operationalPublicKey: string;
  authority: WalletAuthAuthorityRef;
  materialOwner: MpcMaterialOwnerRef;
};

export type Ed25519YaoRecoverySourceStorePort = AccountKeyMaterialStorePort;

export type Ed25519YaoRecoverySourceLocatorV1 = {
  kind: typeof ED25519_YAO_RECOVERY_SOURCE_KEY_KIND;
  profileId: string;
  signerSlot: number;
  chainIdKey: string;
  recoveryId: string;
};

function requireNonEmptyString(value: unknown, label: string): string {
  const parsed = typeof value === 'string' ? value.trim() : '';
  if (!parsed) throw new Error(`${label} is required`);
  return parsed;
}

function requireRecord(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function requireOwnedPrfSecret(secret: Uint8Array): Uint8Array {
  if (secret.byteLength !== SECRET_BYTES) {
    throw new Error('Passkey PRF first output must contain exactly 32 bytes');
  }
  return secret;
}

function toArrayBufferCopy(bytes: Uint8Array): ArrayBuffer {
  const output = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(output).set(bytes);
  return output;
}

function encodeBinding(binding: Ed25519YaoRecoverySourceBindingV1): Uint8Array {
  return new TextEncoder().encode(alphabetizeStringify(binding));
}

async function admissionRequestDigestB64u(
  request: RouterAbEd25519YaoRecoveryAdmissionRequestV1,
): Promise<string> {
  return base64UrlEncode(await sha256BytesUtf8(alphabetizeStringify(request)));
}

async function buildRecoverySourceBinding(input: {
  request: RouterAbEd25519YaoRecoveryAdmissionRequestV1;
  identity: Ed25519YaoRecoverySourceIdentityV1;
}): Promise<Ed25519YaoRecoverySourceBindingV1> {
  return {
    kind: RECOVERY_SOURCE_AAD_KIND,
    recoveryId: input.request.scope.lifecycle_id,
    admissionRequestDigestB64u: await admissionRequestDigestB64u(input.request),
    authority: input.identity.authority,
    materialOwner: input.identity.materialOwner,
  };
}

async function deriveRecoverySourceKey(
  ownedPasskeyPrfFirst: Uint8Array,
  bindingBytes: Uint8Array,
  usages: readonly KeyUsage[],
): Promise<CryptoKey> {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) throw new Error('WebCrypto is required to seal Ed25519 Yao recovery state');
  const salt = await subtle.digest('SHA-256', toArrayBufferCopy(bindingBytes));
  const hkdfKey = await subtle.importKey(
    'raw',
    toArrayBufferCopy(requireOwnedPrfSecret(ownedPasskeyPrfFirst)),
    'HKDF',
    false,
    ['deriveKey'],
  );
  return subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt,
      info: toArrayBufferCopy(new TextEncoder().encode(RECOVERY_SOURCE_HKDF_INFO)),
    },
    hkdfKey,
    { name: 'AES-GCM', length: 256 },
    false,
    [...usages],
  );
}

function packActivationEntropy(entropy: RouterAbEd25519YaoActivationEntropyV1): Uint8Array {
  if (
    entropy.recipientKeyMaterial.byteLength !== SECRET_BYTES ||
    entropy.deriverASealSeed.byteLength !== SECRET_BYTES ||
    entropy.deriverBSealSeed.byteLength !== SECRET_BYTES
  ) {
    throw new Error('Ed25519 Yao activation entropy must contain three 32-byte secrets');
  }
  const plaintext = new Uint8Array(ACTIVATION_ENTROPY_BYTES);
  plaintext.set(entropy.recipientKeyMaterial, 0);
  plaintext.set(entropy.deriverASealSeed, SECRET_BYTES);
  plaintext.set(entropy.deriverBSealSeed, SECRET_BYTES * 2);
  return plaintext;
}

function unpackActivationEntropy(plaintext: Uint8Array): RouterAbEd25519YaoActivationEntropyV1 {
  if (plaintext.byteLength !== ACTIVATION_ENTROPY_BYTES) {
    throw new Error('Sealed Ed25519 Yao recovery source has invalid plaintext length');
  }
  return {
    recipientKeyMaterial: plaintext.slice(0, SECRET_BYTES),
    deriverASealSeed: plaintext.slice(SECRET_BYTES, SECRET_BYTES * 2),
    deriverBSealSeed: plaintext.slice(SECRET_BYTES * 2, ACTIVATION_ENTROPY_BYTES),
  };
}

function parseStoredBinding(raw: unknown): Ed25519YaoRecoverySourceBindingV1 {
  const record = requireRecord(raw, 'recovery source binding');
  const authority = parseWalletAuthAuthorityRef(record.authority);
  const materialOwner = parseMpcMaterialOwnerRef(record.materialOwner);
  if (
    Object.keys(record).length !== 5 ||
    record.kind !== RECOVERY_SOURCE_AAD_KIND ||
    !authority ||
    !materialOwner.ok
  ) {
    throw new Error('Stored Ed25519 Yao recovery source binding is invalid');
  }
  return {
    kind: RECOVERY_SOURCE_AAD_KIND,
    recoveryId: requireNonEmptyString(record.recoveryId, 'recovery source recoveryId'),
    admissionRequestDigestB64u: requireNonEmptyString(
      record.admissionRequestDigestB64u,
      'recovery source admission request digest',
    ),
    authority,
    materialOwner: materialOwner.value,
  };
}

function recoverySourceCoordinates(identity: Ed25519YaoRecoverySourceIdentityV1): {
  profileId: string;
  chainIdKey: string;
  accountAddress: string;
} {
  return {
    profileId: identity.walletId,
    chainIdKey: inferNearChainIdKey(identity.nearAccountId),
    accountAddress: String(identity.nearAccountId).trim().toLowerCase(),
  };
}

function assertStoredRecoverySource(input: {
  stored: KeyMaterialRecord;
  identity: Ed25519YaoRecoverySourceIdentityV1;
  binding: Ed25519YaoRecoverySourceBindingV1;
}): void {
  const coordinates = recoverySourceCoordinates(input.identity);
  const envelope = input.stored.payloadEnvelope;
  const storedBinding = parseStoredBinding(input.stored.payload?.binding);
  const expectedEnvelopeAad = buildEnvelopeAAD({
    ...coordinates,
    signerSlot: input.identity.signerSlot,
    keyKind: ED25519_YAO_RECOVERY_SOURCE_KEY_KIND,
    schemaVersion: RECOVERY_SOURCE_SCHEMA_VERSION,
    signerId: input.identity.nearEd25519SigningKeyId,
  });
  if (
    input.stored.profileId !== coordinates.profileId ||
    input.stored.signerSlot !== input.identity.signerSlot ||
    input.stored.chainIdKey !== coordinates.chainIdKey ||
    input.stored.accountAddress !== coordinates.accountAddress ||
    input.stored.keyKind !== ED25519_YAO_RECOVERY_SOURCE_KEY_KIND ||
    input.stored.algorithm !== 'ed25519' ||
    input.stored.publicKey !== input.identity.operationalPublicKey ||
    input.stored.signerId !== input.identity.nearEd25519SigningKeyId ||
    input.stored.schemaVersion !== RECOVERY_SOURCE_SCHEMA_VERSION ||
    envelope?.encVersion !== KEY_PAYLOAD_ENC_VERSION ||
    envelope.alg !== RECOVERY_SOURCE_ALGORITHM ||
    alphabetizeStringify(envelope.aad) !== alphabetizeStringify(expectedEnvelopeAad) ||
    alphabetizeStringify(storedBinding) !== alphabetizeStringify(input.binding)
  ) {
    throw new Error('Stored Ed25519 Yao recovery source does not match its exact binding');
  }
}

export async function sealEd25519YaoRecoverySourceV1(input: {
  store: Ed25519YaoRecoverySourceStorePort;
  identity: Ed25519YaoRecoverySourceIdentityV1;
  request: RouterAbEd25519YaoRecoveryAdmissionRequestV1;
  ownedPasskeyPrfFirst: Uint8Array;
  entropy: RouterAbEd25519YaoActivationEntropyV1;
}): Promise<Ed25519YaoRecoverySourceLocatorV1> {
  const binding = await buildRecoverySourceBinding(input);
  const bindingBytes = encodeBinding(binding);
  const key = await deriveRecoverySourceKey(input.ownedPasskeyPrfFirst, bindingBytes, ['encrypt']);
  const iv = new Uint8Array(AES_GCM_IV_BYTES);
  globalThis.crypto.getRandomValues(iv);
  const plaintext = packActivationEntropy(input.entropy);
  let ciphertext: ArrayBuffer;
  try {
    ciphertext = await globalThis.crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: toArrayBufferCopy(iv),
        additionalData: toArrayBufferCopy(bindingBytes),
      },
      key,
      toArrayBufferCopy(plaintext),
    );
  } finally {
    plaintext.fill(0);
  }
  const coordinates = recoverySourceCoordinates(input.identity);
  const record: KeyMaterialRecord = {
    ...coordinates,
    signerSlot: input.identity.signerSlot,
    keyKind: ED25519_YAO_RECOVERY_SOURCE_KEY_KIND,
    algorithm: 'ed25519',
    publicKey: input.identity.operationalPublicKey,
    signerId: input.identity.nearEd25519SigningKeyId,
    payload: { binding },
    payloadEnvelope: {
      encVersion: KEY_PAYLOAD_ENC_VERSION,
      alg: RECOVERY_SOURCE_ALGORITHM,
      nonce: base64UrlEncode(iv),
      ciphertext: base64UrlEncode(ciphertext),
      aad: buildEnvelopeAAD({
        ...coordinates,
        signerSlot: input.identity.signerSlot,
        keyKind: ED25519_YAO_RECOVERY_SOURCE_KEY_KIND,
        schemaVersion: RECOVERY_SOURCE_SCHEMA_VERSION,
        signerId: input.identity.nearEd25519SigningKeyId,
      }),
    },
    timestamp: Date.now(),
    schemaVersion: RECOVERY_SOURCE_SCHEMA_VERSION,
  };
  await input.store.storeKeyMaterial(record);
  return {
    kind: ED25519_YAO_RECOVERY_SOURCE_KEY_KIND,
    profileId: coordinates.profileId,
    signerSlot: input.identity.signerSlot,
    chainIdKey: coordinates.chainIdKey,
    recoveryId: binding.recoveryId,
  };
}

export async function openEd25519YaoRecoverySourceV1(input: {
  store: Ed25519YaoRecoverySourceStorePort;
  identity: Ed25519YaoRecoverySourceIdentityV1;
  request: RouterAbEd25519YaoRecoveryAdmissionRequestV1;
  ownedPasskeyPrfFirst: Uint8Array;
}): Promise<RouterAbEd25519YaoActivationEntropyV1> {
  const coordinates = recoverySourceCoordinates(input.identity);
  const stored = await input.store.getKeyMaterial(
    coordinates.profileId,
    input.identity.signerSlot,
    coordinates.chainIdKey,
    ED25519_YAO_RECOVERY_SOURCE_KEY_KIND,
  );
  if (!stored) throw new Error('Sealed Ed25519 Yao recovery source is unavailable');
  const binding = await buildRecoverySourceBinding(input);
  assertStoredRecoverySource({ stored, identity: input.identity, binding });
  const envelope = stored.payloadEnvelope;
  if (!envelope) throw new Error('Sealed Ed25519 Yao recovery source envelope is unavailable');
  const bindingBytes = encodeBinding(binding);
  const key = await deriveRecoverySourceKey(input.ownedPasskeyPrfFirst, bindingBytes, ['decrypt']);
  const plaintextBuffer = await globalThis.crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: toArrayBufferCopy(base64UrlDecode(envelope.nonce)),
      additionalData: toArrayBufferCopy(bindingBytes),
    },
    key,
    toArrayBufferCopy(base64UrlDecode(envelope.ciphertext)),
  );
  const plaintext = new Uint8Array(plaintextBuffer);
  try {
    return unpackActivationEntropy(plaintext);
  } finally {
    plaintext.fill(0);
  }
}
