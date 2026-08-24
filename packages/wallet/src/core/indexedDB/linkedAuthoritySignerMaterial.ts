import {
  parseLinkedDeviceEcdsaSourcePreservingActivationReceiptV1,
  type CommittedAuthorityPackagesV1,
  type CommittedEcdsaSignerPackageV1,
  type CommittedEd25519SignerPackageV1,
} from '@shared/device-linking';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/base64';
import { alphabetizeStringify, sha256Bytes } from '@shared/utils/digests';
import { parseDigestB64u, type DigestB64u } from '@shared/utils/canonicalPrimitives';
import {
  mpcMaterialActivationRefsEqual,
  parseMpcMaterialActivationRef,
  parseWalletAuthMethodId,
  parseWalletAuthorityId,
  parseWebAuthnCredentialIdB64u,
  parseWebAuthnRpId,
  type MpcMaterialActivationRef,
  type WalletAuthMethodId,
  type WalletAuthorityId,
  type WalletId,
} from '@shared/utils/domainIds';
import {
  parseRouterAbEd25519YaoActivationPublicReceiptV1,
  parseRouterAbEd25519YaoApplicationBindingFactsV1,
  parseRouterAbEd25519YaoCeremonyBindingV1,
  parseRouterAbEd25519YaoParticipantIdsV1,
} from '@shared/utils/routerAbEd25519Yao';
import { routerAbMpcMaterialActivationRefFromWire } from '@shared/utils/routerAbNormalSigningIdentity';
import type {
  WalletAuthorityLinkedMaterialTargetFactorV1,
  WalletAuthorityLinkedSignerMaterialPublicFactsV1,
  WalletAuthorityLinkedSignerMaterialRecordV1,
} from './passkeyClientDB.types';
import { parseEcdsaThresholdKeyId } from '../signingEngine/session/keyMaterialBrands';

export type LinkedSignerPackageForMaterialV1 =
  | {
      readonly keyFamily: 'ed25519';
      readonly package: CommittedEd25519SignerPackageV1;
    }
  | {
      readonly keyFamily: 'ecdsa_secp256k1';
      readonly package: CommittedEcdsaSignerPackageV1;
    };

export type LinkedAuthorityMaterialSealInputV1 = {
  readonly authorityId: WalletAuthorityId;
  readonly walletId: WalletId;
  readonly walletAuthMethodId: WalletAuthMethodId;
  readonly packageSetDigestB64u: DigestB64u;
  readonly targetFactor: WalletAuthorityLinkedMaterialTargetFactorV1;
  readonly materialActivation: MpcMaterialActivationRef;
  readonly keyFamily: 'ed25519' | 'ecdsa_secp256k1';
};

export type OpenWalletAuthorityLinkedSignerMaterialInputV1 = {
  readonly record: WalletAuthorityLinkedSignerMaterialRecordV1;
  readonly factorSecret: Uint8Array;
  readonly expected: LinkedAuthorityMaterialSealInputV1;
};

export type OpenWalletAuthorityLinkedSignerMaterialResultV1 =
  | {
      readonly kind: 'opened_wallet_authority_linked_signer_material_v1';
      readonly authorityId: WalletAuthorityId;
      readonly walletAuthMethodId: WalletAuthMethodId;
      readonly keyFamily: 'ed25519';
      readonly materialActivation: MpcMaterialActivationRef;
      readonly publicFacts: Extract<
        WalletAuthorityLinkedSignerMaterialPublicFactsV1,
        { readonly keyFamily: 'ed25519' }
      >;
      readonly material: Uint8Array;
    }
  | {
      readonly kind: 'opened_wallet_authority_linked_signer_material_v1';
      readonly authorityId: WalletAuthorityId;
      readonly walletAuthMethodId: WalletAuthMethodId;
      readonly keyFamily: 'ecdsa_secp256k1';
      readonly materialActivation: MpcMaterialActivationRef;
      readonly publicFacts: Extract<
        WalletAuthorityLinkedSignerMaterialPublicFactsV1,
        { readonly keyFamily: 'ecdsa_secp256k1' }
      >;
      readonly material: Uint8Array;
    }
  | {
      readonly kind: 'wallet_authority_linked_signer_material_open_failed_v1';
      readonly reason:
        | 'identity_mismatch'
        | 'target_factor_mismatch'
        | 'package_digest_mismatch'
        | 'factor_secret_invalid'
        | 'sealed_material_invalid'
        | 'sealed_material_digest_mismatch'
        | 'sealed_material_authentication_failed';
    };

export function linkedAuthorityMaterialSealAadV1(
  input: LinkedAuthorityMaterialSealInputV1,
): string {
  return alphabetizeStringify({
    domain: 'seams/wallet/ordinary-authority-material-seal-aad/v1',
    authorityId: String(input.authorityId),
    walletId: String(input.walletId),
    walletAuthMethodId: String(input.walletAuthMethodId),
    packageSetDigestB64u: String(input.packageSetDigestB64u),
    targetFactor: input.targetFactor,
    keyFamily: input.keyFamily,
    materialActivation: input.materialActivation,
  });
}

export async function sealWalletAuthorityLinkedSignerMaterialV1(input: {
  readonly factorSecret: Uint8Array;
  readonly aad: LinkedAuthorityMaterialSealInputV1;
  readonly material: Uint8Array;
}): Promise<{
  readonly sealedMaterialB64u: string;
  readonly sealedMaterialDigestB64u: DigestB64u;
}> {
  if (input.factorSecret.byteLength !== 32 || input.material.byteLength === 0) {
    throw new Error('ordinary signer material sealing inputs are invalid');
  }
  const encoder = new TextEncoder();
  const aad = encoder.encode(linkedAuthorityMaterialSealAadV1(input.aad));
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
  const nonce = new Uint8Array(12);
  globalThis.crypto.getRandomValues(nonce);
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

export function walletAuthorityLinkedSignerMaterialRecordFromPackageV1(input: {
  readonly committed: CommittedAuthorityPackagesV1;
  readonly targetFactor: WalletAuthorityLinkedMaterialTargetFactorV1;
  readonly packageValue: LinkedSignerPackageForMaterialV1;
  readonly sealedMaterialB64u: string;
  readonly sealedMaterialDigestB64u: DigestB64u;
}): WalletAuthorityLinkedSignerMaterialRecordV1 {
  if (input.targetFactor.walletAuthMethodId !== input.committed.authMethod.walletAuthMethodId) {
    throw new Error('linked signer material target factor auth method differs from package');
  }
  const common = {
    kind: 'wallet_authority_linked_signer_material_v1' as const,
    authorityId: input.committed.authority.authorityId,
    walletAuthMethodId: input.committed.authMethod.walletAuthMethodId,
    materialActivation: input.packageValue.package.materialActivation,
    activationId: input.packageValue.package.materialActivation.activationId,
    sealedMaterialB64u: input.sealedMaterialB64u,
    sealedMaterialDigestB64u: input.sealedMaterialDigestB64u,
    packageSetDigestB64u: input.committed.packageSetDigestB64u,
    targetFactor: input.targetFactor,
  };
  if (input.packageValue.keyFamily === 'ed25519') {
    return {
      ...common,
      keyFamily: 'ed25519',
      publicFacts: {
        keyFamily: 'ed25519',
        participantIds: input.packageValue.package.participantIds,
        targetBinding: input.packageValue.package.targetBinding,
        applicationBinding: input.packageValue.package.applicationBinding,
        activationReceipt: input.packageValue.package.activationReceipt,
      },
    };
  }
  const ecdsaThresholdKeyId =
    input.packageValue.package.activationReceipt.sourceDerivation.ecdsaThresholdKeyId;
  return {
    ...common,
    keyFamily: 'ecdsa_secp256k1',
    ecdsaThresholdKeyId,
    publicFacts: {
      keyFamily: 'ecdsa_secp256k1',
      ecdsaThresholdKeyId,
      activationReceipt: input.packageValue.package.activationReceipt,
    },
  };
}

export function parseWalletAuthorityLinkedSignerMaterialRecordV1(
  value: unknown,
): WalletAuthorityLinkedSignerMaterialRecordV1 {
  const record = requireRecord(value, 'linked signer material record');
  if (record.kind !== 'wallet_authority_linked_signer_material_v1') {
    throw new Error('linked signer material record kind is invalid');
  }
  if (record.keyFamily !== 'ed25519' && record.keyFamily !== 'ecdsa_secp256k1') {
    throw new Error('linked signer material keyFamily is invalid');
  }
  const commonKeys = [
    'kind',
    'authorityId',
    'walletAuthMethodId',
    'activationId',
    'keyFamily',
    'materialActivation',
    'sealedMaterialB64u',
    'sealedMaterialDigestB64u',
    'packageSetDigestB64u',
    'targetFactor',
    'publicFacts',
  ] as const;
  const expectedKeys =
    record.keyFamily === 'ecdsa_secp256k1' ? [...commonKeys, 'ecdsaThresholdKeyId'] : commonKeys;
  exactKeys(record, expectedKeys, 'linked signer material record');
  const authorityId = parseBoundaryValue(parseWalletAuthorityId(record.authorityId), 'authorityId');
  const walletAuthMethodId = parseBoundaryValue(
    parseWalletAuthMethodId(record.walletAuthMethodId),
    'walletAuthMethodId',
  );
  const materialActivation = parseBoundaryValue(
    parseMpcMaterialActivationRef(record.materialActivation),
    'materialActivation',
  );
  const activationId = requireNonEmptyString(record.activationId, 'activationId');
  if (materialActivation.activationId !== activationId) {
    throw new Error('linked signer material activationId does not match materialActivation');
  }
  const sealedMaterialB64u = parseCanonicalNonEmptyB64u(
    record.sealedMaterialB64u,
    'sealedMaterialB64u',
  );
  const sealedMaterialDigestB64u = parseDigestB64u(record.sealedMaterialDigestB64u);
  const packageSetDigestB64u = parseDigestB64u(record.packageSetDigestB64u);
  const targetFactor = parseWalletAuthorityLinkedMaterialTargetFactorV1(record.targetFactor);
  if (targetFactor.walletAuthMethodId !== walletAuthMethodId) {
    throw new Error('linked signer material target factor auth method differs from record');
  }
  if (record.keyFamily === 'ed25519') {
    const publicFacts = parseEd25519PublicFacts(record.publicFacts, materialActivation);
    return {
      kind: 'wallet_authority_linked_signer_material_v1',
      authorityId,
      walletAuthMethodId,
      activationId: materialActivation.activationId,
      keyFamily: 'ed25519',
      materialActivation,
      sealedMaterialB64u,
      sealedMaterialDigestB64u,
      packageSetDigestB64u,
      targetFactor,
      publicFacts,
    };
  }
  const ecdsaThresholdKeyId = parseEcdsaThresholdKeyId(record.ecdsaThresholdKeyId);
  const publicFacts = parseEcdsaPublicFacts(record.publicFacts, materialActivation);
  if (publicFacts.ecdsaThresholdKeyId !== ecdsaThresholdKeyId) {
    throw new Error('linked signer material ECDSA threshold key id differs from public facts');
  }
  return {
    kind: 'wallet_authority_linked_signer_material_v1',
    authorityId,
    walletAuthMethodId,
    activationId: materialActivation.activationId,
    keyFamily: 'ecdsa_secp256k1',
    ecdsaThresholdKeyId,
    materialActivation,
    sealedMaterialB64u,
    sealedMaterialDigestB64u,
    packageSetDigestB64u,
    targetFactor,
    publicFacts,
  };
}

export async function openWalletAuthorityLinkedSignerMaterialV1(
  input: OpenWalletAuthorityLinkedSignerMaterialInputV1,
): Promise<OpenWalletAuthorityLinkedSignerMaterialResultV1> {
  const record = input.record;
  if (
    record.authorityId !== input.expected.authorityId ||
    record.walletAuthMethodId !== input.expected.walletAuthMethodId ||
    record.keyFamily !== input.expected.keyFamily ||
    !mpcMaterialActivationRefsEqual(record.materialActivation, input.expected.materialActivation)
  ) {
    return {
      kind: 'wallet_authority_linked_signer_material_open_failed_v1',
      reason: 'identity_mismatch',
    };
  }
  if (!sameCanonicalValue(record.targetFactor, input.expected.targetFactor)) {
    return {
      kind: 'wallet_authority_linked_signer_material_open_failed_v1',
      reason: 'target_factor_mismatch',
    };
  }
  if (record.packageSetDigestB64u !== input.expected.packageSetDigestB64u) {
    return {
      kind: 'wallet_authority_linked_signer_material_open_failed_v1',
      reason: 'package_digest_mismatch',
    };
  }
  if (input.factorSecret.byteLength !== 32) {
    return {
      kind: 'wallet_authority_linked_signer_material_open_failed_v1',
      reason: 'factor_secret_invalid',
    };
  }
  let sealed: Uint8Array;
  try {
    sealed = base64UrlDecode(record.sealedMaterialB64u);
  } catch {
    return {
      kind: 'wallet_authority_linked_signer_material_open_failed_v1',
      reason: 'sealed_material_invalid',
    };
  }
  if (sealed.length < 12 + 16 + 1) {
    sealed.fill(0);
    return {
      kind: 'wallet_authority_linked_signer_material_open_failed_v1',
      reason: 'sealed_material_invalid',
    };
  }
  const digest = parseDigestB64u(base64UrlEncode(await sha256Bytes(sealed)));
  if (digest !== record.sealedMaterialDigestB64u) {
    sealed.fill(0);
    return {
      kind: 'wallet_authority_linked_signer_material_open_failed_v1',
      reason: 'sealed_material_digest_mismatch',
    };
  }
  const encoder = new TextEncoder();
  const aad = encoder.encode(linkedAuthorityMaterialSealAadV1(input.expected));
  const salt = await sha256Bytes(aad);
  const nonce = sealed.slice(0, 12);
  const ciphertext = sealed.slice(12);
  try {
    const factorKey = await globalThis.crypto.subtle.importKey(
      'raw',
      input.factorSecret,
      { name: 'HKDF' },
      false,
      ['deriveKey'],
    );
    const openKey = await globalThis.crypto.subtle.deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt,
        info: encoder.encode('seams/wallet/ordinary-authority-material-seal/v1'),
      },
      factorKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt'],
    );
    const material = new Uint8Array(
      await globalThis.crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: nonce, additionalData: aad },
        openKey,
        ciphertext,
      ),
    );
    if (record.keyFamily === 'ed25519') {
      return {
        kind: 'opened_wallet_authority_linked_signer_material_v1',
        authorityId: record.authorityId,
        walletAuthMethodId: record.walletAuthMethodId,
        keyFamily: 'ed25519',
        materialActivation: record.materialActivation,
        publicFacts: record.publicFacts,
        material,
      };
    }
    return {
      kind: 'opened_wallet_authority_linked_signer_material_v1',
      authorityId: record.authorityId,
      walletAuthMethodId: record.walletAuthMethodId,
      keyFamily: 'ecdsa_secp256k1',
      materialActivation: record.materialActivation,
      publicFacts: record.publicFacts,
      material,
    };
  } catch {
    return {
      kind: 'wallet_authority_linked_signer_material_open_failed_v1',
      reason: 'sealed_material_authentication_failed',
    };
  } finally {
    sealed.fill(0);
    aad.fill(0);
    salt.fill(0);
    nonce.fill(0);
    ciphertext.fill(0);
  }
}

function parseWalletAuthorityLinkedMaterialTargetFactorV1(
  value: unknown,
): WalletAuthorityLinkedMaterialTargetFactorV1 {
  const record = requireRecord(value, 'linked signer material target factor');
  if (record.kind === 'passkey') {
    exactKeys(
      record,
      ['kind', 'walletAuthMethodId', 'verificationDigestB64u', 'rpId', 'credentialIdB64u'],
      'linked signer material passkey target factor',
    );
    return {
      kind: 'passkey',
      walletAuthMethodId: parseBoundaryValue(
        parseWalletAuthMethodId(record.walletAuthMethodId),
        'targetFactor.walletAuthMethodId',
      ),
      verificationDigestB64u: parseDigestB64u(record.verificationDigestB64u),
      rpId: parseBoundaryValue(parseWebAuthnRpId(record.rpId), 'targetFactor.rpId'),
      credentialIdB64u: parseCanonicalNonEmptyB64u(
        parseBoundaryValue(
          parseWebAuthnCredentialIdB64u(record.credentialIdB64u),
          'targetFactor.credentialIdB64u',
        ),
        'targetFactor.credentialIdB64u',
      ),
    };
  }
  if (record.kind === 'email_otp') {
    exactKeys(
      record,
      [
        'kind',
        'walletAuthMethodId',
        'verificationDigestB64u',
        'emailHashHex',
        'registrationAuthorityId',
      ],
      'linked signer material email target factor',
    );
    const emailHashHex = requireNonEmptyString(record.emailHashHex, 'targetFactor.emailHashHex');
    if (!/^[0-9a-f]{64}$/.test(emailHashHex)) {
      throw new Error('targetFactor.emailHashHex is invalid');
    }
    return {
      kind: 'email_otp',
      walletAuthMethodId: parseBoundaryValue(
        parseWalletAuthMethodId(record.walletAuthMethodId),
        'targetFactor.walletAuthMethodId',
      ),
      verificationDigestB64u: parseDigestB64u(record.verificationDigestB64u),
      emailHashHex,
      registrationAuthorityId: requireNonEmptyString(
        record.registrationAuthorityId,
        'targetFactor.registrationAuthorityId',
      ),
    };
  }
  throw new Error('linked signer material target factor kind is invalid');
}

function parseEd25519PublicFacts(
  value: unknown,
  materialActivation: MpcMaterialActivationRef,
): Extract<WalletAuthorityLinkedSignerMaterialPublicFactsV1, { readonly keyFamily: 'ed25519' }> {
  const record = requireRecord(value, 'linked signer material Ed25519 public facts');
  exactKeys(
    record,
    ['keyFamily', 'participantIds', 'targetBinding', 'applicationBinding', 'activationReceipt'],
    'linked signer material Ed25519 public facts',
  );
  if (record.keyFamily !== 'ed25519') {
    throw new Error('linked signer material Ed25519 public facts family is invalid');
  }
  const activationReceipt = parseRouterAbEd25519YaoActivationPublicReceiptV1(
    record.activationReceipt,
  );
  const targetBinding = parseRouterAbEd25519YaoCeremonyBindingV1(record.targetBinding);
  const applicationBinding = parseRouterAbEd25519YaoApplicationBindingFactsV1(
    record.applicationBinding,
  );
  if (
    !mpcMaterialActivationRefsEqual(
      materialActivation,
      routerAbMpcMaterialActivationRefFromWire(activationReceipt.material_activation),
    )
  ) {
    throw new Error('linked signer material Ed25519 receipt activation differs');
  }
  return {
    keyFamily: 'ed25519',
    participantIds: parseRouterAbEd25519YaoParticipantIdsV1(record.participantIds),
    targetBinding,
    applicationBinding,
    activationReceipt,
  };
}

function parseEcdsaPublicFacts(
  value: unknown,
  materialActivation: MpcMaterialActivationRef,
): Extract<
  WalletAuthorityLinkedSignerMaterialPublicFactsV1,
  { readonly keyFamily: 'ecdsa_secp256k1' }
> {
  const record = requireRecord(value, 'linked signer material ECDSA public facts');
  exactKeys(
    record,
    ['keyFamily', 'ecdsaThresholdKeyId', 'activationReceipt'],
    'linked signer material ECDSA public facts',
  );
  if (record.keyFamily !== 'ecdsa_secp256k1') {
    throw new Error('linked signer material ECDSA public facts family is invalid');
  }
  const activationReceipt = parseLinkedDeviceEcdsaSourcePreservingActivationReceiptV1(
    record.activationReceipt,
  );
  if (
    !mpcMaterialActivationRefsEqual(materialActivation, activationReceipt.binding.target.activation)
  ) {
    throw new Error('linked signer material ECDSA receipt activation differs');
  }
  return {
    keyFamily: 'ecdsa_secp256k1',
    ecdsaThresholdKeyId: parseEcdsaThresholdKeyId(record.ecdsaThresholdKeyId),
    activationReceipt,
  };
}

function parseCanonicalNonEmptyB64u(value: unknown, label: string): string {
  if (typeof value !== 'string' || value.length === 0 || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error(`${label} must be canonical non-empty base64url`);
  }
  const decoded = base64UrlDecode(value);
  if (decoded.length === 0 || base64UrlEncode(decoded) !== value) {
    decoded.fill(0);
    throw new Error(`${label} must be canonical non-empty base64url`);
  }
  decoded.fill(0);
  return value;
}

function parseBoundaryValue<T>(
  result:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
  label: string,
): T {
  if (!result.ok) throw new Error(`${label}: ${result.error.message}`);
  return result.value;
}

function requireNonEmptyString(value: unknown, label: string): string {
  if (typeof value !== 'string' || value.length === 0 || value.trim() !== value) {
    throw new Error(`${label} must be a non-empty canonical string`);
  }
  return value;
}

function requireRecord(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function exactKeys(record: Record<string, unknown>, keys: readonly string[], label: string): void {
  const actual = Object.keys(record);
  if (actual.length !== keys.length || keys.some((key) => !actual.includes(key))) {
    throw new Error(`${label} fields are invalid`);
  }
}

function sameCanonicalValue(left: unknown, right: unknown): boolean {
  return alphabetizeStringify(left) === alphabetizeStringify(right);
}
