import type { DeviceId } from '../authorization/capabilityKinds';
import type { CanonicalDelegatedWalletPermissionSetV1 } from '../authorization/delegatedAuthority';
import type { PendingWalletAuthorityV1 } from '../authorization/walletAuthority';
import {
  parseMpcMaterialActivationRef,
  mpcMaterialActivationRefsEqual,
  type LinkDeviceSessionId,
  type LinkedDeviceEnrollmentId,
  type MpcMaterialActivationRef,
  type WalletAuthMethodId,
  type WalletAuthorityId,
  type WalletId,
} from '../utils/domainIds';
import { base64UrlEncode } from '../utils/base64';
import { parseDigestB64u, type DigestB64u } from '../utils/canonicalPrimitives';
import { alphabetizeStringify, sha256BytesUtf8 } from '../utils/digests';
import {
  parseWalletAuthMethodRecordV2,
  type WalletAuthMethodRecordV2,
} from '../utils/registrationIntent';
import { parseWalletAuthorityV1 } from '../authorization/walletAuthority';
import {
  parseLinkedDeviceEd25519ExportRootPackageV1,
  type LinkedDeviceEd25519ExportRootPackageV1,
} from './ed25519ExportRoot';
import {
  parseLinkedDeviceEcdsaEncryptedSourceContributionV1,
  parseLinkedDeviceEcdsaSourcePreservingActivationReceiptV1,
  type LinkedDeviceEcdsaEncryptedSourceContributionV1,
  type LinkedDeviceEcdsaSourcePreservingActivationReceiptV1,
} from './sourceContribution';
import {
  parseRouterAbEd25519YaoEncryptedPackageV1,
  parseRouterAbEd25519YaoActivationPublicReceiptV1,
  parseRouterAbEd25519YaoParticipantIdsV1,
  type RouterAbEd25519YaoActivationPublicReceiptV1,
  type RouterAbEd25519YaoActivationClientPackageV1,
} from '../utils/routerAbEd25519Yao';
import { routerAbMpcMaterialActivationRefFromWire } from '../utils/routerAbNormalSigningIdentity';

const COMMITTED_SIGNER_PACKAGE_DOMAIN_V1 = 'seams/wallet/committed-signer-package/v1' as const;
const COMMITTED_SIGNER_PACKAGE_SET_DOMAIN_V1 =
  'seams/wallet/committed-signer-package-set/v1' as const;

export type CommittedEd25519SignerPackageV1 = {
  readonly kind: 'committed_ed25519_signer_package_v1';
  readonly materialActivation: MpcMaterialActivationRef;
  readonly participantIds: readonly [number, number];
  readonly activationReceipt: RouterAbEd25519YaoActivationPublicReceiptV1;
  readonly deriver_a_client_package: RouterAbEd25519YaoActivationClientPackageV1<'deriver_a'>;
  readonly deriver_b_client_package: RouterAbEd25519YaoActivationClientPackageV1<'deriver_b'>;
};

export type CommittedEcdsaSignerPackageV1 = {
  readonly kind: 'committed_ecdsa_signer_package_v1';
  readonly materialActivation: MpcMaterialActivationRef;
  readonly encryptedTargetClientShare: LinkedDeviceEcdsaEncryptedSourceContributionV1;
  readonly activationReceipt: LinkedDeviceEcdsaSourcePreservingActivationReceiptV1;
};

export type CommittedSignerPackageSetV1 =
  | {
      readonly kind: 'committed_signer_package_set_v1';
      readonly keyFamilies: readonly ['ed25519'];
      readonly ed25519: CommittedEd25519SignerPackageV1;
      readonly ecdsa?: never;
    }
  | {
      readonly kind: 'committed_signer_package_set_v1';
      readonly keyFamilies: readonly ['ecdsa_secp256k1'];
      readonly ed25519?: never;
      readonly ecdsa: CommittedEcdsaSignerPackageV1;
    }
  | {
      readonly kind: 'committed_signer_package_set_v1';
      readonly keyFamilies: readonly ['ed25519', 'ecdsa_secp256k1'];
      readonly ed25519: CommittedEd25519SignerPackageV1;
      readonly ecdsa: CommittedEcdsaSignerPackageV1;
    };

export type PendingWalletAuthMethodRecordV1 = Extract<
  WalletAuthMethodRecordV2,
  { readonly status: 'pending_local_install' }
>;

export type CommittedAuthorityPackagesV1 = {
  readonly kind: 'committed_authority_packages_v1';
  readonly authority: PendingWalletAuthorityV1;
  readonly authMethod: PendingWalletAuthMethodRecordV1;
  readonly signerPackages: CommittedSignerPackageSetV1;
  readonly ed25519ExportRootPackage: LinkedDeviceEd25519ExportRootPackageV1 | null;
  readonly packageSetDigestB64u: DigestB64u;
};

export function parseCommittedAuthorityPackagesV1(raw: unknown): CommittedAuthorityPackagesV1 {
  const record = exactRecord(
    raw,
    ['kind', 'authority', 'authMethod', 'signerPackages', 'ed25519ExportRootPackage', 'packageSetDigestB64u'],
    'CommittedAuthorityPackagesV1',
  );
  if (record.kind !== 'committed_authority_packages_v1') {
    throw new Error('CommittedAuthorityPackagesV1.kind is invalid');
  }
  const authority = parseWalletAuthorityV1(record.authority);
  if (!authority.ok || authority.value.state !== 'pending_local_install') {
    throw new Error('CommittedAuthorityPackagesV1.authority is not pending');
  }
  const authMethod = parseWalletAuthMethodRecordV2(record.authMethod);
  if (!authMethod || authMethod.status !== 'pending_local_install') {
    throw new Error('CommittedAuthorityPackagesV1.authMethod is not pending');
  }
  if (
    authMethod.walletId !== authority.value.walletId ||
    authMethod.walletAuthorityId !== authority.value.authorityId
  ) {
    throw new Error('CommittedAuthorityPackagesV1 authority and auth method identities differ');
  }
  const signerPackages = parseCommittedSignerPackageSetV1(record.signerPackages);
  assertSignerPackagesMatchAuthority(signerPackages, authority.value.signerActivations);
  const ed25519ExportRootPackage =
    record.ed25519ExportRootPackage === null
      ? null
      : parseLinkedDeviceEd25519ExportRootPackageV1(record.ed25519ExportRootPackage);
  if (ed25519ExportRootPackage) {
    if (
      ed25519ExportRootPackage.walletId !== authority.value.walletId ||
      ed25519ExportRootPackage.revocationEpoch !== authority.value.revocationEpoch ||
      authority.value.provenance.kind !== 'device_link' ||
      ed25519ExportRootPackage.enrollmentId !== authority.value.provenance.enrollmentId ||
      ed25519ExportRootPackage.linkSessionId !== authority.value.provenance.linkSessionId ||
      String(ed25519ExportRootPackage.deviceId) !== String(authority.value.principal.deviceId)
    ) {
      throw new Error('CommittedAuthorityPackagesV1 export root identity does not match authority');
    }
  }
  return {
    kind: 'committed_authority_packages_v1',
    authority: authority.value,
    authMethod,
    signerPackages,
    ed25519ExportRootPackage,
    packageSetDigestB64u: parseCommittedSignerPackageSetDigestB64u(record.packageSetDigestB64u),
  };
}

function assertSignerPackagesMatchAuthority(
  packages: CommittedSignerPackageSetV1,
  activations: PendingWalletAuthorityV1['signerActivations'],
): void {
  if (packages.keyFamilies.length !== activations.keyFamilies.length) {
    throw new Error('CommittedAuthorityPackagesV1 signer families do not match authority');
  }
  for (let index = 0; index < packages.keyFamilies.length; index += 1) {
    if (packages.keyFamilies[index] !== activations.keyFamilies[index]) {
      throw new Error('CommittedAuthorityPackagesV1 signer family order does not match authority');
    }
  }
  if (packages.keyFamilies.length === 1 && packages.keyFamilies[0] === 'ed25519') {
    if (!activations.ed25519 || !packages.ed25519) {
      throw new Error('CommittedAuthorityPackagesV1 Ed25519 activation is missing');
    }
    if (!mpcMaterialActivationRefsEqual(packages.ed25519.materialActivation, activations.ed25519.materialActivation)) {
      throw new Error('CommittedAuthorityPackagesV1 Ed25519 activation does not match authority');
    }
    return;
  }
  if (packages.keyFamilies.length === 1 && packages.keyFamilies[0] === 'ecdsa_secp256k1') {
    if (!activations.ecdsa || !packages.ecdsa) {
      throw new Error('CommittedAuthorityPackagesV1 ECDSA activation is missing');
    }
    if (!mpcMaterialActivationRefsEqual(packages.ecdsa.materialActivation, activations.ecdsa.materialActivation)) {
      throw new Error('CommittedAuthorityPackagesV1 ECDSA activation does not match authority');
    }
    return;
  }
  if (!activations.ed25519 || !activations.ecdsa || !packages.ed25519 || !packages.ecdsa) {
    throw new Error('CommittedAuthorityPackagesV1 combined activations are incomplete');
  }
  if (
    !mpcMaterialActivationRefsEqual(packages.ed25519.materialActivation, activations.ed25519.materialActivation) ||
    !mpcMaterialActivationRefsEqual(packages.ecdsa.materialActivation, activations.ecdsa.materialActivation)
  ) {
    throw new Error('CommittedAuthorityPackagesV1 activation references do not match authority');
  }
}

export type CommittedSignerPackageSetDigestInputV1 = {
  readonly authorityId: WalletAuthorityId;
  readonly walletId: WalletId;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly linkSessionId: LinkDeviceSessionId;
  readonly deviceId: DeviceId;
  readonly authMethodId: WalletAuthMethodId;
  readonly permissions: CanonicalDelegatedWalletPermissionSetV1;
  readonly sourceManifestDigestB64u: DigestB64u;
  readonly signerPackages: CommittedSignerPackageSetV1;
  readonly ed25519ExportRootPackageDigestB64u: DigestB64u | null;
  readonly targetFactorVerificationDigestB64u: DigestB64u;
};

export function parseCommittedSignerPackageSetV1(raw: unknown): CommittedSignerPackageSetV1 {
  const record = objectRecord(raw, 'CommittedSignerPackageSetV1');
  if (record.kind !== 'committed_signer_package_set_v1') {
    throw new Error('CommittedSignerPackageSetV1.kind is invalid');
  }
  const keyFamilies = parseKeyFamilies(record.keyFamilies);
  if (keyFamilies.length === 1 && keyFamilies[0] === 'ed25519') {
    exactKeys(record, ['kind', 'keyFamilies', 'ed25519'], 'CommittedSignerPackageSetV1');
    return {
      kind: 'committed_signer_package_set_v1',
      keyFamilies,
      ed25519: parseEd25519Package(record.ed25519),
    };
  }
  if (keyFamilies.length === 1 && keyFamilies[0] === 'ecdsa_secp256k1') {
    exactKeys(record, ['kind', 'keyFamilies', 'ecdsa'], 'CommittedSignerPackageSetV1');
    return {
      kind: 'committed_signer_package_set_v1',
      keyFamilies,
      ecdsa: parseEcdsaPackage(record.ecdsa),
    };
  }
  exactKeys(record, ['kind', 'keyFamilies', 'ed25519', 'ecdsa'], 'CommittedSignerPackageSetV1');
  const ed25519 = parseEd25519Package(record.ed25519);
  const ecdsa = parseEcdsaPackage(record.ecdsa);
  if (ed25519.materialActivation.activationId === ecdsa.materialActivation.activationId) {
    throw new Error('CommittedSignerPackageSetV1 activation references must be distinct');
  }
  return {
    kind: 'committed_signer_package_set_v1',
    keyFamilies,
    ed25519,
    ecdsa,
  };
}

export function parseCommittedSignerPackageSetDigestB64u(raw: unknown): DigestB64u {
  return parseDigestB64u(raw);
}

export async function computeCommittedSignerPackageDigestB64u(
  value: CommittedEd25519SignerPackageV1 | CommittedEcdsaSignerPackageV1,
): Promise<DigestB64u> {
  return parseDigestB64u(
    base64UrlEncode(
      await sha256BytesUtf8(
        alphabetizeStringify({ domain: COMMITTED_SIGNER_PACKAGE_DOMAIN_V1, package: value }),
      ),
    ),
  );
}

export async function computeCommittedSignerPackageSetDigestB64u(
  input: CommittedSignerPackageSetDigestInputV1,
): Promise<DigestB64u> {
  const packageEntries = await committedSignerPackageSetCanonicalValue(input.signerPackages);
  const value = [
    COMMITTED_SIGNER_PACKAGE_SET_DOMAIN_V1,
    input.authorityId,
    input.walletId,
    input.enrollmentId,
    input.linkSessionId,
    input.deviceId,
    input.authMethodId,
    [...input.permissions],
    input.sourceManifestDigestB64u,
    packageEntries,
    input.ed25519ExportRootPackageDigestB64u,
    input.targetFactorVerificationDigestB64u,
  ];
  return parseDigestB64u(base64UrlEncode(await sha256BytesUtf8(alphabetizeStringify(value))));
}

function parseEd25519Package(raw: unknown): CommittedEd25519SignerPackageV1 {
  const record = exactRecord(
    raw,
    [
      'kind',
      'materialActivation',
      'participantIds',
      'activationReceipt',
      'deriver_a_client_package',
      'deriver_b_client_package',
    ],
    'CommittedEd25519SignerPackageV1',
  );
  if (record.kind !== 'committed_ed25519_signer_package_v1') {
    throw new Error('CommittedEd25519SignerPackageV1.kind is invalid');
  }
  const materialActivation = parseActivation(record.materialActivation, 'materialActivation');
  const activationReceipt = parseRouterAbEd25519YaoActivationPublicReceiptV1(
    record.activationReceipt,
  );
  if (
    !mpcMaterialActivationRefsEqual(
      materialActivation,
      routerAbMpcMaterialActivationRefFromWire(activationReceipt.material_activation),
    )
  ) {
    throw new Error('CommittedEd25519SignerPackageV1 activation receipt does not match material');
  }
  const deriverA = parseEd25519ClientPackage(
    record.deriver_a_client_package,
    'deriver_a_client_package',
    'deriver_a',
  );
  const deriverB = parseEd25519ClientPackage(
    record.deriver_b_client_package,
    'deriver_b_client_package',
    'deriver_b',
  );
  if (
    !sameBytes(activationReceipt.transcript, deriverA.transcript) ||
    !sameBytes(activationReceipt.transcript, deriverB.transcript)
  ) {
    throw new Error('CommittedEd25519SignerPackageV1 receipt transcript does not match packages');
  }
  return {
    kind: 'committed_ed25519_signer_package_v1',
    materialActivation,
    participantIds: parseRouterAbEd25519YaoParticipantIdsV1(record.participantIds),
    activationReceipt,
    deriver_a_client_package: deriverA,
    deriver_b_client_package: deriverB,
  };
}

function parseEcdsaPackage(raw: unknown): CommittedEcdsaSignerPackageV1 {
  const record = exactRecord(
    raw,
    ['kind', 'materialActivation', 'encryptedTargetClientShare', 'activationReceipt'],
    'CommittedEcdsaSignerPackageV1',
  );
  if (record.kind !== 'committed_ecdsa_signer_package_v1') {
    throw new Error('CommittedEcdsaSignerPackageV1.kind is invalid');
  }
  const materialActivation = parseActivation(record.materialActivation, 'materialActivation');
  const activationReceipt = parseLinkedDeviceEcdsaSourcePreservingActivationReceiptV1(
    record.activationReceipt,
  );
  const targetActivation = activationReceipt.binding.target.activation;
  if (!mpcMaterialActivationRefsEqual(materialActivation, targetActivation)) {
    throw new Error('CommittedEcdsaSignerPackageV1 receipt activation does not match material');
  }
  const encryptedTargetClientShare = parseLinkedDeviceEcdsaEncryptedSourceContributionV1(
    record.encryptedTargetClientShare,
    'encryptedTargetClientShare',
  );
  if (
    encryptedTargetClientShare.recipientPublicKeyB64u !==
      activationReceipt.binding.target.clientRecipientPublicKeyB64u
  ) {
    throw new Error('CommittedEcdsaSignerPackageV1 client share recipient does not match receipt');
  }
  return {
    kind: 'committed_ecdsa_signer_package_v1',
    materialActivation,
    encryptedTargetClientShare,
    activationReceipt,
  };
}

function parseEd25519ClientPackage<Role extends 'deriver_a' | 'deriver_b'>(
  raw: unknown,
  label: string,
  deriver: Role,
): RouterAbEd25519YaoActivationClientPackageV1<Role> {
  const parsed = parseRouterAbEd25519YaoEncryptedPackageV1(raw);
  if (!parsed.ok) throw new Error(`${label} ${parsed.message}`);
  if (parsed.value.kind !== 'activation_client' || parsed.value.deriver !== deriver) {
    throw new Error(`${label} must be an activation_client for ${deriver}`);
  }
  return {
    kind: 'activation_client',
    deriver,
    session: parsed.value.session,
    transcript: parsed.value.transcript,
    encapsulated_key: parsed.value.encapsulated_key,
    ciphertext: parsed.value.ciphertext,
  };
}

function parseActivation(raw: unknown, label: string): MpcMaterialActivationRef {
  const parsed = parseMpcMaterialActivationRef(raw);
  if (!parsed.ok) throw new Error(`${label} ${parsed.error.message}`);
  return parsed.value;
}

function parseKeyFamilies(raw: unknown): CommittedSignerPackageSetV1['keyFamilies'] {
  if (!Array.isArray(raw))
    throw new Error('CommittedSignerPackageSetV1.keyFamilies must be an array');
  if (raw.length === 1 && raw[0] === 'ed25519') return ['ed25519'];
  if (raw.length === 1 && raw[0] === 'ecdsa_secp256k1') return ['ecdsa_secp256k1'];
  if (raw.length === 2 && raw[0] === 'ed25519' && raw[1] === 'ecdsa_secp256k1') {
    return ['ed25519', 'ecdsa_secp256k1'];
  }
  throw new Error('CommittedSignerPackageSetV1.keyFamilies must use canonical family order');
}

function exactRecord(
  raw: unknown,
  keys: readonly string[],
  label: string,
): Record<string, unknown> {
  const record = objectRecord(raw, label);
  exactKeys(record, keys, label);
  return record;
}

function objectRecord(raw: unknown, label: string): Record<string, unknown> {
  if (!isRecord(raw)) {
    throw new Error(`${label} must be an object`);
  }
  return raw;
}

function isRecord(raw: unknown): raw is Record<string, unknown> {
  return raw !== null && typeof raw === 'object' && !Array.isArray(raw);
}

function sameBytes(left: readonly number[], right: readonly number[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function exactKeys(record: Record<string, unknown>, keys: readonly string[], label: string): void {
  const expected = new Set(keys);
  const actual = Object.keys(record);
  if (actual.length !== keys.length) {
    throw new Error(`${label} contains unexpected fields`);
  }
  for (const key of actual) {
    if (!expected.has(key)) throw new Error(`${label} contains unexpected fields`);
  }
  for (const key of keys) {
    if (!Object.prototype.hasOwnProperty.call(record, key)) {
      throw new Error(`${label}.${key} is required`);
    }
  }
}

async function committedSignerPackageSetCanonicalValue(
  value: CommittedSignerPackageSetV1,
): Promise<readonly unknown[]> {
  switch (value.keyFamilies.length) {
    case 1:
      if (value.keyFamilies[0] === 'ed25519') {
        if (!value.ed25519)
          throw new Error('CommittedSignerPackageSetV1 Ed25519 package is required');
        return [
          value.kind,
          value.keyFamilies,
          value.ed25519.materialActivation,
          await computeCommittedSignerPackageDigestB64u(value.ed25519),
        ];
      }
      if (!value.ecdsa) throw new Error('CommittedSignerPackageSetV1 ECDSA package is required');
      return [
        value.kind,
        value.keyFamilies,
        value.ecdsa.materialActivation,
        await computeCommittedSignerPackageDigestB64u(value.ecdsa),
      ];
    case 2:
      if (!value.ed25519 || !value.ecdsa) {
        throw new Error('CommittedSignerPackageSetV1 packages are incomplete');
      }
      return [
        value.kind,
        value.keyFamilies,
        value.ed25519.materialActivation,
        await computeCommittedSignerPackageDigestB64u(value.ed25519),
        value.ecdsa.materialActivation,
        await computeCommittedSignerPackageDigestB64u(value.ecdsa),
      ];
    default:
      throw new Error('CommittedSignerPackageSetV1 keyFamilies is invalid');
  }
}
