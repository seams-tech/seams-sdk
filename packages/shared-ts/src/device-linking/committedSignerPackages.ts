import type { DeviceId } from '../authorization/capabilityKinds';
import type { CanonicalDelegatedWalletPermissionSetV1 } from '../authorization/delegatedAuthority';
import type { PendingWalletAuthorityV1 } from '../authorization/walletAuthority';
import {
  parseMpcMaterialActivationRef,
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
import type { WalletAuthMethodRecordV2 } from '../utils/registrationIntent';
import type { LinkedDeviceEd25519ExportRootPackageV1 } from './ed25519ExportRoot';
import {
  parseRouterAbEcdsaDerivationRoleEncryptedEnvelopeV1,
  type RouterAbEcdsaDerivationRoleEncryptedEnvelopeV1,
} from '../utils/routerAbEcdsaDerivation';
import {
  parseRouterAbEd25519YaoEncryptedPackageV1,
  type RouterAbEd25519YaoActivationClientPackageV1,
} from '../utils/routerAbEd25519Yao';

const COMMITTED_SIGNER_PACKAGE_DOMAIN_V1 = 'seams/wallet/committed-signer-package/v1' as const;
const COMMITTED_SIGNER_PACKAGE_SET_DOMAIN_V1 =
  'seams/wallet/committed-signer-package-set/v1' as const;

export type CommittedEd25519SignerPackageV1 = {
  readonly kind: 'committed_ed25519_signer_package_v1';
  readonly materialActivation: MpcMaterialActivationRef;
  readonly deriver_a_client_package: RouterAbEd25519YaoActivationClientPackageV1<'deriver_a'>;
  readonly deriver_b_client_package: RouterAbEd25519YaoActivationClientPackageV1<'deriver_b'>;
};

export type CommittedEcdsaSignerPackageV1 = {
  readonly kind: 'committed_ecdsa_signer_package_v1';
  readonly materialActivation: MpcMaterialActivationRef;
  readonly deriver_a_client_package: RouterAbEcdsaDerivationRoleEncryptedEnvelopeV1<'signer_a'>;
  readonly deriver_b_client_package: RouterAbEcdsaDerivationRoleEncryptedEnvelopeV1<'signer_b'>;
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
    ['kind', 'materialActivation', 'deriver_a_client_package', 'deriver_b_client_package'],
    'CommittedEd25519SignerPackageV1',
  );
  if (record.kind !== 'committed_ed25519_signer_package_v1') {
    throw new Error('CommittedEd25519SignerPackageV1.kind is invalid');
  }
  return {
    kind: 'committed_ed25519_signer_package_v1',
    materialActivation: parseActivation(record.materialActivation, 'materialActivation'),
    deriver_a_client_package: parseEd25519ClientPackage(
      record.deriver_a_client_package,
      'deriver_a_client_package',
      'deriver_a',
    ),
    deriver_b_client_package: parseEd25519ClientPackage(
      record.deriver_b_client_package,
      'deriver_b_client_package',
      'deriver_b',
    ),
  };
}

function parseEcdsaPackage(raw: unknown): CommittedEcdsaSignerPackageV1 {
  const record = exactRecord(
    raw,
    ['kind', 'materialActivation', 'deriver_a_client_package', 'deriver_b_client_package'],
    'CommittedEcdsaSignerPackageV1',
  );
  if (record.kind !== 'committed_ecdsa_signer_package_v1') {
    throw new Error('CommittedEcdsaSignerPackageV1.kind is invalid');
  }
  return {
    kind: 'committed_ecdsa_signer_package_v1',
    materialActivation: parseActivation(record.materialActivation, 'materialActivation'),
    deriver_a_client_package: parseRouterAbEcdsaDerivationRoleEncryptedEnvelopeV1(
      record.deriver_a_client_package,
      'deriver_a_client_package',
      'signer_a',
    ),
    deriver_b_client_package: parseRouterAbEcdsaDerivationRoleEncryptedEnvelopeV1(
      record.deriver_b_client_package,
      'deriver_b_client_package',
      'signer_b',
    ),
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
