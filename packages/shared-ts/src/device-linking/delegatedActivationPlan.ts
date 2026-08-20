import type { AuthorizationParseResult } from '../authorization/capabilityKinds';
import {
  hasDelegatedWalletPermissionV1,
  parseDelegatedWalletAuthorityV1,
  type DelegatedWalletAuthorityV1,
} from '../authorization/delegatedAuthority';
import {
  parseEd25519PublicKeyB64u,
  parseSecp256k1CompressedPublicKeyB64u,
  rejectUnknownFields,
  requireRecord,
  type Ed25519PublicKeyB64u,
  type Secp256k1CompressedPublicKeyB64u,
} from '../passkey-custody/primitives';
import { parseWalletKeyId, type WalletKeyId } from '../signing-lanes/ids';
import { parseWalletId, type WalletId } from '../utils/domainIds';
import {
  parseLinkedDeviceEd25519ExportRootPackageV1,
  type LinkedDeviceEd25519ExportRootPackageV1,
} from './ed25519ExportRoot';

const opaqueValidatedPlanBrand: unique symbol = Symbol('opaqueValidatedPlanBrand');

export type ExactAdministeredSignerManifestV1 =
  | {
      readonly kind: 'exact_administered_signer_manifest_v1';
      readonly keyFamilies: readonly ['ed25519'];
      readonly signers: readonly [ExactAdministeredEd25519SignerV1];
      readonly ecdsa?: never;
    }
  | {
      readonly kind: 'exact_administered_signer_manifest_v1';
      readonly keyFamilies: readonly ['ecdsa_secp256k1'];
      readonly signers: readonly [ExactAdministeredEcdsaSignerV1];
      readonly ed25519?: never;
    }
  | {
      readonly kind: 'exact_administered_signer_manifest_v1';
      readonly keyFamilies: readonly ['ed25519', 'ecdsa_secp256k1'];
      readonly signers: readonly [ExactAdministeredEd25519SignerV1, ExactAdministeredEcdsaSignerV1];
    };

export type ExactAdministeredEd25519SignerV1 = {
  readonly kind: 'exact_administered_ed25519_signer_v1';
  readonly keyFamily: 'ed25519';
  readonly walletId: WalletId;
  readonly walletKeyId: WalletKeyId;
  readonly registeredPublicKeyB64u: Ed25519PublicKeyB64u;
};

export type ExactAdministeredEcdsaSignerV1 = {
  readonly kind: 'exact_administered_ecdsa_signer_v1';
  readonly keyFamily: 'ecdsa_secp256k1';
  readonly walletId: WalletId;
  readonly walletKeyId: WalletKeyId;
  readonly thresholdPublicKey33B64u: Secp256k1CompressedPublicKeyB64u;
  readonly evmAddress: string;
};

export type ExactAdministeredSignerV1 =
  | ExactAdministeredEd25519SignerV1
  | ExactAdministeredEcdsaSignerV1;

export type ExactAdministeredSignerActivationSetV1 =
  | {
      readonly kind: 'exact_administered_signer_activation_set_v1';
      readonly keyFamilies: readonly ['ed25519'];
      readonly activations: readonly [ExactAdministeredEd25519SignerV1];
      readonly ecdsa?: never;
    }
  | {
      readonly kind: 'exact_administered_signer_activation_set_v1';
      readonly keyFamilies: readonly ['ecdsa_secp256k1'];
      readonly activations: readonly [ExactAdministeredEcdsaSignerV1];
      readonly ed25519?: never;
    }
  | {
      readonly kind: 'exact_administered_signer_activation_set_v1';
      readonly keyFamilies: readonly ['ed25519', 'ecdsa_secp256k1'];
      readonly activations: readonly [
        ExactAdministeredEd25519SignerV1,
        ExactAdministeredEcdsaSignerV1,
      ];
    };

export type FactorBoundEd25519ExportRootPackageV1 = LinkedDeviceEd25519ExportRootPackageV1;

export type SigningActivationRequirementV1 =
  | {
      readonly kind: 'required';
      readonly activations: ExactAdministeredSignerActivationSetV1;
    }
  | {
      readonly kind: 'not_granted';
      readonly activations?: never;
    };

export type Ed25519ExportRootRequirementV1 =
  | {
      readonly kind: 'required';
      readonly package: FactorBoundEd25519ExportRootPackageV1;
    }
  | {
      readonly kind: 'not_granted' | 'family_absent';
      readonly package?: never;
    };

export type EcdsaExportMaterialRequirementV1 =
  | {
      readonly kind: 'required';
      readonly material: ExactAdministeredEcdsaSignerV1;
    }
  | {
      readonly kind: 'not_granted' | 'family_absent';
      readonly material?: never;
    };

type DelegatedDeviceActivationPlanFieldsV1 = {
  readonly authority: DelegatedWalletAuthorityV1;
  readonly sourceSignerManifest: ExactAdministeredSignerManifestV1;
  readonly signing: SigningActivationRequirementV1;
  readonly ed25519Export: Ed25519ExportRootRequirementV1;
  readonly ecdsaExport: EcdsaExportMaterialRequirementV1;
};

/** Generic marker used to keep validated plans out of direct object construction. */
export type OpaqueValidatedPlan<T extends object> = T & {
  readonly [opaqueValidatedPlanBrand]: true;
};

class DelegatedDeviceActivationPlanProof {
  readonly [opaqueValidatedPlanBrand] = true as const;
  readonly authority: DelegatedWalletAuthorityV1;
  readonly sourceSignerManifest: ExactAdministeredSignerManifestV1;
  readonly signing: SigningActivationRequirementV1;
  readonly ed25519Export: Ed25519ExportRootRequirementV1;
  readonly ecdsaExport: EcdsaExportMaterialRequirementV1;

  private retainProof(): true {
    return true;
  }

  private constructor(fields: DelegatedDeviceActivationPlanFieldsV1) {
    void this.retainProof();
    this.authority = fields.authority;
    this.sourceSignerManifest = fields.sourceSignerManifest;
    this.signing = fields.signing;
    this.ed25519Export = fields.ed25519Export;
    this.ecdsaExport = fields.ecdsaExport;
  }

  static create(fields: DelegatedDeviceActivationPlanFieldsV1): DelegatedDeviceActivationPlanProof {
    return new DelegatedDeviceActivationPlanProof(fields);
  }
}

export type DelegatedDeviceActivationPlanV1 = DelegatedDeviceActivationPlanProof &
  OpaqueValidatedPlan<DelegatedDeviceActivationPlanFieldsV1>;

export type DelegatedDeviceActivationPlanInputV1 = {
  readonly authority: DelegatedWalletAuthorityV1;
  readonly sourceSignerManifest: ExactAdministeredSignerManifestV1;
  readonly ed25519ExportRootPackage: FactorBoundEd25519ExportRootPackageV1 | null;
};

const MANIFEST_FIELDS = ['kind', 'keyFamilies', 'signers'] as const;
const ED25519_SIGNER_FIELDS = [
  'kind',
  'keyFamily',
  'walletId',
  'walletKeyId',
  'registeredPublicKeyB64u',
] as const;
const ECDSA_SIGNER_FIELDS = [
  'kind',
  'keyFamily',
  'walletId',
  'walletKeyId',
  'thresholdPublicKey33B64u',
  'evmAddress',
] as const;
const PLAN_FIELDS = ['authority', 'sourceSignerManifest', 'ed25519ExportRootPackage'] as const;

export function buildExactAdministeredSignerManifestV1(
  signers: readonly ExactAdministeredSignerV1[],
): ExactAdministeredSignerManifestV1 {
  if (signers.length === 0) {
    throw new Error('exact administered signer manifest must contain at least one active family');
  }

  let walletId: WalletId | undefined;
  let ed25519: ExactAdministeredEd25519SignerV1 | undefined;
  let ecdsa: ExactAdministeredEcdsaSignerV1 | undefined;
  const seenWalletKeyIds = new Set<string>();

  for (const signer of signers) {
    if (walletId !== undefined && walletId !== signer.walletId) {
      throw new Error('exact administered signer manifest must use one wallet identity');
    }
    walletId = signer.walletId;
    if (seenWalletKeyIds.has(signer.walletKeyId)) {
      throw new Error(
        `exact administered signer manifest repeats wallet key ${signer.walletKeyId}`,
      );
    }
    seenWalletKeyIds.add(signer.walletKeyId);

    switch (signer.keyFamily) {
      case 'ed25519':
        if (ed25519 !== undefined) {
          throw new Error('exact administered signer manifest repeats the ed25519 family');
        }
        if (signer.kind !== 'exact_administered_ed25519_signer_v1') {
          throw new Error('exact administered signer manifest has an invalid Ed25519 signer');
        }
        ed25519 = signer;
        break;
      case 'ecdsa_secp256k1':
        if (ecdsa !== undefined) {
          throw new Error('exact administered signer manifest repeats the ecdsa family');
        }
        if (signer.kind !== 'exact_administered_ecdsa_signer_v1') {
          throw new Error('exact administered signer manifest has an invalid ECDSA signer');
        }
        ecdsa = signer;
        break;
    }
  }

  if (ed25519 !== undefined && ecdsa !== undefined) {
    return {
      kind: 'exact_administered_signer_manifest_v1',
      keyFamilies: ['ed25519', 'ecdsa_secp256k1'],
      signers: [ed25519, ecdsa],
    };
  }
  if (ed25519 !== undefined) {
    return {
      kind: 'exact_administered_signer_manifest_v1',
      keyFamilies: ['ed25519'],
      signers: [ed25519],
    };
  }
  if (ecdsa !== undefined) {
    return {
      kind: 'exact_administered_signer_manifest_v1',
      keyFamilies: ['ecdsa_secp256k1'],
      signers: [ecdsa],
    };
  }
  throw new Error('exact administered signer manifest must contain a supported family');
}

export function parseExactAdministeredSignerManifestV1(
  raw: unknown,
): ExactAdministeredSignerManifestV1 {
  const record = exactRecord(raw, MANIFEST_FIELDS, 'ExactAdministeredSignerManifestV1');
  if (record.kind !== 'exact_administered_signer_manifest_v1') {
    throw new Error('ExactAdministeredSignerManifestV1.kind is invalid');
  }
  const keyFamilies = parseManifestFamilies(record.keyFamilies);
  if (!Array.isArray(record.signers)) {
    throw new Error('ExactAdministeredSignerManifestV1.signers must be an array');
  }
  const signers: ExactAdministeredSignerV1[] = [];
  for (let index = 0; index < record.signers.length; index += 1) {
    signers.push(parseExactAdministeredSignerV1(record.signers[index], `signers[${index}]`));
  }
  const manifest = buildExactAdministeredSignerManifestV1(signers);
  if (!sameManifestFamilies(keyFamilies, manifest.keyFamilies)) {
    throw new Error('ExactAdministeredSignerManifestV1.keyFamilies do not match signers');
  }
  return manifest;
}

function parseExactAdministeredSignerV1(raw: unknown, label: string): ExactAdministeredSignerV1 {
  const record = requireRecord(raw, label);
  switch (record.keyFamily) {
    case 'ed25519':
      rejectUnknownFields(record, ED25519_SIGNER_FIELDS, label);
      if (record.kind !== 'exact_administered_ed25519_signer_v1') {
        throw new Error(`${label}.kind is invalid for Ed25519`);
      }
      return {
        kind: 'exact_administered_ed25519_signer_v1',
        keyFamily: 'ed25519',
        walletId: requireParsed(parseWalletId(record.walletId), `${label}.walletId`),
        walletKeyId: requireParsed(parseWalletKeyId(record.walletKeyId), `${label}.walletKeyId`),
        registeredPublicKeyB64u: parseEd25519PublicKeyB64u(
          record.registeredPublicKeyB64u,
          `${label}.registeredPublicKeyB64u`,
        ),
      };
    case 'ecdsa_secp256k1':
      rejectUnknownFields(record, ECDSA_SIGNER_FIELDS, label);
      if (record.kind !== 'exact_administered_ecdsa_signer_v1') {
        throw new Error(`${label}.kind is invalid for ECDSA`);
      }
      return {
        kind: 'exact_administered_ecdsa_signer_v1',
        keyFamily: 'ecdsa_secp256k1',
        walletId: requireParsed(parseWalletId(record.walletId), `${label}.walletId`),
        walletKeyId: requireParsed(parseWalletKeyId(record.walletKeyId), `${label}.walletKeyId`),
        thresholdPublicKey33B64u: parseSecp256k1CompressedPublicKeyB64u(
          record.thresholdPublicKey33B64u,
          `${label}.thresholdPublicKey33B64u`,
        ),
        evmAddress: parseEvmAddress(record.evmAddress, `${label}.evmAddress`),
      };
    default:
      throw new Error(`${label}.keyFamily is unsupported`);
  }
}

export function buildExactAdministeredSignerActivationSetV1(
  manifest: ExactAdministeredSignerManifestV1,
): ExactAdministeredSignerActivationSetV1 {
  if (isBothFamilyManifest(manifest)) {
    return {
      kind: 'exact_administered_signer_activation_set_v1',
      keyFamilies: ['ed25519', 'ecdsa_secp256k1'],
      activations: [manifest.signers[0], manifest.signers[1]],
    };
  }
  if (isEd25519OnlyManifest(manifest)) {
    return {
      kind: 'exact_administered_signer_activation_set_v1',
      keyFamilies: ['ed25519'],
      activations: [manifest.signers[0]],
    };
  }
  return {
    kind: 'exact_administered_signer_activation_set_v1',
    keyFamilies: ['ecdsa_secp256k1'],
    activations: [manifest.signers[0]],
  };
}

export function parseFactorBoundEd25519ExportRootPackageV1(
  raw: unknown,
): FactorBoundEd25519ExportRootPackageV1 {
  return parseLinkedDeviceEd25519ExportRootPackageV1(raw);
}

export function buildDelegatedDeviceActivationPlanV1(
  input: DelegatedDeviceActivationPlanInputV1,
): DelegatedDeviceActivationPlanV1 {
  const activationSet = buildExactAdministeredSignerActivationSetV1(input.sourceSignerManifest);
  const signing = hasDelegatedWalletPermissionV1(input.authority, 'sign')
    ? buildRequiredSigningActivation(activationSet)
    : buildNotGrantedSigningActivation();
  const ed25519Export = buildEd25519ExportRequirement(input);
  const ecdsaExport = buildEcdsaExportRequirement(input.authority, input.sourceSignerManifest);

  return DelegatedDeviceActivationPlanProof.create({
    authority: input.authority,
    sourceSignerManifest: input.sourceSignerManifest,
    signing,
    ed25519Export,
    ecdsaExport,
  });
}

export function parseDelegatedDeviceActivationPlanV1(
  raw: unknown,
): AuthorizationParseResult<DelegatedDeviceActivationPlanV1> {
  try {
    const record = exactRecord(raw, PLAN_FIELDS, 'DelegatedDeviceActivationPlanV1');
    const authority = parseDelegatedWalletAuthorityV1(record.authority);
    if (!authority.ok) return authority;
    const sourceSignerManifest = parseExactAdministeredSignerManifestV1(
      record.sourceSignerManifest,
    );
    const ed25519ExportRootPackage =
      record.ed25519ExportRootPackage === null
        ? null
        : parseFactorBoundEd25519ExportRootPackageV1(record.ed25519ExportRootPackage);
    return {
      ok: true,
      value: buildDelegatedDeviceActivationPlanV1({
        authority: authority.value,
        sourceSignerManifest,
        ed25519ExportRootPackage,
      }),
    };
  } catch (error) {
    return {
      ok: false,
      error: {
        code: 'invalid',
        message: error instanceof Error ? error.message : 'delegated activation plan is invalid',
      },
    };
  }
}

function buildRequiredSigningActivation(
  activations: ExactAdministeredSignerActivationSetV1,
): SigningActivationRequirementV1 {
  return { kind: 'required', activations };
}

function buildNotGrantedSigningActivation(): SigningActivationRequirementV1 {
  return { kind: 'not_granted' };
}

function buildEd25519ExportRequirement(
  input: DelegatedDeviceActivationPlanInputV1,
): Ed25519ExportRootRequirementV1 {
  const hasExportPermission = hasDelegatedWalletPermissionV1(input.authority, 'export_keys');
  const hasEd25519 = manifestHasEd25519(input.sourceSignerManifest);
  if (!hasExportPermission) {
    if (input.ed25519ExportRootPackage !== null) {
      throw new Error('an Ed25519 export-root package requires export_keys permission');
    }
    return { kind: 'not_granted' };
  }
  if (!hasEd25519) {
    if (input.ed25519ExportRootPackage !== null) {
      throw new Error('an Ed25519 export-root package requires an Ed25519 signer family');
    }
    return { kind: 'family_absent' };
  }
  const packageValue = input.ed25519ExportRootPackage;
  if (packageValue === null) {
    throw new Error('export_keys with Ed25519 requires a factor-bound export-root package');
  }
  const ed25519 = administeredEd25519Key(input.sourceSignerManifest);
  if (
    packageValue.walletId !== ed25519.walletId ||
    packageValue.walletKeyId !== ed25519.walletKeyId ||
    packageValue.registeredPublicKeyB64u !== ed25519.registeredPublicKeyB64u
  ) {
    throw new Error('Ed25519 export-root package does not match the source signer manifest');
  }
  return { kind: 'required', package: packageValue };
}

function buildEcdsaExportRequirement(
  authority: DelegatedWalletAuthorityV1,
  manifest: ExactAdministeredSignerManifestV1,
): EcdsaExportMaterialRequirementV1 {
  if (!hasDelegatedWalletPermissionV1(authority, 'export_keys')) {
    return { kind: 'not_granted' };
  }
  if (!manifestHasEcdsa(manifest)) {
    return { kind: 'family_absent' };
  }
  return { kind: 'required', material: administeredEcdsaKey(manifest) };
}

function administeredEd25519Key(
  manifest: ExactAdministeredSignerManifestV1,
): ExactAdministeredEd25519SignerV1 {
  if (!manifestHasEd25519(manifest)) {
    throw new Error('source signer manifest does not contain Ed25519');
  }
  if (isEd25519OnlyManifest(manifest) || isBothFamilyManifest(manifest)) {
    return manifest.signers[0];
  }
  throw new Error('source signer manifest does not contain Ed25519');
}

function administeredEcdsaKey(
  manifest: ExactAdministeredSignerManifestV1,
): ExactAdministeredEcdsaSignerV1 {
  if (isEcdsaOnlyManifest(manifest)) return manifest.signers[0];
  if (isBothFamilyManifest(manifest)) return manifest.signers[1];
  throw new Error('source signer manifest does not contain ECDSA');
}

function isEd25519OnlyManifest(
  manifest: ExactAdministeredSignerManifestV1,
): manifest is Extract<
  ExactAdministeredSignerManifestV1,
  { readonly keyFamilies: readonly ['ed25519'] }
> {
  return manifest.keyFamilies.length === 1 && manifest.keyFamilies[0] === 'ed25519';
}

function isEcdsaOnlyManifest(
  manifest: ExactAdministeredSignerManifestV1,
): manifest is Extract<
  ExactAdministeredSignerManifestV1,
  { readonly keyFamilies: readonly ['ecdsa_secp256k1'] }
> {
  return manifest.keyFamilies.length === 1 && manifest.keyFamilies[0] === 'ecdsa_secp256k1';
}

function isBothFamilyManifest(
  manifest: ExactAdministeredSignerManifestV1,
): manifest is Extract<
  ExactAdministeredSignerManifestV1,
  { readonly keyFamilies: readonly ['ed25519', 'ecdsa_secp256k1'] }
> {
  return manifest.keyFamilies.length === 2;
}

function manifestHasEd25519(manifest: ExactAdministeredSignerManifestV1): boolean {
  return isEd25519OnlyManifest(manifest) || isBothFamilyManifest(manifest);
}

function manifestHasEcdsa(manifest: ExactAdministeredSignerManifestV1): boolean {
  return isEcdsaOnlyManifest(manifest) || isBothFamilyManifest(manifest);
}

function parseManifestFamilies(raw: unknown): ExactAdministeredSignerManifestV1['keyFamilies'] {
  if (!Array.isArray(raw) || raw.length === 0 || raw.length > 2) {
    throw new Error('ExactAdministeredSignerManifestV1.keyFamilies must be non-empty');
  }
  if (raw.length === 1 && raw[0] === 'ed25519') return ['ed25519'];
  if (raw.length === 1 && raw[0] === 'ecdsa_secp256k1') return ['ecdsa_secp256k1'];
  if (raw.length === 2 && raw[0] === 'ed25519' && raw[1] === 'ecdsa_secp256k1') {
    return ['ed25519', 'ecdsa_secp256k1'];
  }
  throw new Error(
    'ExactAdministeredSignerManifestV1.keyFamilies must be canonical and duplicate-free',
  );
}

function sameManifestFamilies(
  left: ExactAdministeredSignerManifestV1['keyFamilies'],
  right: ExactAdministeredSignerManifestV1['keyFamilies'],
): boolean {
  if (left.length !== right.length) return false;
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) return false;
  }
  return true;
}

function parseEvmAddress(raw: unknown, label: string): string {
  if (typeof raw !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(raw)) {
    throw new Error(`${label} must be a 20-byte hexadecimal EVM address`);
  }
  return raw;
}

function exactRecord(
  raw: unknown,
  fields: readonly string[],
  label: string,
): Record<string, unknown> {
  const record = requireRecord(raw, label);
  rejectUnknownFields(record, fields, label);
  for (const field of fields) {
    if (!(field in record)) throw new Error(`${label}.${field} is required`);
  }
  return record;
}

function requireParsed<T>(
  parsed:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
  label: string,
): T {
  if (!parsed.ok) throw new Error(`${label} ${parsed.error.message}`);
  return parsed.value;
}
