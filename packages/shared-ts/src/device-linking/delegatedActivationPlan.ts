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
