import { alphabetizeStringify, sha256BytesUtf8 } from '@shared/utils/digests';
import { parseWebAuthnRpId, type WebAuthnRpId } from '@shared/utils/domainIds';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import { deriveSigningRootId } from '@shared/threshold/signingRootScope';
import {
  normalizeSigningRootSecretShareId,
  type SigningRootSecretShareId,
  type SealedSigningRootSecretShare,
} from './signingRootSecretShareWires';

export const SIGNING_ROOT_RECORD_VERSION_V1 = 'signing_root_record_v1';
export const SIGNING_ROOT_MIGRATION_BUNDLE_VERSION_V1 = 'signing_root_migration_bundle_v1';
export const SIGNING_ROOT_MIGRATION_EXPORT_ARTIFACT_VERSION_V1 =
  'signing_root_migration_export_artifact_v1';

export type SigningRootRecordSource =
  | 'hosted-export'
  | 'customer-import'
  | 'customer-generated'
  | 'dev';

export type SigningRootAuthorityScope = {
  readonly kind: 'passkey_rp';
  readonly rpId: WebAuthnRpId;
};

export type SigningRootRecord = {
  readonly version: typeof SIGNING_ROOT_RECORD_VERSION_V1;
  readonly projectId: string;
  readonly envId: string;
  readonly signingRootId: string;
  readonly walletOrigin: string;
  readonly authorityScope: SigningRootAuthorityScope;
  readonly rpId?: never;
  readonly signingRootVersion: string;
  readonly rootShareEpoch: number;
  readonly shareThreshold: 2;
  readonly shareCount: 3;
  readonly sealedSigningRootSecretShares: readonly SealedSigningRootSecretShare[];
  readonly derivationVersion: number;
  readonly createdAtMs: number;
  readonly updatedAtMs: number;
  readonly source: SigningRootRecordSource;
};

export type SigningRootMigrationBundleShareV1 = {
  readonly shareId: SigningRootSecretShareId;
  readonly sealedShareB64u: string;
  readonly storageId?: string;
  readonly kekId?: string;
};

export type SigningRootMigrationWalletInventoryEntryV1 = {
  readonly userId: string;
  readonly authorityScope: SigningRootAuthorityScope;
  readonly rpId?: never;
  readonly walletKeyVersion: string;
  readonly signingRootVersion: string;
  readonly ecdsaThresholdKeyId?: string;
  readonly thresholdEcdsaPublicKeyB64u?: string;
  readonly ethereumAddress?: string;
  readonly status?: 'active' | 'retired';
};

export type SigningRootMigrationBundleV1 = {
  readonly version: typeof SIGNING_ROOT_MIGRATION_BUNDLE_VERSION_V1;
  readonly projectId: string;
  readonly envId: string;
  readonly signingRootId: string;
  readonly walletOrigin: string;
  readonly authorityScope: SigningRootAuthorityScope;
  readonly rpId?: never;
  readonly signingRootVersion: string;
  readonly rootShareEpoch: number;
  readonly shareThreshold: 2;
  readonly shareCount: 3;
  readonly derivationVersion: number;
  readonly sealedSigningRootSecretShares: readonly SigningRootMigrationBundleShareV1[];
  readonly walletInventory?: readonly SigningRootMigrationWalletInventoryEntryV1[];
  readonly exportedAtMs: number;
  readonly exportActor?: string;
};

export type SigningRootMigrationExportArtifactV1 = {
  readonly version: typeof SIGNING_ROOT_MIGRATION_EXPORT_ARTIFACT_VERSION_V1;
  readonly bundle: SigningRootMigrationBundleV1;
  readonly checksumB64u: string;
  readonly createdAtMs: number;
};

export type SigningRootRecordResult<T> =
  | { ok: true; value: T }
  | {
      ok: false;
      code: 'invalid_signing_root_record' | 'invalid_migration_bundle';
      message: string;
    };

function ok<T>(value: T): SigningRootRecordResult<T> {
  return { ok: true, value };
}

function err<T>(
  code: 'invalid_signing_root_record' | 'invalid_migration_bundle',
  message: string,
): SigningRootRecordResult<T> {
  return { ok: false, code, message };
}

function isObject(input: unknown): input is Record<string, unknown> {
  return Boolean(input && typeof input === 'object' && !Array.isArray(input));
}

function validPositiveInteger(input: unknown): number | null {
  if (typeof input !== 'number' || !Number.isFinite(input)) return null;
  const value = Math.floor(input);
  return value === input && value >= 1 ? value : null;
}

function validTimestampMs(input: unknown): number | null {
  if (typeof input !== 'number' || !Number.isFinite(input)) return null;
  const value = Math.floor(input);
  return value === input && value >= 0 ? value : null;
}

function normalizeWalletOrigin(input: unknown): string | null {
  const raw = toOptionalTrimmedString(input);
  if (!raw) return null;
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    return null;
  }
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') return null;
  return parsed.origin === raw ? raw : null;
}

function parseSigningRootRecordSource(input: unknown): SigningRootRecordSource | null {
  const value = toOptionalTrimmedString(input);
  switch (value) {
    case 'hosted-export':
    case 'customer-import':
    case 'customer-generated':
    case 'dev':
      return value;
    default:
      return null;
  }
}

function parseSigningRootAuthorityScope(raw: unknown): SigningRootAuthorityScope | null {
  if (!isObject(raw)) return null;
  const kind = toOptionalTrimmedString(raw.kind);
  const rpId = parseWebAuthnRpId(raw.rpId);
  if (kind !== 'passkey_rp' || !rpId.ok) return null;
  return { kind: 'passkey_rp', rpId: rpId.value };
}

function parseSigningRootSecretShareRecords(input: {
  readonly signingRootId: string;
  readonly signingRootVersion: string;
  readonly shareThreshold: 2;
  readonly shareCount: 3;
  readonly rawShares: unknown;
  readonly errorCode: 'invalid_signing_root_record' | 'invalid_migration_bundle';
}): SigningRootRecordResult<readonly SealedSigningRootSecretShare[]> {
  if (!Array.isArray(input.rawShares)) {
    return err(input.errorCode, 'sealedSigningRootSecretShares must be an array');
  }
  if (input.rawShares.length !== input.shareCount) {
    return err(input.errorCode, 'sealedSigningRootSecretShares must contain exactly three shares');
  }

  const seen = new Set<SigningRootSecretShareId>();
  const out: SealedSigningRootSecretShare[] = [];
  for (const raw of input.rawShares) {
    if (!isObject(raw)) return err(input.errorCode, 'sealed signing-root share is invalid');
    const shareId = normalizeSigningRootSecretShareId(raw.shareId);
    if (!shareId) return err(input.errorCode, 'sealed signing-root shareId is invalid');
    if (seen.has(shareId)) {
      return err(input.errorCode, 'sealedSigningRootSecretShares contain duplicate share ids');
    }
    seen.add(shareId);

    const sealedShare =
      raw.sealedShare instanceof Uint8Array
        ? new Uint8Array(raw.sealedShare)
        : typeof raw.sealedShareB64u === 'string'
          ? decodeSealedShareB64u(raw.sealedShareB64u)
          : null;
    if (!sealedShare || sealedShare.length === 0) {
      return err(input.errorCode, 'sealed signing-root share bytes are required');
    }

    const signingRootId = toOptionalTrimmedString(raw.signingRootId) || input.signingRootId;
    const signingRootVersion =
      toOptionalTrimmedString(raw.signingRootVersion) || input.signingRootVersion;
    if (signingRootId !== input.signingRootId || signingRootVersion !== input.signingRootVersion) {
      return err(input.errorCode, 'sealed signing-root share metadata mismatch');
    }

    out.push({
      signingRootId,
      signingRootVersion,
      shareId,
      sealedShare,
      ...(toOptionalTrimmedString(raw.storageId)
        ? { storageId: toOptionalTrimmedString(raw.storageId) }
        : {}),
      ...(toOptionalTrimmedString(raw.kekId) ? { kekId: toOptionalTrimmedString(raw.kekId) } : {}),
    });
  }

  if (seen.size < input.shareThreshold) {
    return err(input.errorCode, 'not enough unique signing-root shares');
  }
  return ok(out.sort((a, b) => a.shareId - b.shareId));
}

function validateMigrationBundleExtras(
  raw: Record<string, unknown>,
): SigningRootRecordResult<true> {
  if (validTimestampMs(raw.exportedAtMs) === null) {
    return err('invalid_migration_bundle', 'exportedAtMs must be a timestamp in milliseconds');
  }
  const walletInventory = raw.walletInventory;
  if (walletInventory === undefined) return ok(true);
  if (!Array.isArray(walletInventory)) {
    return err('invalid_migration_bundle', 'walletInventory must be an array when present');
  }
  for (const entry of walletInventory) {
    if (!isObject(entry))
      return err('invalid_migration_bundle', 'walletInventory entry is invalid');
    if (
      !toOptionalTrimmedString(entry.userId) ||
      !parseSigningRootAuthorityScope(entry.authorityScope) ||
      Object.prototype.hasOwnProperty.call(entry, 'rpId') ||
      !toOptionalTrimmedString(entry.walletKeyVersion) ||
      !toOptionalTrimmedString(entry.signingRootVersion)
    ) {
      return err('invalid_migration_bundle', 'walletInventory entry metadata is invalid');
    }
  }
  return ok(true);
}

export function createSigningRootMigrationWalletInventory(
  entries: readonly SigningRootMigrationWalletInventoryEntryV1[],
): SigningRootRecordResult<readonly SigningRootMigrationWalletInventoryEntryV1[]> {
  if (!Array.isArray(entries)) {
    return err('invalid_migration_bundle', 'walletInventory must be an array');
  }
  const out: SigningRootMigrationWalletInventoryEntryV1[] = [];
  for (const entry of entries) {
    if (!isObject(entry)) {
      return err('invalid_migration_bundle', 'walletInventory entry is invalid');
    }
    const userId = toOptionalTrimmedString(entry.userId);
    const authorityScope = parseSigningRootAuthorityScope(entry.authorityScope);
    const walletKeyVersion = toOptionalTrimmedString(entry.walletKeyVersion);
    const signingRootVersion = toOptionalTrimmedString(entry.signingRootVersion);
    if (
      !userId ||
      !authorityScope ||
      Object.prototype.hasOwnProperty.call(entry, 'rpId') ||
      !walletKeyVersion ||
      !signingRootVersion
    ) {
      return err('invalid_migration_bundle', 'walletInventory entry metadata is invalid');
    }
    const status = entry.status === 'retired' ? 'retired' : 'active';
    out.push({
      userId,
      authorityScope,
      walletKeyVersion,
      signingRootVersion,
      ...(toOptionalTrimmedString(entry.ecdsaThresholdKeyId)
        ? { ecdsaThresholdKeyId: toOptionalTrimmedString(entry.ecdsaThresholdKeyId) }
        : {}),
      ...(toOptionalTrimmedString(entry.thresholdEcdsaPublicKeyB64u)
        ? {
            thresholdEcdsaPublicKeyB64u: toOptionalTrimmedString(entry.thresholdEcdsaPublicKeyB64u),
          }
        : {}),
      ...(toOptionalTrimmedString(entry.ethereumAddress)
        ? { ethereumAddress: toOptionalTrimmedString(entry.ethereumAddress) }
        : {}),
      status,
    });
  }
  return ok(
    out.sort((a, b) =>
      `${a.userId}\0${a.authorityScope.rpId}\0${a.walletKeyVersion}`.localeCompare(
        `${b.userId}\0${b.authorityScope.rpId}\0${b.walletKeyVersion}`,
      ),
    ),
  );
}

function decodeSealedShareB64u(input: string): Uint8Array | null {
  try {
    return base64UrlDecode(input);
  } catch {
    return null;
  }
}

function parseSigningRootRecordBase(input: {
  readonly raw: unknown;
  readonly expectedVersion: string;
  readonly errorCode: 'invalid_signing_root_record' | 'invalid_migration_bundle';
  readonly source?: SigningRootRecordSource;
  readonly createdAtMs?: number;
  readonly updatedAtMs?: number;
}): SigningRootRecordResult<SigningRootRecord> {
  if (!isObject(input.raw)) return err(input.errorCode, 'signing-root record must be an object');
  if (toOptionalTrimmedString(input.raw.version) !== input.expectedVersion) {
    return err(input.errorCode, 'signing-root record version is unsupported');
  }

  const projectId = toOptionalTrimmedString(input.raw.projectId);
  const envId = toOptionalTrimmedString(input.raw.envId);
  const signingRootId =
    toOptionalTrimmedString(input.raw.signingRootId) ||
    (projectId && envId ? deriveSigningRootId({ projectId, envId }) : '');
  const walletOrigin = normalizeWalletOrigin(input.raw.walletOrigin);
  const authorityScope = parseSigningRootAuthorityScope(input.raw.authorityScope);
  const signingRootVersion = toOptionalTrimmedString(input.raw.signingRootVersion);
  const rootShareEpoch = validPositiveInteger(input.raw.rootShareEpoch);
  const derivationVersion = validPositiveInteger(input.raw.derivationVersion);
  const shareThreshold = input.raw.shareThreshold === 2 ? 2 : null;
  const shareCount = input.raw.shareCount === 3 ? 3 : null;
  const createdAtMs = input.createdAtMs ?? validTimestampMs(input.raw.createdAtMs);
  const updatedAtMs = input.updatedAtMs ?? validTimestampMs(input.raw.updatedAtMs);
  const source = input.source ?? parseSigningRootRecordSource(input.raw.source);

  if (
    !projectId ||
    !envId ||
    !signingRootId ||
    !walletOrigin ||
    !authorityScope ||
    Object.prototype.hasOwnProperty.call(input.raw, 'rpId') ||
    !signingRootVersion ||
    !rootShareEpoch ||
    !derivationVersion ||
    shareThreshold !== 2 ||
    shareCount !== 3 ||
    createdAtMs === null ||
    updatedAtMs === null ||
    !source
  ) {
    return err(input.errorCode, 'signing-root record metadata is invalid');
  }

  const shares = parseSigningRootSecretShareRecords({
    signingRootId,
    signingRootVersion,
    shareThreshold,
    shareCount,
    rawShares: input.raw.sealedSigningRootSecretShares,
    errorCode: input.errorCode,
  });
  if (!shares.ok) return shares;

  return ok({
    version: SIGNING_ROOT_RECORD_VERSION_V1,
    projectId,
    envId,
    signingRootId,
    walletOrigin,
    authorityScope,
    signingRootVersion,
    rootShareEpoch,
    shareThreshold,
    shareCount,
    sealedSigningRootSecretShares: shares.value,
    derivationVersion,
    createdAtMs,
    updatedAtMs,
    source,
  });
}

export function parseSigningRootRecord(raw: unknown): SigningRootRecordResult<SigningRootRecord> {
  return parseSigningRootRecordBase({
    raw,
    expectedVersion: SIGNING_ROOT_RECORD_VERSION_V1,
    errorCode: 'invalid_signing_root_record',
  });
}

export function signingRootRecordFromMigrationBundle(
  raw: unknown,
): SigningRootRecordResult<SigningRootRecord> {
  if (!isObject(raw)) return err('invalid_migration_bundle', 'migration bundle must be an object');
  const extras = validateMigrationBundleExtras(raw);
  if (!extras.ok) return extras;
  const nowMs = Date.now();
  return parseSigningRootRecordBase({
    raw,
    expectedVersion: SIGNING_ROOT_MIGRATION_BUNDLE_VERSION_V1,
    errorCode: 'invalid_migration_bundle',
    source: 'hosted-export',
    createdAtMs: nowMs,
    updatedAtMs: nowMs,
  });
}

export function signingRootRecordToMigrationBundle(
  record: SigningRootRecord,
  input: {
    readonly exportedAtMs: number;
    readonly exportActor?: string;
    readonly walletInventory?: readonly SigningRootMigrationWalletInventoryEntryV1[];
  },
): SigningRootMigrationBundleV1 {
  return {
    version: SIGNING_ROOT_MIGRATION_BUNDLE_VERSION_V1,
    projectId: record.projectId,
    envId: record.envId,
    signingRootId: record.signingRootId,
    walletOrigin: record.walletOrigin,
    authorityScope: record.authorityScope,
    signingRootVersion: record.signingRootVersion,
    rootShareEpoch: record.rootShareEpoch,
    shareThreshold: record.shareThreshold,
    shareCount: record.shareCount,
    derivationVersion: record.derivationVersion,
    sealedSigningRootSecretShares: record.sealedSigningRootSecretShares.map((share) => ({
      shareId: share.shareId,
      sealedShareB64u: base64UrlEncode(share.sealedShare),
      ...(share.storageId ? { storageId: share.storageId } : {}),
      ...(share.kekId ? { kekId: share.kekId } : {}),
    })),
    ...(input.walletInventory ? { walletInventory: input.walletInventory } : {}),
    exportedAtMs: input.exportedAtMs,
    ...(toOptionalTrimmedString(input.exportActor)
      ? { exportActor: toOptionalTrimmedString(input.exportActor) }
      : {}),
  };
}

export async function computeSigningRootContextHashB64u(
  record: SigningRootRecord,
): Promise<string> {
  const digest = await sha256BytesUtf8(
    alphabetizeStringify({
      version: 'signing_root_context_hash_v1',
      projectId: record.projectId,
      envId: record.envId,
      signingRootId: record.signingRootId,
      walletOrigin: record.walletOrigin,
      authorityScope: record.authorityScope,
      signingRootVersion: record.signingRootVersion,
      rootShareEpoch: record.rootShareEpoch,
      shareThreshold: record.shareThreshold,
      shareCount: record.shareCount,
      derivationVersion: record.derivationVersion,
      shareIds: record.sealedSigningRootSecretShares.map((share) => share.shareId).sort(),
    }),
  );
  return base64UrlEncode(digest);
}

export async function computeSigningRootMigrationBundleChecksumB64u(
  bundle: SigningRootMigrationBundleV1,
): Promise<string> {
  const digest = await sha256BytesUtf8(
    alphabetizeStringify({
      version: 'signing_root_migration_bundle_checksum_v1',
      bundle,
    }),
  );
  return base64UrlEncode(digest);
}

export async function createSigningRootMigrationExportArtifact(
  record: SigningRootRecord,
  input: {
    readonly exportedAtMs: number;
    readonly exportActor?: string;
    readonly walletInventory?: readonly SigningRootMigrationWalletInventoryEntryV1[];
  },
): Promise<SigningRootMigrationExportArtifactV1> {
  const bundle = signingRootRecordToMigrationBundle(record, input);
  return {
    version: SIGNING_ROOT_MIGRATION_EXPORT_ARTIFACT_VERSION_V1,
    bundle,
    checksumB64u: await computeSigningRootMigrationBundleChecksumB64u(bundle),
    createdAtMs: input.exportedAtMs,
  };
}
