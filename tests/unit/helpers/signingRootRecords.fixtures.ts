import { parseWebAuthnRpId } from '../../../packages/shared-ts/src/utils/domainIds';
import {
  SIGNING_ROOT_RECORD_VERSION_V1,
  parseSigningRootRecord,
  signingRootRecordToMigrationBundle,
  type SigningRootAuthorityScope,
  type SigningRootMigrationBundleV1,
  type SigningRootMigrationWalletInventoryEntryV1,
  type SigningRootRecord,
} from '../../../packages/sdk-server-ts/src/core/ThresholdService/signingRootRecords';

export function seedSigningRootAuthorityScope(
  rpId = 'wallet.example.test',
): SigningRootAuthorityScope {
  const parsed = parseWebAuthnRpId(rpId);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return { kind: 'passkey_rp', rpId: parsed.value };
}

/**
 * Self-host signing-root record validated through the production
 * `parseSigningRootRecord` parser, so the fixture cannot drift from the
 * current record schema. Overrides apply before validation.
 */
export function seedSigningRootRecord(
  overrides: Partial<SigningRootRecord> = {},
): SigningRootRecord {
  const record: SigningRootRecord = {
    version: SIGNING_ROOT_RECORD_VERSION_V1,
    projectId: 'project-alpha',
    envId: 'dev',
    signingRootId: 'project-alpha:dev',
    walletOrigin: 'https://wallet.example.test',
    authorityScope: seedSigningRootAuthorityScope(),
    signingRootVersion: 'root-v1',
    rootShareEpoch: 1,
    shareThreshold: 2,
    shareCount: 3,
    sealedSigningRootSecretShares: ([1, 2, 3] as const).map((shareId) => ({
      signingRootId: 'project-alpha:dev',
      signingRootVersion: 'root-v1',
      shareId,
      sealedShare: new Uint8Array([shareId, 0xaa, 0xbb, 0xcc]),
      storageId: `storage-${shareId}`,
      kekId: `kek-${shareId}`,
    })),
    derivationVersion: 1,
    createdAtMs: 10,
    updatedAtMs: 20,
    source: 'hosted-export',
    ...overrides,
  };
  const parsed = parseSigningRootRecord(record);
  if (!parsed.ok) {
    throw new Error(`seedSigningRootRecord produced an invalid record: ${parsed.message}`);
  }
  return parsed.value;
}

/**
 * Signing-root migration bundle built through the production
 * `signingRootRecordToMigrationBundle` serializer from a seeded (or supplied)
 * signing-root record.
 */
export function seedSigningRootMigrationBundle(
  args: {
    record?: SigningRootRecord;
    exportedAtMs?: number;
    exportActor?: string;
    walletInventory?: readonly SigningRootMigrationWalletInventoryEntryV1[];
  } = {},
): SigningRootMigrationBundleV1 {
  return signingRootRecordToMigrationBundle(args.record ?? seedSigningRootRecord(), {
    exportedAtMs: args.exportedAtMs ?? 30,
    ...(args.exportActor !== undefined ? { exportActor: args.exportActor } : {}),
    ...(args.walletInventory ? { walletInventory: args.walletInventory } : {}),
  });
}
