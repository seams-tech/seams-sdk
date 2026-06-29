import type { WebAuthnRpId } from '@shared/utils/domainIds';
import type {
  SigningRootMigrationBundleV1,
  SigningRootMigrationWalletInventoryEntryV1,
  SigningRootRecord,
} from './signingRootRecords';

declare const rpId: WebAuthnRpId;

const authorityScope = { kind: 'passkey_rp', rpId } as const;

const validSigningRootRecord: SigningRootRecord = {
  version: 'signing_root_record_v1',
  projectId: 'project-alpha',
  envId: 'dev',
  signingRootId: 'project-alpha:dev',
  walletOrigin: 'https://wallet.example.test',
  authorityScope,
  signingRootVersion: 'root-v1',
  rootShareEpoch: 1,
  shareThreshold: 2,
  shareCount: 3,
  sealedSigningRootSecretShares: [
    { signingRootId: 'project-alpha:dev', signingRootVersion: 'root-v1', shareId: 1, sealedShare: new Uint8Array([1]) },
    { signingRootId: 'project-alpha:dev', signingRootVersion: 'root-v1', shareId: 2, sealedShare: new Uint8Array([2]) },
    { signingRootId: 'project-alpha:dev', signingRootVersion: 'root-v1', shareId: 3, sealedShare: new Uint8Array([3]) },
  ],
  derivationVersion: 1,
  createdAtMs: 1,
  updatedAtMs: 1,
  source: 'hosted-export',
};

const invalidRootRpIdRecord: SigningRootRecord = {
  version: 'signing_root_record_v1',
  projectId: 'project-alpha',
  envId: 'dev',
  signingRootId: 'project-alpha:dev',
  walletOrigin: 'https://wallet.example.test',
  authorityScope,
  // @ts-expect-error signing-root records carry authorityScope, never root rpId.
  rpId: 'wallet.example.test',
  signingRootVersion: 'root-v1',
  rootShareEpoch: 1,
  shareThreshold: 2,
  shareCount: 3,
  sealedSigningRootSecretShares: [
    { signingRootId: 'project-alpha:dev', signingRootVersion: 'root-v1', shareId: 1, sealedShare: new Uint8Array([1]) },
    { signingRootId: 'project-alpha:dev', signingRootVersion: 'root-v1', shareId: 2, sealedShare: new Uint8Array([2]) },
    { signingRootId: 'project-alpha:dev', signingRootVersion: 'root-v1', shareId: 3, sealedShare: new Uint8Array([3]) },
  ],
  derivationVersion: 1,
  createdAtMs: 1,
  updatedAtMs: 1,
  source: 'hosted-export',
};

const validInventoryEntry: SigningRootMigrationWalletInventoryEntryV1 = {
  userId: 'alice.near',
  authorityScope,
  walletKeyVersion: 'wallet-key-v1',
  signingRootVersion: 'root-v1',
};

const invalidRootRpIdInventoryEntry: SigningRootMigrationWalletInventoryEntryV1 = {
  userId: 'alice.near',
  authorityScope,
  // @ts-expect-error signing-root wallet inventory carries authorityScope, never root rpId.
  rpId: 'wallet.example.test',
  walletKeyVersion: 'wallet-key-v1',
  signingRootVersion: 'root-v1',
};

const validBundle: SigningRootMigrationBundleV1 = {
  version: 'signing_root_migration_bundle_v1',
  projectId: 'project-alpha',
  envId: 'dev',
  signingRootId: 'project-alpha:dev',
  walletOrigin: 'https://wallet.example.test',
  authorityScope,
  signingRootVersion: 'root-v1',
  rootShareEpoch: 1,
  shareThreshold: 2,
  shareCount: 3,
  derivationVersion: 1,
  sealedSigningRootSecretShares: [
    { shareId: 1, sealedShareB64u: 'AQ' },
    { shareId: 2, sealedShareB64u: 'Ag' },
    { shareId: 3, sealedShareB64u: 'Aw' },
  ],
  walletInventory: [validInventoryEntry],
  exportedAtMs: 1,
};

const invalidRootRpIdBundle: SigningRootMigrationBundleV1 = {
  version: 'signing_root_migration_bundle_v1',
  projectId: 'project-alpha',
  envId: 'dev',
  signingRootId: 'project-alpha:dev',
  walletOrigin: 'https://wallet.example.test',
  authorityScope,
  // @ts-expect-error signing-root migration bundles carry authorityScope, never root rpId.
  rpId: 'wallet.example.test',
  signingRootVersion: 'root-v1',
  rootShareEpoch: 1,
  shareThreshold: 2,
  shareCount: 3,
  derivationVersion: 1,
  sealedSigningRootSecretShares: [
    { shareId: 1, sealedShareB64u: 'AQ' },
    { shareId: 2, sealedShareB64u: 'Ag' },
    { shareId: 3, sealedShareB64u: 'Aw' },
  ],
  walletInventory: [validInventoryEntry],
  exportedAtMs: 1,
};

void validSigningRootRecord;
void invalidRootRpIdRecord;
void validInventoryEntry;
void invalidRootRpIdInventoryEntry;
void validBundle;
void invalidRootRpIdBundle;
