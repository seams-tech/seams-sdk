import { expect, test } from '@playwright/test';
import { parseWebAuthnRpId, type WebAuthnRpId } from '../../packages/shared-ts/src/utils/domainIds';
import { base64UrlEncode } from '../../packages/shared-ts/src/utils/encoders';
import {
  SIGNING_ROOT_MIGRATION_BUNDLE_VERSION_V1,
  SIGNING_ROOT_MIGRATION_EXPORT_ARTIFACT_VERSION_V1,
  SIGNING_ROOT_RECORD_VERSION_V1,
  computeSigningRootContextHashB64u,
  computeSigningRootMigrationBundleChecksumB64u,
  createSigningRootMigrationExportArtifact,
  createSigningRootMigrationWalletInventory,
  parseSigningRootRecord,
  signingRootRecordFromMigrationBundle,
  signingRootRecordToMigrationBundle,
  type SigningRootMigrationBundleV1,
  type SigningRootRecord,
} from '../../packages/sdk-server-ts/src/core/ThresholdService/signingRootRecords';

function webAuthnRpId(value: string): WebAuthnRpId {
  const parsed = parseWebAuthnRpId(value);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

function passkeyAuthorityScope(rpId = 'wallet.example.test') {
  return { kind: 'passkey_rp', rpId: webAuthnRpId(rpId) } as const;
}

function sealedShareBytes(shareId: 1 | 2 | 3): Uint8Array {
  return new Uint8Array([shareId, 0xaa, 0xbb, 0xcc]);
}

function recordFixture(): SigningRootRecord {
  return {
    version: SIGNING_ROOT_RECORD_VERSION_V1,
    projectId: 'project-alpha',
    envId: 'dev',
    signingRootId: 'project-alpha:dev',
    walletOrigin: 'https://wallet.example.test',
    authorityScope: passkeyAuthorityScope(),
    signingRootVersion: 'root-v1',
    rootShareEpoch: 1,
    shareThreshold: 2,
    shareCount: 3,
    sealedSigningRootSecretShares: [1, 2, 3].map((shareId) => ({
      signingRootId: 'project-alpha:dev',
      signingRootVersion: 'root-v1',
      shareId: shareId as 1 | 2 | 3,
      sealedShare: sealedShareBytes(shareId as 1 | 2 | 3),
      storageId: `storage-${shareId}`,
      kekId: `kek-${shareId}`,
    })),
    derivationVersion: 1,
    createdAtMs: 10,
    updatedAtMs: 20,
    source: 'hosted-export',
  };
}

test('parseSigningRootRecord validates the self-host signing-root record shape', () => {
  const parsed = parseSigningRootRecord(recordFixture());

  expect(parsed.ok).toBe(true);
  if (!parsed.ok) throw new Error(parsed.message);
  expect(parsed.value.signingRootId).toBe('project-alpha:dev');
  expect(parsed.value.shareThreshold).toBe(2);
  expect(parsed.value.shareCount).toBe(3);
  expect(parsed.value.sealedSigningRootSecretShares.map((share) => share.shareId)).toEqual([1, 2, 3]);
  expect(parsed.value.sealedSigningRootSecretShares[0].sealedShare).not.toBe(
    recordFixture().sealedSigningRootSecretShares[0].sealedShare,
  );
});

test('parseSigningRootRecord rejects malformed signing-root records', () => {
  expect(parseSigningRootRecord({ ...recordFixture(), shareThreshold: 1 })).toMatchObject({
    ok: false,
    code: 'invalid_signing_root_record',
  });
  expect(parseSigningRootRecord({ ...recordFixture(), rpId: 'wallet.example.test' })).toMatchObject(
    {
      ok: false,
      code: 'invalid_signing_root_record',
    },
  );
  expect(
    parseSigningRootRecord({
      ...recordFixture(),
      sealedSigningRootSecretShares: [
        recordFixture().sealedSigningRootSecretShares[0],
        recordFixture().sealedSigningRootSecretShares[0],
        recordFixture().sealedSigningRootSecretShares[2],
      ],
    }),
  ).toMatchObject({
    ok: false,
    code: 'invalid_signing_root_record',
  });
});

test('signing-root migration bundle converts to runtime record and back', () => {
  const bundle = {
    version: SIGNING_ROOT_MIGRATION_BUNDLE_VERSION_V1,
    projectId: 'project-alpha',
    envId: 'dev',
    signingRootId: 'project-alpha:dev',
    walletOrigin: 'https://wallet.example.test',
    authorityScope: passkeyAuthorityScope(),
    signingRootVersion: 'root-v1',
    rootShareEpoch: 1,
    shareThreshold: 2,
    shareCount: 3,
    derivationVersion: 1,
    sealedSigningRootSecretShares: ([1, 2, 3] as const).map((shareId) => ({
      shareId,
      sealedShareB64u: base64UrlEncode(sealedShareBytes(shareId as 1 | 2 | 3)),
      storageId: `storage-${shareId}`,
      kekId: `kek-${shareId}`,
    })),
    exportedAtMs: 30,
    exportActor: 'admin@example.test',
    walletInventory: [
      {
        userId: 'alice.near',
        authorityScope: passkeyAuthorityScope(),
        walletKeyVersion: 'v1',
        signingRootVersion: 'root-v1',
        ethereumAddress: `0x${'11'.repeat(20)}`,
        status: 'active',
      },
    ],
  } satisfies SigningRootMigrationBundleV1;

  const record = signingRootRecordFromMigrationBundle(bundle);
  expect(record.ok).toBe(true);
  if (!record.ok) throw new Error(record.message);
  expect(record.value.source).toBe('hosted-export');
  expect(Array.from(record.value.sealedSigningRootSecretShares[1].sealedShare)).toEqual([
    2, 0xaa, 0xbb, 0xcc,
  ]);

  const roundTrip = signingRootRecordToMigrationBundle(record.value, {
    exportedAtMs: bundle.exportedAtMs,
    exportActor: bundle.exportActor,
    walletInventory: bundle.walletInventory,
  });
  expect(roundTrip.sealedSigningRootSecretShares.map((share) => share.shareId)).toEqual([1, 2, 3]);
  expect(roundTrip.walletInventory?.[0]?.userId).toBe('alice.near');
});

test('signing-root migration bundle rejects malformed export metadata', () => {
  const bundle = signingRootRecordToMigrationBundle(recordFixture(), {
    exportedAtMs: 30,
    walletInventory: [
      {
        userId: 'alice.near',
        authorityScope: passkeyAuthorityScope(),
        walletKeyVersion: 'v1',
        signingRootVersion: 'root-v1',
      },
    ],
  });

  expect(signingRootRecordFromMigrationBundle({ ...bundle, exportedAtMs: -1 })).toMatchObject({
    ok: false,
    code: 'invalid_migration_bundle',
  });
  expect(
    signingRootRecordFromMigrationBundle({ ...bundle, rpId: 'wallet.example.test' }),
  ).toMatchObject({
    ok: false,
    code: 'invalid_migration_bundle',
  });
  expect(
    signingRootRecordFromMigrationBundle({
      ...bundle,
      walletInventory: [{ userId: 'alice.near' }],
    }),
  ).toMatchObject({
    ok: false,
    code: 'invalid_migration_bundle',
  });
});

test('signing-root context hash is stable and excludes sealed share bytes', async () => {
  const first = recordFixture();
  const second = {
    ...recordFixture(),
    sealedSigningRootSecretShares: recordFixture().sealedSigningRootSecretShares.map((share) => ({
      ...share,
      sealedShare: new Uint8Array([share.shareId, 0xff]),
    })),
  };

  const firstHash = await computeSigningRootContextHashB64u(first);
  const secondHash = await computeSigningRootContextHashB64u(second);
  const changedContextHash = await computeSigningRootContextHashB64u({
    ...first,
    signingRootVersion: 'root-v2',
  });

  expect(firstHash).toBe(secondHash);
  expect(firstHash).not.toBe(changedContextHash);
});

test('signing-root migration bundle checksum is stable and covers exported bundle bytes', async () => {
  const bundle = signingRootRecordToMigrationBundle(recordFixture(), {
    exportedAtMs: 30,
    exportActor: 'admin@example.test',
    walletInventory: [
      {
        userId: 'alice.near',
        authorityScope: passkeyAuthorityScope(),
        walletKeyVersion: 'v1',
        signingRootVersion: 'root-v1',
      },
    ],
  });
  const reordered = {
    exportActor: bundle.exportActor,
    exportedAtMs: bundle.exportedAtMs,
    walletInventory: bundle.walletInventory,
    sealedSigningRootSecretShares: bundle.sealedSigningRootSecretShares,
    derivationVersion: bundle.derivationVersion,
    shareCount: bundle.shareCount,
    shareThreshold: bundle.shareThreshold,
    rootShareEpoch: bundle.rootShareEpoch,
    signingRootVersion: bundle.signingRootVersion,
    authorityScope: bundle.authorityScope,
    walletOrigin: bundle.walletOrigin,
    envId: bundle.envId,
    projectId: bundle.projectId,
    signingRootId: bundle.signingRootId,
    version: bundle.version,
  } satisfies SigningRootMigrationBundleV1;
  const modified = {
    ...bundle,
    sealedSigningRootSecretShares: [
      {
        ...bundle.sealedSigningRootSecretShares[0],
        sealedShareB64u: base64UrlEncode(new Uint8Array([0xff])),
      },
      ...bundle.sealedSigningRootSecretShares.slice(1),
    ],
  };

  await expect(computeSigningRootMigrationBundleChecksumB64u(bundle)).resolves.toBe(
    await computeSigningRootMigrationBundleChecksumB64u(reordered),
  );
  await expect(computeSigningRootMigrationBundleChecksumB64u(modified)).resolves.not.toBe(
    await computeSigningRootMigrationBundleChecksumB64u(bundle),
  );
});

test('signing-root migration export artifact packages bundle and checksum for hosted export tooling', async () => {
  const artifact = await createSigningRootMigrationExportArtifact(recordFixture(), {
    exportedAtMs: 30,
    exportActor: 'admin@example.test',
    walletInventory: [
      {
        userId: 'alice.near',
        authorityScope: passkeyAuthorityScope(),
        walletKeyVersion: 'v1',
        signingRootVersion: 'root-v1',
      },
    ],
  });

  expect(artifact.version).toBe(SIGNING_ROOT_MIGRATION_EXPORT_ARTIFACT_VERSION_V1);
  expect(artifact.createdAtMs).toBe(30);
  expect(artifact.bundle.signingRootId).toBe('project-alpha:dev');
  expect(artifact.bundle.walletInventory?.[0]?.userId).toBe('alice.near');
  await expect(computeSigningRootMigrationBundleChecksumB64u(artifact.bundle)).resolves.toBe(
    artifact.checksumB64u,
  );
});

test('signing-root wallet inventory export helper validates trims and sorts entries', () => {
  const inventory = createSigningRootMigrationWalletInventory([
    {
      userId: ' bob.near ',
      authorityScope: passkeyAuthorityScope(),
      walletKeyVersion: ' v2 ',
      signingRootVersion: ' root-v1 ',
      status: 'retired',
      ethereumAddress: ` 0x${'22'.repeat(20)} `,
    },
    {
      userId: 'alice.near',
      authorityScope: passkeyAuthorityScope(),
      walletKeyVersion: 'v1',
      signingRootVersion: 'root-v1',
      ecdsaThresholdKeyId: ' key-alpha ',
      thresholdEcdsaPublicKeyB64u: ' pub-alpha ',
    },
  ]);

  expect(inventory.ok).toBe(true);
  if (!inventory.ok) throw new Error(inventory.message);
  expect(inventory.value).toEqual([
    {
      userId: 'alice.near',
      authorityScope: passkeyAuthorityScope(),
      walletKeyVersion: 'v1',
      signingRootVersion: 'root-v1',
      ecdsaThresholdKeyId: 'key-alpha',
      thresholdEcdsaPublicKeyB64u: 'pub-alpha',
      status: 'active',
    },
    {
      userId: 'bob.near',
      authorityScope: passkeyAuthorityScope(),
      walletKeyVersion: 'v2',
      signingRootVersion: 'root-v1',
      ethereumAddress: `0x${'22'.repeat(20)}`,
      status: 'retired',
    },
  ]);

  expect(
    createSigningRootMigrationWalletInventory([
      {
        userId: '',
        authorityScope: passkeyAuthorityScope(),
        walletKeyVersion: 'v1',
        signingRootVersion: 'root-v1',
      },
    ]),
  ).toMatchObject({ ok: false, code: 'invalid_migration_bundle' });
});
