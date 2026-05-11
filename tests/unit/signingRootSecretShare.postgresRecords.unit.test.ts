import { expect, test } from '@playwright/test';
import { base64UrlEncode } from '../../shared/src/utils/encoders';
import { parseCurrentSigningRootSecretShareRecord } from '../../server/src/core/ThresholdService/postgresRecords';

test.describe('signing root secret share postgres records', () => {
  test('parses only current signing-root secret share rows', () => {
    const sealedShare = new Uint8Array([1, 2, 3, 4]);

    expect(
      parseCurrentSigningRootSecretShareRecord({
        signing_root_id: 'signing-root',
        signing_root_version: 'default',
        share_id: 2,
        sealed_share_b64u: base64UrlEncode(sealedShare),
        storage_id: 'storage-id',
        kek_id: 'kek-id',
        created_at_ms: 100,
        updated_at_ms: 200,
      }),
    ).toEqual({
      signingRootId: 'signing-root',
      signingRootVersion: 'default',
      shareId: 2,
      sealedShare,
      storageId: 'storage-id',
      kekId: 'kek-id',
      createdAtMs: 100,
      updatedAtMs: 200,
    });

    expect(
      parseCurrentSigningRootSecretShareRecord({
        signing_root_id: 'signing-root',
        signing_root_version: '',
        share_id: 1,
        sealed_share_b64u: base64UrlEncode(sealedShare),
        created_at_ms: 100,
        updated_at_ms: 200,
      }),
    ).toEqual({
      signingRootId: 'signing-root',
      shareId: 1,
      sealedShare,
      createdAtMs: 100,
      updatedAtMs: 200,
    });

    expect(
      parseCurrentSigningRootSecretShareRecord({
        signing_root_id: 'signing-root',
        signing_root_version: 'default',
        share_id: 4,
        sealed_share_b64u: base64UrlEncode(sealedShare),
        created_at_ms: 100,
        updated_at_ms: 200,
      }),
    ).toBeNull();

    expect(
      parseCurrentSigningRootSecretShareRecord({
        signing_root_id: 'signing-root',
        signing_root_version: 'default',
        share_id: 1,
        sealed_share_b64u: '!!!not-b64u!!!',
        created_at_ms: 100,
        updated_at_ms: 200,
      }),
    ).toBeNull();

    expect(
      parseCurrentSigningRootSecretShareRecord({
        signing_root_id: 'signing-root',
        signing_root_version: 'default',
        share_id: 1,
        sealed_share_b64u: base64UrlEncode(sealedShare),
        created_at_ms: 200,
        updated_at_ms: 100,
      }),
    ).toBeNull();
  });
});
