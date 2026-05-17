import { expect, test } from '@playwright/test';
import {
  parseCurrentThresholdEcdsaKeyRecord,
  parseCurrentThresholdEcdsaPresignSessionRow,
  parseCurrentThresholdEcdsaPresignatureRecord,
  parseCurrentThresholdEcdsaSigningSessionRow,
  parseCurrentThresholdEd25519KeyRecord,
} from '../../server/src/core/ThresholdService/postgresRecords';
import { createThresholdEcdsaKeyStore } from '../../server/src/core/ThresholdService/stores/KeyStore';
import { normalizeLogger } from '../../server/src/core/logger';

function makeThresholdEcdsaIntegratedKeyRecord(
  overrides: Record<string, unknown> = {},
): NonNullable<ReturnType<typeof parseCurrentThresholdEcdsaKeyRecord>> {
  const record = parseCurrentThresholdEcdsaKeyRecord({
    version: 'threshold_ecdsa_hss_key_v1',
    ecdsaThresholdKeyId: 'threshold-key',
    walletSessionUserId: 'alice.testnet',
    subjectId: 'wallet-subject-alice',
    rpId: 'example.localhost',
    schemeId: 'scheme-v1',
    clientVerifyingShareB64u: 'client-share',
    thresholdEcdsaPublicKeyB64u: 'public-key',
    ethereumAddress: '0x1111111111111111111111111111111111111111',
    signingRootId: 'signing-root',
    signingRootVersion: 'default',
    walletKeyVersion: 'wallet-key-v1',
    derivationVersion: 1,
    participantIds: [2, 1],
    relayerRootShare32B64u: 'root-share',
    relayerBackendInputB64u: 'backend-input',
    createdAtMs: 100,
    updatedAtMs: 200,
    ...overrides,
  });
  if (!record) throw new Error('test fixture must be a current threshold ECDSA key record');
  return record;
}

test.describe('threshold ecdsa postgres records', () => {
  test('parses only current key records', () => {
    expect(
      parseCurrentThresholdEd25519KeyRecord({
        nearAccountId: 'alice.testnet',
        rpId: 'example.localhost',
        publicKey: 'ed25519:public',
        relayerSigningShareB64u: 'signing-share',
        relayerVerifyingShareB64u: 'verifying-share',
        keyVersion: 'key-v1',
        recoveryExportCapable: true,
      }),
    ).toEqual({
      nearAccountId: 'alice.testnet',
      rpId: 'example.localhost',
      publicKey: 'ed25519:public',
      relayerSigningShareB64u: 'signing-share',
      relayerVerifyingShareB64u: 'verifying-share',
      keyVersion: 'key-v1',
      recoveryExportCapable: true,
    });

    expect(
      parseCurrentThresholdEcdsaKeyRecord({
        version: 'threshold_ecdsa_hss_key_v1',
        ecdsaThresholdKeyId: 'threshold-key',
        walletSessionUserId: 'alice.testnet',
        subjectId: 'alice.testnet',
        chainTarget: { kind: 'evm', namespace: 'eip155', chainId: 11155111 },
        rpId: 'example.localhost',
        schemeId: 'scheme-v1',
        clientVerifyingShareB64u: 'client-share',
        thresholdEcdsaPublicKeyB64u: 'public-key',
        ethereumAddress: '0x1234',
        signingRootId: 'signing-root',
        walletKeyVersion: 'wallet-key-v1',
        derivationVersion: 1,
        participantIds: [2, 1],
        relayerRootShare32B64u: 'root-share',
        relayerBackendInputB64u: 'backend-input',
        createdAtMs: 100,
        updatedAtMs: 200,
      }),
    ).toEqual({
      version: 'threshold_ecdsa_hss_key_v1',
      ecdsaThresholdKeyId: 'threshold-key',
      walletSessionUserId: 'alice.testnet',
      subjectId: 'alice.testnet',
      rpId: 'example.localhost',
      schemeId: 'scheme-v1',
      clientVerifyingShareB64u: 'client-share',
      thresholdEcdsaPublicKeyB64u: 'public-key',
      ethereumAddress: '0x1234',
      signingRootId: 'signing-root',
      walletKeyVersion: 'wallet-key-v1',
      derivationVersion: 1,
      participantIds: [1, 2],
      relayerRootShare32B64u: 'root-share',
      relayerBackendInputB64u: 'backend-input',
      createdAtMs: 100,
      updatedAtMs: 200,
    });

    expect(
      parseCurrentThresholdEcdsaKeyRecord({
        version: 'threshold_ecdsa_hss_key_v1',
        ecdsaThresholdKeyId: 'threshold-key',
        walletSessionUserId: 'alice.testnet',
        subjectId: 'alice.testnet',
        chainTarget: { kind: 'evm', namespace: 'eip155', chainId: 11155111 },
        rpId: 'example.localhost',
        schemeId: 'scheme-v1',
        clientVerifyingShareB64u: 'client-share',
        thresholdEcdsaPublicKeyB64u: 'public-key',
        ethereumAddress: '0x1234',
        signingRootId: 'signing-root',
        walletKeyVersion: 'wallet-key-v1',
        derivationVersion: 1,
        relayerRootShare32B64u: 'root-share',
        relayerBackendInputB64u: 'backend-input',
        createdAtMs: 100,
        updatedAtMs: 200,
      }),
    ).toBeNull();
  });

  test('rejects malformed signing session rows', () => {
    expect(
      parseCurrentThresholdEcdsaSigningSessionRow({
        recordJson: {
          expiresAtMs: 123_456,
          mpcSessionId: 'mpc-session',
          relayerKeyId: 'relayer-key',
          ecdsaThresholdKeyId: 'threshold-key',
          thresholdEcdsaPublicKeyB64u: 'public-key',
          signingDigestB64u: 'digest',
          userId: 'alice.testnet',
          rpId: 'example.localhost',
          clientVerifyingShareB64u: 'client-share',
          participantIds: [2, 1],
          presignatureId: 'presignature',
          entropyB64u: 'entropy',
          signingRootId: 'signing-root',
          walletKeyVersion: 'wallet-key-v1',
          derivationVersion: 1,
        },
        expiresAtMs: 123_456,
      }),
    ).toEqual({
      record: {
        expiresAtMs: 123_456,
        mpcSessionId: 'mpc-session',
        relayerKeyId: 'relayer-key',
        ecdsaThresholdKeyId: 'threshold-key',
        thresholdEcdsaPublicKeyB64u: 'public-key',
        signingDigestB64u: 'digest',
        walletSessionUserId: 'alice.testnet',
        rpId: 'example.localhost',
        clientVerifyingShareB64u: 'client-share',
        participantIds: [1, 2],
        presignatureId: 'presignature',
        entropyB64u: 'entropy',
        signingRootId: 'signing-root',
        walletKeyVersion: 'wallet-key-v1',
        derivationVersion: 1,
      },
      expiresAtMs: 123_456,
    });

    expect(
      parseCurrentThresholdEcdsaSigningSessionRow({
        recordJson: {
          expiresAtMs: 123_456,
          mpcSessionId: 'mpc-session',
          relayerKeyId: 'relayer-key',
          ecdsaThresholdKeyId: 'threshold-key',
          thresholdEcdsaPublicKeyB64u: 'public-key',
          signingDigestB64u: 'digest',
          userId: 'alice.testnet',
          rpId: 'example.localhost',
          clientVerifyingShareB64u: 'client-share',
          presignatureId: 'presignature',
          entropyB64u: 'entropy',
          signingRootId: 'signing-root',
          walletKeyVersion: 'wallet-key-v1',
          derivationVersion: 1,
        },
        expiresAtMs: 123_456,
      }),
    ).toBeNull();

    expect(
      parseCurrentThresholdEcdsaSigningSessionRow({
        recordJson: {
          expiresAtMs: 123_456,
          mpcSessionId: 'mpc-session',
          relayerKeyId: 'relayer-key',
          ecdsaThresholdKeyId: 'threshold-key',
          thresholdEcdsaPublicKeyB64u: 'public-key',
          signingDigestB64u: 'digest',
          userId: 'alice.testnet',
          rpId: 'example.localhost',
          clientVerifyingShareB64u: 'client-share',
          participantIds: [1, 2],
          presignatureId: 'presignature',
          entropyB64u: 'entropy',
          signingRootId: 'signing-root',
          walletKeyVersion: 'wallet-key-v1',
          derivationVersion: 1,
        },
        expiresAtMs: 123_457,
      }),
    ).toBeNull();
  });

  test('rejects malformed presign session rows and presignatures', () => {
    expect(
      parseCurrentThresholdEcdsaPresignSessionRow({
        recordJson: {
          expiresAtMs: 999_999,
          userId: 'alice.testnet',
          rpId: 'example.localhost',
          relayerKeyId: 'relayer-key',
          participantIds: [2, 1],
          clientParticipantId: 1,
          relayerParticipantId: 2,
          stage: 'triples',
          version: 1,
          createdAtMs: 100,
          updatedAtMs: 150,
          signingRootId: 'signing-root',
          walletKeyVersion: 'wallet-key-v1',
          derivationVersion: 1,
        },
        expiresAtMs: 999_999,
      }),
    ).toEqual({
      record: {
        expiresAtMs: 999_999,
        walletSessionUserId: 'alice.testnet',
        rpId: 'example.localhost',
        relayerKeyId: 'relayer-key',
        participantIds: [1, 2],
        clientParticipantId: 1,
        relayerParticipantId: 2,
        stage: 'triples',
        version: 1,
        createdAtMs: 100,
        updatedAtMs: 150,
        signingRootId: 'signing-root',
        walletKeyVersion: 'wallet-key-v1',
        derivationVersion: 1,
      },
      expiresAtMs: 999_999,
    });

    expect(
      parseCurrentThresholdEcdsaPresignSessionRow({
        recordJson: {
          expiresAtMs: 999_999,
          userId: 'alice.testnet',
          rpId: 'example.localhost',
          relayerKeyId: 'relayer-key',
          participantIds: [1, 2],
          clientParticipantId: 1,
          relayerParticipantId: 2,
          stage: 'triples',
          version: 1,
          createdAtMs: 100,
          updatedAtMs: 99,
          signingRootId: 'signing-root',
          walletKeyVersion: 'wallet-key-v1',
          derivationVersion: 1,
        },
        expiresAtMs: 999_999,
      }),
    ).toBeNull();

    expect(
      parseCurrentThresholdEcdsaPresignatureRecord({
        relayerKeyId: 'relayer-key',
        presignatureId: 'presignature',
        bigRB64u: 'big-r',
        kShareB64u: 'k-share',
        sigmaShareB64u: 'sigma-share',
        createdAtMs: 123,
      }),
    ).toEqual({
      relayerKeyId: 'relayer-key',
      presignatureId: 'presignature',
      bigRB64u: 'big-r',
      kShareB64u: 'k-share',
      sigmaShareB64u: 'sigma-share',
      createdAtMs: 123,
    });

    expect(
      parseCurrentThresholdEcdsaPresignatureRecord({
        relayerKeyId: 'relayer-key',
        presignatureId: 'presignature',
        bigRB64u: 'big-r',
        kShareB64u: 'k-share',
        sigmaShareB64u: 'sigma-share',
        createdAtMs: 0,
      }),
    ).toBeNull();
  });

  test('server key store rejects a second shared EVM-family key identity', async () => {
    const store = createThresholdEcdsaKeyStore({
      config: { kind: 'in-memory' },
      logger: normalizeLogger(null),
      isNode: true,
    });
    const first = makeThresholdEcdsaIntegratedKeyRecord({
      signingRootId: 'server-shared-root',
    });
    await store.put(first.ecdsaThresholdKeyId, first);

    const conflicting = makeThresholdEcdsaIntegratedKeyRecord({
      ecdsaThresholdKeyId: 'threshold-key-conflict',
      signingRootId: 'server-shared-root',
      updatedAtMs: 201,
    });
    await expect(store.put(conflicting.ecdsaThresholdKeyId, conflicting)).rejects.toThrow(
      /EVM-family key identity/,
    );
  });
});
