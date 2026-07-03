import { expect, test } from '@playwright/test';
import {
  parseCurrentThresholdEd25519StoreSessionRow,
  parseCurrentThresholdEd25519SessionRecord,
  parseCurrentThresholdEd25519SessionStatusRow,
} from '../../packages/sdk-server-ts/src/core/ThresholdService/persistedRecords';

const authorityScope = { kind: 'passkey_rp' as const, rpId: 'example.localhost' };

test.describe('threshold ed25519 persisted records', () => {
  test('parses current session records only when participant ids are explicit', () => {
    const parsed = parseCurrentThresholdEd25519SessionRecord({
      expiresAtMs: 123_456,
      relayerKeyId: 'relayer-key',
      userId: 'alice.testnet',
      walletId: 'wallet-ed25519',
      nearAccountId: 'alice.testnet',
      nearEd25519SigningKeyId: 'alice.testnet',
      authorityScope,
      participantIds: [2, 1],
      signingRootId: 'signing-root',
      walletKeyVersion: 'wallet-key-v1',
      derivationVersion: 1,
    });

    expect(parsed).toEqual({
      expiresAtMs: 123_456,
      relayerKeyId: 'relayer-key',
      userId: 'alice.testnet',
      walletId: 'wallet-ed25519',
      nearAccountId: 'alice.testnet',
      nearEd25519SigningKeyId: 'alice.testnet',
      authorityScope,
      participantIds: [1, 2],
      signingRootId: 'signing-root',
      walletKeyVersion: 'wallet-key-v1',
      derivationVersion: 1,
    });

    expect(
      parseCurrentThresholdEd25519SessionRecord({
        expiresAtMs: 123_456,
        relayerKeyId: 'relayer-key',
        userId: 'alice.testnet',
        authorityScope,
      }),
    ).toBeNull();
  });

  test('rejects malformed session status rows', () => {
    expect(
      parseCurrentThresholdEd25519SessionStatusRow({
        recordJson: {
          expiresAtMs: 123_456,
          relayerKeyId: 'relayer-key',
          userId: 'alice.testnet',
          walletId: 'wallet-ed25519',
          nearAccountId: 'alice.testnet',
          nearEd25519SigningKeyId: 'alice.testnet',
          authorityScope,
          participantIds: [1, 2],
        },
        expiresAtMs: 123_456,
        remainingUses: 0,
      }),
    ).toEqual({
      record: {
        expiresAtMs: 123_456,
        relayerKeyId: 'relayer-key',
        userId: 'alice.testnet',
        walletId: 'wallet-ed25519',
        nearAccountId: 'alice.testnet',
        nearEd25519SigningKeyId: 'alice.testnet',
        authorityScope,
        participantIds: [1, 2],
      },
      expiresAtMs: 123_456,
      remainingUses: 0,
    });

    expect(
      parseCurrentThresholdEd25519SessionStatusRow({
        recordJson: {
          expiresAtMs: 123_456,
          relayerKeyId: 'relayer-key',
          userId: 'alice.testnet',
          walletId: 'wallet-ed25519',
          nearAccountId: 'alice.testnet',
          nearEd25519SigningKeyId: 'alice.testnet',
          authorityScope,
          participantIds: [1, 2],
        },
        expiresAtMs: 999_999,
        remainingUses: 0,
      }),
    ).toBeNull();

    expect(
      parseCurrentThresholdEd25519SessionStatusRow({
        recordJson: {
          expiresAtMs: 123_456,
          relayerKeyId: 'relayer-key',
          userId: 'alice.testnet',
          walletId: 'wallet-ed25519',
          nearAccountId: 'alice.testnet',
          nearEd25519SigningKeyId: 'alice.testnet',
          authorityScope,
          participantIds: [1, 2],
        },
        expiresAtMs: 123_456,
        remainingUses: -1,
      }),
    ).toBeNull();
  });

  test('parses only current mpc, signing, and coordinator store session rows', () => {
    expect(
      parseCurrentThresholdEd25519StoreSessionRow({
        kind: 'mpc',
        recordJson: {
          expiresAtMs: 456_789,
          relayerKeyId: 'relayer-key',
          purpose: 'sign',
          intentDigestB64u: 'intent',
          signingDigestB64u: 'digest',
          userId: 'alice.testnet',
          authorityScope,
          participantIds: [2, 1],
        },
        expiresAtMs: 456_789,
      }),
    ).toEqual({
      kind: 'mpc',
      record: {
        expiresAtMs: 456_789,
        relayerKeyId: 'relayer-key',
        purpose: 'sign',
        intentDigestB64u: 'intent',
        signingDigestB64u: 'digest',
        userId: 'alice.testnet',
        authorityScope,
        participantIds: [1, 2],
      },
      expiresAtMs: 456_789,
    });

    expect(
      parseCurrentThresholdEd25519StoreSessionRow({
        kind: 'signing',
        recordJson: {
          expiresAtMs: 456_789,
          mpcSessionId: 'mpc-session',
          relayerKeyId: 'relayer-key',
          signingDigestB64u: 'digest',
          userId: 'alice.testnet',
          authorityScope,
          commitmentsById: {
            '1': { hiding: 'h1', binding: 'b1' },
          },
          relayerNoncesB64u: 'nonces',
          participantIds: [1, 2],
        },
        expiresAtMs: 456_789,
      }),
    ).toEqual({
      kind: 'signing',
      record: {
        expiresAtMs: 456_789,
        mpcSessionId: 'mpc-session',
        relayerKeyId: 'relayer-key',
        signingDigestB64u: 'digest',
        userId: 'alice.testnet',
        authorityScope,
        commitmentsById: {
          '1': { hiding: 'h1', binding: 'b1' },
        },
        signingShare: { kind: 'key_store' },
        relayerNoncesB64u: 'nonces',
        participantIds: [1, 2],
      },
      expiresAtMs: 456_789,
    });

    expect(
      parseCurrentThresholdEd25519StoreSessionRow({
        kind: 'signing',
        recordJson: {
          expiresAtMs: 456_789,
          mpcSessionId: 'mpc-session',
          relayerKeyId: 'relayer-key',
          signingDigestB64u: 'digest',
          userId: 'alice.testnet',
          authorityScope,
          commitmentsById: {
            '1': { hiding: 'h1', binding: 'b1' },
          },
          relayerSigningShareB64u: 'signing-share',
          relayerNoncesB64u: 'nonces',
          participantIds: [1, 2],
        },
        expiresAtMs: 456_789,
      }),
    ).toEqual({
      kind: 'signing',
      record: {
        expiresAtMs: 456_789,
        mpcSessionId: 'mpc-session',
        relayerKeyId: 'relayer-key',
        signingDigestB64u: 'digest',
        userId: 'alice.testnet',
        authorityScope,
        commitmentsById: {
          '1': { hiding: 'h1', binding: 'b1' },
        },
        signingShare: {
          kind: 'embedded_cosigner_share',
          relayerSigningShareB64u: 'signing-share',
        },
        relayerNoncesB64u: 'nonces',
        participantIds: [1, 2],
      },
      expiresAtMs: 456_789,
    });

    expect(
      parseCurrentThresholdEd25519StoreSessionRow({
        kind: 'coordinator',
        recordJson: {
          mode: 'cosigner',
          expiresAtMs: 456_789,
          mpcSessionId: 'mpc-session',
          relayerKeyId: 'relayer-key',
          signingDigestB64u: 'digest',
          userId: 'alice.testnet',
          authorityScope,
          commitmentsById: {
            '1': { hiding: 'h1', binding: 'b1' },
          },
          participantIds: [2, 1],
          groupPublicKey: 'group-public-key',
          cosignerIds: [2, 3],
          cosignerRelayerUrlsById: {
            '2': 'https://cosigner-2.example',
          },
          cosignerCoordinatorGrantsById: {
            '2': 'grant-2',
          },
          relayerVerifyingSharesById: {
            '2': 'verifying-share-2',
          },
        },
        expiresAtMs: 456_789,
      }),
    ).toEqual({
      kind: 'coordinator',
      record: {
        mode: 'cosigner',
        expiresAtMs: 456_789,
        mpcSessionId: 'mpc-session',
        relayerKeyId: 'relayer-key',
        signingDigestB64u: 'digest',
        userId: 'alice.testnet',
        authorityScope,
        commitmentsById: {
          '1': { hiding: 'h1', binding: 'b1' },
        },
        participantIds: [1, 2],
        groupPublicKey: 'group-public-key',
        cosignerIds: [2, 3],
        cosignerRelayerUrlsById: {
          '2': 'https://cosigner-2.example',
        },
        cosignerCoordinatorGrantsById: {
          '2': 'grant-2',
        },
        relayerVerifyingSharesById: {
          '2': 'verifying-share-2',
        },
      },
      expiresAtMs: 456_789,
    });

    expect(
      parseCurrentThresholdEd25519StoreSessionRow({
        kind: 'mpc',
        recordJson: {
          expiresAtMs: 456_789,
          relayerKeyId: 'relayer-key',
          purpose: 'sign',
          intentDigestB64u: 'intent',
          signingDigestB64u: 'digest',
          userId: 'alice.testnet',
          authorityScope,
        },
        expiresAtMs: 456_789,
      }),
    ).toBeNull();

    expect(
      parseCurrentThresholdEd25519StoreSessionRow({
        kind: 'signing',
        recordJson: {
          expiresAtMs: 456_789,
          mpcSessionId: 'mpc-session',
          relayerKeyId: 'relayer-key',
          signingDigestB64u: 'digest',
          userId: 'alice.testnet',
          authorityScope,
          commitmentsById: {
            '1': { hiding: 'h1', binding: 'b1' },
          },
          relayerNoncesB64u: 'nonces',
          participantIds: [1, 2],
        },
        expiresAtMs: 456_790,
      }),
    ).toBeNull();
  });
});
