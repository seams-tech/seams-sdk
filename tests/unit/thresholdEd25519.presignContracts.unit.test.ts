import { expect, test } from '@playwright/test';
import {
  parseThresholdEd25519FinalizeAndDispatchRequest,
  parseThresholdEd25519PresignRecord,
  parseThresholdEd25519PresignRefillRequest,
} from '../../packages/sdk-server-ts/src/core/ThresholdService/validation';
import {
  thresholdEd25519DelegateActionOperationFingerprint,
  thresholdEd25519NearTransactionOperationFingerprint,
  thresholdEd25519Nep413OperationFingerprint,
} from '@shared/threshold/ed25519OperationFingerprint';

const DIGEST_32_B64U = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

function runtimePolicyScope() {
  return {
    orgId: 'org-presign',
    projectId: 'project-presign',
    envId: 'test',
    signingRootVersion: 'root-v1',
  };
}

test.describe('threshold Ed25519 presign contracts', () => {
  test('canonical operation fingerprints use exact domain fields and strip unknown payload fields', async () => {
    const canonicalScope = {
      nearAccountId: 'alice.testnet',
      nearNetworkId: 'testnet',
      relayerKeyId: 'ed25519:relayer-key',
      signerPublicKey: 'ed25519:signer-key',
    };
    const nearInput = {
      ...canonicalScope,
      transactions: [
        {
          nearAccountId: 'alice.testnet',
          receiverId: 'receiver.testnet',
          actions: [{ action_type: 'Transfer', deposit: '1', ignored: 'transport-only' }],
          ignored: 'transport-only',
        },
      ],
      unsignedTransactionBorshB64u: 'unsigned-a',
      signingDigestB64u: DIGEST_32_B64U,
      ignored: 'transport-only',
    } as const;

    await expect(thresholdEd25519NearTransactionOperationFingerprint(nearInput)).resolves.toBe(
      await thresholdEd25519NearTransactionOperationFingerprint({
        ...canonicalScope,
        transactions: [
          {
            nearAccountId: 'alice.testnet',
            receiverId: 'receiver.testnet',
            actions: [{ action_type: 'Transfer', deposit: '1' }],
          },
        ],
        unsignedTransactionBorshB64u: 'unsigned-a',
        signingDigestB64u: DIGEST_32_B64U,
      }),
    );

    const baseNear = await thresholdEd25519NearTransactionOperationFingerprint(nearInput);
    await expect(
      thresholdEd25519NearTransactionOperationFingerprint({
        ...nearInput,
        nearNetworkId: 'mainnet',
      }),
    ).resolves.not.toBe(baseNear);
    await expect(
      thresholdEd25519NearTransactionOperationFingerprint({
        ...nearInput,
        signerPublicKey: 'ed25519:other-signer',
      }),
    ).resolves.not.toBe(baseNear);
    await expect(
      thresholdEd25519NearTransactionOperationFingerprint({
        ...nearInput,
        signingDigestB64u: 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB',
      }),
    ).resolves.not.toBe(baseNear);

    const baseNep413 = await thresholdEd25519Nep413OperationFingerprint({
      ...canonicalScope,
      message: 'hello',
      recipient: 'recipient.testnet',
      nonce: 'nonce',
      state: null,
    });
    await expect(
      thresholdEd25519Nep413OperationFingerprint({
        ...canonicalScope,
        relayerKeyId: 'ed25519:other-relayer',
        message: 'hello',
        recipient: 'recipient.testnet',
        nonce: 'nonce',
        state: null,
      }),
    ).resolves.not.toBe(baseNep413);

    const delegateWithExtraFields = {
      senderId: 'alice.testnet',
      receiverId: 'receiver.testnet',
      actions: [{ action_type: 'Transfer', deposit: '1', ignored: 'transport-only' }],
      nonce: '1',
      maxBlockHeight: '2',
      publicKey: 'ed25519:signer-key',
      ignored: 'transport-only',
    } as const;
    const baseDelegate = await thresholdEd25519DelegateActionOperationFingerprint({
      ...canonicalScope,
      delegate: delegateWithExtraFields,
    });
    await expect(
      thresholdEd25519DelegateActionOperationFingerprint({
        ...canonicalScope,
        delegate: {
          senderId: 'alice.testnet',
          receiverId: 'receiver.testnet',
          actions: [{ action_type: 'Transfer', deposit: '1' }],
          nonce: '1',
          maxBlockHeight: '2',
          publicKey: 'ed25519:signer-key',
        },
      }),
    ).resolves.toBe(baseDelegate);
  });

  test('parses presign refill requests at the route boundary', () => {
    const parsed = parseThresholdEd25519PresignRefillRequest({
      kind: 'threshold_ed25519_presign_refill_v1',
      relayerKeyId: 'relayer-key',
      nearAccountId: 'alice.testnet',
      nearNetworkId: 'testnet',
      expectedSignerPublicKey: 'ed25519-public-key',
      participantIds: [2, 1],
      clientPresigns: [
        {
          clientPresignId: 'client-presign-1',
          clientVerifyingShareB64u: 'client-verifying-share',
          clientCommitments: { hiding: 'client-hiding', binding: 'client-binding' },
        },
      ],
      requestTag: 'background_presign_pool_refill',
    });

    expect(parsed).toEqual({
      ok: true,
      value: {
        kind: 'threshold_ed25519_presign_refill_v1',
        relayerKeyId: 'relayer-key',
        nearAccountId: 'alice.testnet',
        nearNetworkId: 'testnet',
        expectedSignerPublicKey: 'ed25519-public-key',
        participantIds: [1, 2],
        clientPresigns: [
          {
            clientPresignId: 'client-presign-1',
            clientVerifyingShareB64u: 'client-verifying-share',
            clientCommitments: { hiding: 'client-hiding', binding: 'client-binding' },
          },
        ],
        requestTag: 'background_presign_pool_refill',
      },
    });

    expect(
      parseThresholdEd25519PresignRefillRequest({
        kind: 'threshold_ed25519_presign_refill_v1',
        clientPresigns: [],
      }),
    ).toMatchObject({ ok: false, code: 'invalid_body' });
  });

  test('parses finalize-and-dispatch request branches', () => {
    const signatureOnly = parseThresholdEd25519FinalizeAndDispatchRequest({
      kind: 'threshold_ed25519_finalize_signature_only_v1',
      operation: {
        kind: 'threshold_ed25519_signing_operation_v1',
        operationId: 'operation-1',
        operationFingerprint: 'fingerprint-1',
        purpose: 'nep413_message',
      },
      requestIntegrityHash: 'sha256:request-integrity-1',
      presignId: 'presign-1',
      relayerKeyId: 'relayer-key',
      nearAccountId: 'alice.testnet',
      nearNetworkId: 'testnet',
      expectedSignerPublicKey: 'ed25519-public-key',
      intent: {
        kind: 'nep413_message_v1',
        message: 'hello',
        recipient: 'recipient.testnet',
        nonce: 'nonce',
      },
      clientSignatureShareB64u: 'client-share',
    });

    expect(signatureOnly).toMatchObject({
      ok: true,
      value: {
        kind: 'threshold_ed25519_finalize_signature_only_v1',
        operation: { operationFingerprint: 'fingerprint-1' },
      },
    });

    const dispatch = parseThresholdEd25519FinalizeAndDispatchRequest({
      kind: 'threshold_ed25519_finalize_and_dispatch_near_tx_v1',
      operation: {
        kind: 'threshold_ed25519_signing_operation_v1',
        operationId: 'operation-2',
        operationFingerprint: 'fingerprint-2',
        purpose: 'near_transaction',
      },
      requestIntegrityHash: 'sha256:request-integrity-2',
      presignId: 'presign-2',
      relayerKeyId: 'relayer-key',
      nearAccountId: 'alice.testnet',
      nearNetworkId: 'testnet',
      expectedSignerPublicKey: 'ed25519-public-key',
      transactions: [{ nearAccountId: 'alice.testnet', receiverId: 'bob.testnet', actions: [] }],
      unsignedTransactionBorshB64u: 'unsigned-tx',
      signingDigestB64u: DIGEST_32_B64U,
      clientSignatureShareB64u: 'client-share',
      dispatch: { kind: 'near_rpc_configured_default_v1' },
    });

    expect(dispatch).toMatchObject({
      ok: true,
      value: {
        kind: 'threshold_ed25519_finalize_and_dispatch_near_tx_v1',
        dispatch: { kind: 'near_rpc_configured_default_v1' },
      },
    });

    expect(
      parseThresholdEd25519FinalizeAndDispatchRequest({
        kind: 'threshold_ed25519_finalize_signature_only_v1',
        operation: {
          kind: 'threshold_ed25519_signing_operation_v1',
          operationId: 'operation-legacy-digest',
          operationFingerprint: 'fingerprint-legacy-digest',
          purpose: 'nep413_message',
        },
        requestIntegrityHash: 'sha256:request-integrity-legacy',
        presignId: 'presign-legacy-digest',
        relayerKeyId: 'relayer-key',
        nearAccountId: 'alice.testnet',
        nearNetworkId: 'testnet',
        expectedSignerPublicKey: 'ed25519-public-key',
        signingDigestB64u: DIGEST_32_B64U,
        clientSignatureShareB64u: 'client-share',
      }),
    ).toMatchObject({
      ok: false,
      code: 'invalid_body',
      message: 'intent must be an object',
    });

    expect(
      parseThresholdEd25519FinalizeAndDispatchRequest({
        kind: 'threshold_ed25519_finalize_signature_only_v1',
        operation: {
          kind: 'threshold_ed25519_signing_operation_v1',
          operationId: 'operation-1',
          purpose: 'nep413_message',
        },
        signingDigestB64u: DIGEST_32_B64U,
      }),
    ).toMatchObject({ ok: false, code: 'invalid_body' });
  });

  test('parses current presign records only with complete scope', () => {
    const parsed = parseThresholdEd25519PresignRecord({
      kind: 'threshold_ed25519_presign_record_v1',
      expiresAtMs: 123_456,
      thresholdSessionId: 'threshold-session',
      walletSigningSessionId: 'wallet-signing-session',
      relayerKeyId: 'relayer-key',
      nearAccountId: 'alice.testnet',
      nearNetworkId: 'testnet',
      signerPublicKey: 'ed25519-public-key',
      rpcPolicyId: 'ed25519-presign-finalize',
      rpId: 'example.localhost',
      runtimePolicyScope: runtimePolicyScope(),
      protocolVersion: 'ed25519_frost_2p_presign_v1',
      participantIds: [2, 1],
      groupPublicKey: 'group-public-key',
      clientVerifyingShareB64u: 'client-verifying-share',
      clientCommitments: { hiding: 'client-hiding', binding: 'client-binding' },
      relayerCommitments: { hiding: 'relayer-hiding', binding: 'relayer-binding' },
      relayerVerifyingShareB64u: 'relayer-verifying-share',
      relayerNoncesB64u: 'relayer-nonces',
    });

    expect(parsed).toMatchObject({
      kind: 'threshold_ed25519_presign_record_v1',
      participantIds: [1, 2],
      runtimePolicyScope: runtimePolicyScope(),
    });

    expect(
      parseThresholdEd25519PresignRecord({
        kind: 'threshold_ed25519_presign_record_v1',
        expiresAtMs: 123_456,
      }),
    ).toBeNull();
  });
});
