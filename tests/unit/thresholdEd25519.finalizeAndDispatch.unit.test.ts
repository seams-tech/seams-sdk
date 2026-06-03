import { expect, test } from '@playwright/test';
import bs58 from 'bs58';
import { createRelayRouter } from '@server/router/express-adaptor';
import { signerBoundWalletSigningBudgetSessionId } from '@server/core/ThresholdService/walletSigningBudget';
import { THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID } from '@server/core/ThresholdService/schemes/schemeIds';
import type { ThresholdEd25519FinalizeSignatureOnlyRequest } from '@server/core/types';
import type { ThresholdEd25519PresignRecord } from '@server/core/ThresholdService/stores/SessionStore';
import type { ThresholdEd25519SessionClaims } from '@server/core/ThresholdService/validation';
import { base64UrlEncode } from '@shared/utils/encoders';
import {
  thresholdEd25519DelegateActionOperationFingerprint,
  thresholdEd25519FinalizeRequestIntegrityHash,
  type ThresholdEd25519NearAction,
  type ThresholdEd25519NearTransaction,
  thresholdEd25519NearTransactionOperationFingerprint,
  thresholdEd25519Nep413OperationFingerprint,
} from '@shared/threshold/ed25519OperationFingerprint';
import {
  createThresholdSigningServiceForUnitTests,
  deriveThresholdEd25519VerifyingShareForUnitTests,
} from '../helpers/thresholdEd25519TestUtils';
import {
  fetchJson,
  makeFakeAuthService,
  makeSessionAdapter,
  startExpressRouter,
} from '../relayer/helpers';
import {
  threshold_ed25519_build_near_tx_unsigned_borsh,
  threshold_ed25519_client_presign_create,
  threshold_ed25519_client_presign_sign,
  threshold_ed25519_compute_delegate_signing_digest,
  threshold_ed25519_compute_nep413_signing_digest,
  threshold_ed25519_keygen_from_client_verifying_share,
  threshold_ed25519_round1_commit,
} from '../../wasm/near_signer/pkg/wasm_signer_worker.js';

const SESSION_ID = 'threshold-session-finalize';
const WALLET_SIGNING_SESSION_ID = 'wallet-signing-session-finalize';
const WALLET_ID = 'alice.testnet';
const RP_ID = 'wallet.example.test';
const RELAYER_KEY_ID = 'relayer-ed25519-finalize';
const SIGNER_PUBLIC_KEY = 'ed25519:86mqiBdv45gM4c5uLmvT3TU4g7DAg6KLpuabBSFweigm';
const SIGNING_DIGEST_B64U = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const RELAYER_SIGNING_SHARE_B64U = 'BwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const CLIENT_BASE_B64U = base64UrlEncode(new Uint8Array([5, ...new Array(31).fill(0)]));
const WALLET_BUDGET_SESSION_ID = signerBoundWalletSigningBudgetSessionId({
  walletSigningSessionId: WALLET_SIGNING_SESSION_ID,
  curve: 'ed25519',
  thresholdSessionId: SESSION_ID,
});
type SignatureOnlyIntent = ThresholdEd25519FinalizeSignatureOnlyRequest['intent'];

const DEFAULT_NEP413_INTENT: SignatureOnlyIntent = {
  kind: 'nep413_message_v1',
  message: 'hello threshold Ed25519',
  recipient: 'recipient.testnet',
  nonce: 'CAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg=',
  state: 'state-1',
};

const DEFAULT_DELEGATE_INTENT: SignatureOnlyIntent = {
  kind: 'near_delegate_action_v1',
  delegate: {
    senderId: WALLET_ID,
    receiverId: 'receiver.testnet',
    actions: [],
    nonce: '1',
    maxBlockHeight: '2',
    publicKey: SIGNER_PUBLIC_KEY,
  },
};

function delegateIntent(overrides: {
  senderId?: string;
  receiverId?: string;
  actions?: readonly ThresholdEd25519NearAction[];
  nonce?: string;
  maxBlockHeight?: string;
  publicKey?: string;
}): SignatureOnlyIntent {
  if (DEFAULT_DELEGATE_INTENT.kind !== 'near_delegate_action_v1') {
    throw new Error('invalid delegate fixture');
  }
  return {
    kind: 'near_delegate_action_v1',
    delegate: {
      ...DEFAULT_DELEGATE_INTENT.delegate,
      ...overrides,
    },
  };
}

const runtimePolicyScope = {
  orgId: 'org-finalize',
  projectId: 'project-finalize',
  envId: 'test',
  signingRootVersion: 'root-v1',
};

function claims(): ThresholdEd25519SessionClaims {
  return {
    sub: WALLET_ID,
    walletId: WALLET_ID,
    kind: 'threshold_ed25519_session_v1',
    sessionId: SESSION_ID,
    walletSigningSessionId: WALLET_SIGNING_SESSION_ID,
    relayerKeyId: RELAYER_KEY_ID,
    rpId: RP_ID,
    runtimePolicyScope,
    thresholdExpiresAtMs: Date.now() + 60_000,
    participantIds: [1, 2],
  };
}

function presignRecord(): ThresholdEd25519PresignRecord {
  return {
    kind: 'threshold_ed25519_presign_record_v1',
    expiresAtMs: Date.now() + 60_000,
    thresholdSessionId: SESSION_ID,
    walletSigningSessionId: WALLET_SIGNING_SESSION_ID,
    relayerKeyId: RELAYER_KEY_ID,
    nearAccountId: WALLET_ID,
    nearNetworkId: 'testnet',
    signerPublicKey: SIGNER_PUBLIC_KEY,
    rpcPolicyId: 'ed25519-presign-finalize',
    rpId: RP_ID,
    runtimePolicyScope,
    protocolVersion: 'ed25519_frost_2p_presign_v1',
    participantIds: [1, 2],
    groupPublicKey: SIGNER_PUBLIC_KEY,
    clientVerifyingShareB64u: 'client-verifying-share',
    clientCommitments: { hiding: 'client-hiding', binding: 'client-binding' },
    relayerCommitments: { hiding: 'relayer-hiding', binding: 'relayer-binding' },
    relayerVerifyingShareB64u: 'relayer-verifying-share',
    relayerNoncesB64u: 'invalid-relayer-nonces',
  };
}

type ThresholdEd25519SuccessFixture = {
  record: ThresholdEd25519PresignRecord;
  relayerSigningShareB64u: string;
  signerPublicKey: string;
  clientSignatureShareB64u: string;
};

function signatureOnlyIntentSigningDigestB64u(intent: SignatureOnlyIntent): string {
  if (intent.kind === 'near_delegate_action_v1') {
    return base64UrlEncode(
      threshold_ed25519_compute_delegate_signing_digest({
        delegate: intent.delegate,
      }),
    );
  }
  return base64UrlEncode(
    threshold_ed25519_compute_nep413_signing_digest({
      message: intent.message,
      recipient: intent.recipient,
      nonce: intent.nonce,
      ...(intent.state ? { state: intent.state } : {}),
    }),
  );
}

async function successFixture(input?: {
  signingDigestB64u?: string;
  signingDigestForSignerPublicKey?: (publicKey: string) => string;
}): Promise<ThresholdEd25519SuccessFixture> {
  const clientVerifyingShareB64u = deriveThresholdEd25519VerifyingShareForUnitTests({
    signingShareB64u: CLIENT_BASE_B64U,
  });
  const keygen = threshold_ed25519_keygen_from_client_verifying_share({
    clientParticipantId: 1,
    relayerParticipantId: 2,
    clientVerifyingShareB64u,
  }) as {
    publicKey: string;
    relayerSigningShareB64u: string;
    relayerVerifyingShareB64u: string;
  };
  const signingDigestB64u =
    input?.signingDigestB64u ||
    input?.signingDigestForSignerPublicKey?.(keygen.publicKey) ||
    signatureOnlyIntentSigningDigestB64u(DEFAULT_NEP413_INTENT);
  const clientPresign = threshold_ed25519_client_presign_create({
    clientParticipantId: 1,
    relayerParticipantId: 2,
    xClientBaseB64u: CLIENT_BASE_B64U,
    groupPublicKey: keygen.publicKey,
  }) as {
    clientNonceHandleB64u: string;
    clientCommitments: { hiding: string; binding: string };
    clientVerifyingShareB64u: string;
  };
  const relayerPresign = threshold_ed25519_round1_commit(keygen.relayerSigningShareB64u) as {
    relayerNoncesB64u: string;
    relayerCommitments: { hiding: string; binding: string };
  };
  const clientSignature = threshold_ed25519_client_presign_sign({
    clientParticipantId: 1,
    relayerParticipantId: 2,
    xClientBaseB64u: CLIENT_BASE_B64U,
    groupPublicKey: keygen.publicKey,
    signingDigestB64u,
    clientNonceHandleB64u: clientPresign.clientNonceHandleB64u,
    clientCommitments: clientPresign.clientCommitments,
    relayerCommitments: relayerPresign.relayerCommitments,
  }) as { clientSignatureShareB64u: string };
  return {
    signerPublicKey: keygen.publicKey,
    relayerSigningShareB64u: keygen.relayerSigningShareB64u,
    clientSignatureShareB64u: clientSignature.clientSignatureShareB64u,
    record: {
      ...presignRecord(),
      signerPublicKey: keygen.publicKey,
      groupPublicKey: keygen.publicKey,
      clientVerifyingShareB64u: clientPresign.clientVerifyingShareB64u,
      clientCommitments: clientPresign.clientCommitments,
      relayerCommitments: relayerPresign.relayerCommitments,
      relayerVerifyingShareB64u: keygen.relayerVerifyingShareB64u,
      relayerNoncesB64u: relayerPresign.relayerNoncesB64u,
    },
  };
}

async function seedBudget(
  authSessionStore: ReturnType<
    typeof createThresholdSigningServiceForUnitTests
  >['authSessionStore'],
  remainingUses: number,
): Promise<void> {
  await authSessionStore.putSession(
    WALLET_BUDGET_SESSION_ID,
    {
      expiresAtMs: Date.now() + 60_000,
      relayerKeyId: 'wallet-signing-budget',
      userId: WALLET_ID,
      rpId: RP_ID,
      participantIds: [1, 2],
      walletBudgetBinding: { curve: 'ed25519', thresholdSessionId: SESSION_ID },
    },
    { ttlMs: 60_000, remainingUses },
  );
}

async function signatureOnlyOperationFingerprint(input: {
  nearAccountId: string;
  nearNetworkId: string;
  relayerKeyId: string;
  signerPublicKey: string;
  intent: SignatureOnlyIntent;
}): Promise<string> {
  if (input.intent.kind === 'nep413_message_v1') {
    return thresholdEd25519Nep413OperationFingerprint({
      nearAccountId: input.nearAccountId,
      nearNetworkId: input.nearNetworkId,
      relayerKeyId: input.relayerKeyId,
      signerPublicKey: input.signerPublicKey,
      message: input.intent.message,
      recipient: input.intent.recipient,
      nonce: input.intent.nonce,
      state: input.intent.state || null,
    });
  }
  return thresholdEd25519DelegateActionOperationFingerprint({
    nearAccountId: input.nearAccountId,
    nearNetworkId: input.nearNetworkId,
    relayerKeyId: input.relayerKeyId,
    signerPublicKey: input.signerPublicKey,
    delegate: input.intent.delegate,
  });
}

async function nearTxOperationFingerprint(input: {
  nearAccountId: string;
  nearNetworkId: string;
  relayerKeyId: string;
  signerPublicKey: string;
  transactions: readonly ThresholdEd25519NearTransaction[];
  unsignedTransactionBorshB64u: string;
  signingDigestB64u: string;
}): Promise<string> {
  return thresholdEd25519NearTransactionOperationFingerprint(input);
}

async function signatureOnlyRequest(input: {
  operationId: string;
  presignId: string;
  nearAccountId?: string;
  expectedSignerPublicKey?: string;
  clientSignatureShareB64u?: string;
  operationFingerprint?: string;
  purpose?: 'nep413_message' | 'delegate_action';
  intent?: SignatureOnlyIntent;
}): Promise<ThresholdEd25519FinalizeSignatureOnlyRequest> {
  const intent = input.intent || DEFAULT_NEP413_INTENT;
  const purpose =
    input.purpose || (intent.kind === 'nep413_message_v1' ? 'nep413_message' : 'delegate_action');
  const relayerKeyId = RELAYER_KEY_ID;
  const nearAccountId = input.nearAccountId || WALLET_ID;
  const nearNetworkId = 'testnet';
  const expectedSignerPublicKey = input.expectedSignerPublicKey || SIGNER_PUBLIC_KEY;
  const operationFingerprint =
    input.operationFingerprint ||
    (await signatureOnlyOperationFingerprint({
      nearAccountId,
      nearNetworkId,
      relayerKeyId,
      signerPublicKey: expectedSignerPublicKey,
      intent,
    }));
  const request = {
    kind: 'threshold_ed25519_finalize_signature_only_v1' as const,
    operation: {
      kind: 'threshold_ed25519_signing_operation_v1' as const,
      operationId: input.operationId,
      operationFingerprint,
      purpose,
    },
    presignId: input.presignId,
    relayerKeyId,
    nearAccountId,
    nearNetworkId,
    expectedSignerPublicKey,
    intent,
    clientSignatureShareB64u: input.clientSignatureShareB64u || 'client-signature-share',
  };
  return {
    ...request,
    requestIntegrityHash: await thresholdEd25519FinalizeRequestIntegrityHash(request),
  };
}

type NearTxSuccessFixture = ThresholdEd25519SuccessFixture & {
  transactions: readonly ThresholdEd25519NearTransaction[];
  unsignedTransactionBorshB64u: string;
  signingDigestB64u: string;
};

async function nearTxSuccessFixture(input?: {
  unsignedNearAccountId?: string;
  unsignedSignerPublicKey?: string;
}): Promise<NearTxSuccessFixture> {
  const clientVerifyingShareB64u = deriveThresholdEd25519VerifyingShareForUnitTests({
    signingShareB64u: CLIENT_BASE_B64U,
  });
  const keygen = threshold_ed25519_keygen_from_client_verifying_share({
    clientParticipantId: 1,
    relayerParticipantId: 2,
    clientVerifyingShareB64u,
  }) as {
    publicKey: string;
    relayerSigningShareB64u: string;
    relayerVerifyingShareB64u: string;
  };
  const transactions: ThresholdEd25519NearTransaction[] = [
    {
      nearAccountId: input?.unsignedNearAccountId || WALLET_ID,
      receiverId: WALLET_ID,
      actions: [{ action_type: 'Transfer', deposit: '1' }],
    },
  ];
  const unsigned = threshold_ed25519_build_near_tx_unsigned_borsh({
    kind: 'near_tx',
    txSigningRequests: transactions,
    transactionContext: {
      nearPublicKeyStr: input?.unsignedSignerPublicKey || keygen.publicKey,
      nextNonce: '1',
      txBlockHeight: '1',
      txBlockHash: bs58.encode(new Uint8Array(32).fill(7)),
    },
  }) as Array<{ unsignedTransactionBorshB64u: string; signingDigestB64u: string }>;
  const firstUnsigned = unsigned[0];
  if (!firstUnsigned?.unsignedTransactionBorshB64u || !firstUnsigned.signingDigestB64u) {
    throw new Error('failed to build unsigned NEAR transaction fixture');
  }
  const clientPresign = threshold_ed25519_client_presign_create({
    clientParticipantId: 1,
    relayerParticipantId: 2,
    xClientBaseB64u: CLIENT_BASE_B64U,
    groupPublicKey: keygen.publicKey,
  }) as {
    clientNonceHandleB64u: string;
    clientCommitments: { hiding: string; binding: string };
    clientVerifyingShareB64u: string;
  };
  const relayerPresign = threshold_ed25519_round1_commit(keygen.relayerSigningShareB64u) as {
    relayerNoncesB64u: string;
    relayerCommitments: { hiding: string; binding: string };
  };
  const clientSignature = threshold_ed25519_client_presign_sign({
    clientParticipantId: 1,
    relayerParticipantId: 2,
    xClientBaseB64u: CLIENT_BASE_B64U,
    groupPublicKey: keygen.publicKey,
    signingDigestB64u: firstUnsigned.signingDigestB64u,
    clientNonceHandleB64u: clientPresign.clientNonceHandleB64u,
    clientCommitments: clientPresign.clientCommitments,
    relayerCommitments: relayerPresign.relayerCommitments,
  }) as { clientSignatureShareB64u: string };
  return {
    signerPublicKey: keygen.publicKey,
    relayerSigningShareB64u: keygen.relayerSigningShareB64u,
    clientSignatureShareB64u: clientSignature.clientSignatureShareB64u,
    transactions,
    unsignedTransactionBorshB64u: firstUnsigned.unsignedTransactionBorshB64u,
    signingDigestB64u: firstUnsigned.signingDigestB64u,
    record: {
      ...presignRecord(),
      rpcPolicyId: 'ed25519-presign-finalize',
      signerPublicKey: keygen.publicKey,
      groupPublicKey: keygen.publicKey,
      clientVerifyingShareB64u: clientPresign.clientVerifyingShareB64u,
      clientCommitments: clientPresign.clientCommitments,
      relayerCommitments: relayerPresign.relayerCommitments,
      relayerVerifyingShareB64u: keygen.relayerVerifyingShareB64u,
      relayerNoncesB64u: relayerPresign.relayerNoncesB64u,
    },
  };
}

async function nearTxRequest(input: {
  operationId: string;
  presignId: string;
  fixture: NearTxSuccessFixture;
  transactions?: NearTxSuccessFixture['transactions'];
  signingDigestB64u?: string;
  nearNetworkId?: string;
}) {
  const signingDigestB64u = input.signingDigestB64u || input.fixture.signingDigestB64u;
  const nearNetworkId = input.nearNetworkId || 'testnet';
  const transactions = input.transactions || input.fixture.transactions;
  const request = {
    kind: 'threshold_ed25519_finalize_and_dispatch_near_tx_v1' as const,
    operation: {
      kind: 'threshold_ed25519_signing_operation_v1' as const,
      operationId: input.operationId,
      operationFingerprint: await nearTxOperationFingerprint({
        nearAccountId: WALLET_ID,
        nearNetworkId,
        relayerKeyId: RELAYER_KEY_ID,
        signerPublicKey: input.fixture.signerPublicKey,
        transactions,
        unsignedTransactionBorshB64u: input.fixture.unsignedTransactionBorshB64u,
        signingDigestB64u,
      }),
      purpose: 'near_transaction' as const,
    },
    presignId: input.presignId,
    relayerKeyId: RELAYER_KEY_ID,
    nearAccountId: WALLET_ID,
    nearNetworkId,
    expectedSignerPublicKey: input.fixture.signerPublicKey,
    transactions,
    unsignedTransactionBorshB64u: input.fixture.unsignedTransactionBorshB64u,
    signingDigestB64u,
    clientSignatureShareB64u: input.fixture.clientSignatureShareB64u,
    dispatch: { kind: 'near_rpc_configured_default_v1' as const },
  };
  return {
    ...request,
    requestIntegrityHash: await thresholdEd25519FinalizeRequestIntegrityHash(request),
  };
}

test.describe('threshold Ed25519 finalize-and-dispatch service', () => {
  test('wrong scope rejects without consuming presign or budget', async () => {
    const { svc, sessionStore, authSessionStore } = createThresholdSigningServiceForUnitTests({
      keyRecord: {
        publicKey: SIGNER_PUBLIC_KEY,
        relayerSigningShareB64u: RELAYER_SIGNING_SHARE_B64U,
        keyVersion: 'v1',
        recoveryExportCapable: true,
      },
    });
    const scheme = svc.getSchemeModule(THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID);
    if (!scheme || scheme.schemeId !== THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID) {
      throw new Error('missing Ed25519 scheme');
    }
    await seedBudget(authSessionStore, 1);
    const record = presignRecord();
    await sessionStore.putPresign('presign-wrong-scope', record, 60_000);

    const result = await scheme.presign.finalizeAndDispatch({
      claims: claims(),
      request: await signatureOnlyRequest({
        operationId: 'operation-wrong-scope',
        presignId: 'presign-wrong-scope',
        nearAccountId: 'mallory.testnet',
      }),
    });

    expect(result).toMatchObject({
      ok: false,
      code: 'wrong_scope',
      budgetState: 'not_consumed',
      presignConsumed: false,
      dispatchState: 'not_attempted',
    });
    await expect(
      authSessionStore.getSessionStatus(WALLET_BUDGET_SESSION_ID),
    ).resolves.toMatchObject({
      remainingUses: 1,
    });
    const retained = await sessionStore.takePresignForFinalize('presign-wrong-scope', {
      thresholdSessionId: record.thresholdSessionId,
      walletSigningSessionId: record.walletSigningSessionId,
      relayerKeyId: record.relayerKeyId,
      nearAccountId: record.nearAccountId,
      nearNetworkId: record.nearNetworkId,
      signerPublicKey: record.signerPublicKey,
      rpcPolicyId: record.rpcPolicyId,
      rpId: record.rpId,
      runtimePolicyScope: record.runtimePolicyScope,
      participantIds: record.participantIds,
      groupPublicKey: record.groupPublicKey,
    });
    expect(retained).toMatchObject({ ok: true });
  });

  test('wrong-scope pressure leaves presign and budget intact', async () => {
    const { svc, sessionStore, authSessionStore } = createThresholdSigningServiceForUnitTests({
      keyRecord: {
        publicKey: SIGNER_PUBLIC_KEY,
        relayerSigningShareB64u: RELAYER_SIGNING_SHARE_B64U,
        keyVersion: 'v1',
        recoveryExportCapable: true,
      },
    });
    const scheme = svc.getSchemeModule(THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID);
    if (!scheme || scheme.schemeId !== THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID) {
      throw new Error('missing Ed25519 scheme');
    }
    await seedBudget(authSessionStore, 1);
    const record = presignRecord();
    await sessionStore.putPresign('presign-wrong-scope-pressure', record, 60_000);

    for (let index = 0; index < 12; index += 1) {
      await expect(
        scheme.presign.finalizeAndDispatch({
          claims: claims(),
          request: await signatureOnlyRequest({
            operationId: `operation-wrong-scope-pressure-${index + 1}`,
            presignId: 'presign-wrong-scope-pressure',
            nearAccountId: 'mallory.testnet',
          }),
        }),
      ).resolves.toMatchObject({
        ok: false,
        code: 'wrong_scope',
        budgetState: 'not_consumed',
        presignConsumed: false,
        dispatchState: 'not_attempted',
      });
    }

    await expect(
      authSessionStore.getSessionStatus(WALLET_BUDGET_SESSION_ID),
    ).resolves.toMatchObject({
      remainingUses: 1,
    });
    await expect(
      sessionStore.takePresignForFinalize('presign-wrong-scope-pressure', {
        thresholdSessionId: record.thresholdSessionId,
        walletSigningSessionId: record.walletSigningSessionId,
        relayerKeyId: record.relayerKeyId,
        nearAccountId: record.nearAccountId,
        nearNetworkId: record.nearNetworkId,
        signerPublicKey: record.signerPublicKey,
        rpcPolicyId: record.rpcPolicyId,
        rpId: record.rpId,
        runtimePolicyScope: record.runtimePolicyScope,
        participantIds: record.participantIds,
        groupPublicKey: record.groupPublicKey,
      }),
    ).resolves.toMatchObject({ ok: true });
  });

  test('operation fingerprint mismatch rejects before presign or budget consume', async () => {
    const { svc, sessionStore, authSessionStore } = createThresholdSigningServiceForUnitTests({
      keyRecord: {
        publicKey: SIGNER_PUBLIC_KEY,
        relayerSigningShareB64u: RELAYER_SIGNING_SHARE_B64U,
        keyVersion: 'v1',
        recoveryExportCapable: true,
      },
    });
    const scheme = svc.getSchemeModule(THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID);
    if (!scheme || scheme.schemeId !== THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID) {
      throw new Error('missing Ed25519 scheme');
    }
    await seedBudget(authSessionStore, 1);
    const record = presignRecord();
    await sessionStore.putPresign('presign-fingerprint-mismatch', record, 60_000);

    const result = await scheme.presign.finalizeAndDispatch({
      claims: claims(),
      request: await signatureOnlyRequest({
        operationId: 'operation-fingerprint-mismatch',
        operationFingerprint: 'sha256:wrong-fingerprint',
        presignId: 'presign-fingerprint-mismatch',
      }),
    });

    expect(result).toMatchObject({
      ok: false,
      code: 'operation_fingerprint_mismatch',
      budgetState: 'not_consumed',
      presignConsumed: false,
      dispatchState: 'not_attempted',
    });
    await expect(
      authSessionStore.getSessionStatus(WALLET_BUDGET_SESSION_ID),
    ).resolves.toMatchObject({
      remainingUses: 1,
    });
    await expect(
      sessionStore.takePresignForFinalize('presign-fingerprint-mismatch', {
        thresholdSessionId: record.thresholdSessionId,
        walletSigningSessionId: record.walletSigningSessionId,
        relayerKeyId: record.relayerKeyId,
        nearAccountId: record.nearAccountId,
        nearNetworkId: record.nearNetworkId,
        signerPublicKey: record.signerPublicKey,
        rpcPolicyId: record.rpcPolicyId,
        rpId: record.rpId,
        runtimePolicyScope: record.runtimePolicyScope,
        participantIds: record.participantIds,
        groupPublicKey: record.groupPublicKey,
      }),
    ).resolves.toMatchObject({ ok: true });
  });

  test('same operation id with a different domain fingerprint rejects before presign or budget consume', async () => {
    const { svc, sessionStore, authSessionStore } = createThresholdSigningServiceForUnitTests({
      keyRecord: {
        publicKey: SIGNER_PUBLIC_KEY,
        relayerSigningShareB64u: RELAYER_SIGNING_SHARE_B64U,
        keyVersion: 'v1',
        recoveryExportCapable: true,
      },
    });
    const scheme = svc.getSchemeModule(THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID);
    if (!scheme || scheme.schemeId !== THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID) {
      throw new Error('missing Ed25519 scheme');
    }
    await seedBudget(authSessionStore, 1);
    const record = presignRecord();
    await sessionStore.putPresign('presign-duplicate-operation-fingerprint', record, 60_000);
    const differentDomainFingerprint = await signatureOnlyOperationFingerprint({
      nearAccountId: WALLET_ID,
      nearNetworkId: 'testnet',
      relayerKeyId: RELAYER_KEY_ID,
      signerPublicKey: SIGNER_PUBLIC_KEY,
      intent: {
        kind: 'nep413_message_v1',
        message: 'different user-authorized payload',
        recipient: DEFAULT_NEP413_INTENT.recipient,
        nonce: DEFAULT_NEP413_INTENT.nonce,
        state: DEFAULT_NEP413_INTENT.state || undefined,
      },
    });

    const result = await scheme.presign.finalizeAndDispatch({
      claims: claims(),
      request: await signatureOnlyRequest({
        operationId: 'operation-duplicate-id',
        operationFingerprint: differentDomainFingerprint,
        presignId: 'presign-duplicate-operation-fingerprint',
      }),
    });

    expect(result).toMatchObject({
      ok: false,
      code: 'operation_fingerprint_mismatch',
      budgetState: 'not_consumed',
      presignConsumed: false,
      dispatchState: 'not_attempted',
    });
    await expect(
      authSessionStore.getSessionStatus(WALLET_BUDGET_SESSION_ID),
    ).resolves.toMatchObject({
      remainingUses: 1,
    });
    await expect(
      sessionStore.takePresignForFinalize('presign-duplicate-operation-fingerprint', {
        thresholdSessionId: record.thresholdSessionId,
        walletSigningSessionId: record.walletSigningSessionId,
        relayerKeyId: record.relayerKeyId,
        nearAccountId: record.nearAccountId,
        nearNetworkId: record.nearNetworkId,
        signerPublicKey: record.signerPublicKey,
        rpcPolicyId: record.rpcPolicyId,
        rpId: record.rpId,
        runtimePolicyScope: record.runtimePolicyScope,
        participantIds: record.participantIds,
        groupPublicKey: record.groupPublicKey,
      }),
    ).resolves.toMatchObject({ ok: true });
  });

  test('request integrity mismatch rejects before presign or budget consume', async () => {
    const { svc, sessionStore, authSessionStore } = createThresholdSigningServiceForUnitTests({
      keyRecord: {
        publicKey: SIGNER_PUBLIC_KEY,
        relayerSigningShareB64u: RELAYER_SIGNING_SHARE_B64U,
        keyVersion: 'v1',
        recoveryExportCapable: true,
      },
    });
    const scheme = svc.getSchemeModule(THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID);
    if (!scheme || scheme.schemeId !== THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID) {
      throw new Error('missing Ed25519 scheme');
    }
    await seedBudget(authSessionStore, 1);
    const record = presignRecord();
    await sessionStore.putPresign('presign-request-integrity-mismatch', record, 60_000);
    const request = await signatureOnlyRequest({
      operationId: 'operation-request-integrity-mismatch',
      presignId: 'presign-request-integrity-mismatch',
    });

    const result = await scheme.presign.finalizeAndDispatch({
      claims: claims(),
      request: {
        ...request,
        requestIntegrityHash: 'sha256:wrong-request-integrity',
      },
    });

    expect(result).toMatchObject({
      ok: false,
      code: 'request_integrity_mismatch',
      budgetState: 'not_consumed',
      presignConsumed: false,
      dispatchState: 'not_attempted',
    });
    await expect(
      authSessionStore.getSessionStatus(WALLET_BUDGET_SESSION_ID),
    ).resolves.toMatchObject({
      remainingUses: 1,
    });
    await expect(
      sessionStore.takePresignForFinalize('presign-request-integrity-mismatch', {
        thresholdSessionId: record.thresholdSessionId,
        walletSigningSessionId: record.walletSigningSessionId,
        relayerKeyId: record.relayerKeyId,
        nearAccountId: record.nearAccountId,
        nearNetworkId: record.nearNetworkId,
        signerPublicKey: record.signerPublicKey,
        rpcPolicyId: record.rpcPolicyId,
        rpId: record.rpId,
        runtimePolicyScope: record.runtimePolicyScope,
        participantIds: record.participantIds,
        groupPublicKey: record.groupPublicKey,
      }),
    ).resolves.toMatchObject({ ok: true });
  });

  test('NEP-413 intent field changes reject before presign or budget consume', async () => {
    const { svc, sessionStore, authSessionStore } = createThresholdSigningServiceForUnitTests({
      keyRecord: {
        publicKey: SIGNER_PUBLIC_KEY,
        relayerSigningShareB64u: RELAYER_SIGNING_SHARE_B64U,
        keyVersion: 'v1',
        recoveryExportCapable: true,
      },
    });
    const scheme = svc.getSchemeModule(THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID);
    if (!scheme || scheme.schemeId !== THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID) {
      throw new Error('missing Ed25519 scheme');
    }
    await seedBudget(authSessionStore, 1);
    const record = presignRecord();
    await sessionStore.putPresign('presign-nep413-field-mismatch', record, 60_000);
    const originalFingerprint = await signatureOnlyOperationFingerprint({
      nearAccountId: WALLET_ID,
      nearNetworkId: 'testnet',
      relayerKeyId: RELAYER_KEY_ID,
      signerPublicKey: SIGNER_PUBLIC_KEY,
      intent: DEFAULT_NEP413_INTENT,
    });
    const changedIntents: readonly SignatureOnlyIntent[] = [
      { ...DEFAULT_NEP413_INTENT, message: 'changed message' },
      { ...DEFAULT_NEP413_INTENT, recipient: 'changed-recipient.testnet' },
      { ...DEFAULT_NEP413_INTENT, nonce: 'CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk=' },
      { ...DEFAULT_NEP413_INTENT, state: 'changed-state' },
    ];

    for (const [index, intent] of changedIntents.entries()) {
      await expect(
        scheme.presign.finalizeAndDispatch({
          claims: claims(),
          request: await signatureOnlyRequest({
            operationId: `operation-nep413-field-mismatch-${index + 1}`,
            operationFingerprint: originalFingerprint,
            presignId: 'presign-nep413-field-mismatch',
            intent,
          }),
        }),
      ).resolves.toMatchObject({
        ok: false,
        code: 'operation_fingerprint_mismatch',
        budgetState: 'not_consumed',
        presignConsumed: false,
        dispatchState: 'not_attempted',
      });
    }
    await expect(
      authSessionStore.getSessionStatus(WALLET_BUDGET_SESSION_ID),
    ).resolves.toMatchObject({
      remainingUses: 1,
    });
    await expect(
      sessionStore.takePresignForFinalize('presign-nep413-field-mismatch', {
        thresholdSessionId: record.thresholdSessionId,
        walletSigningSessionId: record.walletSigningSessionId,
        relayerKeyId: record.relayerKeyId,
        nearAccountId: record.nearAccountId,
        nearNetworkId: record.nearNetworkId,
        signerPublicKey: record.signerPublicKey,
        rpcPolicyId: record.rpcPolicyId,
        rpId: record.rpId,
        runtimePolicyScope: record.runtimePolicyScope,
        participantIds: record.participantIds,
        groupPublicKey: record.groupPublicKey,
      }),
    ).resolves.toMatchObject({ ok: true });
  });

  test('delegate intent payload changes reject before presign or budget consume', async () => {
    const { svc, sessionStore, authSessionStore } = createThresholdSigningServiceForUnitTests({
      keyRecord: {
        publicKey: SIGNER_PUBLIC_KEY,
        relayerSigningShareB64u: RELAYER_SIGNING_SHARE_B64U,
        keyVersion: 'v1',
        recoveryExportCapable: true,
      },
    });
    const scheme = svc.getSchemeModule(THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID);
    if (!scheme || scheme.schemeId !== THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID) {
      throw new Error('missing Ed25519 scheme');
    }
    await seedBudget(authSessionStore, 1);
    const record = presignRecord();
    await sessionStore.putPresign('presign-delegate-payload-mismatch', record, 60_000);
    const originalFingerprint = await signatureOnlyOperationFingerprint({
      nearAccountId: WALLET_ID,
      nearNetworkId: 'testnet',
      relayerKeyId: RELAYER_KEY_ID,
      signerPublicKey: SIGNER_PUBLIC_KEY,
      intent: DEFAULT_DELEGATE_INTENT,
    });
    const changedIntents: readonly SignatureOnlyIntent[] = [
      delegateIntent({ receiverId: 'changed-receiver.testnet' }),
      delegateIntent({ actions: [{ action_type: 'Transfer', deposit: '1' }] }),
      delegateIntent({ nonce: '2' }),
      delegateIntent({ maxBlockHeight: '3' }),
    ];

    for (const [index, intent] of changedIntents.entries()) {
      await expect(
        scheme.presign.finalizeAndDispatch({
          claims: claims(),
          request: await signatureOnlyRequest({
            operationId: `operation-delegate-payload-mismatch-${index + 1}`,
            operationFingerprint: originalFingerprint,
            presignId: 'presign-delegate-payload-mismatch',
            intent,
          }),
        }),
      ).resolves.toMatchObject({
        ok: false,
        code: 'operation_fingerprint_mismatch',
        budgetState: 'not_consumed',
        presignConsumed: false,
        dispatchState: 'not_attempted',
      });
    }
    await expect(
      authSessionStore.getSessionStatus(WALLET_BUDGET_SESSION_ID),
    ).resolves.toMatchObject({
      remainingUses: 1,
    });
    await expect(
      sessionStore.takePresignForFinalize('presign-delegate-payload-mismatch', {
        thresholdSessionId: record.thresholdSessionId,
        walletSigningSessionId: record.walletSigningSessionId,
        relayerKeyId: record.relayerKeyId,
        nearAccountId: record.nearAccountId,
        nearNetworkId: record.nearNetworkId,
        signerPublicKey: record.signerPublicKey,
        rpcPolicyId: record.rpcPolicyId,
        rpId: record.rpId,
        runtimePolicyScope: record.runtimePolicyScope,
        participantIds: record.participantIds,
        groupPublicKey: record.groupPublicKey,
      }),
    ).resolves.toMatchObject({ ok: true });
  });

  test('signature-only purpose mismatch rejects before presign or budget consume', async () => {
    const { svc, sessionStore, authSessionStore } = createThresholdSigningServiceForUnitTests({
      keyRecord: {
        publicKey: SIGNER_PUBLIC_KEY,
        relayerSigningShareB64u: RELAYER_SIGNING_SHARE_B64U,
        keyVersion: 'v1',
        recoveryExportCapable: true,
      },
    });
    const scheme = svc.getSchemeModule(THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID);
    if (!scheme || scheme.schemeId !== THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID) {
      throw new Error('missing Ed25519 scheme');
    }
    await seedBudget(authSessionStore, 1);
    const record = presignRecord();
    await sessionStore.putPresign('presign-purpose-mismatch', record, 60_000);

    const result = await scheme.presign.finalizeAndDispatch({
      claims: claims(),
      request: await signatureOnlyRequest({
        operationId: 'operation-purpose-mismatch',
        presignId: 'presign-purpose-mismatch',
        purpose: 'delegate_action',
      }),
    });

    expect(result).toMatchObject({
      ok: false,
      code: 'wrong_scope',
      budgetState: 'not_consumed',
      presignConsumed: false,
      dispatchState: 'not_attempted',
    });
    await expect(
      authSessionStore.getSessionStatus(WALLET_BUDGET_SESSION_ID),
    ).resolves.toMatchObject({
      remainingUses: 1,
    });
    await expect(
      sessionStore.takePresignForFinalize('presign-purpose-mismatch', {
        thresholdSessionId: record.thresholdSessionId,
        walletSigningSessionId: record.walletSigningSessionId,
        relayerKeyId: record.relayerKeyId,
        nearAccountId: record.nearAccountId,
        nearNetworkId: record.nearNetworkId,
        signerPublicKey: record.signerPublicKey,
        rpcPolicyId: record.rpcPolicyId,
        rpId: record.rpId,
        runtimePolicyScope: record.runtimePolicyScope,
        participantIds: record.participantIds,
        groupPublicKey: record.groupPublicKey,
      }),
    ).resolves.toMatchObject({ ok: true });
  });

  test('delegate intent scope and signer mismatches reject before presign or budget consume', async () => {
    const { svc, sessionStore, authSessionStore } = createThresholdSigningServiceForUnitTests({
      keyRecord: {
        publicKey: SIGNER_PUBLIC_KEY,
        relayerSigningShareB64u: RELAYER_SIGNING_SHARE_B64U,
        keyVersion: 'v1',
        recoveryExportCapable: true,
      },
    });
    const scheme = svc.getSchemeModule(THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID);
    if (!scheme || scheme.schemeId !== THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID) {
      throw new Error('missing Ed25519 scheme');
    }
    await seedBudget(authSessionStore, 1);
    const record = presignRecord();
    await sessionStore.putPresign('presign-delegate-mismatch', record, 60_000);

    await expect(
      scheme.presign.finalizeAndDispatch({
        claims: claims(),
        request: await signatureOnlyRequest({
          operationId: 'operation-delegate-sender-mismatch',
          presignId: 'presign-delegate-mismatch',
          intent: delegateIntent({ senderId: 'mallory.testnet' }),
        }),
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'transaction_scope_mismatch',
      budgetState: 'not_consumed',
      presignConsumed: false,
      dispatchState: 'not_attempted',
    });
    await expect(
      scheme.presign.finalizeAndDispatch({
        claims: claims(),
        request: await signatureOnlyRequest({
          operationId: 'operation-delegate-public-key-mismatch',
          presignId: 'presign-delegate-mismatch',
          intent: delegateIntent({
            publicKey: 'ed25519:9y1xWJmQkZ3V5j7CzDxwjz7v5KdfD1G1d2Fh4kG9Wcaa',
          }),
        }),
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'transaction_signer_key_mismatch',
      budgetState: 'not_consumed',
      presignConsumed: false,
      dispatchState: 'not_attempted',
    });
    await expect(
      authSessionStore.getSessionStatus(WALLET_BUDGET_SESSION_ID),
    ).resolves.toMatchObject({
      remainingUses: 1,
    });
    await expect(
      sessionStore.takePresignForFinalize('presign-delegate-mismatch', {
        thresholdSessionId: record.thresholdSessionId,
        walletSigningSessionId: record.walletSigningSessionId,
        relayerKeyId: record.relayerKeyId,
        nearAccountId: record.nearAccountId,
        nearNetworkId: record.nearNetworkId,
        signerPublicKey: record.signerPublicKey,
        rpcPolicyId: record.rpcPolicyId,
        rpId: record.rpId,
        runtimePolicyScope: record.runtimePolicyScope,
        participantIds: record.participantIds,
        groupPublicKey: record.groupPublicKey,
      }),
    ).resolves.toMatchObject({ ok: true });
  });

  test('signature-only finalize aggregates and verifies a valid presign transcript', async () => {
    const fixture = await successFixture();
    const { svc, sessionStore, authSessionStore } = createThresholdSigningServiceForUnitTests({
      keyRecord: {
        publicKey: fixture.signerPublicKey,
        relayerSigningShareB64u: fixture.relayerSigningShareB64u,
        keyVersion: 'v1',
        recoveryExportCapable: true,
      },
    });
    const scheme = svc.getSchemeModule(THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID);
    if (!scheme || scheme.schemeId !== THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID) {
      throw new Error('missing Ed25519 scheme');
    }
    await seedBudget(authSessionStore, 1);
    await sessionStore.putPresign('presign-success', fixture.record, 60_000);

    const result = await scheme.presign.finalizeAndDispatch({
      claims: claims(),
      request: await signatureOnlyRequest({
        operationId: 'operation-success',
        presignId: 'presign-success',
        expectedSignerPublicKey: fixture.signerPublicKey,
        clientSignatureShareB64u: fixture.clientSignatureShareB64u,
      }),
    });

    expect(result).toMatchObject({
      ok: true,
      kind: 'threshold_ed25519_signature_only_result_v1',
      operationId: 'operation-success',
      budgetState: 'consumed',
      remainingSigningUses: 0,
      signerPublicKey: fixture.signerPublicKey,
    });
    expect(result.ok && result.signatureB64u.length).toBeGreaterThan(0);
    await expect(
      authSessionStore.getSessionStatus(WALLET_BUDGET_SESSION_ID),
    ).resolves.toMatchObject({
      remainingUses: 0,
    });
    await expect(
      sessionStore.takePresignForFinalize('presign-success', {
        thresholdSessionId: SESSION_ID,
        walletSigningSessionId: WALLET_SIGNING_SESSION_ID,
        relayerKeyId: RELAYER_KEY_ID,
        nearAccountId: WALLET_ID,
        nearNetworkId: 'testnet',
        signerPublicKey: fixture.signerPublicKey,
        rpcPolicyId: 'ed25519-presign-finalize',
        rpId: RP_ID,
        runtimePolicyScope,
        participantIds: [1, 2],
        groupPublicKey: fixture.signerPublicKey,
      }),
    ).resolves.toEqual({ ok: false, code: 'not_found' });
  });

  test('express signature-only route finalizes and returns the verified signature result', async () => {
    const fixture = await successFixture();
    const { svc, sessionStore, authSessionStore } = createThresholdSigningServiceForUnitTests({
      keyRecord: {
        publicKey: fixture.signerPublicKey,
        relayerSigningShareB64u: fixture.relayerSigningShareB64u,
        keyVersion: 'v1',
        recoveryExportCapable: true,
      },
    });
    await seedBudget(authSessionStore, 1);
    await sessionStore.putPresign('presign-route-success', fixture.record, 60_000);

    const session = makeSessionAdapter({
      parse: async () => ({ ok: true as const, claims: claims() }),
    });
    const service = makeFakeAuthService();
    const router = createRelayRouter(service, { threshold: svc, session });
    const server = await startExpressRouter(router);

    try {
      const res = await fetchJson(
        `${server.baseUrl}/threshold-ed25519/sign/finalize-and-dispatch`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Authorization: 'Bearer route-test' },
          body: JSON.stringify(
            await signatureOnlyRequest({
              operationId: 'operation-route-success',
              presignId: 'presign-route-success',
              expectedSignerPublicKey: fixture.signerPublicKey,
              clientSignatureShareB64u: fixture.clientSignatureShareB64u,
            }),
          ),
        },
      );

      expect(res.status).toBe(200);
      expect(res.json).toMatchObject({
        ok: true,
        kind: 'threshold_ed25519_signature_only_result_v1',
        operationId: 'operation-route-success',
        budgetState: 'consumed',
        remainingSigningUses: 0,
        signerPublicKey: fixture.signerPublicKey,
      });
      expect(typeof res.json?.signatureB64u).toBe('string');
      expect((res.json?.signatureB64u as string).length).toBeGreaterThan(0);
    } finally {
      await server.close();
    }
  });

  test('NEAR finalize-and-dispatch builds signed transaction bytes and dispatches once', async () => {
    const fixture = await nearTxSuccessFixture();
    const dispatched: string[] = [];
    const { svc, sessionStore, authSessionStore } = createThresholdSigningServiceForUnitTests({
      keyRecord: {
        publicKey: fixture.signerPublicKey,
        relayerSigningShareB64u: fixture.relayerSigningShareB64u,
        keyVersion: 'v1',
        recoveryExportCapable: true,
      },
      accessKeysOnChain: [fixture.signerPublicKey],
      dispatchNearTransaction: async ({ signedTransactionBorshB64u }) => {
        dispatched.push(signedTransactionBorshB64u);
        return { rpcResult: { status: { SuccessValue: '' } } };
      },
    });
    const scheme = svc.getSchemeModule(THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID);
    if (!scheme || scheme.schemeId !== THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID) {
      throw new Error('missing Ed25519 scheme');
    }
    await seedBudget(authSessionStore, 1);
    await sessionStore.putPresign('presign-near-dispatch-success', fixture.record, 60_000);

    const result = await scheme.presign.finalizeAndDispatch({
      claims: claims(),
      request: await nearTxRequest({
        operationId: 'operation-near-dispatch-success',
        presignId: 'presign-near-dispatch-success',
        fixture,
      }),
    });

    expect(result).toMatchObject({
      ok: true,
      kind: 'threshold_ed25519_dispatched_near_tx_result_v1',
      operationId: 'operation-near-dispatch-success',
      budgetState: 'consumed',
      remainingSigningUses: 0,
      signerPublicKey: fixture.signerPublicKey,
      rpcResult: { status: { SuccessValue: '' } },
    });
    if (!result.ok || result.kind !== 'threshold_ed25519_dispatched_near_tx_result_v1') {
      throw new Error('expected dispatched NEAR transaction result');
    }
    expect(result.signedTransactionBorshB64u.length).toBeGreaterThan(0);
    expect(result.transactionHash.length).toBeGreaterThan(0);
    expect(dispatched).toEqual([result.signedTransactionBorshB64u]);
    await expect(
      authSessionStore.getSessionStatus(WALLET_BUDGET_SESSION_ID),
    ).resolves.toMatchObject({
      remainingUses: 0,
    });
  });

  test('express NEAR finalize-and-dispatch route dispatches signed transaction bytes', async () => {
    const fixture = await nearTxSuccessFixture();
    const dispatched: string[] = [];
    const { svc, sessionStore, authSessionStore } = createThresholdSigningServiceForUnitTests({
      keyRecord: {
        publicKey: fixture.signerPublicKey,
        relayerSigningShareB64u: fixture.relayerSigningShareB64u,
        keyVersion: 'v1',
        recoveryExportCapable: true,
      },
      accessKeysOnChain: [fixture.signerPublicKey],
      dispatchNearTransaction: async ({ signedTransactionBorshB64u }) => {
        dispatched.push(signedTransactionBorshB64u);
        return { rpcResult: { status: { SuccessValue: '' } } };
      },
    });
    await seedBudget(authSessionStore, 1);
    await sessionStore.putPresign('presign-near-route-success', fixture.record, 60_000);

    const session = makeSessionAdapter({
      parse: async () => ({ ok: true as const, claims: claims() }),
    });
    const service = makeFakeAuthService();
    const router = createRelayRouter(service, { threshold: svc, session });
    const server = await startExpressRouter(router);

    try {
      const res = await fetchJson(
        `${server.baseUrl}/threshold-ed25519/sign/finalize-and-dispatch`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Authorization: 'Bearer near-route' },
          body: JSON.stringify(
            await nearTxRequest({
              operationId: 'operation-near-route-success',
              presignId: 'presign-near-route-success',
              fixture,
            }),
          ),
        },
      );

      expect(res.status).toBe(200);
      expect(res.json).toMatchObject({
        ok: true,
        kind: 'threshold_ed25519_dispatched_near_tx_result_v1',
        operationId: 'operation-near-route-success',
        budgetState: 'consumed',
        remainingSigningUses: 0,
        signerPublicKey: fixture.signerPublicKey,
      });
      expect(dispatched).toEqual([res.json?.signedTransactionBorshB64u]);
    } finally {
      await server.close();
    }
  });

  test('NEAR finalize-and-dispatch digest mismatch rejects before consuming presign or budget', async () => {
    const fixture = await nearTxSuccessFixture();
    const dispatched: string[] = [];
    const { svc, sessionStore, authSessionStore } = createThresholdSigningServiceForUnitTests({
      keyRecord: {
        publicKey: fixture.signerPublicKey,
        relayerSigningShareB64u: fixture.relayerSigningShareB64u,
        keyVersion: 'v1',
        recoveryExportCapable: true,
      },
      accessKeysOnChain: [fixture.signerPublicKey],
      dispatchNearTransaction: async ({ signedTransactionBorshB64u }) => {
        dispatched.push(signedTransactionBorshB64u);
        return { rpcResult: { status: { SuccessValue: '' } } };
      },
    });
    const scheme = svc.getSchemeModule(THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID);
    if (!scheme || scheme.schemeId !== THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID) {
      throw new Error('missing Ed25519 scheme');
    }
    await seedBudget(authSessionStore, 1);
    await sessionStore.putPresign('presign-near-digest-mismatch', fixture.record, 60_000);

    const result = await scheme.presign.finalizeAndDispatch({
      claims: claims(),
      request: await nearTxRequest({
        operationId: 'operation-near-digest-mismatch',
        presignId: 'presign-near-digest-mismatch',
        fixture,
        signingDigestB64u: SIGNING_DIGEST_B64U,
      }),
    });

    expect(result).toMatchObject({
      ok: false,
      code: 'digest_mismatch',
      budgetState: 'not_consumed',
      presignConsumed: false,
      dispatchState: 'not_attempted',
    });
    expect(dispatched).toEqual([]);
    await expect(
      authSessionStore.getSessionStatus(WALLET_BUDGET_SESSION_ID),
    ).resolves.toMatchObject({
      remainingUses: 1,
    });
  });

  test('NEAR finalize-and-dispatch rejects typed transaction intent mismatch before consume', async () => {
    const fixture = await nearTxSuccessFixture();
    const mismatchedTransactions: ThresholdEd25519NearTransaction[] = [
      {
        nearAccountId: WALLET_ID,
        receiverId: 'different-receiver.testnet',
        actions: [{ action_type: 'Transfer', deposit: '1' }],
      },
    ];
    const dispatched: string[] = [];
    const { svc, sessionStore, authSessionStore } = createThresholdSigningServiceForUnitTests({
      keyRecord: {
        publicKey: fixture.signerPublicKey,
        relayerSigningShareB64u: fixture.relayerSigningShareB64u,
        keyVersion: 'v1',
        recoveryExportCapable: true,
      },
      accessKeysOnChain: [fixture.signerPublicKey],
      dispatchNearTransaction: async ({ signedTransactionBorshB64u }) => {
        dispatched.push(signedTransactionBorshB64u);
        return { rpcResult: { status: { SuccessValue: '' } } };
      },
    });
    const scheme = svc.getSchemeModule(THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID);
    if (!scheme || scheme.schemeId !== THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID) {
      throw new Error('missing Ed25519 scheme');
    }
    await seedBudget(authSessionStore, 1);
    await sessionStore.putPresign('presign-near-intent-mismatch', fixture.record, 60_000);

    const result = await scheme.presign.finalizeAndDispatch({
      claims: claims(),
      request: await nearTxRequest({
        operationId: 'operation-near-intent-mismatch',
        presignId: 'presign-near-intent-mismatch',
        fixture,
        transactions: mismatchedTransactions,
      }),
    });

    expect(result).toMatchObject({
      ok: false,
      code: 'invalid_body',
      budgetState: 'not_consumed',
      presignConsumed: false,
      dispatchState: 'not_attempted',
    });
    if (result.ok) throw new Error('expected NEAR intent mismatch to reject');
    expect(result.message).toContain('does not match txSigningRequests');
    expect(dispatched).toEqual([]);
    await expect(
      authSessionStore.getSessionStatus(WALLET_BUDGET_SESSION_ID),
    ).resolves.toMatchObject({
      remainingUses: 1,
    });
    await expect(
      sessionStore.takePresignForFinalize('presign-near-intent-mismatch', {
        thresholdSessionId: fixture.record.thresholdSessionId,
        walletSigningSessionId: fixture.record.walletSigningSessionId,
        relayerKeyId: fixture.record.relayerKeyId,
        nearAccountId: fixture.record.nearAccountId,
        nearNetworkId: fixture.record.nearNetworkId,
        signerPublicKey: fixture.record.signerPublicKey,
        rpcPolicyId: fixture.record.rpcPolicyId,
        rpId: fixture.record.rpId,
        runtimePolicyScope: fixture.record.runtimePolicyScope,
        participantIds: fixture.record.participantIds,
        groupPublicKey: fixture.record.groupPublicKey,
      }),
    ).resolves.toMatchObject({ ok: true });
  });

  test('NEAR finalize-and-dispatch rejects unsigned transaction signer account mismatch before consume', async () => {
    const fixture = await nearTxSuccessFixture({ unsignedNearAccountId: 'mallory.testnet' });
    const dispatched: string[] = [];
    const { svc, sessionStore, authSessionStore } = createThresholdSigningServiceForUnitTests({
      keyRecord: {
        publicKey: fixture.signerPublicKey,
        relayerSigningShareB64u: fixture.relayerSigningShareB64u,
        keyVersion: 'v1',
        recoveryExportCapable: true,
      },
      dispatchNearTransaction: async ({ signedTransactionBorshB64u }) => {
        dispatched.push(signedTransactionBorshB64u);
        return { rpcResult: { status: { SuccessValue: '' } } };
      },
    });
    const scheme = svc.getSchemeModule(THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID);
    if (!scheme || scheme.schemeId !== THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID) {
      throw new Error('missing Ed25519 scheme');
    }
    await seedBudget(authSessionStore, 1);
    await sessionStore.putPresign('presign-near-account-mismatch', fixture.record, 60_000);

    const result = await scheme.presign.finalizeAndDispatch({
      claims: claims(),
      request: await nearTxRequest({
        operationId: 'operation-near-account-mismatch',
        presignId: 'presign-near-account-mismatch',
        fixture,
      }),
    });

    expect(result).toMatchObject({
      ok: false,
      code: 'transaction_scope_mismatch',
      budgetState: 'not_consumed',
      presignConsumed: false,
      dispatchState: 'not_attempted',
    });
    expect(dispatched).toEqual([]);
    await expect(
      authSessionStore.getSessionStatus(WALLET_BUDGET_SESSION_ID),
    ).resolves.toMatchObject({
      remainingUses: 1,
    });
  });

  test('NEAR finalize-and-dispatch rejects unsigned transaction signer key mismatch before consume', async () => {
    const fixture = await nearTxSuccessFixture({ unsignedSignerPublicKey: SIGNER_PUBLIC_KEY });
    const dispatched: string[] = [];
    const { svc, sessionStore, authSessionStore } = createThresholdSigningServiceForUnitTests({
      keyRecord: {
        publicKey: fixture.signerPublicKey,
        relayerSigningShareB64u: fixture.relayerSigningShareB64u,
        keyVersion: 'v1',
        recoveryExportCapable: true,
      },
      dispatchNearTransaction: async ({ signedTransactionBorshB64u }) => {
        dispatched.push(signedTransactionBorshB64u);
        return { rpcResult: { status: { SuccessValue: '' } } };
      },
    });
    const scheme = svc.getSchemeModule(THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID);
    if (!scheme || scheme.schemeId !== THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID) {
      throw new Error('missing Ed25519 scheme');
    }
    await seedBudget(authSessionStore, 1);
    await sessionStore.putPresign('presign-near-key-mismatch', fixture.record, 60_000);

    const result = await scheme.presign.finalizeAndDispatch({
      claims: claims(),
      request: await nearTxRequest({
        operationId: 'operation-near-key-mismatch',
        presignId: 'presign-near-key-mismatch',
        fixture,
      }),
    });

    expect(result).toMatchObject({
      ok: false,
      code: 'transaction_signer_key_mismatch',
      budgetState: 'not_consumed',
      presignConsumed: false,
      dispatchState: 'not_attempted',
    });
    expect(dispatched).toEqual([]);
    await expect(
      authSessionStore.getSessionStatus(WALLET_BUDGET_SESSION_ID),
    ).resolves.toMatchObject({
      remainingUses: 1,
    });
  });

  test('NEAR finalize-and-dispatch rejects network scope mismatch before consuming budget', async () => {
    const fixture = await nearTxSuccessFixture();
    const dispatched: string[] = [];
    const { svc, sessionStore, authSessionStore } = createThresholdSigningServiceForUnitTests({
      keyRecord: {
        publicKey: fixture.signerPublicKey,
        relayerSigningShareB64u: fixture.relayerSigningShareB64u,
        keyVersion: 'v1',
        recoveryExportCapable: true,
      },
      accessKeysOnChain: [fixture.signerPublicKey],
      dispatchNearTransaction: async ({ signedTransactionBorshB64u }) => {
        dispatched.push(signedTransactionBorshB64u);
        return { rpcResult: { status: { SuccessValue: '' } } };
      },
    });
    const scheme = svc.getSchemeModule(THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID);
    if (!scheme || scheme.schemeId !== THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID) {
      throw new Error('missing Ed25519 scheme');
    }
    await seedBudget(authSessionStore, 1);
    await sessionStore.putPresign('presign-near-network-mismatch', fixture.record, 60_000);

    const result = await scheme.presign.finalizeAndDispatch({
      claims: claims(),
      request: await nearTxRequest({
        operationId: 'operation-near-network-mismatch',
        presignId: 'presign-near-network-mismatch',
        fixture,
        nearNetworkId: 'mainnet',
      }),
    });

    expect(result).toMatchObject({
      ok: false,
      code: 'wrong_scope',
      budgetState: 'not_consumed',
      presignConsumed: false,
      dispatchState: 'not_attempted',
    });
    expect(dispatched).toEqual([]);
    await expect(
      authSessionStore.getSessionStatus(WALLET_BUDGET_SESSION_ID),
    ).resolves.toMatchObject({
      remainingUses: 1,
    });
  });

  test('NEAR finalize-and-dispatch rejects missing active access key before consume', async () => {
    const fixture = await nearTxSuccessFixture();
    const dispatched: string[] = [];
    const { svc, sessionStore, authSessionStore } = createThresholdSigningServiceForUnitTests({
      keyRecord: {
        publicKey: fixture.signerPublicKey,
        relayerSigningShareB64u: fixture.relayerSigningShareB64u,
        keyVersion: 'v1',
        recoveryExportCapable: true,
      },
      accessKeysOnChain: [],
      dispatchNearTransaction: async ({ signedTransactionBorshB64u }) => {
        dispatched.push(signedTransactionBorshB64u);
        return { rpcResult: { status: { SuccessValue: '' } } };
      },
    });
    const scheme = svc.getSchemeModule(THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID);
    if (!scheme || scheme.schemeId !== THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID) {
      throw new Error('missing Ed25519 scheme');
    }
    await seedBudget(authSessionStore, 1);
    await sessionStore.putPresign('presign-near-missing-access-key', fixture.record, 60_000);

    const result = await scheme.presign.finalizeAndDispatch({
      claims: claims(),
      request: await nearTxRequest({
        operationId: 'operation-near-missing-access-key',
        presignId: 'presign-near-missing-access-key',
        fixture,
      }),
    });

    expect(result).toMatchObject({
      ok: false,
      code: 'transaction_signer_key_mismatch',
      budgetState: 'not_consumed',
      presignConsumed: false,
      dispatchState: 'not_attempted',
    });
    expect(dispatched).toEqual([]);
    await expect(
      authSessionStore.getSessionStatus(WALLET_BUDGET_SESSION_ID),
    ).resolves.toMatchObject({
      remainingUses: 1,
    });
  });

  test('NEAR finalize-and-dispatch rejects stale transaction nonce before consume', async () => {
    const fixture = await nearTxSuccessFixture();
    const dispatched: string[] = [];
    const { svc, sessionStore, authSessionStore } = createThresholdSigningServiceForUnitTests({
      keyRecord: {
        publicKey: fixture.signerPublicKey,
        relayerSigningShareB64u: fixture.relayerSigningShareB64u,
        keyVersion: 'v1',
        recoveryExportCapable: true,
      },
      accessKeysOnChain: [{ publicKey: fixture.signerPublicKey, nonce: 1 }],
      dispatchNearTransaction: async ({ signedTransactionBorshB64u }) => {
        dispatched.push(signedTransactionBorshB64u);
        return { rpcResult: { status: { SuccessValue: '' } } };
      },
    });
    const scheme = svc.getSchemeModule(THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID);
    if (!scheme || scheme.schemeId !== THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID) {
      throw new Error('missing Ed25519 scheme');
    }
    await seedBudget(authSessionStore, 1);
    await sessionStore.putPresign('presign-near-stale-nonce', fixture.record, 60_000);

    const result = await scheme.presign.finalizeAndDispatch({
      claims: claims(),
      request: await nearTxRequest({
        operationId: 'operation-near-stale-nonce',
        presignId: 'presign-near-stale-nonce',
        fixture,
      }),
    });

    expect(result).toMatchObject({
      ok: false,
      code: 'transaction_scope_mismatch',
      budgetState: 'not_consumed',
      presignConsumed: false,
      dispatchState: 'not_attempted',
    });
    expect(dispatched).toEqual([]);
    await expect(
      authSessionStore.getSessionStatus(WALLET_BUDGET_SESSION_ID),
    ).resolves.toMatchObject({
      remainingUses: 1,
    });
  });

  test('NEAR finalize-and-dispatch reports attempted dispatch failure after signature build', async () => {
    const fixture = await nearTxSuccessFixture();
    const { svc, sessionStore, authSessionStore } = createThresholdSigningServiceForUnitTests({
      keyRecord: {
        publicKey: fixture.signerPublicKey,
        relayerSigningShareB64u: fixture.relayerSigningShareB64u,
        keyVersion: 'v1',
        recoveryExportCapable: true,
      },
      accessKeysOnChain: [fixture.signerPublicKey],
      dispatchNearTransaction: async () => {
        throw new Error('mock NEAR RPC dispatch failed');
      },
    });
    const scheme = svc.getSchemeModule(THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID);
    if (!scheme || scheme.schemeId !== THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID) {
      throw new Error('missing Ed25519 scheme');
    }
    await seedBudget(authSessionStore, 1);
    await sessionStore.putPresign('presign-near-dispatch-failed', fixture.record, 60_000);

    const result = await scheme.presign.finalizeAndDispatch({
      claims: claims(),
      request: await nearTxRequest({
        operationId: 'operation-near-dispatch-failed',
        presignId: 'presign-near-dispatch-failed',
        fixture,
      }),
    });

    expect(result).toMatchObject({
      ok: false,
      code: 'dispatch_failed',
      budgetState: 'consumed',
      presignConsumed: true,
      dispatchState: 'attempted',
    });
    await expect(
      authSessionStore.getSessionStatus(WALLET_BUDGET_SESSION_ID),
    ).resolves.toMatchObject({
      remainingUses: 0,
    });
  });

  test('client share signed for a different intent rejects after consuming presign and budget', async () => {
    const fixture = await successFixture();
    const { svc, sessionStore, authSessionStore } = createThresholdSigningServiceForUnitTests({
      keyRecord: {
        publicKey: fixture.signerPublicKey,
        relayerSigningShareB64u: fixture.relayerSigningShareB64u,
        keyVersion: 'v1',
        recoveryExportCapable: true,
      },
    });
    const scheme = svc.getSchemeModule(THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID);
    if (!scheme || scheme.schemeId !== THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID) {
      throw new Error('missing Ed25519 scheme');
    }
    await seedBudget(authSessionStore, 1);
    await sessionStore.putPresign('presign-digest-mismatch', fixture.record, 60_000);

    const result = await scheme.presign.finalizeAndDispatch({
      claims: claims(),
      request: await signatureOnlyRequest({
        operationId: 'operation-digest-mismatch',
        presignId: 'presign-digest-mismatch',
        expectedSignerPublicKey: fixture.signerPublicKey,
        clientSignatureShareB64u: fixture.clientSignatureShareB64u,
        intent: {
          kind: 'nep413_message_v1',
          message: 'different message',
          recipient: DEFAULT_NEP413_INTENT.recipient,
          nonce: DEFAULT_NEP413_INTENT.nonce,
          state: DEFAULT_NEP413_INTENT.state,
        },
      }),
    });

    expect(result).toMatchObject({
      ok: false,
      code: 'signature_verification_failed',
      budgetState: 'consumed',
      presignConsumed: true,
      dispatchState: 'not_attempted',
    });
    await expect(
      authSessionStore.getSessionStatus(WALLET_BUDGET_SESSION_ID),
    ).resolves.toMatchObject({
      remainingUses: 0,
    });
    await expect(
      sessionStore.takePresignForFinalize('presign-digest-mismatch', {
        thresholdSessionId: SESSION_ID,
        walletSigningSessionId: WALLET_SIGNING_SESSION_ID,
        relayerKeyId: RELAYER_KEY_ID,
        nearAccountId: WALLET_ID,
        nearNetworkId: 'testnet',
        signerPublicKey: fixture.signerPublicKey,
        rpcPolicyId: 'ed25519-presign-finalize',
        rpId: RP_ID,
        runtimePolicyScope,
        participantIds: [1, 2],
        groupPublicKey: fixture.signerPublicKey,
      }),
    ).resolves.toEqual({ ok: false, code: 'not_found' });
  });

  test('delegate client share signed for a different digest rejects after consuming presign and budget', async () => {
    const fixture = await successFixture({
      signingDigestForSignerPublicKey: (publicKey) =>
        signatureOnlyIntentSigningDigestB64u(delegateIntent({ publicKey })),
    });
    const { svc, sessionStore, authSessionStore } = createThresholdSigningServiceForUnitTests({
      keyRecord: {
        publicKey: fixture.signerPublicKey,
        relayerSigningShareB64u: fixture.relayerSigningShareB64u,
        keyVersion: 'v1',
        recoveryExportCapable: true,
      },
    });
    const scheme = svc.getSchemeModule(THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID);
    if (!scheme || scheme.schemeId !== THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID) {
      throw new Error('missing Ed25519 scheme');
    }
    await seedBudget(authSessionStore, 1);
    await sessionStore.putPresign('presign-delegate-digest-mismatch', fixture.record, 60_000);

    const result = await scheme.presign.finalizeAndDispatch({
      claims: claims(),
      request: await signatureOnlyRequest({
        operationId: 'operation-delegate-digest-mismatch',
        presignId: 'presign-delegate-digest-mismatch',
        expectedSignerPublicKey: fixture.signerPublicKey,
        clientSignatureShareB64u: fixture.clientSignatureShareB64u,
        intent: delegateIntent({
          publicKey: fixture.signerPublicKey,
          receiverId: 'changed-receiver.testnet',
        }),
      }),
    });

    expect(result).toMatchObject({
      ok: false,
      code: 'signature_verification_failed',
      budgetState: 'consumed',
      presignConsumed: true,
      dispatchState: 'not_attempted',
    });
    await expect(
      authSessionStore.getSessionStatus(WALLET_BUDGET_SESSION_ID),
    ).resolves.toMatchObject({
      remainingUses: 0,
    });
    await expect(
      sessionStore.takePresignForFinalize('presign-delegate-digest-mismatch', {
        thresholdSessionId: SESSION_ID,
        walletSigningSessionId: WALLET_SIGNING_SESSION_ID,
        relayerKeyId: RELAYER_KEY_ID,
        nearAccountId: WALLET_ID,
        nearNetworkId: 'testnet',
        signerPublicKey: fixture.signerPublicKey,
        rpcPolicyId: 'ed25519-presign-finalize',
        rpId: RP_ID,
        runtimePolicyScope,
        participantIds: [1, 2],
        groupPublicKey: fixture.signerPublicKey,
      }),
    ).resolves.toEqual({ ok: false, code: 'not_found' });
  });

  test('invalid signature material burns consumed presign and decrements budget', async () => {
    const logs: unknown[][] = [];
    const { svc, sessionStore, authSessionStore } = createThresholdSigningServiceForUnitTests({
      logger: {
        info: (...args: unknown[]) => logs.push(args),
      },
      keyRecord: {
        publicKey: SIGNER_PUBLIC_KEY,
        relayerSigningShareB64u: RELAYER_SIGNING_SHARE_B64U,
        keyVersion: 'v1',
        recoveryExportCapable: true,
      },
    });
    const scheme = svc.getSchemeModule(THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID);
    if (!scheme || scheme.schemeId !== THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID) {
      throw new Error('missing Ed25519 scheme');
    }
    await seedBudget(authSessionStore, 1);
    await sessionStore.putPresign('presign-invalid-share', presignRecord(), 60_000);

    const result = await scheme.presign.finalizeAndDispatch({
      claims: claims(),
      request: await signatureOnlyRequest({
        operationId: 'operation-invalid-share',
        presignId: 'presign-invalid-share',
      }),
    });

    expect(result).toMatchObject({
      ok: false,
      code: 'invalid_signature_share',
      budgetState: 'consumed',
      presignConsumed: true,
      dispatchState: 'not_attempted',
    });
    await expect(
      authSessionStore.getSessionStatus(WALLET_BUDGET_SESSION_ID),
    ).resolves.toMatchObject({
      remainingUses: 0,
    });
    const replay = await scheme.presign.finalizeAndDispatch({
      claims: claims(),
      request: await signatureOnlyRequest({
        operationId: 'operation-missing-consumed-presign',
        presignId: 'presign-invalid-share',
      }),
    });
    expect(replay).toMatchObject({
      ok: false,
      code: 'presign_unavailable',
      budgetState: 'not_consumed',
      presignConsumed: false,
      dispatchState: 'not_attempted',
    });
    await expect(
      authSessionStore.getSessionStatus(WALLET_BUDGET_SESSION_ID),
    ).resolves.toMatchObject({
      remainingUses: 0,
    });
    const metricLogs = logs.filter((entry) => entry[0] === '[threshold-ed25519-presign-metrics]');
    expect(metricLogs).toEqual([
      [
        '[threshold-ed25519-presign-metrics]',
        expect.objectContaining({
          metric: 'ed25519_presign_finalize_take_result',
          takeResult: 'consumed',
          doubleConsumeAttempt: false,
          ttlCleanupCount: 0,
        }),
      ],
      [
        '[threshold-ed25519-presign-metrics]',
        expect.objectContaining({
          metric: 'ed25519_presign_finalize_take_result',
          takeResult: 'not_found',
          doubleConsumeAttempt: true,
          ttlCleanupCount: 0,
          code: 'not_found',
        }),
      ],
    ]);
    const serialized = JSON.stringify(metricLogs);
    expect(serialized).not.toContain(RELAYER_SIGNING_SHARE_B64U);
    expect(serialized).not.toContain('invalid-relayer-nonces');
    expect(serialized).not.toContain('client-signature-share');
    expect(serialized).not.toContain('client-hiding');
    expect(serialized).not.toContain('client-binding');
    await expect(
      sessionStore.takePresignForFinalize('presign-invalid-share', {
        thresholdSessionId: SESSION_ID,
        walletSigningSessionId: WALLET_SIGNING_SESSION_ID,
        relayerKeyId: RELAYER_KEY_ID,
        nearAccountId: WALLET_ID,
        nearNetworkId: 'testnet',
        signerPublicKey: SIGNER_PUBLIC_KEY,
        rpcPolicyId: 'ed25519-presign-finalize',
        rpId: RP_ID,
        runtimePolicyScope,
        participantIds: [1, 2],
        groupPublicKey: SIGNER_PUBLIC_KEY,
      }),
    ).resolves.toEqual({ ok: false, code: 'not_found' });
  });

  test('budget operation conflict rejects before consuming a fresh presign', async () => {
    const { svc, sessionStore, authSessionStore } = createThresholdSigningServiceForUnitTests({
      keyRecord: {
        publicKey: SIGNER_PUBLIC_KEY,
        relayerSigningShareB64u: RELAYER_SIGNING_SHARE_B64U,
        keyVersion: 'v1',
        recoveryExportCapable: true,
      },
    });
    const scheme = svc.getSchemeModule(THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID);
    if (!scheme || scheme.schemeId !== THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID) {
      throw new Error('missing Ed25519 scheme');
    }
    await seedBudget(authSessionStore, 1);
    await sessionStore.putPresign('presign-budget-first', presignRecord(), 60_000);

    const request = await signatureOnlyRequest({
      operationId: 'operation-budget-conflict',
      presignId: 'presign-budget-first',
    });

    await expect(
      scheme.presign.finalizeAndDispatch({
        claims: claims(),
        request,
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'invalid_signature_share',
      budgetState: 'consumed',
      presignConsumed: true,
      dispatchState: 'not_attempted',
    });
    await sessionStore.putPresign('presign-budget-conflict', presignRecord(), 60_000);
    const conflictRequest = {
      ...request,
      presignId: 'presign-budget-conflict',
      requestIntegrityHash: '',
    };
    conflictRequest.requestIntegrityHash =
      await thresholdEd25519FinalizeRequestIntegrityHash(conflictRequest);

    const conflict = await scheme.presign.finalizeAndDispatch({
      claims: claims(),
      request: conflictRequest,
    });
    expect(conflict).toMatchObject({
      ok: false,
      code: 'budget_operation_conflict',
      budgetState: 'already_consumed',
      presignConsumed: false,
      dispatchState: 'not_attempted',
    });
    await expect(
      authSessionStore.getSessionStatus(WALLET_BUDGET_SESSION_ID),
    ).resolves.toMatchObject({
      remainingUses: 0,
    });
    await expect(
      sessionStore.takePresignForFinalize('presign-budget-conflict', {
        thresholdSessionId: SESSION_ID,
        walletSigningSessionId: WALLET_SIGNING_SESSION_ID,
        relayerKeyId: RELAYER_KEY_ID,
        nearAccountId: WALLET_ID,
        nearNetworkId: 'testnet',
        signerPublicKey: SIGNER_PUBLIC_KEY,
        rpcPolicyId: 'ed25519-presign-finalize',
        rpId: RP_ID,
        runtimePolicyScope,
        participantIds: [1, 2],
        groupPublicKey: SIGNER_PUBLIC_KEY,
      }),
    ).resolves.toMatchObject({ ok: true });
  });
});
