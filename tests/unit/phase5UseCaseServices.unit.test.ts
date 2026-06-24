import { expect, test } from '@playwright/test';
import { base64UrlEncode } from '@shared/utils/base64';
import {
  buildEcdsaRoleLocalPasskeyAuthMethod,
  buildEcdsaRoleLocalPublicFacts,
  buildEcdsaRoleLocalReadyRecord,
} from '@/core/signingEngine/session/persistence/ecdsaRoleLocalRecords';
import {
  thresholdEcdsaChainTargetFromChainFamily,
  toWalletId,
  type EvmEip155ChainTarget,
  type TempoChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { toRpId } from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import {
  buildRelayerKeyId,
  type CredentialIdB64u,
  type EcdsaRoleLocalReadyRecord,
} from '@/core/platform';
import type { AccountId } from '@/core/types/accountIds';
import type { EvmAddress, EvmSigningRequest, Hex } from '@/core/signingEngine/chains/evm/evmSigning.types';
import type {
  NearTransactionWithActionsPayload,
  NearTransactionWithActionsResult,
} from '@/core/signingEngine/interfaces/near';
import {
  createRegisterWalletUseCase,
  type RegisterWalletDeps,
} from '@/core/signingEngine/useCases/registerWallet';
import {
  createRestorePersistedSessionsUseCase,
  type RestorePersistedSessionsDeps,
} from '@/core/signingEngine/useCases/restorePersistedSessions';
import {
  createSignEvmFamilyUseCase,
  type SignEvmFamilyDeps,
} from '@/core/signingEngine/useCases/signEvmFamily';
import { createSignNearUseCase, type SignNearDeps } from '@/core/signingEngine/useCases/signNear';
import {
  createUnlockWalletUseCase,
  type UnlockWalletDeps,
} from '@/core/signingEngine/useCases/unlockWallet';
import type {
  Ed25519RelayerKeyId,
  EcdsaRelayerKeyId,
  IdempotencyKey,
  NearTransactionDigest,
  EcdsaUseCaseReadyLane,
  ReadyEd25519Lane,
  RestoreAttemptId,
  SigningSessionActivationPasskeyAuth,
  SigningSessionSealWriteInput,
  UnixTimeMs,
  WarmSessionBudgetSpend,
  WarmSessionRemainingUses,
  WebAuthnUserHandle,
} from '@/core/signingEngine/useCases/lifecycle';
import type {
  SigningOperationId,
  ThresholdSessionId,
  SigningGrantId,
} from '@/core/signingEngine/session/operationState/types';

function b64u(length: number, fill: number): string {
  return base64UrlEncode(new Uint8Array(length).fill(fill));
}

function publicKey33(fill: number): string {
  const bytes = new Uint8Array(33).fill(fill);
  bytes[0] = fill % 2 === 0 ? 2 : 3;
  return base64UrlEncode(bytes);
}

function asBrand<T>(value: unknown): T {
  return value as T;
}

const walletId = toWalletId('phase5-wallet');
const rpId = toRpId('wallet.example');
const walletKeyId = asBrand<EcdsaUseCaseReadyLane['walletKeyId']>('wallet-key-phase5');
const evmTarget = thresholdEcdsaChainTargetFromChainFamily({
  chain: 'evm',
  chainId: 11155111,
}) as EvmEip155ChainTarget;
const tempoTarget = thresholdEcdsaChainTargetFromChainFamily({
  chain: 'tempo',
  chainId: 42431,
}) as TempoChainTarget;
const credentialIdB64u = buildEcdsaRoleLocalPasskeyAuthMethod({
  credentialIdB64u: 'credential-phase5',
  rpId,
}).credentialIdB64u;
const ecdsaKeyHandle = 'key-handle-phase5';
const thresholdSessionId = asBrand<ThresholdSessionId>('threshold-session');
const signingGrantId = asBrand<SigningGrantId>('wallet-session');
const expiresAtMs = asBrand<UnixTimeMs>(1_900_000_000_000);
const remainingUses = asBrand<WarmSessionRemainingUses>(8);
const idempotencyKey = asBrand<IdempotencyKey>('idempotency-key');
const operationId = asBrand<SigningOperationId>('operation-id');
const restoreAttemptId = asBrand<RestoreAttemptId>('restore-attempt');
const budgetSpend: WarmSessionBudgetSpend = {
  kind: 'warm_session_budget_spend_v1',
  walletId,
  signingGrantId,
  thresholdSessionId,
  uses: asBrand(1),
  remainingUses,
};

function readyRecord(chainTarget = evmTarget): EcdsaRoleLocalReadyRecord {
  const publicFacts = buildEcdsaRoleLocalPublicFacts({
    walletId,
    walletKeyId,
    chainTarget,
    keyHandle: ecdsaKeyHandle,
    ecdsaThresholdKeyId: 'ecdsa-key',
    signingRootId: 'signing-root',
    signingRootVersion: 'v1',
    clientParticipantId: 1,
    relayerParticipantId: 2,
    participantIds: [1, 2],
    contextBinding32B64u: b64u(32, 7),
    hssClientSharePublicKey33B64u: publicKey33(8),
    relayerPublicKey33B64u: publicKey33(10),
    groupPublicKey33B64u: publicKey33(12),
    ethereumAddress: '0x1111111111111111111111111111111111111111',
  });
  return buildEcdsaRoleLocalReadyRecord({
    stateBlob: {
      kind: 'ecdsa_role_local_state_blob_v1',
      curve: 'secp256k1',
      encoding: 'base64url',
      producer: 'signer_core',
      stateBlobB64u: b64u(64, 13),
    },
    publicFacts,
    authMethod: buildEcdsaRoleLocalPasskeyAuthMethod({
      credentialIdB64u,
      rpId,
    }),
  });
}

const passkeyAuth: SigningSessionActivationPasskeyAuth = {
  kind: 'passkey',
  walletId,
  rpId,
  credentialIdB64u,
};

function readyEd25519Lane(): ReadyEd25519Lane {
  return {
    kind: 'ed25519_ready_lane_v1',
    walletId,
    rpId,
    thresholdSessionId,
    signingGrantId,
    relayerKeyId: buildRelayerKeyId('ed25519-relayer') as Ed25519RelayerKeyId,
    remainingUses,
    expiresAtMs,
  };
}

function readyEcdsaLane(chainTarget = evmTarget): EcdsaUseCaseReadyLane {
  return {
    kind: 'ecdsa_ready_lane_v1',
    walletId,
    walletKeyId,
    rpId,
    chainTarget,
    readyRecord: readyRecord(chainTarget),
    relayerKeyId: buildRelayerKeyId('ecdsa-relayer') as EcdsaRelayerKeyId,
    thresholdSessionId,
    signingGrantId,
    remainingUses,
    expiresAtMs,
  };
}

function ed25519SealWrite(lane = readyEd25519Lane()): SigningSessionSealWriteInput {
  return {
    kind: 'passkey_ed25519_seal_write_v1',
    auth: passkeyAuth,
    material: {
      kind: 'ed25519_session',
      thresholdSessionId: lane.thresholdSessionId,
      signingGrantId: lane.signingGrantId,
      relayerKeyId: lane.relayerKeyId,
    },
    expiresAtMs,
    remainingUses,
  };
}

function ecdsaSealWrite(lane = readyEcdsaLane()): SigningSessionSealWriteInput {
  return {
    kind: 'passkey_ecdsa_seal_write_v1',
    auth: passkeyAuth,
    material: {
      kind: 'ecdsa_session',
      thresholdSessionId: lane.thresholdSessionId,
      signingGrantId: lane.signingGrantId,
      record: lane.readyRecord,
    },
    expiresAtMs,
    remainingUses,
  };
}

test('RegisterWalletUseCase provisions Ed25519 and exact requested ECDSA lanes before commit', async () => {
  const lifecycle: string[] = [];
  const ed25519 = readyEd25519Lane();
  const ecdsa = readyEcdsaLane();
  const deps: RegisterWalletDeps = {
    authenticator: { authenticate: async () => ({ ok: true }) },
    ed25519Provisioner: {
      provision: async () => ({
        ok: true,
        lane: ed25519,
        sealWrite: ed25519SealWrite(ed25519),
        walletSignerWrite: { kind: 'ed25519_wallet_signer_write_v1', lane: ed25519 },
      }),
    },
    ecdsaProvisioner: {
      provision: async () => ({
        ok: true,
        lanes: [ecdsa],
        sealWrites: [ecdsaSealWrite(ecdsa)],
        walletSignerWrites: [{ kind: 'ecdsa_wallet_signer_write_v1', lane: ecdsa }],
      }),
    },
    walletStore: { commitRegistration: async () => ({ ok: true }) },
    lifecycle: {
      transition: (state) => {
        lifecycle.push(state.kind);
      },
    },
  };

  const result = await createRegisterWalletUseCase(deps).register({
    walletId,
    rpId,
    auth: {
      kind: 'passkey_registration',
      credentialCreation: {
        kind: 'authenticator_create_request_v1',
        challengeB64u: b64u(32, 1),
        userHandleB64u: b64u(16, 2),
      },
      userHandle: asBrand<WebAuthnUserHandle>('user-handle'),
    },
    ecdsaTargets: { kind: 'explicit', targets: [evmTarget] },
    idempotencyKey,
  });

  expect(result).toMatchObject({
    ok: true,
    walletId,
    lanes: { ed25519, ecdsa: [ecdsa] },
  });
  expect(lifecycle).toEqual([
    'received_input',
    'authenticating',
    'provisioning_ed25519',
    'provisioning_ecdsa',
    'sealing_sessions',
    'persisting_wallet',
    'ready',
  ]);
});

test('UnlockWalletUseCase provisions missing ECDSA targets and writes all seals once', async () => {
  const ed25519 = readyEd25519Lane();
  const ecdsa = readyEcdsaLane();
  const written: readonly SigningSessionSealWriteInput[][] = [];
  const deps: UnlockWalletDeps = {
    authenticator: { authenticate: async () => ({ ok: true }) },
    sessionRestorer: {
      restore: async () => ({
        ok: true,
        restored: [ed25519],
        reauthRequired: [],
        missingEcdsaTargets: [evmTarget],
        sealWrites: [ed25519SealWrite(ed25519)],
      }),
    },
    ecdsaProvisioner: {
      provisionMissing: async ({ missingTargets }) => ({
        ok: true,
        provisioned: missingTargets.map(() => ecdsa),
        sealWrites: [ecdsaSealWrite(ecdsa)],
      }),
    },
    sealWriter: {
      writeAll: async (writes) => {
        (written as SigningSessionSealWriteInput[][]).push([...writes]);
        return { ok: true };
      },
    },
    readiness: {
      resolve: () => ({
        kind: 'ready',
        walletId,
        ed25519: [ed25519],
        ecdsa: [ecdsa],
      }),
    },
  };

  const result = await createUnlockWalletUseCase(deps).unlock({
    walletId,
    rpId,
    auth: {
      kind: 'passkey_unlock',
      credentialId: credentialIdB64u,
      assertionRequest: {
        kind: 'authenticator_get_request_v1',
        challengeB64u: b64u(32, 3),
        credentialIdB64u,
      },
    },
    ecdsaTargets: { kind: 'explicit', targets: [evmTarget] },
    idempotencyKey,
  });

  expect(result).toMatchObject({ ok: true, provisioned: [ecdsa] });
  expect(written).toHaveLength(1);
  expect(written[0]).toHaveLength(2);
});

test('SignEvmFamilyUseCase signs only after exact lane resolution and budget reservation', async () => {
  const lane = readyEcdsaLane(evmTarget);
  const deps: SignEvmFamilyDeps = {
    laneResolver: {
      resolve: async () => ({ ok: true, lane, usedAuth: 'warm_session' }),
    },
    budget: {
      reserve: async () => ({ ok: true, budgetSpend }),
    },
    signer: {
      sign: async ({ input }) => ({
        ok: true,
        kind: 'evm_transaction',
        walletId: input.walletId,
        usedAuth: 'warm_session',
        signerLane: lane,
        budgetSpend,
        chainTarget: evmTarget,
        result: {
          kind: 'evm_signature',
          signature: { kind: 'ecdsa_secp256k1_signature_v1', signatureHex: '0x01' },
          nonceSender: '0x1111111111111111111111111111111111111111' as EvmAddress,
        },
      }),
    },
  };
  const evmRequest: EvmSigningRequest = {
    chain: 'evm',
    kind: 'eip1559',
    tx: {
      chainId: 11155111,
      maxPriorityFeePerGas: 1n,
      maxFeePerGas: 1n,
      gasLimit: 21_000n,
      value: 0n,
    },
    senderSignatureAlgorithm: 'secp256k1',
  };

  await expect(
    createSignEvmFamilyUseCase(deps).sign({
      kind: 'evm_transaction',
      operationId,
      walletId,
      rpId,
      chainTarget: evmTarget,
      request: evmRequest,
      authPolicy: { kind: 'warm_session_only' },
    }),
  ).resolves.toMatchObject({ ok: true, kind: 'evm_transaction' });
});

test('SignNearUseCase rejects request validation failures before budget and signer ports', async () => {
  const lane = readyEd25519Lane();
  let budgetCalls = 0;
  const deps: SignNearDeps = {
    laneResolver: {
      resolve: async () => ({
        ok: true,
        lane,
        usedAuth: 'warm_session',
        signingPath: 'presign_pool',
      }),
    },
    requestValidator: {
      validate: async () => ({
        ok: false,
        code: 'digest_mismatch',
        source: 'domain',
        message: 'digest mismatch',
        retryable: false,
      }),
    },
    budget: {
      reserve: async () => {
        budgetCalls += 1;
        return { ok: true, budgetSpend };
      },
    },
    signer: {
      sign: async () => {
        throw new Error('signer should not run');
      },
    },
  };

  const result = await createSignNearUseCase(deps).sign({
    kind: 'transaction_with_actions',
    operationId,
    walletId,
    rpId,
    accountId: asBrand<AccountId>('alice.testnet'),
    request: {} as NearTransactionWithActionsPayload,
    transactionDigests: [asBrand<NearTransactionDigest>('digest')],
    requiredSignatureUses: asBrand(1),
    authPolicy: { kind: 'warm_session_only' },
  });

  expect(result).toMatchObject({ ok: false, code: 'digest_mismatch' });
  expect(budgetCalls).toBe(0);
});

test('RestorePersistedSessionsUseCase cleans classified stale records before returning readiness', async () => {
  const ed25519 = readyEd25519Lane();
  const cleaned: string[] = [];
  const deps: RestorePersistedSessionsDeps = {
    reader: {
      read: async () => ({
        ok: true,
        material: [ed25519],
        cleanup: [
          {
            kind: 'cleanup_required',
            walletId,
            rpId,
            target: { kind: 'ed25519' },
            reason: 'expired_record',
          },
        ],
      }),
    },
    classifier: {
      classify: async ({ cleanup }) => ({
        ok: true,
        readiness: {
          kind: 'ready',
          walletId,
          ed25519: [ed25519],
          ecdsa: [],
        },
        restored: [ed25519],
        reauthRequired: [],
        cleanup,
      }),
    },
    cleanup: {
      clean: async (records) => {
        cleaned.push(records[0].reason);
        return { ok: true };
      },
    },
  };

  const result = await createRestorePersistedSessionsUseCase(deps).restore({
    restoreAttemptId,
    walletId,
    rpId,
    auth: { kind: 'missing_auth' },
    requested: [{ kind: 'ed25519' }],
    ecdsaTargets: { kind: 'configured' },
    reason: 'page_load',
  });

  expect(result).toMatchObject({ ok: true, restored: [ed25519] });
  expect(cleaned).toEqual(['expired_record']);
});
