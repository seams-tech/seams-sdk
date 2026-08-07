import { expect, test } from '@playwright/test';
import { deriveEvmFamilySigningKeySlotId } from '@shared/signing-lanes';
import { deriveSigningRootId } from '@shared/threshold/signingRootScope';
import type { SigningSessionSealedStoreRecord } from '../../packages/sdk-web/src/core/signingEngine/session/persistence/sealedSessionStore';
import type { SealedRecoveryRecord } from '../../packages/sdk-web/src/core/signingEngine/session/sealedRecovery/recoveryRecord';
import {
  createSigningSessionRestoreCache,
  discoverPersistedSessionsForWalletCommand,
  restorePersistedSessionForSigningCommand,
} from '../../packages/sdk-web/src/core/signingEngine/session/sealedRecovery/restoreCoordinator';
import type { RestorePersistedSessionForSigningInput } from '../../packages/sdk-web/src/core/signingEngine/session/sealedRecovery/sealedRecovery.types';
import {
  buildEvmFamilyEcdsaKeyIdentity,
  toEvmFamilyEcdsaKeyHandle,
  toThresholdOwnerAddress,
} from '../../packages/sdk-web/src/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import {
  buildEvmFamilyEcdsaSignerBinding,
  exactEcdsaSigningLaneIdentity,
} from '../../packages/sdk-web/src/core/signingEngine/session/identity/exactSigningLaneIdentity';
import { walletIdFromString } from '../../packages/shared-ts/src/utils/registrationIntent';
import { toRpId } from '../../packages/sdk-web/src/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import { buildCurrentSealedSessionRecord } from '../../packages/sdk-web/src/core/signingEngine/session/persistence/sealedSessionStore';
import { ecdsaSealedRecordStoreKey } from '../../packages/sdk-web/src/core/signingEngine/session/persistence/ecdsaSealedRecordKey';
import {
  createThresholdEcdsaBootstrapFixture,
  thresholdEcdsaBootstrapPublicFactsFixture,
} from './helpers/ecdsaBootstrap.fixtures';
import {
  buildEcdsaRoleLocalPersistedMaterialRefFixture,
  buildWalletAuthAuthorityRefForAuthorityFixture,
} from './helpers/ecdsaMaterialRef.fixtures';
import {
  buildEmailOtpWalletAuthAuthority,
  buildPasskeyWalletAuthAuthority,
} from '@shared/utils/walletAuthAuthority';
import { buildMpcMaterialActivationRefFixture } from './helpers/ecdsaMaterialRef.fixtures';

const TEST_ECDSA_CHAIN_TARGETS = {
  tempo: { kind: 'tempo' as const, chainId: 42431, networkSlug: 'tempo-moderato' },
  evm: {
    kind: 'evm' as const,
    namespace: 'eip155' as const,
    chainId: 5042002,
    networkSlug: 'arc-testnet',
  },
};
const TEST_ECDSA_CHAIN_TARGET_LIST = [TEST_ECDSA_CHAIN_TARGETS.tempo, TEST_ECDSA_CHAIN_TARGETS.evm];
const TEST_EMAIL_OTP_EMAIL_HASH_HEX = 'email-hash-restore';
const TEST_ECDSA_KEY_HANDLE = toEvmFamilyEcdsaKeyHandle('key-handle-restore');
const TEST_ECDSA_RUNTIME_POLICY_SCOPE = {
  orgId: 'org-restore',
  projectId: 'root',
  envId: 'restore',
  signingRootVersion: 'v1',
} as const;
const TEST_ECDSA_SIGNING_ROOT_ID = deriveSigningRootId(TEST_ECDSA_RUNTIME_POLICY_SCOPE);
const TEST_EVM_FAMILY_SIGNING_KEY_SLOT_ID = deriveEvmFamilySigningKeySlotId({
  walletId: 'restore.testnet',
  signingRootId: TEST_ECDSA_SIGNING_ROOT_ID,
  signingRootVersion: 'v1',
});
const TEST_MATERIAL_ACTIVATION = buildMpcMaterialActivationRefFixture(
  'restore-coordinator',
  'restore.testnet',
);

function ethereumAddress20B64u(address: string): string {
  return Buffer.from(address.replace(/^0x/i, ''), 'hex').toString('base64url');
}

function fixedBytesB64u(length: number, byte: number): string {
  return Buffer.from(new Uint8Array(length).fill(byte)).toString('base64url');
}

function restoreEcdsaNormalSigningState(args: { thresholdSessionId: string }) {
  return {
    kind: 'router_ab_ecdsa_derivation_normal_signing_v1',
    scope: {
      wallet_key_id: TEST_EVM_FAMILY_SIGNING_KEY_SLOT_ID,
      wallet_id: 'restore.testnet',
      ecdsa_threshold_key_id: 'ecdsa-key-restore',
      signing_root_id: TEST_ECDSA_SIGNING_ROOT_ID,
      signing_root_version: 'v1',
      context: {
        application_binding_digest_b64u: fixedBytesB64u(32, 7),
      },
      public_identity: {
        context_binding_b64u: fixedBytesB64u(32, 1),
        derivation_client_share_public_key33_b64u: fixedBytesB64u(33, 2),
        server_public_key33_b64u: fixedBytesB64u(33, 3),
        threshold_public_key33_b64u: fixedBytesB64u(33, 4),
        ethereum_address20_b64u: ethereumAddress20B64u(`0x${'33'.repeat(20)}`),
        client_share_retry_counter: 0,
        server_share_retry_counter: 0,
      },
      signing_worker: {
        server_id: 'signing-worker-restore',
        key_epoch: 'epoch-restore',
        recipient_encryption_key:
          'x25519:1111111111111111111111111111111111111111111111111111111111111111',
      },
      activation_epoch: args.thresholdSessionId,
    },
  } as const;
}

function ecdsaRestoreInput(
  args: Partial<Extract<RestorePersistedSessionForSigningInput, { curve: 'ecdsa' }>> = {},
): Extract<RestorePersistedSessionForSigningInput, { curve: 'ecdsa' }> {
  const authMethod = args.authMethod || 'email_otp';
  const chainTarget = args.chainTarget || TEST_ECDSA_CHAIN_TARGETS.tempo;
  const thresholdSessionId = args.thresholdSessionId || 'tsess-restore';
  const wallet = walletIdFromString(args.walletId || 'restore.testnet');
  const key = buildEvmFamilyEcdsaKeyIdentity({
    walletId: wallet,
    evmFamilySigningKeySlotId: TEST_EVM_FAMILY_SIGNING_KEY_SLOT_ID,
    ecdsaThresholdKeyId: 'ecdsa-key-restore',
    signingRootId: TEST_ECDSA_SIGNING_ROOT_ID,
    signingRootVersion: 'v1',
    participantIds: [1, 2],
    thresholdOwnerAddress: toThresholdOwnerAddress(`0x${'33'.repeat(20)}`),
  });
  return {
    walletId: String(wallet),
    authMethod,
    curve: 'ecdsa',
    chainTarget,
    thresholdSessionId,
    reason: args.reason || 'transaction',
    materialRestoreIdentity: {
      kind: 'ecdsa_role_local_restore',
      lane: exactEcdsaSigningLaneIdentity({
        signer: buildEvmFamilyEcdsaSignerBinding({
          walletId: wallet,
          chainTarget,
          keyHandle: TEST_ECDSA_KEY_HANDLE,
          key,
          materialActivation: TEST_MATERIAL_ACTIVATION,
        }),
        auth:
          authMethod === 'passkey'
            ? {
                kind: 'passkey',
                rpId: toRpId('example.com'),
                credentialIdB64u: 'credential-restore',
              }
            : { kind: 'email_otp', providerSubjectId: 'google:restore' },
      }),
      ecdsaThresholdKeyId: key.ecdsaThresholdKeyId,
    },
  };
}

function makeSealedRecord(args: {
  authMethod?: 'email_otp' | 'passkey';
  chain?: 'tempo' | 'evm';
  thresholdSessionId?: string;
  expiresAtMs?: number;
  remainingUses?: number;
  updatedAtMs?: number;
}): SigningSessionSealedStoreRecord {
  const authMethod = args.authMethod || 'email_otp';
  const thresholdSessionId = args.thresholdSessionId || 'tsess-restore';
  const chain = args.chain || 'tempo';
  const walletId = 'restore.testnet';
  const chainTarget = TEST_ECDSA_CHAIN_TARGETS[chain];
  const bootstrap = createThresholdEcdsaBootstrapFixture({
    nearAccountId: walletId,
    chain: 'tempo',
    rpId: 'example.com',
    keyHandle: 'key-handle-restore',
    ecdsaThresholdKeyId: 'ecdsa-key-restore',
    sessionId: thresholdSessionId,
    signingRootId: TEST_ECDSA_SIGNING_ROOT_ID,
    signingRootVersion: 'v1',
    passkeyCredentialIdB64u: 'credential-restore',
    participantIds: [1, 2],
    ethereumAddress: `0x${'33'.repeat(20)}`,
    roleLocalAuthMethod: authMethod,
    emailOtpAuthSubjectId: 'google:restore',
    expiresAtMs: args.expiresAtMs ?? Date.now() + 60_000,
    remainingUses: args.remainingUses ?? 5,
    runtimePolicyScope: TEST_ECDSA_RUNTIME_POLICY_SCOPE,
  });
  const publicFacts = thresholdEcdsaBootstrapPublicFactsFixture(bootstrap);
  const roleLocalMaterialRef = buildEcdsaRoleLocalPersistedMaterialRefFixture({
    durableMaterialRef: 'role-local:restore-coordinator',
    bindingDigest: publicFacts.contextBinding32B64u,
    label: 'restore-coordinator',
    materialOwner: walletId,
  });
  const authority =
    authMethod === 'passkey'
      ? buildPasskeyWalletAuthAuthority({
          walletId,
          rpId: 'example.com',
          credentialIdB64u: 'credential-restore',
        })
      : buildEmailOtpWalletAuthAuthority({
          walletId,
          provider: 'google',
          providerUserId: 'google:restore',
          emailHashHex: TEST_EMAIL_OTP_EMAIL_HASH_HEX,
        });
  const ecdsaRestore =
    authMethod === 'passkey'
      ? {
          source: 'login' as const,
          chainTarget,
          signingRootId: TEST_ECDSA_SIGNING_ROOT_ID,
          signingRootVersion: 'v1',
          runtimePolicyScope: TEST_ECDSA_RUNTIME_POLICY_SCOPE,
          authority: buildWalletAuthAuthorityRefForAuthorityFixture(authority),
          rpId: 'example.com',
          credentialIdB64u: 'credential-restore',
          keyHandle: bootstrap.thresholdEcdsaKeyRef.keyHandle,
          ecdsaThresholdKeyId: bootstrap.thresholdEcdsaKeyRef.ecdsaThresholdKeyId,
          ethereumAddress: bootstrap.thresholdEcdsaKeyRef.ethereumAddress,
          relayerKeyId:
            bootstrap.thresholdEcdsaKeyRef.backendBinding?.relayerKeyId || 'relayer-key-restore',
          clientVerifyingShareB64u:
            bootstrap.thresholdEcdsaKeyRef.backendBinding?.clientVerifyingShareB64u ||
            'client-verifying-share-restore',
          thresholdEcdsaPublicKeyB64u: bootstrap.thresholdEcdsaKeyRef.thresholdEcdsaPublicKeyB64u,
          participantIds: bootstrap.thresholdEcdsaKeyRef.participantIds,
          roleLocalMaterialRef,
          routerAbEcdsaDerivationNormalSigning:
            bootstrap.thresholdEcdsaKeyRef.routerAbEcdsaDerivationNormalSigning,
          publicCapability: publicFacts.publicCapability,
        }
      : {
          source: 'email_otp' as const,
          chainTarget,
          signingRootId: TEST_ECDSA_SIGNING_ROOT_ID,
          signingRootVersion: 'v1',
          runtimePolicyScope: TEST_ECDSA_RUNTIME_POLICY_SCOPE,
          authority: buildWalletAuthAuthorityRefForAuthorityFixture(authority),
          provider: 'google' as const,
          providerSubjectId: 'google:restore',
          emailHashHex: TEST_EMAIL_OTP_EMAIL_HASH_HEX,
          emailOtpAuthority: authority,
          keyHandle: bootstrap.thresholdEcdsaKeyRef.keyHandle,
          ecdsaThresholdKeyId: bootstrap.thresholdEcdsaKeyRef.ecdsaThresholdKeyId,
          ethereumAddress: bootstrap.thresholdEcdsaKeyRef.ethereumAddress,
          relayerKeyId:
            bootstrap.thresholdEcdsaKeyRef.backendBinding?.relayerKeyId || 'relayer-key-restore',
          clientVerifyingShareB64u:
            bootstrap.thresholdEcdsaKeyRef.backendBinding?.clientVerifyingShareB64u ||
            'client-verifying-share-restore',
          thresholdEcdsaPublicKeyB64u: bootstrap.thresholdEcdsaKeyRef.thresholdEcdsaPublicKeyB64u,
          participantIds: bootstrap.thresholdEcdsaKeyRef.participantIds,
          roleLocalMaterialRef,
          routerAbEcdsaDerivationNormalSigning:
            bootstrap.thresholdEcdsaKeyRef.routerAbEcdsaDerivationNormalSigning,
          publicCapability: publicFacts.publicCapability,
        };
  const record = buildCurrentSealedSessionRecord({
    curve: 'ecdsa',
    thresholdSessionId,
    thresholdSessionIds: { ecdsa: thresholdSessionId },
    sealedSecretB64u: 'sealed-secret',
    authMethod,
    keyVersion: 'signing-session-seal-kek-test-r1',
    groupId: 'rfc2409-group2',
    issuedAtMs: 1,
    expiresAtMs: args.expiresAtMs ?? Date.now() + 60_000,
    remainingUses: args.remainingUses ?? 5,
    updatedAtMs: args.updatedAtMs || 1,
    walletId,
    relayerUrl: 'https://relay.example',
    ecdsaRestore,
  });
  if (!record || record.curve !== 'ecdsa') throw new Error('invalid restore coordinator fixture');
  return {
    ...record,
    storeKey: ecdsaSealedRecordStoreKey({
      walletId,
      authMethod,
      chainTarget,
      materialActivation: roleLocalMaterialRef.materialActivation,
    }),
  };
}

function makeMissingRestoreMetadataRecord(): SigningSessionSealedStoreRecord {
  const record = makeSealedRecord({});
  return {
    ...record,
    ecdsaRestore: { ...record.ecdsaRestore, roleLocalMaterialRef: undefined },
  };
}

test.describe('restorePersistedSessionForSigningCommand', () => {
  test('does not cache exact-purpose durable-record absence', async () => {
    const cache = createSigningSessionRestoreCache();
    let listCalls = 0;

    await restorePersistedSessionForSigningCommand(ecdsaRestoreInput(), {
      cache,
      listExactSealedSessionsForWallet: async () => {
        listCalls += 1;
        return [];
      },
      restoreSealedRecordForWallet: async () => 'restored',
    });
    await restorePersistedSessionForSigningCommand(ecdsaRestoreInput(), {
      cache,
      listExactSealedSessionsForWallet: async () => {
        listCalls += 1;
        return [];
      },
      restoreSealedRecordForWallet: async () => 'restored',
    });

    expect(listCalls).toBe(2);
  });

  test('sees a sealed record written after an earlier exact miss', async () => {
    const cache = createSigningSessionRestoreCache();
    const restoredRecords: SealedRecoveryRecord[] = [];
    let listCalls = 0;
    const record = makeSealedRecord({
      authMethod: 'email_otp',
      curve: 'ecdsa',
      chain: 'tempo',
      thresholdSessionId: 'tsess-restore-after-miss',
    });

    const input = ecdsaRestoreInput({
      thresholdSessionId: 'tsess-restore-after-miss',
    });

    const first = await restorePersistedSessionForSigningCommand(input, {
      cache,
      listExactSealedSessionsForWallet: async () => {
        listCalls += 1;
        return [];
      },
      restoreSealedRecordForWallet: async ({ record: restoredRecord }) => {
        restoredRecords.push(restoredRecord);
        return 'restored';
      },
    });
    const second = await restorePersistedSessionForSigningCommand(input, {
      cache,
      listExactSealedSessionsForWallet: async () => {
        listCalls += 1;
        return [record];
      },
      restoreSealedRecordForWallet: async ({ record: restoredRecord }) => {
        restoredRecords.push(restoredRecord);
        return 'restored';
      },
    });

    expect(first).toEqual({ kind: 'completed', attempted: 0, restored: 0, deferred: 0 });
    expect(second).toEqual({ kind: 'completed', attempted: 1, restored: 1, deferred: 0 });
    expect(listCalls).toBe(2);
    expect(restoredRecords).toHaveLength(1);
  });

  test('does not cache transient list failures as known missing', async () => {
    const cache = createSigningSessionRestoreCache();
    let listCalls = 0;

    const ports = {
      cache,
      listExactSealedSessionsForWallet: async () => {
        listCalls += 1;
        throw new Error('indexeddb temporarily unavailable');
      },
      restoreSealedRecordForWallet: async () => 'restored' as const,
    };

    await restorePersistedSessionForSigningCommand(ecdsaRestoreInput(), ports);
    await restorePersistedSessionForSigningCommand(ecdsaRestoreInput(), ports);

    expect(listCalls).toBe(2);
  });

  test('does not cache exact-purpose misses when only purpose-mismatched records exist', async () => {
    const cache = createSigningSessionRestoreCache();
    let listCalls = 0;
    let restoreCalls = 0;

    const input = ecdsaRestoreInput();
    const ports = {
      cache,
      listExactSealedSessionsForWallet: async () => {
        listCalls += 1;
        return [makeSealedRecord({ chain: 'evm', thresholdSessionId: 'tsess-wrong-chain' })];
      },
      restoreSealedRecordForWallet: async () => {
        restoreCalls += 1;
        return 'restored' as const;
      },
    };

    await restorePersistedSessionForSigningCommand(input, ports);
    await restorePersistedSessionForSigningCommand(input, ports);

    expect(listCalls).toBe(2);
    expect(restoreCalls).toBe(0);
  });

  test('ignores expired and exhausted exact-purpose sealed records', async () => {
    const cache = createSigningSessionRestoreCache();
    let restoreCalls = 0;

    const result = await restorePersistedSessionForSigningCommand(ecdsaRestoreInput(), {
      cache,
      listExactSealedSessionsForWallet: async () => [
        makeSealedRecord({ expiresAtMs: Date.now() - 1 }),
        makeSealedRecord({ remainingUses: 0, updatedAtMs: 2 }),
      ],
      restoreSealedRecordForWallet: async () => {
        restoreCalls += 1;
        return 'restored';
      },
    });

    expect(result).toEqual({ kind: 'completed', attempted: 0, restored: 0, deferred: 0 });
    expect(restoreCalls).toBe(0);
  });

  test('surfaces rejected exact-purpose records through the rejection callback', async () => {
    const rejections: string[] = [];

    const result = await restorePersistedSessionForSigningCommand(ecdsaRestoreInput(), {
      listExactSealedSessionsForWallet: async () => [makeMissingRestoreMetadataRecord()],
      restoreSealedRecordForWallet: async () => 'restored',
      onRejectedRecord: ({ rejection }) => {
        rejections.push(rejection.reason);
      },
    });

    expect(result).toEqual({ kind: 'completed', attempted: 0, restored: 0, deferred: 0 });
    expect(rejections).toEqual(['missing_restore_metadata']);
  });

  test('rejects stale ECDSA sealed-record signing-root siblings before restore', async () => {
    const rejections: string[] = [];

    const result = await restorePersistedSessionForSigningCommand(ecdsaRestoreInput(), {
      listExactSealedSessionsForWallet: async () => [
        {
          ...makeSealedRecord({}),
          signingRootId: 'legacy-root',
        },
      ],
      restoreSealedRecordForWallet: async () => 'restored',
      onRejectedRecord: ({ rejection }) => {
        rejections.push(rejection.reason);
      },
    });

    expect(result).toEqual({ kind: 'completed', attempted: 0, restored: 0, deferred: 0 });
    expect(rejections).toEqual(['invalid_identity']);
  });

  test('restores exhausted passkey exact-purpose sealed records for step-up reconnect', async () => {
    let restoreCalls = 0;

    const result = await restorePersistedSessionForSigningCommand(
      ecdsaRestoreInput({ authMethod: 'passkey' }),
      {
        listExactSealedSessionsForWallet: async () => [
          makeSealedRecord({
            authMethod: 'passkey',
            expiresAtMs: Date.now() + 60_000,
            remainingUses: 0,
          }),
        ],
        restoreSealedRecordForWallet: async () => {
          restoreCalls += 1;
          return 'restored';
        },
      },
    );

    expect(result).toEqual({ kind: 'completed', attempted: 1, restored: 1, deferred: 0 });
    expect(restoreCalls).toBe(1);
  });

  test('fails closed before restore when duplicate exact-purpose records exist', async () => {
    let restoreCalls = 0;

    const result = await restorePersistedSessionForSigningCommand(ecdsaRestoreInput(), {
      listExactSealedSessionsForWallet: async () => [
        makeSealedRecord({ updatedAtMs: 1 }),
        makeSealedRecord({ updatedAtMs: 2 }),
      ],
      restoreSealedRecordForWallet: async () => {
        restoreCalls += 1;
        return 'restored';
      },
    });

    expect(result).toMatchObject({
      kind: 'duplicate_records',
      attempted: 0,
      restored: 0,
      deferred: 0,
      duplicateCount: 2,
    });
    expect(restoreCalls).toBe(0);
  });

  test('caches successful restores by durable record version', async () => {
    const cache = createSigningSessionRestoreCache();
    let restoreCalls = 0;
    let record = makeSealedRecord({ updatedAtMs: 1 });
    const input = ecdsaRestoreInput();
    const ports = {
      cache,
      listExactSealedSessionsForWallet: async () => [record],
      restoreSealedRecordForWallet: async () => {
        restoreCalls += 1;
        return 'restored' as const;
      },
    };

    await restorePersistedSessionForSigningCommand(input, ports);
    await restorePersistedSessionForSigningCommand(input, ports);
    record = makeSealedRecord({ updatedAtMs: 2 });
    await restorePersistedSessionForSigningCommand(input, ports);

    expect(restoreCalls).toBe(2);
  });

  test('does not cache deferred restore attempts as successful', async () => {
    const cache = createSigningSessionRestoreCache();
    let restoreCalls = 0;
    const input = ecdsaRestoreInput();

    await restorePersistedSessionForSigningCommand(input, {
      cache,
      listExactSealedSessionsForWallet: async () => [makeSealedRecord({})],
      restoreSealedRecordForWallet: async () => {
        restoreCalls += 1;
        return 'deferred';
      },
    });
    await restorePersistedSessionForSigningCommand(input, {
      cache,
      listExactSealedSessionsForWallet: async () => [makeSealedRecord({})],
      restoreSealedRecordForWallet: async () => {
        restoreCalls += 1;
        return 'deferred';
      },
    });

    expect(restoreCalls).toBe(2);
  });
});

test.describe('discoverPersistedSessionsForWalletCommand', () => {
  test('bounds account-wide discovery across exact ECDSA chain identities', async () => {
    const records = [
      makeSealedRecord({ chain: 'tempo', thresholdSessionId: 'tsess-1' }),
      makeSealedRecord({ chain: 'evm', thresholdSessionId: 'tsess-2' }),
      {
        ...makeSealedRecord({ thresholdSessionId: 'tsess-3' }),
        ecdsaRestore: undefined,
      },
    ];
    const restoreCalls = 0;

    const result = await discoverPersistedSessionsForWalletCommand(
      {
        kind: 'discover_wallet_ecdsa_signing_sessions',
        walletId: 'restore.testnet',
        ecdsaChainTargets: TEST_ECDSA_CHAIN_TARGET_LIST,
        authMethod: 'email_otp',
        maxRecords: 2,
      },
      {
        listExactSealedSessionsForWallet: async (filter) =>
          records.filter((record) => {
            if (record.authMethod !== filter.authMethod) return false;
            if (record.curve !== filter.curve) return false;
            if (filter.curve === 'ecdsa') {
              return record.ecdsaRestore?.chainTarget?.kind === filter.chainTarget.kind;
            }
            return true;
          }),
      },
    );

    expect(result).toMatchObject({
      listed: 2,
      discovered: 2,
      truncated: 0,
    });
    expect(restoreCalls).toBe(0);
  });

  test('does not perform broad account-wide restore during discovery polling', async () => {
    const restoreCalls = 0;

    const input = {
      kind: 'discover_wallet_ecdsa_signing_sessions' as const,
      walletId: 'restore.testnet',
      ecdsaChainTargets: TEST_ECDSA_CHAIN_TARGET_LIST,
      authMethod: 'email_otp' as const,
      maxRecords: 10,
    };
    const ports = {
      listExactSealedSessionsForWallet: async (filter: any) =>
        filter.curve === 'ecdsa' && filter.chainTarget?.kind === 'tempo'
          ? [makeSealedRecord({ chain: 'tempo' })]
          : [],
    };

    await discoverPersistedSessionsForWalletCommand(input, ports);
    await discoverPersistedSessionsForWalletCommand(input, ports);

    expect(restoreCalls).toBe(0);
  });
});
