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
  exactEd25519SigningLaneIdentity,
  nearEd25519SignerBindingFromBoundaryFields,
} from '../../packages/sdk-web/src/core/signingEngine/session/identity/exactSigningLaneIdentity';
import {
  parseEd25519WorkerMaterialBindingDigest,
  parseEd25519WorkerMaterialKeyId,
} from '../../packages/sdk-web/src/core/signingEngine/session/keyMaterialBrands';
import { resolveEd25519RestoreMaterialIdentity } from '../../packages/sdk-web/src/core/signingEngine/session/ed25519MaterialAuthority';
import {
  nearEd25519SigningKeyIdFromString,
  walletIdFromString,
} from '../../packages/shared-ts/src/utils/registrationIntent';
import { toRpId } from '../../packages/sdk-web/src/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';

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
const TEST_ED25519_MATERIAL_BINDING_DIGEST = 'ed25519-worker-material-binding-digest-restore';
const TEST_ED25519_MATERIAL_KEY_ID = 'ed25519-worker-material-key-restore';
const TEST_EMAIL_OTP_EMAIL_HASH_HEX = 'email-hash-restore';
const TEST_ED25519_SEALED_MATERIAL = {
  clientVerifyingShareB64u: 'ed25519-client-verifying-share-restore',
  ed25519WorkerMaterialBindingDigest: TEST_ED25519_MATERIAL_BINDING_DIGEST,
  sealedWorkerMaterialRef: 'ed25519-sealed-worker-material-ref-restore',
  materialFormatVersion: 'ed25519_worker_material_v1',
  materialKeyId: TEST_ED25519_MATERIAL_KEY_ID,
  materialCreatedAtMs: 1_700_000_000_000,
} as const;
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

function ethereumAddress20B64u(address: string): string {
  return Buffer.from(address.replace(/^0x/i, ''), 'hex').toString('base64url');
}

function fixedBytesB64u(length: number, byte: number): string {
  return Buffer.from(new Uint8Array(length).fill(byte)).toString('base64url');
}

function restoreEcdsaNormalSigningState(args: { thresholdSessionId: string }) {
  return {
    kind: 'router_ab_ecdsa_hss_normal_signing_v1',
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
        client_public_key33_b64u: fixedBytesB64u(33, 2),
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
  const signingGrantId = args.signingGrantId || 'wsess-restore';
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
    signingGrantId,
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
        }),
        auth:
          authMethod === 'passkey'
            ? {
                kind: 'passkey',
                rpId: toRpId('example.com'),
                credentialIdB64u: 'credential-restore',
              }
            : { kind: 'email_otp', providerSubjectId: 'google:restore' },
        signingGrantId,
        thresholdSessionId,
      }),
      ecdsaThresholdKeyId: key.ecdsaThresholdKeyId,
    },
  };
}

function ed25519RestoreInput(
  args: Partial<Extract<RestorePersistedSessionForSigningInput, { curve: 'ed25519' }>> = {},
): Extract<RestorePersistedSessionForSigningInput, { curve: 'ed25519' }> {
  const authMethod = args.authMethod || 'email_otp';
  const signingGrantId = args.signingGrantId || 'wsess-restore';
  const thresholdSessionId = args.thresholdSessionId || 'tsess-restore';
  const wallet = walletIdFromString(args.walletId || 'restore.testnet');
  const walletId = String(wallet);
  const nearEd25519SigningKeyId = nearEd25519SigningKeyIdFromString('restore.testnet');
  return {
    walletId,
    authMethod,
    curve: 'ed25519',
    chain: 'near',
    signingGrantId,
    thresholdSessionId,
    reason: args.reason || 'transaction',
    materialRestoreIdentity: {
      kind: 'ed25519_worker_material_restore',
      lane: exactEd25519SigningLaneIdentity({
        signer: nearEd25519SignerBindingFromBoundaryFields({
          walletId: wallet,
          nearAccountId: 'restore.testnet',
          nearEd25519SigningKeyId,
          signerSlot: 1,
        }),
        auth:
          authMethod === 'passkey'
            ? {
                kind: 'passkey',
                rpId: toRpId('example.com'),
                credentialIdB64u: 'credential-restore',
              }
            : { kind: 'email_otp', providerSubjectId: 'google:restore' },
        signingGrantId,
        thresholdSessionId,
      }),
      material: requireTestEd25519RestoreMaterial(thresholdSessionId),
    },
  };
}

// Restore material identities are only constructible via the boundary resolver
// (session/ed25519MaterialAuthority.ts). With no live record in the store the
// resolution falls back to the supplied hint, mirroring production behavior.
function requireTestEd25519RestoreMaterial(thresholdSessionId: string) {
  const resolution = resolveEd25519RestoreMaterialIdentity({
    thresholdSessionId,
    hint: {
      bindingDigest: parseEd25519WorkerMaterialBindingDigest(
        TEST_ED25519_MATERIAL_BINDING_DIGEST,
      ),
      materialKeyId: parseEd25519WorkerMaterialKeyId(TEST_ED25519_MATERIAL_KEY_ID),
    },
  });
  if (resolution.kind !== 'resolved') {
    throw new Error('expected test Ed25519 restore material to resolve');
  }
  return resolution.identity;
}

function makeSealedRecord(args: {
  authMethod?: 'email_otp' | 'passkey';
  chain?: 'tempo' | 'evm';
  curve?: 'ed25519' | 'ecdsa';
  thresholdSessionId?: string;
  thresholdSessionIds?: {
    ed25519?: string;
    ecdsa?: string;
  };
  signingGrantId?: string;
  expiresAtMs?: number;
  remainingUses?: number;
  updatedAtMs?: number;
}): SigningSessionSealedStoreRecord {
  const authMethod = args.authMethod || 'email_otp';
  const curve = args.curve || 'ecdsa';
  const thresholdSessionId = args.thresholdSessionId || 'tsess-restore';
  const chain = args.chain || 'tempo';
  const chainTarget = TEST_ECDSA_CHAIN_TARGETS[chain];
  const ecdsaRestore =
    authMethod === 'passkey'
      ? {
          source: 'login' as const,
          chainTarget,
          evmFamilySigningKeySlotId: TEST_EVM_FAMILY_SIGNING_KEY_SLOT_ID,
          runtimePolicyScope: TEST_ECDSA_RUNTIME_POLICY_SCOPE,
          rpId: 'example.com',
          credentialIdB64u: 'credential-restore',
          sessionKind: 'jwt' as const,
          walletSessionJwt: 'jwt-restore',
          keyHandle: 'key-handle-restore',
          ecdsaThresholdKeyId: 'ecdsa-key-restore',
          ethereumAddress: `0x${'33'.repeat(20)}`,
          relayerKeyId: 'relayer-key-restore',
          clientVerifyingShareB64u: 'client-verifying-share-restore',
          thresholdEcdsaPublicKeyB64u: 'threshold-public-key-restore',
          participantIds: [1, 2],
          routerAbEcdsaHssNormalSigning: restoreEcdsaNormalSigningState({
            thresholdSessionId,
          }),
        }
      : {
          source: 'email_otp' as const,
          chainTarget,
          evmFamilySigningKeySlotId: TEST_EVM_FAMILY_SIGNING_KEY_SLOT_ID,
          runtimePolicyScope: TEST_ECDSA_RUNTIME_POLICY_SCOPE,
          providerSubjectId: 'google:restore',
          emailHashHex: TEST_EMAIL_OTP_EMAIL_HASH_HEX,
          sessionKind: 'jwt' as const,
          walletSessionJwt: 'jwt-restore',
          keyHandle: 'key-handle-restore',
          ecdsaThresholdKeyId: 'ecdsa-key-restore',
          ethereumAddress: `0x${'33'.repeat(20)}`,
          relayerKeyId: 'relayer-key-restore',
          clientVerifyingShareB64u: 'client-verifying-share-restore',
          thresholdEcdsaPublicKeyB64u: 'threshold-public-key-restore',
          participantIds: [1, 2],
          routerAbEcdsaHssNormalSigning: restoreEcdsaNormalSigningState({
            thresholdSessionId,
          }),
        };
  return {
    v: 1,
    alg: 'shamir3pass-v1',
    storageScope: 'iframe_origin_indexeddb',
    authMethod,
    secretKind: 'signing_session_secret32',
    storeKey: `${authMethod}:${curve}:${args.chain || 'near'}:${thresholdSessionId}`,
    signingGrantId: args.signingGrantId || 'wsess-restore',
    thresholdSessionIds:
      args.thresholdSessionIds ||
      (curve === 'ecdsa' ? { ecdsa: thresholdSessionId } : { ed25519: thresholdSessionId }),
    sealedSecretB64u: 'sealed-secret',
    curve,
    walletId: 'restore.testnet',
    relayerUrl: 'https://relay.example',
    ...(curve === 'ecdsa'
      ? {
          keyVersion: 'signing-session-seal-kek-test-r1',
          shamirPrimeB64u: 'prime-b64u',
          ecdsaRestore,
        }
      : {
          ed25519Restore: {
            nearAccountId: 'restore.testnet',
            nearEd25519SigningKeyId: 'restore.testnet',
            rpId: 'example.com',
            ...(authMethod === 'passkey'
              ? { credentialIdB64u: 'credential-restore' }
              : {
                  providerSubjectId: 'google:restore',
                  emailHashHex: TEST_EMAIL_OTP_EMAIL_HASH_HEX,
                }),
            relayerKeyId: 'relayer-key-restore',
            participantIds: [1, 2],
            ...TEST_ED25519_SEALED_MATERIAL,
            sessionKind: 'jwt' as const,
            walletSessionJwt: 'jwt-restore',
            signerSlot: 1,
          },
        }),
    issuedAtMs: 1,
    expiresAtMs: args.expiresAtMs ?? Date.now() + 60_000,
    remainingUses: args.remainingUses ?? 5,
    updatedAtMs: args.updatedAtMs || 1,
  };
}

function makeEd25519RecordWithEcdsaCompanion(args: {
  thresholdSessionId: string;
  signingGrantId: string;
  ecdsaThresholdSessionId: string;
}): SigningSessionSealedStoreRecord {
  return {
    ...makeSealedRecord({
      curve: 'ed25519',
      thresholdSessionId: args.thresholdSessionId,
      signingGrantId: args.signingGrantId,
    }),
    thresholdSessionIds: {
      ecdsa: args.ecdsaThresholdSessionId,
      ed25519: args.thresholdSessionId,
    },
    ecdsaRestore: {
      chainTarget: TEST_ECDSA_CHAIN_TARGETS.tempo,
      source: 'email_otp',
      evmFamilySigningKeySlotId: TEST_EVM_FAMILY_SIGNING_KEY_SLOT_ID,
      runtimePolicyScope: TEST_ECDSA_RUNTIME_POLICY_SCOPE,
      providerSubjectId: 'google:restore',
      emailHashHex: TEST_EMAIL_OTP_EMAIL_HASH_HEX,
      sessionKind: 'jwt',
      walletSessionJwt: 'jwt-restore',
      keyHandle: 'key-handle-restore',
      ecdsaThresholdKeyId: 'ecdsa-key-restore',
      ethereumAddress: `0x${'33'.repeat(20)}`,
      relayerKeyId: 'relayer-key-restore',
      clientVerifyingShareB64u: 'client-verifying-share-restore',
      thresholdEcdsaPublicKeyB64u: 'threshold-public-key-restore',
      participantIds: [1, 2],
      routerAbEcdsaHssNormalSigning: restoreEcdsaNormalSigningState({
        thresholdSessionId: args.ecdsaThresholdSessionId,
      }),
    },
  };
}

function makeEcdsaRecordWithEd25519Companion(args: {
  thresholdSessionId: string;
  signingGrantId: string;
  ed25519ThresholdSessionId: string;
}): SigningSessionSealedStoreRecord {
  return {
    ...makeSealedRecord({
      authMethod: 'email_otp',
      curve: 'ecdsa',
      thresholdSessionId: args.thresholdSessionId,
      signingGrantId: args.signingGrantId,
      thresholdSessionIds: {
        ecdsa: args.thresholdSessionId,
        ed25519: args.ed25519ThresholdSessionId,
      },
    }),
    ed25519Restore: {
      nearAccountId: 'restore.testnet',
      nearEd25519SigningKeyId: 'restore.testnet',
      rpId: 'example.com',
      providerSubjectId: 'google:restore',
      emailHashHex: TEST_EMAIL_OTP_EMAIL_HASH_HEX,
      relayerKeyId: 'relayer-key-restore',
      participantIds: [1, 2],
      ...TEST_ED25519_SEALED_MATERIAL,
      sessionKind: 'jwt',
      walletSessionJwt: 'jwt-ed25519-companion',
      signerSlot: 1,
      runtimePolicyScope: TEST_ECDSA_RUNTIME_POLICY_SCOPE,
    },
  };
}

test.describe('restorePersistedSessionForSigningCommand', () => {
  test('does not cache exact-purpose durable-record absence', async () => {
    const cache = createSigningSessionRestoreCache();
    let listCalls = 0;

    await restorePersistedSessionForSigningCommand(
      ecdsaRestoreInput(),
      {
        cache,
        listExactSealedSessionsForWallet: async () => {
          listCalls += 1;
          return [];
        },
        restoreSealedRecordForWallet: async () => 'restored',
      },
    );
    await restorePersistedSessionForSigningCommand(
      ecdsaRestoreInput(),
      {
        cache,
        listExactSealedSessionsForWallet: async () => {
          listCalls += 1;
          return [];
        },
        restoreSealedRecordForWallet: async () => 'restored',
      },
    );

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
      signingGrantId: 'wsess-restore-after-miss',
    });

    const input = ecdsaRestoreInput({
      signingGrantId: 'wsess-restore-after-miss',
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

    await restorePersistedSessionForSigningCommand(
      ecdsaRestoreInput(),
      ports,
    );
    await restorePersistedSessionForSigningCommand(
      ecdsaRestoreInput(),
      ports,
    );

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

    const result = await restorePersistedSessionForSigningCommand(
      ecdsaRestoreInput(),
      {
        cache,
        listExactSealedSessionsForWallet: async () => [
          makeSealedRecord({ expiresAtMs: Date.now() - 1 }),
          makeSealedRecord({ remainingUses: 0, updatedAtMs: 2 }),
        ],
        restoreSealedRecordForWallet: async () => {
          restoreCalls += 1;
          return 'restored';
        },
      },
    );

    expect(result).toEqual({ kind: 'completed', attempted: 0, restored: 0, deferred: 0 });
    expect(restoreCalls).toBe(0);
  });

  test('passes expired Ed25519 exact-purpose sealed records to the curve adapter', async () => {
    let restoreCalls = 0;
    let restoredRecord: SealedRecoveryRecord | null = null;

    const result = await restorePersistedSessionForSigningCommand(
      ed25519RestoreInput(),
      {
        listExactSealedSessionsForWallet: async () => [
          makeSealedRecord({
            curve: 'ed25519',
            expiresAtMs: Date.now() - 1,
            remainingUses: 3,
          }),
        ],
        restoreSealedRecordForWallet: async ({ record }) => {
          restoreCalls += 1;
          restoredRecord = record;
          return 'deferred';
        },
      },
    );

    expect(result).toEqual({ kind: 'completed', attempted: 1, restored: 0, deferred: 1 });
    expect(restoreCalls).toBe(1);
    expect(restoredRecord).toMatchObject({
      curve: 'ed25519',
      expiresAtMs: expect.any(Number),
      remainingUses: 3,
    });
  });

  test('surfaces rejected exact-purpose records through the rejection callback', async () => {
    const rejections: string[] = [];

    const result = await restorePersistedSessionForSigningCommand(
      ed25519RestoreInput(),
      {
        listExactSealedSessionsForWallet: async () => [
          {
            ...makeSealedRecord({ curve: 'ed25519' }),
	            ed25519Restore: {
	              nearAccountId: 'restore.testnet',
	              nearEd25519SigningKeyId: 'restore.testnet',
	              rpId: 'example.com',
              relayerKeyId: 'relayer-key-restore',
              participantIds: [1, 2],
              sessionKind: 'jwt',
              walletSessionJwt: 'jwt-restore',
            },
          },
        ],
        restoreSealedRecordForWallet: async () => 'restored',
        onRejectedRecord: ({ rejection }) => {
          rejections.push(rejection.reason);
        },
      },
    );

    expect(result).toEqual({ kind: 'completed', attempted: 0, restored: 0, deferred: 0 });
    expect(rejections).toEqual(['missing_restore_metadata']);
  });

  test('rejects stale sealed-record identity aliases before restore', async () => {
    const rejections: string[] = [];
    const ed25519Record = makeSealedRecord({ curve: 'ed25519' });

    const result = await restorePersistedSessionForSigningCommand(
      ed25519RestoreInput(),
      {
        listExactSealedSessionsForWallet: async () => [
          {
            ...ed25519Record,
            ed25519Restore: {
              ...ed25519Record.ed25519Restore!,
              authSubjectId: 'legacy-auth-subject',
            },
          },
        ],
        restoreSealedRecordForWallet: async () => 'restored',
        onRejectedRecord: ({ rejection }) => {
          rejections.push(rejection.reason);
        },
      },
    );

    expect(result).toEqual({ kind: 'completed', attempted: 0, restored: 0, deferred: 0 });
    expect(rejections).toEqual(['invalid_identity']);
  });

  test('rejects stale ECDSA sealed-record signing-root siblings before restore', async () => {
    const rejections: string[] = [];

    const result = await restorePersistedSessionForSigningCommand(
      ecdsaRestoreInput(),
      {
        listExactSealedSessionsForWallet: async () => [
          {
            ...makeSealedRecord({ curve: 'ecdsa' }),
            signingRootId: 'legacy-root',
          },
        ],
        restoreSealedRecordForWallet: async () => 'restored',
        onRejectedRecord: ({ rejection }) => {
          rejections.push(rejection.reason);
        },
      },
    );

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

    const result = await restorePersistedSessionForSigningCommand(
      ecdsaRestoreInput(),
      {
        listExactSealedSessionsForWallet: async () => [
          makeSealedRecord({ updatedAtMs: 1 }),
          makeSealedRecord({ updatedAtMs: 2 }),
        ],
        restoreSealedRecordForWallet: async () => {
          restoreCalls += 1;
          return 'restored';
        },
      },
    );

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

  test('restores Ed25519 intent from an ECDSA-primary companion sealed record', async () => {
    let restoreCalls = 0;
    let restoredRecord: SealedRecoveryRecord | null = null;
    const companionRecord = makeEd25519RecordWithEcdsaCompanion({
      thresholdSessionId: 'tsess-ed25519-companion',
      signingGrantId: 'wsess-companion',
      ecdsaThresholdSessionId: 'tsess-ecdsa-companion',
    });

    const result = await restorePersistedSessionForSigningCommand(
      ed25519RestoreInput({
        thresholdSessionId: 'tsess-ed25519-companion',
        signingGrantId: 'wsess-companion',
      }),
      {
        listExactSealedSessionsForWallet: async ({ curve }) =>
          curve === 'ed25519' ? [companionRecord] : [],
        restoreSealedRecordForWallet: async ({ record }) => {
          restoreCalls += 1;
          restoredRecord = record;
          return 'restored';
        },
      },
    );

    expect(result).toMatchObject({ attempted: 1, restored: 1, deferred: 0 });
    expect(restoreCalls).toBe(1);
    expect(restoredRecord).toMatchObject({
      authMethod: 'email_otp',
      curve: 'ed25519',
      thresholdSessionId: 'tsess-ed25519-companion',
      companionEcdsaRecovery: {
        thresholdSessionId: 'tsess-ecdsa-companion',
      },
    });
  });

  test('passes Ed25519 purpose through to the restore port for an ECDSA-primary companion record', async () => {
    const companionRecord = makeEd25519RecordWithEcdsaCompanion({
      thresholdSessionId: 'tsess-ed25519-purpose',
      signingGrantId: 'wsess-companion-purpose',
      ecdsaThresholdSessionId: 'tsess-ecdsa-primary',
    });
    const restoredPurposes: unknown[] = [];

    const result = await restorePersistedSessionForSigningCommand(
      ed25519RestoreInput({
        signingGrantId: 'wsess-companion-purpose',
        thresholdSessionId: 'tsess-ed25519-purpose',
      }),
      {
        listExactSealedSessionsForWallet: async (filter) =>
          filter.curve === 'ed25519' ? [companionRecord] : [],
        restoreSealedRecordForWallet: async ({ purpose }) => {
          restoredPurposes.push(purpose);
          return 'restored';
        },
      },
    );

    expect(result).toMatchObject({ attempted: 1, restored: 1, deferred: 0 });
    expect(restoredPurposes).toEqual([
      {
        walletId: 'restore.testnet',
        authMethod: 'email_otp',
        curve: 'ed25519',
        chain: 'near',
        signingGrantId: 'wsess-companion-purpose',
        thresholdSessionId: 'tsess-ed25519-purpose',
        reason: 'transaction',
      },
    ]);
  });

  test('matches Ed25519 signing purpose from an Email OTP ECDSA sealed record with Ed25519 companion metadata', async () => {
    let restoreCalls = 0;
    let restoredPurpose: unknown = null;
    let restoredRecord: SealedRecoveryRecord | null = null;
    const ecdsaPrimaryRecord = makeEcdsaRecordWithEd25519Companion({
      thresholdSessionId: 'tsess-ecdsa-primary',
      signingGrantId: 'wsess-ecdsa-primary',
      ed25519ThresholdSessionId: 'tsess-ed25519-companion',
    });

    const result = await restorePersistedSessionForSigningCommand(
      ed25519RestoreInput({
        signingGrantId: 'wsess-ecdsa-primary',
        thresholdSessionId: 'tsess-ed25519-companion',
      }),
      {
        listExactSealedSessionsForWallet: async ({ curve }) =>
          curve === 'ed25519' ? [ecdsaPrimaryRecord] : [],
        restoreSealedRecordForWallet: async ({ purpose, record }) => {
          restoreCalls += 1;
          restoredPurpose = purpose;
          restoredRecord = record;
          return 'restored';
        },
      },
    );

    expect(result).toMatchObject({ attempted: 1, restored: 1, deferred: 0 });
    expect(restoreCalls).toBe(1);
    expect(restoredPurpose).toEqual({
      walletId: 'restore.testnet',
      authMethod: 'email_otp',
      curve: 'ed25519',
      chain: 'near',
      signingGrantId: 'wsess-ecdsa-primary',
      thresholdSessionId: 'tsess-ed25519-companion',
      reason: 'transaction',
    });
    expect(restoredRecord).toMatchObject({
      authMethod: 'email_otp',
      curve: 'ed25519',
      signingGrantId: 'wsess-ecdsa-primary',
      thresholdSessionId: 'tsess-ed25519-companion',
      materialCache: {
        ed25519WorkerMaterialBindingDigest: TEST_ED25519_MATERIAL_BINDING_DIGEST,
        materialKeyId: TEST_ED25519_MATERIAL_KEY_ID,
      },
    });
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
    let restoreCalls = 0;

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
    let restoreCalls = 0;

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

  test('enumerates passkey Ed25519 and ECDSA lanes for account startup discovery', async () => {
    const records = [
      makeSealedRecord({
        authMethod: 'passkey',
        curve: 'ed25519',
        thresholdSessionId: 'tsess-passkey-ed25519',
      }),
      makeSealedRecord({
        authMethod: 'passkey',
        curve: 'ecdsa',
        chain: 'tempo',
        thresholdSessionId: 'tsess-passkey-tempo',
      }),
      makeSealedRecord({
        authMethod: 'email_otp',
        curve: 'ecdsa',
        chain: 'tempo',
        thresholdSessionId: 'tsess-email-tempo',
      }),
    ];
    let restoreCalls = 0;

    const result = await discoverPersistedSessionsForWalletCommand(
      {
        kind: 'discover_wallet_all_signing_sessions',
        walletId: 'restore.testnet',
        ecdsaChainTargets: TEST_ECDSA_CHAIN_TARGET_LIST,
        authMethod: 'passkey',
        maxRecords: 10,
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

  test('discovers separate account work items for a multi-curve sealed record', async () => {
    const companionRecord = makeEd25519RecordWithEcdsaCompanion({
      thresholdSessionId: 'tsess-ed25519-account',
      signingGrantId: 'wsess-account-companion',
      ecdsaThresholdSessionId: 'tsess-ecdsa-account',
    });
    let restoreCalls = 0;

    const result = await discoverPersistedSessionsForWalletCommand(
      {
        kind: 'discover_wallet_all_signing_sessions',
        walletId: 'restore.testnet',
        ecdsaChainTargets: TEST_ECDSA_CHAIN_TARGET_LIST,
        authMethod: 'email_otp',
        maxRecords: 10,
      },
      {
        listExactSealedSessionsForWallet: async (filter) => {
          if (filter.curve === 'ed25519') return [companionRecord];
          if (filter.curve === 'ecdsa' && filter.chainTarget.kind === 'tempo') {
            return [companionRecord];
          }
          return [];
        },
      },
    );

    expect(result).toMatchObject({
      discovered: 2,
      truncated: 0,
    });
    expect(restoreCalls).toBe(0);
  });
});
