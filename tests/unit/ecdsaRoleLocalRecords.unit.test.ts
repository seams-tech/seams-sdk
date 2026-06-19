import { expect, test } from '@playwright/test';
import { base64UrlEncode } from '@shared/utils/base64';
import { createBrowserPlatformRuntime } from '@/core/platform';
import {
  clearAllThresholdEcdsaSessionRecords,
  getStoredThresholdEcdsaSessionRecordByThresholdSessionId,
  upsertRestoredThresholdEcdsaSessionRecord,
} from '@/core/signingEngine/session/persistence/records';
import {
  buildEcdsaRoleLocalEmailOtpAuthMethod,
  buildEcdsaRoleLocalPasskeyAuthMethod,
  buildEcdsaRoleLocalPublicFacts,
  buildEcdsaRoleLocalReadyRecord,
  classifyThresholdEcdsaSessionRecordRoleLocalState,
  ecdsaRoleLocalReadyRecordStorageKey,
  parseEcdsaRoleLocalReadyRecord,
  parseRawEcdsaRoleLocalRecord,
  parseThresholdEcdsaSessionRecordAsRoleLocalExportMaterial,
  parseThresholdEcdsaSessionRecordAsRoleLocalWorkerExportMaterial,
  parseThresholdEcdsaSessionRecordAsRoleLocalReadyRecord,
  serializeEcdsaRoleLocalReadyRecord,
} from '@/core/signingEngine/session/persistence/ecdsaRoleLocalRecords';
import {
  thresholdEcdsaChainTargetKey,
  thresholdEcdsaChainTargetFromChainFamily,
  toWalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { toRpId } from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import {
  toEcdsaHssSigningRootId,
  toEcdsaHssSigningRootVersion,
  toEcdsaHssThresholdKeyId,
  toEmailOtpAuthSubjectId,
} from '@/core/signingEngine/session/identity/emailOtpHssIdentity';
import type { EcdsaRoleLocalAuthMethod, LoadEcdsaRoleLocalReadyRecordInput } from '@/core/platform';

function bytesB64u(length: number, fill: number): string {
  return base64UrlEncode(new Uint8Array(length).fill(fill));
}

function compressedPublicKeyB64u(prefix: 2 | 3, fill: number): string {
  const bytes = new Uint8Array(33).fill(fill);
  bytes[0] = prefix;
  return base64UrlEncode(bytes);
}

const chainTarget = thresholdEcdsaChainTargetFromChainFamily({
  chain: 'tempo',
  chainId: 42431,
  networkSlug: 'tempo-testnet',
});

const walletId = toWalletId('wallet.testnet');
const rpId = toRpId('localhost');
const keyHandle = 'ecdsa-key-handle';
const passkeyCredentialIdB64u = 'passkey-credential-id';
const ecdsaThresholdKeyId = toEcdsaHssThresholdKeyId('ehss-key');
const signingRootId = toEcdsaHssSigningRootId('root');
const signingRootVersion = toEcdsaHssSigningRootVersion('v1');
const hssClientSharePublicKey33B64u = compressedPublicKeyB64u(2, 11);
const relayerPublicKey33B64u = compressedPublicKeyB64u(3, 12);
const groupPublicKey33B64u = compressedPublicKeyB64u(2, 13);
const share32B64u = bytesB64u(32, 5);
const ownerAddress = '0x0000000000000000000000000000000000000001';
const emailOtpAuthSubjectId = toEmailOtpAuthSubjectId('google:wallet.testnet');
const passkeyAuthMethod = buildEcdsaRoleLocalPasskeyAuthMethod({
  credentialIdB64u: passkeyCredentialIdB64u,
  rpId,
});
const emailOtpAuthMethod = buildEcdsaRoleLocalEmailOtpAuthMethod({
  authSubjectId: emailOtpAuthSubjectId,
});

function loadInput(
  authMethod: EcdsaRoleLocalAuthMethod = passkeyAuthMethod,
): LoadEcdsaRoleLocalReadyRecordInput {
  return {
    walletId,
    rpId,
    chainTarget,
    keyHandle,
    ecdsaThresholdKeyId,
    signingRootId,
    signingRootVersion,
    participantIds: [1, 2],
    authMethod,
  };
}

function legacyRoleLocalState(): Record<string, unknown> {
  return {
    kind: 'role_local_ready',
    artifactKind: 'ecdsa-hss-role-local-client-state',
    contextBinding32B64u: share32B64u,
    clientShare32B64u: bytesB64u(32, 6),
    clientPublicKey33B64u: hssClientSharePublicKey33B64u,
    clientShareRetryCounter: 0,
    relayerPublicKey33B64u,
    groupPublicKey33B64u,
    ethereumAddress: ownerAddress,
    clientCaitSithInput: {
      participantId: 1,
      mappedPrivateShare32B64u: bytesB64u(32, 7),
      verifyingShare33B64u: hssClientSharePublicKey33B64u,
    },
    createdAtMs: 1,
    updatedAtMs: 1,
  };
}

function publicFacts() {
  return buildEcdsaRoleLocalPublicFacts({
    walletId,
    rpId,
    chainTarget,
    keyHandle,
    ecdsaThresholdKeyId,
    signingRootId,
    signingRootVersion,
    clientParticipantId: 1,
    relayerParticipantId: 2,
    participantIds: [1, 2],
    contextBinding32B64u: share32B64u,
    hssClientSharePublicKey33B64u,
    relayerPublicKey33B64u,
    groupPublicKey33B64u,
    ethereumAddress: ownerAddress,
  });
}

function readyRecord(authMethod: EcdsaRoleLocalAuthMethod = passkeyAuthMethod) {
  return buildEcdsaRoleLocalReadyRecord({
    stateBlob: {
      kind: 'ecdsa_role_local_state_blob_v1',
      curve: 'secp256k1',
      encoding: 'base64url',
      producer: 'signer_core',
      stateBlobB64u: bytesB64u(48, 9),
    },
    publicFacts: publicFacts(),
    authMethod,
  });
}

function rawSessionRecord(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  const source = String(overrides.source || 'registration');
  return {
    walletId,
    authMetadata: { rpId },
    chainTarget,
    relayerUrl: 'https://relayer.example',
    keyHandle,
    ecdsaThresholdKeyId,
    signingRootId,
    signingRootVersion,
    relayerKeyId: 'relayer-key',
    clientVerifyingShareB64u: hssClientSharePublicKey33B64u,
    ecdsaRoleLocalReadyRecord: readyRecord(
      source === 'email_otp' ? emailOtpAuthMethod : passkeyAuthMethod,
    ),
    participantIds: [1, 2],
    thresholdSessionKind: 'jwt',
    thresholdSessionId: 'tehss-session',
    signingGrantId: 'wss-session',
    walletSessionJwt: 'jwt',
    expiresAtMs: Date.now() + 60_000,
    remainingUses: 3,
    thresholdEcdsaPublicKeyB64u: groupPublicKey33B64u,
    verifiedPublicFacts: {
      kind: 'verified_ecdsa_public_facts',
      keyHandle,
      publicKeyB64u: groupPublicKey33B64u,
      participantIds: [1, 2],
      thresholdOwnerAddress: ownerAddress,
    },
    ethereumAddress: ownerAddress,
    relayerVerifyingShareB64u: relayerPublicKey33B64u,
    updatedAtMs: 1,
    source,
    ...overrides,
  };
}

test.describe('ECDSA role-local record boundary parser', () => {
  test.beforeEach(() => {
    clearAllThresholdEcdsaSessionRecords({ recordsByLane: new Map() });
  });

  test.afterEach(() => {
    clearAllThresholdEcdsaSessionRecords({ recordsByLane: new Map() });
  });

  test('parses canonical threshold ECDSA session records into normalized ready records', () => {
    const ready = parseThresholdEcdsaSessionRecordAsRoleLocalReadyRecord(rawSessionRecord());
    expect(ready.kind).toBe('ecdsa_role_local_ready_passkey_v1');
    expect(ready.authMethod).toEqual({
      kind: 'passkey',
      credentialIdB64u: passkeyCredentialIdB64u,
      rpId,
    });
    expect(ready.publicFacts.walletId).toBe(walletId);
    expect(ready.publicFacts.rpId).toBe(rpId);
    expect(ready.publicFacts.keyHandle).toBe(keyHandle);
    expect(ready.publicFacts.hssClientSharePublicKey33B64u).toBe(hssClientSharePublicKey33B64u);
    expect(ready.stateBlob.kind).toBe('ecdsa_role_local_state_blob_v1');
  });

  test('restored passkey ECDSA records are written to the active session index', () => {
    const restored = upsertRestoredThresholdEcdsaSessionRecord(
      rawSessionRecord({ source: 'login', thresholdSessionId: 'tehss-restored' }),
    );

    expect(restored.thresholdSessionId).toBe('tehss-restored');
    expect(
      getStoredThresholdEcdsaSessionRecordByThresholdSessionId('tehss-restored')
        ?.signingGrantId,
    ).toBe(restored.signingGrantId);
  });

  test('reads persisted ready records without legacy role-local raw state', () => {
    const ready = parseThresholdEcdsaSessionRecordAsRoleLocalReadyRecord(rawSessionRecord());
    const record = rawSessionRecord({
      ecdsaRoleLocalReadyRecord: ready,
      ecdsaHssRoleLocalClientState: undefined,
      clientAdditiveShare32B64u: share32B64u,
    });

    const parsed = parseThresholdEcdsaSessionRecordAsRoleLocalReadyRecord(record);
    expect(parsed.publicFacts.hssClientSharePublicKey33B64u).toBe(hssClientSharePublicKey33B64u);

    const state = classifyThresholdEcdsaSessionRecordRoleLocalState({
      record,
      nowMs: 1,
    });
    expect(state.kind).toBe('ready_passkey_role_local_material_v1');
    if (state.kind !== 'ready_passkey_role_local_material_v1') {
      throw new Error('expected ready passkey material');
    }
    expect(state.readyRecord.publicFacts.keyHandle).toBe(keyHandle);
    expect(state.inlineSigningMaterial).toEqual({
      kind: 'role_local_ready_state_blob',
      stateBlob: state.readyRecord.stateBlob,
    });
  });

  test('rejects deleted legacy role-local session state', () => {
    expect(() =>
      parseThresholdEcdsaSessionRecordAsRoleLocalReadyRecord(
        rawSessionRecord({
          ecdsaRoleLocalReadyRecord: undefined,
          ecdsaHssRoleLocalClientState: legacyRoleLocalState(),
        }),
      ),
    ).toThrow(/deleted ecdsaHssRoleLocalClientState/);
  });

  test('returns parse results for branch-specific ready records', () => {
    const parsedReadyRecord =
      parseThresholdEcdsaSessionRecordAsRoleLocalReadyRecord(rawSessionRecord());
    const readyRecordWire = serializeEcdsaRoleLocalReadyRecord(parsedReadyRecord);
    const ready = parseRawEcdsaRoleLocalRecord({
      raw: readyRecordWire,
      lookup: loadInput(
        buildEcdsaRoleLocalPasskeyAuthMethod({ credentialIdB64u: passkeyCredentialIdB64u, rpId }),
      ),
    });
    expect(ready).toMatchObject({
      ok: true,
      source: 'ready_record',
    });
  });

  test('rejects deleted legacy and unbranched ready-record shapes at the raw record boundary', () => {
    const legacy = parseRawEcdsaRoleLocalRecord({
      raw: rawSessionRecord(),
      lookup: loadInput(
        buildEcdsaRoleLocalPasskeyAuthMethod({ credentialIdB64u: passkeyCredentialIdB64u, rpId }),
      ),
    });
    expect(legacy).toMatchObject({
      ok: false,
      code: 'malformed_record',
    });

    const ready = parseThresholdEcdsaSessionRecordAsRoleLocalReadyRecord(rawSessionRecord());
    const { authMethod: _authMethod, ...wire } = serializeEcdsaRoleLocalReadyRecord(ready);
    const currentUnbranched = parseRawEcdsaRoleLocalRecord({
      raw: {
        ...wire,
        kind: 'ecdsa_role_local_ready_record_v1',
      },
      lookup: loadInput(passkeyAuthMethod),
    });
    expect(currentUnbranched).toMatchObject({
      ok: false,
      code: 'malformed_record',
    });
  });

  test('returns malformed parse results for invalid raw records', () => {
    const result = parseRawEcdsaRoleLocalRecord({
      raw: { kind: 'wrong' },
      lookup: loadInput(),
    });
    expect(result).toMatchObject({
      ok: false,
      code: 'malformed_record',
    });
  });

  test('rejects malformed raw records at the role-local boundary', () => {
    expect(() =>
      parseThresholdEcdsaSessionRecordAsRoleLocalReadyRecord(
        rawSessionRecord({ ecdsaRoleLocalReadyRecord: undefined }),
      ),
    ).toThrow(/role-local/i);
  });

  test('parses export material without exposing raw role-local state to export consumers', () => {
    const material = parseThresholdEcdsaSessionRecordAsRoleLocalExportMaterial(rawSessionRecord());
    expect(material.readyRecord.publicFacts.groupPublicKey33B64u).toBe(groupPublicKey33B64u);
    expect(material.contextBinding32B64u).toBe(share32B64u);
  });

  test('rejects export material when required public identity is missing', () => {
    expect(() =>
      parseThresholdEcdsaSessionRecordAsRoleLocalExportMaterial(
        rawSessionRecord({
          ecdsaRoleLocalReadyRecord: {
            ...readyRecord(),
            publicFacts: {
              ...publicFacts(),
              relayerPublicKey33B64u: '',
            },
          },
        }),
      ),
    ).toThrow(/role-local|public/i);
  });

  test('classifies passkey ready-state blob material without inline share fields', () => {
    const state = classifyThresholdEcdsaSessionRecordRoleLocalState({
      record: rawSessionRecord(),
      nowMs: 1,
    });
    expect(state.kind).toBe('ready_passkey_role_local_material_v1');
    if (state.kind !== 'ready_passkey_role_local_material_v1') {
      throw new Error('expected ready passkey material');
    }
    expect(state.inlineSigningMaterial).toEqual({
      kind: 'role_local_ready_state_blob',
      stateBlob: state.readyRecord.stateBlob,
    });
  });

  test('classifies Email OTP worker-owned material without exposing inline share fields', () => {
    const state = classifyThresholdEcdsaSessionRecordRoleLocalState({
      record: rawSessionRecord({
        source: 'email_otp',
        emailOtpAuthContext: {
          policy: 'session',
          retention: 'session',
          reason: 'login',
          authMethod: 'email_otp',
          authSubjectId: emailOtpAuthSubjectId,
        },
        clientAdditiveShareHandle: {
          kind: 'email_otp_worker_session',
          sessionId: 'email-otp-session',
        },
      }),
      nowMs: 1,
    });
    expect(state.kind).toBe('ready_email_otp_role_local_material_v1');
    if (state.kind !== 'ready_email_otp_role_local_material_v1') {
      throw new Error('expected ready Email OTP material');
    }
    expect(state.inlineSigningMaterial).toEqual({
      kind: 'email_otp_worker_share',
      workerSessionId: 'email-otp-session',
    });
    expect(state.authMethod).toEqual(emailOtpAuthMethod);
  });

  test('classifies Email OTP registration ready-state blob material as ready', () => {
    const state = classifyThresholdEcdsaSessionRecordRoleLocalState({
      record: rawSessionRecord({
        source: 'email_otp',
        emailOtpAuthContext: {
          policy: 'session',
          retention: 'session',
          reason: 'login',
          authMethod: 'email_otp',
          authSubjectId: emailOtpAuthSubjectId,
        },
      }),
      nowMs: 1,
    });
    expect(state.kind).toBe('ready_email_otp_role_local_material_v1');
    if (state.kind !== 'ready_email_otp_role_local_material_v1') {
      throw new Error('expected ready Email OTP registration material');
    }
    expect(state.inlineSigningMaterial).toEqual({
      kind: 'role_local_ready_state_blob',
      stateBlob: state.readyRecord.stateBlob,
    });
    expect(state.authMethod).toEqual(emailOtpAuthMethod);
  });

  test('classifies expired and malformed records without raw-shape leakage', () => {
    const expired = classifyThresholdEcdsaSessionRecordRoleLocalState({
      record: rawSessionRecord({
        clientAdditiveShare32B64u: share32B64u,
        expiresAtMs: 10,
      }),
      nowMs: 11,
    });
    expect(expired).toMatchObject({
      kind: 'reauth_required_role_local_material_v1',
      reason: 'expired',
    });

    const malformed = classifyThresholdEcdsaSessionRecordRoleLocalState({
      record: { kind: 'wrong' },
      nowMs: 1,
    });
    expect(malformed).toMatchObject({
      kind: 'cleanup_only_raw_role_local_record_v1',
      reason: 'malformed_record',
    });
  });

  test('parses worker export material at the boundary for current browser worker calls', () => {
    const material =
      parseThresholdEcdsaSessionRecordAsRoleLocalWorkerExportMaterial(rawSessionRecord());
    expect(material.readyRecord.publicFacts.relayerPublicKey33B64u).toBe(relayerPublicKey33B64u);
    expect(material.readyRecord.publicFacts.hssClientSharePublicKey33B64u).toBe(
      hssClientSharePublicKey33B64u,
    );
    expect('roleLocalState' in material).toBe(false);
  });

  test('round-trips persisted ready records through the browser durable store', async () => {
    const appState = new Map<string, unknown>();
    const indexedDB = {
      async getAppState<T>(key: string): Promise<T | undefined> {
        return appState.get(key) as T | undefined;
      },
      async setAppState<T>(key: string, value: T): Promise<void> {
        appState.set(key, value);
      },
    };
    const runtime = createBrowserPlatformRuntime({
      indexedDB: indexedDB as unknown as import('@/core/indexedDB').UnifiedIndexedDBManager,
    });
    const ready = parseThresholdEcdsaSessionRecordAsRoleLocalReadyRecord(rawSessionRecord());
    const storageKeyFacts = loadInput(
      buildEcdsaRoleLocalPasskeyAuthMethod({ credentialIdB64u: passkeyCredentialIdB64u, rpId }),
    );
    const persist = await runtime.storage.persistEcdsaRoleLocalReadyRecord({
      record: ready,
      storageKeyFacts,
    });
    expect(persist.ok).toBe(true);
    const loaded = await runtime.storage.loadEcdsaRoleLocalReadyRecord(storageKeyFacts);
    expect(loaded.ok).toBe(true);
    if (loaded.ok && loaded.value.kind === 'found') {
      expect(loaded.value.record.publicFacts.keyHandle).toBe(keyHandle);
    }
    const key = ecdsaRoleLocalReadyRecordStorageKey(storageKeyFacts);
    appState.set(key, { kind: 'wrong' });
    const malformed = await runtime.storage.loadEcdsaRoleLocalReadyRecord(storageKeyFacts);
    expect(malformed).toMatchObject({ ok: true, value: { kind: 'malformed' } });
    const cleanup = await runtime.storage.cleanupMalformedEcdsaRoleLocalRecord({
      walletId,
      rpId,
      chainTarget,
      keyHandle,
      ecdsaThresholdKeyId,
      signingRootId,
      signingRootVersion,
      participantIds: [1, 2],
      authMethod: storageKeyFacts.authMethod,
      reason: 'test',
    });
    expect(cleanup.ok).toBe(true);
    expect(appState.get(key)).toBeNull();
  });

  test('serializes the exact branch-specific ready-record wire shape without raw share fields', () => {
    const ready = parseThresholdEcdsaSessionRecordAsRoleLocalReadyRecord(rawSessionRecord());
    const wire = serializeEcdsaRoleLocalReadyRecord(ready);

    expect(wire).toEqual({
      kind: 'ecdsa_role_local_ready_passkey_v1',
      stateBlob: {
        kind: 'ecdsa_role_local_state_blob_v1',
        curve: 'secp256k1',
        encoding: 'base64url',
        producer: 'signer_core',
        stateBlobB64u: ready.stateBlob.stateBlobB64u,
      },
      publicFacts: {
        walletId,
        rpId,
        chainTarget,
        keyHandle,
        ecdsaThresholdKeyId,
        signingRootId,
        signingRootVersion,
        clientParticipantId: 1,
        relayerParticipantId: 2,
        participantIds: [1, 2],
        hssClientSharePublicKey33B64u,
        relayerPublicKey33B64u,
        groupPublicKey33B64u,
        ethereumAddress: ownerAddress,
        contextBinding32B64u: share32B64u,
      },
      authMethod: {
        kind: 'passkey',
        credentialIdB64u: passkeyCredentialIdB64u,
        rpId,
      },
    });
    const json = JSON.stringify(wire);
    expect(json).not.toContain('clientShare32B64u');
    expect(json).not.toContain('clientAdditiveShare32B64u');
    expect(json).not.toContain('mappedPrivateShare32B64u');
    expect(json).not.toContain('verifyingShare33B64u');
  });

  test('uses branch-specific storage keys for passkey and Email OTP records', () => {
    const passkeyKey = ecdsaRoleLocalReadyRecordStorageKey(loadInput(passkeyAuthMethod));
    const emailOtpKey = ecdsaRoleLocalReadyRecordStorageKey(loadInput(emailOtpAuthMethod));

    expect(passkeyKey).toContain('passkey');
    expect(emailOtpKey).toContain('email_otp');
    expect(passkeyKey).toContain(encodeURIComponent(thresholdEcdsaChainTargetKey(chainTarget)));
    expect(passkeyKey).not.toBe(emailOtpKey);
  });

  test('cleanup deletes only the branch-specific storage key derived from typed lookup input', async () => {
    const appState = new Map<string, unknown>();
    const indexedDB = {
      async getAppState<T>(key: string): Promise<T | undefined> {
        return appState.get(key) as T | undefined;
      },
      async setAppState<T>(key: string, value: T): Promise<void> {
        appState.set(key, value);
      },
    };
    const runtime = createBrowserPlatformRuntime({
      indexedDB: indexedDB as unknown as import('@/core/indexedDB').UnifiedIndexedDBManager,
    });
    const passkeyKey = ecdsaRoleLocalReadyRecordStorageKey(loadInput(passkeyAuthMethod));
    const emailOtpKey = ecdsaRoleLocalReadyRecordStorageKey(loadInput(emailOtpAuthMethod));
    appState.set(passkeyKey, { kind: 'malformed-passkey' });
    appState.set(emailOtpKey, { kind: 'malformed-email-otp' });

    const cleanup = await runtime.storage.cleanupMalformedEcdsaRoleLocalRecord({
      ...loadInput(emailOtpAuthMethod),
      reason: 'malformed Email OTP row',
    });

    expect(cleanup.ok).toBe(true);
    expect(appState.get(emailOtpKey)).toBeNull();
    expect(appState.get(passkeyKey)).toEqual({ kind: 'malformed-passkey' });
  });

  test('rejects persisted ready records whose state blob is malformed', () => {
    const ready = parseThresholdEcdsaSessionRecordAsRoleLocalReadyRecord(rawSessionRecord());
    expect(() =>
      parseEcdsaRoleLocalReadyRecord({
        kind: ready.kind,
        publicFacts: ready.publicFacts,
        authMethod: ready.authMethod,
        stateBlob: {
          kind: 'ecdsa_role_local_state_blob_v1',
          curve: 'secp256k1',
          encoding: 'base64url',
          producer: 'signer_core',
          stateBlobB64u: '',
        },
      }),
    ).toThrow(/stateBlob/i);
  });
});
