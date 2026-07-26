import { expect, test } from '@playwright/test';
import { deriveEvmFamilySigningKeySlotId } from '@shared/signing-lanes';
import { base64UrlEncode } from '@shared/utils/base64';
import { createBrowserPlatformRuntime } from '@/core/platform';
import {
  clearAllThresholdEcdsaSessionRecords,
  getThresholdEcdsaSessionRecordByThresholdSessionId,
  getStoredThresholdEcdsaSessionRecordByThresholdSessionId,
  upsertThresholdEcdsaSessionFact,
  upsertRestoredThresholdEcdsaSessionRecord,
} from '@/core/signingEngine/session/persistence/records';
import { buildEmailOtpAuthContextForWalletAuthMethod } from '@/core/signingEngine/session/identity/laneIdentity';
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
  toEcdsaDerivationSigningRootId,
  toEcdsaDerivationSigningRootVersion,
  toEcdsaDerivationThresholdKeyId,
  toEmailOtpAuthSubjectId,
} from '@/core/signingEngine/session/identity/emailOtpEcdsaDerivationIdentity';
import type { EcdsaRoleLocalAuthMethod, LoadEcdsaRoleLocalReadyRecordInput } from '@/core/platform';
import { createThresholdEcdsaBootstrapFixture } from './helpers/ecdsaBootstrap.fixtures';
import {
  buildEmailOtpEcdsaSessionRecordFixture,
  buildPasskeyEcdsaSessionRecordFixture,
} from './helpers/signingSessionRecord.fixtures';

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
const otherWalletId = toWalletId('other-wallet.testnet');
const rpId = toRpId('localhost');
const keyHandle = 'ecdsa-key-handle';
const passkeyCredentialIdB64u = 'passkey-credential-id';
const ecdsaThresholdKeyId = toEcdsaDerivationThresholdKeyId('ederivation-key');
const signingRootId = toEcdsaDerivationSigningRootId('root');
const signingRootVersion = toEcdsaDerivationSigningRootVersion('v1');
const evmFamilySigningKeySlotId = deriveEvmFamilySigningKeySlotId({
  walletId,
  signingRootId,
  signingRootVersion,
});
const otherEvmFamilySigningKeySlotId = deriveEvmFamilySigningKeySlotId({
  walletId: otherWalletId,
  signingRootId,
  signingRootVersion,
});
const derivationClientSharePublicKey33B64u = compressedPublicKeyB64u(2, 11);
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
const roleLocalDurableMaterialRef = 'role-local-durable-tederivation-session';

function emailOtpSessionAuthContext() {
  return buildEmailOtpAuthContextForWalletAuthMethod({
    policy: 'session',
    walletId,
    emailHashHex: '11'.repeat(32),
    reason: 'login',
    retention: 'session',
    provider: 'google',
    providerUserId: emailOtpAuthSubjectId,
  });
}

function loadInput(
  authMethod: EcdsaRoleLocalAuthMethod = passkeyAuthMethod,
): LoadEcdsaRoleLocalReadyRecordInput {
  return {
    walletId,
    evmFamilySigningKeySlotId,
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
    artifactKind: 'ecdsa-derivation-role-local-client-state',
    contextBinding32B64u: share32B64u,
    clientShare32B64u: bytesB64u(32, 6),
    clientPublicKey33B64u: derivationClientSharePublicKey33B64u,
    clientShareRetryCounter: 0,
    relayerPublicKey33B64u,
    groupPublicKey33B64u,
    ethereumAddress: ownerAddress,
    clientCaitSithInput: {
      participantId: 1,
      mappedPrivateShare32B64u: bytesB64u(32, 7),
      verifyingShare33B64u: derivationClientSharePublicKey33B64u,
    },
    createdAtMs: 1,
    updatedAtMs: 1,
  };
}

function publicFacts() {
  return readyRecord().publicFacts;
}

function readyRecord(authMethod: EcdsaRoleLocalAuthMethod = passkeyAuthMethod) {
  const bootstrap = createThresholdEcdsaBootstrapFixture({
    nearAccountId: walletId,
    chain: 'tempo',
    rpId,
    keyHandle,
    ecdsaThresholdKeyId,
    sessionId: 'tederivation-session',
    signingGrantId: 'wss-session',
    relayerUrl: 'https://relayer.example',
    relayerKeyId: 'relayer-key',
    passkeyCredentialIdB64u,
    signingRootId,
    signingRootVersion,
    ethereumAddress: ownerAddress,
    expiresAtMs: Date.now() + 60_000,
    remainingUses: 3,
    roleLocalAuthMethod: authMethod.kind,
    ...(authMethod.kind === 'email_otp'
      ? { emailOtpAuthSubjectId: authMethod.authSubjectId }
      : {}),
  });
  const binding = bootstrap.thresholdEcdsaKeyRef.backendBinding;
  if (binding?.materialKind !== 'role_local_ready_state_blob') {
    throw new Error('expected role-local ready-record fixture');
  }
  return binding.ecdsaRoleLocalReadyRecord;
}

function rawSessionRecord(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  const sourceRaw = String(overrides.source || 'registration');
  const thresholdSessionId = String(overrides.thresholdSessionId || 'tederivation-session');
  const signingGrantId = String(overrides.signingGrantId || 'wss-session');
  const expiresAtMs = Number(overrides.expiresAtMs ?? Date.now() + 60_000);
  const remainingUses = Number(overrides.remainingUses ?? 3);
  const common = {
    walletId,
    chain: 'tempo' as const,
    chainTarget,
    keyHandle,
    ecdsaThresholdKeyId,
    thresholdSessionId,
    signingGrantId,
    relayerUrl: 'https://relayer.example',
    relayerKeyId: 'relayer-key',
    signingRootId,
    signingRootVersion,
    ethereumAddress: ownerAddress,
    expiresAtMs,
    remainingUses,
    updatedAtMs: 1,
  };
  if (sourceRaw === 'email_otp') {
    const record = buildEmailOtpEcdsaSessionRecordFixture({
      ...common,
      emailOtpAuthContext: emailOtpSessionAuthContext(),
    });
    return {
      ...record,
      clientAdditiveShareHandle: undefined,
      ...overrides,
    };
  }
  const source =
    sourceRaw === 'login' || sourceRaw === 'manual-bootstrap' ? sourceRaw : 'registration';
  const record = buildPasskeyEcdsaSessionRecordFixture({
    ...common,
    rpId,
    passkeyCredentialIdB64u,
    source,
    roleLocalDurableMaterialRef,
  });
  return {
    ...record,
    ...overrides,
  };
}

function emailOtpRawSessionRecord(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return rawSessionRecord({
    source: 'email_otp',
    emailOtpAuthContext: emailOtpSessionAuthContext(),
    ...overrides,
  });
}

test.describe('ECDSA role-local record boundary parser', () => {
  test.beforeEach(() => {
    clearAllThresholdEcdsaSessionRecords({ recordsByLane: new Map() });
  });

  test.afterEach(() => {
    clearAllThresholdEcdsaSessionRecords({ recordsByLane: new Map() });
  });

  test('parses canonical inline Email OTP sessions into normalized ready records', () => {
    const ready = parseThresholdEcdsaSessionRecordAsRoleLocalReadyRecord(
      emailOtpRawSessionRecord(),
    );
    expect(ready.kind).toBe('ecdsa_role_local_ready_email_otp_v1');
    expect(ready.authMethod).toEqual(emailOtpAuthMethod);
    expect(ready.publicFacts.walletId).toBe(walletId);
    expect(ready.publicFacts.evmFamilySigningKeySlotId).toBe(evmFamilySigningKeySlotId);
    expect(ready.publicFacts.keyHandle).toBe(keyHandle);
    expect(ready.publicFacts.derivationClientSharePublicKey33B64u).toBe(
      publicFacts().derivationClientSharePublicKey33B64u,
    );
    expect(ready.stateBlob.kind).toBe('ecdsa_role_local_state_blob_v1');
  });

  test('rejects auth fields inside ECDSA role-local public facts', () => {
    expect(() =>
      buildEcdsaRoleLocalPublicFacts({
        ...publicFacts(),
        rpId,
      }),
    ).toThrow(/auth fields are not publicFacts/);
  });

  test('rejects deleted nested wallet-key metadata on ECDSA session records', () => {
    expect(() =>
      parseThresholdEcdsaSessionRecordAsRoleLocalReadyRecord(
        rawSessionRecord({
          authMetadata: { evmFamilySigningKeySlotId },
        }),
      ),
    ).toThrow(/deleted authMetadata/);
  });

  test('rejects ECDSA session records whose role-local wallet key disagrees', () => {
    const emailOtpReadyRecord = readyRecord(emailOtpAuthMethod);
    const mismatchedPublicFacts = buildEcdsaRoleLocalPublicFacts({
      ...emailOtpReadyRecord.publicFacts,
      evmFamilySigningKeySlotId: otherEvmFamilySigningKeySlotId,
    });
    const mismatchedReadyRecord = buildEcdsaRoleLocalReadyRecord({
      ...emailOtpReadyRecord,
      publicFacts: mismatchedPublicFacts,
    });

    expect(() =>
      parseThresholdEcdsaSessionRecordAsRoleLocalReadyRecord(
        emailOtpRawSessionRecord({
          ecdsaRoleLocalPublicFacts: mismatchedPublicFacts,
          ecdsaRoleLocalReadyRecord: mismatchedReadyRecord,
        }),
      ),
    ).toThrow(/evmFamilySigningKeySlotId mismatch/);
  });

  test('restored passkey ECDSA records are written to the active session index', () => {
    const restored = upsertRestoredThresholdEcdsaSessionRecord(
      rawSessionRecord({ source: 'login', thresholdSessionId: 'tederivation-restored' }),
    );

    expect(restored.thresholdSessionId).toBe('tederivation-restored');
    expect(
      getStoredThresholdEcdsaSessionRecordByThresholdSessionId('tederivation-restored')
        ?.signingGrantId,
    ).toBe(restored.signingGrantId);
  });

  test('threshold-session ECDSA lookup fails closed when multiple lane identities match', () => {
    const thresholdSessionId = 'tederivation-ambiguous';
    upsertRestoredThresholdEcdsaSessionRecord(
      rawSessionRecord({
        source: 'email_otp',
        thresholdSessionId,
        signingGrantId: 'wss-ambiguous-a',
        emailOtpAuthContext: emailOtpSessionAuthContext(),
      }),
    );
    upsertRestoredThresholdEcdsaSessionRecord(
      rawSessionRecord({
        source: 'email_otp',
        thresholdSessionId,
        signingGrantId: 'wss-ambiguous-b',
        emailOtpAuthContext: emailOtpSessionAuthContext(),
      }),
    );

    expect(getStoredThresholdEcdsaSessionRecordByThresholdSessionId(thresholdSessionId)).toBeNull();
  });

  test('deps threshold-session ECDSA lookup fails closed across local and in-memory stores', () => {
    const thresholdSessionId = 'tederivation-store-ambiguous';
    const deps = { recordsByLane: new Map() };
    upsertThresholdEcdsaSessionFact(
      deps,
      rawSessionRecord({
        source: 'email_otp',
        thresholdSessionId,
        signingGrantId: 'wss-store-ambiguous-a',
        emailOtpAuthContext: emailOtpSessionAuthContext(),
      }),
    );
    upsertRestoredThresholdEcdsaSessionRecord(
      rawSessionRecord({
        source: 'email_otp',
        thresholdSessionId,
        signingGrantId: 'wss-store-ambiguous-b',
        emailOtpAuthContext: emailOtpSessionAuthContext(),
      }),
    );

    expect(getThresholdEcdsaSessionRecordByThresholdSessionId(deps, thresholdSessionId)).toBeNull();
  });

  test('reads persisted ready records without legacy role-local raw state', () => {
    const ready = readyRecord(emailOtpAuthMethod);
    const record = emailOtpRawSessionRecord({
      ecdsaRoleLocalReadyRecord: ready,
      ecdsaDerivationRoleLocalClientState: undefined,
    });

    const parsed = parseThresholdEcdsaSessionRecordAsRoleLocalReadyRecord(record);
    expect(parsed.publicFacts.derivationClientSharePublicKey33B64u).toBe(
      ready.publicFacts.derivationClientSharePublicKey33B64u,
    );

    const state = classifyThresholdEcdsaSessionRecordRoleLocalState({
      record,
      nowMs: 1,
    });
    expect(state.kind).toBe('ready_email_otp_role_local_material_v1');
    if (state.kind !== 'ready_email_otp_role_local_material_v1') {
      throw new Error('expected ready Email OTP material');
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
          ecdsaDerivationRoleLocalClientState: legacyRoleLocalState(),
        }),
      ),
    ).toThrow(/deleted ecdsaDerivationRoleLocalClientState/);
  });

  test('returns parse results for branch-specific ready records', () => {
    const parsedReadyRecord = readyRecord();
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

    const ready = readyRecord();
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
    const material = parseThresholdEcdsaSessionRecordAsRoleLocalExportMaterial(
      emailOtpRawSessionRecord(),
    );
    expect(material.readyRecord.publicFacts.groupPublicKey33B64u).toBe(
      publicFacts().groupPublicKey33B64u,
    );
    expect(material.contextBinding32B64u).toBe(publicFacts().contextBinding32B64u);
  });

  test('rejects export material when required public identity is missing', () => {
    expect(() =>
      parseThresholdEcdsaSessionRecordAsRoleLocalExportMaterial(
        emailOtpRawSessionRecord({
          ecdsaRoleLocalReadyRecord: {
            ...readyRecord(emailOtpAuthMethod),
            publicFacts: {
              ...readyRecord(emailOtpAuthMethod).publicFacts,
              relayerPublicKey33B64u: '',
            },
          },
        }),
      ),
    ).toThrow(/role-local|public/i);
  });

  test('classifies passkey durable material without inline share fields', () => {
    const state = classifyThresholdEcdsaSessionRecordRoleLocalState({
      record: rawSessionRecord(),
      nowMs: 1,
    });
    expect(state.kind).toBe('ready_passkey_role_local_material_v1');
    if (state.kind !== 'ready_passkey_role_local_material_v1') {
      throw new Error('expected ready passkey material');
    }
    expect(state.durableMaterialRef).toBe(roleLocalDurableMaterialRef);
    expect('inlineSigningMaterial' in state).toBe(false);
  });

  test('classifies Email OTP worker-owned material without exposing inline share fields', () => {
    const state = classifyThresholdEcdsaSessionRecordRoleLocalState({
      record: rawSessionRecord({
        source: 'email_otp',
        emailOtpAuthContext: emailOtpSessionAuthContext(),
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
        emailOtpAuthContext: emailOtpSessionAuthContext(),
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
    const ready = readyRecord();
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
      evmFamilySigningKeySlotId,
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
    const ready = readyRecord();
    const facts = ready.publicFacts;
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
        evmFamilySigningKeySlotId,
        chainTarget: facts.chainTarget,
        keyHandle,
        ecdsaThresholdKeyId,
        signingRootId,
        signingRootVersion,
        clientParticipantId: 1,
        relayerParticipantId: 2,
        participantIds: [1, 2],
        derivationClientSharePublicKey33B64u: facts.derivationClientSharePublicKey33B64u,
        relayerPublicKey33B64u: facts.relayerPublicKey33B64u,
        groupPublicKey33B64u: facts.groupPublicKey33B64u,
        ethereumAddress: ownerAddress,
        applicationBindingDigestB64u: facts.applicationBindingDigestB64u,
        contextBinding32B64u: facts.contextBinding32B64u,
        publicCapability: facts.publicCapability,
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
    const ready = readyRecord();
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
