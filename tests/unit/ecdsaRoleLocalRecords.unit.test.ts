import { expect, test } from '@playwright/test';
import { base64UrlEncode } from '@shared/utils/base64';
import { createBrowserPlatformRuntime } from '@/core/platform';
import {
  ecdsaRoleLocalReadyRecordStorageKey,
  parseEcdsaRoleLocalReadyRecord,
  parseRawEcdsaRoleLocalRecord,
  parseThresholdEcdsaSessionRecordAsRoleLocalExportMaterial,
  parseThresholdEcdsaSessionRecordAsRoleLocalReadyRecord,
} from '@/core/platform/ecdsaRoleLocalRecords';
import { thresholdEcdsaChainTargetFromChainFamily, toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { toRpId } from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import {
  toEcdsaHssSigningRootId,
  toEcdsaHssSigningRootVersion,
  toEcdsaHssThresholdKeyId,
} from '@/core/signingEngine/session/identity/emailOtpHssIdentity';

function bytesB64u(length: number, fill: number): string {
  return base64UrlEncode(new Uint8Array(length).fill(fill));
}

const chainTarget = thresholdEcdsaChainTargetFromChainFamily({
  chain: 'tempo',
  chainId: 42431,
  networkSlug: 'tempo-testnet',
});

const walletId = toWalletId('wallet.testnet');
const rpId = toRpId('localhost');
const keyHandle = 'ecdsa-key-handle';
const ecdsaThresholdKeyId = toEcdsaHssThresholdKeyId('ehss-key');
const signingRootId = toEcdsaHssSigningRootId('root');
const signingRootVersion = toEcdsaHssSigningRootVersion('v1');
const clientPublicKey33B64u = bytesB64u(33, 2);
const relayerPublicKey33B64u = bytesB64u(33, 3);
const groupPublicKey33B64u = bytesB64u(33, 4);
const share32B64u = bytesB64u(32, 5);
const ownerAddress = '0x0000000000000000000000000000000000000001';

function rawSessionRecord(overrides: Record<string, unknown> = {}): Record<string, unknown> {
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
    clientVerifyingShareB64u: clientPublicKey33B64u,
    ecdsaHssRoleLocalClientState: {
      kind: 'role_local_ready',
      artifactKind: 'ecdsa-hss-role-local-client-state',
      contextBinding32B64u: share32B64u,
      clientShare32B64u: bytesB64u(32, 6),
      clientPublicKey33B64u,
      clientShareRetryCounter: 0,
      relayerPublicKey33B64u,
      groupPublicKey33B64u,
      ethereumAddress: ownerAddress,
      clientCaitSithInput: {
        participantId: 1,
        mappedPrivateShare32B64u: bytesB64u(32, 7),
        verifyingShare33B64u: clientPublicKey33B64u,
      },
      createdAtMs: 1,
      updatedAtMs: 1,
    },
    participantIds: [1, 2],
    thresholdSessionKind: 'jwt',
    thresholdSessionId: 'tehss-session',
    walletSigningSessionId: 'wss-session',
    thresholdSessionAuthToken: 'jwt',
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
    source: 'registration',
    ...overrides,
  };
}

test.describe('ECDSA role-local record boundary parser', () => {
  test('parses raw threshold ECDSA session records into normalized ready records', () => {
    const ready = parseThresholdEcdsaSessionRecordAsRoleLocalReadyRecord(rawSessionRecord());
    expect(ready.kind).toBe('ecdsa_role_local_ready_record_v1');
    expect(ready.publicFacts.walletId).toBe(walletId);
    expect(ready.publicFacts.rpId).toBe(rpId);
    expect(ready.publicFacts.keyHandle).toBe(keyHandle);
    expect(ready.publicFacts.hssClientSharePublicKey33B64u).toBe(clientPublicKey33B64u);
    expect(ready.stateBlob.kind).toBe('ecdsa_role_local_state_blob_v1');
  });

  test('returns parse results for ready records and legacy session records', () => {
    const legacy = parseRawEcdsaRoleLocalRecord(rawSessionRecord());
    expect(legacy).toMatchObject({
      ok: true,
      source: 'legacy_threshold_ecdsa_session_record',
    });
    if (!legacy.ok) throw new Error(legacy.message);

    const ready = parseRawEcdsaRoleLocalRecord(legacy.record);
    expect(ready).toMatchObject({
      ok: true,
      source: 'ready_record',
    });
  });

  test('returns malformed parse results for invalid raw records', () => {
    const result = parseRawEcdsaRoleLocalRecord({ kind: 'wrong' });
    expect(result).toMatchObject({
      ok: false,
      code: 'malformed_record',
    });
  });

  test('rejects malformed raw records at the role-local boundary', () => {
    expect(() =>
      parseThresholdEcdsaSessionRecordAsRoleLocalReadyRecord(
        rawSessionRecord({ ecdsaHssRoleLocalClientState: undefined }),
      ),
    ).toThrow(/role-local/i);
  });

  test('parses export material without exposing raw role-local state to export consumers', () => {
    const material = parseThresholdEcdsaSessionRecordAsRoleLocalExportMaterial(rawSessionRecord());
    expect(material.readyRecord.publicFacts.groupPublicKey33B64u).toBe(groupPublicKey33B64u);
    expect(material.contextBinding32B64u).toBe(share32B64u);
    expect(material.clientShareRetryCounter).toBe(0);
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
      indexedDB: indexedDB as typeof import('@/core/indexedDB').UnifiedIndexedDBManager,
    });
    const ready = parseThresholdEcdsaSessionRecordAsRoleLocalReadyRecord(rawSessionRecord());
    const persist = await runtime.storage.persistEcdsaRoleLocalReadyRecord({ record: ready });
    expect(persist.ok).toBe(true);
    const loadInput = {
      walletId,
      rpId,
      chainTarget,
      keyHandle,
      ecdsaThresholdKeyId,
      signingRootId,
      signingRootVersion,
      participantIds: [1, 2] as const,
    };
    const loaded = await runtime.storage.loadEcdsaRoleLocalReadyRecord(loadInput);
    expect(loaded.ok).toBe(true);
    if (loaded.ok) {
      expect(loaded.value?.publicFacts.keyHandle).toBe(keyHandle);
    }
    const key = ecdsaRoleLocalReadyRecordStorageKey(loadInput);
    appState.set(key, { kind: 'wrong' });
    const malformed = await runtime.storage.loadEcdsaRoleLocalReadyRecord(loadInput);
    expect(malformed).toMatchObject({ ok: false, code: 'malformed_record' });
    const cleanup = await runtime.storage.cleanupMalformedEcdsaRoleLocalRecord({
      walletId,
      rpId,
      chainTarget,
      keyHandle,
      ecdsaThresholdKeyId,
      signingRootId,
      signingRootVersion,
      participantIds: [1, 2],
      reason: 'test',
    });
    expect(cleanup.ok).toBe(true);
    expect(appState.get(key)).toBeNull();
  });

  test('rejects persisted ready records whose state blob is malformed', () => {
    const ready = parseThresholdEcdsaSessionRecordAsRoleLocalReadyRecord(rawSessionRecord());
    expect(() =>
      parseEcdsaRoleLocalReadyRecord({
        kind: ready.kind,
        publicFacts: ready.publicFacts,
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
