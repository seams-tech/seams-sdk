import { expect, test } from '@playwright/test';
import {
  assertWarmSessionEnvelopeInvariant,
  type WarmSessionEnvelope,
} from '@/core/signingEngine/session/warmCapabilities/types';
import { selectedEcdsaLane } from '@/core/signingEngine/session/identity/laneIdentity';
import { testEcdsaChainTarget } from './helpers/warmSessionStore.fixtures';
import {
  createWarmSessionTestServices,
  createThresholdEcdsaBootstrapFixture,
  createThresholdEcdsaStoreFixture,
  createWarmSessionStatusReader,
  resetWarmSessionFixtureState,
  seedEd25519WarmSessionRecord,
  seedEcdsaWarmSessionRecord,
} from './helpers/warmSessionStore.fixtures';

function createEmptyEnvelope(): WarmSessionEnvelope {
  return {
    walletId: 'invariants.testnet' as any,
    capabilities: {
      ed25519: {
        capability: 'ed25519',
        record: null,
        auth: null,
        prfClaim: null,
        state: 'missing',
      },
      ecdsa: {
        evm: {
          capability: 'ecdsa',
          record: null,
          key: null,
          lane: null,
          auth: null,
          prfClaim: null,
          state: 'missing',
        },
        tempo: {
          capability: 'ecdsa',
          record: null,
          key: null,
          lane: null,
          auth: null,
          prfClaim: null,
          state: 'missing',
        },
      },
    },
    updatedAtMs: Date.now(),
  };
}

function createEcdsaIdentityArgs(args: {
  walletId: string;
  subjectId: string;
  thresholdSessionId: string;
  walletSigningSessionId: string;
  chain: 'evm' | 'tempo';
  source: 'login' | 'email_otp';
}) {
  const chainTarget = testEcdsaChainTarget(args.chain);
  const record = {
    walletId: args.walletId,
    subjectId: args.subjectId,
    rpId: 'example.localhost',
    chainTarget,
    ecdsaThresholdKeyId: `ek-${args.chain}`,
    signingRootId: 'signing-root',
    signingRootVersion: 'default',
    participantIds: [1, 2],
    ethereumAddress: `0x${'11'.repeat(20)}`,
    thresholdSessionKind: 'cookie',
    thresholdSessionId: args.thresholdSessionId,
    walletSigningSessionId: args.walletSigningSessionId,
    relayerUrl: 'https://relay.example',
    relayerKeyId: 'relayer-key',
    clientVerifyingShareB64u: 'AQ',
    expiresAtMs: Date.now() + 120_000,
    remainingUses: 2,
    source: args.source,
    updatedAtMs: Date.now(),
  } as any;
  const key = {
    walletId: args.walletId,
    subjectId: args.subjectId,
    rpId: 'example.localhost',
    keyScope: 'evm-family',
    ecdsaThresholdKeyId: `ek-${args.chain}`,
    signingRootId: 'signing-root',
    signingRootVersion: 'default',
    participantIds: [1, 2],
    thresholdOwnerAddress: `0x${'11'.repeat(20)}`,
  } as any;
  const lane = selectedEcdsaLane({
    key,
    walletId: args.walletId as any,
    authMethod: args.source === 'email_otp' ? 'email_otp' : 'passkey',
    walletSigningSessionId: args.walletSigningSessionId,
    thresholdSessionId: args.thresholdSessionId,
    subjectId: args.subjectId,
    chainTarget,
    ecdsaThresholdKeyId: key.ecdsaThresholdKeyId,
    signingRootId: key.signingRootId,
    signingRootVersion: key.signingRootVersion,
  });
  return { record, key, lane };
}

test.describe('WarmSessionStore invariants', () => {
  test('accepts a valid warm-session envelope from the store', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);

    const edRecord = seedEd25519WarmSessionRecord({
      nearAccountId: 'invariants.testnet',
      thresholdSessionId: 'ed-invariant-session',
      thresholdSessionAuthToken: 'jwt:ed-invariant-session',
    });
    const evmRecord = seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId: 'invariants.testnet',
      chain: 'evm',
      source: 'login',
      bootstrap: createThresholdEcdsaBootstrapFixture({
        nearAccountId: 'invariants.testnet',
        chain: 'evm',
        ecdsaThresholdKeyId: 'ek-invariants',
        sessionId: 'evm-invariant-session',
        sessionAuthToken: 'jwt:evm-invariant-session',
      }),
    });

    const store = createWarmSessionTestServices({
      touchConfirm: createWarmSessionStatusReader({
        [edRecord.thresholdSessionId]: {
          state: 'warm',
          remainingUses: edRecord.remainingUses,
          expiresAtMs: edRecord.expiresAtMs,
        },
        [evmRecord.thresholdSessionId]: {
          state: 'warm',
          remainingUses: evmRecord.remainingUses || 5,
          expiresAtMs: evmRecord.expiresAtMs || Date.now() + 120_000,
        },
      }),
    });

    const warmSession = await store.getWarmSession('invariants.testnet');
    expect(assertWarmSessionEnvelopeInvariant(warmSession)).toBe(warmSession);
  });

  test('rejects a missing capability that still carries auth material', () => {
    const envelope = createEmptyEnvelope();
    envelope.capabilities.ed25519.auth = {
      capability: 'ed25519',
      record: {} as any,
      thresholdSessionAuthTokenSource: 'none',
    };

    expect(() => assertWarmSessionEnvelopeInvariant(envelope)).toThrow(
      'invalid ed25519 capability: missing record cannot have auth',
    );
  });

  test('rejects a ready capability whose warm-session status does not match the record sessionId', () => {
    const envelope = createEmptyEnvelope();
    const { record, key, lane } = createEcdsaIdentityArgs({
      walletId: 'invariants.testnet',
      subjectId: 'wallet-subject-invariants',
      thresholdSessionId: 'record-session',
      walletSigningSessionId: 'wallet-session-record',
      chain: 'evm',
      source: 'login',
    });
    envelope.capabilities.ecdsa.evm = {
      capability: 'ecdsa',
      record,
      key,
      lane: {
        ...lane,
        key,
      },
      auth: {
        capability: 'ecdsa',
        record: {
          ...record,
        } as any,
        thresholdSessionAuthToken: 'jwt:record-session',
        thresholdSessionAuthTokenSource: 'ecdsa',
      },
      prfClaim: {
        state: 'warm',
        sessionId: 'other-session',
        remainingUses: 2,
        expiresAtMs: Date.now() + 10_000,
      },
      state: 'ready',
    };

    expect(() => assertWarmSessionEnvelopeInvariant(envelope)).toThrow(
      'invalid ecdsa.evm capability: auth.record must reference the capability record',
    );
  });

  test('rejects a JWT capability marked ready without a JWT', () => {
    const envelope = createEmptyEnvelope();
    const record = {
      nearAccountId: 'invariants.testnet',
      thresholdSessionId: 'jwt-missing-session',
      thresholdSessionKind: 'jwt',
    } as any;
    envelope.capabilities.ed25519 = {
      capability: 'ed25519',
      record,
      auth: {
        capability: 'ed25519',
        record,
        thresholdSessionAuthTokenSource: 'none',
      },
      prfClaim: {
        state: 'warm',
        sessionId: 'jwt-missing-session',
        remainingUses: 1,
        expiresAtMs: Date.now() + 10_000,
      },
      state: 'ready',
    };

    expect(() => assertWarmSessionEnvelopeInvariant(envelope)).toThrow(
      'invalid ed25519 capability: state=ready does not match derived state=auth_missing',
    );
  });

  test('rejects a warm status with non-positive remaining uses', () => {
    const envelope = createEmptyEnvelope();
    const { record, key, lane } = createEcdsaIdentityArgs({
      walletId: 'invariants.testnet',
      subjectId: 'wallet-subject-invariants',
      thresholdSessionId: 'tempo-bad-claim',
      walletSigningSessionId: 'wallet-session-tempo',
      chain: 'tempo',
      source: 'login',
    });
    envelope.capabilities.ecdsa.tempo = {
      capability: 'ecdsa',
      record,
      key,
      lane: {
        ...lane,
        key,
      },
      auth: {
        capability: 'ecdsa',
        record,
        thresholdSessionAuthTokenSource: 'none',
      },
      prfClaim: {
        state: 'warm',
        sessionId: 'tempo-bad-claim',
        remainingUses: 0,
        expiresAtMs: Date.now() + 10_000,
      },
      state: 'ready',
    };

    expect(() => assertWarmSessionEnvelopeInvariant(envelope)).toThrow(
      'invalid ecdsa.tempo capability: warm warm-session status requires positive remainingUses and expiresAtMs',
    );
  });
});
