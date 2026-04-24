import { expect, test } from '@playwright/test';
import {
  assertWarmSessionEnvelopeInvariant,
  type WarmSessionEnvelope,
} from '@/core/signingEngine/session/warmSessionTypes';
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
    accountId: 'invariants.testnet' as any,
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
          chain: 'evm',
          record: null,
          auth: null,
          prfClaim: null,
          state: 'missing',
        },
        tempo: {
          capability: 'ecdsa',
          chain: 'tempo',
          record: null,
          auth: null,
          prfClaim: null,
          state: 'missing',
        },
      },
    },
    updatedAtMs: Date.now(),
  };
}

test.describe('WarmSessionStore invariants', () => {
  test('accepts a valid warm-session envelope from the store', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);

    const edRecord = seedEd25519WarmSessionRecord({
      nearAccountId: 'invariants.testnet',
      thresholdSessionId: 'ed-invariant-session',
      thresholdSessionJwt: 'jwt:ed-invariant-session',
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
        sessionJwt: 'jwt:evm-invariant-session',
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
      thresholdSessionJwtSource: 'none',
    };

    expect(() => assertWarmSessionEnvelopeInvariant(envelope)).toThrow(
      'invalid ed25519 capability: missing record cannot have auth',
    );
  });

  test('rejects a ready capability whose warm-session status does not match the record sessionId', () => {
    const envelope = createEmptyEnvelope();
    envelope.capabilities.ecdsa.evm = {
      capability: 'ecdsa',
      chain: 'evm',
      record: {
        nearAccountId: 'invariants.testnet',
        chain: 'evm',
        thresholdSessionId: 'record-session',
        thresholdSessionKind: 'jwt',
      } as any,
      auth: {
        capability: 'ecdsa',
        chain: 'evm',
        record: {
          nearAccountId: 'invariants.testnet',
          chain: 'evm',
          thresholdSessionId: 'record-session',
          thresholdSessionKind: 'jwt',
        } as any,
        thresholdSessionJwt: 'jwt:record-session',
        thresholdSessionJwtSource: 'ecdsa',
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
        thresholdSessionJwtSource: 'none',
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
    const record = {
      nearAccountId: 'invariants.testnet',
      chain: 'tempo',
      thresholdSessionId: 'tempo-bad-claim',
      thresholdSessionKind: 'cookie',
    } as any;
    envelope.capabilities.ecdsa.tempo = {
      capability: 'ecdsa',
      chain: 'tempo',
      record,
      auth: {
        capability: 'ecdsa',
        chain: 'tempo',
        record,
        thresholdSessionJwtSource: 'none',
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
