import { expect, test } from '@playwright/test';
import {
  assertWarmSessionEnvelopeInvariant,
  type WarmSessionEnvelope,
} from '@/core/signingEngine/session/warmCapabilities/types';
import { selectedEcdsaLane } from '@/core/signingEngine/session/identity/laneIdentity';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
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
    walletId: toWalletId('invariants.testnet'),
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
  signingGrantId: string;
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
    keyHandle: `ek-${args.chain}-handle`,
    thresholdSessionKind: 'cookie',
    thresholdSessionId: args.thresholdSessionId,
    signingGrantId: args.signingGrantId,
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
    keyHandle: record.keyHandle,
    walletId: args.walletId as any,
    auth:
      args.source === 'email_otp'
        ? { kind: 'email_otp', providerSubjectId: 'google:invariants' }
        : {
            kind: 'passkey',
            rpId: 'example.localhost' as any,
            credentialIdB64u: 'credential-invariants',
          },
    signingGrantId: args.signingGrantId,
    thresholdSessionId: args.thresholdSessionId,
    chainTarget,
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
      walletSessionJwt: 'jwt:ed-invariant-session',
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
        walletSessionJwt: 'jwt:evm-invariant-session',
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

    const warmSession = await store.getWarmSession(toWalletId('invariants.testnet'));
    expect(assertWarmSessionEnvelopeInvariant(warmSession)).toBe(warmSession);
  });

  test('rejects a missing capability that still carries auth material', () => {
    const envelope = createEmptyEnvelope();
    envelope.capabilities.ed25519.auth = {
      capability: 'ed25519',
      record: {} as any,
      walletSessionJwtSource: 'none',
    };

    expect(() => assertWarmSessionEnvelopeInvariant(envelope)).toThrow(
      'invalid ed25519 capability: missing record cannot have auth',
    );
  });

  test('rejects a ready capability whose warm-session status does not match the record sessionId', () => {
    const envelope = createEmptyEnvelope();
    const { record, key, lane } = createEcdsaIdentityArgs({
      walletId: 'invariants.testnet',
      subjectId: 'wallet-invariants',
      thresholdSessionId: 'record-session',
      signingGrantId: 'wallet-session-record',
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
        state: 'ready',
        record: {
          ...record,
        } as any,
        walletSessionJwt: 'jwt:record-session',
        walletSessionJwtSource: 'ecdsa_record',
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

  test('rejects a warm status with non-positive remaining uses', () => {
    const envelope = createEmptyEnvelope();
    const { record, key, lane } = createEcdsaIdentityArgs({
      walletId: 'invariants.testnet',
      subjectId: 'wallet-invariants',
      thresholdSessionId: 'tempo-bad-claim',
      signingGrantId: 'wallet-session-tempo',
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
        state: 'ready',
        record,
        walletSessionJwt: 'jwt:tempo-bad-claim',
        walletSessionJwtSource: 'ecdsa_record',
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
