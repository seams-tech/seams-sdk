import { expect, test } from '@playwright/test';
import {
  buildReusableEcdsaBootstrapResult,
  getEcdsaCapabilityCandidates,
  getMatchingReadyEcdsaCapability,
  getPrimaryAndSecondaryEcdsaCapabilities,
  normalizeParticipantIds,
  toOptionalNonEmptyString,
} from '@/core/signingEngine/session/passkey/ecdsaProvisioner';
import { selectedEcdsaLane } from '@/core/signingEngine/session/identity/laneIdentity';
import type { WarmSessionEnvelope } from '@/core/signingEngine/session/warmCapabilities/types';
import {
  buildEvmFamilyEcdsaKeyIdentityFromRecord,
} from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import { thresholdEcdsaRecordRpId } from '@/core/signingEngine/session/persistence/records';
import {
  createThresholdEcdsaStoreFixture,
  createThresholdEcdsaBootstrapFixture,
  seedEcdsaWarmSessionRecord,
  testEcdsaChainTarget,
} from './helpers/warmSessionStore.fixtures';

const EVM_CHAIN_TARGET = testEcdsaChainTarget('evm');
const TEMPO_CHAIN_TARGET = testEcdsaChainTarget('tempo');

function createEnvelope(): WarmSessionEnvelope {
  const ecdsaSessions = createThresholdEcdsaStoreFixture();
  const evmBootstrap = createThresholdEcdsaBootstrapFixture({
    nearAccountId: 'provisioning.testnet',
    chain: 'evm',
    ecdsaThresholdKeyId: 'ek-evm',
    sessionId: 'evm-session',
    sessionAuthToken: 'jwt.evm.session',
  });
  const tempoBootstrap = createThresholdEcdsaBootstrapFixture({
    nearAccountId: 'provisioning.testnet',
    chain: 'tempo',
    ecdsaThresholdKeyId: 'ek-evm',
    sessionId: 'tempo-session',
    sessionAuthToken: 'jwt.tempo.session',
  });
  const evmRecord = seedEcdsaWarmSessionRecord(ecdsaSessions, {
    nearAccountId: 'provisioning.testnet',
    chain: 'evm',
    source: 'login',
    bootstrap: evmBootstrap,
  });
  const tempoRecord = seedEcdsaWarmSessionRecord(ecdsaSessions, {
    nearAccountId: 'provisioning.testnet',
    chain: 'tempo',
    source: 'login',
    bootstrap: tempoBootstrap,
  });
  const evmKey = buildEvmFamilyEcdsaKeyIdentityFromRecord({
    record: evmRecord,
    rpId: thresholdEcdsaRecordRpId(evmRecord),
  });
  const tempoKey = buildEvmFamilyEcdsaKeyIdentityFromRecord({
    record: tempoRecord,
    rpId: thresholdEcdsaRecordRpId(tempoRecord),
  });
  const envelope: WarmSessionEnvelope = {
    walletId: evmRecord.walletId,
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
          record: evmRecord,
          key: evmKey,
          lane: selectedEcdsaLane({
            key: evmKey,
            keyHandle: evmRecord.keyHandle,
            walletId: evmRecord.walletId,
            authMethod: 'passkey',
            walletSigningSessionId: evmRecord.walletSigningSessionId,
            thresholdSessionId: evmRecord.thresholdSessionId,
            chainTarget: evmRecord.chainTarget,
          }),
          auth: {
            capability: 'ecdsa',
            record: evmRecord,
            thresholdSessionAuthToken: evmRecord.thresholdSessionAuthToken,
            thresholdSessionAuthTokenSource: 'ecdsa',
          },
          prfClaim: {
            state: 'warm',
            sessionId: 'evm-session',
            remainingUses: 3,
            expiresAtMs: Date.now() + 120_000,
          },
          state: 'ready',
        },
        tempo: {
          capability: 'ecdsa',
          record: tempoRecord,
          key: tempoKey,
          lane: selectedEcdsaLane({
            key: tempoKey,
            keyHandle: tempoRecord.keyHandle,
            walletId: tempoRecord.walletId,
            authMethod: 'passkey',
            walletSigningSessionId: tempoRecord.walletSigningSessionId,
            thresholdSessionId: tempoRecord.thresholdSessionId,
            chainTarget: tempoRecord.chainTarget,
          }),
          auth: {
            capability: 'ecdsa',
            record: tempoRecord,
            thresholdSessionAuthToken: tempoRecord.thresholdSessionAuthToken,
            thresholdSessionAuthTokenSource: 'ecdsa',
          },
          prfClaim: {
            state: 'warm',
            sessionId: 'tempo-session',
            remainingUses: 1,
            expiresAtMs: Date.now() + 120_000,
          },
          state: 'ready',
        },
      },
    },
    updatedAtMs: Date.now(),
  };
  return envelope;
}

test.describe('warmSessionEcdsaProvisioning', () => {
  test('matches only the ready capability with the same session and threshold key id', () => {
    const envelope = createEnvelope();
    const record = envelope.capabilities.ecdsa.evm.record!;

    expect(
      getMatchingReadyEcdsaCapability({
        warmSession: envelope,
        chainTarget: EVM_CHAIN_TARGET,
        record,
        usesNeeded: 2,
      }),
    ).toBe(envelope.capabilities.ecdsa.evm);

    expect(
      getMatchingReadyEcdsaCapability({
        warmSession: envelope,
        chainTarget: EVM_CHAIN_TARGET,
        record: {
          ...record,
          thresholdSessionId: 'wrong-session',
        },
        usesNeeded: 1,
      }),
    ).toBeNull();
  });

  test('builds a reusable bootstrap result from a ready ECDSA capability', () => {
    const envelope = createEnvelope();
    const record = envelope.capabilities.ecdsa.evm.record!;

    expect(
      buildReusableEcdsaBootstrapResult({
        record,
        capability: envelope.capabilities.ecdsa.evm,
        source: 'login',
      }),
    ).toMatchObject({
      thresholdEcdsaKeyRef: {
        ecdsaThresholdKeyId: 'ek-evm',
        thresholdSessionId: 'evm-session',
        thresholdSessionAuthToken: record.thresholdSessionAuthToken,
      },
      session: {
        ok: true,
        sessionId: 'evm-session',
        walletSigningSessionId: 'wsess-evm-session',
        jwt: record.thresholdSessionAuthToken,
      },
    });
  });

  test('returns primary and secondary ECDSA capabilities in chain order', () => {
    const envelope = createEnvelope();
    const candidates = getEcdsaCapabilityCandidates({
      warmSession: envelope,
      chainTarget: TEMPO_CHAIN_TARGET,
    });
    const ordering = getPrimaryAndSecondaryEcdsaCapabilities({
      warmSession: envelope,
      chainTarget: TEMPO_CHAIN_TARGET,
    });

    expect(candidates).toEqual([
      envelope.capabilities.ecdsa.tempo,
      envelope.capabilities.ecdsa.evm,
    ]);
    expect(ordering).toEqual({
      primary: envelope.capabilities.ecdsa.tempo,
      secondary: envelope.capabilities.ecdsa.evm,
    });
  });

  test('normalizes optional participant ids and strings', () => {
    expect(normalizeParticipantIds(['1', 2, 'x'])).toEqual([1, 2]);
    expect(normalizeParticipantIds('not-an-array')).toBeUndefined();
    expect(toOptionalNonEmptyString('  value  ')).toBe('value');
    expect(toOptionalNonEmptyString('   ')).toBeUndefined();
  });
});
