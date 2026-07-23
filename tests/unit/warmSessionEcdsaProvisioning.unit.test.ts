import { expect, test } from '@playwright/test';
import {
  buildReusableEcdsaBootstrapResult,
  getEcdsaCapabilityCandidates,
  getMatchingReadyEcdsaCapability,
  getPrimaryAndSecondaryEcdsaCapabilities,
  normalizeParticipantIds,
  toOptionalNonEmptyString,
} from '@/core/signingEngine/useCases/provisionEcdsaSession';
import type { WarmSessionEnvelope } from '@/core/signingEngine/session/warmCapabilities/types';
import { testEcdsaChainTarget } from './helpers/ecdsaChainTarget.fixtures';

import {
  seedEcdsaWarmSessionRecord,
  createThresholdEcdsaStoreFixture,
} from './helpers/signingSessionRecord.fixtures';
import { createThresholdEcdsaBootstrapFixture } from './helpers/ecdsaBootstrap.fixtures';
import {
  createReadyPasskeyWarmSessionEcdsaCapability,
  createWarmSessionEnvelopeFixture,
  toWorkerOwnedPasskeyEcdsaBootstrapFixture,
} from './helpers/warmSessionTestServices.fixtures';

const EVM_CHAIN_TARGET = testEcdsaChainTarget('evm');
const TEMPO_CHAIN_TARGET = testEcdsaChainTarget('tempo');

function createEnvelope(): WarmSessionEnvelope {
  const ecdsaSessions = createThresholdEcdsaStoreFixture();
  const evmBootstrap = toWorkerOwnedPasskeyEcdsaBootstrapFixture(
    createThresholdEcdsaBootstrapFixture({
      nearAccountId: 'provisioning.testnet',
      chain: 'evm',
      ecdsaThresholdKeyId: 'ek-evm',
      sessionId: 'evm-session',
      walletSessionJwt: 'jwt.evm.session',
    }),
  );
  const tempoBootstrap = toWorkerOwnedPasskeyEcdsaBootstrapFixture(
    createThresholdEcdsaBootstrapFixture({
      nearAccountId: 'provisioning.testnet',
      chain: 'tempo',
      ecdsaThresholdKeyId: 'ek-evm',
      sessionId: 'tempo-session',
      walletSessionJwt: 'jwt.tempo.session',
    }),
  );
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
  return createWarmSessionEnvelopeFixture({
    walletId: evmRecord.walletId,
    ecdsa: {
      evm: createReadyPasskeyWarmSessionEcdsaCapability({
        record: evmRecord,
        prfClaim: { remainingUses: 3 },
      }),
      tempo: createReadyPasskeyWarmSessionEcdsaCapability({
        record: tempoRecord,
        prfClaim: { remainingUses: 1 },
      }),
    },
  });
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
        walletSessionJwt: record.walletSessionJwt,
      },
      session: {
        ok: true,
        thresholdSessionId: 'evm-session',
        signingGrantId: 'wsess-evm-session',
        jwt: record.walletSessionJwt,
      },
    });
  });

  test('does not reuse persisted record JWT when warm capability auth is missing', () => {
    const envelope = createEnvelope();
    const evmCapability = envelope.capabilities.ecdsa.evm;
    if (evmCapability.state === 'missing') {
      throw new Error('expected a present evm ECDSA capability');
    }
    const record = evmCapability.record;
    // Factory-built capability with a visible corrupting override; conformance is
    // checked where it is passed as WarmSessionEcdsaCapabilityState below.
    const authMissingCapability = {
      ...evmCapability,
      auth: null,
      state: 'auth_missing' as const,
    };

    expect(
      buildReusableEcdsaBootstrapResult({
        record,
        capability: authMissingCapability,
        source: 'login',
      }),
    ).toBeNull();
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
