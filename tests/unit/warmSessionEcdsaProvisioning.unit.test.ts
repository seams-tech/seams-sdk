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
  createThresholdEcdsaBootstrapFixture,
  testEcdsaChainTarget,
} from './helpers/warmSessionStore.fixtures';

const EVM_CHAIN_TARGET = testEcdsaChainTarget('evm');
const TEMPO_CHAIN_TARGET = testEcdsaChainTarget('tempo');

function createEnvelope(): WarmSessionEnvelope {
  const evmBootstrap = createThresholdEcdsaBootstrapFixture({
    nearAccountId: 'provisioning.testnet',
    chain: 'evm',
    ecdsaThresholdKeyId: 'ek-evm',
    sessionId: 'evm-session',
    sessionAuthToken: 'jwt:evm-session',
  });
  const tempoBootstrap = createThresholdEcdsaBootstrapFixture({
    nearAccountId: 'provisioning.testnet',
    chain: 'tempo',
    ecdsaThresholdKeyId: 'ek-tempo',
    sessionId: 'tempo-session',
    sessionAuthToken: 'jwt:tempo-session',
  });
  const envelope: WarmSessionEnvelope = {
    walletId: 'provisioning.testnet' as any,
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
          record: {
            walletId: 'provisioning.testnet',
            subjectId: evmBootstrap.thresholdEcdsaKeyRef.subjectId,
            chainTarget: EVM_CHAIN_TARGET,
            ecdsaThresholdKeyId: 'ek-evm',
            signingRootId: evmBootstrap.thresholdEcdsaKeyRef.signingRootId,
            signingRootVersion: evmBootstrap.thresholdEcdsaKeyRef.signingRootVersion,
            thresholdSessionId: 'evm-session',
            walletSigningSessionId: evmBootstrap.session.walletSigningSessionId,
            thresholdSessionKind: 'jwt',
            relayerUrl: evmBootstrap.thresholdEcdsaKeyRef.relayerUrl,
            relayerKeyId: evmBootstrap.keygen.relayerKeyId,
            clientVerifyingShareB64u: evmBootstrap.keygen.clientVerifyingShareB64u,
            clientAdditiveShare32B64u:
              evmBootstrap.thresholdEcdsaKeyRef.backendBinding?.clientAdditiveShare32B64u,
            participantIds: [1, 2],
          } as any,
          key: null as any,
          lane: null as any,
          auth: {
            capability: 'ecdsa',
            record: {} as any,
            thresholdSessionAuthToken: 'jwt:evm-session',
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
          record: {
            walletId: 'provisioning.testnet',
            subjectId: tempoBootstrap.thresholdEcdsaKeyRef.subjectId,
            chainTarget: TEMPO_CHAIN_TARGET,
            ecdsaThresholdKeyId: 'ek-tempo',
            signingRootId: tempoBootstrap.thresholdEcdsaKeyRef.signingRootId,
            signingRootVersion: tempoBootstrap.thresholdEcdsaKeyRef.signingRootVersion,
            thresholdSessionId: 'tempo-session',
            walletSigningSessionId: tempoBootstrap.session.walletSigningSessionId,
            thresholdSessionKind: 'jwt',
            relayerUrl: tempoBootstrap.thresholdEcdsaKeyRef.relayerUrl,
            relayerKeyId: tempoBootstrap.keygen.relayerKeyId,
            clientVerifyingShareB64u: tempoBootstrap.keygen.clientVerifyingShareB64u,
            clientAdditiveShare32B64u:
              tempoBootstrap.thresholdEcdsaKeyRef.backendBinding?.clientAdditiveShare32B64u,
            participantIds: [1, 2],
          } as any,
          key: null as any,
          lane: null as any,
          auth: {
            capability: 'ecdsa',
            record: {} as any,
            thresholdSessionAuthToken: 'jwt:tempo-session',
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
  envelope.capabilities.ecdsa.evm.auth!.record = envelope.capabilities.ecdsa.evm.record!;
  envelope.capabilities.ecdsa.tempo.auth!.record = envelope.capabilities.ecdsa.tempo.record!;
  const evmRecord = envelope.capabilities.ecdsa.evm.record!;
  const evmKey = {
    walletId: evmRecord.walletId,
    subjectId: evmRecord.subjectId,
    rpId: 'example.localhost',
    keyScope: 'evm-family',
    ecdsaThresholdKeyId: evmRecord.ecdsaThresholdKeyId,
    signingRootId: evmRecord.signingRootId,
    signingRootVersion: evmRecord.signingRootVersion,
    participantIds: [1, 2],
    thresholdOwnerAddress: `0x${'11'.repeat(20)}`,
  };
  envelope.capabilities.ecdsa.evm.key = evmKey as any;
  envelope.capabilities.ecdsa.evm.lane = {
    ...selectedEcdsaLane({
      key: evmKey as any,
      walletId: evmRecord.walletId as any,
      authMethod: 'passkey',
      walletSigningSessionId: evmRecord.walletSigningSessionId,
      thresholdSessionId: evmRecord.thresholdSessionId,
      subjectId: evmRecord.subjectId,
      chainTarget: evmRecord.chainTarget,
      ecdsaThresholdKeyId: evmRecord.ecdsaThresholdKeyId,
      signingRootId: evmRecord.signingRootId,
      signingRootVersion: evmRecord.signingRootVersion,
    }),
    key: evmKey,
  } as any;

  const tempoRecord = envelope.capabilities.ecdsa.tempo.record!;
  const tempoKey = {
    walletId: tempoRecord.walletId,
    subjectId: tempoRecord.subjectId,
    rpId: 'example.localhost',
    keyScope: 'evm-family',
    ecdsaThresholdKeyId: tempoRecord.ecdsaThresholdKeyId,
    signingRootId: tempoRecord.signingRootId,
    signingRootVersion: tempoRecord.signingRootVersion,
    participantIds: [1, 2],
    thresholdOwnerAddress: `0x${'11'.repeat(20)}`,
  };
  envelope.capabilities.ecdsa.tempo.key = tempoKey as any;
  envelope.capabilities.ecdsa.tempo.lane = {
    ...selectedEcdsaLane({
      key: tempoKey as any,
      walletId: tempoRecord.walletId as any,
      authMethod: 'passkey',
      walletSigningSessionId: tempoRecord.walletSigningSessionId,
      thresholdSessionId: tempoRecord.thresholdSessionId,
      subjectId: tempoRecord.subjectId,
      chainTarget: tempoRecord.chainTarget,
      ecdsaThresholdKeyId: tempoRecord.ecdsaThresholdKeyId,
      signingRootId: tempoRecord.signingRootId,
      signingRootVersion: tempoRecord.signingRootVersion,
    }),
    key: tempoKey,
  } as any;
  return envelope;
}

test.describe('warmSessionEcdsaProvisioning', () => {
  test('matches only the ready capability with the same session and threshold key id', () => {
    const envelope = createEnvelope();
    const keyRef = createThresholdEcdsaBootstrapFixture({
      nearAccountId: 'provisioning.testnet',
      chain: 'evm',
      ecdsaThresholdKeyId: 'ek-evm',
      sessionId: 'evm-session',
      sessionAuthToken: 'jwt:evm-session',
    }).thresholdEcdsaKeyRef;

    expect(
      getMatchingReadyEcdsaCapability({
        warmSession: envelope,
        chainTarget: EVM_CHAIN_TARGET,
        keyRef,
        usesNeeded: 2,
      }),
    ).toBe(envelope.capabilities.ecdsa.evm);

    expect(
      getMatchingReadyEcdsaCapability({
        warmSession: envelope,
        chainTarget: EVM_CHAIN_TARGET,
        keyRef: {
          ...keyRef,
          thresholdSessionId: 'wrong-session',
        },
        usesNeeded: 1,
      }),
    ).toBeNull();
  });

  test('builds a reusable bootstrap result from a ready ECDSA capability', () => {
    const envelope = createEnvelope();
    const keyRef = createThresholdEcdsaBootstrapFixture({
      nearAccountId: 'provisioning.testnet',
      chain: 'evm',
      ecdsaThresholdKeyId: 'ek-evm',
      sessionId: 'evm-session',
      sessionAuthToken: 'jwt:evm-session',
    }).thresholdEcdsaKeyRef;

    expect(
      buildReusableEcdsaBootstrapResult({
        keyRef,
        capability: envelope.capabilities.ecdsa.evm,
        source: 'login',
      }),
    ).toMatchObject({
      thresholdEcdsaKeyRef: {
        ecdsaThresholdKeyId: 'ek-evm',
        thresholdSessionId: 'evm-session',
        thresholdSessionAuthToken: 'jwt:evm-session',
      },
      session: {
        ok: true,
        sessionId: 'evm-session',
        walletSigningSessionId: 'wsess-evm-session',
        jwt: 'jwt:evm-session',
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
