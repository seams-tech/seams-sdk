import { expect, test } from '@playwright/test';
import { toAccountId } from '@/core/types/accountIds';
import { toWalletSubjectId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { resolveEvmFamilyEcdsaSigningSelection } from '@/core/signingEngine/flows/signEvmFamily/ecdsaSelection';
import type { EcdsaLaneCandidate } from '@/core/signingEngine/session/identity/laneIdentity';
import type { EvmFamilyEcdsaSigningSelectionDeps } from '@/core/signingEngine/flows/signEvmFamily/ecdsaSelection';
import type { ThresholdEcdsaSessionRecord } from '@/core/signingEngine/session/persistence/records';
import type { ThresholdEcdsaSecp256k1KeyRef } from '@/core/signingEngine/interfaces/signing';
import { buildEvmFamilyEcdsaKeyIdentity } from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';

type DirectEcdsaLaneCandidate = Extract<
  EcdsaLaneCandidate,
  {
    source: 'durable_sealed_record' | 'runtime_session_record' | 'runtime_and_durable' | 'unknown';
  }
>;

const chainTarget = {
  kind: 'evm' as const,
  namespace: 'eip155' as const,
  chainId: 5042002,
  networkSlug: 'arc-testnet',
};

const tempoChainTarget = {
  kind: 'tempo' as const,
  chainId: 42431,
  networkSlug: 'tempo-testnet',
};

function candidate(state: EcdsaLaneCandidate['state']): DirectEcdsaLaneCandidate {
  return {
    kind: 'lane_candidate',
    authMethod: 'passkey',
    curve: 'ecdsa',
    chain: 'evm',
    walletId: toAccountId('restorable.testnet'),
    key: buildEvmFamilyEcdsaKeyIdentity({
      walletId: toAccountId('restorable.testnet'),
      subjectId: toWalletSubjectId('restorable.testnet'),
      rpId: 'example.localhost',
      ecdsaThresholdKeyId: 'ek-restorable',
      signingRootId: 'proj_local:dev',
      signingRootVersion: 'default',
      participantIds: [1, 2],
      thresholdOwnerAddress: `0x${'aa'.repeat(20)}`,
    }),
    chainTarget,
    walletSigningSessionId: 'wsess-restorable',
    thresholdSessionId: 'tsess-restorable',
    state,
    remainingUses: null,
    expiresAtMs: null,
    updatedAtMs: Date.now(),
    source: 'durable_sealed_record',
  };
}

function sharedTempoCandidate(): EcdsaLaneCandidate {
  const base = candidate('deferred');
  return {
    ...base,
    chain: 'tempo',
    chainTarget: tempoChainTarget,
    source: 'evm_family_shared_key',
    sourceChainTarget: chainTarget,
  };
}

function emailOtpCandidate(state: EcdsaLaneCandidate['state']): EcdsaLaneCandidate {
  return {
    ...candidate(state),
    authMethod: 'email_otp',
    source: 'runtime_session_record',
  };
}

function emailOtpSharedTempoCandidate(): EcdsaLaneCandidate {
  return {
    ...sharedTempoCandidate(),
    authMethod: 'email_otp',
  };
}

function selectionDeps(): EvmFamilyEcdsaSigningSelectionDeps {
  const missing = () => {
    throw new Error('missing exact material');
  };
  return {
    indexedDB: {} as EvmFamilyEcdsaSigningSelectionDeps['indexedDB'],
    getEmailOtpThresholdEcdsaKeyRefForSigning: missing,
    getEmailOtpThresholdEcdsaSessionRecordForSigning: missing,
    getPasskeyThresholdEcdsaKeyRefForSigning: missing,
    getPasskeyThresholdEcdsaSessionRecordForSigning: missing,
    listThresholdEcdsaSessionRecordsForSigning: () => [],
    listThresholdEcdsaKeyRefsForSigning: () => [],
    getThresholdEcdsaSessionRecordByKey: () => null,
    getThresholdEcdsaKeyRefByKey: () => null,
  };
}

function recordForChainTarget(
  input: EcdsaLaneCandidate,
  materialChainTarget: typeof chainTarget | typeof tempoChainTarget,
): ThresholdEcdsaSessionRecord {
  return {
    walletId: input.walletId,
    subjectId: input.key.subjectId,
    rpId: input.key.rpId,
    chainTarget: materialChainTarget,
    relayerUrl: 'https://relay.example',
    ecdsaThresholdKeyId:
      input.key.ecdsaThresholdKeyId as ThresholdEcdsaSessionRecord['ecdsaThresholdKeyId'],
    signingRootId: input.key.signingRootId,
    signingRootVersion: input.key.signingRootVersion,
    relayerKeyId: 'rk-restorable',
    clientVerifyingShareB64u: 'client-verifying-share',
    participantIds: [1, 2],
    ethereumAddress: `0x${'aa'.repeat(20)}`,
    thresholdSessionKind: 'jwt',
    thresholdSessionId: input.thresholdSessionId,
    walletSigningSessionId: input.walletSigningSessionId,
    thresholdSessionAuthToken: 'threshold-session-token',
    expiresAtMs: Date.now() + 60_000,
    remainingUses: input.state === 'exhausted' ? 0 : 1,
    updatedAtMs: Date.now(),
    source: 'registration',
  };
}

function emailOtpRecordForChainTarget(
  input: EcdsaLaneCandidate,
  materialChainTarget: typeof chainTarget | typeof tempoChainTarget,
): ThresholdEcdsaSessionRecord {
  return {
    ...recordForChainTarget(input, materialChainTarget),
    source: 'email_otp',
    emailOtpAuthContext: {
      policy: 'session',
      retention: 'session',
      reason: 'login',
      authMethod: 'email_otp',
    },
    clientAdditiveShareHandle: {
      kind: 'email_otp_worker_session',
      sessionId: 'email-otp-worker-session',
    },
  };
}

function keyRefForChainTarget(
  input: EcdsaLaneCandidate,
  materialChainTarget: typeof chainTarget | typeof tempoChainTarget,
): ThresholdEcdsaSecp256k1KeyRef {
  return {
    type: 'threshold-ecdsa-secp256k1',
    userId: String(input.walletId),
    subjectId: input.key.subjectId,
    chainTarget: materialChainTarget,
    relayerUrl: 'https://relay.example',
    ecdsaThresholdKeyId:
      input.key.ecdsaThresholdKeyId as ThresholdEcdsaSecp256k1KeyRef['ecdsaThresholdKeyId'],
    signingRootId: input.key.signingRootId,
    signingRootVersion: input.key.signingRootVersion,
    backendBinding: {
      relayerKeyId: 'rk-restorable',
      clientVerifyingShareB64u: 'client-verifying-share',
    },
    participantIds: [1, 2],
    ethereumAddress: `0x${'aa'.repeat(20)}`,
    thresholdSessionKind: 'jwt',
    thresholdSessionAuthToken: 'threshold-session-token',
    thresholdSessionId: input.thresholdSessionId,
    walletSigningSessionId: input.walletSigningSessionId,
  };
}

function emailOtpKeyRefForChainTarget(
  input: EcdsaLaneCandidate,
  materialChainTarget: typeof chainTarget | typeof tempoChainTarget,
): ThresholdEcdsaSecp256k1KeyRef {
  const keyRef = keyRefForChainTarget(input, materialChainTarget);
  return {
    ...keyRef,
    backendBinding: {
      relayerKeyId: 'rk-restorable',
      clientVerifyingShareB64u: 'client-verifying-share',
      clientAdditiveShareHandle: {
        kind: 'email_otp_worker_session',
        sessionId: 'email-otp-worker-session',
      },
    },
  };
}

function selectionDepsWithExactMaterial(
  input: EcdsaLaneCandidate,
): EvmFamilyEcdsaSigningSelectionDeps {
  const deps = selectionDeps();
  return {
    ...deps,
    getThresholdEcdsaSessionRecordByKey: () => recordForChainTarget(input, input.chainTarget),
    getThresholdEcdsaKeyRefByKey: () => ({
      source: 'registration',
      keyRef: keyRefForChainTarget(input, input.chainTarget),
    }),
  };
}

test.describe('ECDSA restorable lane selection', () => {
  test('routes restorable passkey lanes without hot material through reauth', async () => {
    const selection = await resolveEvmFamilyEcdsaSigningSelection({
      deps: selectionDeps(),
      walletId: 'restorable.testnet',
      subjectId: toWalletSubjectId('restorable.testnet'),
      chain: 'evm',
      chainTarget,
      senderSignatureAlgorithm: 'webauthnP256',
      authMethod: 'passkey',
      laneCandidate: candidate('restorable'),
    });

    expect(selection.kind).toBe('reauth_required');
    expect(selection.kind === 'reauth_required' ? selection.reason : '').toBe(
      'missing_hot_material',
    );
  });

  test('keeps ready lanes strict when exact material is missing', async () => {
    const selection = await resolveEvmFamilyEcdsaSigningSelection({
      deps: selectionDeps(),
      walletId: 'restorable.testnet',
      subjectId: toWalletSubjectId('restorable.testnet'),
      chain: 'evm',
      chainTarget,
      senderSignatureAlgorithm: 'webauthnP256',
      authMethod: 'passkey',
      laneCandidate: candidate('ready'),
    });

    expect(selection.kind).toBe('missing_material');
  });

  test('routes exhausted passkey lanes through reauth without marking stale material ready', async () => {
    const exhaustedCandidate = candidate('exhausted');
    const selection = await resolveEvmFamilyEcdsaSigningSelection({
      deps: selectionDepsWithExactMaterial(exhaustedCandidate),
      walletId: 'restorable.testnet',
      subjectId: toWalletSubjectId('restorable.testnet'),
      chain: 'evm',
      chainTarget,
      senderSignatureAlgorithm: 'webauthnP256',
      authMethod: 'passkey',
      laneCandidate: exhaustedCandidate,
    });

    expect(selection.kind).toBe('reauth_required');
    if (selection.kind !== 'reauth_required') return;
    expect(selection.reason).toBe('exhausted');
    expect(selection.material.kind).toBe('missing');
  });

  test('uses source material for deferred shared EVM-family lanes without passkey reauth', async () => {
    const tempoCandidate = sharedTempoCandidate();
    const sourceRecord = recordForChainTarget(tempoCandidate, chainTarget);
    const sourceKeyRef = keyRefForChainTarget(tempoCandidate, chainTarget);
    const deps: EvmFamilyEcdsaSigningSelectionDeps = {
      ...selectionDeps(),
      getPasskeyThresholdEcdsaSessionRecordForSigning: ({
        chainTarget: requestedChainTarget,
        source,
      }) => {
        if (
          source === 'registration' &&
          requestedChainTarget.kind === chainTarget.kind &&
          requestedChainTarget.chainId === chainTarget.chainId
        ) {
          return sourceRecord;
        }
        throw new Error('missing source record');
      },
      getPasskeyThresholdEcdsaKeyRefForSigning: ({
        chainTarget: requestedChainTarget,
        source,
      }) => {
        if (
          source === 'registration' &&
          requestedChainTarget.kind === chainTarget.kind &&
          requestedChainTarget.chainId === chainTarget.chainId
        ) {
          return sourceKeyRef;
        }
        throw new Error('missing source key ref');
      },
    };

    const selection = await resolveEvmFamilyEcdsaSigningSelection({
      deps,
      walletId: 'restorable.testnet',
      subjectId: toWalletSubjectId('restorable.testnet'),
      chain: 'tempo',
      chainTarget: tempoChainTarget,
      senderSignatureAlgorithm: 'webauthnP256',
      authMethod: 'passkey',
      laneCandidate: tempoCandidate,
    });

    expect(selection.kind).toBe('ready');
    if (selection.kind !== 'ready') return;
    expect(selection.lane.chainTarget).toEqual(tempoChainTarget);
    expect(selection.material.chainTarget).toEqual(tempoChainTarget);
    expect(selection.material.record.chainTarget).toEqual(chainTarget);
    expect(selection.material.keyRef.chainTarget).toEqual(chainTarget);
    expect(selection.diagnostics.selectedLaneCandidate).toMatchObject({
      source: 'evm_family_shared_key',
      sourceChainTarget: chainTarget,
    });
  });

  test('keeps Email OTP exact material out of passkey diagnostics selection', async () => {
    const input = emailOtpCandidate('ready');
    const emailOtpRecord = emailOtpRecordForChainTarget(input, input.chainTarget);
    const emailOtpKeyRef = emailOtpKeyRefForChainTarget(input, input.chainTarget);
    const deps: EvmFamilyEcdsaSigningSelectionDeps = {
      ...selectionDeps(),
      getThresholdEcdsaSessionRecordByKey: () => emailOtpRecord,
      getThresholdEcdsaKeyRefByKey: () => ({
        source: 'email_otp',
        keyRef: emailOtpKeyRef,
      }),
      getEmailOtpThresholdEcdsaSessionRecordForSigning: () => emailOtpRecord,
      getEmailOtpThresholdEcdsaKeyRefForSigning: () => emailOtpKeyRef,
    };

    const selection = await resolveEvmFamilyEcdsaSigningSelection({
      deps,
      walletId: 'restorable.testnet',
      subjectId: toWalletSubjectId('restorable.testnet'),
      chain: 'evm',
      chainTarget,
      senderSignatureAlgorithm: 'secp256k1',
      authMethod: 'email_otp',
      laneCandidate: input,
    });

    expect(selection.kind).toBe('ready');
    if (selection.kind !== 'ready') return;
    expect(selection.authMethod).toBe('email_otp');
    expect(selection.source).toBe('email_otp');
    expect(selection.material.record.source).toBe('email_otp');
    expect(selection.diagnostics.selectedPasskeyMaterial).toEqual({ present: false });
    expect(selection.diagnostics.visibleEmailOtpMaterial).toMatchObject({
      present: true,
      authMethod: 'email_otp',
      source: 'email_otp',
    });
  });

  test('uses Email OTP source material for shared Tempo ECDSA lanes', async () => {
    const input = emailOtpSharedTempoCandidate();
    const emailOtpRecord = emailOtpRecordForChainTarget(input, chainTarget);
    const emailOtpKeyRef = emailOtpKeyRefForChainTarget(input, chainTarget);
    const deps: EvmFamilyEcdsaSigningSelectionDeps = {
      ...selectionDeps(),
      getEmailOtpThresholdEcdsaSessionRecordForSigning: ({
        chainTarget: requestedChainTarget,
      }) => {
        if (
          requestedChainTarget.kind === chainTarget.kind &&
          requestedChainTarget.chainId === chainTarget.chainId
        ) {
          return emailOtpRecord;
        }
        throw new Error('missing Email OTP source record');
      },
      getEmailOtpThresholdEcdsaKeyRefForSigning: ({ chainTarget: requestedChainTarget }) => {
        if (
          requestedChainTarget.kind === chainTarget.kind &&
          requestedChainTarget.chainId === chainTarget.chainId
        ) {
          return emailOtpKeyRef;
        }
        throw new Error('missing Email OTP source key ref');
      },
    };

    const selection = await resolveEvmFamilyEcdsaSigningSelection({
      deps,
      walletId: 'restorable.testnet',
      subjectId: toWalletSubjectId('restorable.testnet'),
      chain: 'tempo',
      chainTarget: tempoChainTarget,
      senderSignatureAlgorithm: 'secp256k1',
      authMethod: 'email_otp',
      laneCandidate: input,
    });

    expect(selection.kind).toBe('ready');
    if (selection.kind !== 'ready') return;
    expect(selection.authMethod).toBe('email_otp');
    expect(selection.lane.chainTarget).toEqual(tempoChainTarget);
    expect(selection.material.chainTarget).toEqual(tempoChainTarget);
    expect(selection.material.record.chainTarget).toEqual(chainTarget);
    expect(selection.material.keyRef.chainTarget).toEqual(chainTarget);
    expect(selection.diagnostics.selectedPasskeyMaterial).toEqual({ present: false });
  });
});
