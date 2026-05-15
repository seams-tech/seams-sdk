import { expect, test } from '@playwright/test';
import { toAccountId } from '@/core/types/accountIds';
import { toWalletSubjectId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { resolveEvmFamilyEcdsaSigningSelection } from '@/core/signingEngine/flows/signEvmFamily/ecdsaSelection';
import type { EcdsaLaneCandidate } from '@/core/signingEngine/session/identity/laneIdentity';
import type { EvmFamilyEcdsaSigningSelectionDeps } from '@/core/signingEngine/flows/signEvmFamily/ecdsaSelection';
import type { ThresholdEcdsaSessionRecord } from '@/core/signingEngine/session/persistence/records';
import type { ThresholdEcdsaSecp256k1KeyRef } from '@/core/signingEngine/interfaces/signing';

const chainTarget = {
  kind: 'evm' as const,
  namespace: 'eip155' as const,
  chainId: 5042002,
  networkSlug: 'arc-testnet',
};

function candidate(state: EcdsaLaneCandidate['state']): EcdsaLaneCandidate {
  return {
    kind: 'lane_candidate',
    authMethod: 'passkey',
    curve: 'ecdsa',
    chain: 'evm',
    walletId: toAccountId('restorable.testnet'),
    subjectId: toWalletSubjectId('restorable.testnet'),
    chainTarget,
    ecdsaThresholdKeyId: 'ek-restorable',
    signingRootId: 'proj_local:dev',
    signingRootVersion: 'default',
    walletSigningSessionId: 'wsess-restorable',
    thresholdSessionId: 'tsess-restorable',
    state,
    remainingUses: null,
    expiresAtMs: null,
    updatedAtMs: Date.now(),
    source: 'durable_sealed_record',
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

function recordForCandidate(input: EcdsaLaneCandidate): ThresholdEcdsaSessionRecord {
  return {
    walletId: input.walletId,
    subjectId: input.subjectId,
    chainTarget: input.chainTarget,
    relayerUrl: 'https://relay.example',
    ecdsaThresholdKeyId:
      input.ecdsaThresholdKeyId as ThresholdEcdsaSessionRecord['ecdsaThresholdKeyId'],
    signingRootId: input.signingRootId,
    signingRootVersion: input.signingRootVersion,
    relayerKeyId: 'rk-restorable',
    clientVerifyingShareB64u: 'client-verifying-share',
    participantIds: [1, 2],
    thresholdSessionKind: 'jwt',
    thresholdSessionId: input.thresholdSessionId,
    walletSigningSessionId: input.walletSigningSessionId,
    thresholdSessionAuthToken: 'threshold-session-token',
    expiresAtMs: Date.now() + 60_000,
    remainingUses: 0,
    updatedAtMs: Date.now(),
    source: 'registration',
  };
}

function keyRefForCandidate(input: EcdsaLaneCandidate): ThresholdEcdsaSecp256k1KeyRef {
  return {
    type: 'threshold-ecdsa-secp256k1',
    userId: String(input.walletId),
    subjectId: input.subjectId,
    chainTarget: input.chainTarget,
    relayerUrl: 'https://relay.example',
    ecdsaThresholdKeyId:
      input.ecdsaThresholdKeyId as ThresholdEcdsaSecp256k1KeyRef['ecdsaThresholdKeyId'],
    signingRootId: input.signingRootId,
    signingRootVersion: input.signingRootVersion,
    backendBinding: {
      relayerKeyId: 'rk-restorable',
      clientVerifyingShareB64u: 'client-verifying-share',
    },
    participantIds: [1, 2],
    thresholdSessionKind: 'jwt',
    thresholdSessionAuthToken: 'threshold-session-token',
    thresholdSessionId: input.thresholdSessionId,
    walletSigningSessionId: input.walletSigningSessionId,
  };
}

function selectionDepsWithExactMaterial(
  input: EcdsaLaneCandidate,
): EvmFamilyEcdsaSigningSelectionDeps {
  const deps = selectionDeps();
  return {
    ...deps,
    getThresholdEcdsaSessionRecordByKey: () => recordForCandidate(input),
    getThresholdEcdsaKeyRefByKey: () => ({
      source: 'registration',
      keyRef: keyRefForCandidate(input),
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

  test('routes exhausted passkey lanes with exact material through reauth', async () => {
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
    expect(selection.material.kind).toBe('ready_material');
  });
});
