import { expect, test } from '@playwright/test';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { toEvmFamilyEcdsaKeyHandle } from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import {
  listThresholdEcdsaRuntimeLanesForWallet,
  upsertThresholdEcdsaSessionFact,
  type ThresholdEcdsaSessionStoreDeps,
} from '@/core/signingEngine/session/persistence/records';
import type { ThresholdEcdsaExplicitKeyExportActivationResult } from '@/core/signingEngine/threshold/ecdsa/activation';
import { createThresholdEcdsaBootstrapFixture } from './helpers/ecdsaBootstrap.fixtures';

const WALLET_ID = toWalletId('ephemeral-export-isolation.testnet');

function requireString(value: unknown, label: string): string {
  const normalized = String(value ?? '').trim();
  if (!normalized) throw new Error(`${label} is required by the test fixture`);
  return normalized;
}

function explicitExportResultFixture(): ThresholdEcdsaExplicitKeyExportActivationResult {
  const bootstrap = createThresholdEcdsaBootstrapFixture({
    nearAccountId: WALLET_ID,
    chain: 'evm',
    sessionId: 'ephemeral-export-session',
    signingGrantId: 'ephemeral-export-grant',
    remainingUses: 1,
  });
  const keyRef = bootstrap.thresholdEcdsaKeyRef;
  const readyRecord = keyRef.backendBinding?.ecdsaRoleLocalReadyRecord;
  if (!readyRecord) throw new Error('role-local ready record is required by the test fixture');
  return {
    kind: 'explicit_key_export_ecdsa_activation_result',
    purpose: 'explicit_key_export',
    material: {
      walletId: WALLET_ID,
      evmFamilySigningKeySlotId: requireString(
        bootstrap.keygen.evmFamilySigningKeySlotId,
        'evmFamilySigningKeySlotId',
      ),
      chainTarget: keyRef.chainTarget,
      relayerUrl: requireString(keyRef.relayerUrl, 'relayerUrl'),
      keyHandle: toEvmFamilyEcdsaKeyHandle(requireString(keyRef.keyHandle, 'keyHandle')),
      ecdsaThresholdKeyId: requireString(keyRef.ecdsaThresholdKeyId, 'ecdsaThresholdKeyId'),
      relayerKeyId: requireString(keyRef.backendBinding?.relayerKeyId, 'relayerKeyId'),
      clientVerifyingShareB64u: requireString(
        keyRef.backendBinding?.clientVerifyingShareB64u,
        'clientVerifyingShareB64u',
      ),
      participantIds: [...keyRef.participantIds],
      thresholdEcdsaPublicKeyB64u: requireString(
        keyRef.thresholdEcdsaPublicKeyB64u,
        'thresholdEcdsaPublicKeyB64u',
      ),
      ethereumAddress: requireString(keyRef.ethereumAddress, 'ethereumAddress'),
      relayerVerifyingShareB64u: requireString(
        keyRef.relayerVerifyingShareB64u,
        'relayerVerifyingShareB64u',
      ),
      thresholdSessionId: requireString(
        bootstrap.session.thresholdSessionId,
        'thresholdSessionId',
      ),
      signingGrantId: requireString(bootstrap.session.signingGrantId, 'signingGrantId'),
      expiresAtMs: bootstrap.session.expiresAtMs,
      remainingUses: bootstrap.session.remainingUses,
      walletSessionJwt: requireString(bootstrap.session.jwt, 'walletSessionJwt'),
      ecdsaRoleLocalReadyRecord: readyRecord,
    },
    passkeyPrfFirstB64u: 'ephemeral-export-prf-first',
    passkeyCredentialIdB64u: requireString(
      bootstrap.passkeyCredentialIdB64u,
      'passkeyCredentialIdB64u',
    ),
  };
}

function persistenceError(args: {
  store: ThresholdEcdsaSessionStoreDeps;
  value: unknown;
}): unknown {
  try {
    upsertThresholdEcdsaSessionFact(args.store, args.value);
    return null;
  } catch (error: unknown) {
    return error;
  }
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

test('ephemeral ECDSA export results cannot enter transaction persistence or availability', () => {
  const store: ThresholdEcdsaSessionStoreDeps = {
    recordsByLane: new Map(),
    exportArtifactsByLane: new Map(),
  };
  const exportResult = explicitExportResultFixture();

  const error = persistenceError({ store, value: exportResult });

  expect(errorMessage(error)).toContain('expected transaction_signing purpose');
  expect(store.recordsByLane.size).toBe(0);
  expect(listThresholdEcdsaRuntimeLanesForWallet(store, WALLET_ID)).toEqual([]);
});
