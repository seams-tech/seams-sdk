import { expect, test } from '@playwright/test';
import { buildEcdsaOperationStepUpPreparation } from '../../packages/wallet/src/core/signingEngine/threshold/ecdsa/operationStepUp';
import { parseDigestB64u } from '../../packages/shared-ts/src/utils/canonicalPrimitives';
import { parseWalletId } from '../../packages/shared-ts/src/utils/domainIds';
import { routerAbMpcMaterialActivationRefToWire } from '../../packages/shared-ts/src/utils/routerAbNormalSigningIdentity';
import { resolveV2EcdsaCustodySigner } from '../../packages/wallet-server/src/router/transport/fetch/routes/thresholdEcdsa';
import { buildMpcMaterialActivationRefFixture } from './helpers/ecdsaMaterialRef.fixtures';
import { testEcdsaChainTarget } from './helpers/ecdsaChainTarget.fixtures';
import { createWalletEcdsaSignerRecord } from './helpers/walletRegistrationSigner.fixtures';

const walletIdResult = parseWalletId('wallet-v2-step-up-admission');
if (!walletIdResult.ok) throw new Error(walletIdResult.error.message);
const walletId = walletIdResult.value;
const now = Date.now();

function compressedPublicKey(seed: number): string {
  const bytes = Buffer.alloc(33, seed);
  bytes[0] = 2;
  return bytes.toString('base64url');
}

function buildOperation(
  signer: ReturnType<typeof createWalletEcdsaSignerRecord>,
  materialActivation = buildMpcMaterialActivationRefFixture(
    'target-authority',
    String(walletId),
    'signing-worker-registration-signer-fixture',
    signer.walletKey.ecdsaThresholdKeyId,
  ),
  publicIdentity = signer.walletKey.publicCapability.public_identity,
) {
  const capability = signer.walletKey.publicCapability;
  return buildEcdsaOperationStepUpPreparation({
    walletId: String(walletId),
    operationKind: 'evm.export_key',
    operationId: 'ecdsa-v2-export-operation',
    operationDigests: {
      laneDigest: parseDigestB64u(Buffer.alloc(32, 1).toString('base64url')),
      intentDigest: parseDigestB64u(Buffer.alloc(32, 2).toString('base64url')),
      displayDigest: parseDigestB64u(Buffer.alloc(32, 3).toString('base64url')),
    },
    materialActivation,
    normalSigningScope: {
      wallet_id: String(walletId),
      ecdsa_threshold_key_id: signer.walletKey.ecdsaThresholdKeyId,
      signing_root_id: signer.walletKey.signingRootId,
      signing_root_version: signer.walletKey.signingRootVersion,
      context: capability.context,
      public_identity: publicIdentity,
      material_activation: routerAbMpcMaterialActivationRefToWire(materialActivation),
      signing_worker: capability.signer_set.selected_server,
      activation_epoch: capability.activation_epoch,
    },
    keyHandle: signer.walletKey.keyHandle,
    relayerKeyId: signer.walletKey.relayerKeyId,
    participantIds: signer.walletKey.participantIds,
    expiresAtMs: now + 60_000,
  });
}

test('V2 ECDSA step-up resolves one custody identity across chain aliases for target activation', () => {
  const tempoAlias = createWalletEcdsaSignerRecord({
    walletId,
    now,
    walletKeyOverrides: { chainTarget: testEcdsaChainTarget('tempo') },
  });
  const evmAlias = createWalletEcdsaSignerRecord({ walletId, now });
  const targetActivation = buildMpcMaterialActivationRefFixture(
    'target-authority',
    String(walletId),
    'signing-worker-registration-signer-fixture',
    evmAlias.walletKey.ecdsaThresholdKeyId,
  );
  const operation = buildOperation(evmAlias, targetActivation, {
    ...evmAlias.walletKey.publicCapability.public_identity,
    derivation_client_share_public_key33_b64u: compressedPublicKey(9),
    server_public_key33_b64u: compressedPublicKey(10),
  });

  const resolved = resolveV2EcdsaCustodySigner({
    continuity: [evmAlias, tempoAlias],
    walletId: String(walletId),
    admittedThresholdPublicKey33B64u: evmAlias.walletKey.thresholdEcdsaPublicKeyB64u,
    admittedEvmAddress: evmAlias.walletKey.thresholdOwnerAddress,
    operation,
  });

  expect(operation.material_activation.activation_id).not.toBe(
    evmAlias.walletKey.publicCapability.material_activation.activation_id,
  );
  expect(resolved).toBe(evmAlias);
});

test('V2 ECDSA step-up rejects conflicting topology among matching chain aliases', () => {
  const evmAlias = createWalletEcdsaSignerRecord({ walletId, now });
  const conflictingAlias = createWalletEcdsaSignerRecord({
    walletId,
    now,
    walletKeyOverrides: {
      chainTarget: testEcdsaChainTarget('tempo'),
      publicCapability: {
        ...evmAlias.walletKey.publicCapability,
        router_id: 'conflicting-router-id',
      },
    },
  });
  const operation = buildOperation(evmAlias);

  const resolved = resolveV2EcdsaCustodySigner({
    continuity: [evmAlias, conflictingAlias],
    walletId: String(walletId),
    admittedThresholdPublicKey33B64u: evmAlias.walletKey.thresholdEcdsaPublicKeyB64u,
    admittedEvmAddress: evmAlias.walletKey.thresholdOwnerAddress,
    operation,
  });

  expect(resolved).toBeNull();
});
