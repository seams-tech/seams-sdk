import { expect, test } from '@playwright/test';
import type {
  WalletEcdsaPendingSessionActivationRecord,
  WalletEcdsaSignerRecord,
  WalletEd25519SignerRecord,
} from '../../packages/sdk-server-ts/src/core/WalletStore';
import {
  resolveWalletRecoveryKeyManifestV1,
  verifyWalletRecoveryKeyActivationsV1,
} from '../../packages/sdk-server-ts/src/router/domains/passkeyCustody/walletRecoveryKeyManifest';
import {
  buildYaoEd25519WalletSignerRecord,
  ed25519NearPublicKeyFromBytes,
} from '../../packages/sdk-server-ts/src/router/cloudflare/d1/ed25519Yao/d1Ed25519YaoWalletSigner';
import {
  parseRouterAbEcdsaDerivationActivationRefreshRequestV1,
  parseRouterAbEcdsaDerivationActivationRefreshResponseV1,
  parseRouterAbEcdsaDerivationRecoveryRequestV1,
  parseRouterAbEcdsaRegistrationActivationReceiptV1,
  parseRouterAbEcdsaStrictForwardedRegistrationResponseV1,
  type RouterAbEcdsaDerivationRoleEncryptedEnvelopeV1,
} from '../../packages/shared-ts/src/utils/routerAbEcdsaDerivation';
import { walletIdFromString } from '../../packages/shared-ts/src/utils/registrationIntent';
import { createWalletEcdsaSignerRecord } from './helpers/walletRegistrationSigner.fixtures';
import { buildRouterAbEd25519YaoCapabilityReplacementFixture } from './helpers/routerAbEd25519YaoRecoveryRequestScoped.fixtures';
import { D1WalletStore } from '../../packages/sdk-server-ts/src/core/d1WalletStore';
import { cleanupTemporaryD1Database, createTemporaryD1Database } from '../helpers/sqliteD1';

const WALLET_ID = walletIdFromString('alice.testnet');
const CORRELATION_ID = 'wallet-recovery-reservation-1';
const DIGEST_B64U = 'A'.repeat(43);
const X25519_PUBLIC_KEY = `x25519:${'1'.repeat(64)}`;

type RecoveryRegistryState = {
  readonly ed25519Signers: readonly WalletEd25519SignerRecord[];
  readonly ecdsaSigners: readonly WalletEcdsaSignerRecord[];
  readonly pending: readonly WalletEcdsaPendingSessionActivationRecord[];
};

function registry(state: RecoveryRegistryState) {
  return {
    listEd25519SignersForWallet: async () => state.ed25519Signers,
    listEcdsaSignersForWallet: async () => state.ecdsaSigners,
    listEcdsaPendingSessionActivationsForLifecycle: async () => state.pending,
  };
}

function proofBundle() {
  return {
    kind: 'recipient_proof_bundle' as const,
    transcriptDigestB64u: DIGEST_B64U,
    payloadB64u: 'AQ',
  };
}

function roleEnvelope<Role extends 'signer_a' | 'signer_b'>(
  role: Role,
): RouterAbEcdsaDerivationRoleEncryptedEnvelopeV1<Role> {
  return {
    recipient_role: role,
    header_digest: { bytes: new Array<number>(32).fill(0) },
    aad_digest: { bytes: new Array<number>(32).fill(0) },
    ciphertext: { bytes: [1] },
  };
}

function ecdsaRecoveryProofs(
  signer: WalletEcdsaSignerRecord,
  options: { readonly staleActivation?: boolean } = {},
): readonly WalletEcdsaPendingSessionActivationRecord[] {
  const capability = signer.walletKey.publicCapability;
  const nextActivationEpoch = 'root-v2';
  const replacementMaterialActivation = options.staleActivation
    ? capability.material_activation
    : {
        ...capability.material_activation,
        activation_id: 'wallet-recovery-activation-2',
        lifecycle_binding: CORRELATION_ID,
      };
  const lifecycleBase = {
    lifecycle_id: CORRELATION_ID,
    account_id: WALLET_ID,
    session_id: 'threshold-session-recovery-1',
    signer_set_id: capability.signer_set.signer_set_id,
    selected_server_id: capability.signer_set.selected_server.server_id,
  } as const;
  const recoveryRequest = parseRouterAbEcdsaDerivationRecoveryRequestV1({
    context: capability.context,
    lifecycle: {
      ...lifecycleBase,
      work_kind: 'recovery',
      primitive_request_kind: 'recovery',
      root_share_epoch: capability.activation_epoch,
    },
    public_identity: capability.public_identity,
    signer_set: capability.signer_set,
    router_id: capability.router_id,
    client_id: capability.client_id,
    client_ephemeral_public_key: X25519_PUBLIC_KEY,
    recovery_authorization_digest_b64u: DIGEST_B64U,
    recovery_nonce: 'recovery-nonce-1',
    expires_at_ms: Date.now() + 60_000,
    deriver_a_recovery_envelope: roleEnvelope('signer_a'),
    deriver_b_recovery_envelope: roleEnvelope('signer_b'),
  });
  const refreshRequest = parseRouterAbEcdsaDerivationActivationRefreshRequestV1({
    context: capability.context,
    lifecycle: {
      ...lifecycleBase,
      work_kind: 'server_share_refresh',
      primitive_request_kind: 'refresh',
      root_share_epoch: nextActivationEpoch,
    },
    public_identity: capability.public_identity,
    signer_set: capability.signer_set,
    router_id: capability.router_id,
    client_id: capability.client_id,
    signing_worker_ephemeral_public_key: X25519_PUBLIC_KEY,
    refresh_authorization_digest_b64u: DIGEST_B64U,
    refresh_nonce: 'refresh-nonce-1',
    previous_activation_epoch: capability.activation_epoch,
    next_activation_epoch: nextActivationEpoch,
    material_activation: replacementMaterialActivation,
    expires_at_ms: Date.now() + 60_000,
    deriver_a_refresh_envelope: roleEnvelope('signer_a'),
    deriver_b_refresh_envelope: roleEnvelope('signer_b'),
  });
  const recoveryResponse = parseRouterAbEcdsaStrictForwardedRegistrationResponseV1({
    result: 'forwarded',
    response: { bundles: { signerA: proofBundle(), signerB: proofBundle() } },
  });
  const activationReceipt = parseRouterAbEcdsaRegistrationActivationReceiptV1({
    activation_correlation_id: 'ecdsa-recovery-activation-correlation-1',
    activation_request_digest: { bytes: new Array<number>(32).fill(0) },
    server_generation: 'server-generation-2',
    ecdsa_activation: {
      context: capability.context,
      public_identity: capability.public_identity,
      signing_worker: capability.signer_set.selected_server,
      material_activation: replacementMaterialActivation,
      activation_epoch: nextActivationEpoch,
      activation_digest_b64u: DIGEST_B64U,
      activated_at_ms: Date.now(),
    },
    lifecycle_id: CORRELATION_ID,
    transcript_digest: { bytes: new Array<number>(32).fill(0) },
  });
  const refreshResponse = parseRouterAbEcdsaDerivationActivationRefreshResponseV1({
    result: 'forwarded',
    response: { bundles: { signerA: proofBundle(), signerB: proofBundle() } },
    signing_worker_activation: activationReceipt,
  });
  if (refreshResponse.result !== 'forwarded') {
    throw new Error('ECDSA recovery fixture did not build a forwarded refresh');
  }
  const nowMs = Date.now();
  return [
    {
      version: 'wallet_ecdsa_pending_session_activation_v1',
      walletId: WALLET_ID,
      lifecycleId: CORRELATION_ID,
      requestId: recoveryRequest.recovery_nonce,
      publicCapability: capability,
      operation: 'recovery',
      request: recoveryRequest,
      response: recoveryResponse,
      createdAtMs: nowMs,
      expiresAtMs: nowMs + 60_000,
    },
    {
      version: 'wallet_ecdsa_pending_session_activation_v1',
      walletId: WALLET_ID,
      lifecycleId: CORRELATION_ID,
      requestId: refreshRequest.refresh_nonce,
      publicCapability: capability,
      operation: 'refresh',
      request: refreshRequest,
      response: refreshResponse,
      createdAtMs: nowMs,
      expiresAtMs: nowMs + 60_000,
    },
  ];
}

function recoveredEd25519Signer(): WalletEd25519SignerRecord {
  const fixture = buildRouterAbEd25519YaoCapabilityReplacementFixture();
  const capability = fixture.next;
  if (capability.version !== 'wallet_ed25519_yao_recovery_capability_v1') {
    throw new Error('Ed25519 recovery fixture did not build a recovery capability');
  }
  const application = capability.admissionRequest.application_binding;
  const scope = capability.admissionRequest.scope;
  return buildYaoEd25519WalletSignerRecord({
    walletId: walletIdFromString(fixture.walletId),
    nearAccountId: fixture.nearAccountId,
    nearEd25519SigningKeyId: fixture.nearSigningKeyId,
    thresholdSessionId: scope.threshold_session_id,
    signerSlot: application.key_creation_signer_slot,
    publicKey: ed25519NearPublicKeyFromBytes(
      capability.activationResult.public_receipt.registered_public_key,
    ),
    signingWorkerId: fixture.signingWorkerId,
    keyVersion: 'yao-recovery-key-v1',
    participantIds: capability.admissionRequest.participant_ids,
    signingRootId: application.signing_root_id,
    signingRootVersion: scope.root_share_epoch,
    runtimePolicyScope: capability.runtimePolicyScope,
    activeYaoCapability: capability,
    now: Date.now(),
  });
}

test('the server manifest deduplicates EVM chain targets by exact key handle', async () => {
  const base = createWalletEcdsaSignerRecord({ walletId: WALLET_ID, now: Date.now() });
  const secondTarget = createWalletEcdsaSignerRecord({
    walletId: WALLET_ID,
    now: Date.now(),
    keyHandle: base.walletKey.keyHandle,
    walletKeyOverrides: {
      chainTarget: { kind: 'evm', namespace: 'eip155', chainId: 42161 },
      publicCapability: base.walletKey.publicCapability,
    },
  });
  const manifest = await resolveWalletRecoveryKeyManifestV1({
    registry: registry({ ed25519Signers: [], ecdsaSigners: [base, secondTarget], pending: [] }),
    walletId: WALLET_ID,
  });

  expect(manifest.entries).toHaveLength(1);
  expect(manifest.entries[0]).toMatchObject({
    kind: 'evm_family_ecdsa',
    keySetId: `evm_family_ecdsa:${base.walletKey.keyHandle}`,
    chainTargetKeys: [base.chainTargetKey, secondTarget.chainTargetKey].sort(),
  });
});

test('exact ECDSA recovery and refresh receipts admit the server-derived key set', async () => {
  const signer = createWalletEcdsaSignerRecord({ walletId: WALLET_ID, now: Date.now() });
  const verified = await verifyWalletRecoveryKeyActivationsV1({
    registry: registry({
      ed25519Signers: [],
      ecdsaSigners: [signer],
      pending: ecdsaRecoveryProofs(signer),
    }),
    walletId: WALLET_ID,
    recoveryCorrelationId: CORRELATION_ID,
  });

  expect(verified).toEqual({
    kind: 'verified',
    keySetIds: [`evm_family_ecdsa:${signer.walletKey.keyHandle}`],
  });
});

test('missing or stale ECDSA activations cannot consume a recovery code', async () => {
  const signer = createWalletEcdsaSignerRecord({ walletId: WALLET_ID, now: Date.now() });
  const missing = await verifyWalletRecoveryKeyActivationsV1({
    registry: registry({ ed25519Signers: [], ecdsaSigners: [signer], pending: [] }),
    walletId: WALLET_ID,
    recoveryCorrelationId: CORRELATION_ID,
  });
  const stale = await verifyWalletRecoveryKeyActivationsV1({
    registry: registry({
      ed25519Signers: [],
      ecdsaSigners: [signer],
      pending: ecdsaRecoveryProofs(signer, { staleActivation: true }),
    }),
    walletId: WALLET_ID,
    recoveryCorrelationId: CORRELATION_ID,
  });

  expect(missing.kind).toBe('refused');
  expect(stale).toMatchObject({ kind: 'refused' });
});

test('Ed25519 recovery must be the durable capability for this reservation', async () => {
  const signer = recoveredEd25519Signer();
  const correlationId = signer.activeYaoCapability.admissionRequest.scope.lifecycle_id;
  const accepted = await verifyWalletRecoveryKeyActivationsV1({
    registry: registry({ ed25519Signers: [signer], ecdsaSigners: [], pending: [] }),
    walletId: signer.walletId,
    recoveryCorrelationId: correlationId,
  });
  const unrelated = await verifyWalletRecoveryKeyActivationsV1({
    registry: registry({ ed25519Signers: [signer], ecdsaSigners: [], pending: [] }),
    walletId: signer.walletId,
    recoveryCorrelationId: 'another-wallet-recovery',
  });

  expect(accepted).toEqual({
    kind: 'verified',
    keySetIds: [`near_ed25519:${signer.signerId}`],
  });
  expect(unrelated).toMatchObject({ kind: 'refused' });
});

test('D1 queries the exact wallet recovery lifecycle without consuming its receipts', async () => {
  const temporary = createTemporaryD1Database();
  try {
    const store = new D1WalletStore({
      database: temporary.database,
      namespace: 'wallet-recovery-manifest-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
    });
    const signer = createWalletEcdsaSignerRecord({ walletId: WALLET_ID, now: Date.now() });
    const proofs = ecdsaRecoveryProofs(signer);
    await store.putSigner(signer);
    for (const proof of proofs) await store.putEcdsaPendingSessionActivation(proof);

    const first = await store.listEcdsaPendingSessionActivationsForLifecycle({
      walletId: WALLET_ID,
      lifecycleId: CORRELATION_ID,
    });
    const second = await store.listEcdsaPendingSessionActivationsForLifecycle({
      walletId: WALLET_ID,
      lifecycleId: CORRELATION_ID,
    });

    expect(first).toHaveLength(2);
    expect(second).toEqual(first);
    await expect(
      store.listEcdsaPendingSessionActivationsForLifecycle({
        walletId: WALLET_ID,
        lifecycleId: 'another-recovery',
      }),
    ).resolves.toEqual([]);
  } finally {
    cleanupTemporaryD1Database(temporary.tempDir);
  }
});
