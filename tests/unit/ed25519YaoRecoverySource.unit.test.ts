import { expect, test } from '@playwright/test';
import { readFileSync } from 'node:fs';
import type { AccountKeyMaterialStorePort } from '../../packages/wallet/src/core/indexedDB/accountKeyMaterial';
import type {
  KeyMaterialKind,
  KeyMaterialRecord,
} from '../../packages/wallet/src/core/indexedDB/keyMaterial.types';
import {
  openEd25519YaoRecoverySourceV1,
  sealEd25519YaoRecoverySourceV1,
} from '../../packages/wallet/src/core/signingEngine/session/passkey/ed25519YaoRecoverySource';
import {
  buildPreparedNearEd25519YaoRecoveryJournalV1,
  finalizeCancelledPromotedNearEd25519YaoRecoveryV1,
  finalizePromotionCommittedNearEd25519YaoRecoveryV1,
  parseNearEd25519YaoRecoveryCommitJournalV1,
  persistPreparedNearEd25519YaoRecoveryJournalV1,
  persistPromotionCommittedNearEd25519YaoRecoveryV1,
  readNearEd25519YaoRecoveryJournalV1,
  requestCancelNearEd25519YaoRecoveryV1,
  type NearEd25519YaoRecoveryJournalStorePort,
} from '../../packages/wallet/src/core/signingEngine/session/passkey/ed25519YaoRecoveryJournal';
import {
  createRouterAbEd25519YaoActivationEntropyV1,
  RouterAbEd25519YaoClientV1,
  zeroizeRouterAbEd25519YaoActivationEntropyV1,
  type RouterAbEd25519YaoRecoveryTransportRequestV1,
  type RouterAbEd25519YaoRecoveryTransportV1,
  type RouterAbEd25519YaoRegistrationTransportResultV1,
} from '../../packages/wallet/src/core/signingEngine/threshold/ed25519/yaoClient';
import { toAccountId } from '../../packages/wallet/src/core/types/accountIds';
import { parseMpcMaterialOwnerRef } from '@shared/utils/domainIds';
import {
  parseRouterAbEd25519YaoRecoveryAdmissionRequestV1,
  parseRouterAbEd25519YaoRecoveryActivationReceiptV1,
  type RouterAbEd25519YaoRecoveryAdmissionRequestV1,
} from '@shared/utils/routerAbEd25519Yao';
import { parseWalletAuthAuthorityRef } from '@shared/utils/walletAuthAuthority';
import { buildActiveClientKeyMaterialRecord } from './helpers/ed25519YaoRecoverySource.fixtures';

class MemoryKeyMaterialStore implements AccountKeyMaterialStorePort {
  record: KeyMaterialRecord | null = null;

  async getKeyMaterial(
    profileId: string,
    signerSlot: number,
    chainIdKey: string,
    keyKind: KeyMaterialKind,
  ): Promise<KeyMaterialRecord | null> {
    const record = this.record;
    if (
      !record ||
      record.profileId !== profileId ||
      record.signerSlot !== signerSlot ||
      record.chainIdKey !== chainIdKey ||
      record.keyKind !== keyKind
    ) {
      return null;
    }
    return record;
  }

  async storeKeyMaterial(input: KeyMaterialRecord): Promise<void> {
    this.record = input;
  }
}

class MemoryRecoveryJournalStore
  extends MemoryKeyMaterialStore
  implements NearEd25519YaoRecoveryJournalStorePort
{
  appState = new Map<string, unknown>();

  async getAppState<T = unknown>(key: string): Promise<T | undefined> {
    return this.appState.get(key) as T | undefined;
  }

  async compareAndSwapAppState(input: {
    key: string;
    expected: unknown | null;
    replacement: unknown;
  }): Promise<boolean> {
    const current = this.appState.get(input.key);
    const matches =
      input.expected === null
        ? current === undefined
        : JSON.stringify(current) === JSON.stringify(input.expected);
    if (!matches) return false;
    this.appState.set(input.key, input.replacement);
    return true;
  }

  async finalizeKeyMaterialRecovery(input: {
    journalKey: string;
    expectedJournal: unknown;
    replacement: KeyMaterialRecord;
  }): Promise<void> {
    if (
      JSON.stringify(this.appState.get(input.journalKey)) !== JSON.stringify(input.expectedJournal)
    ) {
      throw new Error('journal changed');
    }
    this.record = input.replacement;
    this.appState.delete(input.journalKey);
  }
}

class FaultInjectingRecoveryJournalStore extends MemoryRecoveryJournalStore {
  failNextFinalization = true;

  override async finalizeKeyMaterialRecovery(input: {
    journalKey: string;
    expectedJournal: unknown;
    replacement: KeyMaterialRecord;
  }): Promise<void> {
    if (this.failNextFinalization) {
      this.failNextFinalization = false;
      throw new Error('injected atomic finalization crash');
    }
    await super.finalizeKeyMaterialRecovery(input);
  }
}

class AdmittedRecoveryStatusTransport implements RouterAbEd25519YaoRecoveryTransportV1 {
  sawExecute = false;

  constructor(private readonly request: RouterAbEd25519YaoRecoveryAdmissionRequestV1) {}

  async send(
    input: RouterAbEd25519YaoRecoveryTransportRequestV1,
  ): Promise<RouterAbEd25519YaoRegistrationTransportResultV1> {
    if (input.kind === 'recovery_status') {
      return {
        ok: true,
        value: {
          stage: 'admitted',
          lifecycle_id: this.request.scope.lifecycle_id,
          admission_receipt: {
            binding: {
              lifecycle: {
                lifecycle_id: this.request.scope.lifecycle_id,
                work_kind: 'recovery',
                primitive_request_kind: 'recovery',
                root_share_epoch: this.request.scope.root_share_epoch,
                account_id: this.request.scope.account_id,
                session_id: this.request.scope.threshold_session_id,
                signer_set_id: this.request.scope.signer_set_id,
                selected_server_id: this.request.scope.signing_worker_id,
              },
              operation: 'recovery',
              session_id: new Array<number>(32).fill(7),
              stable_key_context_binding: new Array<number>(32).fill(8),
              material_activation: this.request.scope.material_activation,
            },
            keyset: {
              deriver_a_input_public_key: new Array<number>(32).fill(1),
              deriver_b_input_public_key: new Array<number>(32).fill(2),
              signing_worker_recipient_public_key: new Array<number>(32).fill(3),
            },
          },
        },
      };
    }
    if (input.kind === 'recovery_execute') {
      this.sawExecute = true;
      return {
        ok: false,
        code: 'transport_failed',
        status: 503,
        message: 'bounded resume test stops after session reconstruction',
      };
    }
    return {
      ok: false,
      code: 'router_rejected',
      status: 409,
      message: `unexpected ${input.kind}`,
    };
  }
}

function requireAdmissionRequest(
  lifecycleId = 'recovery-source-lifecycle-1',
): RouterAbEd25519YaoRecoveryAdmissionRequestV1 {
  const parsed = parseRouterAbEd25519YaoRecoveryAdmissionRequestV1({
    scope: {
      lifecycle_id: lifecycleId,
      root_share_epoch: 'root-share-epoch-1',
      account_id: 'wallet-recovery-source-1',
      threshold_session_id: 'wallet-session-1',
      signer_set_id: 'signer-set-1',
      signing_worker_id: 'signing-worker-1',
      material_activation: {
        kind: 'mpc_material_activation_ref',
        activation_id: 'recovery-material-activation-1',
        capability: 'recovery-capability-1',
        material_owner: 'wallet-recovery-source-1',
        key_binding: 'recovery-key-binding-1',
        lifecycle_binding: 'recovery-lifecycle-binding-1',
        signing_worker: 'signing-worker-1',
      },
    },
    active_material_activation: {
      kind: 'mpc_material_activation_ref',
      activation_id: 'active-material-activation-1',
      capability: 'recovery-capability-1',
      material_owner: 'wallet-recovery-source-1',
      key_binding: 'recovery-key-binding-1',
      lifecycle_binding: 'active-lifecycle-binding-1',
      signing_worker: 'signing-worker-1',
    },
    application_binding: {
      wallet_id: 'wallet-recovery-source-1',
      near_ed25519_signing_key_id: 'near-signing-key-1',
      signing_root_id: 'project:test',
      key_creation_signer_slot: 1,
    },
    participant_ids: [11, 29],
    active_capability_binding: new Array<number>(32).fill(1),
    replacement_capability_binding: new Array<number>(32).fill(2),
    registered_public_key: new Array<number>(32).fill(3),
  });
  if (!parsed.ok) throw new Error(parsed.message);
  return parsed.value;
}

function requireAuthority() {
  const parsed = parseWalletAuthAuthorityRef({
    kind: 'wallet_auth_authority_ref',
    walletId: 'wallet-recovery-source-1',
    authorityDigest: 'authority-digest-1',
  });
  if (!parsed) throw new Error('authority fixture is invalid');
  return parsed;
}

function requireMaterialOwner() {
  const parsed = parseMpcMaterialOwnerRef('wallet-recovery-source-1');
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

function requireSubstitutedMaterialOwner() {
  const parsed = parseMpcMaterialOwnerRef('wallet-recovery-source-substituted');
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

function substituteReplacementActivation(record: KeyMaterialRecord): KeyMaterialRecord {
  const substituted = structuredClone(record);
  const binding = substituted.payload?.binding;
  if (!binding || typeof binding !== 'object' || Array.isArray(binding)) {
    throw new Error('active-client replacement fixture binding is unavailable');
  }
  const activation = binding.materialActivation;
  if (!activation || typeof activation !== 'object' || Array.isArray(activation)) {
    throw new Error('active-client replacement fixture activation is unavailable');
  }
  activation.activationId = 'substituted-material-activation';
  return substituted;
}

function requirePromotionReceipt(request: RouterAbEd25519YaoRecoveryAdmissionRequestV1) {
  const parsed = parseRouterAbEd25519YaoRecoveryActivationReceiptV1({
    binding: {
      lifecycle: {
        lifecycle_id: request.scope.lifecycle_id,
        work_kind: 'recovery',
        primitive_request_kind: 'recovery',
        root_share_epoch: request.scope.root_share_epoch,
        account_id: request.scope.account_id,
        session_id: request.scope.threshold_session_id,
        signer_set_id: request.scope.signer_set_id,
        selected_server_id: request.scope.signing_worker_id,
      },
      operation: 'recovery',
      session_id: new Array<number>(32).fill(7),
      stable_key_context_binding: new Array<number>(32).fill(8),
      material_activation: request.scope.material_activation,
    },
    public_receipt: {
      transcript: new Array<number>(32).fill(11),
      registered_public_key: request.registered_public_key,
      joined_client_commitment: new Array<number>(32).fill(13),
      joined_signing_worker_commitment: new Array<number>(32).fill(14),
      signing_worker_verifying_share: new Array<number>(32).fill(15),
      state_epoch: 2,
      material_activation: request.scope.material_activation,
    },
    active_capability_binding: request.replacement_capability_binding,
    retired_capability_binding: request.active_capability_binding,
  });
  if (!parsed.ok) throw new Error(parsed.message);
  return parsed.value;
}

test('seals and opens exact recovery entropy and rejects an admission binding mismatch', async () => {
  const store = new MemoryKeyMaterialStore();
  const prf = new Uint8Array(32).fill(17);
  const entropy = createRouterAbEd25519YaoActivationEntropyV1();
  const expected = {
    recipientKeyMaterial: entropy.recipientKeyMaterial.slice(),
    deriverASealSeed: entropy.deriverASealSeed.slice(),
    deriverBSealSeed: entropy.deriverBSealSeed.slice(),
  };
  const identity = {
    walletId: 'wallet-recovery-source-1',
    nearAccountId: toAccountId('wallet-recovery-source.testnet'),
    nearEd25519SigningKeyId: 'near-signing-key-1',
    signerSlot: 1,
    operationalPublicKey: 'ed25519:public-key-1',
    authority: requireAuthority(),
    materialOwner: requireMaterialOwner(),
  };
  const request = requireAdmissionRequest();

  await sealEd25519YaoRecoverySourceV1({
    store,
    identity,
    request,
    ownedPasskeyPrfFirst: prf,
    entropy,
  });
  expect(store.record?.payloadEnvelope).toMatchObject({
    alg: 'aes-256-gcm-hkdf-sha256-prf-v1',
  });
  expect(store.record?.payload).toEqual({
    binding: expect.objectContaining({
      recoveryId: request.scope.lifecycle_id,
      authority: identity.authority,
      materialOwner: identity.materialOwner,
    }),
  });

  const opened = await openEd25519YaoRecoverySourceV1({
    store,
    identity,
    request,
    ownedPasskeyPrfFirst: prf,
  });
  expect(opened).toEqual(expected);
  zeroizeRouterAbEd25519YaoActivationEntropyV1(opened);

  await expect(
    openEd25519YaoRecoverySourceV1({
      store,
      identity,
      request: requireAdmissionRequest('substituted-recovery-lifecycle'),
      ownedPasskeyPrfFirst: prf,
    }),
  ).rejects.toThrow('does not match its exact binding');

  zeroizeRouterAbEd25519YaoActivationEntropyV1(entropy);
  zeroizeRouterAbEd25519YaoActivationEntropyV1(expected);
  prf.fill(0);
});

test('rejects a recovery journal whose outer material owner differs from its activation refs', async () => {
  const store = new MemoryKeyMaterialStore();
  const entropy = createRouterAbEd25519YaoActivationEntropyV1();
  const prf = new Uint8Array(32).fill(18);
  const request = requireAdmissionRequest();
  const identity = {
    walletId: 'wallet-recovery-source-1',
    nearAccountId: toAccountId('wallet-recovery-source.testnet'),
    nearEd25519SigningKeyId: 'near-signing-key-1',
    signerSlot: 1,
    operationalPublicKey: 'ed25519:public-key-1',
    authority: requireAuthority(),
    materialOwner: requireMaterialOwner(),
  };
  const source = await sealEd25519YaoRecoverySourceV1({
    store,
    identity,
    request,
    ownedPasskeyPrfFirst: prf,
    entropy,
  });

  const prepared = buildPreparedNearEd25519YaoRecoveryJournalV1({
    authority: identity.authority,
    materialOwner: identity.materialOwner,
    source,
    request,
  });
  const substituted = {
    ...prepared,
    materialOwner: String(requireSubstitutedMaterialOwner()),
  };

  expect(() => parseNearEd25519YaoRecoveryCommitJournalV1(substituted)).toThrow(
    'Near recovery journal material owner does not match its admission request',
  );

  zeroizeRouterAbEd25519YaoActivationEntropyV1(entropy);
  prf.fill(0);
});

test('validates authoritative admitted status while resuming a recovery session', async () => {
  const request = requireAdmissionRequest();
  const transport = new AdmittedRecoveryStatusTransport(request);
  const ownedSecret32 = new Uint8Array(32).fill(19);
  const entropy = createRouterAbEd25519YaoActivationEntropyV1();
  const client = await RouterAbEd25519YaoClientV1.initialize(
    new Uint8Array(
      readFileSync(
        new URL(
          '../../crates/router-ab-ed25519-yao-client/pkg/router_ab_ed25519_yao_client_bg.wasm',
          import.meta.url,
        ),
      ),
    ),
  );

  const result = await client.resumePreparedRecovery({
    request,
    factor: { kind: 'passkey_prf_first', ownedSecret32 },
    entropy,
    transport,
  });

  expect(result, JSON.stringify(result)).toMatchObject({
    ok: false,
    code: 'invalid_client_result',
    status: 0,
    message: 'Ed25519 Yao registration binding does not match Client facts',
  });
  expect(transport.sawExecute).toBe(false);
  expect(ownedSecret32).toEqual(new Uint8Array(32));
  expect(entropy).toEqual({
    recipientKeyMaterial: new Uint8Array(32),
    deriverASealSeed: new Uint8Array(32),
    deriverBSealSeed: new Uint8Array(32),
  });
});

test('preserves cancellation across reload and atomically finalizes its promoted result', async () => {
  const store = new MemoryRecoveryJournalStore();
  const entropy = createRouterAbEd25519YaoActivationEntropyV1();
  const prf = new Uint8Array(32).fill(23);
  const identity = {
    walletId: 'wallet-recovery-source-1',
    nearAccountId: toAccountId('wallet-recovery-source.testnet'),
    nearEd25519SigningKeyId: 'near-signing-key-1',
    signerSlot: 1,
    operationalPublicKey: 'ed25519:public-key-1',
    authority: requireAuthority(),
    materialOwner: requireMaterialOwner(),
  };
  const request = requireAdmissionRequest();
  const source = await sealEd25519YaoRecoverySourceV1({
    store,
    identity,
    request,
    ownedPasskeyPrfFirst: prf,
    entropy,
  });
  const prepared = buildPreparedNearEd25519YaoRecoveryJournalV1({
    authority: identity.authority,
    materialOwner: identity.materialOwner,
    source,
    request,
  });
  await persistPreparedNearEd25519YaoRecoveryJournalV1({
    store,
    walletId: identity.walletId,
    signerSlot: identity.signerSlot,
    journal: prepared,
  });
  expect(
    await requestCancelNearEd25519YaoRecoveryV1({
      store,
      walletId: identity.walletId,
      signerSlot: identity.signerSlot,
    }),
  ).toBe(true);
  const reloaded = await readNearEd25519YaoRecoveryJournalV1({
    store,
    walletId: identity.walletId,
    signerSlot: identity.signerSlot,
  });
  expect(reloaded).toMatchObject({ kind: 'prepared', disposition: 'cancel_requested' });
  if (!reloaded || reloaded.kind !== 'prepared' || !store.record?.payloadEnvelope) {
    throw new Error('prepared recovery fixture is unavailable');
  }
  const replacement = buildActiveClientKeyMaterialRecord(
    store.record,
    request.scope.material_activation,
  );
  await finalizeCancelledPromotedNearEd25519YaoRecoveryV1({
    store,
    walletId: identity.walletId,
    signerSlot: identity.signerSlot,
    journal: reloaded,
    promotionReceipt: requirePromotionReceipt(request),
    replacement,
  });
  expect(
    await readNearEd25519YaoRecoveryJournalV1({
      store,
      walletId: identity.walletId,
      signerSlot: identity.signerSlot,
    }),
  ).toBeNull();
  expect(store.record?.keyKind).toBe('router_ab_ed25519_yao_active_client_v1');
  zeroizeRouterAbEd25519YaoActivationEntropyV1(entropy);
  prf.fill(0);
});

test('atomically finalizes a promotion-committed journal', async () => {
  const store = new MemoryRecoveryJournalStore();
  const entropy = createRouterAbEd25519YaoActivationEntropyV1();
  const prf = new Uint8Array(32).fill(29);
  const identity = {
    walletId: 'wallet-recovery-source-1',
    nearAccountId: toAccountId('wallet-recovery-source.testnet'),
    nearEd25519SigningKeyId: 'near-signing-key-1',
    signerSlot: 1,
    operationalPublicKey: 'ed25519:public-key-1',
    authority: requireAuthority(),
    materialOwner: requireMaterialOwner(),
  };
  const request = requireAdmissionRequest();
  const source = await sealEd25519YaoRecoverySourceV1({
    store,
    identity,
    request,
    ownedPasskeyPrfFirst: prf,
    entropy,
  });
  const prepared = buildPreparedNearEd25519YaoRecoveryJournalV1({
    authority: identity.authority,
    materialOwner: identity.materialOwner,
    source,
    request,
  });
  await persistPreparedNearEd25519YaoRecoveryJournalV1({
    store,
    walletId: identity.walletId,
    signerSlot: identity.signerSlot,
    journal: prepared,
  });
  if (!store.record?.payloadEnvelope) {
    throw new Error('prepared recovery fixture is unavailable');
  }
  const replacement = buildActiveClientKeyMaterialRecord(
    store.record,
    request.scope.material_activation,
  );
  const committed = await persistPromotionCommittedNearEd25519YaoRecoveryV1({
    store,
    walletId: identity.walletId,
    signerSlot: identity.signerSlot,
    prepared,
    promotionReceipt: requirePromotionReceipt(request),
    replacement,
  });
  await finalizePromotionCommittedNearEd25519YaoRecoveryV1({
    store,
    walletId: identity.walletId,
    signerSlot: identity.signerSlot,
    journal: committed,
  });
  expect(
    await readNearEd25519YaoRecoveryJournalV1({
      store,
      walletId: identity.walletId,
      signerSlot: identity.signerSlot,
    }),
  ).toBeNull();
  expect(store.record?.keyKind).toBe('router_ab_ed25519_yao_active_client_v1');
  zeroizeRouterAbEd25519YaoActivationEntropyV1(entropy);
  prf.fill(0);
});

test('rejects replacement material activation substitution before atomic finalization', async () => {
  const store = new MemoryRecoveryJournalStore();
  const entropy = createRouterAbEd25519YaoActivationEntropyV1();
  const prf = new Uint8Array(32).fill(30);
  const identity = {
    walletId: 'wallet-recovery-source-1',
    nearAccountId: toAccountId('wallet-recovery-source.testnet'),
    nearEd25519SigningKeyId: 'near-signing-key-1',
    signerSlot: 1,
    operationalPublicKey: 'ed25519:public-key-1',
    authority: requireAuthority(),
    materialOwner: requireMaterialOwner(),
  };
  const request = requireAdmissionRequest();
  const source = await sealEd25519YaoRecoverySourceV1({
    store,
    identity,
    request,
    ownedPasskeyPrfFirst: prf,
    entropy,
  });
  const prepared = buildPreparedNearEd25519YaoRecoveryJournalV1({
    authority: identity.authority,
    materialOwner: identity.materialOwner,
    source,
    request,
  });
  await persistPreparedNearEd25519YaoRecoveryJournalV1({
    store,
    walletId: identity.walletId,
    signerSlot: identity.signerSlot,
    journal: prepared,
  });
  if (!store.record?.payloadEnvelope) {
    throw new Error('prepared recovery fixture is unavailable');
  }
  const replacement = buildActiveClientKeyMaterialRecord(
    store.record,
    request.scope.material_activation,
  );
  const committed = await persistPromotionCommittedNearEd25519YaoRecoveryV1({
    store,
    walletId: identity.walletId,
    signerSlot: identity.signerSlot,
    prepared,
    promotionReceipt: requirePromotionReceipt(request),
    replacement,
  });
  const substituted = {
    ...committed,
    finalization: {
      ...committed.finalization,
      replacement: substituteReplacementActivation(committed.finalization.replacement),
    },
  };

  await expect(
    finalizePromotionCommittedNearEd25519YaoRecoveryV1({
      store,
      walletId: identity.walletId,
      signerSlot: identity.signerSlot,
      journal: substituted,
    }),
  ).rejects.toThrow('Near recovery replacement material activation does not match promotion');
  expect(store.record?.keyKind).toBe('router_ab_ed25519_yao_recovery_source_v1');
  expect(
    await readNearEd25519YaoRecoveryJournalV1({
      store,
      walletId: identity.walletId,
      signerSlot: identity.signerSlot,
    }),
  ).toMatchObject({ kind: 'promotion_committed' });

  zeroizeRouterAbEd25519YaoActivationEntropyV1(entropy);
  prf.fill(0);
});

test('survives crashes before recovery call, after readback, and during atomic finalization', async () => {
  const store = new FaultInjectingRecoveryJournalStore();
  const entropy = createRouterAbEd25519YaoActivationEntropyV1();
  const prf = new Uint8Array(32).fill(31);
  const identity = {
    walletId: 'wallet-recovery-source-1',
    nearAccountId: toAccountId('wallet-recovery-source.testnet'),
    nearEd25519SigningKeyId: 'near-signing-key-1',
    signerSlot: 1,
    operationalPublicKey: 'ed25519:public-key-1',
    authority: requireAuthority(),
    materialOwner: requireMaterialOwner(),
  };
  const request = requireAdmissionRequest();
  const source = await sealEd25519YaoRecoverySourceV1({
    store,
    identity,
    request,
    ownedPasskeyPrfFirst: prf,
    entropy,
  });
  const prepared = buildPreparedNearEd25519YaoRecoveryJournalV1({
    authority: identity.authority,
    materialOwner: identity.materialOwner,
    source,
    request,
  });
  await persistPreparedNearEd25519YaoRecoveryJournalV1({
    store,
    walletId: identity.walletId,
    signerSlot: identity.signerSlot,
    journal: prepared,
  });

  expect(
    await readNearEd25519YaoRecoveryJournalV1({
      store,
      walletId: identity.walletId,
      signerSlot: identity.signerSlot,
    }),
  ).toMatchObject({ kind: 'prepared', recoveryId: prepared.recoveryId });

  if (!store.record?.payloadEnvelope) {
    throw new Error('prepared recovery fixture is unavailable');
  }
  const replacement = buildActiveClientKeyMaterialRecord(
    store.record,
    request.scope.material_activation,
  );
  const committed = await persistPromotionCommittedNearEd25519YaoRecoveryV1({
    store,
    walletId: identity.walletId,
    signerSlot: identity.signerSlot,
    prepared,
    promotionReceipt: requirePromotionReceipt(request),
    replacement,
  });

  expect(
    await readNearEd25519YaoRecoveryJournalV1({
      store,
      walletId: identity.walletId,
      signerSlot: identity.signerSlot,
    }),
  ).toMatchObject({ kind: 'promotion_committed', recoveryId: prepared.recoveryId });

  await expect(
    finalizePromotionCommittedNearEd25519YaoRecoveryV1({
      store,
      walletId: identity.walletId,
      signerSlot: identity.signerSlot,
      journal: committed,
    }),
  ).rejects.toThrow('injected atomic finalization crash');
  expect(store.record?.keyKind).toBe('router_ab_ed25519_yao_recovery_source_v1');
  expect(
    await readNearEd25519YaoRecoveryJournalV1({
      store,
      walletId: identity.walletId,
      signerSlot: identity.signerSlot,
    }),
  ).toMatchObject({ kind: 'promotion_committed', recoveryId: prepared.recoveryId });

  await finalizePromotionCommittedNearEd25519YaoRecoveryV1({
    store,
    walletId: identity.walletId,
    signerSlot: identity.signerSlot,
    journal: committed,
  });
  expect(
    await readNearEd25519YaoRecoveryJournalV1({
      store,
      walletId: identity.walletId,
      signerSlot: identity.signerSlot,
    }),
  ).toBeNull();
  expect(store.record?.keyKind).toBe('router_ab_ed25519_yao_active_client_v1');
  zeroizeRouterAbEd25519YaoActivationEntropyV1(entropy);
  prf.fill(0);
});
