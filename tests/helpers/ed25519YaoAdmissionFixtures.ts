/**
 * Shared factory for Ed25519-Yao admission records.
 *
 * Both are built through the production parsers, so a change to either shape
 * fails here rather than silently drifting — the rule in tests/AGENTS.md for
 * complex domain records. Before this existed, each caller hand-wrote the
 * literal, which meant guessing at nested shapes the parser then rejected.
 *
 * Callers override only the fields they exercise.
 */

import {
  parseRouterAbEd25519YaoRegistrationActivationAdmissionReceiptV1,
  parseRouterAbEd25519YaoRegistrationAdmissionRequestV1,
  type RouterAbEd25519YaoActivationAdmissionReceiptV1,
  type RouterAbEd25519YaoRegistrationAdmissionRequestV1,
} from '../../packages/shared-ts/src/utils/routerAbEd25519Yao';

/** Deterministic 32-byte material; the parsers check length, not entropy. */
export function ed25519YaoFixtureBytes(seed: number): number[] {
  return Array.from({ length: 32 }, (_, index) => (seed + index) & 0xff);
}

export function buildFixtureEd25519YaoRegistrationAdmissionRequest(
  overrides: {
    readonly lifecycleId?: string;
    readonly rootShareEpoch?: string;
    readonly walletId?: string;
    readonly signerSetId?: string;
    readonly signingWorkerId?: string;
    readonly nearEd25519SigningKeyId?: string;
    readonly signingRootId?: string;
    readonly participantIds?: readonly [number, number];
    readonly signerSlot?: number;
  } = {},
): RouterAbEd25519YaoRegistrationAdmissionRequestV1 {
  const lifecycleId = overrides.lifecycleId ?? 'registration-ceremony-fixture';
  const walletId = overrides.walletId ?? 'near-account.testnet';
  const signerSlot = overrides.signerSlot ?? 3;
  const parsed = parseRouterAbEd25519YaoRegistrationAdmissionRequestV1({
    scope: {
      lifecycle_id: lifecycleId,
      root_share_epoch: overrides.rootShareEpoch ?? 'root-share-epoch-9',
      account_id: walletId,
      wallet_session_id: `${lifecycleId}-session`,
      signer_set_id: overrides.signerSetId ?? 'signer-set-fixture',
      signing_worker_id: overrides.signingWorkerId ?? 'signing-worker-a',
      material_activation: {
        kind: 'mpc_material_activation_ref',
        activation_id: `${lifecycleId}-activation`,
        capability: `${lifecycleId}-capability`,
        material_owner: walletId,
        key_binding: `${lifecycleId}-key`,
        lifecycle_binding: `${lifecycleId}-lifecycle-binding`,
        signing_worker: overrides.signingWorkerId ?? 'signing-worker-a',
      },
    },
    application_binding: {
      wallet_id: walletId,
      near_ed25519_signing_key_id:
        overrides.nearEd25519SigningKeyId ?? 'ed25519ks_fixture',
      signing_root_id: overrides.signingRootId ?? 'project_fixture:dev',
      key_creation_signer_slot: signerSlot,
    },
    participant_ids: overrides.participantIds ?? [11, 29],
  });
  if (!parsed.ok) throw new Error(parsed.message);
  return parsed.value;
}

export function buildFixtureEd25519YaoRegistrationAdmissionReceipt(
  overrides: {
    readonly lifecycleId?: string;
    readonly rootShareEpoch?: string;
    readonly walletId?: string;
    readonly signerSetId?: string;
    readonly signingWorkerId?: string;
  } = {},
): RouterAbEd25519YaoActivationAdmissionReceiptV1<'registration'> {
  const lifecycleId = overrides.lifecycleId ?? 'registration-ceremony-fixture';
  const parsed = parseRouterAbEd25519YaoRegistrationActivationAdmissionReceiptV1({
    binding: {
      lifecycle: {
        lifecycle_id: lifecycleId,
        work_kind: 'registration_prepare',
        primitive_request_kind: 'registration',
        root_share_epoch: overrides.rootShareEpoch ?? 'root-share-epoch-9',
        account_id: overrides.walletId ?? 'near-account.testnet',
        session_id: `${lifecycleId}-session`,
        signer_set_id: overrides.signerSetId ?? 'signer-set-fixture',
        selected_server_id: overrides.signingWorkerId ?? 'signing-worker-a',
      },
      operation: 'registration',
      session_id: ed25519YaoFixtureBytes(1),
      stable_key_context_binding: ed25519YaoFixtureBytes(33),
    },
    keyset: {
      deriver_a_input_public_key: ed25519YaoFixtureBytes(65),
      deriver_b_input_public_key: ed25519YaoFixtureBytes(97),
      signing_worker_recipient_public_key: ed25519YaoFixtureBytes(129),
    },
  });
  if (!parsed.ok) throw new Error(parsed.message);
  return parsed.value;
}

/** The deferred-NEAR arm respond returns for a mixed signer plan. */
export function buildFixtureRespondEd25519DeferredWork(
  overrides: Parameters<typeof buildFixtureEd25519YaoRegistrationAdmissionReceipt>[0] = {},
): {
  status: 'deferred';
  admissionRequest: RouterAbEd25519YaoRegistrationAdmissionRequestV1;
  admissionReceipt: RouterAbEd25519YaoActivationAdmissionReceiptV1<'registration'>;
} {
  return {
    status: 'deferred',
    admissionRequest: buildFixtureEd25519YaoRegistrationAdmissionRequest(overrides),
    admissionReceipt: buildFixtureEd25519YaoRegistrationAdmissionReceipt(overrides),
  };
}
