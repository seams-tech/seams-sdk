import { expect, test } from '@playwright/test';
import {
  parseRouterAbEd25519YaoRecoveryActivationExecuteRequestV1,
  parseRouterAbEd25519YaoRecoveryAdmissionRequestV1,
  ROUTER_AB_ED25519_YAO_RECOVERY_ADMISSION_PATH_V1,
  ROUTER_AB_ED25519_YAO_RECOVERY_CHALLENGE_ID_HEADER_V1,
  ROUTER_AB_ED25519_YAO_RECOVERY_EXECUTE_PATH_V1,
  type RouterAbEd25519YaoRecoveryAdmissionRequestV1,
} from '@shared/utils/routerAbEd25519Yao';
import { RouterAbEd25519YaoHttpActivationTransportV1 } from '../../packages/wallet/src/core/signingEngine/threshold/ed25519/yaoClient';

function bytes(seed: number, length = 32): number[] {
  return new Array<number>(length).fill(seed);
}

function materialActivation(
  lifecycleId: string,
  owner: string,
  worker: string,
  stableIdentityId = lifecycleId,
) {
  return {
    kind: 'mpc_material_activation_ref' as const,
    activation_id: `${lifecycleId}-activation`,
    capability: `${stableIdentityId}-capability`,
    material_owner: owner,
    key_binding: `${stableIdentityId}-key`,
    lifecycle_binding: `${lifecycleId}-binding`,
    signing_worker: worker,
  };
}

function parseRecoveryAdmission(): RouterAbEd25519YaoRecoveryAdmissionRequestV1 {
  const lifecycleId = 'recovery-header-test';
  const walletId = 'wallet-header-test';
  const worker = 'signing-worker-header-test';
  const stableIdentityId = 'stable-header-test';
  const parsed = parseRouterAbEd25519YaoRecoveryAdmissionRequestV1({
    scope: {
      lifecycle_id: lifecycleId,
      root_share_epoch: 'root-header-test',
      account_id: walletId,
      threshold_session_id: 'threshold-header-test',
      signer_set_id: 'signer-set-header-test',
      signing_worker_id: worker,
      material_activation: materialActivation(lifecycleId, walletId, worker, stableIdentityId),
    },
    active_material_activation: materialActivation(
      'registration-header-test',
      walletId,
      worker,
      stableIdentityId,
    ),
    application_binding: {
      wallet_id: walletId,
      near_ed25519_signing_key_id: 'near-header-test',
      signing_root_id: 'project-header:test',
      key_creation_signer_slot: 1,
    },
    participant_ids: [1, 2],
    active_capability_binding: bytes(1),
    replacement_capability_binding: bytes(2),
    registered_public_key: bytes(3),
  });
  if (!parsed.ok) throw new Error(parsed.message);
  return parsed.value;
}

function parseRecoveryExecute(
  admission: RouterAbEd25519YaoRecoveryAdmissionRequestV1,
): Parameters<RouterAbEd25519YaoHttpActivationTransportV1['send']>[0] {
  const binding = {
    lifecycle: {
      lifecycle_id: admission.scope.lifecycle_id,
      work_kind: 'recovery' as const,
      primitive_request_kind: 'recovery' as const,
      root_share_epoch: admission.scope.root_share_epoch,
      account_id: admission.scope.account_id,
      session_id: admission.scope.threshold_session_id,
      signer_set_id: admission.scope.signer_set_id,
      selected_server_id: admission.scope.signing_worker_id,
    },
    operation: 'recovery' as const,
    session_id: bytes(7),
    stable_key_context_binding: bytes(8),
    material_activation: admission.scope.material_activation,
  };
  const parsed = parseRouterAbEd25519YaoRecoveryActivationExecuteRequestV1({
    binding,
    deriver_a_input: {
      kind: 'activation',
      deriver: 'deriver_a',
      operation: 'recovery',
      session: binding.session_id,
      stable_context_binding: binding.stable_key_context_binding,
      encapsulated_key: bytes(9),
      ciphertext: bytes(10, 16),
    },
    deriver_b_input: {
      kind: 'activation',
      deriver: 'deriver_b',
      operation: 'recovery',
      session: binding.session_id,
      stable_context_binding: binding.stable_key_context_binding,
      encapsulated_key: bytes(11),
      ciphertext: bytes(12, 16),
    },
  });
  if (!parsed.ok) throw new Error(parsed.message);
  return {
    kind: 'recovery_execute',
    path: ROUTER_AB_ED25519_YAO_RECOVERY_EXECUTE_PATH_V1,
    body: parsed.value,
  };
}

test('sends the recovery challenge header only on recovery admission', async () => {
  const requests: RequestInit[] = [];
  const fetchImpl: typeof fetch = async (_input, init) => {
    requests.push(init ?? {});
    return new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  };
  const transport = new RouterAbEd25519YaoHttpActivationTransportV1({
    routerOrigin: 'https://router.example.test',
    authorization: { kind: 'recovery_challenge', challengeId: 'challenge-header-test' },
    fetch: fetchImpl,
  });
  const admission = parseRecoveryAdmission();

  await transport.send({
    kind: 'recovery_admit',
    path: ROUTER_AB_ED25519_YAO_RECOVERY_ADMISSION_PATH_V1,
    body: admission,
  });
  await transport.send(parseRecoveryExecute(admission));

  expect(requests).toHaveLength(2);
  expect(
    new Headers(requests[0]?.headers).get(ROUTER_AB_ED25519_YAO_RECOVERY_CHALLENGE_ID_HEADER_V1),
  ).toBe('challenge-header-test');
  expect(
    new Headers(requests[1]?.headers).get(ROUTER_AB_ED25519_YAO_RECOVERY_CHALLENGE_ID_HEADER_V1),
  ).toBeNull();
  expect(new Headers(requests[1]?.headers).get('authorization')).toBeNull();
});
