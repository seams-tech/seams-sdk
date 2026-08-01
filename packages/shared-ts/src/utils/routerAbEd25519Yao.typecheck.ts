import type {
  RouterAbEd25519YaoActivationBindingV1,
  RouterAbEd25519YaoActivationClientPackageV1,
  RouterAbEd25519YaoActivationEncryptedInputV1,
  RouterAbEd25519YaoActivationExecuteRequestV1,
  RouterAbEd25519YaoRouterExecuteRequestV1,
} from './routerAbEd25519Yao';

const bytes32 = new Array<number>(32).fill(1);
const materialActivation = {
  kind: 'mpc_material_activation_ref' as const,
  activation_id: 'activation-1',
  capability: 'capability-1',
  material_owner: 'owner-1',
  key_binding: 'key-1',
  lifecycle_binding: 'lifecycle-1',
  signing_worker: 'signing-worker-1',
};

const registrationBinding: RouterAbEd25519YaoActivationBindingV1<'registration'> = {
  lifecycle: {
    lifecycle_id: 'lifecycle-1',
    work_kind: 'registration_prepare',
    primitive_request_kind: 'registration',
    root_share_epoch: 'epoch-1',
    account_id: 'account-1',
    session_id: 'wallet-session-1',
    signer_set_id: 'signer-set-1',
    selected_server_id: 'signing-worker-1',
  },
  operation: 'registration',
  session_id: bytes32,
  stable_key_context_binding: bytes32,
  material_activation: materialActivation,
};

const recoveryBinding: RouterAbEd25519YaoActivationBindingV1<'recovery'> = {
  lifecycle: {
    lifecycle_id: 'lifecycle-2',
    work_kind: 'recovery',
    primitive_request_kind: 'recovery',
    root_share_epoch: 'epoch-1',
    account_id: 'account-1',
    session_id: 'wallet-session-2',
    signer_set_id: 'signer-set-1',
    selected_server_id: 'signing-worker-1',
  },
  operation: 'recovery',
  session_id: bytes32,
  stable_key_context_binding: bytes32,
  material_activation: materialActivation,
};

const registrationInputA: RouterAbEd25519YaoActivationEncryptedInputV1<
  'deriver_a',
  'registration'
> = {
  kind: 'activation',
  deriver: 'deriver_a',
  operation: 'registration',
  session: bytes32,
  stable_context_binding: bytes32,
  encapsulated_key: bytes32,
  ciphertext: new Array<number>(16).fill(2),
};

const registrationInputB: RouterAbEd25519YaoActivationEncryptedInputV1<
  'deriver_b',
  'registration'
> = {
  kind: 'activation',
  deriver: 'deriver_b',
  operation: 'registration',
  session: bytes32,
  stable_context_binding: bytes32,
  encapsulated_key: bytes32,
  ciphertext: new Array<number>(16).fill(2),
};

const recoveryInputA: RouterAbEd25519YaoActivationEncryptedInputV1<'deriver_a', 'recovery'> = {
  kind: 'activation',
  deriver: 'deriver_a',
  operation: 'recovery',
  session: bytes32,
  stable_context_binding: bytes32,
  encapsulated_key: bytes32,
  ciphertext: new Array<number>(16).fill(2),
};

const recoveryInputB: RouterAbEd25519YaoActivationEncryptedInputV1<'deriver_b', 'recovery'> = {
  kind: 'activation',
  deriver: 'deriver_b',
  operation: 'recovery',
  session: bytes32,
  stable_context_binding: bytes32,
  encapsulated_key: bytes32,
  ciphertext: new Array<number>(16).fill(2),
};

const validRegistrationExecuteRequest: RouterAbEd25519YaoActivationExecuteRequestV1<'registration'> = {
  binding: registrationBinding,
  deriver_a_input: registrationInputA,
  deriver_b_input: registrationInputB,
};

const validRecoveryExecuteRequest: RouterAbEd25519YaoActivationExecuteRequestV1<'recovery'> = {
  binding: recoveryBinding,
  deriver_a_input: recoveryInputA,
  deriver_b_input: recoveryInputB,
};

const validRouterExecuteRequest: RouterAbEd25519YaoRouterExecuteRequestV1 = {
  operation: 'registration',
  authority: {
    authority_digest: { bytes: bytes32 },
    issued_at_ms: 1,
    expires_at_ms: 2,
  },
  binding: registrationBinding,
  pair_binding: {
    ceremony: {
      binding: registrationBinding,
      circuit: 'activation_v1',
      protocol: 'v1',
    },
    deriver_a_input_digest: { bytes: bytes32 },
    deriver_b_input_digest: { bytes: bytes32 },
    recipient_set_digest: { bytes: bytes32 },
    authorization_digest: { bytes: bytes32 },
    pair_digest: { bytes: bytes32 },
  },
  deriver_a_input: registrationInputA,
  deriver_b_input: registrationInputB,
};

const missingRouterPair = {
  operation: 'registration' as const,
  authority: validRouterExecuteRequest.authority,
  binding: registrationBinding,
  deriver_a_input: registrationInputA,
  deriver_b_input: registrationInputB,
};
// @ts-expect-error Router execution requires a canonical pair binding.
const invalidRouterExecuteRequest: RouterAbEd25519YaoRouterExecuteRequestV1 = missingRouterPair;

const wrongRouterOperationBinding = {
  ...validRouterExecuteRequest,
  operation: 'recovery' as const,
};
// @ts-expect-error Operation branches cannot be relabeled independently of their binding.
const invalidRouterOperationBinding: RouterAbEd25519YaoRouterExecuteRequestV1 =
  wrongRouterOperationBinding;

const deriverAClientPackage: RouterAbEd25519YaoActivationClientPackageV1<'deriver_a'> = {
  kind: 'activation_client',
  deriver: 'deriver_a',
  session: bytes32,
  transcript: bytes32,
  encapsulated_key: bytes32,
  ciphertext: new Array<number>(16).fill(3),
};

const wrongRoleInput: RouterAbEd25519YaoActivationEncryptedInputV1<
  'deriver_a',
  'registration'
> = {
  kind: 'activation',
  // @ts-expect-error Deriver A slots reject Deriver B envelopes.
  deriver: 'deriver_b',
  operation: 'registration',
  session: bytes32,
  stable_context_binding: bytes32,
  encapsulated_key: bytes32,
  ciphertext: new Array<number>(16).fill(2),
};

const wrongOperationInput: RouterAbEd25519YaoActivationEncryptedInputV1<
  'deriver_a',
  'registration'
> = {
  kind: 'activation',
  deriver: 'deriver_a',
  // @ts-expect-error Registration input slots reject Recovery envelopes.
  operation: 'recovery',
  session: bytes32,
  stable_context_binding: bytes32,
  encapsulated_key: bytes32,
  ciphertext: new Array<number>(16).fill(2),
};

const wrongRecoveryPrimitive: RouterAbEd25519YaoActivationBindingV1<'recovery'> = {
  lifecycle: {
    lifecycle_id: 'lifecycle-2',
    work_kind: 'recovery',
    // @ts-expect-error Recovery requires its dedicated primitive request kind.
    primitive_request_kind: 'export',
    root_share_epoch: 'epoch-1',
    account_id: 'account-1',
    session_id: 'wallet-session-2',
    signer_set_id: 'signer-set-1',
    selected_server_id: 'signing-worker-1',
  },
  operation: 'recovery',
  session_id: bytes32,
  stable_key_context_binding: bytes32,
};

const mixedActivationRequest: RouterAbEd25519YaoActivationExecuteRequestV1<'recovery'> = {
  binding: recoveryBinding,
  // @ts-expect-error Recovery slots reject Registration envelopes.
  deriver_a_input: registrationInputA,
  // @ts-expect-error Recovery slots reject Registration envelopes.
  deriver_b_input: registrationInputB,
};

const spreadRegistrationBinding = { ...registrationBinding, operation: 'recovery' as const };
// @ts-expect-error A spread cannot relabel a Registration lifecycle as Recovery.
const invalidSpreadRecoveryBinding: RouterAbEd25519YaoActivationBindingV1<'recovery'> =
  spreadRegistrationBinding;

void validRegistrationExecuteRequest;
void validRecoveryExecuteRequest;
void validRouterExecuteRequest;
void invalidRouterExecuteRequest;
void invalidRouterOperationBinding;
void deriverAClientPackage;
void wrongRoleInput;
void wrongOperationInput;
void wrongRecoveryPrimitive;
void mixedActivationRequest;
void invalidSpreadRecoveryBinding;
