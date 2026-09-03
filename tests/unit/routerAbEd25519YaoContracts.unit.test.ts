import { expect, test } from '@playwright/test';
import {
  deriveRouterAbEd25519YaoApplicationBindingDigestV1,
  deriveRouterAbEd25519YaoStableContextBindingV1,
  parseRouterAbEd25519YaoRecoveryActivationAdmissionReceiptV1,
  parseRouterAbEd25519YaoRecoveryActivationExecuteRequestV1,
  parseRouterAbEd25519YaoRecoveryActivationRequestV1,
  parseRouterAbEd25519YaoRecoveryActivationResultV1,
  parseRouterAbEd25519YaoRecoveryAdmissionRequestV1,
  parseRouterAbEd25519YaoRegistrationActivationAdmissionReceiptV1 as parseRouterAbEd25519YaoRegistrationAdmissionReceiptV1,
  parseRouterAbEd25519YaoRegistrationAdmissionRequestV1,
  parseRouterAbEd25519YaoRegistrationActivationExecuteRequestV1 as parseRouterAbEd25519YaoRegistrationExecuteRequestV1,
  parseRouterAbEd25519YaoRegistrationActivationResultV1 as parseRouterAbEd25519YaoRegistrationResultV1,
  ROUTER_AB_ED25519_YAO_REGISTRATION_ADMISSION_PATH_V1,
  ROUTER_AB_ED25519_YAO_REGISTRATION_EXECUTE_PATH_V1,
  type RouterAbEd25519YaoActivationBindingV1,
  type RouterAbEd25519YaoActivationExecuteRequestV1,
  type RouterAbEd25519YaoRegistrationAdmissionRequestV1,
} from '@shared/utils/routerAbEd25519Yao';
import {
  InMemoryRouterAbEd25519YaoRegistrationService,
  InMemoryRouterAbEd25519YaoRegistrationStateV1,
  createRouterAbEd25519YaoRegistrationModule,
  type RouterAbEd25519YaoRegistrationAuthorizationAdapter,
  type RouterAbEd25519YaoRegistrationAuthorizationInput,
  type RouterAbEd25519YaoRegistrationAuthorizationResult,
  type RouterAbEd25519YaoRegistrationBackend,
  type RouterAbEd25519YaoRegistrationBackendFailure,
  type RouterAbEd25519YaoRegistrationBackendResult,
} from '../../packages/wallet-server/src/router/domains/ed25519Yao/registration/routerAbEd25519YaoRegistration';
import { coerceRouterLogger } from '../../packages/wallet-server/src/router/framework/logger';
import {
  createRouterAbEd25519YaoHttpRegistrationBackendFromEnv,
  parseRouterAbEd25519YaoActivationKeysetFromEnvV1,
} from '../../packages/wallet-server/src/router/domains/ed25519Yao/registration/routerAbEd25519YaoHttpRegistrationBackend';

type RouterAbEd25519YaoRegistrationBindingV1 =
  RouterAbEd25519YaoActivationBindingV1<'registration'>;
type RouterAbEd25519YaoRegistrationExecuteRequestV1 =
  RouterAbEd25519YaoActivationExecuteRequestV1<'registration'>;

type TestExecutionBehavior =
  | { kind: 'success'; body: unknown }
  | { kind: 'failure'; failure: RouterAbEd25519YaoRegistrationBackendFailure };

type DeferredExecutionState =
  | { kind: 'idle' }
  | {
      kind: 'pending';
      resolve: (result: RouterAbEd25519YaoRegistrationBackendResult) => void;
    }
  | { kind: 'resolved' };

type ScriptedFetchState =
  | { kind: 'unbound' }
  | { kind: 'bound'; binding: RouterAbEd25519YaoActivationBindingV1 };

type ScriptedExecutionResult =
  | { kind: 'success' }
  | { kind: 'burned'; reason: 'protocol_failure' }
  | { kind: 'recoverable'; code: 'ceremony_expired' };

class TestRegistrationBackend implements RouterAbEd25519YaoRegistrationBackend {
  admitCalls = 0;
  executeCalls = 0;

  constructor(
    private readonly admissionBody: unknown,
    private readonly executionBehavior: TestExecutionBehavior,
  ) {}

  admit(): RouterAbEd25519YaoRegistrationBackendResult {
    this.admitCalls += 1;
    return { ok: true, body: this.admissionBody };
  }

  execute(): RouterAbEd25519YaoRegistrationBackendResult {
    this.executeCalls += 1;
    switch (this.executionBehavior.kind) {
      case 'success':
        return { ok: true, body: this.executionBehavior.body };
      case 'failure':
        return this.executionBehavior.failure;
    }
  }
}

class TestRegistrationAuthorization implements RouterAbEd25519YaoRegistrationAuthorizationAdapter {
  readonly inputs: RouterAbEd25519YaoRegistrationAuthorizationInput[] = [];

  constructor(private readonly result: RouterAbEd25519YaoRegistrationAuthorizationResult) {}

  authorize(
    input: RouterAbEd25519YaoRegistrationAuthorizationInput,
  ): RouterAbEd25519YaoRegistrationAuthorizationResult {
    this.inputs.push(input);
    return this.result;
  }
}

class DeferredRegistrationBackend implements RouterAbEd25519YaoRegistrationBackend {
  private state: DeferredExecutionState = { kind: 'idle' };

  constructor(private readonly admissionBody: unknown) {}

  admit(): RouterAbEd25519YaoRegistrationBackendResult {
    return { ok: true, body: this.admissionBody };
  }

  execute(): Promise<RouterAbEd25519YaoRegistrationBackendResult> {
    if (this.state.kind !== 'idle') throw new Error('deferred execution already started');
    return new Promise<RouterAbEd25519YaoRegistrationBackendResult>(
      this.captureExecution.bind(this),
    );
  }

  resolve(body: unknown): void {
    if (this.state.kind !== 'pending') throw new Error('deferred execution is not pending');
    const resolve = this.state.resolve;
    this.state = { kind: 'resolved' };
    resolve({ ok: true, body });
  }

  private captureExecution(
    resolve: (result: RouterAbEd25519YaoRegistrationBackendResult) => void,
  ): void {
    this.state = { kind: 'pending', resolve };
  }
}

class ScriptedLocalYaoFetch {
  readonly calls: string[] = [];
  readonly requestUrls: string[] = [];
  readonly traceIds: string[] = [];
  readonly requestBodies: string[] = [];
  readonly replayHeaders: string[] = [];
  failNextExecute = false;
  dropNextExecuteResponse = false;
  executionResult: ScriptedExecutionResult = { kind: 'success' };
  private state: ScriptedFetchState = { kind: 'unbound' };

  bindActivation(binding: RouterAbEd25519YaoActivationBindingV1): void {
    if (this.state.kind !== 'unbound') throw new Error('scripted fetch session already bound');
    this.state = { kind: 'bound', binding };
  }

  async fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
    if (this.state.kind !== 'bound') throw new Error('scripted fetch session is not bound');
    const url = this.url(input);
    const method = init?.method || 'GET';
    const traceId = new Headers(init?.headers).get('x-seams-trace-id');
    if (!traceId || !/^[0-9a-f]{32}$/.test(traceId)) {
      throw new Error('Router request must carry a canonical opaque trace ID');
    }
    this.calls.push(`${method} ${url.pathname}`);
    this.requestUrls.push(url.toString());
    this.traceIds.push(traceId);
    this.requestBodies.push(typeof init?.body === 'string' ? init.body : '');
    this.replayHeaders.push(new Headers(init?.headers).get('x-seams-yao-replay') ?? '');
    if (this.failNextExecute && url.pathname === '/router-ab/router/ed25519-yao/execute') {
      this.failNextExecute = false;
      throw new Error('simulated Router transport failure');
    }
    const response = this.response(url.pathname, this.state.binding);
    if (this.dropNextExecuteResponse && url.pathname === '/router-ab/router/ed25519-yao/execute') {
      this.dropNextExecuteResponse = false;
      throw new Error('simulated Router response loss after execution');
    }
    return response;
  }

  private url(input: RequestInfo | URL): URL {
    if (typeof input === 'string') return new URL(input);
    if (input instanceof URL) return input;
    return new URL(input.url);
  }

  private response(path: string, binding: RouterAbEd25519YaoActivationBindingV1): Response {
    const session = binding.session_id;
    switch (path) {
      case '/router-ab/router/ed25519-yao/execute':
        if (this.executionResult.kind === 'burned') {
          return this.json({
            status: 'burned',
            execution_id: bytes(18),
            reason: this.executionResult.reason,
          });
        }
        if (this.executionResult.kind === 'recoverable') {
          return this.json({
            status: 'recoverable_failure',
            code: this.executionResult.code,
            retry_after_ms: 1_000,
          });
        }
        return this.json({
          status: 'succeeded',
          result: {
            operation: binding.operation,
            result: activationResultForBinding(binding),
          },
        });
      case '/router-ab/router/ed25519-yao/recovery/promote':
        return this.json({
          status: 'active',
          session,
          transcript: bytes(11),
          registered_public_key: bytes(12),
          joined_client_commitment: bytes(13),
          joined_signing_worker_commitment: bytes(15),
          signing_worker_verifying_share: bytes(15),
          state_epoch: 2,
        });
      default:
        return this.json({ code: 'unexpected_path', path }, 404);
    }
  }

  private json(body: unknown, status = 200): Response {
    return new Response(JSON.stringify(body), {
      status,
      headers: { 'content-type': 'application/json' },
    });
  }
}

function bytes(seed: number, length = 32): number[] {
  return new Array<number>(length).fill(seed);
}

function hex(bytesValue: readonly number[]): string {
  let encoded = '';
  for (const byte of bytesValue) encoded += byte.toString(16).padStart(2, '0');
  return encoded;
}

function x25519(seed: number): string {
  return `x25519:${hex(bytes(seed))}`;
}

test('parses the deployment Yao activation keyset from canonical x25519 env values', () => {
  const keyset = parseRouterAbEd25519YaoActivationKeysetFromEnvV1({
    DERIVER_A_ED25519_YAO_INPUT_PUBLIC_KEY: x25519(1),
    DERIVER_B_ED25519_YAO_INPUT_PUBLIC_KEY: x25519(2),
    SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY: x25519(3),
  });
  expect(keyset.deriver_a_input_public_key).toEqual(bytes(1));
  expect(keyset.deriver_b_input_public_key).toEqual(bytes(2));
  expect(keyset.signing_worker_recipient_public_key).toEqual(bytes(3));
});

function localHttpBackendEnv(): Readonly<Record<string, unknown>> {
  return {
    MPC_ROUTER_URL: 'http://router.local',
    SIGNING_WORKER_ID: 'signing-worker-1',
    ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET: 'local-service-auth',
    DERIVER_A_ED25519_YAO_INPUT_PUBLIC_KEY: x25519(1),
    DERIVER_B_ED25519_YAO_INPUT_PUBLIC_KEY: x25519(2),
    SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY: x25519(3),
  };
}

const testTenantRootResolver = async () => ({
  identityDigestB64u: 'tenant-root-identity-digest',
  custodyLineageB64u: 'tenant-root-custody-lineage',
});

function registrationBinding(): Record<string, unknown> {
  return {
    lifecycle: {
      lifecycle_id: 'registration-1',
      work_kind: 'registration_prepare',
      primitive_request_kind: 'registration',
      root_share_epoch: 'epoch-1',
      account_id: 'account-1',
      session_id: 'wallet-session-1',
      signer_set_id: 'signer-set-1',
      selected_server_id: 'signing-worker-1',
    },
    operation: 'registration',
    session_id: bytes(7),
    stable_key_context_binding: bytes(8),
    material_activation: {
      kind: 'mpc_material_activation_ref',
      activation_id: 'registration-activation-1',
      capability: 'registration-capability-1',
      material_owner: 'account-1',
      key_binding: 'registration-key-1',
      lifecycle_binding: 'registration-lifecycle-binding-1',
      signing_worker: 'signing-worker-1',
    },
  };
}

function registrationAdmissionRequest(): Record<string, unknown> {
  return {
    scope: {
      lifecycle_id: 'registration-1',
      root_share_epoch: 'epoch-1',
      account_id: 'account-1',
      threshold_session_id: 'wallet-session-1',
      signer_set_id: 'signer-set-1',
      signing_worker_id: 'signing-worker-1',
      material_activation: {
        kind: 'mpc_material_activation_ref',
        activation_id: 'registration-activation-1',
        capability: 'registration-capability-1',
        material_owner: 'account-1',
        key_binding: 'registration-key-1',
        lifecycle_binding: 'registration-lifecycle-binding-1',
        signing_worker: 'signing-worker-1',
      },
    },
    application_binding: {
      wallet_id: 'wallet-1',
      near_ed25519_signing_key_id: 'ed25519ks_1',
      signing_root_id: 'project:local',
      key_creation_signer_slot: 1,
    },
    participant_ids: [1, 2],
  };
}

function recoveryAdmissionRequest(): Record<string, unknown> {
  return {
    scope: {
      lifecycle_id: 'recovery-1',
      root_share_epoch: 'epoch-1',
      account_id: 'account-1',
      threshold_session_id: 'wallet-session-1',
      signer_set_id: 'signer-set-1',
      signing_worker_id: 'signing-worker-1',
      material_activation: {
        kind: 'mpc_material_activation_ref',
        activation_id: 'recovery-activation-1',
        capability: 'registration-capability-1',
        material_owner: 'account-1',
        key_binding: 'registration-key-1',
        lifecycle_binding: 'recovery-lifecycle-binding-1',
        signing_worker: 'signing-worker-1',
      },
    },
    active_material_activation: {
      kind: 'mpc_material_activation_ref',
      activation_id: 'registration-activation-1',
      capability: 'registration-capability-1',
      material_owner: 'account-1',
      key_binding: 'registration-key-1',
      lifecycle_binding: 'registration-lifecycle-binding-1',
      signing_worker: 'signing-worker-1',
    },
    application_binding: {
      wallet_id: 'wallet-1',
      near_ed25519_signing_key_id: 'ed25519ks_1',
      signing_root_id: 'project:local',
      key_creation_signer_slot: 1,
    },
    participant_ids: [1, 2],
    active_capability_binding: bytes(20),
    replacement_capability_binding: bytes(21),
    registered_public_key: bytes(12),
  };
}

function encryptedInput(deriver: 'deriver_a' | 'deriver_b'): Record<string, unknown> {
  return {
    kind: 'activation',
    deriver,
    operation: 'registration',
    session: bytes(7),
    stable_context_binding: bytes(8),
    encapsulated_key: bytes(9),
    ciphertext: bytes(10, 32),
  };
}

function encryptedInputForBinding(
  binding: RouterAbEd25519YaoActivationBindingV1,
  deriver: 'deriver_a' | 'deriver_b',
): Record<string, unknown> {
  return {
    kind: 'activation',
    deriver,
    operation: binding.operation,
    session: binding.session_id,
    stable_context_binding: binding.stable_key_context_binding,
    encapsulated_key: bytes(9),
    ciphertext: bytes(10, 32),
  };
}

function registrationExecuteRequest(): Record<string, unknown> {
  return {
    binding: registrationBinding(),
    deriver_a_input: encryptedInput('deriver_a'),
    deriver_b_input: encryptedInput('deriver_b'),
  };
}

function encryptedClientPackage(deriver: 'deriver_a' | 'deriver_b'): Record<string, unknown> {
  return {
    kind: 'activation_client',
    deriver,
    session: bytes(7),
    transcript: bytes(11),
    encapsulated_key: bytes(16),
    ciphertext: bytes(17, 32),
  };
}

function activationResultForBinding(
  binding: RouterAbEd25519YaoActivationBindingV1,
): Record<string, unknown> {
  const session = binding.session_id;
  return {
    binding,
    deriver_a_client_package: {
      ...encryptedClientPackage('deriver_a'),
      session,
    },
    deriver_b_client_package: {
      ...encryptedClientPackage('deriver_b'),
      session,
    },
    public_receipt: {
      transcript: bytes(11),
      registered_public_key: bytes(12),
      joined_client_commitment: bytes(13),
      joined_signing_worker_commitment: bytes(15),
      signing_worker_verifying_share: bytes(15),
      state_epoch: binding.operation === 'recovery' ? 2 : 1,
      material_activation: binding.material_activation,
    },
  };
}

function registrationResult(): Record<string, unknown> {
  return {
    binding: registrationBinding(),
    deriver_a_client_package: encryptedClientPackage('deriver_a'),
    deriver_b_client_package: encryptedClientPackage('deriver_b'),
    public_receipt: {
      transcript: bytes(11),
      registered_public_key: bytes(12),
      joined_client_commitment: bytes(13),
      joined_signing_worker_commitment: bytes(14),
      signing_worker_verifying_share: bytes(15),
      state_epoch: 1,
      material_activation: registrationBinding().material_activation,
    },
  };
}

function registrationAdmissionReceipt(): Record<string, unknown> {
  return {
    binding: registrationBinding(),
    keyset: {
      deriver_a_input_public_key: bytes(1),
      deriver_b_input_public_key: bytes(2),
      signing_worker_recipient_public_key: bytes(3),
    },
  };
}

function parsedAdmissionRequest(): RouterAbEd25519YaoRegistrationAdmissionRequestV1 {
  const parsed = parseRouterAbEd25519YaoRegistrationAdmissionRequestV1(
    registrationAdmissionRequest(),
  );
  if (!parsed.ok) throw new Error(parsed.message);
  return parsed.value;
}

function parsedExecuteRequest(): RouterAbEd25519YaoRegistrationExecuteRequestV1 {
  const parsed = parseRouterAbEd25519YaoRegistrationExecuteRequestV1(registrationExecuteRequest());
  if (!parsed.ok) throw new Error(parsed.message);
  return parsed.value;
}

function parsedExecuteRequestWithCiphertextSeed(
  seed: number,
): RouterAbEd25519YaoRegistrationExecuteRequestV1 {
  const raw = registrationExecuteRequest();
  const deriverAInput = requireRawRecord(raw.deriver_a_input, 'deriver_a_input');
  deriverAInput.ciphertext = bytes(seed, 32);
  const parsed = parseRouterAbEd25519YaoRegistrationExecuteRequestV1(raw);
  if (!parsed.ok) throw new Error(parsed.message);
  return parsed.value;
}

function requireRawRecord(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be a record`);
  }
  return value as Record<string, unknown>;
}

function jsonRequest(path: string, body: unknown): Request {
  return new Request(`http://router.local${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: 'Bearer local-grant' },
    body: JSON.stringify(body),
  });
}

function createMalformedLocalRegistrationBackend(): void {
  createRouterAbEd25519YaoHttpRegistrationBackendFromEnv({
    env: {
      MPC_ROUTER_URL: 'http://router.local',
      SIGNING_WORKER_ID: 'signing-worker-1',
      ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET: 'local-service-auth',
      DERIVER_A_ED25519_YAO_INPUT_PUBLIC_KEY: x25519(1),
      DERIVER_B_ED25519_YAO_INPUT_PUBLIC_KEY: x25519(2),
      SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY: 'x25519:00',
    },
    resolveTenantRoot: testTenantRootResolver,
    fetch: globalThis.fetch,
  });
}

test.describe('Router A/B Ed25519 Yao registration contracts', () => {
  test('matches the canonical signer-core application and stable-context digests', async () => {
    const application = {
      wallet_id: 'wallet-fixture',
      near_ed25519_signing_key_id: 'ed25519ks_fixture',
      signing_root_id: 'project-fixture:env-fixture',
      key_creation_signer_slot: 1,
    };
    expect(hex(await deriveRouterAbEd25519YaoApplicationBindingDigestV1(application))).toBe(
      'b1dbafce5fd696ae4bd5611e3684a778febfdf7f716e2dfe3211ce0cff708121',
    );
    expect(hex(await deriveRouterAbEd25519YaoStableContextBindingV1(application, [1, 2]))).toBe(
      'b5601ad156882b545a2e4a4a694e87c7982842d37a4c666645302604b2720655',
    );
  });

  test('freezes the two-step public paths and accepts coherent Rust wire shapes', () => {
    expect(ROUTER_AB_ED25519_YAO_REGISTRATION_ADMISSION_PATH_V1).toBe(
      '/router-ab/ed25519/yao/registration/admit',
    );
    expect(ROUTER_AB_ED25519_YAO_REGISTRATION_EXECUTE_PATH_V1).toBe(
      '/router-ab/ed25519/yao/registration/execute',
    );

    expect(
      parseRouterAbEd25519YaoRegistrationAdmissionRequestV1(registrationAdmissionRequest()),
    ).toEqual({
      ok: true,
      value: registrationAdmissionRequest(),
    });
    expect(
      parseRouterAbEd25519YaoRegistrationAdmissionReceiptV1(registrationAdmissionReceipt()).ok,
    ).toBe(true);
    expect(
      parseRouterAbEd25519YaoRegistrationExecuteRequestV1(registrationExecuteRequest()).ok,
    ).toBe(true);
    expect(parseRouterAbEd25519YaoRegistrationResultV1(registrationResult()).ok).toBe(true);
  });

  test('rejects unknown fields and non-canonical participant identifiers', () => {
    const unknownField = registrationAdmissionRequest();
    unknownField.legacy_derivation_handle = 'forbidden';
    expect(parseRouterAbEd25519YaoRegistrationAdmissionRequestV1(unknownField).ok).toBe(false);

    const invalidParticipants = registrationAdmissionRequest();
    invalidParticipants.participant_ids = [2, 1];
    expect(parseRouterAbEd25519YaoRegistrationAdmissionRequestV1(invalidParticipants).ok).toBe(
      false,
    );
  });

  test('rejects swapped roles and mixed ceremony bindings before orchestration', () => {
    const swappedRoles = registrationExecuteRequest();
    swappedRoles.deriver_a_input = encryptedInput('deriver_b');
    expect(parseRouterAbEd25519YaoRegistrationExecuteRequestV1(swappedRoles).ok).toBe(false);

    const mixedSession = registrationExecuteRequest();
    const deriverBInput = requireRawRecord(mixedSession.deriver_b_input, 'deriver_b_input');
    deriverBInput.session = bytes(18);
    expect(parseRouterAbEd25519YaoRegistrationExecuteRequestV1(mixedSession).ok).toBe(false);
  });

  test('rejects recipient and transcript substitution in terminal results', () => {
    const wrongRecipient = registrationResult();
    wrongRecipient.deriver_a_client_package = encryptedClientPackage('deriver_b');
    expect(parseRouterAbEd25519YaoRegistrationResultV1(wrongRecipient).ok).toBe(false);

    const wrongTranscript = registrationResult();
    const packageA = requireRawRecord(
      wrongTranscript.deriver_a_client_package,
      'deriver_a_client_package',
    );
    packageA.transcript = bytes(19);
    expect(parseRouterAbEd25519YaoRegistrationResultV1(wrongTranscript).ok).toBe(false);
  });

  test('rejects owner, worker, and complete activation-reference substitution', () => {
    const wrongOwner = registrationAdmissionRequest();
    const wrongOwnerScope = requireRawRecord(wrongOwner.scope, 'scope');
    const wrongOwnerActivation = requireRawRecord(
      wrongOwnerScope.material_activation,
      'scope.material_activation',
    );
    wrongOwnerActivation.material_owner = 'other-account';
    expect(parseRouterAbEd25519YaoRegistrationAdmissionRequestV1(wrongOwner).ok).toBe(false);

    const wrongWorker = registrationAdmissionRequest();
    const wrongWorkerScope = requireRawRecord(wrongWorker.scope, 'scope');
    const wrongWorkerActivation = requireRawRecord(
      wrongWorkerScope.material_activation,
      'scope.material_activation',
    );
    wrongWorkerActivation.signing_worker = 'other-signing-worker';
    expect(parseRouterAbEd25519YaoRegistrationAdmissionRequestV1(wrongWorker).ok).toBe(false);

    for (const field of [
      'activation_id',
      'capability',
      'material_owner',
      'key_binding',
      'lifecycle_binding',
      'signing_worker',
    ] as const) {
      const substitutedResult = registrationResult();
      const receipt = requireRawRecord(substitutedResult.public_receipt, 'public_receipt');
      const activation = requireRawRecord(
        receipt.material_activation,
        'public_receipt.material_activation',
      );
      activation[field] = `substituted-${field}`;
      expect(parseRouterAbEd25519YaoRegistrationResultV1(substitutedResult).ok).toBe(false);
    }
  });

  test('caches exact activated retries and rejects payload substitution', async () => {
    const backend = new TestRegistrationBackend(registrationAdmissionReceipt(), {
      kind: 'success',
      body: registrationResult(),
    });
    const service = new InMemoryRouterAbEd25519YaoRegistrationService(backend);
    const admission = await service.admit(parsedAdmissionRequest());
    expect(admission.ok).toBe(true);

    const request = parsedExecuteRequest();
    const activated = await service.execute(request);
    expect(activated.ok).toBe(true);
    const retry = await service.execute(request);
    expect(retry).toEqual(activated);
    expect(backend.executeCalls).toBe(1);

    const substituted = await service.execute(parsedExecuteRequestWithCiphertextSeed(20));
    expect(substituted).toMatchObject({
      ok: false,
      status: 409,
      code: 'binding_mismatch',
    });
    expect(backend.executeCalls).toBe(1);
  });

  test('binds a verified activation to one exact-idempotent wallet finalization', async () => {
    const backend = new TestRegistrationBackend(registrationAdmissionReceipt(), {
      kind: 'success',
      body: registrationResult(),
    });
    const service = new InMemoryRouterAbEd25519YaoRegistrationService(backend);
    expect((await service.admit(parsedAdmissionRequest())).ok).toBe(true);
    expect((await service.execute(parsedExecuteRequest())).ok).toBe(true);

    const reference = {
      lifecycleId: 'registration-1',
      sessionId: bytes(7),
    };
    const consumed = service.consumeActivated({
      reference,
      consumerBinding: 'wallet-finalize-request-1',
    });
    expect(consumed).toMatchObject({
      ok: true,
      activation: {
        admissionRequest: { scope: { lifecycle_id: 'registration-1' } },
        result: { public_receipt: { state_epoch: 1 } },
      },
    });
    expect(
      service.consumeActivated({ reference, consumerBinding: 'wallet-finalize-request-1' }),
    ).toEqual(consumed);
    expect(
      service.consumeActivated({ reference, consumerBinding: 'wallet-finalize-request-2' }),
    ).toEqual({
      ok: false,
      code: 'activation_consumed',
      message: 'Yao activation was already consumed by wallet finalization',
    });
  });

  test('rejects activation consumption before execution and for a substituted session', async () => {
    const backend = new TestRegistrationBackend(registrationAdmissionReceipt(), {
      kind: 'success',
      body: registrationResult(),
    });
    const service = new InMemoryRouterAbEd25519YaoRegistrationService(backend);
    expect((await service.admit(parsedAdmissionRequest())).ok).toBe(true);

    expect(
      service.consumeActivated({
        reference: { lifecycleId: 'registration-1', sessionId: bytes(7) },
        consumerBinding: 'wallet-finalize-request-1',
      }),
    ).toMatchObject({ ok: false, code: 'registration_not_activated' });
    expect((await service.execute(parsedExecuteRequest())).ok).toBe(true);
    expect(
      service.consumeActivated({
        reference: { lifecycleId: 'registration-1', sessionId: bytes(19) },
        consumerBinding: 'wallet-finalize-request-1',
      }),
    ).toMatchObject({ ok: false, code: 'activation_reference_mismatch' });
    expect(
      service.consumeActivated({
        reference: { lifecycleId: 'registration-substituted', sessionId: bytes(7) },
        consumerBinding: 'wallet-finalize-request-1',
      }),
    ).toMatchObject({ ok: false, code: 'unknown_registration' });
  });

  test('redelivers an exact completed admission without invoking the backend again', async () => {
    const backend = new TestRegistrationBackend(registrationAdmissionReceipt(), {
      kind: 'success',
      body: registrationResult(),
    });
    const service = new InMemoryRouterAbEd25519YaoRegistrationService(backend);
    const first = await service.admit(parsedAdmissionRequest());
    expect(first).toMatchObject({ ok: true, status: 200 });
    expect(await service.admit(parsedAdmissionRequest())).toEqual(first);
    expect(backend.admitCalls).toBe(1);
  });

  test('commits executing before awaiting the Yao backend', async () => {
    const backend = new DeferredRegistrationBackend(registrationAdmissionReceipt());
    const service = new InMemoryRouterAbEd25519YaoRegistrationService(backend);
    expect((await service.admit(parsedAdmissionRequest())).ok).toBe(true);
    const request = parsedExecuteRequest();

    const firstExecution = service.execute(request);
    const concurrentRetry = await service.execute(request);
    expect(concurrentRetry).toMatchObject({
      ok: false,
      status: 409,
      code: 'execution_in_progress',
    });

    backend.resolve(registrationResult());
    expect((await firstExecution).ok).toBe(true);
  });

  test('exposes a typed preclaim and terminal commit boundary', async () => {
    const backend = new TestRegistrationBackend(registrationAdmissionReceipt(), {
      kind: 'success',
      body: registrationResult(),
    });
    const service = new InMemoryRouterAbEd25519YaoRegistrationService(backend);
    expect((await service.admit(parsedAdmissionRequest())).ok).toBe(true);

    const request = parsedExecuteRequest();
    const preparation = service.prepareExecute(request);
    expect(preparation.kind).toBe('claimed');
    if (preparation.kind !== 'claimed') throw new Error('execution claim is required');
    expect(service.prepareExecute(request)).toMatchObject({
      kind: 'failed',
      failure: { code: 'execution_in_progress' },
    });
    expect(
      service.commitExecute({
        request,
        claim: preparation.claim,
        outcome: {
          kind: 'backend_response',
          result: { ok: true, body: registrationResult() },
        },
      }),
    ).toMatchObject({ ok: true, status: 200 });
    expect(backend.executeCalls).toBe(0);
  });

  test('persists an admission claim boundary before the backend is allowed to run', () => {
    const backend = new TestRegistrationBackend(registrationAdmissionReceipt(), {
      kind: 'success',
      body: registrationResult(),
    });
    const state = new InMemoryRouterAbEd25519YaoRegistrationStateV1();
    const service = new InMemoryRouterAbEd25519YaoRegistrationService(backend, state);
    const request = parsedAdmissionRequest();

    const preparation = service.prepareAdmit(request);
    expect(preparation.kind).toBe('claimed');
    expect(backend.admitCalls).toBe(0);
    expect(state.admissionClaims.get('registration-1')).toMatchObject({
      lifecycleId: 'registration-1',
    });
    expect(service.prepareAdmit(request)).toMatchObject({
      kind: 'failed',
      failure: { code: 'admission_in_progress' },
    });
    if (preparation.kind !== 'claimed') throw new Error('admission claim is required');
    const committed = service.commitAdmit({
      request,
      claim: preparation.claim,
      outcome: {
        kind: 'backend_response',
        result: backend.admit(),
      },
    });
    expect(committed).toMatchObject({ ok: true, status: 200 });
    expect(state.admissionClaims.size).toBe(0);
    expect(state.lifecycleSessions.get('registration-1')).toBeTruthy();
  });

  test('keeps an uncertain admission claim durable and rejects a duplicate backend call', () => {
    const backend = new TestRegistrationBackend(registrationAdmissionReceipt(), {
      kind: 'success',
      body: registrationResult(),
    });
    const state = new InMemoryRouterAbEd25519YaoRegistrationStateV1();
    const service = new InMemoryRouterAbEd25519YaoRegistrationService(backend, state);
    const request = parsedAdmissionRequest();
    const preparation = service.prepareAdmit(request);
    if (preparation.kind !== 'claimed') throw new Error('admission claim is required');

    expect(
      service.commitAdmit({
        request,
        claim: preparation.claim,
        outcome: { kind: 'backend_uncertain', message: 'Router response was lost' },
      }),
    ).toMatchObject({ ok: false, code: 'admission_uncertain', status: 503 });
    expect(service.prepareAdmit(request)).toMatchObject({
      kind: 'failed',
      failure: { code: 'admission_in_progress' },
    });
    expect(backend.admitCalls).toBe(0);
  });

  test('burns a failed execution and never invokes the backend twice', async () => {
    const backend = new TestRegistrationBackend(registrationAdmissionReceipt(), {
      kind: 'failure',
      failure: {
        ok: false,
        status: 503,
        code: 'deriver_disconnected',
        message: 'Deriver B disconnected',
      },
    });
    const service = new InMemoryRouterAbEd25519YaoRegistrationService(backend);
    expect((await service.admit(parsedAdmissionRequest())).ok).toBe(true);

    const request = parsedExecuteRequest();
    const failed = await service.execute(request);
    expect(failed).toMatchObject({ ok: false, status: 503, code: 'execution_failed' });
    expect(await service.execute(request)).toEqual(failed);
    expect(backend.executeCalls).toBe(1);
  });

  test('rejects a backend admission receipt outside the requested scope', async () => {
    const receipt = registrationAdmissionReceipt();
    const binding = requireRawRecord(receipt.binding, 'binding');
    const lifecycle = requireRawRecord(binding.lifecycle, 'binding.lifecycle');
    lifecycle.account_id = 'substituted-account';
    const backend = new TestRegistrationBackend(receipt, {
      kind: 'success',
      body: registrationResult(),
    });
    const service = new InMemoryRouterAbEd25519YaoRegistrationService(backend);
    expect(await service.admit(parsedAdmissionRequest())).toMatchObject({
      ok: false,
      status: 502,
      code: 'invalid_backend_response',
    });
  });

  test('mounts both authorized SDK Router paths as an explicit module', async () => {
    const backend = new TestRegistrationBackend(registrationAdmissionReceipt(), {
      kind: 'success',
      body: registrationResult(),
    });
    const service = new InMemoryRouterAbEd25519YaoRegistrationService(backend);
    const authorization = new TestRegistrationAuthorization({ ok: true });
    const module = createRouterAbEd25519YaoRegistrationModule({ service, authorization });
    const extension = module.routeExtensions[0];
    if (!extension) throw new Error('registration route extension is required');
    const admissionRoute = extension.routes[0];
    const executeRoute = extension.routes[1];
    if (!admissionRoute || !executeRoute) throw new Error('registration routes are required');
    const logger = coerceRouterLogger(null);

    const admissionRequest = jsonRequest(
      ROUTER_AB_ED25519_YAO_REGISTRATION_ADMISSION_PATH_V1,
      registrationAdmissionRequest(),
    );
    const admissionResponse = await extension.handleFetchRoute({
      request: admissionRequest,
      route: admissionRoute,
      pathname: admissionRoute.path,
      method: 'POST',
      logger,
      runtime: { kind: 'inline' },
    });
    expect(admissionResponse.status).toBe(200);
    expect(
      parseRouterAbEd25519YaoRegistrationAdmissionReceiptV1(await admissionResponse.json()).ok,
    ).toBe(true);

    const executeRequest = jsonRequest(
      ROUTER_AB_ED25519_YAO_REGISTRATION_EXECUTE_PATH_V1,
      registrationExecuteRequest(),
    );
    const executeResponse = await extension.handleFetchRoute({
      request: executeRequest,
      route: executeRoute,
      pathname: executeRoute.path,
      method: 'POST',
      logger,
      runtime: { kind: 'inline' },
    });
    expect(executeResponse.status).toBe(200);
    expect(parseRouterAbEd25519YaoRegistrationResultV1(await executeResponse.json()).ok).toBe(true);
    expect(authorization.inputs).toHaveLength(2);
    expect(authorization.inputs[0]?.kind).toBe('admit');
    expect(authorization.inputs[1]?.kind).toBe('execute');
  });

  test('rejects a malformed trace ID at the HTTP boundary before authorization or work', async () => {
    const backend = new TestRegistrationBackend(registrationAdmissionReceipt(), {
      kind: 'success',
      body: registrationResult(),
    });
    const service = new InMemoryRouterAbEd25519YaoRegistrationService(backend);
    const authorization = new TestRegistrationAuthorization({ ok: true });
    const module = createRouterAbEd25519YaoRegistrationModule({ service, authorization });
    const extension = module.routeExtensions[0];
    if (!extension) throw new Error('registration route extension is required');
    const route = extension.routes[0];
    if (!route) throw new Error('registration admission route is required');
    const request = jsonRequest(route.path, registrationAdmissionRequest());
    request.headers.set('x-seams-trace-id', 'contains-sensitive-data');
    const response = await extension.handleFetchRoute({
      request,
      route,
      pathname: route.path,
      method: 'POST',
      logger: coerceRouterLogger(null),
      runtime: { kind: 'inline' },
    });
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({
      ok: false,
      code: 'invalid_trace_id',
      message: 'Router trace ID must be 32 lowercase hexadecimal characters',
    });
    expect(authorization.inputs).toHaveLength(0);
    expect(backend.admitCalls).toBe(0);
  });

  test('rejects route authorization before invoking registration work', async () => {
    const backend = new TestRegistrationBackend(registrationAdmissionReceipt(), {
      kind: 'success',
      body: registrationResult(),
    });
    const service = new InMemoryRouterAbEd25519YaoRegistrationService(backend);
    const authorization = new TestRegistrationAuthorization({
      ok: false,
      status: 403,
      code: 'registration_grant_rejected',
      message: 'Registration grant rejected',
    });
    const module = createRouterAbEd25519YaoRegistrationModule({ service, authorization });
    const extension = module.routeExtensions[0];
    const route = extension?.routes[0];
    if (!extension || !route) throw new Error('registration admission route is required');
    const request = jsonRequest(route.path, registrationAdmissionRequest());
    const response = await extension.handleFetchRoute({
      request,
      route,
      pathname: route.path,
      method: 'POST',
      logger: coerceRouterLogger(null),
      runtime: { kind: 'inline' },
    });
    expect(response.status).toBe(403);
    expect(await response.json()).toEqual({
      ok: false,
      code: 'registration_grant_rejected',
      message: 'Registration grant rejected',
    });
    expect(backend.admitCalls).toBe(0);
  });

  test('drives one local MPC Router request for registration', async () => {
    const scriptedFetch = new ScriptedLocalYaoFetch();
    const spans: Array<{
      span: string;
      operation: string;
      outcome: string;
      duration_ms: number;
      trace_id: string;
    }> = [];
    const backend = createRouterAbEd25519YaoHttpRegistrationBackendFromEnv({
      env: {
        MPC_ROUTER_URL: 'http://router.local',
        SIGNING_WORKER_ID: 'signing-worker-1',
        ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET: 'local-service-auth',
        DERIVER_A_ED25519_YAO_INPUT_PUBLIC_KEY: x25519(1),
        DERIVER_B_ED25519_YAO_INPUT_PUBLIC_KEY: x25519(2),
        SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY: x25519(3),
      },
      resolveTenantRoot: testTenantRootResolver,
      onSpan: (span) => spans.push(span),
      fetch: scriptedFetch.fetch.bind(scriptedFetch),
    });

    const admitted = await backend.admit(parsedAdmissionRequest());
    if (!admitted.ok) throw new Error(admitted.message);
    const parsedAdmission = parseRouterAbEd25519YaoRegistrationAdmissionReceiptV1(admitted.body);
    if (!parsedAdmission.ok) throw new Error(parsedAdmission.message);
    scriptedFetch.bindActivation(parsedAdmission.value.binding);

    const rawExecution = {
      binding: parsedAdmission.value.binding,
      deriver_a_input: encryptedInputForBinding(parsedAdmission.value.binding, 'deriver_a'),
      deriver_b_input: encryptedInputForBinding(parsedAdmission.value.binding, 'deriver_b'),
    };
    const parsedExecution = parseRouterAbEd25519YaoRegistrationExecuteRequestV1(rawExecution);
    if (!parsedExecution.ok) throw new Error(parsedExecution.message);

    scriptedFetch.failNextExecute = true;
    const executed = await backend.execute(parsedExecution.value, parsedAdmissionRequest());
    if (!executed.ok) throw new Error(executed.message);
    expect(parseRouterAbEd25519YaoRegistrationResultV1(executed.body).ok).toBe(true);
    expect(scriptedFetch.calls).toEqual([
      'POST /router-ab/router/ed25519-yao/execute',
      'POST /router-ab/router/ed25519-yao/execute',
    ]);
    expect(scriptedFetch.requestUrls.map((url) => new URL(url).origin)).toEqual([
      'http://router.local',
      'http://router.local',
    ]);
    expect(scriptedFetch.requestBodies[0]).toBe(scriptedFetch.requestBodies[1]);
    const routerBody = JSON.parse(scriptedFetch.requestBodies[0]) as Record<string, unknown>;
    expect(routerBody).toEqual({
      tenant_root: {
        identity_digest_b64u: 'tenant-root-identity-digest',
        custody_lineage_b64u: 'tenant-root-custody-lineage',
      },
      application: parsedAdmissionRequest().application_binding,
      participant_ids: parsedAdmissionRequest().participant_ids,
      target: {
        binding: parsedExecution.value.binding,
        deriver_a_input: parsedExecution.value.deriver_a_input,
        deriver_b_input: parsedExecution.value.deriver_b_input,
      },
    });
    expect(scriptedFetch.replayHeaders).toEqual(['', '1']);
    expect(scriptedFetch.traceIds).toHaveLength(2);
    expect(scriptedFetch.traceIds[0]).toBe(scriptedFetch.traceIds[1]);
    expect(scriptedFetch.traceIds[0]).toMatch(/^[0-9a-f]{32}$/);
    expect(spans.map((span) => span.span)).toEqual(['gateway.pre_yao', 'gateway.yao_execute']);
    expect(spans.every((span) => span.operation === 'registration')).toBe(true);
    expect(spans.every((span) => span.outcome === 'success')).toBe(true);
    expect(spans.every((span) => span.duration_ms >= 0)).toBe(true);
    expect(spans.map((span) => span.trace_id)).toEqual([
      scriptedFetch.traceIds[0],
      scriptedFetch.traceIds[0],
    ]);
  });

  test('replays the exact admitted request when the Router response is lost after execution', async () => {
    const scriptedFetch = new ScriptedLocalYaoFetch();
    const backend = createRouterAbEd25519YaoHttpRegistrationBackendFromEnv({
      env: localHttpBackendEnv(),
      resolveTenantRoot: testTenantRootResolver,
      fetch: scriptedFetch.fetch.bind(scriptedFetch),
    });

    const admitted = await backend.admit(parsedAdmissionRequest());
    if (!admitted.ok) throw new Error(admitted.message);
    const parsedAdmission = parseRouterAbEd25519YaoRegistrationAdmissionReceiptV1(admitted.body);
    if (!parsedAdmission.ok) throw new Error(parsedAdmission.message);
    scriptedFetch.bindActivation(parsedAdmission.value.binding);

    const parsedExecution = parseRouterAbEd25519YaoRegistrationExecuteRequestV1({
      binding: parsedAdmission.value.binding,
      deriver_a_input: encryptedInputForBinding(parsedAdmission.value.binding, 'deriver_a'),
      deriver_b_input: encryptedInputForBinding(parsedAdmission.value.binding, 'deriver_b'),
    });
    if (!parsedExecution.ok) throw new Error(parsedExecution.message);

    scriptedFetch.dropNextExecuteResponse = true;
    const executed = await backend.execute(parsedExecution.value, parsedAdmissionRequest());
    if (!executed.ok) throw new Error(executed.message);
    expect(parseRouterAbEd25519YaoRegistrationResultV1(executed.body).ok).toBe(true);
    expect(scriptedFetch.calls).toEqual([
      'POST /router-ab/router/ed25519-yao/execute',
      'POST /router-ab/router/ed25519-yao/execute',
    ]);
    expect(scriptedFetch.requestBodies[0]).toBe(scriptedFetch.requestBodies[1]);
    expect(scriptedFetch.replayHeaders).toEqual(['', '1']);
    expect(scriptedFetch.traceIds).toHaveLength(2);
    expect(scriptedFetch.traceIds[0]).toBe(scriptedFetch.traceIds[1]);
  });

  test('surfaces a burned Router execution without retrying it', async () => {
    const scriptedFetch = new ScriptedLocalYaoFetch();
    scriptedFetch.executionResult = { kind: 'burned', reason: 'protocol_failure' };
    const backend = createRouterAbEd25519YaoHttpRegistrationBackendFromEnv({
      env: localHttpBackendEnv(),
      resolveTenantRoot: testTenantRootResolver,
      fetch: scriptedFetch.fetch.bind(scriptedFetch),
    });

    const admitted = await backend.admit(parsedAdmissionRequest());
    if (!admitted.ok) throw new Error(admitted.message);
    const parsedAdmission = parseRouterAbEd25519YaoRegistrationAdmissionReceiptV1(admitted.body);
    if (!parsedAdmission.ok) throw new Error(parsedAdmission.message);
    scriptedFetch.bindActivation(parsedAdmission.value.binding);

    const parsedExecution = parseRouterAbEd25519YaoRegistrationExecuteRequestV1({
      binding: parsedAdmission.value.binding,
      deriver_a_input: encryptedInputForBinding(parsedAdmission.value.binding, 'deriver_a'),
      deriver_b_input: encryptedInputForBinding(parsedAdmission.value.binding, 'deriver_b'),
    });
    if (!parsedExecution.ok) throw new Error(parsedExecution.message);

    const burned = await backend.execute(parsedExecution.value, parsedAdmissionRequest());
    expect(burned).toEqual({
      ok: false,
      status: 502,
      code: 'router_execution_burned',
      message: 'Router Yao execution was burned',
    });
    expect(scriptedFetch.calls).toEqual(['POST /router-ab/router/ed25519-yao/execute']);
    expect(scriptedFetch.replayHeaders).toEqual(['']);
  });

  test('surfaces ceremony expiry as a terminal new-identity failure', async () => {
    const scriptedFetch = new ScriptedLocalYaoFetch();
    scriptedFetch.executionResult = { kind: 'recoverable', code: 'ceremony_expired' };
    const backend = createRouterAbEd25519YaoHttpRegistrationBackendFromEnv({
      env: localHttpBackendEnv(),
      resolveTenantRoot: testTenantRootResolver,
      fetch: scriptedFetch.fetch.bind(scriptedFetch),
    });

    const admitted = await backend.admit(parsedAdmissionRequest());
    if (!admitted.ok) throw new Error(admitted.message);
    const parsedAdmission = parseRouterAbEd25519YaoRegistrationAdmissionReceiptV1(admitted.body);
    if (!parsedAdmission.ok) throw new Error(parsedAdmission.message);
    scriptedFetch.bindActivation(parsedAdmission.value.binding);

    const parsedExecution = parseRouterAbEd25519YaoRegistrationExecuteRequestV1({
      binding: parsedAdmission.value.binding,
      deriver_a_input: encryptedInputForBinding(parsedAdmission.value.binding, 'deriver_a'),
      deriver_b_input: encryptedInputForBinding(parsedAdmission.value.binding, 'deriver_b'),
    });
    if (!parsedExecution.ok) throw new Error(parsedExecution.message);

    await expect(backend.execute(parsedExecution.value, parsedAdmissionRequest())).resolves.toEqual(
      {
        ok: false,
        status: 409,
        code: 'ceremony_expired',
        message: 'Router Yao ceremony expired; allocate a new ceremony identity',
      },
    );
    expect(scriptedFetch.calls).toEqual(['POST /router-ab/router/ed25519-yao/execute']);
  });

  test('promotes a SigningWorker-owned staged recovery across request-scoped HTTP backends', async () => {
    const scriptedFetch = new ScriptedLocalYaoFetch();
    const executionBackend = createRouterAbEd25519YaoHttpRegistrationBackendFromEnv({
      env: localHttpBackendEnv(),
      resolveTenantRoot: testTenantRootResolver,
      fetch: scriptedFetch.fetch.bind(scriptedFetch),
    });
    const parsedRecoveryAdmission = parseRouterAbEd25519YaoRecoveryAdmissionRequestV1(
      recoveryAdmissionRequest(),
    );
    if (!parsedRecoveryAdmission.ok) throw new Error(parsedRecoveryAdmission.message);
    const admitted = await executionBackend.admitRecovery(parsedRecoveryAdmission.value);
    if (!admitted.ok) throw new Error(admitted.message);
    const parsedAdmission = parseRouterAbEd25519YaoRecoveryActivationAdmissionReceiptV1(
      admitted.body,
    );
    if (!parsedAdmission.ok) throw new Error(parsedAdmission.message);
    scriptedFetch.bindActivation(parsedAdmission.value.binding);

    const parsedExecution = parseRouterAbEd25519YaoRecoveryActivationExecuteRequestV1({
      binding: parsedAdmission.value.binding,
      deriver_a_input: encryptedInputForBinding(parsedAdmission.value.binding, 'deriver_a'),
      deriver_b_input: encryptedInputForBinding(parsedAdmission.value.binding, 'deriver_b'),
    });
    if (!parsedExecution.ok) throw new Error(parsedExecution.message);
    const executed = await executionBackend.executeRecovery(
      parsedExecution.value,
      parsedRecoveryAdmission.value,
    );
    if (!executed.ok) throw new Error(executed.message);
    const parsedResult = parseRouterAbEd25519YaoRecoveryActivationResultV1(executed.body);
    if (!parsedResult.ok) throw new Error(parsedResult.message);
    const parsedActivation = parseRouterAbEd25519YaoRecoveryActivationRequestV1({
      binding: parsedResult.value.binding,
      public_receipt: parsedResult.value.public_receipt,
    });
    if (!parsedActivation.ok) throw new Error(parsedActivation.message);

    const activationBackend = createRouterAbEd25519YaoHttpRegistrationBackendFromEnv({
      env: localHttpBackendEnv(),
      resolveTenantRoot: testTenantRootResolver,
      fetch: scriptedFetch.fetch.bind(scriptedFetch),
    });
    expect(await activationBackend.activateRecovery(parsedActivation.value)).toEqual({
      ok: true,
      body: parsedActivation.value,
    });

    const retryBackend = createRouterAbEd25519YaoHttpRegistrationBackendFromEnv({
      env: localHttpBackendEnv(),
      resolveTenantRoot: testTenantRootResolver,
      fetch: scriptedFetch.fetch.bind(scriptedFetch),
    });
    expect(await retryBackend.activateRecovery(parsedActivation.value)).toEqual({
      ok: true,
      body: parsedActivation.value,
    });
    expect(
      scriptedFetch.calls.filter(
        (call) => call === 'POST /router-ab/router/ed25519-yao/recovery/promote',
      ),
    ).toHaveLength(2);

    const isolatedBackend = createRouterAbEd25519YaoHttpRegistrationBackendFromEnv({
      env: localHttpBackendEnv(),
      resolveTenantRoot: testTenantRootResolver,
      fetch: scriptedFetch.fetch.bind(scriptedFetch),
    });
    expect(await isolatedBackend.activateRecovery(parsedActivation.value)).toEqual({
      ok: true,
      body: parsedActivation.value,
    });
  });

  test('rejects malformed local Router key configuration at the env boundary', () => {
    expect(createMalformedLocalRegistrationBackend).toThrow(
      /SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY/,
    );
  });
});
