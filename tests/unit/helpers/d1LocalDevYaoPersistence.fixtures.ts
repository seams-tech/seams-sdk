import { parseWebAuthnRpId } from '@shared/utils/domainIds';
import {
  parseRouterAbEd25519YaoRegistrationActivationAdmissionReceiptV1,
  parseRouterAbEd25519YaoRegistrationActivationExecuteRequestV1,
  parseRouterAbEd25519YaoRegistrationAdmissionRequestV1,
  type RouterAbEd25519YaoActivationBindingV1,
  type RouterAbEd25519YaoActivationExecuteRequestV1,
} from '@shared/utils/routerAbEd25519Yao';
import {
  registrationIntentGrantFromString,
  walletIdFromString,
  type RegistrationIntentV1,
} from '@shared/utils/registrationIntent';
import type { CfExecutionContext } from '../../../packages/sdk-server-ts/src/router/cloudflare/cloudflare.types';
import { createRouterAbEd25519YaoProductRegistrationPartitionedStateStoreFromD1V1 } from '../../../packages/sdk-server-ts/src/router/routerAbEd25519YaoProductRegistrationPartitionedStateStore';
import { createRouterAbEd25519YaoProductRegistrationRequestScopedRuntimeV1 } from '../../../packages/sdk-server-ts/src/router/routerAbEd25519YaoProductRegistrationRequestScopedRuntime';
import type { D1DatabaseLike } from '../../../packages/sdk-server-ts/src/storage/tenantRoute';
import type { CloudflareServiceBindingFetcher } from '../../../packages/console-server-ts/src/router/cloudflare/routerAbServiceBindings';
import localD1DevWorker from '../../../packages/console-server-ts/src/router/cloudflare/d1LocalDevWorker';
import { UnusedSessionAdapter } from './routerAbEd25519YaoRegistrationBridge.fixtures';

const NAMESPACE = 'seams-local-yao-persistence';
const ORG_ID = 'org_abcdefgh1234';
const PROJECT_ID = 'project-local-yao';
const ENV_ID = 'env-local-yao';
const SIGNING_WORKER_ID = 'signing-worker.local';
const ROOT_SHARE_EPOCH = 'root-local-yao-v1';
const SIGNING_ROOT_ID = `${PROJECT_ID}:${ENV_ID}`;
const EXPIRES_AT_MS = 4_102_444_800_000;

type LocalD1DevWorkerEnv = Parameters<typeof localD1DevWorker.fetch>[1];
type RegistrationBinding = RouterAbEd25519YaoActivationBindingV1<'registration'>;
type RegistrationExecuteRequest = RouterAbEd25519YaoActivationExecuteRequestV1<'registration'>;

type DeferredRouterCall = {
  readonly resolve: (response: Response) => void;
  readonly response: Response;
};

class UnsupportedServiceBinding implements CloudflareServiceBindingFetcher {
  async fetch(): Promise<Response> {
    return Response.json({ ok: false, code: 'unexpected_service_binding' }, { status: 500 });
  }
}

export class LocalYaoRouterBindingFixture implements CloudflareServiceBindingFetcher {
  executeCalls = 0;
  private deferred: DeferredRouterCall | null = null;
  private enteredResolve: (() => void) | null = null;
  private enteredPromise: Promise<void> | null = null;

  deferNextExecute(): void {
    if (this.enteredPromise) throw new Error('Router execute is already deferred');
    this.enteredPromise = new Promise<void>((resolve) => {
      this.enteredResolve = resolve;
    });
  }

  async waitUntilExecuteEntered(): Promise<void> {
    if (!this.enteredPromise) throw new Error('Router execute was not deferred');
    await this.enteredPromise;
  }

  releaseDeferredExecute(): void {
    if (!this.deferred) throw new Error('Deferred Router execute has not entered');
    const deferred = this.deferred;
    this.deferred = null;
    this.enteredPromise = null;
    deferred.resolve(deferred.response);
  }

  async fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
    const request = new Request(input, init);
    if (new URL(request.url).pathname !== '/router-ab/router/ed25519-yao/execute') {
      return Response.json({ ok: false, code: 'unexpected_router_path' }, { status: 404 });
    }
    const body = requireRecord(await request.json(), 'Router execute request');
    if (body.operation !== 'registration') {
      return Response.json({ ok: false, code: 'unexpected_operation' }, { status: 400 });
    }
    const execution = parseRouterAbEd25519YaoRegistrationActivationExecuteRequestV1({
      binding: body.binding,
      deriver_a_input: body.deriver_a_input,
      deriver_b_input: body.deriver_b_input,
    });
    if (!execution.ok) {
      return Response.json({ ok: false, code: execution.code }, { status: 400 });
    }
    this.executeCalls += 1;
    if (!this.enteredResolve) return this.successResponse(execution.value.binding);
    const enteredResolve = this.enteredResolve;
    this.enteredResolve = null;
    enteredResolve();
    return await new Promise<Response>((resolve) => {
      this.deferred = { resolve, response: this.successResponse(execution.value.binding) };
    });
  }

  private successResponse(binding: RegistrationBinding): Response {
    return Response.json({
      status: 'succeeded',
      result: {
        operation: 'registration',
        result: activationResult(binding),
      },
    });
  }
}

export function createLocalYaoWorkerEnv(input: {
  readonly consoleDatabase: D1DatabaseLike;
  readonly signerDatabase: D1DatabaseLike;
  readonly router: LocalYaoRouterBindingFixture;
}): LocalD1DevWorkerEnv {
  const unsupported = new UnsupportedServiceBinding();
  return {
    CONSOLE_DB: input.consoleDatabase,
    SIGNER_DB: input.signerDatabase,
    THRESHOLD_STORE: createUnusedDurableObjectNamespace(),
    MPC_ROUTER: input.router,
    DERIVER_A: unsupported,
    DERIVER_B: unsupported,
    SIGNING_WORKER: unsupported,
    SEAMS_TENANT_STORAGE_NAMESPACE: NAMESPACE,
    SEAMS_LOCAL_CONSOLE_USER_ID: 'local-yao-user',
    SEAMS_LOCAL_CONSOLE_ORG_ID: ORG_ID,
    SEAMS_LOCAL_CONSOLE_PROJECT_ID: PROJECT_ID,
    SEAMS_LOCAL_CONSOLE_ENVIRONMENT_ID: ENV_ID,
    SEAMS_LOCAL_CONSOLE_ROLES: 'owner,admin,developer',
    ROUTER_AB_NORMAL_SIGNING_WORKER_ID: SIGNING_WORKER_ID,
    SIGNING_WORKER_ID,
    ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET: 'local-yao-internal-auth',
    RELAY_SESSION_HMAC_SECRET: 'local-yao-session-secret-at-least-32-bytes',
    DERIVER_A_ED25519_YAO_INPUT_PUBLIC_KEY: `x25519:${'11'.repeat(32)}`,
    DERIVER_B_ED25519_YAO_INPUT_PUBLIC_KEY: `x25519:${'22'.repeat(32)}`,
    DERIVER_A_ENVELOPE_HPKE_KEY_EPOCH: 'epoch-1',
    DERIVER_A_ENVELOPE_HPKE_PUBLIC_KEY: `x25519:${'11'.repeat(32)}`,
    DERIVER_B_ENVELOPE_HPKE_KEY_EPOCH: 'epoch-1',
    DERIVER_B_ENVELOPE_HPKE_PUBLIC_KEY: `x25519:${'22'.repeat(32)}`,
    DERIVER_A_PEER_VERIFYING_KEY_HEX: '33'.repeat(32),
    DERIVER_B_PEER_VERIFYING_KEY_HEX: '44'.repeat(32),
    SIGNING_WORKER_SERVER_OUTPUT_HPKE_KEY_EPOCH: 'epoch-1',
    SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY: `x25519:${'55'.repeat(32)}`,
    ACCOUNT_ID_DERIVATION_SECRET: 'local-yao-account-id-secret',
    ROUTER_AB_CEREMONY_JWT_PRIVATE_JWK: JSON.stringify({
      kty: 'OKP',
      crv: 'Ed25519',
      x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      d: 'AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE',
    }),
    ROUTER_AB_ECDSA_REGISTRATION_TOPOLOGY_JSON: JSON.stringify({
      routerId: 'local-router',
      signerSet: {
        signer_set_id: 'signer-set-v1',
        policy: 'all_2',
        signer_a: { role: 'signer_a', signer_id: 'signer-a', key_epoch: 'epoch-1' },
        signer_b: { role: 'signer_b', signer_id: 'signer-b', key_epoch: 'epoch-1' },
        selected_server: {
          server_id: SIGNING_WORKER_ID,
          key_epoch: 'epoch-1',
          recipient_encryption_key: 'unused-local-recipient-key',
        },
      },
      deriverRecipientKeys: {
        deriver_a: { role: 'signer_a', key_epoch: 'epoch-1', public_key: 'unused-a' },
        deriver_b: { role: 'signer_b', key_epoch: 'epoch-1', public_key: 'unused-b' },
      },
    }),
  };
}

export function buildLocalYaoRegistrationFixture(lifecycleId: string) {
  const walletId = walletIdFromString(`wallet-${lifecycleId}`);
  const grant = registrationIntentGrantFromString(`rig_${lifecycleId}-credential`);
  const admission = parseRouterAbEd25519YaoRegistrationAdmissionRequestV1({
    scope: {
      lifecycle_id: lifecycleId,
      root_share_epoch: ROOT_SHARE_EPOCH,
      account_id: walletId,
      wallet_session_id: `wallet-session-${lifecycleId}`,
      signer_set_id: 'ed25519:1',
      signing_worker_id: SIGNING_WORKER_ID,
    },
    application_binding: {
      wallet_id: walletId,
      near_ed25519_signing_key_id: `ed25519ks_${lifecycleId}`,
      signing_root_id: SIGNING_ROOT_ID,
      key_creation_signer_slot: 1,
    },
    participant_ids: [1, 2],
  });
  if (!admission.ok) throw new Error(admission.message);
  return {
    admission: admission.value,
    grant,
    intent: registrationIntent(walletId),
  };
}

export async function bindLocalYaoRegistrationIntent(input: {
  readonly signerDatabase: D1DatabaseLike;
  readonly fixture: ReturnType<typeof buildLocalYaoRegistrationFixture>;
}): Promise<void> {
  const store = createRouterAbEd25519YaoProductRegistrationPartitionedStateStoreFromD1V1({
    database: input.signerDatabase,
    scope: { namespace: NAMESPACE, orgId: ORG_ID, projectId: PROJECT_ID, envId: ENV_ID },
  });
  const runtime = createRouterAbEd25519YaoProductRegistrationRequestScopedRuntimeV1({
    signingWorkerId: SIGNING_WORKER_ID,
    session: new UnusedSessionAdapter(),
    store,
  });
  const result = await runtime.bindVerifiedIntent({
    kind: 'verified_registration_intent',
    registrationIntentGrant: input.fixture.grant,
    intent: input.fixture.intent,
    admissionRequest: input.fixture.admission,
    expiresAtMs: EXPIRES_AT_MS,
  });
  if (!result.ok) throw new Error(result.message);
}

export function registrationExecuteFromAdmission(
  rawAdmissionReceipt: unknown,
  ciphertextSeed = 9,
): RegistrationExecuteRequest {
  const receipt =
    parseRouterAbEd25519YaoRegistrationActivationAdmissionReceiptV1(rawAdmissionReceipt);
  if (!receipt.ok) throw new Error(receipt.message);
  const binding = receipt.value.binding;
  const execution = parseRouterAbEd25519YaoRegistrationActivationExecuteRequestV1({
    binding,
    deriver_a_input: activationInput(binding, 'deriver_a', ciphertextSeed),
    deriver_b_input: activationInput(binding, 'deriver_b', ciphertextSeed + 1),
  });
  if (!execution.ok) throw new Error(execution.message);
  return execution.value;
}

export async function callLocalYaoWorker(input: {
  readonly env: LocalD1DevWorkerEnv;
  readonly path: string;
  readonly body: unknown;
  readonly grant: string;
}): Promise<Response> {
  return await localD1DevWorker.fetch(
    new Request(`http://127.0.0.1:8787/relay${input.path}`, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${input.grant}`,
        'content-type': 'application/json',
      },
      body: JSON.stringify(input.body),
    }),
    input.env,
    executionContext(),
  );
}

function registrationIntent(walletId: ReturnType<typeof walletIdFromString>): RegistrationIntentV1 {
  const rpId = parseWebAuthnRpId('wallet.local');
  if (!rpId.ok) throw new Error(rpId.error.message);
  return {
    version: 'registration_intent_v1',
    walletId,
    authMethod: { kind: 'passkey', rpId: rpId.value },
    signerSelection: {
      kind: 'signer_set',
      signers: [
        {
          kind: 'near_ed25519',
          accountProvisioning: {
            kind: 'implicit_account',
            accountIdSource: 'ed25519_public_key',
          },
          signerSlot: 1,
          participantIds: [1, 2],
          derivationVersion: 1,
        },
      ],
    },
    nonceB64u: 'local-yao-registration-nonce',
  };
}

function activationInput(
  binding: RegistrationBinding,
  deriver: 'deriver_a' | 'deriver_b',
  ciphertextSeed: number,
) {
  return {
    kind: 'activation',
    deriver,
    operation: 'registration',
    session: binding.session_id,
    stable_context_binding: binding.stable_key_context_binding,
    encapsulated_key: bytes(ciphertextSeed + 10),
    ciphertext: bytes(ciphertextSeed),
  };
}

function activationResult(binding: RegistrationBinding) {
  return {
    binding,
    deriver_a_client_package: activationClientPackage(binding, 'deriver_a', 41),
    deriver_b_client_package: activationClientPackage(binding, 'deriver_b', 51),
    public_receipt: {
      transcript: bytes(61),
      registered_public_key: bytes(62),
      joined_client_commitment: bytes(63),
      joined_signing_worker_commitment: bytes(64),
      signing_worker_verifying_share: bytes(64),
      state_epoch: 1,
    },
  };
}

function activationClientPackage(
  binding: RegistrationBinding,
  deriver: 'deriver_a' | 'deriver_b',
  seed: number,
) {
  return {
    kind: 'activation_client',
    deriver,
    session: binding.session_id,
    transcript: bytes(61),
    encapsulated_key: bytes(seed),
    ciphertext: bytes(seed + 1),
  };
}

function bytes(seed: number): number[] {
  return new Array<number>(32).fill(seed);
}

function requireRecord(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function executionContext(): CfExecutionContext {
  return {
    waitUntil(promise: Promise<unknown>): void {
      void promise;
    },
    passThroughOnException(): void {},
  };
}

function createUnusedDurableObjectNamespace() {
  return {
    idFromName(name: string): string {
      return name;
    },
    get(): { fetch(): Promise<Response> } {
      return {
        async fetch(): Promise<Response> {
          return Response.json(
            { ok: false, code: 'unexpected_durable_object_call' },
            { status: 500 },
          );
        },
      };
    },
  };
}
