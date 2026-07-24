import {
  deriveRouterAbEd25519YaoStableContextBindingV1,
  parseRouterAbEd25519YaoActivationResultV1,
  parseRouterAbEd25519YaoExportResultV1,
  type RouterAbEd25519YaoActivationExecuteRequestV1,
  type RouterAbEd25519YaoCeremonyBindingV1,
  type RouterAbEd25519YaoDeriverRoleV1,
  type RouterAbEd25519YaoEncryptedInputV1,
  type RouterAbEd25519YaoExportBindingV1,
  type RouterAbEd25519YaoRecoveryActivationRequestV1,
  type RouterAbEd25519YaoRecoveryAdmissionRequestV1,
  type RouterAbEd25519YaoRegistrationAdmissionRequestV1,
  type RouterAbEd25519YaoExportAdmissionRequestV1,
  type RouterAbEd25519YaoExportExecuteRequestV1,
  type RouterAbEd25519YaoRouterExecuteRequestV1,
} from '@shared/utils/routerAbEd25519Yao';
import type {
  RouterAbEd25519YaoRegistrationBackend,
  RouterAbEd25519YaoRegistrationBackendFailure,
  RouterAbEd25519YaoRegistrationBackendResult,
} from './routerAbEd25519YaoRegistration';
import type { RouterAbEd25519YaoExportBackend } from './routerAbEd25519YaoExport';

type RouterAbEd25519YaoRegistrationExecuteRequestV1 =
  RouterAbEd25519YaoActivationExecuteRequestV1<'registration'>;
type RouterAbEd25519YaoRecoveryExecuteRequestV1 =
  RouterAbEd25519YaoActivationExecuteRequestV1<'recovery'>;

const INTERNAL_AUTH_HEADER = 'x-router-ab-internal-service-auth';
const TRACE_ID_HEADER = 'x-seams-trace-id';
const ROUTER_EXECUTE_PATH = '/router-ab/router/ed25519-yao/execute';
const ROUTER_RECOVERY_PROMOTE_PATH = '/router-ab/router/ed25519-yao/recovery/promote';

const ROUTER_AB_ENV_KEYS = {
  routerUrl: 'MPC_ROUTER_URL',
  signingWorkerId: 'SIGNING_WORKER_ID',
  internalServiceAuth: 'ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET',
  deriverAInputPublicKey: 'DERIVER_A_ED25519_YAO_INPUT_PUBLIC_KEY',
  deriverBInputPublicKey: 'DERIVER_B_ED25519_YAO_INPUT_PUBLIC_KEY',
  signingWorkerRecipientPublicKey: 'SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY',
} as const;

export type RouterAbEd25519YaoHttpRegistrationBackendConfig = {
  routerUrl: string;
  signingWorkerId: string;
  internalServiceAuth: string;
  deriverAInputPublicKey: readonly number[];
  deriverBInputPublicKey: readonly number[];
  signingWorkerRecipientPublicKey: readonly number[];
  fetch: typeof fetch;
};

export type RouterAbEd25519YaoHttpRegistrationBackendRawEnv = Readonly<Record<string, unknown>>;

type ValidatedHttpBackendConfig = {
  routerUrl: string;
  signingWorkerId: string;
  internalServiceAuth: string;
  deriverAInputPublicKey: readonly number[];
  deriverBInputPublicKey: readonly number[];
  signingWorkerRecipientPublicKey: readonly number[];
  fetch: typeof fetch;
};

type HttpSuccess = { ok: true; body: unknown };
type HttpResult = HttpSuccess | RouterAbEd25519YaoRegistrationBackendFailure;

type ActiveSigningWorkerReceipt = {
  session: readonly number[];
  transcript: readonly number[];
  registeredPublicKey: readonly number[];
  joinedClientCommitment: readonly number[];
  joinedSigningWorkerCommitment: readonly number[];
  signingWorkerVerifyingShare: readonly number[];
  stateEpoch: number;
};

function requireRecord(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function requireExactKeys(
  record: Record<string, unknown>,
  label: string,
  allowedKeys: readonly string[],
): void {
  const allowed = new Set(allowedKeys);
  for (const key of Object.keys(record)) {
    if (!allowed.has(key)) throw new Error(`${label}.${key} is not supported`);
  }
  for (const key of allowedKeys) {
    if (!Object.hasOwn(record, key)) throw new Error(`${label}.${key} is required`);
  }
}

function requireNonEmpty(value: unknown, label: string): string {
  if (typeof value !== 'string' || value.length === 0) throw new Error(`${label} is required`);
  return value;
}

function requireHttpOrigin(value: unknown, label: string): string {
  const parsed = new URL(requireNonEmpty(value, label));
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error(`${label} must use HTTP or HTTPS`);
  }
  if (parsed.pathname !== '/' || parsed.search || parsed.hash) {
    throw new Error(`${label} must contain only an origin`);
  }
  return parsed.origin;
}

function requireByte(value: unknown, label: string): number {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 0 || value > 255) {
    throw new Error(`${label} must be a byte`);
  }
  return value;
}

function requireBytes32(value: unknown, label: string): number[] {
  if (!Array.isArray(value) || value.length !== 32) {
    throw new Error(`${label} must contain 32 bytes`);
  }
  const parsed: number[] = [];
  let nonzero = false;
  for (let index = 0; index < value.length; index += 1) {
    const byte = requireByte(value[index], `${label}[${index}]`);
    parsed.push(byte);
    if (byte !== 0) nonzero = true;
  }
  if (!nonzero) throw new Error(`${label} must be nonzero`);
  return parsed;
}

function equalBytes(left: readonly number[], right: readonly number[]): boolean {
  if (left.length !== right.length) return false;
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) return false;
  }
  return true;
}

function hexToBytes32(value: unknown, label: string): number[] {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) {
    throw new Error(`${label} must be canonical 32-byte lowercase hex`);
  }
  const bytes: number[] = [];
  for (let index = 0; index < value.length; index += 2) {
    bytes.push(Number.parseInt(value.slice(index, index + 2), 16));
  }
  return bytes;
}

function x25519PublicKeyFromEnv(value: unknown, label: string): number[] {
  const encoded = requireNonEmpty(value, label);
  if (!encoded.startsWith('x25519:')) throw new Error(`${label} must use x25519:<hex>`);
  return requireBytes32(hexToBytes32(encoded.slice('x25519:'.length), label), label);
}

function envValue(env: RouterAbEd25519YaoHttpRegistrationBackendRawEnv, key: string): unknown {
  if (!Object.hasOwn(env, key)) throw new Error(`${key} is required`);
  return env[key];
}

function requirePositiveSafeInteger(value: unknown, label: string): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`${label} must be a positive safe integer`);
  }
  return value;
}

function randomSession(): number[] {
  const bytes = new Uint8Array(32);
  do {
    globalThis.crypto.getRandomValues(bytes);
  } while (isZero(bytes));
  return Array.from(bytes);
}

function randomTraceId(): string {
  const bytes = new Uint8Array(16);
  globalThis.crypto.getRandomValues(bytes);
  let traceId = '';
  for (const byte of bytes) traceId += byte.toString(16).padStart(2, '0');
  return traceId;
}

function isZero(bytes: Uint8Array): boolean {
  for (const byte of bytes) {
    if (byte !== 0) return false;
  }
  return true;
}

function validateConfig(
  input: RouterAbEd25519YaoHttpRegistrationBackendConfig,
): ValidatedHttpBackendConfig {
  const deriverAInputPublicKey = requireBytes32(
    input.deriverAInputPublicKey,
    'deriverAInputPublicKey',
  );
  const deriverBInputPublicKey = requireBytes32(
    input.deriverBInputPublicKey,
    'deriverBInputPublicKey',
  );
  const signingWorkerRecipientPublicKey = requireBytes32(
    input.signingWorkerRecipientPublicKey,
    'signingWorkerRecipientPublicKey',
  );
  if (
    equalBytes(deriverAInputPublicKey, deriverBInputPublicKey) ||
    equalBytes(deriverAInputPublicKey, signingWorkerRecipientPublicKey) ||
    equalBytes(deriverBInputPublicKey, signingWorkerRecipientPublicKey)
  ) {
    throw new Error('Ed25519 Yao recipient keys must be distinct');
  }
  if (typeof input.fetch !== 'function') throw new Error('fetch is required');
  return {
    routerUrl: requireHttpOrigin(input.routerUrl, 'routerUrl'),
    signingWorkerId: requireNonEmpty(input.signingWorkerId, 'signingWorkerId'),
    internalServiceAuth: requireNonEmpty(input.internalServiceAuth, 'internalServiceAuth'),
    deriverAInputPublicKey,
    deriverBInputPublicKey,
    signingWorkerRecipientPublicKey,
    fetch: input.fetch,
  };
}

function internalFailure(
  code: string,
  message: string,
): RouterAbEd25519YaoRegistrationBackendFailure {
  return { ok: false, status: 502, code, message };
}

function unavailableFailure(error: unknown): RouterAbEd25519YaoRegistrationBackendFailure {
  return {
    ok: false,
    status: 503,
    code: 'worker_unavailable',
    message: error instanceof Error ? error.message : String(error),
  };
}

function parseSigningWorkerReceipt(
  value: unknown,
  session: readonly number[],
  transcript: readonly number[],
  expectedStatus: 'active' | 'staged',
): ActiveSigningWorkerReceipt {
  const label = `${expectedStatus} SigningWorker receipt`;
  const record = requireRecord(value, label);
  requireExactKeys(record, label, [
    'status',
    'session',
    'transcript',
    'registered_public_key',
    'joined_client_commitment',
    'joined_signing_worker_commitment',
    'signing_worker_verifying_share',
    'state_epoch',
  ]);
  if (record.status !== expectedStatus) {
    throw new Error(`SigningWorker did not return a ${expectedStatus} receipt`);
  }
  const parsedSession = requireBytes32(record.session, `${label} session`);
  const parsedTranscript = requireBytes32(record.transcript, `${label} transcript`);
  if (!equalBytes(parsedSession, session) || !equalBytes(parsedTranscript, transcript)) {
    throw new Error(`${label} does not match the ceremony`);
  }
  const receipt = {
    session: parsedSession,
    transcript: parsedTranscript,
    registeredPublicKey: requireBytes32(
      record.registered_public_key,
      `${label} registered_public_key`,
    ),
    joinedClientCommitment: requireBytes32(
      record.joined_client_commitment,
      `${label} joined_client_commitment`,
    ),
    joinedSigningWorkerCommitment: requireBytes32(
      record.joined_signing_worker_commitment,
      `${label} joined_signing_worker_commitment`,
    ),
    signingWorkerVerifyingShare: requireBytes32(
      record.signing_worker_verifying_share,
      `${label} signing_worker_verifying_share`,
    ),
    stateEpoch: requirePositiveSafeInteger(record.state_epoch, `${label} state_epoch`),
  };
  if (!equalBytes(receipt.signingWorkerVerifyingShare, receipt.joinedSigningWorkerCommitment)) {
    throw new Error(`${label} verifying share does not match its commitment`);
  }
  return receipt;
}

function parseActiveSigningWorkerReceipt(
  value: unknown,
  session: readonly number[],
  transcript: readonly number[],
): ActiveSigningWorkerReceipt {
  return parseSigningWorkerReceipt(value, session, transcript, 'active');
}

function activeReceiptMatchesRecoveryActivation(
  receipt: ActiveSigningWorkerReceipt,
  activation: RouterAbEd25519YaoRecoveryActivationRequestV1,
): boolean {
  const publicReceipt = activation.public_receipt;
  return (
    equalBytes(receipt.session, activation.binding.session_id) &&
    equalBytes(receipt.transcript, publicReceipt.transcript) &&
    equalBytes(receipt.registeredPublicKey, publicReceipt.registered_public_key) &&
    equalBytes(receipt.joinedClientCommitment, publicReceipt.joined_client_commitment) &&
    equalBytes(
      receipt.joinedSigningWorkerCommitment,
      publicReceipt.joined_signing_worker_commitment,
    ) &&
    equalBytes(receipt.signingWorkerVerifyingShare, publicReceipt.signing_worker_verifying_share) &&
    receipt.stateEpoch === publicReceipt.state_epoch
  );
}

type RouterExecuteBoundary = RouterAbEd25519YaoRouterExecuteRequestV1;

type RouterExecuteInput =
  | RouterAbEd25519YaoRegistrationExecuteRequestV1
  | RouterAbEd25519YaoRecoveryExecuteRequestV1
  | RouterAbEd25519YaoExportExecuteRequestV1;

function isExportExecuteRequest(
  request: RouterExecuteInput,
): request is RouterAbEd25519YaoExportExecuteRequestV1 {
  return 'ceremony' in request.binding;
}

function executeOperation(request: RouterExecuteInput): 'registration' | 'recovery' | 'export' {
  return isExportExecuteRequest(request) ? request.binding.ceremony.operation : request.binding.operation;
}

const TEXT_ENCODER = new TextEncoder();

async function sha256Bytes(value: Uint8Array): Promise<number[]> {
  const digest = await globalThis.crypto.subtle.digest('SHA-256', value);
  return Array.from(new Uint8Array(digest));
}

function concatBytes(chunks: readonly Uint8Array[]): Uint8Array {
  const output = new Uint8Array(chunks.reduce((size, chunk) => size + chunk.length, 0));
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.length;
  }
  return output;
}

function u32(value: number): Uint8Array {
  const output = new Uint8Array(4);
  new DataView(output.buffer).setUint32(0, value, false);
  return output;
}

function pushString(value: string): Uint8Array {
  const encoded = TEXT_ENCODER.encode(value);
  return concatBytes([u32(encoded.length), encoded]);
}

function operationTag(operation: RouterAbEd25519YaoOperationV1): number {
  switch (operation) {
    case 'registration':
      return 1;
    case 'recovery':
      return 2;
    case 'refresh':
      return 3;
    case 'export':
      return 4;
  }
}

function inputTag(input: RouterAbEd25519YaoEncryptedInputV1): number {
  return input.kind === 'activation' ? 1 : 2;
}

function roleTag(role: RouterAbEd25519YaoDeriverRoleV1): number {
  return role === 'deriver_a' ? 1 : 2;
}

async function encryptedInputDigest(
  input: RouterAbEd25519YaoEncryptedInputV1,
): Promise<number[]> {
  const ciphertext = Uint8Array.from(input.ciphertext);
  return await sha256Bytes(
    concatBytes([
      TEXT_ENCODER.encode('router-ab-ed25519-yao/input/v1'),
      Uint8Array.of(inputTag(input), roleTag(input.deriver), operationTag(input.operation)),
      Uint8Array.from(input.session),
      Uint8Array.from(input.stable_context_binding),
      Uint8Array.from(input.encapsulated_key),
      u32(ciphertext.length),
      ciphertext,
    ]),
  );
}

function ceremonyIdentityBytes(binding: RouterAbEd25519YaoCeremonyBindingV1): Uint8Array {
  const circuit =
    binding.operation === 'export' ? 'ed25519_yao_export_v1' : 'ed25519_yao_activation_v1';
  return concatBytes([
    TEXT_ENCODER.encode('router_ab_ed25519_yao_v1'),
    Uint8Array.of(0),
    TEXT_ENCODER.encode(circuit),
    Uint8Array.of(0),
    pushString(binding.lifecycle.lifecycle_id),
    pushString(binding.lifecycle.work_kind),
    pushString(binding.lifecycle.primitive_request_kind),
    pushString(binding.lifecycle.root_share_epoch),
    pushString(binding.lifecycle.account_id),
    pushString(binding.lifecycle.session_id),
    pushString(binding.lifecycle.signer_set_id),
    pushString(binding.lifecycle.selected_server_id),
    Uint8Array.of(operationTag(binding.operation)),
    Uint8Array.from(binding.session_id),
    Uint8Array.from(binding.stable_key_context_binding),
  ]);
}

async function routerExecuteRequest(
  request: RouterExecuteInput,
  keyset: {
    deriver_a_input_public_key: readonly number[];
    deriver_b_input_public_key: readonly number[];
    signing_worker_recipient_public_key: readonly number[];
  },
): Promise<RouterExecuteBoundary> {
  const operation = executeOperation(request);
  const ceremony = isExportExecuteRequest(request) ? request.binding.ceremony : request.binding;
  const authorizationDigest =
    operation === 'export'
      ? request.binding.authorization_digest
      : await sha256Bytes(
          concatBytes([
            TEXT_ENCODER.encode('router-ab-ed25519-yao/authorization/v1'),
            TEXT_ENCODER.encode(JSON.stringify(request)),
          ]),
        );
  const recipientSetDigest = await sha256Bytes(
    concatBytes([
      Uint8Array.from(keyset.deriver_a_input_public_key),
      Uint8Array.from(keyset.deriver_b_input_public_key),
      Uint8Array.from(keyset.signing_worker_recipient_public_key),
    ]),
  );
  const deriverAInput = request.deriver_a_input;
  const deriverBInput = request.deriver_b_input;
  const deriverAInputDigest = await encryptedInputDigest(deriverAInput);
  const deriverBInputDigest = await encryptedInputDigest(deriverBInput);
  const pairDigest = await sha256Bytes(
    concatBytes([
      TEXT_ENCODER.encode('router-ab-ed25519-yao/input-pair/v1'),
      ceremonyIdentityBytes(ceremony),
      Uint8Array.from(deriverAInputDigest),
      Uint8Array.from(deriverBInputDigest),
      Uint8Array.from(recipientSetDigest),
      Uint8Array.from(authorizationDigest),
    ]),
  );
  const issuedAt = Date.now();
  const authorityDigest = authorizationDigest;
  const pair_binding = {
    ceremony: {
      binding: ceremony,
      circuit: operation === 'export' ? ('export_v1' as const) : ('activation_v1' as const),
      protocol: 'v1' as const,
    },
    deriver_a_input_digest: { bytes: deriverAInputDigest },
    deriver_b_input_digest: { bytes: deriverBInputDigest },
    recipient_set_digest: { bytes: recipientSetDigest },
    authorization_digest: { bytes: authorizationDigest },
    pair_digest: { bytes: pairDigest },
  };
  const authority = {
    authority_digest: { bytes: authorityDigest },
    issued_at_ms: issuedAt,
    expires_at_ms: issuedAt + 60_000,
  };
  if (isExportExecuteRequest(request)) {
    return {
      operation: 'export',
      authority,
      binding: request.binding,
      pair_binding,
      deriver_a_input: request.deriver_a_input,
      deriver_b_input: request.deriver_b_input,
    };
  }
  switch (request.binding.operation) {
    case 'registration':
      return {
        operation: 'registration',
        authority,
        binding: request.binding,
        pair_binding,
        deriver_a_input: request.deriver_a_input,
        deriver_b_input: request.deriver_b_input,
      };
    case 'recovery':
      return {
        operation: 'recovery',
        authority,
        binding: request.binding,
        pair_binding,
        deriver_a_input: request.deriver_a_input,
        deriver_b_input: request.deriver_b_input,
      };
  }
}

function parseRouterExecuteResult(
  value: unknown,
  request: RouterExecuteInput,
): RouterAbEd25519YaoRegistrationBackendResult {
  try {
    const envelope = requireRecord(value, 'Router Yao execute result');
    switch (envelope.status) {
      case 'recoverable_failure': {
        requireExactKeys(envelope, 'Router Yao recoverable failure', [
          'status',
          'code',
          'retry_after_ms',
        ]);
        if (
          typeof envelope.code !== 'string' ||
          ![
            'service_unavailable',
            'conflicting_pair',
            'missing_preparation',
            'ceremony_expired',
            'signing_worker_uncertain',
            'terminal_role_failure',
            'authorization_rejected',
          ].includes(envelope.code)
        ) {
          throw new Error('Router Yao recoverable failure code is invalid');
        }
        requirePositiveSafeInteger(envelope.retry_after_ms, 'Router Yao retry_after_ms');
        return internalFailure('router_execution_retryable', 'Router Yao execution is retryable');
      }
      case 'rejected': {
        requireExactKeys(envelope, 'Router Yao rejected result', ['status', 'code']);
        if (typeof envelope.code !== 'string' || envelope.code.length === 0) {
          throw new Error('Router Yao rejection code is invalid');
        }
        return internalFailure('router_execution_rejected', 'Router Yao execution was rejected');
      }
      case 'burned': {
        requireExactKeys(envelope, 'Router Yao burned result', [
          'status',
          'execution_id',
          'reason',
        ]);
        requireBytes32(envelope.execution_id, 'Router Yao burned execution_id');
        if (!['caller_disconnected', 'peer_uncertain', 'protocol_failure'].includes(String(envelope.reason))) {
          throw new Error('Router Yao burned reason is invalid');
        }
        return internalFailure('router_execution_burned', 'Router Yao execution was burned');
      }
      case 'succeeded':
        break;
      default:
        throw new Error('Router Yao result status is invalid');
    }
    requireExactKeys(envelope, 'Router Yao execute result', ['status', 'result']);
    const result = requireRecord(envelope.result, 'Router Yao success');
    requireExactKeys(result, 'Router Yao success', ['operation', 'result']);
    const operation = executeOperation(request);
    if (result.operation !== operation) {
      return internalFailure('operation_mismatch', 'Router Yao result operation differs from request');
    }
    switch (operation) {
      case 'registration': {
        const parsed = parseRouterAbEd25519YaoActivationResultV1(result.result);
        if (!parsed.ok || parsed.value.binding.operation !== 'registration') {
          return internalFailure('invalid_router_result', 'Router registration result is invalid');
        }
        return { ok: true, body: parsed.value };
      }
      case 'recovery': {
        const parsed = parseRouterAbEd25519YaoActivationResultV1(result.result);
        if (!parsed.ok || parsed.value.binding.operation !== 'recovery') {
          return internalFailure('invalid_router_result', 'Router recovery result is invalid');
        }
        return { ok: true, body: parsed.value };
      }
      case 'export': {
        const parsed = parseRouterAbEd25519YaoExportResultV1(result.result);
        if (!parsed.ok) {
          return internalFailure('invalid_router_result', 'Router export result is invalid');
        }
        return { ok: true, body: parsed.value };
      }
    }
  } catch (error: unknown) {
    return internalFailure(
      'invalid_router_result',
      error instanceof Error ? error.message : String(error),
    );
  }
}

export class RouterAbEd25519YaoHttpRegistrationBackend
  implements RouterAbEd25519YaoRegistrationBackend, RouterAbEd25519YaoExportBackend
{
  private readonly config: ValidatedHttpBackendConfig;

  constructor(config: RouterAbEd25519YaoHttpRegistrationBackendConfig) {
    this.config = validateConfig(config);
  }

  async admit(
    request: RouterAbEd25519YaoRegistrationAdmissionRequestV1,
  ): Promise<RouterAbEd25519YaoRegistrationBackendResult> {
    return await this.admitActivation(request, 'registration');
  }

  async admitRecovery(
    request: RouterAbEd25519YaoRecoveryAdmissionRequestV1,
  ): Promise<RouterAbEd25519YaoRegistrationBackendResult> {
    return await this.admitActivation(request, 'recovery');
  }

  async admitExport(
    request: RouterAbEd25519YaoExportAdmissionRequestV1,
  ): Promise<RouterAbEd25519YaoRegistrationBackendResult> {
    if (request.scope.signing_worker_id !== this.config.signingWorkerId) {
      return {
        ok: false,
        status: 400,
        code: 'signing_worker_mismatch',
        message: 'export scope selects a different SigningWorker',
      };
    }
    const stableContextBinding = await deriveRouterAbEd25519YaoStableContextBindingV1(
      request.application_binding,
      request.participant_ids,
    );
    return {
      ok: true,
      body: {
        binding: {
          ceremony: {
            lifecycle: {
              lifecycle_id: request.scope.lifecycle_id,
              work_kind: 'key_export',
              primitive_request_kind: 'export',
              root_share_epoch: request.scope.root_share_epoch,
              account_id: request.scope.account_id,
              session_id: request.scope.wallet_session_id,
              signer_set_id: request.scope.signer_set_id,
              selected_server_id: request.scope.signing_worker_id,
            },
            operation: 'export',
            session_id: randomSession(),
            stable_key_context_binding: stableContextBinding,
          },
          registered_public_key: request.registered_public_key,
          state_epoch: request.state_epoch,
          runtime_policy_binding: request.runtime_policy_binding,
          authorization_digest: request.authorization.authorization_digest,
        },
        keyset: {
          deriver_a_input_public_key: this.config.deriverAInputPublicKey,
          deriver_b_input_public_key: this.config.deriverBInputPublicKey,
          signing_worker_recipient_public_key: this.config.signingWorkerRecipientPublicKey,
        },
      },
    };
  }

  async executeExport(
    request: RouterAbEd25519YaoExportExecuteRequestV1,
  ): Promise<RouterAbEd25519YaoRegistrationBackendResult> {
    try {
      const routerRequest = await routerExecuteRequest(request, this.keyset());
      const response = await this.post(ROUTER_EXECUTE_PATH, routerRequest, randomTraceId());
      return response.ok ? parseRouterExecuteResult(response.body, request) : response;
    } catch (error: unknown) {
      return unavailableFailure(error);
    }
  }

  private keyset() {
    return {
      deriver_a_input_public_key: this.config.deriverAInputPublicKey,
      deriver_b_input_public_key: this.config.deriverBInputPublicKey,
      signing_worker_recipient_public_key: this.config.signingWorkerRecipientPublicKey,
    };
  }

  private async admitActivation(
    request:
      | RouterAbEd25519YaoRegistrationAdmissionRequestV1
      | RouterAbEd25519YaoRecoveryAdmissionRequestV1,
    operation: 'registration' | 'recovery',
  ): Promise<RouterAbEd25519YaoRegistrationBackendResult> {
    if (request.scope.signing_worker_id !== this.config.signingWorkerId) {
      return {
        ok: false,
        status: 400,
        code: 'signing_worker_mismatch',
        message: `${operation} scope selects a different SigningWorker`,
      };
    }
    const stableContextBinding = await deriveRouterAbEd25519YaoStableContextBindingV1(
      request.application_binding,
      request.participant_ids,
    );
    const keyset = this.keyset();
    const sessionId = randomSession();
    switch (operation) {
      case 'registration':
        return {
          ok: true,
          body: {
            binding: {
              lifecycle: {
                lifecycle_id: request.scope.lifecycle_id,
                work_kind: 'registration_prepare',
                primitive_request_kind: 'registration',
                root_share_epoch: request.scope.root_share_epoch,
                account_id: request.scope.account_id,
                session_id: request.scope.wallet_session_id,
                signer_set_id: request.scope.signer_set_id,
                selected_server_id: request.scope.signing_worker_id,
              },
              operation: 'registration',
              session_id: sessionId,
              stable_key_context_binding: stableContextBinding,
            },
            keyset,
          },
        };
      case 'recovery':
        return {
          ok: true,
          body: {
            binding: {
              lifecycle: {
                lifecycle_id: request.scope.lifecycle_id,
                work_kind: 'recovery',
                primitive_request_kind: 'recovery',
                root_share_epoch: request.scope.root_share_epoch,
                account_id: request.scope.account_id,
                session_id: request.scope.wallet_session_id,
                signer_set_id: request.scope.signer_set_id,
                selected_server_id: request.scope.signing_worker_id,
              },
              operation: 'recovery',
              session_id: sessionId,
              stable_key_context_binding: stableContextBinding,
            },
            keyset,
          },
        };
    }
  }

  async execute(
    request: RouterAbEd25519YaoRegistrationExecuteRequestV1,
  ): Promise<RouterAbEd25519YaoRegistrationBackendResult> {
    return await this.executeActivation(request);
  }

  async executeRecovery(
    request: RouterAbEd25519YaoRecoveryExecuteRequestV1,
  ): Promise<RouterAbEd25519YaoRegistrationBackendResult> {
    return await this.executeActivation(request);
  }

  private async executeActivation(
    request: RouterAbEd25519YaoRegistrationExecuteRequestV1 | RouterAbEd25519YaoRecoveryExecuteRequestV1,
  ): Promise<RouterAbEd25519YaoRegistrationBackendResult> {
    try {
      const routerRequest = await routerExecuteRequest(request, this.keyset());
      const response = await this.post(ROUTER_EXECUTE_PATH, routerRequest, randomTraceId());
      return response.ok ? parseRouterExecuteResult(response.body, request) : response;
    } catch (error: unknown) {
      return unavailableFailure(error);
    }
  }

  async activateRecovery(
    request: RouterAbEd25519YaoRecoveryActivationRequestV1,
  ): Promise<RouterAbEd25519YaoRegistrationBackendResult> {
    const promoted = await this.post(ROUTER_RECOVERY_PROMOTE_PATH, request, randomTraceId());
    if (!promoted.ok) return promoted;
    const activeReceipt = parseActiveSigningWorkerReceipt(
      promoted.body,
      request.binding.session_id,
      request.public_receipt.transcript,
    );
    if (!activeReceiptMatchesRecoveryActivation(activeReceipt, request)) {
      return internalFailure(
        'recovery_promotion_mismatch',
        'Router promotion receipt does not match the verified recovery result',
      );
    }
    return { ok: true, body: request };
  }

  private async post(path: string, body: unknown, traceId: string): Promise<HttpResult> {
    return await this.request(this.config.routerUrl, path, {
      method: 'POST',
      headers: this.headers(traceId),
      body: JSON.stringify(body),
    });
  }

  private headers(traceId: string): Record<string, string> {
    return {
      'content-type': 'application/json',
      [INTERNAL_AUTH_HEADER]: this.config.internalServiceAuth,
      [TRACE_ID_HEADER]: traceId,
    };
  }

  private async request(baseUrl: string, path: string, init: RequestInit): Promise<HttpResult> {
    const response = await this.config.fetch.call(globalThis, `${baseUrl}${path}`, init);
    const text = await response.text();
    if (!response.ok) {
      return internalFailure(
        'worker_rejected',
        `worker ${path} returned HTTP ${response.status}`,
      );
    }
    let body: unknown;
    try {
      body = text ? JSON.parse(text) : null;
    } catch {
      return internalFailure(
        'worker_invalid_json',
        `worker ${path} returned HTTP ${response.status} with invalid JSON`,
      );
    }
    return { ok: true, body };
  }
}

export function createRouterAbEd25519YaoHttpRegistrationBackendFromEnv(input: {
  env: RouterAbEd25519YaoHttpRegistrationBackendRawEnv;
  fetch: typeof fetch;
}): RouterAbEd25519YaoHttpRegistrationBackend {
  const env = input.env;
  return new RouterAbEd25519YaoHttpRegistrationBackend({
    routerUrl: requireNonEmpty(envValue(env, ROUTER_AB_ENV_KEYS.routerUrl), ROUTER_AB_ENV_KEYS.routerUrl),
    signingWorkerId: requireNonEmpty(
      envValue(env, ROUTER_AB_ENV_KEYS.signingWorkerId),
      ROUTER_AB_ENV_KEYS.signingWorkerId,
    ),
    internalServiceAuth: requireNonEmpty(
      envValue(env, ROUTER_AB_ENV_KEYS.internalServiceAuth),
      ROUTER_AB_ENV_KEYS.internalServiceAuth,
    ),
    deriverAInputPublicKey: x25519PublicKeyFromEnv(
      envValue(env, ROUTER_AB_ENV_KEYS.deriverAInputPublicKey),
      ROUTER_AB_ENV_KEYS.deriverAInputPublicKey,
    ),
    deriverBInputPublicKey: x25519PublicKeyFromEnv(
      envValue(env, ROUTER_AB_ENV_KEYS.deriverBInputPublicKey),
      ROUTER_AB_ENV_KEYS.deriverBInputPublicKey,
    ),
    signingWorkerRecipientPublicKey: x25519PublicKeyFromEnv(
      envValue(env, ROUTER_AB_ENV_KEYS.signingWorkerRecipientPublicKey),
      ROUTER_AB_ENV_KEYS.signingWorkerRecipientPublicKey,
    ),
    fetch: input.fetch,
  });
}
