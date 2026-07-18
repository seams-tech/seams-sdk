import {
  deriveRouterAbEd25519YaoStableContextBindingV1,
  parseRouterAbEd25519YaoEncryptedPackageV1,
  type RouterAbEd25519YaoActivationExecuteRequestV1,
  type RouterAbEd25519YaoActivationBindingV1,
  type RouterAbEd25519YaoCeremonyBindingV1,
  type RouterAbEd25519YaoDeriverRoleV1,
  type RouterAbEd25519YaoEncryptedPackageV1,
  type RouterAbEd25519YaoPackageKindV1,
  type RouterAbEd25519YaoRecoveryActivationRequestV1,
  type RouterAbEd25519YaoRecoveryAdmissionRequestV1,
  type RouterAbEd25519YaoRegistrationAdmissionRequestV1,
  type RouterAbEd25519YaoExportAdmissionRequestV1,
  type RouterAbEd25519YaoExportExecuteRequestV1,
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
const DERIVER_B_STAGE_PATH = '/router-ab/deriver-b/ed25519-yao/activation/stage';
const DERIVER_A_START_PATH = '/router-ab/deriver-a/ed25519-yao/activation/start';
const DERIVER_B_ACTIVATION_RESULT_PATH = '/router-ab/deriver-b/ed25519-yao/activation/result';
const SIGNING_WORKER_DERIVER_A_PATH = '/router-ab/signing-worker/ed25519-yao/activation/deriver-a';
const SIGNING_WORKER_DERIVER_B_PATH = '/router-ab/signing-worker/ed25519-yao/activation/deriver-b';
const SIGNING_WORKER_RECOVERY_PROMOTE_PATH =
  '/router-ab/signing-worker/ed25519-yao/recovery/promote';
const DERIVER_B_EXPORT_STAGE_PATH = '/router-ab/deriver-b/ed25519-yao/export/stage';
const DERIVER_A_EXPORT_START_PATH = '/router-ab/deriver-a/ed25519-yao/export/start';
const DERIVER_B_EXPORT_RESULT_PATH = '/router-ab/deriver-b/ed25519-yao/export/result';

const ROUTER_AB_ENV_KEYS = {
  deriverAUrl: 'DERIVER_A_URL',
  deriverBUrl: 'DERIVER_B_URL',
  signingWorkerUrl: 'SIGNING_WORKER_URL',
  signingWorkerId: 'SIGNING_WORKER_ID',
  internalServiceAuth: 'ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET',
  deriverAInputPublicKey: 'DERIVER_A_ED25519_YAO_INPUT_PUBLIC_KEY',
  deriverBInputPublicKey: 'DERIVER_B_ED25519_YAO_INPUT_PUBLIC_KEY',
  signingWorkerRecipientPublicKey: 'SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY',
} as const;

export type RouterAbEd25519YaoHttpRegistrationBackendConfig = {
  deriverAUrl: string;
  deriverBUrl: string;
  signingWorkerUrl: string;
  signingWorkerId: string;
  internalServiceAuth: string;
  deriverAInputPublicKey: readonly number[];
  deriverBInputPublicKey: readonly number[];
  signingWorkerRecipientPublicKey: readonly number[];
  fetch: typeof fetch;
};

export type RouterAbEd25519YaoHttpRegistrationBackendRawEnv = Readonly<Record<string, unknown>>;

type ValidatedHttpBackendConfig = {
  deriverAUrl: string;
  deriverBUrl: string;
  signingWorkerUrl: string;
  signingWorkerId: string;
  internalServiceAuth: string;
  deriverAInputPublicKey: readonly number[];
  deriverBInputPublicKey: readonly number[];
  signingWorkerRecipientPublicKey: readonly number[];
  fetch: typeof fetch;
};

type HttpSuccess = { ok: true; body: unknown };
type HttpResult = HttpSuccess | RouterAbEd25519YaoRegistrationBackendFailure;

type ActivationRoleExecution = {
  binding: RouterAbEd25519YaoActivationBindingV1;
  deriver: RouterAbEd25519YaoDeriverRoleV1;
  transcript: readonly number[];
  clientCommitment: readonly number[];
  signingWorkerCommitment: readonly number[];
  clientPackage: RouterAbEd25519YaoEncryptedPackageV1;
  signingWorkerPackage: RouterAbEd25519YaoEncryptedPackageV1;
};

type ExportRoleExecution = {
  binding: RouterAbEd25519YaoCeremonyBindingV1;
  deriver: RouterAbEd25519YaoDeriverRoleV1;
  transcript: readonly number[];
  clientPackage: RouterAbEd25519YaoEncryptedPackageV1;
};

type ActiveSigningWorkerReceipt = {
  session: readonly number[];
  transcript: readonly number[];
  registeredPublicKey: readonly number[];
  joinedClientCommitment: readonly number[];
  joinedSigningWorkerCommitment: readonly number[];
  signingWorkerVerifyingShare: readonly number[];
  stateEpoch: number;
};

type SigningWorkerDeliveryReceipt =
  | { kind: 'active'; activeReceipt: ActiveSigningWorkerReceipt }
  | { kind: 'staged_recovery'; stagedReceipt: ActiveSigningWorkerReceipt };

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
    deriverAUrl: requireHttpOrigin(input.deriverAUrl, 'deriverAUrl'),
    deriverBUrl: requireHttpOrigin(input.deriverBUrl, 'deriverBUrl'),
    signingWorkerUrl: requireHttpOrigin(input.signingWorkerUrl, 'signingWorkerUrl'),
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

function requireMatchingString(value: unknown, expected: string, label: string): void {
  if (value !== expected) throw new Error(`${label} does not match the admitted ceremony`);
}

function requireMatchingBytes32(value: unknown, expected: readonly number[], label: string): void {
  const parsed = requireBytes32(value, label);
  if (!equalBytes(parsed, expected)) {
    throw new Error(`${label} does not match the admitted ceremony`);
  }
}

function requireExactCeremonyBinding<Binding extends RouterAbEd25519YaoCeremonyBindingV1>(
  value: unknown,
  expected: Binding,
  label: string,
): Binding {
  const binding = requireRecord(value, label);
  requireExactKeys(binding, label, [
    'lifecycle',
    'operation',
    'session_id',
    'stable_key_context_binding',
  ]);
  const lifecycle = requireRecord(binding.lifecycle, `${label}.lifecycle`);
  requireExactKeys(lifecycle, `${label}.lifecycle`, [
    'lifecycle_id',
    'work_kind',
    'primitive_request_kind',
    'root_share_epoch',
    'account_id',
    'session_id',
    'signer_set_id',
    'selected_server_id',
  ]);
  requireMatchingString(
    lifecycle.lifecycle_id,
    expected.lifecycle.lifecycle_id,
    `${label}.lifecycle.lifecycle_id`,
  );
  requireMatchingString(
    lifecycle.work_kind,
    expected.lifecycle.work_kind,
    `${label}.lifecycle.work_kind`,
  );
  requireMatchingString(
    lifecycle.primitive_request_kind,
    expected.lifecycle.primitive_request_kind,
    `${label}.lifecycle.primitive_request_kind`,
  );
  requireMatchingString(
    lifecycle.root_share_epoch,
    expected.lifecycle.root_share_epoch,
    `${label}.lifecycle.root_share_epoch`,
  );
  requireMatchingString(
    lifecycle.account_id,
    expected.lifecycle.account_id,
    `${label}.lifecycle.account_id`,
  );
  requireMatchingString(
    lifecycle.session_id,
    expected.lifecycle.session_id,
    `${label}.lifecycle.session_id`,
  );
  requireMatchingString(
    lifecycle.signer_set_id,
    expected.lifecycle.signer_set_id,
    `${label}.lifecycle.signer_set_id`,
  );
  requireMatchingString(
    lifecycle.selected_server_id,
    expected.lifecycle.selected_server_id,
    `${label}.lifecycle.selected_server_id`,
  );
  requireMatchingString(binding.operation, expected.operation, `${label}.operation`);
  requireMatchingBytes32(binding.session_id, expected.session_id, `${label}.session_id`);
  requireMatchingBytes32(
    binding.stable_key_context_binding,
    expected.stable_key_context_binding,
    `${label}.stable_key_context_binding`,
  );
  return expected;
}

function parseActivationRoleExecution(
  value: unknown,
  expectedBinding: RouterAbEd25519YaoActivationBindingV1,
  expectedDeriver: RouterAbEd25519YaoDeriverRoleV1,
): ActivationRoleExecution {
  const label = `${expectedDeriver} activation execution`;
  const record = requireRecord(value, label);
  requireExactKeys(record, label, [
    'family',
    'binding',
    'deriver',
    'transcript',
    'client_commitment',
    'signing_worker_commitment',
    'client_package',
    'signing_worker_package',
  ]);
  if (record.family !== 'activation') throw new Error(`${label} has wrong family`);
  if (record.deriver !== expectedDeriver) throw new Error(`${label} has wrong Deriver role`);
  const binding = requireExactCeremonyBinding(record.binding, expectedBinding, `${label}.binding`);
  const transcript = requireBytes32(record.transcript, `${label}.transcript`);
  return {
    binding,
    deriver: expectedDeriver,
    transcript,
    clientCommitment: requireBytes32(record.client_commitment, `${label}.client_commitment`),
    signingWorkerCommitment: requireBytes32(
      record.signing_worker_commitment,
      `${label}.signing_worker_commitment`,
    ),
    clientPackage: requirePackage(
      record.client_package,
      'activation_client',
      expectedDeriver,
      expectedBinding.session_id,
      transcript,
    ),
    signingWorkerPackage: requirePackage(
      record.signing_worker_package,
      'activation_signing_worker',
      expectedDeriver,
      expectedBinding.session_id,
      transcript,
    ),
  };
}

function parseExportRoleExecution(
  value: unknown,
  expectedBinding: RouterAbEd25519YaoCeremonyBindingV1,
  expectedDeriver: RouterAbEd25519YaoDeriverRoleV1,
): ExportRoleExecution {
  const label = `${expectedDeriver} export execution`;
  const record = requireRecord(value, label);
  requireExactKeys(record, label, ['family', 'binding', 'deriver', 'transcript', 'client_package']);
  if (record.family !== 'export') throw new Error(`${label} has wrong family`);
  if (record.deriver !== expectedDeriver) throw new Error(`${label} has wrong Deriver role`);
  const binding = requireExactCeremonyBinding(record.binding, expectedBinding, `${label}.binding`);
  const transcript = requireBytes32(record.transcript, `${label}.transcript`);
  return {
    binding,
    deriver: expectedDeriver,
    transcript,
    clientPackage: requirePackage(
      record.client_package,
      'export_client',
      expectedDeriver,
      expectedBinding.session_id,
      transcript,
    ),
  };
}

function requirePackage(
  value: unknown,
  kind: RouterAbEd25519YaoPackageKindV1,
  deriver: RouterAbEd25519YaoDeriverRoleV1,
  session: readonly number[],
  transcript: readonly number[],
): RouterAbEd25519YaoEncryptedPackageV1 {
  const parsed = parseRouterAbEd25519YaoEncryptedPackageV1(value);
  if (!parsed.ok) throw new Error(parsed.message);
  if (
    parsed.value.kind !== kind ||
    parsed.value.deriver !== deriver ||
    !equalBytes(parsed.value.session, session) ||
    !equalBytes(parsed.value.transcript, transcript)
  ) {
    throw new Error(`${deriver} ${kind} package does not match the ceremony`);
  }
  return parsed.value;
}

function parsePendingSigningWorkerReceipt(
  value: unknown,
  session: readonly number[],
  transcript: readonly number[],
): void {
  const record = requireRecord(value, 'pending SigningWorker receipt');
  requireExactKeys(record, 'pending SigningWorker receipt', [
    'status',
    'accepted_deriver',
    'session',
    'transcript',
  ]);
  if (record.status !== 'pending' || record.accepted_deriver !== 'deriver_a') {
    throw new Error('SigningWorker did not retain the Deriver A package as pending');
  }
  if (
    !equalBytes(requireBytes32(record.session, 'pending receipt session'), session) ||
    !equalBytes(requireBytes32(record.transcript, 'pending receipt transcript'), transcript)
  ) {
    throw new Error('pending SigningWorker receipt does not match the ceremony');
  }
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

function parseStagedSigningWorkerReceipt(
  value: unknown,
  session: readonly number[],
  transcript: readonly number[],
): ActiveSigningWorkerReceipt {
  return parseSigningWorkerReceipt(value, session, transcript, 'staged');
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
      const staged = await this.post(
        this.config.deriverBUrl,
        DERIVER_B_EXPORT_STAGE_PATH,
        request.deriver_b_input,
      );
      if (!staged.ok) return staged;
      const deriverAResult = await this.post(
        this.config.deriverAUrl,
        DERIVER_A_EXPORT_START_PATH,
        request.deriver_a_input,
      );
      if (!deriverAResult.ok) return deriverAResult;
      const deriverBResult = await this.post(
        this.config.deriverBUrl,
        DERIVER_B_EXPORT_RESULT_PATH,
        {
          family: 'export',
          session_id: request.binding.ceremony.session_id,
        },
      );
      if (!deriverBResult.ok) return deriverBResult;
      const executionA = parseExportRoleExecution(
        deriverAResult.body,
        request.binding.ceremony,
        'deriver_a',
      );
      const executionB = parseExportRoleExecution(
        deriverBResult.body,
        request.binding.ceremony,
        'deriver_b',
      );
      if (!equalBytes(executionA.transcript, executionB.transcript)) {
        return internalFailure('transcript_mismatch', 'Deriver export transcripts differ');
      }
      return {
        ok: true,
        body: {
          binding: request.binding,
          transcript: executionA.transcript,
          deriver_a_client_package: executionA.clientPackage,
          deriver_b_client_package: executionB.clientPackage,
        },
      };
    } catch (error: unknown) {
      return unavailableFailure(error);
    }
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
    const keyset = {
      deriver_a_input_public_key: this.config.deriverAInputPublicKey,
      deriver_b_input_public_key: this.config.deriverBInputPublicKey,
      signing_worker_recipient_public_key: this.config.signingWorkerRecipientPublicKey,
    };
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
    try {
      return await this.executeInner(request);
    } catch (error: unknown) {
      return unavailableFailure(error);
    }
  }

  async executeRecovery(
    request: RouterAbEd25519YaoRecoveryExecuteRequestV1,
  ): Promise<RouterAbEd25519YaoRegistrationBackendResult> {
    try {
      return await this.executeInner(request);
    } catch (error: unknown) {
      return unavailableFailure(error);
    }
  }

  async activateRecovery(
    request: RouterAbEd25519YaoRecoveryActivationRequestV1,
  ): Promise<RouterAbEd25519YaoRegistrationBackendResult> {
    const promoted = await this.post(
      this.config.signingWorkerUrl,
      SIGNING_WORKER_RECOVERY_PROMOTE_PATH,
      request,
    );
    if (!promoted.ok) return promoted;
    const activeReceipt = parseActiveSigningWorkerReceipt(
      promoted.body,
      request.binding.session_id,
      request.public_receipt.transcript,
    );
    if (!activeReceiptMatchesRecoveryActivation(activeReceipt, request)) {
      return internalFailure(
        'recovery_promotion_mismatch',
        'SigningWorker promotion receipt does not match the verified recovery result',
      );
    }
    return { ok: true, body: request };
  }

  private async executeInner(
    request: RouterAbEd25519YaoActivationExecuteRequestV1,
  ): Promise<RouterAbEd25519YaoRegistrationBackendResult> {
    const staged = await this.post(
      this.config.deriverBUrl,
      DERIVER_B_STAGE_PATH,
      request.deriver_b_input,
    );
    if (!staged.ok) return staged;

    const deriverAResult = await this.post(
      this.config.deriverAUrl,
      DERIVER_A_START_PATH,
      request.deriver_a_input,
    );
    if (!deriverAResult.ok) return deriverAResult;
    const deriverBResult = await this.post(
      this.config.deriverBUrl,
      DERIVER_B_ACTIVATION_RESULT_PATH,
      {
        family: 'activation',
        session_id: request.binding.session_id,
      },
    );
    if (!deriverBResult.ok) return deriverBResult;

    const executionA = parseActivationRoleExecution(
      deriverAResult.body,
      request.binding,
      'deriver_a',
    );
    const executionB = parseActivationRoleExecution(
      deriverBResult.body,
      request.binding,
      'deriver_b',
    );
    if (!equalBytes(executionA.transcript, executionB.transcript)) {
      return internalFailure('transcript_mismatch', 'Deriver completion transcripts differ');
    }

    const delivered = await this.deliverSigningWorkerPackages(request, executionA, executionB);
    if (!delivered.ok) return delivered;
    let activeReceipt: ActiveSigningWorkerReceipt;
    switch (delivered.body.kind) {
      case 'active':
        if (request.binding.operation !== 'registration') {
          return internalFailure(
            'unexpected_active_recovery',
            'recovery execution activated before Client verification',
          );
        }
        activeReceipt = delivered.body.activeReceipt;
        break;
      case 'staged_recovery': {
        if (request.binding.operation !== 'recovery') {
          return internalFailure(
            'unexpected_staged_registration',
            'registration execution returned a staged recovery candidate',
          );
        }
        activeReceipt = delivered.body.stagedReceipt;
        break;
      }
    }
    return {
      ok: true,
      body: {
        binding: request.binding,
        deriver_a_client_package: executionA.clientPackage,
        deriver_b_client_package: executionB.clientPackage,
        public_receipt: {
          transcript: activeReceipt.transcript,
          registered_public_key: activeReceipt.registeredPublicKey,
          joined_client_commitment: activeReceipt.joinedClientCommitment,
          joined_signing_worker_commitment: activeReceipt.joinedSigningWorkerCommitment,
          signing_worker_verifying_share: activeReceipt.signingWorkerVerifyingShare,
          state_epoch: activeReceipt.stateEpoch,
        },
      },
    };
  }

  private async deliverSigningWorkerPackages(
    request: RouterAbEd25519YaoActivationExecuteRequestV1,
    executionA: ActivationRoleExecution,
    executionB: ActivationRoleExecution,
  ): Promise<
    { ok: true; body: SigningWorkerDeliveryReceipt } | RouterAbEd25519YaoRegistrationBackendFailure
  > {
    const deliveredA = await this.post(
      this.config.signingWorkerUrl,
      SIGNING_WORKER_DERIVER_A_PATH,
      {
        binding: request.binding,
        client_commitment: executionA.clientCommitment,
        signing_worker_commitment: executionA.signingWorkerCommitment,
        package: executionA.signingWorkerPackage,
      },
    );
    if (!deliveredA.ok) return deliveredA;
    parsePendingSigningWorkerReceipt(
      deliveredA.body,
      request.binding.session_id,
      executionA.transcript,
    );

    const deliveredB = await this.post(
      this.config.signingWorkerUrl,
      SIGNING_WORKER_DERIVER_B_PATH,
      {
        binding: request.binding,
        client_commitment: executionB.clientCommitment,
        signing_worker_commitment: executionB.signingWorkerCommitment,
        package: executionB.signingWorkerPackage,
      },
    );
    if (!deliveredB.ok) return deliveredB;
    switch (request.binding.operation) {
      case 'registration':
        return {
          ok: true,
          body: {
            kind: 'active',
            activeReceipt: parseActiveSigningWorkerReceipt(
              deliveredB.body,
              request.binding.session_id,
              executionA.transcript,
            ),
          },
        };
      case 'recovery':
        return {
          ok: true,
          body: {
            kind: 'staged_recovery',
            stagedReceipt: parseStagedSigningWorkerReceipt(
              deliveredB.body,
              request.binding.session_id,
              executionA.transcript,
            ),
          },
        };
    }
  }

  private async post(baseUrl: string, path: string, body: unknown): Promise<HttpResult> {
    return await this.request(baseUrl, path, {
      method: 'POST',
      headers: this.headers(),
      body: JSON.stringify(body),
    });
  }

  private headers(): Record<string, string> {
    return {
      'content-type': 'application/json',
      [INTERNAL_AUTH_HEADER]: this.config.internalServiceAuth,
    };
  }

  private async request(baseUrl: string, path: string, init: RequestInit): Promise<HttpResult> {
    const response = await this.config.fetch.call(globalThis, `${baseUrl}${path}`, init);
    const text = await response.text();
    if (!response.ok) {
      return internalFailure(
        'worker_rejected',
        `worker ${path} returned HTTP ${response.status}: ${text}`,
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
    deriverAUrl: requireNonEmpty(
      envValue(env, ROUTER_AB_ENV_KEYS.deriverAUrl),
      ROUTER_AB_ENV_KEYS.deriverAUrl,
    ),
    deriverBUrl: requireNonEmpty(
      envValue(env, ROUTER_AB_ENV_KEYS.deriverBUrl),
      ROUTER_AB_ENV_KEYS.deriverBUrl,
    ),
    signingWorkerUrl: requireNonEmpty(
      envValue(env, ROUTER_AB_ENV_KEYS.signingWorkerUrl),
      ROUTER_AB_ENV_KEYS.signingWorkerUrl,
    ),
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
