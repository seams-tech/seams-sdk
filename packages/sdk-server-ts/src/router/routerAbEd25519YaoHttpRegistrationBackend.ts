import {
  deriveRouterAbEd25519YaoStableContextBindingV1,
  parseRouterAbEd25519YaoEncryptedPackageV1,
  parseRouterAbEd25519YaoRecoveryActivationRequestV1,
  type RouterAbEd25519YaoActivationExecuteRequestV1,
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
const DERIVER_B_RESULT_PATH = '/router-ab/deriver-b/ed25519-yao/result';
const DERIVER_A_CLIENT_PACKAGE_PATH = '/router-ab/deriver-a/ed25519-yao/activation/client-package';
const DERIVER_B_CLIENT_PACKAGE_PATH = '/router-ab/deriver-b/ed25519-yao/activation/client-package';
const DERIVER_A_SIGNING_WORKER_PACKAGE_PATH =
  '/router-ab/deriver-a/ed25519-yao/activation/signing-worker-package';
const DERIVER_B_SIGNING_WORKER_PACKAGE_PATH =
  '/router-ab/deriver-b/ed25519-yao/activation/signing-worker-package';
const SIGNING_WORKER_DERIVER_A_PATH = '/router-ab/signing-worker/ed25519-yao/activation/deriver-a';
const SIGNING_WORKER_DERIVER_B_PATH = '/router-ab/signing-worker/ed25519-yao/activation/deriver-b';
const SIGNING_WORKER_RECOVERY_PROMOTE_PATH =
  '/router-ab/signing-worker/ed25519-yao/recovery/promote';
const DERIVER_B_EXPORT_STAGE_PATH = '/router-ab/deriver-b/ed25519-yao/export/stage';
const DERIVER_A_EXPORT_START_PATH = '/router-ab/deriver-a/ed25519-yao/export/start';
const DERIVER_A_EXPORT_PACKAGE_PATH =
  '/router-ab/deriver-a/ed25519-yao/export/client-package';
const DERIVER_B_EXPORT_PACKAGE_PATH =
  '/router-ab/deriver-b/ed25519-yao/export/client-package';

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

type ActivationCompletion = {
  session: readonly number[];
  transcript: readonly number[];
  clientCommitment: readonly number[];
  signingWorkerCommitment: readonly number[];
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

type StagedRecoveryReceipt = {
  activeReceipt: ActiveSigningWorkerReceipt;
  promotion: Record<string, unknown>;
};

type RecoveryPromotionState =
  | {
      readonly kind: 'staged';
      readonly activation: RouterAbEd25519YaoRecoveryActivationRequestV1;
      readonly promotion: Record<string, unknown>;
    }
  | {
      readonly kind: 'promoted';
      readonly activation: RouterAbEd25519YaoRecoveryActivationRequestV1;
      readonly promotion: Record<string, unknown>;
    };

export class RouterAbEd25519YaoHttpRegistrationBackendStateV1 {
  private readonly recoveryPromotions = new Map<string, RecoveryPromotionState>();

  stageRecovery(
    activation: RouterAbEd25519YaoRecoveryActivationRequestV1,
    promotion: Record<string, unknown>,
  ): void {
    this.recoveryPromotions.set(bytesToHex(activation.binding.session_id), {
      kind: 'staged',
      activation,
      promotion,
    });
  }

  recoveryPromotion(sessionId: readonly number[]): RecoveryPromotionState | undefined {
    return this.recoveryPromotions.get(bytesToHex(sessionId));
  }

  markRecoveryPromoted(activation: RouterAbEd25519YaoRecoveryActivationRequestV1): void {
    const key = bytesToHex(activation.binding.session_id);
    const current = this.recoveryPromotions.get(key);
    if (!current) throw new Error('recovery promotion state is missing');
    this.recoveryPromotions.set(key, {
      kind: 'promoted',
      activation: current.activation,
      promotion: current.promotion,
    });
  }
}

type SigningWorkerDeliveryReceipt =
  | { kind: 'active'; activeReceipt: ActiveSigningWorkerReceipt }
  | { kind: 'staged_recovery'; staged: StagedRecoveryReceipt };

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

function bytesToHex(bytes: readonly number[]): string {
  let encoded = '';
  for (const byte of bytes) encoded += byte.toString(16).padStart(2, '0');
  return encoded;
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

function parseActivationCompletion(
  value: unknown,
  expectedSession: readonly number[],
): ActivationCompletion {
  const record = requireRecord(value, 'activation completion');
  requireExactKeys(record, 'activation completion', [
    'family',
    'session_hex',
    'transcript_hex',
    'client_commitment_hex',
    'signing_worker_commitment_hex',
    'frame_count',
    'deriver_a_to_b_transport_bytes',
    'deriver_b_to_a_transport_bytes',
    'total_ab_transport_bytes',
  ]);
  if (record.family !== 'activation') throw new Error('activation completion has wrong family');
  const session = hexToBytes32(record.session_hex, 'activation completion session');
  if (!equalBytes(session, expectedSession)) {
    throw new Error('activation completion session does not match admission');
  }
  requirePositiveSafeInteger(record.frame_count, 'activation completion frame_count');
  requirePositiveSafeInteger(
    record.deriver_a_to_b_transport_bytes,
    'activation completion deriver_a_to_b_transport_bytes',
  );
  requirePositiveSafeInteger(
    record.deriver_b_to_a_transport_bytes,
    'activation completion deriver_b_to_a_transport_bytes',
  );
  requirePositiveSafeInteger(
    record.total_ab_transport_bytes,
    'activation completion total_ab_transport_bytes',
  );
  return {
    session,
    transcript: hexToBytes32(record.transcript_hex, 'activation completion transcript'),
    clientCommitment: hexToBytes32(
      record.client_commitment_hex,
      'activation completion client commitment',
    ),
    signingWorkerCommitment: hexToBytes32(
      record.signing_worker_commitment_hex,
      'activation completion SigningWorker commitment',
    ),
  };
}

function parseExportCompletion(value: unknown, expectedSession: readonly number[]): {
  readonly session: readonly number[];
  readonly transcript: readonly number[];
} {
  const record = requireRecord(value, 'export completion');
  requireExactKeys(record, 'export completion', [
    'family',
    'session_hex',
    'transcript_hex',
    'frame_count',
    'deriver_a_to_b_transport_bytes',
    'deriver_b_to_a_transport_bytes',
    'total_ab_transport_bytes',
  ]);
  if (record.family !== 'export') throw new Error('export completion has wrong family');
  const session = hexToBytes32(record.session_hex, 'export completion session');
  if (!equalBytes(session, expectedSession)) {
    throw new Error('export completion session does not match admission');
  }
  requirePositiveSafeInteger(record.frame_count, 'export completion frame_count');
  requirePositiveSafeInteger(
    record.deriver_a_to_b_transport_bytes,
    'export completion deriver_a_to_b_transport_bytes',
  );
  requirePositiveSafeInteger(
    record.deriver_b_to_a_transport_bytes,
    'export completion deriver_b_to_a_transport_bytes',
  );
  requirePositiveSafeInteger(
    record.total_ab_transport_bytes,
    'export completion total_ab_transport_bytes',
  );
  return {
    session,
    transcript: hexToBytes32(record.transcript_hex, 'export completion transcript'),
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

function parseActiveSigningWorkerReceipt(
  value: unknown,
  session: readonly number[],
  transcript: readonly number[],
): ActiveSigningWorkerReceipt {
  const record = requireRecord(value, 'active SigningWorker receipt');
  requireExactKeys(record, 'active SigningWorker receipt', [
    'status',
    'session',
    'transcript',
    'registered_public_key',
    'joined_client_commitment',
    'joined_signing_worker_commitment',
    'signing_worker_verifying_share',
    'state_epoch',
  ]);
  if (record.status !== 'active') throw new Error('SigningWorker did not activate');
  const parsedSession = requireBytes32(record.session, 'active receipt session');
  const parsedTranscript = requireBytes32(record.transcript, 'active receipt transcript');
  if (!equalBytes(parsedSession, session) || !equalBytes(parsedTranscript, transcript)) {
    throw new Error('active SigningWorker receipt does not match the ceremony');
  }
  const receipt = {
    session: parsedSession,
    transcript: parsedTranscript,
    registeredPublicKey: requireBytes32(
      record.registered_public_key,
      'active receipt registered_public_key',
    ),
    joinedClientCommitment: requireBytes32(
      record.joined_client_commitment,
      'active receipt joined_client_commitment',
    ),
    joinedSigningWorkerCommitment: requireBytes32(
      record.joined_signing_worker_commitment,
      'active receipt joined_signing_worker_commitment',
    ),
    signingWorkerVerifyingShare: requireBytes32(
      record.signing_worker_verifying_share,
      'active receipt signing_worker_verifying_share',
    ),
    stateEpoch: requirePositiveSafeInteger(record.state_epoch, 'active receipt state_epoch'),
  };
  if (!equalBytes(receipt.signingWorkerVerifyingShare, receipt.joinedSigningWorkerCommitment)) {
    throw new Error('active SigningWorker receipt verifying share does not match its commitment');
  }
  return receipt;
}

function parseStagedRecoveryReceipt(
  value: unknown,
  session: readonly number[],
  transcript: readonly number[],
): StagedRecoveryReceipt {
  const record = requireRecord(value, 'staged recovery receipt');
  requireExactKeys(record, 'staged recovery receipt', ['status', 'promotion']);
  if (record.status !== 'staged') throw new Error('SigningWorker did not stage recovery');
  const promotion = requireRecord(record.promotion, 'staged recovery promotion');
  requireExactKeys(promotion, 'staged recovery promotion', [
    'binding',
    'session',
    'transcript',
    'registered_public_key',
    'joined_client_commitment',
    'joined_signing_worker_commitment',
    'signing_worker_verifying_share',
    'state_epoch',
  ]);
  const parsedSession = requireBytes32(promotion.session, 'staged recovery session');
  const parsedTranscript = requireBytes32(promotion.transcript, 'staged recovery transcript');
  if (!equalBytes(parsedSession, session) || !equalBytes(parsedTranscript, transcript)) {
    throw new Error('staged recovery receipt does not match the ceremony');
  }
  const publicReceipt = {
    transcript: parsedTranscript,
    registered_public_key: requireBytes32(
      promotion.registered_public_key,
      'staged recovery registered_public_key',
    ),
    joined_client_commitment: requireBytes32(
      promotion.joined_client_commitment,
      'staged recovery joined_client_commitment',
    ),
    joined_signing_worker_commitment: requireBytes32(
      promotion.joined_signing_worker_commitment,
      'staged recovery joined_signing_worker_commitment',
    ),
    signing_worker_verifying_share: requireBytes32(
      promotion.signing_worker_verifying_share,
      'staged recovery signing_worker_verifying_share',
    ),
    state_epoch: requirePositiveSafeInteger(promotion.state_epoch, 'staged recovery state_epoch'),
  };
  const parsedActivation = parseRouterAbEd25519YaoRecoveryActivationRequestV1({
    binding: promotion.binding,
    public_receipt: publicReceipt,
  });
  if (!parsedActivation.ok) throw new Error(parsedActivation.message);
  if (!equalBytes(parsedActivation.value.binding.session_id, session)) {
    throw new Error('staged recovery binding does not match the ceremony session');
  }
  if (
    !equalBytes(
      publicReceipt.signing_worker_verifying_share,
      publicReceipt.joined_signing_worker_commitment,
    )
  ) {
    throw new Error('staged recovery verifying share does not match its commitment');
  }
  return {
    activeReceipt: {
      session: parsedSession,
      transcript: parsedTranscript,
      registeredPublicKey: publicReceipt.registered_public_key,
      joinedClientCommitment: publicReceipt.joined_client_commitment,
      joinedSigningWorkerCommitment: publicReceipt.joined_signing_worker_commitment,
      signingWorkerVerifyingShare: publicReceipt.signing_worker_verifying_share,
      stateEpoch: publicReceipt.state_epoch,
    },
    promotion: {
      binding: parsedActivation.value.binding,
      session: parsedSession,
      transcript: parsedTranscript,
      registered_public_key: publicReceipt.registered_public_key,
      joined_client_commitment: publicReceipt.joined_client_commitment,
      joined_signing_worker_commitment: publicReceipt.joined_signing_worker_commitment,
      signing_worker_verifying_share: publicReceipt.signing_worker_verifying_share,
      state_epoch: publicReceipt.state_epoch,
    },
  };
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
  private readonly state: RouterAbEd25519YaoHttpRegistrationBackendStateV1;

  constructor(
    config: RouterAbEd25519YaoHttpRegistrationBackendConfig,
    state: RouterAbEd25519YaoHttpRegistrationBackendStateV1,
  ) {
    this.config = validateConfig(config);
    this.state = state;
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
      const deriverBResult = await this.get(this.config.deriverBUrl, DERIVER_B_RESULT_PATH);
      if (!deriverBResult.ok) return deriverBResult;
      const session = request.binding.ceremony.session_id;
      const completionA = parseExportCompletion(deriverAResult.body, session);
      const completionB = parseExportCompletion(deriverBResult.body, session);
      if (!equalBytes(completionA.transcript, completionB.transcript)) {
        return internalFailure('transcript_mismatch', 'Deriver export transcripts differ');
      }
      const packageA = await this.get(this.config.deriverAUrl, DERIVER_A_EXPORT_PACKAGE_PATH);
      if (!packageA.ok) return packageA;
      const packageB = await this.get(this.config.deriverBUrl, DERIVER_B_EXPORT_PACKAGE_PATH);
      if (!packageB.ok) return packageB;
      return {
        ok: true,
        body: {
          binding: request.binding,
          transcript: completionA.transcript,
          deriver_a_client_package: requirePackage(
            packageA.body,
            'export_client',
            'deriver_a',
            session,
            completionA.transcript,
          ),
          deriver_b_client_package: requirePackage(
            packageB.body,
            'export_client',
            'deriver_b',
            session,
            completionA.transcript,
          ),
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
    const staged = this.state.recoveryPromotion(request.binding.session_id);
    if (!staged) {
      return {
        ok: false,
        status: 409,
        code: 'recovery_candidate_missing',
        message: 'SigningWorker has no staged recovery candidate',
      };
    }
    if (JSON.stringify(staged.activation) !== JSON.stringify(request)) {
      return {
        ok: false,
        status: 409,
        code: 'recovery_candidate_mismatch',
        message: 'recovery activation does not match the staged result',
      };
    }
    if (staged.kind === 'promoted') return { ok: true, body: staged.activation };
    const promoted = await this.post(
      this.config.signingWorkerUrl,
      SIGNING_WORKER_RECOVERY_PROMOTE_PATH,
      staged.promotion,
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
    this.state.markRecoveryPromoted(request);
    return { ok: true, body: staged.activation };
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
    const deriverBResult = await this.get(this.config.deriverBUrl, DERIVER_B_RESULT_PATH);
    if (!deriverBResult.ok) return deriverBResult;

    const completionA = parseActivationCompletion(deriverAResult.body, request.binding.session_id);
    const completionB = parseActivationCompletion(deriverBResult.body, request.binding.session_id);
    if (!equalBytes(completionA.transcript, completionB.transcript)) {
      return internalFailure('transcript_mismatch', 'Deriver completion transcripts differ');
    }

    const packages = await this.collectPackages(request, completionA.transcript);
    if (!packages.ok) return packages;
    const delivered = await this.deliverSigningWorkerPackages(
      request,
      completionA,
      completionB,
      packages.body,
    );
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
        activeReceipt = delivered.body.staged.activeReceipt;
        const activation: RouterAbEd25519YaoRecoveryActivationRequestV1 = {
          binding: request.binding,
          public_receipt: {
            transcript: activeReceipt.transcript,
            registered_public_key: activeReceipt.registeredPublicKey,
            joined_client_commitment: activeReceipt.joinedClientCommitment,
            joined_signing_worker_commitment: activeReceipt.joinedSigningWorkerCommitment,
            signing_worker_verifying_share: activeReceipt.signingWorkerVerifyingShare,
            state_epoch: activeReceipt.stateEpoch,
          },
        };
        this.state.stageRecovery(activation, delivered.body.staged.promotion);
        break;
      }
    }
    return {
      ok: true,
      body: {
        binding: request.binding,
        deriver_a_client_package: packages.body.deriverAClient,
        deriver_b_client_package: packages.body.deriverBClient,
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

  private async collectPackages(
    request: RouterAbEd25519YaoActivationExecuteRequestV1,
    transcript: readonly number[],
  ): Promise<
    | {
        ok: true;
        body: {
          deriverAClient: RouterAbEd25519YaoEncryptedPackageV1;
          deriverBClient: RouterAbEd25519YaoEncryptedPackageV1;
          deriverAWorker: RouterAbEd25519YaoEncryptedPackageV1;
          deriverBWorker: RouterAbEd25519YaoEncryptedPackageV1;
        };
      }
    | RouterAbEd25519YaoRegistrationBackendFailure
  > {
    const aClient = await this.get(this.config.deriverAUrl, DERIVER_A_CLIENT_PACKAGE_PATH);
    if (!aClient.ok) return aClient;
    const bClient = await this.get(this.config.deriverBUrl, DERIVER_B_CLIENT_PACKAGE_PATH);
    if (!bClient.ok) return bClient;
    const aWorker = await this.get(this.config.deriverAUrl, DERIVER_A_SIGNING_WORKER_PACKAGE_PATH);
    if (!aWorker.ok) return aWorker;
    const bWorker = await this.get(this.config.deriverBUrl, DERIVER_B_SIGNING_WORKER_PACKAGE_PATH);
    if (!bWorker.ok) return bWorker;
    return {
      ok: true,
      body: {
        deriverAClient: requirePackage(
          aClient.body,
          'activation_client',
          'deriver_a',
          request.binding.session_id,
          transcript,
        ),
        deriverBClient: requirePackage(
          bClient.body,
          'activation_client',
          'deriver_b',
          request.binding.session_id,
          transcript,
        ),
        deriverAWorker: requirePackage(
          aWorker.body,
          'activation_signing_worker',
          'deriver_a',
          request.binding.session_id,
          transcript,
        ),
        deriverBWorker: requirePackage(
          bWorker.body,
          'activation_signing_worker',
          'deriver_b',
          request.binding.session_id,
          transcript,
        ),
      },
    };
  }

  private async deliverSigningWorkerPackages(
    request: RouterAbEd25519YaoActivationExecuteRequestV1,
    completionA: ActivationCompletion,
    completionB: ActivationCompletion,
    packages: {
      deriverAClient: RouterAbEd25519YaoEncryptedPackageV1;
      deriverBClient: RouterAbEd25519YaoEncryptedPackageV1;
      deriverAWorker: RouterAbEd25519YaoEncryptedPackageV1;
      deriverBWorker: RouterAbEd25519YaoEncryptedPackageV1;
    },
  ): Promise<
    { ok: true; body: SigningWorkerDeliveryReceipt } | RouterAbEd25519YaoRegistrationBackendFailure
  > {
    const deliveredA = await this.post(
      this.config.signingWorkerUrl,
      SIGNING_WORKER_DERIVER_A_PATH,
      {
        binding: request.binding,
        client_commitment: completionA.clientCommitment,
        signing_worker_commitment: completionA.signingWorkerCommitment,
        package: packages.deriverAWorker,
      },
    );
    if (!deliveredA.ok) return deliveredA;
    parsePendingSigningWorkerReceipt(
      deliveredA.body,
      request.binding.session_id,
      completionA.transcript,
    );

    const deliveredB = await this.post(
      this.config.signingWorkerUrl,
      SIGNING_WORKER_DERIVER_B_PATH,
      {
        binding: request.binding,
        client_commitment: completionB.clientCommitment,
        signing_worker_commitment: completionB.signingWorkerCommitment,
        package: packages.deriverBWorker,
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
              completionA.transcript,
            ),
          },
        };
      case 'recovery':
        return {
          ok: true,
          body: {
            kind: 'staged_recovery',
            staged: parseStagedRecoveryReceipt(
              deliveredB.body,
              request.binding.session_id,
              completionA.transcript,
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

  private async get(baseUrl: string, path: string): Promise<HttpResult> {
    return await this.request(baseUrl, path, { method: 'GET', headers: this.headers() });
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
    let body: unknown;
    try {
      body = text ? JSON.parse(text) : null;
    } catch {
      return internalFailure('worker_invalid_json', `worker ${path} returned invalid JSON`);
    }
    if (!response.ok) {
      return internalFailure(
        'worker_rejected',
        `worker ${path} returned HTTP ${response.status}: ${text}`,
      );
    }
    return { ok: true, body };
  }
}

export function createRouterAbEd25519YaoHttpRegistrationBackendFromEnv(input: {
  env: RouterAbEd25519YaoHttpRegistrationBackendRawEnv;
  fetch: typeof fetch;
  state: RouterAbEd25519YaoHttpRegistrationBackendStateV1;
}): RouterAbEd25519YaoHttpRegistrationBackend {
  const env = input.env;
  return new RouterAbEd25519YaoHttpRegistrationBackend(
    {
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
    },
    input.state,
  );
}
