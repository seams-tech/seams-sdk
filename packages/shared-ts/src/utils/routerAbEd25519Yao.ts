export const ROUTER_AB_ED25519_YAO_REGISTRATION_ADMISSION_PATH_V1 =
  '/router-ab/ed25519/yao/registration/admit' as const;
export const ROUTER_AB_ED25519_YAO_REGISTRATION_EXECUTE_PATH_V1 =
  '/router-ab/ed25519/yao/registration/execute' as const;
export const ROUTER_AB_ED25519_YAO_RECOVERY_ADMISSION_PATH_V1 =
  '/router-ab/ed25519/yao/recovery/admit' as const;
export const ROUTER_AB_ED25519_YAO_RECOVERY_EXECUTE_PATH_V1 =
  '/router-ab/ed25519/yao/recovery/execute' as const;
export const ROUTER_AB_ED25519_YAO_RECOVERY_ACTIVATE_PATH_V1 =
  '/router-ab/ed25519/yao/recovery/activate' as const;
export const ROUTER_AB_ED25519_YAO_WARM_RECOVERY_BOOTSTRAP_PATH_V1 =
  '/router-ab/ed25519/yao/recovery/bootstrap' as const;
export const ROUTER_AB_ED25519_YAO_EXPORT_ADMISSION_PATH_V1 =
  '/router-ab/ed25519/yao/export/admit' as const;
export const ROUTER_AB_ED25519_YAO_EXPORT_EXECUTE_PATH_V1 =
  '/router-ab/ed25519/yao/export/execute' as const;
export const ED25519_YAO_CONTROL_CIPHERTEXT_MAX_BYTES_V1 = 64 * 1024;

export type RouterAbEd25519YaoOperationV1 = 'registration' | 'recovery' | 'refresh' | 'export';
export type RouterAbEd25519YaoDeriverRoleV1 = 'deriver_a' | 'deriver_b';
export type RouterAbEd25519YaoInputKindV1 = 'activation' | 'export';
export type RouterAbEd25519YaoPackageKindV1 =
  | 'activation_client'
  | 'activation_signing_worker'
  | 'export_client';
export type RouterAbEd25519YaoWorkKindV1 =
  | 'registration_prepare'
  | 'key_export'
  | 'recovery'
  | 'server_share_refresh';
export type RouterAbEd25519YaoPrimitiveRequestKindV1 =
  | 'registration'
  | 'recovery'
  | 'export'
  | 'refresh';

export type RouterAbEd25519YaoBytes32V1 = readonly number[];

export type RouterAbEd25519YaoApplicationBindingFactsV1 = {
  wallet_id: string;
  near_ed25519_signing_key_id: string;
  signing_root_id: string;
  key_creation_signer_slot: number;
};

export type RouterAbEd25519YaoLifecycleScopeV1 = {
  lifecycle_id: string;
  root_share_epoch: string;
  account_id: string;
  wallet_session_id: string;
  signer_set_id: string;
  signing_worker_id: string;
};

export type RouterAbEd25519YaoRegistrationAdmissionRequestV1 = {
  scope: RouterAbEd25519YaoLifecycleScopeV1;
  application_binding: RouterAbEd25519YaoApplicationBindingFactsV1;
  participant_ids: readonly [number, number];
};

export type RouterAbEd25519YaoRecoveryAdmissionRequestV1 = {
  scope: RouterAbEd25519YaoLifecycleScopeV1;
  application_binding: RouterAbEd25519YaoApplicationBindingFactsV1;
  participant_ids: readonly [number, number];
  active_capability_binding: RouterAbEd25519YaoBytes32V1;
  replacement_capability_binding: RouterAbEd25519YaoBytes32V1;
  registered_public_key: RouterAbEd25519YaoBytes32V1;
};

export type RouterAbEd25519YaoWarmRecoveryBootstrapRequestV1 = {
  readonly kind: 'router_ab_ed25519_yao_warm_recovery_bootstrap_request_v1';
  readonly walletId: string;
  readonly nearAccountId: string;
  readonly nearEd25519SigningKeyId: string;
  readonly signerSlot: number;
  readonly thresholdSessionId: string;
  readonly signingGrantId: string;
  readonly signingWorkerId: string;
  readonly participantIds: readonly [number, number];
};

export type RouterAbEd25519YaoExportAuthorizationV1 = {
  confirmation_digest: RouterAbEd25519YaoBytes32V1;
  authorization_digest: RouterAbEd25519YaoBytes32V1;
  nonce: RouterAbEd25519YaoBytes32V1;
  issued_at_ms: number;
  expires_at_ms: number;
};

export type RouterAbEd25519YaoExportAdmissionRequestV1 = {
  scope: RouterAbEd25519YaoLifecycleScopeV1;
  application_binding: RouterAbEd25519YaoApplicationBindingFactsV1;
  participant_ids: readonly [number, number];
  registered_public_key: RouterAbEd25519YaoBytes32V1;
  state_epoch: number;
  runtime_policy_binding: RouterAbEd25519YaoBytes32V1;
  authorization: RouterAbEd25519YaoExportAuthorizationV1;
};

export type RouterAbEd25519YaoExportAuthorizationIdentityV1 = Omit<
  RouterAbEd25519YaoExportAdmissionRequestV1,
  'authorization'
>;

export type RouterAbEd25519YaoExportAuthorityBindingV1 =
  | {
      readonly kind: 'passkey';
      readonly credentialIdB64u: string;
      readonly providerSubjectId?: never;
    }
  | {
      readonly kind: 'email_otp';
      readonly providerSubjectId: string;
      readonly credentialIdB64u?: never;
    };

export type RouterAbEd25519YaoAdmittedLifecycleV1 = {
  lifecycle_id: string;
  work_kind: RouterAbEd25519YaoWorkKindV1;
  primitive_request_kind: RouterAbEd25519YaoPrimitiveRequestKindV1;
  root_share_epoch: string;
  account_id: string;
  session_id: string;
  signer_set_id: string;
  selected_server_id: string;
};

export type RouterAbEd25519YaoCeremonyBindingV1 = {
  lifecycle: RouterAbEd25519YaoAdmittedLifecycleV1;
  operation: RouterAbEd25519YaoOperationV1;
  session_id: RouterAbEd25519YaoBytes32V1;
  stable_key_context_binding: RouterAbEd25519YaoBytes32V1;
};

export type RouterAbEd25519YaoRegistrationLifecycleV1 = Omit<
  RouterAbEd25519YaoAdmittedLifecycleV1,
  'work_kind' | 'primitive_request_kind'
> & {
  work_kind: 'registration_prepare';
  primitive_request_kind: 'registration';
};

export type RouterAbEd25519YaoRecoveryLifecycleV1 = Omit<
  RouterAbEd25519YaoAdmittedLifecycleV1,
  'work_kind' | 'primitive_request_kind'
> & {
  work_kind: 'recovery';
  primitive_request_kind: 'recovery';
};

export type RouterAbEd25519YaoExportLifecycleV1 = Omit<
  RouterAbEd25519YaoAdmittedLifecycleV1,
  'work_kind' | 'primitive_request_kind'
> & {
  work_kind: 'key_export';
  primitive_request_kind: 'export';
};

export type RouterAbEd25519YaoExportCeremonyBindingV1 = Omit<
  RouterAbEd25519YaoCeremonyBindingV1,
  'lifecycle' | 'operation'
> & {
  lifecycle: RouterAbEd25519YaoExportLifecycleV1;
  operation: 'export';
};

export type RouterAbEd25519YaoExportBindingV1 = {
  ceremony: RouterAbEd25519YaoExportCeremonyBindingV1;
  registered_public_key: RouterAbEd25519YaoBytes32V1;
  state_epoch: number;
  runtime_policy_binding: RouterAbEd25519YaoBytes32V1;
  authorization_digest: RouterAbEd25519YaoBytes32V1;
};

export type RouterAbEd25519YaoActivationOperationV1 = 'registration' | 'recovery';

type RouterAbEd25519YaoActivationLifecycleForV1<
  Operation extends RouterAbEd25519YaoActivationOperationV1,
> = Operation extends 'registration'
  ? RouterAbEd25519YaoRegistrationLifecycleV1
  : RouterAbEd25519YaoRecoveryLifecycleV1;

export type RouterAbEd25519YaoActivationBindingV1<
  Operation extends RouterAbEd25519YaoActivationOperationV1 =
    RouterAbEd25519YaoActivationOperationV1,
> = Operation extends RouterAbEd25519YaoActivationOperationV1
  ? Omit<RouterAbEd25519YaoCeremonyBindingV1, 'lifecycle' | 'operation'> & {
      lifecycle: RouterAbEd25519YaoActivationLifecycleForV1<Operation>;
      operation: Operation;
    }
  : never;

export type RouterAbEd25519YaoActivationKeysetV1 = {
  deriver_a_input_public_key: RouterAbEd25519YaoBytes32V1;
  deriver_b_input_public_key: RouterAbEd25519YaoBytes32V1;
  signing_worker_recipient_public_key: RouterAbEd25519YaoBytes32V1;
};

export type RouterAbEd25519YaoActivationAdmissionReceiptV1<
  Operation extends RouterAbEd25519YaoActivationOperationV1 =
    RouterAbEd25519YaoActivationOperationV1,
> = Operation extends RouterAbEd25519YaoActivationOperationV1
  ? {
      binding: RouterAbEd25519YaoActivationBindingV1<Operation>;
      keyset: RouterAbEd25519YaoActivationKeysetV1;
    }
  : never;

export type RouterAbEd25519YaoExportAdmissionReceiptV1 = {
  binding: RouterAbEd25519YaoExportBindingV1;
  keyset: RouterAbEd25519YaoActivationKeysetV1;
};

export type RouterAbEd25519YaoEncryptedInputV1 = {
  kind: RouterAbEd25519YaoInputKindV1;
  deriver: RouterAbEd25519YaoDeriverRoleV1;
  operation: RouterAbEd25519YaoOperationV1;
  session: RouterAbEd25519YaoBytes32V1;
  stable_context_binding: RouterAbEd25519YaoBytes32V1;
  encapsulated_key: RouterAbEd25519YaoBytes32V1;
  ciphertext: readonly number[];
};

export type RouterAbEd25519YaoActivationEncryptedInputV1<
  Role extends RouterAbEd25519YaoDeriverRoleV1,
  Operation extends RouterAbEd25519YaoActivationOperationV1 =
    RouterAbEd25519YaoActivationOperationV1,
> = Operation extends RouterAbEd25519YaoActivationOperationV1
  ? Omit<RouterAbEd25519YaoEncryptedInputV1, 'kind' | 'deriver' | 'operation'> & {
      kind: 'activation';
      deriver: Role;
      operation: Operation;
    }
  : never;

export type RouterAbEd25519YaoActivationExecuteRequestV1<
  Operation extends RouterAbEd25519YaoActivationOperationV1 =
    RouterAbEd25519YaoActivationOperationV1,
> = Operation extends RouterAbEd25519YaoActivationOperationV1
  ? {
      binding: RouterAbEd25519YaoActivationBindingV1<Operation>;
      deriver_a_input: RouterAbEd25519YaoActivationEncryptedInputV1<'deriver_a', Operation>;
      deriver_b_input: RouterAbEd25519YaoActivationEncryptedInputV1<'deriver_b', Operation>;
    }
  : never;

export type RouterAbEd25519YaoExportEncryptedInputV1<Role extends RouterAbEd25519YaoDeriverRoleV1> =
  Omit<RouterAbEd25519YaoEncryptedInputV1, 'kind' | 'deriver' | 'operation'> & {
    kind: 'export';
    deriver: Role;
    operation: 'export';
  };

export type RouterAbEd25519YaoExportExecuteRequestV1 = {
  binding: RouterAbEd25519YaoExportBindingV1;
  deriver_a_input: RouterAbEd25519YaoExportEncryptedInputV1<'deriver_a'>;
  deriver_b_input: RouterAbEd25519YaoExportEncryptedInputV1<'deriver_b'>;
};

export type RouterAbEd25519YaoEncryptedPackageV1 = {
  kind: RouterAbEd25519YaoPackageKindV1;
  deriver: RouterAbEd25519YaoDeriverRoleV1;
  session: RouterAbEd25519YaoBytes32V1;
  transcript: RouterAbEd25519YaoBytes32V1;
  encapsulated_key: RouterAbEd25519YaoBytes32V1;
  ciphertext: readonly number[];
};

export type RouterAbEd25519YaoActivationClientPackageV1<
  Role extends RouterAbEd25519YaoDeriverRoleV1,
> = Omit<RouterAbEd25519YaoEncryptedPackageV1, 'kind' | 'deriver'> & {
  kind: 'activation_client';
  deriver: Role;
};

export type RouterAbEd25519YaoExportClientPackageV1<Role extends RouterAbEd25519YaoDeriverRoleV1> =
  Omit<RouterAbEd25519YaoEncryptedPackageV1, 'kind' | 'deriver'> & {
    kind: 'export_client';
    deriver: Role;
  };

export type RouterAbEd25519YaoExportResultV1 = {
  binding: RouterAbEd25519YaoExportBindingV1;
  transcript: RouterAbEd25519YaoBytes32V1;
  deriver_a_client_package: RouterAbEd25519YaoExportClientPackageV1<'deriver_a'>;
  deriver_b_client_package: RouterAbEd25519YaoExportClientPackageV1<'deriver_b'>;
};

export type RouterAbEd25519YaoActivationPublicReceiptV1 = {
  transcript: RouterAbEd25519YaoBytes32V1;
  registered_public_key: RouterAbEd25519YaoBytes32V1;
  joined_client_commitment: RouterAbEd25519YaoBytes32V1;
  joined_signing_worker_commitment: RouterAbEd25519YaoBytes32V1;
  signing_worker_verifying_share: RouterAbEd25519YaoBytes32V1;
  state_epoch: number;
};

export type RouterAbEd25519YaoActivationResultV1<
  Operation extends RouterAbEd25519YaoActivationOperationV1 =
    RouterAbEd25519YaoActivationOperationV1,
> = Operation extends RouterAbEd25519YaoActivationOperationV1
  ? {
      binding: RouterAbEd25519YaoActivationBindingV1<Operation>;
      deriver_a_client_package: RouterAbEd25519YaoActivationClientPackageV1<'deriver_a'>;
      deriver_b_client_package: RouterAbEd25519YaoActivationClientPackageV1<'deriver_b'>;
      public_receipt: RouterAbEd25519YaoActivationPublicReceiptV1;
    }
  : never;

export type RouterAbEd25519YaoRecoveryActivationRequestV1 = {
  binding: RouterAbEd25519YaoActivationBindingV1<'recovery'>;
  public_receipt: RouterAbEd25519YaoActivationPublicReceiptV1;
};

export type RouterAbEd25519YaoRecoveryActivationReceiptV1 = {
  binding: RouterAbEd25519YaoActivationBindingV1<'recovery'>;
  public_receipt: RouterAbEd25519YaoActivationPublicReceiptV1;
  active_capability_binding: RouterAbEd25519YaoBytes32V1;
  retired_capability_binding: RouterAbEd25519YaoBytes32V1;
};

export type RouterAbEd25519YaoParseResult<T> =
  | { ok: true; value: T }
  | { ok: false; code: 'invalid_body'; message: string };

const REGISTRATION_WORK_KIND = 'registration_prepare' as const;
const REGISTRATION_PRIMITIVE_REQUEST_KIND = 'registration' as const;
const RECOVERY_WORK_KIND = 'recovery' as const;
const RECOVERY_PRIMITIVE_REQUEST_KIND = 'recovery' as const;
const EXPORT_WORK_KIND = 'key_export' as const;
const EXPORT_PRIMITIVE_REQUEST_KIND = 'export' as const;
const APPLICATION_BINDING_DOMAIN = 'seams/router-ab/ed25519-yao/application-binding/v1';
const STABLE_KEY_CONTEXT_DOMAIN = 'seams/router-ab/ed25519-yao/stable-key-context/v1';
const STABLE_KEY_CONTEXT_BINDING_DOMAIN =
  'seams/router-ab/ed25519-yao/stable-key-context-binding/v1';
const EXPORT_CONFIRMATION_DOMAIN = 'seams/router-ab/ed25519-yao/export-confirmation/v1';
const EXPORT_AUTHORIZATION_DOMAIN = 'seams/router-ab/ed25519-yao/export-authorization/v1';
const RUNTIME_POLICY_BINDING_DOMAIN = 'seams/router-ab/runtime-policy-binding/v1';
const UTF8 = new TextEncoder();

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
    if (!allowed.has(key)) throw new Error(`${label}.${key} is not a supported field`);
  }
  for (const key of allowedKeys) {
    if (!Object.hasOwn(record, key)) throw new Error(`${label}.${key} is required`);
  }
}

function requireVisibleIdentifier(value: unknown, label: string): string {
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`${label} must be a non-empty visible ASCII string`);
  }
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code < 0x21 || code > 0x7e) {
      throw new Error(`${label} must contain visible ASCII bytes`);
    }
  }
  return value;
}

function requirePositiveU32(value: unknown, label: string): number {
  if (!Number.isInteger(value) || typeof value !== 'number' || value <= 0 || value > 0xffffffff) {
    throw new Error(`${label} must be a positive u32`);
  }
  return value;
}

function requirePositiveSafeInteger(value: unknown, label: string): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`${label} must be a positive safe integer`);
  }
  return value;
}

function requireByte(value: unknown, label: string): number {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 0 || value > 255) {
    throw new Error(`${label} must be a byte`);
  }
  return value;
}

function requireBytes(
  value: unknown,
  label: string,
  minimumLength: number,
  maximumLength: number,
): number[] {
  if (!Array.isArray(value)) throw new Error(`${label} must be a byte array`);
  if (value.length < minimumLength || value.length > maximumLength) {
    throw new Error(`${label} has an invalid length`);
  }
  const parsed: number[] = [];
  for (let index = 0; index < value.length; index += 1) {
    parsed.push(requireByte(value[index], `${label}[${index}]`));
  }
  return parsed;
}

function requireBytes32(value: unknown, label: string, nonzero: boolean): number[] {
  const parsed = requireBytes(value, label, 32, 32);
  if (nonzero && isZeroBytes(parsed)) throw new Error(`${label} must be nonzero`);
  return parsed;
}

function isZeroBytes(value: readonly number[]): boolean {
  for (const byte of value) {
    if (byte !== 0) return false;
  }
  return true;
}

function equalBytes(left: readonly number[], right: readonly number[]): boolean {
  if (left.length !== right.length) return false;
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) return false;
  }
  return true;
}

function u32BigEndian(value: number): Uint8Array {
  const bytes = new Uint8Array(4);
  new DataView(bytes.buffer).setUint32(0, value, false);
  return bytes;
}

function u16BigEndian(value: number): Uint8Array {
  const bytes = new Uint8Array(2);
  new DataView(bytes.buffer).setUint16(0, value, false);
  return bytes;
}

function u64BigEndian(value: number): Uint8Array {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new Error('u64 value must be a positive safe integer');
  }
  const bytes = new Uint8Array(8);
  new DataView(bytes.buffer).setBigUint64(0, BigInt(value), false);
  return bytes;
}

function concatenateBytes(chunks: readonly Uint8Array[]): Uint8Array {
  let length = 0;
  for (const chunk of chunks) length += chunk.length;
  const output = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.length;
  }
  return output;
}

function lengthDelimited(value: Uint8Array): Uint8Array {
  return concatenateBytes([u32BigEndian(value.length), value]);
}

function labeledField(label: string, value: Uint8Array): Uint8Array {
  return concatenateBytes([lengthDelimited(UTF8.encode(label)), lengthDelimited(value)]);
}

async function sha256(value: Uint8Array): Promise<Uint8Array> {
  const digest = await globalThis.crypto.subtle.digest('SHA-256', value);
  return new Uint8Array(digest);
}

export async function deriveRouterAbEd25519YaoApplicationBindingDigestV1(
  facts: RouterAbEd25519YaoApplicationBindingFactsV1,
): Promise<number[]> {
  const encoded = concatenateBytes([
    lengthDelimited(UTF8.encode(APPLICATION_BINDING_DOMAIN)),
    labeledField('walletId', UTF8.encode(facts.wallet_id)),
    labeledField('nearEd25519SigningKeyId', UTF8.encode(facts.near_ed25519_signing_key_id)),
    labeledField('signingRootId', UTF8.encode(facts.signing_root_id)),
    labeledField('keyCreationSignerSlot', u32BigEndian(facts.key_creation_signer_slot)),
  ]);
  return Array.from(await sha256(encoded));
}

export async function deriveRouterAbEd25519YaoStableContextBindingV1(
  applicationBinding: RouterAbEd25519YaoApplicationBindingFactsV1,
  participantIds: readonly [number, number],
): Promise<number[]> {
  const applicationDigest =
    await deriveRouterAbEd25519YaoApplicationBindingDigestV1(applicationBinding);
  const context = concatenateBytes([
    UTF8.encode(STABLE_KEY_CONTEXT_DOMAIN),
    Uint8Array.from(applicationDigest),
    u16BigEndian(participantIds[0]),
    u16BigEndian(participantIds[1]),
  ]);
  return Array.from(
    await sha256(concatenateBytes([UTF8.encode(STABLE_KEY_CONTEXT_BINDING_DOMAIN), context])),
  );
}

export async function deriveRouterAbEd25519YaoRuntimePolicyBindingV1(input: {
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
  readonly signingRootVersion: string;
}): Promise<number[]> {
  const encoded = concatenateBytes([
    lengthDelimited(UTF8.encode(RUNTIME_POLICY_BINDING_DOMAIN)),
    labeledField('orgId', UTF8.encode(requireVisibleIdentifier(input.orgId, 'orgId'))),
    labeledField('projectId', UTF8.encode(requireVisibleIdentifier(input.projectId, 'projectId'))),
    labeledField('envId', UTF8.encode(requireVisibleIdentifier(input.envId, 'envId'))),
    labeledField(
      'signingRootVersion',
      UTF8.encode(requireVisibleIdentifier(input.signingRootVersion, 'signingRootVersion')),
    ),
  ]);
  return Array.from(await sha256(encoded));
}

function exportIdentityFields(
  identity: RouterAbEd25519YaoExportAuthorizationIdentityV1,
): Uint8Array[] {
  const scope = identity.scope;
  const application = identity.application_binding;
  return [
    labeledField('lifecycleId', UTF8.encode(scope.lifecycle_id)),
    labeledField('rootShareEpoch', UTF8.encode(scope.root_share_epoch)),
    labeledField('accountId', UTF8.encode(scope.account_id)),
    labeledField('walletSessionId', UTF8.encode(scope.wallet_session_id)),
    labeledField('signerSetId', UTF8.encode(scope.signer_set_id)),
    labeledField('signingWorkerId', UTF8.encode(scope.signing_worker_id)),
    labeledField('walletId', UTF8.encode(application.wallet_id)),
    labeledField('nearEd25519SigningKeyId', UTF8.encode(application.near_ed25519_signing_key_id)),
    labeledField('signingRootId', UTF8.encode(application.signing_root_id)),
    labeledField('keyCreationSignerSlot', u32BigEndian(application.key_creation_signer_slot)),
    labeledField('participantA', u16BigEndian(identity.participant_ids[0])),
    labeledField('participantB', u16BigEndian(identity.participant_ids[1])),
    labeledField('registeredPublicKey', Uint8Array.from(identity.registered_public_key)),
    labeledField('stateEpoch', u64BigEndian(identity.state_epoch)),
    labeledField('runtimePolicyBinding', Uint8Array.from(identity.runtime_policy_binding)),
  ];
}

export async function deriveRouterAbEd25519YaoExportConfirmationDigestV1(input: {
  readonly identity: RouterAbEd25519YaoExportAuthorizationIdentityV1;
  readonly nonce: RouterAbEd25519YaoBytes32V1;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
}): Promise<number[]> {
  const nonce = requireBytes32(input.nonce, 'export authorization nonce', true);
  if (input.expiresAtMs <= input.issuedAtMs) {
    throw new Error('export authorization expiry must follow issue time');
  }
  const encoded = concatenateBytes([
    lengthDelimited(UTF8.encode(EXPORT_CONFIRMATION_DOMAIN)),
    ...exportIdentityFields(input.identity),
    labeledField('nonce', Uint8Array.from(nonce)),
    labeledField('issuedAtMs', u64BigEndian(input.issuedAtMs)),
    labeledField('expiresAtMs', u64BigEndian(input.expiresAtMs)),
  ]);
  return Array.from(await sha256(encoded));
}

export async function deriveRouterAbEd25519YaoExportAuthorizationDigestV1(input: {
  readonly identity: RouterAbEd25519YaoExportAuthorizationIdentityV1;
  readonly confirmationDigest: RouterAbEd25519YaoBytes32V1;
  readonly nonce: RouterAbEd25519YaoBytes32V1;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
  readonly thresholdSessionId: string;
  readonly signingGrantId: string;
  readonly authority: RouterAbEd25519YaoExportAuthorityBindingV1;
}): Promise<number[]> {
  const confirmationDigest = requireBytes32(
    input.confirmationDigest,
    'export confirmation digest',
    true,
  );
  const nonce = requireBytes32(input.nonce, 'export authorization nonce', true);
  const encoded = concatenateBytes([
    lengthDelimited(UTF8.encode(EXPORT_AUTHORIZATION_DOMAIN)),
    ...exportIdentityFields(input.identity),
    labeledField('confirmationDigest', Uint8Array.from(confirmationDigest)),
    labeledField('nonce', Uint8Array.from(nonce)),
    labeledField('issuedAtMs', u64BigEndian(input.issuedAtMs)),
    labeledField('expiresAtMs', u64BigEndian(input.expiresAtMs)),
    labeledField(
      'thresholdSessionId',
      UTF8.encode(requireVisibleIdentifier(input.thresholdSessionId, 'thresholdSessionId')),
    ),
    labeledField(
      'signingGrantId',
      UTF8.encode(requireVisibleIdentifier(input.signingGrantId, 'signingGrantId')),
    ),
    labeledField('authorityKind', UTF8.encode(input.authority.kind)),
    labeledField(
      'authoritySubject',
      UTF8.encode(
        input.authority.kind === 'passkey'
          ? requireVisibleIdentifier(input.authority.credentialIdB64u, 'credentialIdB64u')
          : requireVisibleIdentifier(input.authority.providerSubjectId, 'providerSubjectId'),
      ),
    ),
  ]);
  return Array.from(await sha256(encoded));
}

function parseOperation(value: unknown, label: string): RouterAbEd25519YaoOperationV1 {
  switch (value) {
    case 'registration':
    case 'recovery':
    case 'refresh':
    case 'export':
      return value;
    default:
      throw new Error(`${label} is invalid`);
  }
}

function parseDeriverRole(value: unknown, label: string): RouterAbEd25519YaoDeriverRoleV1 {
  switch (value) {
    case 'deriver_a':
    case 'deriver_b':
      return value;
    default:
      throw new Error(`${label} is invalid`);
  }
}

function parseInputKind(value: unknown, label: string): RouterAbEd25519YaoInputKindV1 {
  switch (value) {
    case 'activation':
    case 'export':
      return value;
    default:
      throw new Error(`${label} is invalid`);
  }
}

function parsePackageKind(value: unknown, label: string): RouterAbEd25519YaoPackageKindV1 {
  switch (value) {
    case 'activation_client':
    case 'activation_signing_worker':
    case 'export_client':
      return value;
    default:
      throw new Error(`${label} is invalid`);
  }
}

function parseWorkKind(value: unknown, label: string): RouterAbEd25519YaoWorkKindV1 {
  switch (value) {
    case 'registration_prepare':
    case 'key_export':
    case 'recovery':
    case 'server_share_refresh':
      return value;
    default:
      throw new Error(`${label} is invalid`);
  }
}

function parsePrimitiveRequestKind(
  value: unknown,
  label: string,
): RouterAbEd25519YaoPrimitiveRequestKindV1 {
  switch (value) {
    case 'registration':
    case 'recovery':
    case 'export':
    case 'refresh':
      return value;
    default:
      throw new Error(`${label} is invalid`);
  }
}

function parseApplicationBinding(value: unknown): RouterAbEd25519YaoApplicationBindingFactsV1 {
  const record = requireRecord(value, 'application_binding');
  requireExactKeys(record, 'application_binding', [
    'wallet_id',
    'near_ed25519_signing_key_id',
    'signing_root_id',
    'key_creation_signer_slot',
  ]);
  return {
    wallet_id: requireVisibleIdentifier(record.wallet_id, 'application_binding.wallet_id'),
    near_ed25519_signing_key_id: requireVisibleIdentifier(
      record.near_ed25519_signing_key_id,
      'application_binding.near_ed25519_signing_key_id',
    ),
    signing_root_id: requireVisibleIdentifier(
      record.signing_root_id,
      'application_binding.signing_root_id',
    ),
    key_creation_signer_slot: requirePositiveU32(
      record.key_creation_signer_slot,
      'application_binding.key_creation_signer_slot',
    ),
  };
}

function parsePublicLifecycleScope(value: unknown): RouterAbEd25519YaoLifecycleScopeV1 {
  const record = requireRecord(value, 'scope');
  requireExactKeys(record, 'scope', [
    'lifecycle_id',
    'root_share_epoch',
    'account_id',
    'wallet_session_id',
    'signer_set_id',
    'signing_worker_id',
  ]);
  return {
    lifecycle_id: requireVisibleIdentifier(record.lifecycle_id, 'scope.lifecycle_id'),
    root_share_epoch: requireVisibleIdentifier(record.root_share_epoch, 'scope.root_share_epoch'),
    account_id: requireVisibleIdentifier(record.account_id, 'scope.account_id'),
    wallet_session_id: requireVisibleIdentifier(
      record.wallet_session_id,
      'scope.wallet_session_id',
    ),
    signer_set_id: requireVisibleIdentifier(record.signer_set_id, 'scope.signer_set_id'),
    signing_worker_id: requireVisibleIdentifier(
      record.signing_worker_id,
      'scope.signing_worker_id',
    ),
  };
}

function parseParticipantIds(value: unknown): readonly [number, number] {
  if (!Array.isArray(value) || value.length !== 2) {
    throw new Error('participant_ids must contain exactly two values');
  }
  const first = requirePositiveU32(value[0], 'participant_ids[0]');
  const second = requirePositiveU32(value[1], 'participant_ids[1]');
  if (first > 0xffff || second > 0xffff || first >= second) {
    throw new Error('participant_ids must be distinct, nonzero, ascending u16 values');
  }
  return [first, second];
}

function parseAdmittedLifecycle(value: unknown): RouterAbEd25519YaoAdmittedLifecycleV1 {
  const record = requireRecord(value, 'binding.lifecycle');
  requireExactKeys(record, 'binding.lifecycle', [
    'lifecycle_id',
    'work_kind',
    'primitive_request_kind',
    'root_share_epoch',
    'account_id',
    'session_id',
    'signer_set_id',
    'selected_server_id',
  ]);
  const lifecycle = {
    lifecycle_id: requireVisibleIdentifier(record.lifecycle_id, 'binding.lifecycle.lifecycle_id'),
    work_kind: parseWorkKind(record.work_kind, 'binding.lifecycle.work_kind'),
    primitive_request_kind: parsePrimitiveRequestKind(
      record.primitive_request_kind,
      'binding.lifecycle.primitive_request_kind',
    ),
    root_share_epoch: requireVisibleIdentifier(
      record.root_share_epoch,
      'binding.lifecycle.root_share_epoch',
    ),
    account_id: requireVisibleIdentifier(record.account_id, 'binding.lifecycle.account_id'),
    session_id: requireVisibleIdentifier(record.session_id, 'binding.lifecycle.session_id'),
    signer_set_id: requireVisibleIdentifier(
      record.signer_set_id,
      'binding.lifecycle.signer_set_id',
    ),
    selected_server_id: requireVisibleIdentifier(
      record.selected_server_id,
      'binding.lifecycle.selected_server_id',
    ),
  };
  if (
    lifecycle.work_kind === REGISTRATION_WORK_KIND &&
    lifecycle.primitive_request_kind !== REGISTRATION_PRIMITIVE_REQUEST_KIND
  ) {
    throw new Error('binding.lifecycle primitive request kind does not match its work kind');
  }
  if (
    lifecycle.work_kind === RECOVERY_WORK_KIND &&
    lifecycle.primitive_request_kind !== RECOVERY_PRIMITIVE_REQUEST_KIND
  ) {
    throw new Error('binding.lifecycle primitive request kind does not match its work kind');
  }
  if (
    lifecycle.work_kind === EXPORT_WORK_KIND &&
    lifecycle.primitive_request_kind !== EXPORT_PRIMITIVE_REQUEST_KIND
  ) {
    throw new Error('binding.lifecycle primitive request kind does not match its work kind');
  }
  return lifecycle;
}

function parseCeremonyBinding(value: unknown): RouterAbEd25519YaoCeremonyBindingV1 {
  const record = requireRecord(value, 'binding');
  requireExactKeys(record, 'binding', [
    'lifecycle',
    'operation',
    'session_id',
    'stable_key_context_binding',
  ]);
  const binding = {
    lifecycle: parseAdmittedLifecycle(record.lifecycle),
    operation: parseOperation(record.operation, 'binding.operation'),
    session_id: requireBytes32(record.session_id, 'binding.session_id', true),
    stable_key_context_binding: requireBytes32(
      record.stable_key_context_binding,
      'binding.stable_key_context_binding',
      false,
    ),
  };
  if (
    binding.operation === 'registration' &&
    binding.lifecycle.work_kind !== REGISTRATION_WORK_KIND
  ) {
    throw new Error('binding operation does not match its lifecycle work kind');
  }
  if (binding.operation === 'recovery' && binding.lifecycle.work_kind !== RECOVERY_WORK_KIND) {
    throw new Error('binding operation does not match its lifecycle work kind');
  }
  if (binding.operation === 'export' && binding.lifecycle.work_kind !== EXPORT_WORK_KIND) {
    throw new Error('binding operation does not match its lifecycle work kind');
  }
  return binding;
}

function requireExportCeremonyBinding(value: unknown): RouterAbEd25519YaoExportCeremonyBindingV1 {
  const binding = parseCeremonyBinding(value);
  if (
    binding.operation !== 'export' ||
    binding.lifecycle.work_kind !== EXPORT_WORK_KIND ||
    binding.lifecycle.primitive_request_kind !== EXPORT_PRIMITIVE_REQUEST_KIND
  ) {
    throw new Error('export binding requires the exact export lifecycle');
  }
  return {
    lifecycle: {
      lifecycle_id: binding.lifecycle.lifecycle_id,
      work_kind: EXPORT_WORK_KIND,
      primitive_request_kind: EXPORT_PRIMITIVE_REQUEST_KIND,
      root_share_epoch: binding.lifecycle.root_share_epoch,
      account_id: binding.lifecycle.account_id,
      session_id: binding.lifecycle.session_id,
      signer_set_id: binding.lifecycle.signer_set_id,
      selected_server_id: binding.lifecycle.selected_server_id,
    },
    operation: 'export',
    session_id: binding.session_id,
    stable_key_context_binding: binding.stable_key_context_binding,
  };
}

function parseExportBinding(value: unknown): RouterAbEd25519YaoExportBindingV1 {
  const record = requireRecord(value, 'export binding');
  requireExactKeys(record, 'export binding', [
    'ceremony',
    'registered_public_key',
    'state_epoch',
    'runtime_policy_binding',
    'authorization_digest',
  ]);
  return {
    ceremony: requireExportCeremonyBinding(record.ceremony),
    registered_public_key: requireBytes32(
      record.registered_public_key,
      'export binding.registered_public_key',
      true,
    ),
    state_epoch: requirePositiveSafeInteger(record.state_epoch, 'export binding.state_epoch'),
    runtime_policy_binding: requireBytes32(
      record.runtime_policy_binding,
      'export binding.runtime_policy_binding',
      true,
    ),
    authorization_digest: requireBytes32(
      record.authorization_digest,
      'export binding.authorization_digest',
      true,
    ),
  };
}

function requireActivationBinding(
  binding: RouterAbEd25519YaoCeremonyBindingV1,
): RouterAbEd25519YaoActivationBindingV1 {
  switch (binding.operation) {
    case 'registration':
      if (
        binding.lifecycle.work_kind !== REGISTRATION_WORK_KIND ||
        binding.lifecycle.primitive_request_kind !== REGISTRATION_PRIMITIVE_REQUEST_KIND
      ) {
        throw new Error('activation binding has the wrong registration lifecycle kind');
      }
      return {
        lifecycle: {
          lifecycle_id: binding.lifecycle.lifecycle_id,
          work_kind: REGISTRATION_WORK_KIND,
          primitive_request_kind: REGISTRATION_PRIMITIVE_REQUEST_KIND,
          root_share_epoch: binding.lifecycle.root_share_epoch,
          account_id: binding.lifecycle.account_id,
          session_id: binding.lifecycle.session_id,
          signer_set_id: binding.lifecycle.signer_set_id,
          selected_server_id: binding.lifecycle.selected_server_id,
        },
        operation: 'registration',
        session_id: binding.session_id,
        stable_key_context_binding: binding.stable_key_context_binding,
      };
    case 'recovery':
      if (
        binding.lifecycle.work_kind !== RECOVERY_WORK_KIND ||
        binding.lifecycle.primitive_request_kind !== RECOVERY_PRIMITIVE_REQUEST_KIND
      ) {
        throw new Error('activation binding has the wrong recovery lifecycle kind');
      }
      return {
        lifecycle: {
          lifecycle_id: binding.lifecycle.lifecycle_id,
          work_kind: RECOVERY_WORK_KIND,
          primitive_request_kind: RECOVERY_PRIMITIVE_REQUEST_KIND,
          root_share_epoch: binding.lifecycle.root_share_epoch,
          account_id: binding.lifecycle.account_id,
          session_id: binding.lifecycle.session_id,
          signer_set_id: binding.lifecycle.signer_set_id,
          selected_server_id: binding.lifecycle.selected_server_id,
        },
        operation: 'recovery',
        session_id: binding.session_id,
        stable_key_context_binding: binding.stable_key_context_binding,
      };
    case 'refresh':
    case 'export':
      throw new Error('activation binding has a non-activation operation');
  }
}

function parseKeyset(value: unknown): RouterAbEd25519YaoActivationKeysetV1 {
  const record = requireRecord(value, 'keyset');
  requireExactKeys(record, 'keyset', [
    'deriver_a_input_public_key',
    'deriver_b_input_public_key',
    'signing_worker_recipient_public_key',
  ]);
  const keyset = {
    deriver_a_input_public_key: requireBytes32(
      record.deriver_a_input_public_key,
      'keyset.deriver_a_input_public_key',
      true,
    ),
    deriver_b_input_public_key: requireBytes32(
      record.deriver_b_input_public_key,
      'keyset.deriver_b_input_public_key',
      true,
    ),
    signing_worker_recipient_public_key: requireBytes32(
      record.signing_worker_recipient_public_key,
      'keyset.signing_worker_recipient_public_key',
      true,
    ),
  };
  if (
    equalBytes(keyset.deriver_a_input_public_key, keyset.deriver_b_input_public_key) ||
    equalBytes(keyset.deriver_a_input_public_key, keyset.signing_worker_recipient_public_key) ||
    equalBytes(keyset.deriver_b_input_public_key, keyset.signing_worker_recipient_public_key)
  ) {
    throw new Error('keyset public keys must be distinct');
  }
  return keyset;
}

function parseEncryptedInput(value: unknown, label: string): RouterAbEd25519YaoEncryptedInputV1 {
  const record = requireRecord(value, label);
  requireExactKeys(record, label, [
    'kind',
    'deriver',
    'operation',
    'session',
    'stable_context_binding',
    'encapsulated_key',
    'ciphertext',
  ]);
  const input = {
    kind: parseInputKind(record.kind, `${label}.kind`),
    deriver: parseDeriverRole(record.deriver, `${label}.deriver`),
    operation: parseOperation(record.operation, `${label}.operation`),
    session: requireBytes32(record.session, `${label}.session`, true),
    stable_context_binding: requireBytes32(
      record.stable_context_binding,
      `${label}.stable_context_binding`,
      true,
    ),
    encapsulated_key: requireBytes32(record.encapsulated_key, `${label}.encapsulated_key`, true),
    ciphertext: requireBytes(
      record.ciphertext,
      `${label}.ciphertext`,
      16,
      ED25519_YAO_CONTROL_CIPHERTEXT_MAX_BYTES_V1,
    ),
  };
  if (input.kind === 'activation' && input.operation === 'export') {
    throw new Error(`${label} operation does not match its circuit family`);
  }
  if (input.kind === 'export' && input.operation !== 'export') {
    throw new Error(`${label} operation does not match its circuit family`);
  }
  return input;
}

function requireActivationInput<Role extends RouterAbEd25519YaoDeriverRoleV1>(
  binding: RouterAbEd25519YaoActivationBindingV1,
  input: RouterAbEd25519YaoEncryptedInputV1,
  expectedDeriver: Role,
  label: string,
): RouterAbEd25519YaoActivationEncryptedInputV1<Role> {
  if (
    input.kind !== 'activation' ||
    input.deriver !== expectedDeriver ||
    input.operation !== binding.operation ||
    !equalBytes(input.session, binding.session_id) ||
    !equalBytes(input.stable_context_binding, binding.stable_key_context_binding)
  ) {
    throw new Error(`${label} does not match the admitted activation binding`);
  }
  switch (binding.operation) {
    case 'registration':
      return {
        kind: 'activation',
        deriver: expectedDeriver,
        operation: 'registration',
        session: input.session,
        stable_context_binding: input.stable_context_binding,
        encapsulated_key: input.encapsulated_key,
        ciphertext: input.ciphertext,
      };
    case 'recovery':
      return {
        kind: 'activation',
        deriver: expectedDeriver,
        operation: 'recovery',
        session: input.session,
        stable_context_binding: input.stable_context_binding,
        encapsulated_key: input.encapsulated_key,
        ciphertext: input.ciphertext,
      };
  }
}

function requireExportInput<Role extends RouterAbEd25519YaoDeriverRoleV1>(
  binding: RouterAbEd25519YaoExportBindingV1,
  input: RouterAbEd25519YaoEncryptedInputV1,
  expectedDeriver: Role,
  label: string,
): RouterAbEd25519YaoExportEncryptedInputV1<Role> {
  if (
    input.kind !== 'export' ||
    input.deriver !== expectedDeriver ||
    input.operation !== 'export' ||
    !equalBytes(input.session, binding.ceremony.session_id) ||
    !equalBytes(input.stable_context_binding, binding.ceremony.stable_key_context_binding)
  ) {
    throw new Error(`${label} does not match the admitted export binding`);
  }
  return {
    kind: 'export',
    deriver: expectedDeriver,
    operation: 'export',
    session: input.session,
    stable_context_binding: input.stable_context_binding,
    encapsulated_key: input.encapsulated_key,
    ciphertext: input.ciphertext,
  };
}

function parseEncryptedPackage(
  value: unknown,
  label: string,
): RouterAbEd25519YaoEncryptedPackageV1 {
  const record = requireRecord(value, label);
  requireExactKeys(record, label, [
    'kind',
    'deriver',
    'session',
    'transcript',
    'encapsulated_key',
    'ciphertext',
  ]);
  return {
    kind: parsePackageKind(record.kind, `${label}.kind`),
    deriver: parseDeriverRole(record.deriver, `${label}.deriver`),
    session: requireBytes32(record.session, `${label}.session`, true),
    transcript: requireBytes32(record.transcript, `${label}.transcript`, true),
    encapsulated_key: requireBytes32(record.encapsulated_key, `${label}.encapsulated_key`, true),
    ciphertext: requireBytes(
      record.ciphertext,
      `${label}.ciphertext`,
      16,
      ED25519_YAO_CONTROL_CIPHERTEXT_MAX_BYTES_V1,
    ),
  };
}

function parsePublicReceipt(value: unknown): RouterAbEd25519YaoActivationPublicReceiptV1 {
  const record = requireRecord(value, 'public_receipt');
  requireExactKeys(record, 'public_receipt', [
    'transcript',
    'registered_public_key',
    'joined_client_commitment',
    'joined_signing_worker_commitment',
    'signing_worker_verifying_share',
    'state_epoch',
  ]);
  return {
    transcript: requireBytes32(record.transcript, 'public_receipt.transcript', true),
    registered_public_key: requireBytes32(
      record.registered_public_key,
      'public_receipt.registered_public_key',
      true,
    ),
    joined_client_commitment: requireBytes32(
      record.joined_client_commitment,
      'public_receipt.joined_client_commitment',
      true,
    ),
    joined_signing_worker_commitment: requireBytes32(
      record.joined_signing_worker_commitment,
      'public_receipt.joined_signing_worker_commitment',
      true,
    ),
    signing_worker_verifying_share: requireBytes32(
      record.signing_worker_verifying_share,
      'public_receipt.signing_worker_verifying_share',
      true,
    ),
    state_epoch: requirePositiveSafeInteger(record.state_epoch, 'public_receipt.state_epoch'),
  };
}

function requireActivationClientPackage<Role extends RouterAbEd25519YaoDeriverRoleV1>(
  binding: RouterAbEd25519YaoActivationBindingV1,
  receipt: RouterAbEd25519YaoActivationPublicReceiptV1,
  packageValue: RouterAbEd25519YaoEncryptedPackageV1,
  expectedDeriver: Role,
  label: string,
): RouterAbEd25519YaoActivationClientPackageV1<Role> {
  if (
    packageValue.kind !== 'activation_client' ||
    packageValue.deriver !== expectedDeriver ||
    !equalBytes(packageValue.session, binding.session_id) ||
    !equalBytes(packageValue.transcript, receipt.transcript)
  ) {
    throw new Error(`${label} does not match the terminal activation receipt`);
  }
  return {
    kind: 'activation_client',
    deriver: expectedDeriver,
    session: packageValue.session,
    transcript: packageValue.transcript,
    encapsulated_key: packageValue.encapsulated_key,
    ciphertext: packageValue.ciphertext,
  };
}

function requireExportClientPackage<Role extends RouterAbEd25519YaoDeriverRoleV1>(
  binding: RouterAbEd25519YaoExportBindingV1,
  transcript: RouterAbEd25519YaoBytes32V1,
  packageValue: RouterAbEd25519YaoEncryptedPackageV1,
  expectedDeriver: Role,
  label: string,
): RouterAbEd25519YaoExportClientPackageV1<Role> {
  if (
    packageValue.kind !== 'export_client' ||
    packageValue.deriver !== expectedDeriver ||
    !equalBytes(packageValue.session, binding.ceremony.session_id) ||
    !equalBytes(packageValue.transcript, transcript)
  ) {
    throw new Error(`${label} does not match the terminal export result`);
  }
  return {
    kind: 'export_client',
    deriver: expectedDeriver,
    session: packageValue.session,
    transcript: packageValue.transcript,
    encapsulated_key: packageValue.encapsulated_key,
    ciphertext: packageValue.ciphertext,
  };
}

function parseBoundary<T>(
  parser: (value: unknown) => T,
  value: unknown,
): RouterAbEd25519YaoParseResult<T> {
  try {
    return { ok: true, value: parser(value) };
  } catch (error: unknown) {
    return {
      ok: false,
      code: 'invalid_body',
      message: error instanceof Error ? error.message : String(error),
    };
  }
}

function parseRegistrationAdmissionRequestValue(
  value: unknown,
): RouterAbEd25519YaoRegistrationAdmissionRequestV1 {
  const record = requireRecord(value, 'registration admission request');
  requireExactKeys(record, 'registration admission request', [
    'scope',
    'application_binding',
    'participant_ids',
  ]);
  return {
    scope: parsePublicLifecycleScope(record.scope),
    application_binding: parseApplicationBinding(record.application_binding),
    participant_ids: parseParticipantIds(record.participant_ids),
  };
}

function parseRecoveryAdmissionRequestValue(
  value: unknown,
): RouterAbEd25519YaoRecoveryAdmissionRequestV1 {
  const record = requireRecord(value, 'recovery admission request');
  requireExactKeys(record, 'recovery admission request', [
    'scope',
    'application_binding',
    'participant_ids',
    'active_capability_binding',
    'replacement_capability_binding',
    'registered_public_key',
  ]);
  const activeCapabilityBinding = requireBytes32(
    record.active_capability_binding,
    'recovery admission request.active_capability_binding',
    true,
  );
  const replacementCapabilityBinding = requireBytes32(
    record.replacement_capability_binding,
    'recovery admission request.replacement_capability_binding',
    true,
  );
  if (equalBytes(activeCapabilityBinding, replacementCapabilityBinding)) {
    throw new Error('recovery replacement capability binding must be fresh');
  }
  return {
    scope: parsePublicLifecycleScope(record.scope),
    application_binding: parseApplicationBinding(record.application_binding),
    participant_ids: parseParticipantIds(record.participant_ids),
    active_capability_binding: activeCapabilityBinding,
    replacement_capability_binding: replacementCapabilityBinding,
    registered_public_key: requireBytes32(
      record.registered_public_key,
      'recovery admission request.registered_public_key',
      true,
    ),
  };
}

function parseWarmRecoveryBootstrapRequestValue(
  value: unknown,
): RouterAbEd25519YaoWarmRecoveryBootstrapRequestV1 {
  const record = requireRecord(value, 'warm recovery bootstrap request');
  requireExactKeys(record, 'warm recovery bootstrap request', [
    'kind',
    'walletId',
    'nearAccountId',
    'nearEd25519SigningKeyId',
    'signerSlot',
    'thresholdSessionId',
    'signingGrantId',
    'signingWorkerId',
    'participantIds',
  ]);
  if (record.kind !== 'router_ab_ed25519_yao_warm_recovery_bootstrap_request_v1') {
    throw new Error('warm recovery bootstrap request.kind is invalid');
  }
  return {
    kind: 'router_ab_ed25519_yao_warm_recovery_bootstrap_request_v1',
    walletId: requireVisibleIdentifier(record.walletId, 'warm recovery bootstrap request.walletId'),
    nearAccountId: requireVisibleIdentifier(
      record.nearAccountId,
      'warm recovery bootstrap request.nearAccountId',
    ),
    nearEd25519SigningKeyId: requireVisibleIdentifier(
      record.nearEd25519SigningKeyId,
      'warm recovery bootstrap request.nearEd25519SigningKeyId',
    ),
    signerSlot: requirePositiveSafeInteger(
      record.signerSlot,
      'warm recovery bootstrap request.signerSlot',
    ),
    thresholdSessionId: requireVisibleIdentifier(
      record.thresholdSessionId,
      'warm recovery bootstrap request.thresholdSessionId',
    ),
    signingGrantId: requireVisibleIdentifier(
      record.signingGrantId,
      'warm recovery bootstrap request.signingGrantId',
    ),
    signingWorkerId: requireVisibleIdentifier(
      record.signingWorkerId,
      'warm recovery bootstrap request.signingWorkerId',
    ),
    participantIds: parseParticipantIds(record.participantIds),
  };
}

function parseExportAuthorization(value: unknown): RouterAbEd25519YaoExportAuthorizationV1 {
  const record = requireRecord(value, 'export authorization');
  requireExactKeys(record, 'export authorization', [
    'confirmation_digest',
    'authorization_digest',
    'nonce',
    'issued_at_ms',
    'expires_at_ms',
  ]);
  const issuedAtMs = requirePositiveSafeInteger(
    record.issued_at_ms,
    'export authorization.issued_at_ms',
  );
  const expiresAtMs = requirePositiveSafeInteger(
    record.expires_at_ms,
    'export authorization.expires_at_ms',
  );
  if (expiresAtMs <= issuedAtMs) {
    throw new Error('export authorization expiry must follow its issue time');
  }
  return {
    confirmation_digest: requireBytes32(
      record.confirmation_digest,
      'export authorization.confirmation_digest',
      true,
    ),
    authorization_digest: requireBytes32(
      record.authorization_digest,
      'export authorization.authorization_digest',
      true,
    ),
    nonce: requireBytes32(record.nonce, 'export authorization.nonce', true),
    issued_at_ms: issuedAtMs,
    expires_at_ms: expiresAtMs,
  };
}

function parseExportAdmissionRequestValue(
  value: unknown,
): RouterAbEd25519YaoExportAdmissionRequestV1 {
  const record = requireRecord(value, 'export admission request');
  requireExactKeys(record, 'export admission request', [
    'scope',
    'application_binding',
    'participant_ids',
    'registered_public_key',
    'state_epoch',
    'runtime_policy_binding',
    'authorization',
  ]);
  return {
    scope: parsePublicLifecycleScope(record.scope),
    application_binding: parseApplicationBinding(record.application_binding),
    participant_ids: parseParticipantIds(record.participant_ids),
    registered_public_key: requireBytes32(
      record.registered_public_key,
      'export admission request.registered_public_key',
      true,
    ),
    state_epoch: requirePositiveSafeInteger(
      record.state_epoch,
      'export admission request.state_epoch',
    ),
    runtime_policy_binding: requireBytes32(
      record.runtime_policy_binding,
      'export admission request.runtime_policy_binding',
      true,
    ),
    authorization: parseExportAuthorization(record.authorization),
  };
}

function parseExportAdmissionReceiptValue(
  value: unknown,
): RouterAbEd25519YaoExportAdmissionReceiptV1 {
  const record = requireRecord(value, 'export admission receipt');
  requireExactKeys(record, 'export admission receipt', ['binding', 'keyset']);
  return {
    binding: parseExportBinding(record.binding),
    keyset: parseKeyset(record.keyset),
  };
}

function parseExportExecuteRequestValue(value: unknown): RouterAbEd25519YaoExportExecuteRequestV1 {
  const record = requireRecord(value, 'export execute request');
  requireExactKeys(record, 'export execute request', [
    'binding',
    'deriver_a_input',
    'deriver_b_input',
  ]);
  const binding = parseExportBinding(record.binding);
  return {
    binding,
    deriver_a_input: requireExportInput(
      binding,
      parseEncryptedInput(record.deriver_a_input, 'deriver_a_input'),
      'deriver_a',
      'deriver_a_input',
    ),
    deriver_b_input: requireExportInput(
      binding,
      parseEncryptedInput(record.deriver_b_input, 'deriver_b_input'),
      'deriver_b',
      'deriver_b_input',
    ),
  };
}

function parseExportResultValue(value: unknown): RouterAbEd25519YaoExportResultV1 {
  const record = requireRecord(value, 'export result');
  requireExactKeys(record, 'export result', [
    'binding',
    'transcript',
    'deriver_a_client_package',
    'deriver_b_client_package',
  ]);
  const binding = parseExportBinding(record.binding);
  const transcript = requireBytes32(record.transcript, 'export result.transcript', true);
  return {
    binding,
    transcript,
    deriver_a_client_package: requireExportClientPackage(
      binding,
      transcript,
      parseEncryptedPackage(record.deriver_a_client_package, 'deriver_a_client_package'),
      'deriver_a',
      'deriver_a_client_package',
    ),
    deriver_b_client_package: requireExportClientPackage(
      binding,
      transcript,
      parseEncryptedPackage(record.deriver_b_client_package, 'deriver_b_client_package'),
      'deriver_b',
      'deriver_b_client_package',
    ),
  };
}

function parseActivationAdmissionReceiptValue(
  value: unknown,
): RouterAbEd25519YaoActivationAdmissionReceiptV1 {
  const record = requireRecord(value, 'activation admission receipt');
  requireExactKeys(record, 'activation admission receipt', ['binding', 'keyset']);
  const binding = requireActivationBinding(parseCeremonyBinding(record.binding));
  const keyset = parseKeyset(record.keyset);
  switch (binding.operation) {
    case 'registration':
      return { binding, keyset };
    case 'recovery':
      return { binding, keyset };
  }
}

function parseActivationExecuteRequestValue(
  value: unknown,
): RouterAbEd25519YaoActivationExecuteRequestV1 {
  const record = requireRecord(value, 'activation execute request');
  requireExactKeys(record, 'activation execute request', [
    'binding',
    'deriver_a_input',
    'deriver_b_input',
  ]);
  const binding = requireActivationBinding(parseCeremonyBinding(record.binding));
  const deriverAInput = requireActivationInput(
    binding,
    parseEncryptedInput(record.deriver_a_input, 'deriver_a_input'),
    'deriver_a',
    'deriver_a_input',
  );
  const deriverBInput = requireActivationInput(
    binding,
    parseEncryptedInput(record.deriver_b_input, 'deriver_b_input'),
    'deriver_b',
    'deriver_b_input',
  );
  if (binding.operation === 'registration') {
    if (deriverAInput.operation !== 'registration' || deriverBInput.operation !== 'registration') {
      throw new Error('activation inputs do not match registration binding');
    }
    return { binding, deriver_a_input: deriverAInput, deriver_b_input: deriverBInput };
  }
  if (deriverAInput.operation !== 'recovery' || deriverBInput.operation !== 'recovery') {
    throw new Error('activation inputs do not match recovery binding');
  }
  return { binding, deriver_a_input: deriverAInput, deriver_b_input: deriverBInput };
}

function parseActivationResultValue(value: unknown): RouterAbEd25519YaoActivationResultV1 {
  const record = requireRecord(value, 'activation result');
  requireExactKeys(record, 'activation result', [
    'binding',
    'deriver_a_client_package',
    'deriver_b_client_package',
    'public_receipt',
  ]);
  const binding = requireActivationBinding(parseCeremonyBinding(record.binding));
  const receipt = parsePublicReceipt(record.public_receipt);
  const packageA = parseEncryptedPackage(
    record.deriver_a_client_package,
    'deriver_a_client_package',
  );
  const packageB = parseEncryptedPackage(
    record.deriver_b_client_package,
    'deriver_b_client_package',
  );
  const deriverAPackage = requireActivationClientPackage(
    binding,
    receipt,
    packageA,
    'deriver_a',
    'deriver_a_client_package',
  );
  const deriverBPackage = requireActivationClientPackage(
    binding,
    receipt,
    packageB,
    'deriver_b',
    'deriver_b_client_package',
  );
  switch (binding.operation) {
    case 'registration':
      return {
        binding,
        deriver_a_client_package: deriverAPackage,
        deriver_b_client_package: deriverBPackage,
        public_receipt: receipt,
      };
    case 'recovery':
      return {
        binding,
        deriver_a_client_package: deriverAPackage,
        deriver_b_client_package: deriverBPackage,
        public_receipt: receipt,
      };
  }
}

function requireRecoveryBinding(value: unknown): RouterAbEd25519YaoActivationBindingV1<'recovery'> {
  const binding = requireActivationBinding(parseCeremonyBinding(value));
  switch (binding.operation) {
    case 'registration':
      throw new Error('recovery activation requires a recovery binding');
    case 'recovery':
      return binding;
  }
}

function parseRecoveryActivationRequestValue(
  value: unknown,
): RouterAbEd25519YaoRecoveryActivationRequestV1 {
  const record = requireRecord(value, 'recovery activation request');
  requireExactKeys(record, 'recovery activation request', ['binding', 'public_receipt']);
  return {
    binding: requireRecoveryBinding(record.binding),
    public_receipt: parsePublicReceipt(record.public_receipt),
  };
}

function parseRecoveryActivationReceiptValue(
  value: unknown,
): RouterAbEd25519YaoRecoveryActivationReceiptV1 {
  const record = requireRecord(value, 'recovery activation receipt');
  requireExactKeys(record, 'recovery activation receipt', [
    'binding',
    'public_receipt',
    'active_capability_binding',
    'retired_capability_binding',
  ]);
  const activeCapabilityBinding = requireBytes32(
    record.active_capability_binding,
    'recovery activation receipt.active_capability_binding',
    true,
  );
  const retiredCapabilityBinding = requireBytes32(
    record.retired_capability_binding,
    'recovery activation receipt.retired_capability_binding',
    true,
  );
  if (equalBytes(activeCapabilityBinding, retiredCapabilityBinding)) {
    throw new Error('recovery activation receipt capability bindings must be distinct');
  }
  return {
    binding: requireRecoveryBinding(record.binding),
    public_receipt: parsePublicReceipt(record.public_receipt),
    active_capability_binding: activeCapabilityBinding,
    retired_capability_binding: retiredCapabilityBinding,
  };
}

function isActivationAdmissionReceiptFor<Operation extends RouterAbEd25519YaoActivationOperationV1>(
  value: RouterAbEd25519YaoActivationAdmissionReceiptV1,
  operation: Operation,
): value is RouterAbEd25519YaoActivationAdmissionReceiptV1<Operation> {
  return value.binding.operation === operation;
}

function isActivationExecuteRequestFor<Operation extends RouterAbEd25519YaoActivationOperationV1>(
  value: RouterAbEd25519YaoActivationExecuteRequestV1,
  operation: Operation,
): value is RouterAbEd25519YaoActivationExecuteRequestV1<Operation> {
  return value.binding.operation === operation;
}

function isActivationResultFor<Operation extends RouterAbEd25519YaoActivationOperationV1>(
  value: RouterAbEd25519YaoActivationResultV1,
  operation: Operation,
): value is RouterAbEd25519YaoActivationResultV1<Operation> {
  return value.binding.operation === operation;
}

function operationMismatch<T>(
  operation: RouterAbEd25519YaoActivationOperationV1,
): RouterAbEd25519YaoParseResult<T> {
  return {
    ok: false,
    code: 'invalid_body',
    message: `activation value must use the ${operation} operation`,
  };
}

export function parseRouterAbEd25519YaoRegistrationAdmissionRequestV1(
  value: unknown,
): RouterAbEd25519YaoParseResult<RouterAbEd25519YaoRegistrationAdmissionRequestV1> {
  return parseBoundary(parseRegistrationAdmissionRequestValue, value);
}

export function parseRouterAbEd25519YaoRecoveryAdmissionRequestV1(
  value: unknown,
): RouterAbEd25519YaoParseResult<RouterAbEd25519YaoRecoveryAdmissionRequestV1> {
  return parseBoundary(parseRecoveryAdmissionRequestValue, value);
}

export function parseRouterAbEd25519YaoWarmRecoveryBootstrapRequestV1(
  value: unknown,
): RouterAbEd25519YaoParseResult<RouterAbEd25519YaoWarmRecoveryBootstrapRequestV1> {
  return parseBoundary(parseWarmRecoveryBootstrapRequestValue, value);
}

export function parseRouterAbEd25519YaoExportAdmissionRequestV1(
  value: unknown,
): RouterAbEd25519YaoParseResult<RouterAbEd25519YaoExportAdmissionRequestV1> {
  return parseBoundary(parseExportAdmissionRequestValue, value);
}

export function parseRouterAbEd25519YaoExportAdmissionReceiptV1(
  value: unknown,
): RouterAbEd25519YaoParseResult<RouterAbEd25519YaoExportAdmissionReceiptV1> {
  return parseBoundary(parseExportAdmissionReceiptValue, value);
}

export function parseRouterAbEd25519YaoExportExecuteRequestV1(
  value: unknown,
): RouterAbEd25519YaoParseResult<RouterAbEd25519YaoExportExecuteRequestV1> {
  return parseBoundary(parseExportExecuteRequestValue, value);
}

export function parseRouterAbEd25519YaoExportResultV1(
  value: unknown,
): RouterAbEd25519YaoParseResult<RouterAbEd25519YaoExportResultV1> {
  return parseBoundary(parseExportResultValue, value);
}

export function parseRouterAbEd25519YaoActivationAdmissionReceiptV1(
  value: unknown,
): RouterAbEd25519YaoParseResult<RouterAbEd25519YaoActivationAdmissionReceiptV1> {
  return parseBoundary(parseActivationAdmissionReceiptValue, value);
}

export function parseRouterAbEd25519YaoRegistrationActivationAdmissionReceiptV1(
  value: unknown,
): RouterAbEd25519YaoParseResult<RouterAbEd25519YaoActivationAdmissionReceiptV1<'registration'>> {
  const parsed = parseRouterAbEd25519YaoActivationAdmissionReceiptV1(value);
  if (!parsed.ok) return parsed;
  if (!isActivationAdmissionReceiptFor(parsed.value, 'registration')) {
    return operationMismatch('registration');
  }
  return { ok: true, value: parsed.value };
}

export function parseRouterAbEd25519YaoRecoveryActivationAdmissionReceiptV1(
  value: unknown,
): RouterAbEd25519YaoParseResult<RouterAbEd25519YaoActivationAdmissionReceiptV1<'recovery'>> {
  const parsed = parseRouterAbEd25519YaoActivationAdmissionReceiptV1(value);
  if (!parsed.ok) return parsed;
  if (!isActivationAdmissionReceiptFor(parsed.value, 'recovery')) {
    return operationMismatch('recovery');
  }
  return { ok: true, value: parsed.value };
}

export function parseRouterAbEd25519YaoActivationExecuteRequestV1(
  value: unknown,
): RouterAbEd25519YaoParseResult<RouterAbEd25519YaoActivationExecuteRequestV1> {
  return parseBoundary(parseActivationExecuteRequestValue, value);
}

export function parseRouterAbEd25519YaoRegistrationActivationExecuteRequestV1(
  value: unknown,
): RouterAbEd25519YaoParseResult<RouterAbEd25519YaoActivationExecuteRequestV1<'registration'>> {
  const parsed = parseRouterAbEd25519YaoActivationExecuteRequestV1(value);
  if (!parsed.ok) return parsed;
  if (!isActivationExecuteRequestFor(parsed.value, 'registration')) {
    return operationMismatch('registration');
  }
  return { ok: true, value: parsed.value };
}

export function parseRouterAbEd25519YaoRecoveryActivationExecuteRequestV1(
  value: unknown,
): RouterAbEd25519YaoParseResult<RouterAbEd25519YaoActivationExecuteRequestV1<'recovery'>> {
  const parsed = parseRouterAbEd25519YaoActivationExecuteRequestV1(value);
  if (!parsed.ok) return parsed;
  if (!isActivationExecuteRequestFor(parsed.value, 'recovery')) {
    return operationMismatch('recovery');
  }
  return { ok: true, value: parsed.value };
}

export function parseRouterAbEd25519YaoActivationResultV1(
  value: unknown,
): RouterAbEd25519YaoParseResult<RouterAbEd25519YaoActivationResultV1> {
  return parseBoundary(parseActivationResultValue, value);
}

export function parseRouterAbEd25519YaoRegistrationActivationResultV1(
  value: unknown,
): RouterAbEd25519YaoParseResult<RouterAbEd25519YaoActivationResultV1<'registration'>> {
  const parsed = parseRouterAbEd25519YaoActivationResultV1(value);
  if (!parsed.ok) return parsed;
  if (!isActivationResultFor(parsed.value, 'registration')) {
    return operationMismatch('registration');
  }
  return { ok: true, value: parsed.value };
}

export function parseRouterAbEd25519YaoRecoveryActivationResultV1(
  value: unknown,
): RouterAbEd25519YaoParseResult<RouterAbEd25519YaoActivationResultV1<'recovery'>> {
  const parsed = parseRouterAbEd25519YaoActivationResultV1(value);
  if (!parsed.ok) return parsed;
  if (!isActivationResultFor(parsed.value, 'recovery')) {
    return operationMismatch('recovery');
  }
  return { ok: true, value: parsed.value };
}

export function parseRouterAbEd25519YaoRecoveryActivationRequestV1(
  value: unknown,
): RouterAbEd25519YaoParseResult<RouterAbEd25519YaoRecoveryActivationRequestV1> {
  return parseBoundary(parseRecoveryActivationRequestValue, value);
}

export function parseRouterAbEd25519YaoRecoveryActivationReceiptV1(
  value: unknown,
): RouterAbEd25519YaoParseResult<RouterAbEd25519YaoRecoveryActivationReceiptV1> {
  return parseBoundary(parseRecoveryActivationReceiptValue, value);
}

export function parseRouterAbEd25519YaoEncryptedPackageV1(
  value: unknown,
): RouterAbEd25519YaoParseResult<RouterAbEd25519YaoEncryptedPackageV1> {
  return parseBoundary(parseEncryptedPackageValue, value);
}

function parseEncryptedPackageValue(value: unknown): RouterAbEd25519YaoEncryptedPackageV1 {
  return parseEncryptedPackage(value, 'encrypted_package');
}
