import {
  ROUTER_AB_ED25519_YAO_RECOVERY_ACTIVATE_PATH_V1,
  ROUTER_AB_ED25519_YAO_RECOVERY_ADMISSION_PATH_V1,
  ROUTER_AB_ED25519_YAO_RECOVERY_EXECUTE_PATH_V1,
  ROUTER_AB_ED25519_YAO_WARM_RECOVERY_BOOTSTRAP_PATH_V1,
  parseRouterAbEd25519YaoRecoveryActivationAdmissionReceiptV1,
  parseRouterAbEd25519YaoRecoveryActivationExecuteRequestV1,
  parseRouterAbEd25519YaoRecoveryActivationReceiptV1,
  parseRouterAbEd25519YaoRecoveryActivationRequestV1,
  parseRouterAbEd25519YaoRecoveryActivationResultV1,
  parseRouterAbEd25519YaoRecoveryAdmissionRequestV1,
  parseRouterAbEd25519YaoWarmRecoveryBootstrapRequestV1,
  parseRouterAbEd25519YaoRegistrationActivationResultV1,
  parseRouterAbEd25519YaoRegistrationAdmissionRequestV1,
  type RouterAbEd25519YaoActivationAdmissionReceiptV1,
  type RouterAbEd25519YaoActivationBindingV1,
  type RouterAbEd25519YaoActivationExecuteRequestV1,
  type RouterAbEd25519YaoActivationResultV1,
  type RouterAbEd25519YaoApplicationBindingFactsV1,
  type RouterAbEd25519YaoBytes32V1,
  type RouterAbEd25519YaoRecoveryActivationReceiptV1,
  type RouterAbEd25519YaoRecoveryActivationRequestV1,
  type RouterAbEd25519YaoRecoveryAdmissionRequestV1,
  type RouterAbEd25519YaoRegistrationAdmissionRequestV1,
  type RouterAbEd25519YaoWarmRecoveryBootstrapRequestV1,
} from '@shared/utils/routerAbEd25519Yao';
import {
  normalizeRuntimePolicyScope,
  signingRootScopeFromRuntimePolicyScope,
  type RuntimePolicyScope,
} from '@shared/threshold/signingRootScope';
import { json, readJson } from './cloudflare/http';
import { createRouterApiModule, type RouterApiModule } from './modules';
import { defineRoute } from './routeDefinitions';
import type {
  RouterApiCloudflareRouteExtensionInput,
  RouterApiRouteExtension,
} from './routeExtensions';
import type { WalletEd25519YaoActiveCapabilityRecord } from '../core/WalletStore';
import type { RouterAbEd25519WalletSessionClaims } from '../core/ThresholdService/validation';

type RecoveryAdmissionReceipt = RouterAbEd25519YaoActivationAdmissionReceiptV1<'recovery'>;
type RecoveryExecuteRequest = RouterAbEd25519YaoActivationExecuteRequestV1<'recovery'>;
type RecoveryExecutionResult = RouterAbEd25519YaoActivationResultV1<'recovery'>;
type RegistrationResult = RouterAbEd25519YaoActivationResultV1<'registration'>;

export type RouterAbEd25519YaoRecoveryFailureCode =
  | 'invalid_request'
  | 'invalid_backend_response'
  | 'admission_failed'
  | 'admission_in_progress'
  | 'unknown_recovery'
  | 'binding_mismatch'
  | 'execution_in_progress'
  | 'execution_failed'
  | 'recovery_not_staged'
  | 'activation_in_progress'
  | 'activation_failed'
  | 'unknown_capability'
  | 'capability_suspended'
  | 'capability_retired'
  | 'capability_conflict'
  | 'continuity_mismatch'
  | 'stale_epoch';

export type RouterAbEd25519YaoRecoveryFailure = {
  readonly ok: false;
  readonly status: 400 | 404 | 408 | 409 | 429 | 500 | 502 | 503;
  readonly code: RouterAbEd25519YaoRecoveryFailureCode;
  readonly message: string;
};

export type RouterAbEd25519YaoRecoveryServiceResult<T> =
  | { readonly ok: true; readonly status: 200; readonly value: T }
  | RouterAbEd25519YaoRecoveryFailure;

export type RouterAbEd25519YaoRecoveryBackendFailure = {
  readonly ok: false;
  readonly status: 400 | 408 | 409 | 429 | 500 | 502 | 503;
  readonly code: string;
  readonly message: string;
};

export type RouterAbEd25519YaoRecoveryBackendResult =
  | { readonly ok: true; readonly body: unknown }
  | RouterAbEd25519YaoRecoveryBackendFailure;

export interface RouterAbEd25519YaoRecoveryBackend {
  admitRecovery(
    request: RouterAbEd25519YaoRecoveryAdmissionRequestV1,
  ): Promise<RouterAbEd25519YaoRecoveryBackendResult> | RouterAbEd25519YaoRecoveryBackendResult;
  executeRecovery(
    request: RecoveryExecuteRequest,
  ): Promise<RouterAbEd25519YaoRecoveryBackendResult> | RouterAbEd25519YaoRecoveryBackendResult;
  activateRecovery(
    request: RouterAbEd25519YaoRecoveryActivationRequestV1,
  ): Promise<RouterAbEd25519YaoRecoveryBackendResult> | RouterAbEd25519YaoRecoveryBackendResult;
}

export interface RouterAbEd25519YaoRecoveryService {
  admitRecovery(
    request: RouterAbEd25519YaoRecoveryAdmissionRequestV1,
  ): Promise<RouterAbEd25519YaoRecoveryServiceResult<RecoveryAdmissionReceipt>>;
  executeRecovery(
    request: RecoveryExecuteRequest,
  ): Promise<RouterAbEd25519YaoRecoveryServiceResult<RecoveryExecutionResult>>;
  activateRecovery(
    request: RouterAbEd25519YaoRecoveryActivationRequestV1,
  ): Promise<
    RouterAbEd25519YaoRecoveryServiceResult<RouterAbEd25519YaoRecoveryActivationReceiptV1>
  >;
}

export type RouterAbEd25519YaoRecoveryAuthorizationInput =
  | {
      readonly kind: 'bootstrap';
      readonly request: Request;
      readonly body: RouterAbEd25519YaoWarmRecoveryBootstrapRequestV1;
    }
  | {
      readonly kind: 'admit';
      readonly request: Request;
      readonly body: RouterAbEd25519YaoRecoveryAdmissionRequestV1;
    }
  | {
      readonly kind: 'execute';
      readonly request: Request;
      readonly body: RecoveryExecuteRequest;
    }
  | {
      readonly kind: 'activate';
      readonly request: Request;
      readonly body: RouterAbEd25519YaoRecoveryActivationRequestV1;
    };

export type RouterAbEd25519YaoRecoveryAuthorizationResult =
  | {
      readonly ok: true;
      readonly claims: RouterAbEd25519WalletSessionClaims;
    }
  | {
      readonly ok: false;
      readonly status: 401 | 403 | 409 | 429 | 503;
      readonly code: string;
      readonly message: string;
    };

export interface RouterAbEd25519YaoRecoveryAuthorizationAdapter {
  authorize(
    input: RouterAbEd25519YaoRecoveryAuthorizationInput,
  ):
    | Promise<RouterAbEd25519YaoRecoveryAuthorizationResult>
    | RouterAbEd25519YaoRecoveryAuthorizationResult;
}

export type RouterAbEd25519YaoRegistrationFinalizeCapabilityInstallationV1 = {
  readonly kind: 'router_ab_ed25519_yao_registration_finalize_capability_v1';
  readonly activeCapabilityBinding: RouterAbEd25519YaoBytes32V1;
  readonly nearAccountId: string;
  readonly registrationAdmissionRequest: RouterAbEd25519YaoRegistrationAdmissionRequestV1;
  readonly registrationResult: RegistrationResult;
  readonly runtimePolicyScope: RuntimePolicyScope;
};

export type RouterAbEd25519YaoRegistrationFinalizeCapabilityInstallResultV1 =
  | {
      readonly ok: true;
      readonly disposition: 'installed' | 'exact_retry';
      readonly activeCapabilityBinding: RouterAbEd25519YaoBytes32V1;
      readonly registeredPublicKey: RouterAbEd25519YaoBytes32V1;
      readonly stateEpoch: number;
    }
  | {
      readonly ok: false;
      readonly code: 'invalid_installation' | 'capability_conflict' | 'capability_retired';
      readonly message: string;
    };

export interface RouterAbEd25519YaoRegistrationFinalizeCapabilityInstallerV1 {
  installRegistrationFinalizeCapability(
    input: RouterAbEd25519YaoRegistrationFinalizeCapabilityInstallationV1,
  ):
    | Promise<RouterAbEd25519YaoRegistrationFinalizeCapabilityInstallResultV1>
    | RouterAbEd25519YaoRegistrationFinalizeCapabilityInstallResultV1;
}

export interface RouterAbEd25519YaoPersistedActiveCapabilityInstallerV1 {
  installPersistedActiveCapability(
    input: WalletEd25519YaoActiveCapabilityRecord,
  ):
    | Promise<RouterAbEd25519YaoRegistrationFinalizeCapabilityInstallResultV1>
    | RouterAbEd25519YaoRegistrationFinalizeCapabilityInstallResultV1;
}

export type RouterAbEd25519YaoCapabilityPersistenceResultV1 =
  | { readonly ok: true }
  | { readonly ok: false; readonly code: string; readonly message: string };

export interface RouterAbEd25519YaoCapabilityPersistenceV1 {
  replaceActiveCapability(input: {
    readonly previous: WalletEd25519YaoActiveCapabilityRecord;
    readonly next: WalletEd25519YaoActiveCapabilityRecord;
  }):
    | Promise<RouterAbEd25519YaoCapabilityPersistenceResultV1>
    | RouterAbEd25519YaoCapabilityPersistenceResultV1;
}

class EphemeralRouterAbEd25519YaoCapabilityPersistenceV1
  implements RouterAbEd25519YaoCapabilityPersistenceV1
{
  replaceActiveCapability(): RouterAbEd25519YaoCapabilityPersistenceResultV1 {
    return { ok: true };
  }
}

export type RouterAbEd25519YaoActiveCapabilityLookupV1 = {
  readonly kind: 'router_ab_ed25519_yao_active_capability_lookup_v1';
  readonly walletId: string;
  readonly nearAccountId: string;
  readonly nearEd25519SigningKeyId: string;
  readonly signerSlot: number;
  readonly signingWorkerId: string;
  readonly participantIds: readonly [number, number];
};

export type RouterAbEd25519YaoActiveCapabilityDescriptorV1 = {
  readonly kind: 'router_ab_ed25519_yao_active_capability_v1';
  readonly activeCapabilityBinding: RouterAbEd25519YaoBytes32V1;
  readonly registeredPublicKey: RouterAbEd25519YaoBytes32V1;
  readonly nearAccountId: string;
  readonly applicationBinding: RouterAbEd25519YaoApplicationBindingFactsV1;
  readonly runtimePolicyScope: RuntimePolicyScope;
  readonly participantIds: readonly [number, number];
  readonly lifecycle: {
    readonly lifecycleId: string;
    readonly rootShareEpoch: string;
    readonly accountId: string;
    readonly walletSessionId: string;
    readonly signerSetId: string;
    readonly signingWorkerId: string;
  };
  readonly stateEpoch: number;
};

export type RouterAbEd25519YaoActiveCapabilityLookupResultV1 =
  | { readonly ok: true; readonly capability: RouterAbEd25519YaoActiveCapabilityDescriptorV1 }
  | {
      readonly ok: false;
      readonly code: 'invalid_lookup' | 'unknown_capability' | 'capability_conflict';
      readonly message: string;
    };

export type RouterAbEd25519YaoWarmRecoveryBootstrapV1 = {
  readonly kind: 'router_ab_ed25519_yao_warm_recovery_bootstrap_v1';
  readonly walletId: string;
  readonly nearAccountId: string;
  readonly nearEd25519SigningKeyId: string;
  readonly signerSlot: number;
  readonly thresholdSessionId: string;
  readonly signingGrantId: string;
  readonly signingWorkerId: string;
  readonly thresholdExpiresAtMs: number;
  readonly participantIds: readonly [number, number];
  readonly authority: RouterAbEd25519WalletSessionClaims['authority'];
  readonly authorityScope: RouterAbEd25519WalletSessionClaims['authorityScope'];
  readonly runtimePolicyScope: RouterAbEd25519WalletSessionClaims['runtimePolicyScope'];
  readonly routerAbNormalSigning: RouterAbEd25519WalletSessionClaims['routerAbNormalSigning'];
  readonly capability: RouterAbEd25519YaoActiveCapabilityDescriptorV1;
};

export interface RouterAbEd25519YaoActiveCapabilityResolverV1 {
  resolveActiveCapability(
    input: RouterAbEd25519YaoActiveCapabilityLookupV1,
  ):
    | Promise<RouterAbEd25519YaoActiveCapabilityLookupResultV1>
    | RouterAbEd25519YaoActiveCapabilityLookupResultV1;
}

export interface RouterAbEd25519YaoRecoveryRuntimePortV1
  extends
    RouterAbEd25519YaoRegistrationFinalizeCapabilityInstallerV1,
    RouterAbEd25519YaoPersistedActiveCapabilityInstallerV1,
    RouterAbEd25519YaoActiveCapabilityResolverV1 {
  readonly kind: 'router_ab_ed25519_yao_recovery_runtime_v1';
}

type CapabilityIdentity = {
  readonly capabilityBinding: RouterAbEd25519YaoBytes32V1;
  readonly nearAccountId: string;
  readonly applicationBinding: RouterAbEd25519YaoApplicationBindingFactsV1;
  readonly runtimePolicyScope: RuntimePolicyScope;
  readonly participantIds: readonly [number, number];
  readonly activationBinding: RouterAbEd25519YaoActivationBindingV1;
  readonly registeredPublicKey: RouterAbEd25519YaoBytes32V1;
  readonly stateEpoch: number;
  readonly originFingerprint: string;
  readonly persisted: WalletEd25519YaoActiveCapabilityRecord;
};

type ActiveCapabilityState = {
  readonly kind: 'active';
  readonly identity: CapabilityIdentity;
};

type SuspendedCapabilityState = {
  readonly kind: 'suspended';
  readonly identity: CapabilityIdentity;
  readonly recoveryKey: string;
};

type RetiredCapabilityState = {
  readonly kind: 'retired';
  readonly identity: CapabilityIdentity;
  readonly recoveryKey: string;
  readonly replacementCapabilityBinding: RouterAbEd25519YaoBytes32V1;
};

type CapabilityState = ActiveCapabilityState | SuspendedCapabilityState | RetiredCapabilityState;

type RecoveryContext = {
  readonly recoveryKey: string;
  readonly admissionRequest: RouterAbEd25519YaoRecoveryAdmissionRequestV1;
  readonly activeCapability: CapabilityIdentity;
};

type RecoveryAdmittingState = {
  readonly kind: 'admitting';
  readonly context: RecoveryContext;
};

type RecoveryAdmissionFailedState = {
  readonly kind: 'admission_failed';
  readonly context: RecoveryContext;
  readonly failure: RouterAbEd25519YaoRecoveryFailure;
};

type RecoveryAdmittedState = {
  readonly kind: 'admitted';
  readonly context: RecoveryContext;
  readonly admissionReceipt: RecoveryAdmissionReceipt;
};

type RecoveryExecutingState = {
  readonly kind: 'executing';
  readonly context: RecoveryContext;
  readonly admissionReceipt: RecoveryAdmissionReceipt;
  readonly executeFingerprint: string;
};

type RecoveryExecutionFailedState = {
  readonly kind: 'execution_failed';
  readonly context: RecoveryContext;
  readonly admissionReceipt: RecoveryAdmissionReceipt;
  readonly executeFingerprint: string;
  readonly failure: RouterAbEd25519YaoRecoveryFailure;
};

type RecoveryStagedState = {
  readonly kind: 'staged';
  readonly context: RecoveryContext;
  readonly admissionReceipt: RecoveryAdmissionReceipt;
  readonly executeFingerprint: string;
  readonly result: RecoveryExecutionResult;
};

type RecoveryActivatingState = {
  readonly kind: 'activating';
  readonly context: RecoveryContext;
  readonly admissionReceipt: RecoveryAdmissionReceipt;
  readonly executeFingerprint: string;
  readonly result: RecoveryExecutionResult;
  readonly activationFingerprint: string;
};

type RecoveryActivationFailedState = {
  readonly kind: 'activation_failed';
  readonly context: RecoveryContext;
  readonly admissionReceipt: RecoveryAdmissionReceipt;
  readonly executeFingerprint: string;
  readonly result: RecoveryExecutionResult;
  readonly activationFingerprint: string;
  readonly failure: RouterAbEd25519YaoRecoveryFailure;
};

type RecoveryPromotedState = {
  readonly kind: 'promoted';
  readonly context: RecoveryContext;
  readonly admissionReceipt: RecoveryAdmissionReceipt;
  readonly executeFingerprint: string;
  readonly result: RecoveryExecutionResult;
  readonly activationFingerprint: string;
  readonly activationReceipt: RouterAbEd25519YaoRecoveryActivationReceiptV1;
};

type RecoveryLifecycleState =
  | RecoveryAdmittingState
  | RecoveryAdmissionFailedState
  | RecoveryAdmittedState
  | RecoveryExecutingState
  | RecoveryExecutionFailedState
  | RecoveryStagedState
  | RecoveryActivatingState
  | RecoveryActivationFailedState
  | RecoveryPromotedState;

export class InMemoryRouterAbEd25519YaoRecoveryStateV1 {
  readonly capabilities = new Map<string, CapabilityState>();
  readonly identityCapabilities = new Map<string, string>();
  readonly recoveries = new Map<string, RecoveryLifecycleState>();
  readonly recoverySessions = new Map<string, string>();
}

const ROUTER_AB_ED25519_YAO_RECOVERY_ROUTES = Object.freeze([
  defineRoute({
    id: 'router_ab_ed25519_yao_warm_recovery_bootstrap',
    surface: 'relay',
    method: 'POST',
    path: ROUTER_AB_ED25519_YAO_WARM_RECOVERY_BOOTSTRAP_PATH_V1,
    auth: {
      plane: 'public',
      proof: 'threshold_protocol_state',
      rationale: 'Warm recovery bootstrap requires an exact Ed25519 Wallet Session JWT.',
    },
    metering: { kind: 'none' },
    requiredServices: [],
    summary: 'Resolve the active capability for an authenticated warm Ed25519 Yao recovery',
  }),
  defineRoute({
    id: 'router_ab_ed25519_yao_recovery_admit',
    surface: 'relay',
    method: 'POST',
    path: ROUTER_AB_ED25519_YAO_RECOVERY_ADMISSION_PATH_V1,
    auth: {
      plane: 'public',
      proof: 'intent_grant',
      rationale: 'Recovery admission requires the explicit recovery authorization adapter.',
    },
    metering: { kind: 'none' },
    requiredServices: [],
    summary: 'Admit an Ed25519 Yao same-root recovery',
  }),
  defineRoute({
    id: 'router_ab_ed25519_yao_recovery_execute',
    surface: 'relay',
    method: 'POST',
    path: ROUTER_AB_ED25519_YAO_RECOVERY_EXECUTE_PATH_V1,
    auth: {
      plane: 'public',
      proof: 'threshold_protocol_state',
      rationale: 'Recovery execution requires the explicit recovery authorization adapter.',
    },
    metering: { kind: 'none' },
    requiredServices: [],
    summary: 'Execute and stage an admitted Ed25519 Yao recovery',
  }),
  defineRoute({
    id: 'router_ab_ed25519_yao_recovery_activate',
    surface: 'relay',
    method: 'POST',
    path: ROUTER_AB_ED25519_YAO_RECOVERY_ACTIVATE_PATH_V1,
    auth: {
      plane: 'public',
      proof: 'threshold_protocol_state',
      rationale: 'Recovery activation requires the explicit recovery authorization adapter.',
    },
    metering: { kind: 'none' },
    requiredServices: [],
    summary: 'Promote a verified Ed25519 Yao recovery candidate',
  }),
]);

function canonicalFingerprint(value: unknown): string {
  return JSON.stringify(value);
}

function equalWire(left: unknown, right: unknown): boolean {
  return canonicalFingerprint(left) === canonicalFingerprint(right);
}

function bytesToHex(bytes: readonly number[]): string {
  let encoded = '';
  for (const byte of bytes) encoded += byte.toString(16).padStart(2, '0');
  return encoded;
}

function equalBytes(left: readonly number[], right: readonly number[]): boolean {
  if (left.length !== right.length) return false;
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) return false;
  }
  return true;
}

function exactRuntimePolicyScope(
  left: RuntimePolicyScope,
  right: RuntimePolicyScope,
): boolean {
  return (
    left.orgId === right.orgId &&
    left.projectId === right.projectId &&
    left.envId === right.envId &&
    left.signingRootVersion === right.signingRootVersion
  );
}

function warmBootstrapCapabilityMatchesClaims(input: {
  readonly request: RouterAbEd25519YaoWarmRecoveryBootstrapRequestV1;
  readonly claims: RouterAbEd25519WalletSessionClaims;
  readonly capability: RouterAbEd25519YaoActiveCapabilityDescriptorV1;
}): boolean {
  const request = input.request;
  const claims = input.claims;
  const capability = input.capability;
  return (
    capability.applicationBinding.wallet_id === request.walletId &&
    capability.nearAccountId === request.nearAccountId &&
    capability.applicationBinding.near_ed25519_signing_key_id ===
      request.nearEd25519SigningKeyId &&
    capability.applicationBinding.key_creation_signer_slot === request.signerSlot &&
    capability.lifecycle.accountId === request.walletId &&
    capability.lifecycle.walletSessionId === request.thresholdSessionId &&
    capability.lifecycle.signingWorkerId === request.signingWorkerId &&
    capability.lifecycle.rootShareEpoch === claims.runtimePolicyScope.signingRootVersion &&
    capability.participantIds[0] === request.participantIds[0] &&
    capability.participantIds[1] === request.participantIds[1] &&
    exactRuntimePolicyScope(capability.runtimePolicyScope, claims.runtimePolicyScope)
  );
}

function parseCapabilityBinding(
  value: RouterAbEd25519YaoBytes32V1,
): RouterAbEd25519YaoBytes32V1 | null {
  if (
    value.length !== 32 ||
    value.some((byte) => !Number.isInteger(byte) || byte < 0 || byte > 255) ||
    value.every((byte) => byte === 0)
  ) {
    return null;
  }
  return Object.freeze([...value]);
}

function identityKey(identity: CapabilityIdentity): string {
  const binding = identity.activationBinding;
  return canonicalFingerprint({
    stableKeyContextBinding: binding.stable_key_context_binding,
    rootShareEpoch: binding.lifecycle.root_share_epoch,
    accountId: binding.lifecycle.account_id,
    signerSetId: binding.lifecycle.signer_set_id,
    signingWorkerId: binding.lifecycle.selected_server_id,
  });
}

function capabilityInstallResult(
  disposition: 'installed' | 'exact_retry',
  identity: CapabilityIdentity,
): RouterAbEd25519YaoRegistrationFinalizeCapabilityInstallResultV1 {
  return {
    ok: true,
    disposition,
    activeCapabilityBinding: identity.capabilityBinding,
    registeredPublicKey: identity.registeredPublicKey,
    stateEpoch: identity.stateEpoch,
  };
}

function recoveryFailure(input: {
  status: RouterAbEd25519YaoRecoveryFailure['status'];
  code: RouterAbEd25519YaoRecoveryFailureCode;
  message: string;
}): RouterAbEd25519YaoRecoveryFailure {
  return { ok: false, status: input.status, code: input.code, message: input.message };
}

function invalidBackendResponse(message: string): RouterAbEd25519YaoRecoveryFailure {
  return recoveryFailure({ status: 502, code: 'invalid_backend_response', message });
}

function backendFailure(
  result: RouterAbEd25519YaoRecoveryBackendFailure,
  phase: 'admission_failed' | 'execution_failed' | 'activation_failed',
): RouterAbEd25519YaoRecoveryFailure {
  return recoveryFailure({
    status: result.status,
    code: phase,
    message: `${result.code}: ${result.message}`,
  });
}

function uncertainFailure(
  error: unknown,
  phase: 'admission_failed' | 'execution_failed' | 'activation_failed',
): RouterAbEd25519YaoRecoveryFailure {
  return recoveryFailure({
    status: 503,
    code: phase,
    message: error instanceof Error ? error.message : String(error),
  });
}

function assertNever(value: never): never {
  throw new Error(`Unhandled Ed25519 Yao recovery state: ${String(value)}`);
}

function routeFailureResponse(
  failure:
    | RouterAbEd25519YaoRecoveryFailure
    | Extract<RouterAbEd25519YaoRecoveryAuthorizationResult, { ok: false }>,
): Response {
  return json(
    { ok: false, code: failure.code, message: failure.message },
    { status: failure.status },
  );
}

type CapabilityIdentityBuildResult =
  | { readonly ok: true; readonly identity: CapabilityIdentity }
  | {
      readonly ok: false;
      readonly result: Extract<
        RouterAbEd25519YaoRegistrationFinalizeCapabilityInstallResultV1,
        { readonly ok: false }
      >;
    };

function invalidInstallation(message: string): CapabilityIdentityBuildResult {
  return {
    ok: false,
    result: { ok: false, code: 'invalid_installation', message },
  };
}

function registrationResultMatchesAdmission(
  request: RouterAbEd25519YaoRegistrationAdmissionRequestV1,
  result: RegistrationResult,
): boolean {
  const scope = request.scope;
  const lifecycle = result.binding.lifecycle;
  return (
    scope.lifecycle_id === lifecycle.lifecycle_id &&
    scope.root_share_epoch === lifecycle.root_share_epoch &&
    scope.account_id === lifecycle.account_id &&
    scope.wallet_session_id === lifecycle.session_id &&
    scope.signer_set_id === lifecycle.signer_set_id &&
    scope.signing_worker_id === lifecycle.selected_server_id
  );
}

function recoveryResultMatchesAdmission(
  request: RouterAbEd25519YaoRecoveryAdmissionRequestV1,
  result: RecoveryExecutionResult,
): boolean {
  const scope = request.scope;
  const lifecycle = result.binding.lifecycle;
  return (
    scope.lifecycle_id === lifecycle.lifecycle_id &&
    scope.root_share_epoch === lifecycle.root_share_epoch &&
    scope.account_id === lifecycle.account_id &&
    scope.wallet_session_id === lifecycle.session_id &&
    scope.signer_set_id === lifecycle.signer_set_id &&
    scope.signing_worker_id === lifecycle.selected_server_id &&
    equalBytes(request.registered_public_key, result.public_receipt.registered_public_key) &&
    result.public_receipt.state_epoch > 1
  );
}

function buildCapabilityIdentity(
  input: RouterAbEd25519YaoRegistrationFinalizeCapabilityInstallationV1,
): CapabilityIdentityBuildResult {
  if (input.kind !== 'router_ab_ed25519_yao_registration_finalize_capability_v1') {
    return invalidInstallation('registration finalize capability kind is invalid');
  }
  const capabilityBinding = parseCapabilityBinding(input.activeCapabilityBinding);
  if (!capabilityBinding) {
    return invalidInstallation('registration finalize capability binding is invalid');
  }
  const nearAccountId = String(input.nearAccountId || '').trim();
  if (!nearAccountId) {
    return invalidInstallation('registration finalize NEAR account ID is invalid');
  }
  const parsedRequest = parseRouterAbEd25519YaoRegistrationAdmissionRequestV1(
    input.registrationAdmissionRequest,
  );
  if (!parsedRequest.ok) return invalidInstallation(parsedRequest.message);
  const parsedResult = parseRouterAbEd25519YaoRegistrationActivationResultV1(
    input.registrationResult,
  );
  if (!parsedResult.ok) return invalidInstallation(parsedResult.message);
  if (!registrationResultMatchesAdmission(parsedRequest.value, parsedResult.value)) {
    return invalidInstallation('registration result does not match its admitted lifecycle');
  }
  let runtimePolicyScope: RuntimePolicyScope;
  try {
    runtimePolicyScope = normalizeRuntimePolicyScope(input.runtimePolicyScope);
  } catch {
    return invalidInstallation('registration runtime policy scope is invalid');
  }
  const signingRootScope = signingRootScopeFromRuntimePolicyScope(runtimePolicyScope);
  if (
    signingRootScope.signingRootId !== parsedRequest.value.application_binding.signing_root_id ||
    signingRootScope.signingRootVersion !== parsedRequest.value.scope.root_share_epoch
  ) {
    return invalidInstallation('registration runtime policy signing root does not match scope');
  }
  if (
    parsedResult.value.public_receipt.state_epoch !== 1 ||
    !equalBytes(
      parsedResult.value.public_receipt.joined_signing_worker_commitment,
      parsedResult.value.public_receipt.signing_worker_verifying_share,
    )
  ) {
    return invalidInstallation('registration result does not establish a valid epoch-one identity');
  }
  const originFingerprint = canonicalFingerprint({
    capabilityBinding,
    nearAccountId,
    registrationAdmissionRequest: parsedRequest.value,
    registrationResult: parsedResult.value,
    runtimePolicyScope,
  });
  const persisted: WalletEd25519YaoActiveCapabilityRecord = {
    version: 'wallet_ed25519_yao_registration_capability_v1',
    activeCapabilityBinding: capabilityBinding,
    nearAccountId,
    admissionRequest: parsedRequest.value,
    activationResult: parsedResult.value,
    runtimePolicyScope,
  };
  return {
    ok: true,
    identity: {
      capabilityBinding,
      nearAccountId,
      applicationBinding: parsedRequest.value.application_binding,
      runtimePolicyScope,
      participantIds: parsedRequest.value.participant_ids,
      activationBinding: parsedResult.value.binding,
      registeredPublicKey: parsedResult.value.public_receipt.registered_public_key,
      stateEpoch: parsedResult.value.public_receipt.state_epoch,
      originFingerprint,
      persisted,
    },
  };
}

function buildPersistedCapabilityIdentity(
  input: WalletEd25519YaoActiveCapabilityRecord,
): CapabilityIdentityBuildResult {
  switch (input.version) {
    case 'wallet_ed25519_yao_registration_capability_v1':
      return buildCapabilityIdentity({
        kind: 'router_ab_ed25519_yao_registration_finalize_capability_v1',
        activeCapabilityBinding: input.activeCapabilityBinding,
        nearAccountId: input.nearAccountId,
        registrationAdmissionRequest: input.admissionRequest,
        registrationResult: input.activationResult,
        runtimePolicyScope: input.runtimePolicyScope,
      });
    case 'wallet_ed25519_yao_recovery_capability_v1': {
      const capabilityBinding = parseCapabilityBinding(input.activeCapabilityBinding);
      const nearAccountId = String(input.nearAccountId || '').trim();
      const parsedRequest = parseRouterAbEd25519YaoRecoveryAdmissionRequestV1(
        input.admissionRequest,
      );
      const parsedResult = parseRouterAbEd25519YaoRecoveryActivationResultV1(
        input.activationResult,
      );
      if (!capabilityBinding || !nearAccountId || !parsedRequest.ok || !parsedResult.ok) {
        return invalidInstallation('persisted recovery capability is invalid');
      }
      if (
        !equalBytes(capabilityBinding, parsedRequest.value.replacement_capability_binding) ||
        !recoveryResultMatchesAdmission(parsedRequest.value, parsedResult.value) ||
        !equalBytes(
          parsedResult.value.public_receipt.joined_signing_worker_commitment,
          parsedResult.value.public_receipt.signing_worker_verifying_share,
        )
      ) {
        return invalidInstallation('persisted recovery capability continuity is invalid');
      }
      let runtimePolicyScope: RuntimePolicyScope;
      try {
        runtimePolicyScope = normalizeRuntimePolicyScope(input.runtimePolicyScope);
      } catch {
        return invalidInstallation('persisted recovery runtime policy scope is invalid');
      }
      const signingRootScope = signingRootScopeFromRuntimePolicyScope(runtimePolicyScope);
      if (
        signingRootScope.signingRootId !== parsedRequest.value.application_binding.signing_root_id ||
        signingRootScope.signingRootVersion !== parsedRequest.value.scope.root_share_epoch
      ) {
        return invalidInstallation('persisted recovery signing root does not match its scope');
      }
      const persisted: WalletEd25519YaoActiveCapabilityRecord = {
        version: 'wallet_ed25519_yao_recovery_capability_v1',
        activeCapabilityBinding: capabilityBinding,
        nearAccountId,
        admissionRequest: parsedRequest.value,
        activationResult: parsedResult.value,
        runtimePolicyScope,
      };
      return {
        ok: true,
        identity: {
          capabilityBinding,
          nearAccountId,
          applicationBinding: parsedRequest.value.application_binding,
          runtimePolicyScope,
          participantIds: parsedRequest.value.participant_ids,
          activationBinding: parsedResult.value.binding,
          registeredPublicKey: parsedResult.value.public_receipt.registered_public_key,
          stateEpoch: parsedResult.value.public_receipt.state_epoch,
          originFingerprint: canonicalFingerprint(persisted),
          persisted,
        },
      };
    }
    default:
      return assertNever(input);
  }
}

export type RouterAbEd25519YaoActiveCapabilityRecordBuildResultV1 =
  | { readonly ok: true; readonly record: WalletEd25519YaoActiveCapabilityRecord }
  | Extract<
      RouterAbEd25519YaoRegistrationFinalizeCapabilityInstallResultV1,
      { readonly ok: false }
    >;

export function buildRouterAbEd25519YaoRegistrationCapabilityRecordV1(
  input: RouterAbEd25519YaoRegistrationFinalizeCapabilityInstallationV1,
): RouterAbEd25519YaoActiveCapabilityRecordBuildResultV1 {
  const built = buildCapabilityIdentity(input);
  if (!built.ok) return built.result;
  return { ok: true, record: built.identity.persisted };
}

function recoveryRequestMatchesCapability(
  request: RouterAbEd25519YaoRecoveryAdmissionRequestV1,
  identity: CapabilityIdentity,
): boolean {
  const scope = request.scope;
  const activeLifecycle = identity.activationBinding.lifecycle;
  return (
    equalBytes(request.active_capability_binding, identity.capabilityBinding) &&
    equalBytes(request.registered_public_key, identity.registeredPublicKey) &&
    equalWire(request.application_binding, identity.applicationBinding) &&
    equalWire(request.participant_ids, identity.participantIds) &&
    scope.root_share_epoch === activeLifecycle.root_share_epoch &&
    scope.account_id === activeLifecycle.account_id &&
    scope.wallet_session_id === activeLifecycle.session_id &&
    scope.signer_set_id === activeLifecycle.signer_set_id &&
    scope.signing_worker_id === activeLifecycle.selected_server_id
  );
}

function recoveryAdmissionReceiptMatches(
  request: RouterAbEd25519YaoRecoveryAdmissionRequestV1,
  identity: CapabilityIdentity,
  receipt: RecoveryAdmissionReceipt,
): boolean {
  const scope = request.scope;
  const lifecycle = receipt.binding.lifecycle;
  return (
    scope.lifecycle_id === lifecycle.lifecycle_id &&
    scope.root_share_epoch === lifecycle.root_share_epoch &&
    scope.account_id === lifecycle.account_id &&
    scope.wallet_session_id === lifecycle.session_id &&
    scope.signer_set_id === lifecycle.signer_set_id &&
    scope.signing_worker_id === lifecycle.selected_server_id &&
    equalBytes(
      receipt.binding.stable_key_context_binding,
      identity.activationBinding.stable_key_context_binding,
    )
  );
}

function expectedRecoveryEpoch(identity: CapabilityIdentity): number | null {
  if (identity.stateEpoch >= Number.MAX_SAFE_INTEGER) return null;
  return identity.stateEpoch + 1;
}

function recoveryResultMatches(
  request: RecoveryExecuteRequest,
  identity: CapabilityIdentity,
  result: RecoveryExecutionResult,
): 'match' | 'binding_mismatch' | 'public_key_mismatch' | 'stale_epoch' {
  if (!equalWire(request.binding, result.binding)) return 'binding_mismatch';
  if (
    !equalBytes(
      result.binding.stable_key_context_binding,
      identity.activationBinding.stable_key_context_binding,
    )
  ) {
    return 'binding_mismatch';
  }
  if (!equalBytes(result.public_receipt.registered_public_key, identity.registeredPublicKey)) {
    return 'public_key_mismatch';
  }
  const expectedEpoch = expectedRecoveryEpoch(identity);
  if (expectedEpoch === null || result.public_receipt.state_epoch !== expectedEpoch) {
    return 'stale_epoch';
  }
  if (
    !equalBytes(
      result.public_receipt.joined_signing_worker_commitment,
      result.public_receipt.signing_worker_verifying_share,
    )
  ) {
    return 'public_key_mismatch';
  }
  return 'match';
}

function executionContinuityFailure(
  mismatch: Exclude<ReturnType<typeof recoveryResultMatches>, 'match'>,
): RouterAbEd25519YaoRecoveryFailure {
  switch (mismatch) {
    case 'binding_mismatch':
      return invalidBackendResponse('recovery result binding does not match execution');
    case 'public_key_mismatch':
      return recoveryFailure({
        status: 409,
        code: 'continuity_mismatch',
        message: 'recovery result does not preserve the registered Ed25519 public key',
      });
    case 'stale_epoch':
      return recoveryFailure({
        status: 409,
        code: 'stale_epoch',
        message: 'recovery result does not use the exact next activation epoch',
      });
  }
}

function activationMatchesStagedResult(
  request: RouterAbEd25519YaoRecoveryActivationRequestV1,
  result: RecoveryExecutionResult,
): boolean {
  return (
    equalWire(request.binding, result.binding) &&
    equalWire(request.public_receipt, result.public_receipt)
  );
}

function activationReceiptMatches(
  request: RouterAbEd25519YaoRecoveryActivationRequestV1,
  context: RecoveryContext,
  receipt: RouterAbEd25519YaoRecoveryActivationReceiptV1,
): boolean {
  return (
    equalWire(receipt.binding, request.binding) &&
    equalWire(receipt.public_receipt, request.public_receipt) &&
    equalBytes(
      receipt.active_capability_binding,
      context.admissionRequest.replacement_capability_binding,
    ) &&
    equalBytes(
      receipt.retired_capability_binding,
      context.admissionRequest.active_capability_binding,
    )
  );
}

function admittedReceiptForState(state: RecoveryLifecycleState): RecoveryAdmissionReceipt | null {
  switch (state.kind) {
    case 'admitting':
    case 'admission_failed':
      return null;
    case 'admitted':
    case 'executing':
    case 'execution_failed':
    case 'staged':
    case 'activating':
    case 'activation_failed':
    case 'promoted':
      return state.admissionReceipt;
    default:
      return assertNever(state);
  }
}

function admissionReplayResult(
  state: RecoveryLifecycleState,
): RouterAbEd25519YaoRecoveryServiceResult<RecoveryAdmissionReceipt> {
  switch (state.kind) {
    case 'admitting':
      return recoveryFailure({
        status: 409,
        code: 'admission_in_progress',
        message: 'recovery admission is already in progress',
      });
    case 'admission_failed':
      return state.failure;
    case 'admitted':
    case 'executing':
    case 'execution_failed':
    case 'staged':
    case 'activating':
    case 'activation_failed':
    case 'promoted':
      return { ok: true, status: 200, value: state.admissionReceipt };
    default:
      return assertNever(state);
  }
}

function executionReplayResult(
  state:
    | RecoveryExecutingState
    | RecoveryExecutionFailedState
    | RecoveryStagedState
    | RecoveryActivatingState
    | RecoveryActivationFailedState
    | RecoveryPromotedState,
  fingerprint: string,
): RouterAbEd25519YaoRecoveryServiceResult<RecoveryExecutionResult> {
  if (state.executeFingerprint !== fingerprint) {
    return recoveryFailure({
      status: 409,
      code: 'binding_mismatch',
      message: 'recovery execution retry does not match the committed payload',
    });
  }
  switch (state.kind) {
    case 'executing':
      return recoveryFailure({
        status: 409,
        code: 'execution_in_progress',
        message: 'recovery execution is already in progress',
      });
    case 'execution_failed':
      return state.failure;
    case 'staged':
    case 'activating':
    case 'activation_failed':
    case 'promoted':
      return { ok: true, status: 200, value: state.result };
    default:
      return assertNever(state);
  }
}

function activationReplayResult(
  state: RecoveryActivatingState | RecoveryActivationFailedState | RecoveryPromotedState,
  fingerprint: string,
): RouterAbEd25519YaoRecoveryServiceResult<RouterAbEd25519YaoRecoveryActivationReceiptV1> {
  if (state.activationFingerprint !== fingerprint) {
    return recoveryFailure({
      status: 409,
      code: 'binding_mismatch',
      message: 'recovery activation retry does not match the staged candidate',
    });
  }
  switch (state.kind) {
    case 'activating':
      return recoveryFailure({
        status: 409,
        code: 'activation_in_progress',
        message: 'recovery activation is already in progress',
      });
    case 'activation_failed':
      return state.failure;
    case 'promoted':
      return { ok: true, status: 200, value: state.activationReceipt };
    default:
      return assertNever(state);
  }
}

class RouterAbEd25519YaoRecoveryRuntimePort implements RouterAbEd25519YaoRecoveryRuntimePortV1 {
  readonly kind = 'router_ab_ed25519_yao_recovery_runtime_v1' as const;

  constructor(
    private readonly service: RouterAbEd25519YaoRegistrationFinalizeCapabilityInstallerV1 &
      RouterAbEd25519YaoPersistedActiveCapabilityInstallerV1 &
      RouterAbEd25519YaoActiveCapabilityResolverV1,
  ) {}

  installRegistrationFinalizeCapability(
    input: RouterAbEd25519YaoRegistrationFinalizeCapabilityInstallationV1,
  ):
    | Promise<RouterAbEd25519YaoRegistrationFinalizeCapabilityInstallResultV1>
    | RouterAbEd25519YaoRegistrationFinalizeCapabilityInstallResultV1 {
    return this.service.installRegistrationFinalizeCapability(input);
  }

  installPersistedActiveCapability(
    input: WalletEd25519YaoActiveCapabilityRecord,
  ):
    | Promise<RouterAbEd25519YaoRegistrationFinalizeCapabilityInstallResultV1>
    | RouterAbEd25519YaoRegistrationFinalizeCapabilityInstallResultV1 {
    return this.service.installPersistedActiveCapability(input);
  }

  resolveActiveCapability(
    input: RouterAbEd25519YaoActiveCapabilityLookupV1,
  ):
    | Promise<RouterAbEd25519YaoActiveCapabilityLookupResultV1>
    | RouterAbEd25519YaoActiveCapabilityLookupResultV1 {
    return this.service.resolveActiveCapability(input);
  }
}

export function createRouterAbEd25519YaoRecoveryRuntimePortV1(
  service: RouterAbEd25519YaoRegistrationFinalizeCapabilityInstallerV1 &
    RouterAbEd25519YaoPersistedActiveCapabilityInstallerV1 &
    RouterAbEd25519YaoActiveCapabilityResolverV1,
): RouterAbEd25519YaoRecoveryRuntimePortV1 {
  return new RouterAbEd25519YaoRecoveryRuntimePort(service);
}

type CapabilityPromotionResult =
  | {
      readonly ok: true;
      readonly identity: CapabilityIdentity;
      readonly previousIdentity: CapabilityIdentity;
    }
  | { readonly ok: false; readonly failure: RouterAbEd25519YaoRecoveryFailure };

export class InMemoryRouterAbEd25519YaoRecoveryService
  implements
    RouterAbEd25519YaoRecoveryService,
    RouterAbEd25519YaoRegistrationFinalizeCapabilityInstallerV1,
    RouterAbEd25519YaoPersistedActiveCapabilityInstallerV1,
    RouterAbEd25519YaoActiveCapabilityResolverV1
{
  private readonly capabilities: Map<string, CapabilityState>;
  private readonly identityCapabilities: Map<string, string>;
  private readonly recoveries: Map<string, RecoveryLifecycleState>;
  private readonly recoverySessions: Map<string, string>;

  constructor(
    private readonly backend: RouterAbEd25519YaoRecoveryBackend,
    state: InMemoryRouterAbEd25519YaoRecoveryStateV1 = new InMemoryRouterAbEd25519YaoRecoveryStateV1(),
    private readonly capabilityPersistence: RouterAbEd25519YaoCapabilityPersistenceV1 = new EphemeralRouterAbEd25519YaoCapabilityPersistenceV1(),
  ) {
    this.capabilities = state.capabilities;
    this.identityCapabilities = state.identityCapabilities;
    this.recoveries = state.recoveries;
    this.recoverySessions = state.recoverySessions;
  }

  installRegistrationFinalizeCapability(
    input: RouterAbEd25519YaoRegistrationFinalizeCapabilityInstallationV1,
  ): RouterAbEd25519YaoRegistrationFinalizeCapabilityInstallResultV1 {
    const built = buildCapabilityIdentity(input);
    if (!built.ok) return built.result;
    return this.installCapabilityIdentity(built.identity);
  }

  installPersistedActiveCapability(
    input: WalletEd25519YaoActiveCapabilityRecord,
  ): RouterAbEd25519YaoRegistrationFinalizeCapabilityInstallResultV1 {
    const built = buildPersistedCapabilityIdentity(input);
    if (!built.ok) return built.result;
    return this.installPersistedCapabilityIdentity(built.identity);
  }

  private installPersistedCapabilityIdentity(
    identity: CapabilityIdentity,
  ): RouterAbEd25519YaoRegistrationFinalizeCapabilityInstallResultV1 {
    const existing = this.capabilities.get(bytesToHex(identity.capabilityBinding));
    if (
      existing &&
      (existing.kind === 'active' || existing.kind === 'suspended') &&
      existing.identity.originFingerprint === identity.originFingerprint
    ) {
      return capabilityInstallResult('exact_retry', existing.identity);
    }
    return this.installCapabilityIdentity(identity);
  }

  private installCapabilityIdentity(
    identity: CapabilityIdentity,
  ): RouterAbEd25519YaoRegistrationFinalizeCapabilityInstallResultV1 {
    const capabilityKey = bytesToHex(identity.capabilityBinding);
    const existing = this.capabilities.get(capabilityKey);
    if (existing) {
      switch (existing.kind) {
        case 'active':
          if (existing.identity.originFingerprint === identity.originFingerprint) {
            return capabilityInstallResult('exact_retry', existing.identity);
          }
          return {
            ok: false,
            code: 'capability_conflict',
            message: 'active capability binding belongs to a different registration result',
          };
        case 'suspended':
          return {
            ok: false,
            code: 'capability_conflict',
            message: 'registration finalize cannot replace a suspended capability',
          };
        case 'retired':
          return {
            ok: false,
            code: 'capability_retired',
            message: 'registration finalize cannot reinstall a retired capability',
          };
        default:
          return assertNever(existing);
      }
    }
    const stableIdentityKey = identityKey(identity);
    const installedCapabilityKey = this.identityCapabilities.get(stableIdentityKey);
    if (installedCapabilityKey) {
      return {
        ok: false,
        code: 'capability_conflict',
        message: 'stable Ed25519 identity already has an installed capability',
      };
    }
    this.capabilities.set(capabilityKey, { kind: 'active', identity });
    this.identityCapabilities.set(stableIdentityKey, capabilityKey);
    return capabilityInstallResult('installed', identity);
  }

  resolveActiveCapability(
    input: RouterAbEd25519YaoActiveCapabilityLookupV1,
  ): RouterAbEd25519YaoActiveCapabilityLookupResultV1 {
    const walletId = String(input.walletId || '').trim();
    const nearAccountId = String(input.nearAccountId || '').trim();
    const nearEd25519SigningKeyId = String(input.nearEd25519SigningKeyId || '').trim();
    const signingWorkerId = String(input.signingWorkerId || '').trim();
    const firstParticipantId = input.participantIds?.[0];
    const secondParticipantId = input.participantIds?.[1];
    if (
      input.kind !== 'router_ab_ed25519_yao_active_capability_lookup_v1' ||
      !walletId ||
      !nearAccountId ||
      !nearEd25519SigningKeyId ||
      !signingWorkerId ||
      !Number.isSafeInteger(input.signerSlot) ||
      input.signerSlot < 1 ||
      !Array.isArray(input.participantIds) ||
      input.participantIds.length !== 2 ||
      !Number.isSafeInteger(firstParticipantId) ||
      !Number.isSafeInteger(secondParticipantId) ||
      Number(firstParticipantId) < 1 ||
      Number(secondParticipantId) < 1 ||
      firstParticipantId === secondParticipantId
    ) {
      return {
        ok: false,
        code: 'invalid_lookup',
        message: 'active Ed25519 Yao capability lookup is invalid',
      };
    }
    let matched: CapabilityIdentity | null = null;
    for (const state of this.capabilities.values()) {
      if (state.kind !== 'active') continue;
      const identity = state.identity;
      if (
        identity.applicationBinding.wallet_id !== walletId ||
        identity.nearAccountId !== nearAccountId ||
        identity.applicationBinding.near_ed25519_signing_key_id !== nearEd25519SigningKeyId ||
        identity.applicationBinding.key_creation_signer_slot !== input.signerSlot ||
        identity.activationBinding.lifecycle.selected_server_id !== signingWorkerId ||
        identity.participantIds[0] !== firstParticipantId ||
        identity.participantIds[1] !== secondParticipantId
      ) {
        continue;
      }
      if (matched) {
        return {
          ok: false,
          code: 'capability_conflict',
          message: 'multiple active Ed25519 Yao capabilities match the wallet identity',
        };
      }
      matched = identity;
    }
    if (!matched) {
      return {
        ok: false,
        code: 'unknown_capability',
        message: 'active Ed25519 Yao capability was not found',
      };
    }
    const lifecycle = matched.activationBinding.lifecycle;
    return {
      ok: true,
      capability: {
        kind: 'router_ab_ed25519_yao_active_capability_v1',
        activeCapabilityBinding: [...matched.capabilityBinding],
        registeredPublicKey: [...matched.registeredPublicKey],
        nearAccountId: matched.nearAccountId,
        applicationBinding: {
          wallet_id: matched.applicationBinding.wallet_id,
          near_ed25519_signing_key_id: matched.applicationBinding.near_ed25519_signing_key_id,
          signing_root_id: matched.applicationBinding.signing_root_id,
          key_creation_signer_slot: matched.applicationBinding.key_creation_signer_slot,
        },
        runtimePolicyScope: {
          orgId: matched.runtimePolicyScope.orgId,
          projectId: matched.runtimePolicyScope.projectId,
          envId: matched.runtimePolicyScope.envId,
          signingRootVersion: matched.runtimePolicyScope.signingRootVersion,
        },
        participantIds: [matched.participantIds[0], matched.participantIds[1]],
        lifecycle: {
          lifecycleId: lifecycle.lifecycle_id,
          rootShareEpoch: lifecycle.root_share_epoch,
          accountId: lifecycle.account_id,
          walletSessionId: lifecycle.session_id,
          signerSetId: lifecycle.signer_set_id,
          signingWorkerId: lifecycle.selected_server_id,
        },
        stateEpoch: matched.stateEpoch,
      },
    };
  }

  async admitRecovery(
    request: RouterAbEd25519YaoRecoveryAdmissionRequestV1,
  ): Promise<RouterAbEd25519YaoRecoveryServiceResult<RecoveryAdmissionReceipt>> {
    const parsed = parseRouterAbEd25519YaoRecoveryAdmissionRequestV1(request);
    if (!parsed.ok) {
      return recoveryFailure({
        status: 400,
        code: 'invalid_request',
        message: parsed.message,
      });
    }
    const admittedRequest = parsed.value;
    const recoveryKey = canonicalFingerprint(admittedRequest);
    const existingRecovery = this.recoveries.get(recoveryKey);
    if (existingRecovery) return admissionReplayResult(existingRecovery);

    const activeCapabilityKey = bytesToHex(admittedRequest.active_capability_binding);
    const activeCapability = this.capabilities.get(activeCapabilityKey);
    if (!activeCapability) {
      return recoveryFailure({
        status: 404,
        code: 'unknown_capability',
        message: 'recovery active capability was not found',
      });
    }
    switch (activeCapability.kind) {
      case 'suspended':
        return recoveryFailure({
          status: 409,
          code: 'capability_suspended',
          message: 'recovery active capability is already suspended',
        });
      case 'retired':
        return recoveryFailure({
          status: 409,
          code: 'capability_retired',
          message: 'recovery active capability is retired',
        });
      case 'active':
        break;
      default:
        return assertNever(activeCapability);
    }
    if (!recoveryRequestMatchesCapability(admittedRequest, activeCapability.identity)) {
      return recoveryFailure({
        status: 409,
        code: 'continuity_mismatch',
        message: 'recovery request does not match the active capability identity',
      });
    }
    const replacementCapabilityKey = bytesToHex(admittedRequest.replacement_capability_binding);
    const replacementCapability = this.capabilities.get(replacementCapabilityKey);
    if (replacementCapability) {
      const code =
        replacementCapability.kind === 'retired' ? 'capability_retired' : 'capability_conflict';
      return recoveryFailure({
        status: 409,
        code,
        message: 'recovery replacement capability binding has already been used',
      });
    }
    const context: RecoveryContext = {
      recoveryKey,
      admissionRequest: admittedRequest,
      activeCapability: activeCapability.identity,
    };
    this.capabilities.set(activeCapabilityKey, {
      kind: 'suspended',
      identity: activeCapability.identity,
      recoveryKey,
    });
    this.recoveries.set(recoveryKey, { kind: 'admitting', context });

    let backendResult: RouterAbEd25519YaoRecoveryBackendResult;
    try {
      backendResult = await this.backend.admitRecovery(admittedRequest);
    } catch (error: unknown) {
      const failure = uncertainFailure(error, 'admission_failed');
      this.storeAdmissionFailure(context, failure);
      return failure;
    }
    if (!backendResult.ok) {
      const failure = backendFailure(backendResult, 'admission_failed');
      this.storeAdmissionFailure(context, failure);
      return failure;
    }
    const parsedReceipt = parseRouterAbEd25519YaoRecoveryActivationAdmissionReceiptV1(
      backendResult.body,
    );
    if (!parsedReceipt.ok) {
      const failure = invalidBackendResponse(parsedReceipt.message);
      this.storeAdmissionFailure(context, failure);
      return failure;
    }
    if (
      !recoveryAdmissionReceiptMatches(
        admittedRequest,
        activeCapability.identity,
        parsedReceipt.value,
      )
    ) {
      const failure = invalidBackendResponse(
        'recovery admission receipt does not preserve the active binding',
      );
      this.storeAdmissionFailure(context, failure);
      return failure;
    }
    const sessionKey = bytesToHex(parsedReceipt.value.binding.session_id);
    if (this.recoverySessions.has(sessionKey)) {
      const failure = invalidBackendResponse('recovery backend reused a session identifier');
      this.storeAdmissionFailure(context, failure);
      return failure;
    }
    this.recoverySessions.set(sessionKey, recoveryKey);
    this.recoveries.set(recoveryKey, {
      kind: 'admitted',
      context,
      admissionReceipt: parsedReceipt.value,
    });
    return { ok: true, status: 200, value: parsedReceipt.value };
  }

  async executeRecovery(
    request: RecoveryExecuteRequest,
  ): Promise<RouterAbEd25519YaoRecoveryServiceResult<RecoveryExecutionResult>> {
    const parsed = parseRouterAbEd25519YaoRecoveryActivationExecuteRequestV1(request);
    if (!parsed.ok) {
      return recoveryFailure({
        status: 400,
        code: 'invalid_request',
        message: parsed.message,
      });
    }
    const executionRequest = parsed.value;
    const state = this.stateForSession(executionRequest.binding.session_id);
    if (!state) {
      return recoveryFailure({
        status: 404,
        code: 'unknown_recovery',
        message: 'recovery admission was not found',
      });
    }
    const admissionReceipt = admittedReceiptForState(state);
    if (!admissionReceipt || !equalWire(executionRequest.binding, admissionReceipt.binding)) {
      return recoveryFailure({
        status: 409,
        code: 'binding_mismatch',
        message: 'recovery execution does not match the admitted binding',
      });
    }
    const executeFingerprint = canonicalFingerprint(executionRequest);
    switch (state.kind) {
      case 'admitted':
        return await this.executeAdmitted(state, executionRequest, executeFingerprint);
      case 'executing':
      case 'execution_failed':
      case 'staged':
      case 'activating':
      case 'activation_failed':
      case 'promoted':
        return executionReplayResult(state, executeFingerprint);
      case 'admitting':
      case 'admission_failed':
        return recoveryFailure({
          status: 404,
          code: 'unknown_recovery',
          message: 'recovery admission has no executable session',
        });
      default:
        return assertNever(state);
    }
  }

  async activateRecovery(
    request: RouterAbEd25519YaoRecoveryActivationRequestV1,
  ): Promise<
    RouterAbEd25519YaoRecoveryServiceResult<RouterAbEd25519YaoRecoveryActivationReceiptV1>
  > {
    const parsed = parseRouterAbEd25519YaoRecoveryActivationRequestV1(request);
    if (!parsed.ok) {
      return recoveryFailure({
        status: 400,
        code: 'invalid_request',
        message: parsed.message,
      });
    }
    const activationRequest = parsed.value;
    const state = this.stateForSession(activationRequest.binding.session_id);
    if (!state) {
      return recoveryFailure({
        status: 404,
        code: 'unknown_recovery',
        message: 'recovery admission was not found',
      });
    }
    const admissionReceipt = admittedReceiptForState(state);
    if (!admissionReceipt || !equalWire(activationRequest.binding, admissionReceipt.binding)) {
      return recoveryFailure({
        status: 409,
        code: 'binding_mismatch',
        message: 'recovery activation does not match the admitted binding',
      });
    }
    const activationFingerprint = canonicalFingerprint(activationRequest);
    switch (state.kind) {
      case 'staged':
        if (!activationMatchesStagedResult(activationRequest, state.result)) {
          return recoveryFailure({
            status: 409,
            code: 'binding_mismatch',
            message: 'recovery activation does not match the staged candidate',
          });
        }
        return await this.activateStaged(state, activationRequest, activationFingerprint);
      case 'activating':
      case 'activation_failed':
      case 'promoted':
        return activationReplayResult(state, activationFingerprint);
      case 'admitted':
      case 'executing':
      case 'execution_failed':
        return recoveryFailure({
          status: 409,
          code: 'recovery_not_staged',
          message: 'recovery has no verified staged candidate',
        });
      case 'admitting':
      case 'admission_failed':
        return recoveryFailure({
          status: 404,
          code: 'unknown_recovery',
          message: 'recovery admission has no activation session',
        });
      default:
        return assertNever(state);
    }
  }

  private async executeAdmitted(
    state: RecoveryAdmittedState,
    request: RecoveryExecuteRequest,
    executeFingerprint: string,
  ): Promise<RouterAbEd25519YaoRecoveryServiceResult<RecoveryExecutionResult>> {
    const executing: RecoveryExecutingState = {
      kind: 'executing',
      context: state.context,
      admissionReceipt: state.admissionReceipt,
      executeFingerprint,
    };
    this.recoveries.set(state.context.recoveryKey, executing);
    let backendResult: RouterAbEd25519YaoRecoveryBackendResult;
    try {
      backendResult = await this.backend.executeRecovery(request);
    } catch (error: unknown) {
      const failure = uncertainFailure(error, 'execution_failed');
      this.storeExecutionFailure(executing, failure);
      return failure;
    }
    if (!backendResult.ok) {
      const failure = backendFailure(backendResult, 'execution_failed');
      this.storeExecutionFailure(executing, failure);
      return failure;
    }
    const parsedResult = parseRouterAbEd25519YaoRecoveryActivationResultV1(backendResult.body);
    if (!parsedResult.ok) {
      const failure = invalidBackendResponse(parsedResult.message);
      this.storeExecutionFailure(executing, failure);
      return failure;
    }
    const continuity = recoveryResultMatches(
      request,
      state.context.activeCapability,
      parsedResult.value,
    );
    if (continuity !== 'match') {
      const failure = executionContinuityFailure(continuity);
      this.storeExecutionFailure(executing, failure);
      return failure;
    }
    this.recoveries.set(state.context.recoveryKey, {
      kind: 'staged',
      context: state.context,
      admissionReceipt: state.admissionReceipt,
      executeFingerprint,
      result: parsedResult.value,
    });
    return { ok: true, status: 200, value: parsedResult.value };
  }

  private async activateStaged(
    state: RecoveryStagedState,
    request: RouterAbEd25519YaoRecoveryActivationRequestV1,
    activationFingerprint: string,
  ): Promise<
    RouterAbEd25519YaoRecoveryServiceResult<RouterAbEd25519YaoRecoveryActivationReceiptV1>
  > {
    const activating: RecoveryActivatingState = {
      kind: 'activating',
      context: state.context,
      admissionReceipt: state.admissionReceipt,
      executeFingerprint: state.executeFingerprint,
      result: state.result,
      activationFingerprint,
    };
    this.recoveries.set(state.context.recoveryKey, activating);
    let backendResult: RouterAbEd25519YaoRecoveryBackendResult;
    try {
      backendResult = await this.backend.activateRecovery(request);
    } catch (error: unknown) {
      const failure = uncertainFailure(error, 'activation_failed');
      this.storeActivationFailure(activating, failure);
      return failure;
    }
    if (!backendResult.ok) {
      const failure = backendFailure(backendResult, 'activation_failed');
      this.storeActivationFailure(activating, failure);
      return failure;
    }
    const parsedConfirmation = parseRouterAbEd25519YaoRecoveryActivationRequestV1(
      backendResult.body,
    );
    if (!parsedConfirmation.ok) {
      const failure = invalidBackendResponse(parsedConfirmation.message);
      this.storeActivationFailure(activating, failure);
      return failure;
    }
    if (!equalWire(parsedConfirmation.value, request)) {
      const failure = invalidBackendResponse(
        'recovery activation confirmation does not match the staged transition',
      );
      this.storeActivationFailure(activating, failure);
      return failure;
    }
    const activationReceipt = parseRouterAbEd25519YaoRecoveryActivationReceiptV1({
      binding: request.binding,
      public_receipt: request.public_receipt,
      active_capability_binding: state.context.admissionRequest.replacement_capability_binding,
      retired_capability_binding: state.context.admissionRequest.active_capability_binding,
    });
    if (!activationReceipt.ok) {
      const failure = invalidBackendResponse(activationReceipt.message);
      this.storeActivationFailure(activating, failure);
      return failure;
    }
    if (!activationReceiptMatches(request, state.context, activationReceipt.value)) {
      const failure = invalidBackendResponse(
        'recovery activation receipt does not match the staged transition',
      );
      this.storeActivationFailure(activating, failure);
      return failure;
    }
    const promoted = this.promoteCapability(activating);
    if (!promoted.ok) {
      this.storeActivationFailure(activating, promoted.failure);
      return promoted.failure;
    }
    const persisted = await this.capabilityPersistence.replaceActiveCapability({
      previous: promoted.previousIdentity.persisted,
      next: promoted.identity.persisted,
    });
    if (!persisted.ok) {
      this.rollbackCapabilityPromotion(promoted.previousIdentity, promoted.identity);
      const failure = recoveryFailure({
        status: 503,
        code: 'activation_failed',
        message: `${persisted.code}: ${persisted.message}`,
      });
      this.storeActivationFailure(activating, failure);
      return failure;
    }
    this.recoveries.set(state.context.recoveryKey, {
      kind: 'promoted',
      context: state.context,
      admissionReceipt: state.admissionReceipt,
      executeFingerprint: state.executeFingerprint,
      result: state.result,
      activationFingerprint,
      activationReceipt: activationReceipt.value,
    });
    return { ok: true, status: 200, value: activationReceipt.value };
  }

  private promoteCapability(
    state: RecoveryActivatingState,
  ): CapabilityPromotionResult {
    const activeCapabilityKey = bytesToHex(
      state.context.admissionRequest.active_capability_binding,
    );
    const activeCapability = this.capabilities.get(activeCapabilityKey);
    if (
      !activeCapability ||
      activeCapability.kind !== 'suspended' ||
      activeCapability.recoveryKey !== state.context.recoveryKey
    ) {
      return {
        ok: false,
        failure: recoveryFailure({
          status: 409,
          code: 'capability_conflict',
          message: 'suspended recovery capability no longer matches the staged transition',
        }),
      };
    }
    const replacementCapabilityBinding = parseCapabilityBinding(
      state.context.admissionRequest.replacement_capability_binding,
    );
    if (!replacementCapabilityBinding) {
      return {
        ok: false,
        failure: recoveryFailure({
          status: 409,
          code: 'capability_conflict',
          message: 'replacement capability binding is invalid',
        }),
      };
    }
    const replacementCapabilityKey = bytesToHex(replacementCapabilityBinding);
    if (this.capabilities.has(replacementCapabilityKey)) {
      return {
        ok: false,
        failure: recoveryFailure({
          status: 409,
          code: 'capability_conflict',
          message: 'replacement capability binding was consumed before promotion',
        }),
      };
    }
    const stableIdentityKey = identityKey(activeCapability.identity);
    if (this.identityCapabilities.get(stableIdentityKey) !== activeCapabilityKey) {
      return {
        ok: false,
        failure: recoveryFailure({
          status: 409,
          code: 'capability_conflict',
          message: 'stable identity capability ownership changed before promotion',
        }),
      };
    }
    const persisted: WalletEd25519YaoActiveCapabilityRecord = {
      version: 'wallet_ed25519_yao_recovery_capability_v1',
      activeCapabilityBinding: replacementCapabilityBinding,
      nearAccountId: activeCapability.identity.nearAccountId,
      admissionRequest: state.context.admissionRequest,
      activationResult: state.result,
      runtimePolicyScope: activeCapability.identity.runtimePolicyScope,
    };
    const builtSuccessor = buildPersistedCapabilityIdentity(persisted);
    if (!builtSuccessor.ok) {
      return {
        ok: false,
        failure: recoveryFailure({
          status: 409,
          code: 'capability_conflict',
          message: `promoted capability is invalid: ${builtSuccessor.result.message}`,
        }),
      };
    }
    const successor = builtSuccessor.identity;
    this.capabilities.set(activeCapabilityKey, {
      kind: 'retired',
      identity: activeCapability.identity,
      recoveryKey: state.context.recoveryKey,
      replacementCapabilityBinding,
    });
    this.capabilities.set(replacementCapabilityKey, { kind: 'active', identity: successor });
    this.identityCapabilities.set(stableIdentityKey, replacementCapabilityKey);
    return {
      ok: true,
      identity: successor,
      previousIdentity: activeCapability.identity,
    };
  }

  private rollbackCapabilityPromotion(
    previousIdentity: CapabilityIdentity,
    promotedIdentity: CapabilityIdentity,
  ): void {
    const previousKey = bytesToHex(previousIdentity.capabilityBinding);
    const promotedKey = bytesToHex(promotedIdentity.capabilityBinding);
    this.capabilities.delete(promotedKey);
    this.capabilities.set(previousKey, { kind: 'active', identity: previousIdentity });
    this.identityCapabilities.set(identityKey(previousIdentity), previousKey);
  }

  private stateForSession(session: RouterAbEd25519YaoBytes32V1): RecoveryLifecycleState | null {
    const recoveryKey = this.recoverySessions.get(bytesToHex(session));
    if (!recoveryKey) return null;
    return this.recoveries.get(recoveryKey) ?? null;
  }

  private storeAdmissionFailure(
    context: RecoveryContext,
    failure: RouterAbEd25519YaoRecoveryFailure,
  ): void {
    this.recoveries.set(context.recoveryKey, {
      kind: 'admission_failed',
      context,
      failure,
    });
  }

  private storeExecutionFailure(
    state: RecoveryExecutingState,
    failure: RouterAbEd25519YaoRecoveryFailure,
  ): void {
    this.recoveries.set(state.context.recoveryKey, {
      kind: 'execution_failed',
      context: state.context,
      admissionReceipt: state.admissionReceipt,
      executeFingerprint: state.executeFingerprint,
      failure,
    });
  }

  private storeActivationFailure(
    state: RecoveryActivatingState,
    failure: RouterAbEd25519YaoRecoveryFailure,
  ): void {
    this.recoveries.set(state.context.recoveryKey, {
      kind: 'activation_failed',
      context: state.context,
      admissionReceipt: state.admissionReceipt,
      executeFingerprint: state.executeFingerprint,
      result: state.result,
      activationFingerprint: state.activationFingerprint,
      failure,
    });
  }
}

class RouterAbEd25519YaoRecoveryRouteExtension implements RouterApiRouteExtension {
  readonly kind = 'cloudflare_route_extension' as const;
  readonly id = 'router_ab_ed25519_yao_recovery';
  readonly routes = ROUTER_AB_ED25519_YAO_RECOVERY_ROUTES;

  constructor(
    private readonly service: RouterAbEd25519YaoRecoveryService,
    private readonly capabilities: RouterAbEd25519YaoActiveCapabilityResolverV1,
    private readonly authorization: RouterAbEd25519YaoRecoveryAuthorizationAdapter,
  ) {}

  async handleCloudflareRoute(input: RouterApiCloudflareRouteExtensionInput): Promise<Response> {
    if (input.method !== 'POST') {
      return json(
        { ok: false, code: 'method_not_allowed', message: 'Method not allowed' },
        { status: 405 },
      );
    }
    const rawBody = await readJson(input.request);
    switch (input.pathname) {
      case ROUTER_AB_ED25519_YAO_WARM_RECOVERY_BOOTSTRAP_PATH_V1:
        return await this.handleWarmBootstrap(input.request, rawBody);
      case ROUTER_AB_ED25519_YAO_RECOVERY_ADMISSION_PATH_V1:
        return await this.handleAdmission(input.request, rawBody);
      case ROUTER_AB_ED25519_YAO_RECOVERY_EXECUTE_PATH_V1:
        return await this.handleExecution(input.request, rawBody);
      case ROUTER_AB_ED25519_YAO_RECOVERY_ACTIVATE_PATH_V1:
        return await this.handleActivation(input.request, rawBody);
      default:
        return json({ ok: false, code: 'not_found', message: 'Not found' }, { status: 404 });
    }
  }

  private async handleWarmBootstrap(request: Request, rawBody: unknown): Promise<Response> {
    const parsed = parseRouterAbEd25519YaoWarmRecoveryBootstrapRequestV1(rawBody);
    if (!parsed.ok) {
      return json({ ok: false, code: parsed.code, message: parsed.message }, { status: 400 });
    }
    const authorization = await this.authorization.authorize({
      kind: 'bootstrap',
      request,
      body: parsed.value,
    });
    if (!authorization.ok) return routeFailureResponse(authorization);
    const activeCapability = await this.capabilities.resolveActiveCapability({
      kind: 'router_ab_ed25519_yao_active_capability_lookup_v1',
      walletId: parsed.value.walletId,
      nearAccountId: parsed.value.nearAccountId,
      nearEd25519SigningKeyId: parsed.value.nearEd25519SigningKeyId,
      signerSlot: parsed.value.signerSlot,
      signingWorkerId: parsed.value.signingWorkerId,
      participantIds: parsed.value.participantIds,
    });
    if (!activeCapability.ok) {
      return json(
        {
          ok: false,
          code: activeCapability.code,
          message: activeCapability.message,
        },
        { status: activeCapability.code === 'unknown_capability' ? 404 : 409 },
      );
    }
    if (
      !warmBootstrapCapabilityMatchesClaims({
        request: parsed.value,
        claims: authorization.claims,
        capability: activeCapability.capability,
      })
    ) {
      return json(
        {
          ok: false,
          code: 'continuity_mismatch',
          message: 'active Ed25519 Yao capability does not match the Wallet Session lifecycle',
        },
        { status: 409 },
      );
    }
    const participantIds = authorization.claims.participantIds;
    const firstParticipantId = participantIds[0];
    const secondParticipantId = participantIds[1];
    if (firstParticipantId === undefined || secondParticipantId === undefined) {
      return json(
        {
          ok: false,
          code: 'recovery_wallet_session_invalid',
          message: 'Ed25519 Yao recovery requires exactly two Wallet Session participants',
        },
        { status: 401 },
      );
    }
    const response: RouterAbEd25519YaoWarmRecoveryBootstrapV1 = {
      kind: 'router_ab_ed25519_yao_warm_recovery_bootstrap_v1',
      walletId: authorization.claims.walletId,
      nearAccountId: authorization.claims.nearAccountId,
      nearEd25519SigningKeyId: authorization.claims.nearEd25519SigningKeyId,
      signerSlot: parsed.value.signerSlot,
      thresholdSessionId: authorization.claims.thresholdSessionId,
      signingGrantId: authorization.claims.signingGrantId,
      signingWorkerId: authorization.claims.routerAbNormalSigning.signingWorkerId,
      thresholdExpiresAtMs: authorization.claims.thresholdExpiresAtMs,
      participantIds: [firstParticipantId, secondParticipantId],
      authority: authorization.claims.authority,
      authorityScope: authorization.claims.authorityScope,
      runtimePolicyScope: authorization.claims.runtimePolicyScope,
      routerAbNormalSigning: authorization.claims.routerAbNormalSigning,
      capability: activeCapability.capability,
    };
    return json(response, { status: 200 });
  }

  private async handleAdmission(request: Request, rawBody: unknown): Promise<Response> {
    const parsed = parseRouterAbEd25519YaoRecoveryAdmissionRequestV1(rawBody);
    if (!parsed.ok) {
      return json({ ok: false, code: parsed.code, message: parsed.message }, { status: 400 });
    }
    const authorization = await this.authorization.authorize({
      kind: 'admit',
      request,
      body: parsed.value,
    });
    if (!authorization.ok) return routeFailureResponse(authorization);
    const result = await this.service.admitRecovery(parsed.value);
    if (!result.ok) return routeFailureResponse(result);
    return json(result.value, { status: result.status });
  }

  private async handleExecution(request: Request, rawBody: unknown): Promise<Response> {
    const parsed = parseRouterAbEd25519YaoRecoveryActivationExecuteRequestV1(rawBody);
    if (!parsed.ok) {
      return json({ ok: false, code: parsed.code, message: parsed.message }, { status: 400 });
    }
    const authorization = await this.authorization.authorize({
      kind: 'execute',
      request,
      body: parsed.value,
    });
    if (!authorization.ok) return routeFailureResponse(authorization);
    const result = await this.service.executeRecovery(parsed.value);
    if (!result.ok) return routeFailureResponse(result);
    return json(result.value, { status: result.status });
  }

  private async handleActivation(request: Request, rawBody: unknown): Promise<Response> {
    const parsed = parseRouterAbEd25519YaoRecoveryActivationRequestV1(rawBody);
    if (!parsed.ok) {
      return json({ ok: false, code: parsed.code, message: parsed.message }, { status: 400 });
    }
    const authorization = await this.authorization.authorize({
      kind: 'activate',
      request,
      body: parsed.value,
    });
    if (!authorization.ok) return routeFailureResponse(authorization);
    const result = await this.service.activateRecovery(parsed.value);
    if (!result.ok) return routeFailureResponse(result);
    return json(result.value, { status: result.status });
  }
}

export function createRouterAbEd25519YaoRecoveryModule(input: {
  readonly service: RouterAbEd25519YaoRecoveryService &
    RouterAbEd25519YaoActiveCapabilityResolverV1;
  readonly authorization: RouterAbEd25519YaoRecoveryAuthorizationAdapter;
}): RouterApiModule {
  return createRouterApiModule({
    id: 'router_ab_ed25519_yao_recovery',
    routeExtensions: [
      new RouterAbEd25519YaoRecoveryRouteExtension(
        input.service,
        input.service,
        input.authorization,
      ),
    ],
  });
}
