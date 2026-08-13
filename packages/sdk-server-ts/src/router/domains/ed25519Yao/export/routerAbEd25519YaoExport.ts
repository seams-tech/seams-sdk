import {
  ROUTER_AB_ED25519_YAO_EXPORT_ADMISSION_PATH_V1,
  ROUTER_AB_ED25519_YAO_EXPORT_EXECUTE_PATH_V1,
  deriveRouterAbEd25519YaoExportAuthorizationDigestV1,
  deriveRouterAbEd25519YaoExportConfirmationDigestV1,
  deriveRouterAbEd25519YaoRuntimePolicyBindingV1,
  parseRouterAbEd25519YaoExportAdmissionReceiptV1,
  parseRouterAbEd25519YaoExportAdmissionRequestV1,
  parseRouterAbEd25519YaoExportExecuteRequestV1,
  parseRouterAbEd25519YaoExportResultV1,
  type RouterAbEd25519YaoExportAdmissionReceiptV1,
  type RouterAbEd25519YaoExportAdmissionRequestV1,
  type RouterAbEd25519YaoExportAuthorizationIdentityV1,
  type RouterAbEd25519YaoExportExecuteRequestV1,
  type RouterAbEd25519YaoExportResultV1,
} from '@shared/utils/routerAbEd25519Yao';
import {
  createRouterAbTraceContextV1,
  parseRouterAbTraceContextV1,
  ROUTER_AB_TRACE_ID_HEADER_V1,
  type RouterAbTraceContextV1,
} from '@shared/utils/routerAbTraceContext';
import {
  parseThresholdEd25519SessionId,
  type ThresholdEd25519SessionId,
} from '@shared/utils/domainIds';
import type { WalletSessionId } from '@shared/authorization/capabilityKinds';
import type { AuthFactorIdentity, WalletAuthAuthority } from '@shared/utils/walletAuthAuthority';
import { base64UrlEncode } from '@shared/utils/encoders';
import { isPlainObject } from '@shared/utils/validation';
import type { WebAuthnAuthenticationCredential } from '../../../../core/types';
import { normalizeCorsOrigin } from '../../../../core/SessionService';
import {
  parseWebAuthnAuthenticationCredential,
  webAuthnCredentialIdB64uFromCredential,
} from '../../../auth/webAuthnCredentialCodecs';
import type { RouterApiWebAuthnService } from '../../../framework/authServicePort';
import {
  parseRouterAbEd25519WalletSessionClaims,
  type RouterAbEd25519OwnerWalletSessionClaims,
} from '../../../../core/ThresholdService/validation';
import { headersToRecord, json, readJson } from '../../../framework/http';
import { createRouterApiModule, type RouterApiModule } from '../../../framework/modules';
import { defineRoute } from '../../../framework/routeDefinitions';
import type { SessionAdapter } from '../../../framework/routerApi';
import {
  walletSessionFailureCodeFromParseReason,
  walletSessionFailureMessage,
  walletSessionFailureStatus,
} from '../../../auth/walletSessionFailure';
import type {
  RouterApiFetchRouteExtensionInput,
  RouterApiRouteExtension,
} from '../../../framework/routeExtensions';
import type {
  RouterAbEd25519YaoActiveCapabilityDescriptorV1,
  RouterAbEd25519YaoActiveCapabilityResolverV1,
} from '../recovery/routerAbEd25519YaoRecovery';
import { sameRouterAbMpcMaterialActivationRef } from '@shared/utils/routerAbNormalSigningIdentity';

const EXPORT_AUTH_MAX_TTL_MS = 60_000;
const EXPORT_AUTH_CLOCK_SKEW_MS = 30_000;

export type RouterAbEd25519YaoExportFailure = {
  readonly ok: false;
  readonly status: 400 | 404 | 408 | 409 | 429 | 500 | 502 | 503;
  readonly code:
    | 'invalid_backend_response'
    | 'admission_failed'
    | 'admission_in_progress'
    | 'unknown_export'
    | 'binding_mismatch'
    | 'export_consumed'
    | 'execution_in_progress'
    | 'execution_failed'
    | 'ceremony_expired'
    | 'active_identity_mismatch';
  readonly message: string;
};

export type RouterAbEd25519YaoExportServiceResult<T> =
  | { readonly ok: true; readonly status: 200; readonly value: T }
  | RouterAbEd25519YaoExportFailure;

export type RouterAbEd25519YaoExportBackendResult =
  | { readonly ok: true; readonly body: unknown }
  | {
      readonly ok: false;
      readonly status: 400 | 408 | 409 | 429 | 500 | 502 | 503;
      readonly code: string;
      readonly message: string;
    };

function exportBackendFailure(
  result: Extract<RouterAbEd25519YaoExportBackendResult, { readonly ok: false }>,
  fallbackCode: 'admission_failed' | 'execution_failed',
): RouterAbEd25519YaoExportFailure {
  return {
    ok: false,
    status: result.code === 'ceremony_expired' ? 409 : result.status,
    code: result.code === 'ceremony_expired' ? 'ceremony_expired' : fallbackCode,
    message: `${result.code}: ${result.message}`,
  };
}

export interface RouterAbEd25519YaoExportBackend {
  admitExport(
    request: RouterAbEd25519YaoExportAdmissionRequestV1,
    traceContext?: RouterAbTraceContextV1,
  ): Promise<RouterAbEd25519YaoExportBackendResult> | RouterAbEd25519YaoExportBackendResult;
  executeExport(
    request: RouterAbEd25519YaoExportExecuteRequestV1,
    traceContext?: RouterAbTraceContextV1,
  ): Promise<RouterAbEd25519YaoExportBackendResult> | RouterAbEd25519YaoExportBackendResult;
}

export interface RouterAbEd25519YaoExportService {
  admitExport(
    request: RouterAbEd25519YaoExportAdmissionRequestV1,
    authorizationIdentity: RouterAbEd25519YaoExportServerAuthorizationIdentityV1,
    traceContext?: RouterAbTraceContextV1,
  ): Promise<RouterAbEd25519YaoExportServiceResult<RouterAbEd25519YaoExportAdmissionReceiptV1>>;
  executeExport(
    request: RouterAbEd25519YaoExportExecuteRequestV1,
    authorizationIdentity: RouterAbEd25519YaoExportServerAuthorizationIdentityV1,
    traceContext?: RouterAbTraceContextV1,
  ): Promise<RouterAbEd25519YaoExportServiceResult<RouterAbEd25519YaoExportResultV1>>;
}

export type RouterAbEd25519YaoExportAuthorizationClaimV1 = {
  readonly kind: 'router_ab_ed25519_yao_export_authorization_claim_v1';
  readonly lifecycleId: string;
  readonly exportKey: string;
  readonly authorizationFingerprint: string;
};

export type RouterAbEd25519YaoExportAuthorizationPreparationV1 =
  | {
      readonly kind: 'claimed';
      readonly claim: RouterAbEd25519YaoExportAuthorizationClaimV1;
    }
  | {
      readonly kind: 'completed';
      readonly value: RouterAbEd25519YaoExportAuthorizationResult;
    };

export type RouterAbEd25519YaoExportAuthorizationCommitInputV1 = {
  readonly request: RouterAbEd25519YaoExportAdmissionRequestV1;
  readonly claim: RouterAbEd25519YaoExportAuthorizationClaimV1;
  readonly outcome: RouterAbEd25519YaoExportAuthorizationResult;
};

export type RouterAbEd25519YaoExportAdmissionClaimV1 = {
  readonly kind: 'router_ab_ed25519_yao_export_admission_claim_v1';
  readonly lifecycleId: string;
  readonly exportKey: string;
  readonly authorizationFingerprint: string;
};

export type RouterAbEd25519YaoExportAdmissionPreparationV1 =
  | {
      readonly kind: 'claimed';
      readonly claim: RouterAbEd25519YaoExportAdmissionClaimV1;
    }
  | {
      readonly kind: 'completed';
      readonly value: RouterAbEd25519YaoExportAdmissionReceiptV1;
    }
  | {
      readonly kind: 'failed';
      readonly failure: RouterAbEd25519YaoExportFailure;
    };

export type RouterAbEd25519YaoExportAdmissionCommitInputV1 = {
  readonly request: RouterAbEd25519YaoExportAdmissionRequestV1;
  readonly claim: RouterAbEd25519YaoExportAdmissionClaimV1;
  readonly outcome: {
    readonly kind: 'backend_response';
    readonly result: RouterAbEd25519YaoExportBackendResult;
  };
};

export type RouterAbEd25519YaoExportExecuteClaimV1 = {
  readonly kind: 'router_ab_ed25519_yao_export_execute_claim_v1';
  readonly lifecycleId: string;
  readonly exportKey: string;
  readonly sessionId: string;
  readonly executeFingerprint: string;
};

export type RouterAbEd25519YaoExportExecutePreparationV1 =
  | {
      readonly kind: 'claimed';
      readonly claim: RouterAbEd25519YaoExportExecuteClaimV1;
    }
  | {
      readonly kind: 'completed';
      readonly value: RouterAbEd25519YaoExportResultV1;
    }
  | {
      readonly kind: 'failed';
      readonly failure: RouterAbEd25519YaoExportFailure;
    };

export type RouterAbEd25519YaoExportExecuteCommitInputV1 = {
  readonly request: RouterAbEd25519YaoExportExecuteRequestV1;
  readonly claim: RouterAbEd25519YaoExportExecuteClaimV1;
  readonly outcome: {
    readonly kind: 'backend_response';
    readonly result: RouterAbEd25519YaoExportBackendResult;
  };
};

type RouterAbEd25519YaoTraceContextResolutionV1 =
  | { readonly ok: true; readonly value: RouterAbTraceContextV1 }
  | { readonly ok: false; readonly message: string };

function resolveTraceContext(request: Request): RouterAbEd25519YaoTraceContextResolutionV1 {
  const parsed = parseRouterAbTraceContextV1(request.headers.get(ROUTER_AB_TRACE_ID_HEADER_V1));
  if (parsed.ok) return parsed;
  if (parsed.reason === 'missing') {
    return { ok: true, value: createRouterAbTraceContextV1() };
  }
  return { ok: false, message: parsed.message };
}

export type RouterAbEd25519YaoExportAdmissionAuthorization =
  | {
      readonly kind: 'passkey';
      readonly webauthnAuthentication: WebAuthnAuthenticationCredential;
      readonly providerSubjectId?: never;
    }
  | {
      readonly kind: 'email_otp_factor';
      readonly providerSubjectId: string;
      readonly webauthnAuthentication?: never;
    };

export type RouterAbEd25519YaoExportAuthorizationInput =
  | {
      readonly kind: 'admit';
      readonly request: Request;
      readonly body: RouterAbEd25519YaoExportAdmissionRequestV1;
      readonly authorization: RouterAbEd25519YaoExportAdmissionAuthorization;
      readonly expectedOrigin: string;
    }
  | {
      readonly kind: 'execute';
      readonly request: Request;
      readonly body: RouterAbEd25519YaoExportExecuteRequestV1;
    };

export type RouterAbEd25519YaoExportAuthorizationResult =
  | { readonly ok: true }
  | {
      readonly ok: false;
      readonly status: 401 | 403 | 409 | 429 | 503;
      readonly code: string;
      readonly message: string;
    };

export type RouterAbEd25519YaoExportServerAuthorizationIdentityV1 = {
  readonly thresholdSessionId: ThresholdEd25519SessionId;
  readonly walletSessionId: WalletSessionId;
};

type RouterAbEd25519YaoExportAuthorizationAdapterResult =
  | {
      readonly ok: true;
      readonly authorizationIdentity: RouterAbEd25519YaoExportServerAuthorizationIdentityV1;
    }
  | Extract<RouterAbEd25519YaoExportAuthorizationResult, { readonly ok: false }>;

export type RouterAbEd25519YaoExportAuthorizationIdentityResolutionResult =
  | {
      readonly ok: true;
      readonly authorizationIdentity: RouterAbEd25519YaoExportServerAuthorizationIdentityV1;
    }
  | Extract<RouterAbEd25519YaoExportAuthorizationResult, { readonly ok: false }>;

export interface RouterAbEd25519YaoExportAuthorizationAdapter {
  authorize(
    input: RouterAbEd25519YaoExportAuthorizationInput,
  ):
    | Promise<RouterAbEd25519YaoExportAuthorizationAdapterResult>
    | RouterAbEd25519YaoExportAuthorizationAdapterResult;
  resolveAuthorizationIdentity(
    request: Request,
  ):
    | Promise<RouterAbEd25519YaoExportAuthorizationIdentityResolutionResult>
    | RouterAbEd25519YaoExportAuthorizationIdentityResolutionResult;
}

type ExportAuthorizationContext = {
  readonly request: RouterAbEd25519YaoExportAdmissionRequestV1;
  readonly authorizationFingerprint: string;
  readonly authorizationIdentity: RouterAbEd25519YaoExportServerAuthorizationIdentityV1;
};

type ServerDerivedExportAuthorizationIdentity =
  RouterAbEd25519YaoExportServerAuthorizationIdentityV1;

type ExportAuthorizingState = ExportAuthorizationContext & {
  readonly kind: 'authorizing';
};

type ExportAuthorizationFailedState = ExportAuthorizationContext & {
  readonly kind: 'authorization_failed';
  readonly failure: Extract<RouterAbEd25519YaoExportAuthorizationResult, { readonly ok: false }>;
};

type ExportAuthorizedState = ExportAuthorizationContext & {
  readonly kind: 'authorized';
};

type ExportAdmittingState = ExportAuthorizationContext & {
  readonly kind: 'admitting';
};

type ExportAdmissionFailedState = ExportAuthorizationContext & {
  readonly kind: 'admission_failed';
  readonly failure: RouterAbEd25519YaoExportFailure;
};

type ExportAdmittedState = ExportAuthorizationContext & {
  readonly kind: 'admitted';
  readonly receipt: RouterAbEd25519YaoExportAdmissionReceiptV1;
};

type ExportExecutingState = ExportAuthorizationContext & {
  readonly kind: 'executing';
  readonly receipt: RouterAbEd25519YaoExportAdmissionReceiptV1;
  readonly executeFingerprint: string;
};

type ExportExecutionFailedState = ExportAuthorizationContext & {
  readonly kind: 'execution_failed';
  readonly receipt: RouterAbEd25519YaoExportAdmissionReceiptV1;
  readonly executeFingerprint: string;
  readonly failure: RouterAbEd25519YaoExportFailure;
};

type ExportCompletedState = ExportAuthorizationContext & {
  readonly kind: 'completed';
  readonly receipt: RouterAbEd25519YaoExportAdmissionReceiptV1;
  readonly executeFingerprint: string;
  readonly result: RouterAbEd25519YaoExportResultV1;
};

type ExportLifecycleState =
  | ExportAuthorizingState
  | ExportAuthorizationFailedState
  | ExportAuthorizedState
  | ExportAdmittingState
  | ExportAdmissionFailedState
  | ExportAdmittedState
  | ExportExecutingState
  | ExportExecutionFailedState
  | ExportCompletedState;

export class InMemoryRouterAbEd25519YaoExportStateV1 {
  readonly exports = new Map<string, ExportLifecycleState>();
  readonly authorizationNonces = new Set<string>();
  readonly authorizationUncertain = new Set<string>();
}

function bytesToHex(bytes: readonly number[]): string {
  let encoded = '';
  for (const byte of bytes) encoded += byte.toString(16).padStart(2, '0');
  return encoded;
}

function equalBytes(left: readonly number[], right: readonly number[]): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= (left[index] ?? 0) ^ (right[index] ?? 0);
  }
  return difference === 0;
}

function exactParticipants(left: readonly number[], right: readonly number[]): boolean {
  return left.length === 2 && left[0] === right[0] && left[1] === right[1];
}

function exactApplicationBinding(
  left: RouterAbEd25519YaoExportAdmissionRequestV1['application_binding'],
  right: RouterAbEd25519YaoExportAdmissionRequestV1['application_binding'],
): boolean {
  return (
    left.wallet_id === right.wallet_id &&
    left.near_ed25519_signing_key_id === right.near_ed25519_signing_key_id &&
    left.signing_root_id === right.signing_root_id &&
    left.key_creation_signer_slot === right.key_creation_signer_slot
  );
}

function activeCapabilityIdentityMatchesExportScope(
  request: RouterAbEd25519YaoExportAdmissionRequestV1,
  capability: RouterAbEd25519YaoActiveCapabilityDescriptorV1,
): boolean {
  const scope = request.scope;
  const lifecycle = capability.lifecycle;
  return (
    scope.account_id === request.application_binding.wallet_id &&
    lifecycle.rootShareEpoch === scope.root_share_epoch &&
    lifecycle.accountId === scope.account_id &&
    lifecycle.thresholdSessionId === scope.threshold_session_id &&
    lifecycle.signerSetId === scope.signer_set_id &&
    lifecycle.signingWorkerId === scope.signing_worker_id &&
    sameRouterAbMpcMaterialActivationRef(capability.materialActivation, scope.material_activation)
  );
}

function receiptMatchesAdmissionScope(
  request: RouterAbEd25519YaoExportAdmissionRequestV1,
  receipt: RouterAbEd25519YaoExportAdmissionReceiptV1,
): boolean {
  const scope = request.scope;
  const lifecycle = receipt.binding.ceremony.lifecycle;
  return (
    receipt.binding.ceremony.operation === 'export' &&
    lifecycle.work_kind === 'key_export' &&
    lifecycle.primitive_request_kind === 'export' &&
    lifecycle.lifecycle_id === scope.lifecycle_id &&
    lifecycle.root_share_epoch === scope.root_share_epoch &&
    lifecycle.account_id === scope.account_id &&
    lifecycle.session_id === scope.threshold_session_id &&
    lifecycle.signer_set_id === scope.signer_set_id &&
    lifecycle.selected_server_id === scope.signing_worker_id &&
    sameRouterAbMpcMaterialActivationRef(
      receipt.binding.ceremony.material_activation,
      scope.material_activation,
    )
  );
}

function exportIdentity(
  request: RouterAbEd25519YaoExportAdmissionRequestV1,
): RouterAbEd25519YaoExportAuthorizationIdentityV1 {
  return {
    scope: request.scope,
    application_binding: request.application_binding,
    participant_ids: request.participant_ids,
    registered_public_key: request.registered_public_key,
    state_epoch: request.state_epoch,
    runtime_policy_binding: request.runtime_policy_binding,
  };
}

function failure(input: {
  status: RouterAbEd25519YaoExportFailure['status'];
  code: RouterAbEd25519YaoExportFailure['code'];
  message: string;
}): RouterAbEd25519YaoExportFailure {
  return { ok: false, ...input };
}

function canonicalFingerprint(value: unknown): string {
  return JSON.stringify(value);
}

function equalWire(left: unknown, right: unknown): boolean {
  return canonicalFingerprint(left) === canonicalFingerprint(right);
}

function exportKey(request: RouterAbEd25519YaoExportAdmissionRequestV1): string {
  return bytesToHex(request.authorization.authorization_digest);
}

function authorizationConflict(
  code: string,
  message: string,
): Extract<RouterAbEd25519YaoExportAuthorizationResult, { readonly ok: false }> {
  return { ok: false, status: 409, code, message };
}

function authorizationUnavailable(
  code: string,
  message: string,
): Extract<RouterAbEd25519YaoExportAuthorizationResult, { readonly ok: false }> {
  return { ok: false, status: 503, code, message };
}

function assertNeverExportState(value: never): never {
  throw new Error(`Unhandled Ed25519 Yao export state: ${String(value)}`);
}

function exportStateHasReceipt(
  state: ExportLifecycleState,
): state is
  | ExportAdmittedState
  | ExportExecutingState
  | ExportExecutionFailedState
  | ExportCompletedState {
  switch (state.kind) {
    case 'admitted':
    case 'executing':
    case 'execution_failed':
    case 'completed':
      return true;
    case 'authorizing':
    case 'authorization_failed':
    case 'authorized':
    case 'admitting':
    case 'admission_failed':
      return false;
    default:
      return assertNeverExportState(state);
  }
}

export class InMemoryRouterAbEd25519YaoExportService implements RouterAbEd25519YaoExportService {
  constructor(
    private readonly backend: RouterAbEd25519YaoExportBackend,
    private readonly capabilities: RouterAbEd25519YaoActiveCapabilityResolverV1,
    private readonly state: InMemoryRouterAbEd25519YaoExportStateV1 = new InMemoryRouterAbEd25519YaoExportStateV1(),
  ) {}

  authorizationIsUncertain(request: RouterAbEd25519YaoExportAdmissionRequestV1): boolean {
    return this.state.authorizationUncertain.has(exportKey(request));
  }

  recordAuthorizationUncertain(request: RouterAbEd25519YaoExportAdmissionRequestV1): void {
    this.state.authorizationUncertain.add(exportKey(request));
  }

  async admitExport(
    request: RouterAbEd25519YaoExportAdmissionRequestV1,
    authorizationIdentity: RouterAbEd25519YaoExportServerAuthorizationIdentityV1,
    traceContext?: RouterAbTraceContextV1,
  ): Promise<RouterAbEd25519YaoExportServiceResult<RouterAbEd25519YaoExportAdmissionReceiptV1>> {
    const authorizationFingerprint = exportKey(request);
    const authorization = this.prepareAuthorizeExport(
      request,
      authorizationFingerprint,
      authorizationIdentity,
    );
    if (authorization.kind === 'claimed') {
      const authorized = this.commitAuthorizeExport({
        request,
        claim: authorization.claim,
        outcome: { ok: true },
      });
      if (!authorized.ok) {
        return failure({
          status: authorized.status === 503 ? 503 : 409,
          code: 'admission_failed',
          message: authorized.message,
        });
      }
    } else if (!authorization.value.ok) {
      return failure({
        status: authorization.value.status === 503 ? 503 : 409,
        code: 'admission_failed',
        message: authorization.value.message,
      });
    }
    const preparation = await this.prepareAdmitExport(request, authorizationIdentity);
    switch (preparation.kind) {
      case 'completed':
        return { ok: true, status: 200, value: preparation.value };
      case 'failed':
        return preparation.failure;
      case 'claimed':
        break;
    }
    let outcome: RouterAbEd25519YaoExportAdmissionCommitInputV1['outcome'];
    try {
      outcome = {
        kind: 'backend_response',
        result: await this.backend.admitExport(request, traceContext),
      };
    } catch (error: unknown) {
      return this.failUncertainAdmission(preparation.claim, error);
    }
    return this.commitAdmitExport({ request, claim: preparation.claim, outcome });
  }

  prepareAuthorizeExport(
    request: RouterAbEd25519YaoExportAdmissionRequestV1,
    authorizationFingerprint: string,
    authorizationIdentity: RouterAbEd25519YaoExportServerAuthorizationIdentityV1,
  ): RouterAbEd25519YaoExportAuthorizationPreparationV1 {
    const key = exportKey(request);
    const existing = this.state.exports.get(key);
    if (existing) {
      if (!equalWire(existing.authorizationIdentity, authorizationIdentity)) {
        return {
          kind: 'completed',
          value: authorizationConflict(
            'export_authorization_conflict',
            'Export authorization owner changed for an existing request',
          ),
        };
      }
      if (existing.authorizationFingerprint !== authorizationFingerprint) {
        return {
          kind: 'completed',
          value: authorizationConflict(
            'export_authorization_conflict',
            'Export authorization changed for an existing request',
          ),
        };
      }
      switch (existing.kind) {
        case 'authorizing':
          return {
            kind: 'completed',
            value: authorizationUnavailable(
              'export_authorization_uncertain',
              'Export authorization outcome is uncertain and cannot be retried',
            ),
          };
        case 'authorization_failed':
          return { kind: 'completed', value: existing.failure };
        case 'authorized':
        case 'admitting':
        case 'admission_failed':
        case 'admitted':
        case 'executing':
        case 'execution_failed':
        case 'completed':
          return { kind: 'completed', value: { ok: true } };
        default:
          return assertNeverExportState(existing);
      }
    }
    const nonce = bytesToHex(request.authorization.nonce);
    if (this.state.authorizationNonces.has(nonce)) {
      return {
        kind: 'completed',
        value: authorizationConflict(
          'export_authorization_replayed',
          'Ed25519 Yao export authorization was already used',
        ),
      };
    }
    this.state.authorizationNonces.add(nonce);
    this.state.exports.set(key, {
      kind: 'authorizing',
      request,
      authorizationFingerprint,
      authorizationIdentity,
    });
    return {
      kind: 'claimed',
      claim: {
        kind: 'router_ab_ed25519_yao_export_authorization_claim_v1',
        lifecycleId: request.scope.lifecycle_id,
        exportKey: key,
        authorizationFingerprint,
      },
    };
  }

  readAuthorizationIdentity(
    request: RouterAbEd25519YaoExportAdmissionRequestV1,
  ): RouterAbEd25519YaoExportServerAuthorizationIdentityV1 | null {
    const current = this.state.exports.get(exportKey(request));
    return current?.authorizationIdentity ?? null;
  }

  commitAuthorizeExport(
    input: RouterAbEd25519YaoExportAuthorizationCommitInputV1,
  ): RouterAbEd25519YaoExportAuthorizationResult {
    const key = exportKey(input.request);
    const current = this.state.exports.get(input.claim.exportKey);
    if (
      current?.kind !== 'authorizing' ||
      input.claim.lifecycleId !== input.request.scope.lifecycle_id ||
      input.claim.exportKey !== key ||
      input.claim.authorizationFingerprint !== current.authorizationFingerprint ||
      !equalWire(current.request, input.request)
    ) {
      return authorizationUnavailable(
        'export_authorization_uncertain',
        'Export authorization claim is no longer current',
      );
    }
    if (!input.outcome.ok) {
      this.state.exports.set(key, {
        kind: 'authorization_failed',
        request: current.request,
        authorizationFingerprint: current.authorizationFingerprint,
        authorizationIdentity: current.authorizationIdentity,
        failure: input.outcome,
      });
      return input.outcome;
    }
    this.state.exports.set(key, {
      kind: 'authorized',
      request: current.request,
      authorizationFingerprint: current.authorizationFingerprint,
      authorizationIdentity: current.authorizationIdentity,
    });
    return { ok: true };
  }

  async prepareAdmitExport(
    request: RouterAbEd25519YaoExportAdmissionRequestV1,
    authorizationIdentity: RouterAbEd25519YaoExportServerAuthorizationIdentityV1,
  ): Promise<RouterAbEd25519YaoExportAdmissionPreparationV1> {
    const key = exportKey(request);
    const current = this.state.exports.get(key);
    if (!current || !equalWire(current.request, request)) {
      return {
        kind: 'failed',
        failure: failure({
          status: 409,
          code: 'admission_failed',
          message: 'Export admission requires a durable successful authorization claim',
        }),
      };
    }
    switch (current.kind) {
      case 'admitted':
      case 'executing':
      case 'execution_failed':
      case 'completed':
        return { kind: 'completed', value: current.receipt };
      case 'admission_failed':
        return { kind: 'failed', failure: current.failure };
      case 'admitting':
        return {
          kind: 'failed',
          failure: failure({
            status: 409,
            code: 'admission_in_progress',
            message: 'Export admission is already in progress',
          }),
        };
      case 'authorizing':
      case 'authorization_failed':
        return {
          kind: 'failed',
          failure: failure({
            status: 409,
            code: 'admission_failed',
            message: 'Export admission authorization is incomplete',
          }),
        };
      case 'authorized':
        break;
      default:
        return assertNeverExportState(current);
    }
    const active = await this.capabilities.resolveActiveCapability({
      kind: 'router_ab_ed25519_yao_active_capability_lookup_v1',
      walletId: request.application_binding.wallet_id,
      nearEd25519SigningKeyId: request.application_binding.near_ed25519_signing_key_id,
      signerSlot: request.application_binding.key_creation_signer_slot,
      signingWorkerId: request.scope.signing_worker_id,
      participantIds: request.participant_ids,
    });
    if (!active.ok) {
      const rejected = failure({
        status: 409,
        code: 'active_identity_mismatch',
        message: active.message,
      });
      this.storeAdmissionFailure(current, rejected);
      return { kind: 'failed', failure: rejected };
    }
    const runtimePolicyBinding = await deriveRouterAbEd25519YaoRuntimePolicyBindingV1(
      active.capability.runtimePolicyScope,
    );
    if (
      !activeCapabilityIdentityMatchesExportScope(request, active.capability) ||
      !exactApplicationBinding(request.application_binding, active.capability.applicationBinding) ||
      !exactParticipants(request.participant_ids, active.capability.participantIds) ||
      !equalBytes(request.registered_public_key, active.capability.registeredPublicKey) ||
      request.state_epoch !== active.capability.stateEpoch ||
      !equalBytes(request.runtime_policy_binding, runtimePolicyBinding)
    ) {
      const rejected = failure({
        status: 409,
        code: 'active_identity_mismatch',
        message: 'Ed25519 Yao export does not match the exact active key capability',
      });
      this.storeAdmissionFailure(current, rejected);
      return { kind: 'failed', failure: rejected };
    }
    this.state.exports.set(key, {
      kind: 'admitting',
      request: current.request,
      authorizationFingerprint: current.authorizationFingerprint,
      authorizationIdentity: current.authorizationIdentity,
    });
    return {
      kind: 'claimed',
      claim: {
        kind: 'router_ab_ed25519_yao_export_admission_claim_v1',
        lifecycleId: request.scope.lifecycle_id,
        exportKey: key,
        authorizationFingerprint: current.authorizationFingerprint,
      },
    };
  }

  commitAdmitExport(
    input: RouterAbEd25519YaoExportAdmissionCommitInputV1,
  ): RouterAbEd25519YaoExportServiceResult<RouterAbEd25519YaoExportAdmissionReceiptV1> {
    const key = exportKey(input.request);
    const current = this.state.exports.get(input.claim.exportKey);
    if (
      current?.kind !== 'admitting' ||
      input.claim.lifecycleId !== input.request.scope.lifecycle_id ||
      input.claim.exportKey !== key ||
      input.claim.authorizationFingerprint !== current.authorizationFingerprint ||
      !equalWire(current.request, input.request)
    ) {
      return failure({
        status: 409,
        code: 'admission_in_progress',
        message: 'Export admission claim is no longer current',
      });
    }
    const backendResult = input.outcome.result;
    if (!backendResult.ok) {
      const rejected = exportBackendFailure(backendResult, 'admission_failed');
      this.storeAdmissionFailure(current, rejected);
      return rejected;
    }
    const parsed = parseRouterAbEd25519YaoExportAdmissionReceiptV1(backendResult.body);
    if (!parsed.ok) {
      const rejected = failure({
        status: 502,
        code: 'invalid_backend_response',
        message: parsed.message,
      });
      this.storeAdmissionFailure(current, rejected);
      return rejected;
    }
    if (
      !receiptMatchesAdmissionScope(input.request, parsed.value) ||
      !equalBytes(
        parsed.value.binding.authorization_digest,
        input.request.authorization.authorization_digest,
      ) ||
      !equalBytes(
        parsed.value.binding.registered_public_key,
        input.request.registered_public_key,
      ) ||
      parsed.value.binding.state_epoch !== input.request.state_epoch ||
      !equalBytes(parsed.value.binding.runtime_policy_binding, input.request.runtime_policy_binding)
    ) {
      const rejected = failure({
        status: 502,
        code: 'invalid_backend_response',
        message: 'Ed25519 Yao export admission receipt changed an exact binding',
      });
      this.storeAdmissionFailure(current, rejected);
      return rejected;
    }
    const session = bytesToHex(parsed.value.binding.ceremony.session_id);
    const sessionOwner = this.findExportBySession(session);
    if (sessionOwner && sessionOwner.key !== key) {
      const rejected = failure({
        status: 502,
        code: 'invalid_backend_response',
        message: 'Ed25519 Yao export backend reused a session identifier',
      });
      this.storeAdmissionFailure(current, rejected);
      return rejected;
    }
    this.state.exports.set(key, {
      kind: 'admitted',
      request: current.request,
      authorizationFingerprint: current.authorizationFingerprint,
      authorizationIdentity: current.authorizationIdentity,
      receipt: parsed.value,
    });
    return { ok: true, status: 200, value: parsed.value };
  }

  async executeExport(
    request: RouterAbEd25519YaoExportExecuteRequestV1,
    authorizationIdentity: RouterAbEd25519YaoExportServerAuthorizationIdentityV1,
    traceContext?: RouterAbTraceContextV1,
  ): Promise<RouterAbEd25519YaoExportServiceResult<RouterAbEd25519YaoExportResultV1>> {
    const preparation = this.prepareExecuteExport(request, authorizationIdentity);
    switch (preparation.kind) {
      case 'completed':
        return { ok: true, status: 200, value: preparation.value };
      case 'failed':
        return preparation.failure;
      case 'claimed':
        break;
    }
    let outcome: RouterAbEd25519YaoExportExecuteCommitInputV1['outcome'];
    try {
      outcome = {
        kind: 'backend_response',
        result: await this.backend.executeExport(request, traceContext),
      };
    } catch (error: unknown) {
      return this.failUncertainExecution(preparation.claim, error);
    }
    return this.commitExecuteExport({ request, claim: preparation.claim, outcome });
  }

  prepareExecuteExport(
    request: RouterAbEd25519YaoExportExecuteRequestV1,
    authorizationIdentity: RouterAbEd25519YaoExportServerAuthorizationIdentityV1,
  ): RouterAbEd25519YaoExportExecutePreparationV1 {
    const session = bytesToHex(request.binding.ceremony.session_id);
    const found = this.findExportBySession(session);
    if (!found) {
      return {
        kind: 'failed',
        failure: failure({
          status: 404,
          code: 'unknown_export',
          message: 'Unknown export session',
        }),
      };
    }
    const current = found.state;
    if (
      !exportStateHasReceipt(current) ||
      !equalWire(current.authorizationIdentity, authorizationIdentity) ||
      !equalWire(current.receipt.binding, request.binding)
    ) {
      const rejected = failure({
        status: 409,
        code: 'binding_mismatch',
        message: 'Ed25519 Yao export execution changed the admitted binding',
      });
      if (exportStateHasReceipt(current)) {
        this.state.exports.set(found.key, {
          kind: 'execution_failed',
          request: current.request,
          authorizationFingerprint: current.authorizationFingerprint,
          authorizationIdentity: current.authorizationIdentity,
          receipt: current.receipt,
          executeFingerprint: canonicalFingerprint(request),
          failure: rejected,
        });
      }
      return { kind: 'failed', failure: rejected };
    }
    const executeFingerprint = canonicalFingerprint(request);
    switch (current.kind) {
      case 'admitted':
        this.state.exports.set(found.key, {
          kind: 'executing',
          request: current.request,
          authorizationFingerprint: current.authorizationFingerprint,
          authorizationIdentity: current.authorizationIdentity,
          receipt: current.receipt,
          executeFingerprint,
        });
        return {
          kind: 'claimed',
          claim: {
            kind: 'router_ab_ed25519_yao_export_execute_claim_v1',
            lifecycleId: request.binding.ceremony.lifecycle.lifecycle_id,
            exportKey: found.key,
            sessionId: session,
            executeFingerprint,
          },
        };
      case 'executing':
        return {
          kind: 'failed',
          failure: failure({
            status: 409,
            code: 'execution_in_progress',
            message: 'Export execution outcome is uncertain and cannot be retried',
          }),
        };
      case 'execution_failed':
        return {
          kind: 'failed',
          failure:
            current.executeFingerprint === executeFingerprint
              ? current.failure
              : failure({
                  status: 409,
                  code: 'export_consumed',
                  message: 'Ed25519 Yao export session was consumed by another execution',
                }),
        };
      case 'completed':
        return current.executeFingerprint === executeFingerprint
          ? { kind: 'completed', value: current.result }
          : {
              kind: 'failed',
              failure: failure({
                status: 409,
                code: 'export_consumed',
                message: 'Ed25519 Yao export session was consumed by another execution',
              }),
            };
      default:
        return assertNeverExportState(current);
    }
  }

  commitExecuteExport(
    input: RouterAbEd25519YaoExportExecuteCommitInputV1,
  ): RouterAbEd25519YaoExportServiceResult<RouterAbEd25519YaoExportResultV1> {
    const current = this.state.exports.get(input.claim.exportKey);
    if (
      current?.kind !== 'executing' ||
      input.claim.lifecycleId !== input.request.binding.ceremony.lifecycle.lifecycle_id ||
      input.claim.sessionId !== bytesToHex(input.request.binding.ceremony.session_id) ||
      input.claim.executeFingerprint !== canonicalFingerprint(input.request) ||
      current.executeFingerprint !== input.claim.executeFingerprint ||
      !equalWire(current.receipt.binding, input.request.binding)
    ) {
      return failure({
        status: 409,
        code: 'execution_in_progress',
        message: 'Export execution claim is no longer current',
      });
    }
    const backendResult = input.outcome.result;
    if (!backendResult.ok) {
      const rejected = exportBackendFailure(backendResult, 'execution_failed');
      this.storeExecutionFailure(input.claim.exportKey, current, rejected);
      return rejected;
    }
    const parsed = parseRouterAbEd25519YaoExportResultV1(backendResult.body);
    if (!parsed.ok || !equalWire(parsed.value.binding, input.request.binding)) {
      const rejected = failure({
        status: 502,
        code: 'invalid_backend_response',
        message: parsed.ok ? 'Export result changed the admitted binding' : parsed.message,
      });
      this.storeExecutionFailure(input.claim.exportKey, current, rejected);
      return rejected;
    }
    this.state.exports.set(input.claim.exportKey, {
      kind: 'completed',
      request: current.request,
      authorizationFingerprint: current.authorizationFingerprint,
      authorizationIdentity: current.authorizationIdentity,
      receipt: current.receipt,
      executeFingerprint: current.executeFingerprint,
      result: parsed.value,
    });
    return { ok: true, status: 200, value: parsed.value };
  }

  private failUncertainAdmission(
    claim: RouterAbEd25519YaoExportAdmissionClaimV1,
    error: unknown,
  ): RouterAbEd25519YaoExportFailure {
    const current = this.state.exports.get(claim.exportKey);
    const rejected = failure({
      status: 503,
      code: 'admission_failed',
      message: error instanceof Error ? error.message : String(error),
    });
    if (current?.kind === 'admitting') this.storeAdmissionFailure(current, rejected);
    return rejected;
  }

  private failUncertainExecution(
    claim: RouterAbEd25519YaoExportExecuteClaimV1,
    error: unknown,
  ): RouterAbEd25519YaoExportFailure {
    const current = this.state.exports.get(claim.exportKey);
    const rejected = failure({
      status: 503,
      code: 'execution_failed',
      message: error instanceof Error ? error.message : String(error),
    });
    if (current?.kind === 'executing') {
      this.storeExecutionFailure(claim.exportKey, current, rejected);
    }
    return rejected;
  }

  private storeAdmissionFailure(
    current: ExportAuthorizationContext,
    rejected: RouterAbEd25519YaoExportFailure,
  ): void {
    this.state.exports.set(exportKey(current.request), {
      kind: 'admission_failed',
      request: current.request,
      authorizationFingerprint: current.authorizationFingerprint,
      authorizationIdentity: current.authorizationIdentity,
      failure: rejected,
    });
  }

  private storeExecutionFailure(
    key: string,
    current: ExportExecutingState,
    rejected: RouterAbEd25519YaoExportFailure,
  ): void {
    this.state.exports.set(key, {
      kind: 'execution_failed',
      request: current.request,
      authorizationFingerprint: current.authorizationFingerprint,
      authorizationIdentity: current.authorizationIdentity,
      receipt: current.receipt,
      executeFingerprint: current.executeFingerprint,
      failure: rejected,
    });
  }

  private findExportBySession(
    sessionId: string,
  ): { readonly key: string; readonly state: ExportLifecycleState } | null {
    for (const [key, state] of this.state.exports) {
      if (
        exportStateHasReceipt(state) &&
        bytesToHex(state.receipt.binding.ceremony.session_id) === sessionId
      ) {
        return { key, state };
      }
    }
    return null;
  }
}

type RouterAbEd25519YaoExportAuthorizationFailure = Extract<
  RouterAbEd25519YaoExportAuthorizationResult,
  { readonly ok: false }
>;

function authorizationFailure(
  input: Omit<RouterAbEd25519YaoExportAuthorizationFailure, 'ok'>,
): RouterAbEd25519YaoExportAuthorizationFailure {
  return { ok: false, ...input };
}

function serverDerivedExportAuthorizationIdentity(
  claims: RouterAbEd25519OwnerWalletSessionClaims,
): ServerDerivedExportAuthorizationIdentity | null {
  const thresholdSessionId = parseThresholdEd25519SessionId(claims.thresholdSessionId);
  if (!thresholdSessionId.ok) return null;
  return {
    thresholdSessionId: thresholdSessionId.value,
    walletSessionId: claims.walletSessionId,
  };
}

function claimsMatchExportAdmission(
  claims: RouterAbEd25519OwnerWalletSessionClaims,
  input: ExportAdmissionAuthorizationInput,
  authorizationIdentity: ServerDerivedExportAuthorizationIdentity,
): boolean {
  const request = input.body;
  return (
    claims.walletId === request.application_binding.wallet_id &&
    claims.walletId === request.scope.account_id &&
    claims.nearEd25519SigningKeyId === request.application_binding.near_ed25519_signing_key_id &&
    claims.thresholdSessionId === authorizationIdentity.thresholdSessionId &&
    claims.walletSessionId === authorizationIdentity.walletSessionId &&
    claims.relayerKeyId === request.scope.signing_worker_id &&
    claims.routerAbNormalSigning.signingWorkerId === request.scope.signing_worker_id &&
    claims.runtimePolicyScope.signingRootVersion === request.scope.root_share_epoch &&
    exactParticipants(claims.participantIds, request.participant_ids)
  );
}

type ExportAdmissionAuthorizationInput = Extract<
  RouterAbEd25519YaoExportAuthorizationInput,
  { readonly kind: 'admit' }
>;

type ExportExecutionAuthorizationInput = Extract<
  RouterAbEd25519YaoExportAuthorizationInput,
  { readonly kind: 'execute' }
>;

type ExportAuthorizationDigestAuthority =
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

function assertNeverExportAuthorizationInput(value: never): never {
  throw new Error(`Unsupported Ed25519 Yao export authorization input: ${String(value)}`);
}

function assertNeverExportAdmissionAuthorization(value: never): never {
  throw new Error(`Unsupported Ed25519 Yao export admission authorization: ${String(value)}`);
}

function assertNeverWalletAuthFactor(value: never): never {
  throw new Error(`Unsupported Ed25519 Yao export Wallet Session factor: ${String(value)}`);
}

function assertNeverWalletAuthVerifier(value: never): never {
  throw new Error(`Unsupported Ed25519 Yao export Wallet Session verifier: ${String(value)}`);
}

function invalidExportWalletAuthority(): RouterAbEd25519YaoExportAuthorizationResult {
  return authorizationFailure({
    status: 403,
    code: 'export_wallet_authority_invalid',
    message: 'Ed25519 Yao export Wallet Session authority is unsupported',
  });
}

function exportAuthorizationDigestAuthority(
  authority: WalletAuthAuthority,
): ExportAuthorizationDigestAuthority {
  const factor: AuthFactorIdentity = authority.factor;
  switch (factor.kind) {
    case 'passkey':
      return {
        kind: 'passkey',
        credentialIdB64u: factor.credentialIdB64u,
      };
    case 'email_otp':
      return {
        kind: 'email_otp',
        providerSubjectId: factor.providerUserId,
      };
    default:
      return assertNeverWalletAuthFactor(factor);
  }
}

function authorizeExportExecution(
  claims: RouterAbEd25519OwnerWalletSessionClaims,
  input: ExportExecutionAuthorizationInput,
  authorizationIdentity: ServerDerivedExportAuthorizationIdentity,
): RouterAbEd25519YaoExportAuthorizationResult {
  const lifecycle = input.body.binding.ceremony.lifecycle;
  if (
    claims.walletId !== lifecycle.account_id ||
    claims.thresholdSessionId !== authorizationIdentity.thresholdSessionId ||
    claims.walletSessionId !== authorizationIdentity.walletSessionId ||
    claims.relayerKeyId !== lifecycle.selected_server_id
  ) {
    return authorizationFailure({
      status: 403,
      code: 'wallet_session_scope_mismatch',
      message: walletSessionFailureMessage('wallet_session_scope_mismatch'),
    });
  }
  return { ok: true };
}

async function authorizePasskeyExportAdmission(args: {
  readonly authority: {
    readonly walletId: string;
    readonly credentialIdB64u: string;
    readonly rpId: Extract<WalletAuthAuthority['verifier'], { readonly kind: 'webauthn' }>['rpId'];
  };
  readonly input: ExportAdmissionAuthorizationInput;
  readonly confirmationDigest: readonly number[];
  readonly webAuthn: Pick<RouterApiWebAuthnService, 'verifyWebAuthnAuthenticationLite'>;
}): Promise<RouterAbEd25519YaoExportAuthorizationResult> {
  switch (args.input.authorization.kind) {
    case 'email_otp_factor':
      return authorizationFailure({
        status: 403,
        code: 'export_authorization_method_mismatch',
        message: 'Ed25519 Yao export authorization method does not match the Wallet Session',
      });
    case 'passkey': {
      const credentialId = webAuthnCredentialIdB64uFromCredential(
        args.input.authorization.webauthnAuthentication,
      );
      if (!credentialId.ok || credentialId.credentialIdB64u !== args.authority.credentialIdB64u) {
        return authorizationFailure({
          status: 403,
          code: 'export_webauthn_credential_mismatch',
          message: 'Fresh export assertion used a different passkey credential',
        });
      }
      const verified = await args.webAuthn.verifyWebAuthnAuthenticationLite({
        userId: args.authority.walletId,
        rpId: args.authority.rpId,
        expectedChallenge: base64UrlEncode(Uint8Array.from(args.confirmationDigest)),
        webauthn_authentication: args.input.authorization.webauthnAuthentication,
        expected_origin: args.input.expectedOrigin,
      });
      if (!verified.success || !verified.verified) {
        return authorizationFailure({
          status: 403,
          code: verified.code || 'export_webauthn_not_verified',
          message: verified.message || 'Fresh export WebAuthn assertion was not verified',
        });
      }
      return { ok: true };
    }
    default:
      return assertNeverExportAdmissionAuthorization(args.input.authorization);
  }
}

function authorizeEmailOtpExportAdmission(args: {
  readonly providerSubjectId: string;
  readonly input: ExportAdmissionAuthorizationInput;
}): RouterAbEd25519YaoExportAuthorizationResult {
  switch (args.input.authorization.kind) {
    case 'passkey':
      return authorizationFailure({
        status: 403,
        code: 'export_authorization_method_mismatch',
        message: 'Ed25519 Yao export authorization method does not match the Wallet Session',
      });
    case 'email_otp_factor':
      if (args.input.authorization.providerSubjectId !== args.providerSubjectId) {
        return authorizationFailure({
          status: 403,
          code: 'export_authorization_method_mismatch',
          message: 'Ed25519 Yao export authorization method does not match the Wallet Session',
        });
      }
      return { ok: true };
    default:
      return assertNeverExportAdmissionAuthorization(args.input.authorization);
  }
}

async function authorizeExportAdmissionFactor(args: {
  readonly claims: RouterAbEd25519OwnerWalletSessionClaims;
  readonly input: ExportAdmissionAuthorizationInput;
  readonly confirmationDigest: readonly number[];
  readonly webAuthn: Pick<RouterApiWebAuthnService, 'verifyWebAuthnAuthenticationLite'>;
}): Promise<RouterAbEd25519YaoExportAuthorizationResult> {
  const authority = args.claims.authority;
  const factor: AuthFactorIdentity = authority.factor;
  switch (factor.kind) {
    case 'passkey': {
      const verifier: WalletAuthAuthority['verifier'] = authority.verifier;
      switch (verifier.kind) {
        case 'webauthn':
          return authorizePasskeyExportAdmission({
            authority: {
              walletId: authority.walletId,
              credentialIdB64u: factor.credentialIdB64u,
              rpId: verifier.rpId,
            },
            input: args.input,
            confirmationDigest: args.confirmationDigest,
            webAuthn: args.webAuthn,
          });
        case 'email_otp_wallet_auth_method':
          return invalidExportWalletAuthority();
        default:
          return assertNeverWalletAuthVerifier(verifier);
      }
    }
    case 'email_otp': {
      const verifier: WalletAuthAuthority['verifier'] = authority.verifier;
      switch (verifier.kind) {
        case 'email_otp_wallet_auth_method':
          return authorizeEmailOtpExportAdmission({
            providerSubjectId: factor.providerUserId,
            input: args.input,
          });
        case 'webauthn':
          return invalidExportWalletAuthority();
        default:
          return assertNeverWalletAuthVerifier(verifier);
      }
    }
    default:
      return assertNeverWalletAuthFactor(factor);
  }
}

async function authorizeExportAdmission(args: {
  readonly claims: RouterAbEd25519OwnerWalletSessionClaims;
  readonly authorizationIdentity: ServerDerivedExportAuthorizationIdentity;
  readonly input: ExportAdmissionAuthorizationInput;
  readonly webAuthn: Pick<RouterApiWebAuthnService, 'verifyWebAuthnAuthenticationLite'>;
}): Promise<RouterAbEd25519YaoExportAuthorizationResult> {
  if (!claimsMatchExportAdmission(args.claims, args.input, args.authorizationIdentity)) {
    return authorizationFailure({
      status: 403,
      code: 'wallet_session_scope_mismatch',
      message: walletSessionFailureMessage('wallet_session_scope_mismatch'),
    });
  }
  const nowMs = Date.now();
  const authorization = args.input.body.authorization;
  if (
    authorization.expires_at_ms <= nowMs ||
    authorization.issued_at_ms > nowMs + EXPORT_AUTH_CLOCK_SKEW_MS ||
    authorization.expires_at_ms - authorization.issued_at_ms > EXPORT_AUTH_MAX_TTL_MS
  ) {
    return authorizationFailure({
      status: 403,
      code: 'export_authorization_expired',
      message: 'Ed25519 Yao export authorization is expired or has an invalid lifetime',
    });
  }
  const identity = exportIdentity(args.input.body);
  const expectedConfirmation = await deriveRouterAbEd25519YaoExportConfirmationDigestV1({
    identity,
    nonce: authorization.nonce,
    issuedAtMs: authorization.issued_at_ms,
    expiresAtMs: authorization.expires_at_ms,
  });
  const expectedAuthorization = await deriveRouterAbEd25519YaoExportAuthorizationDigestV1({
    identity,
    confirmationDigest: authorization.confirmation_digest,
    nonce: authorization.nonce,
    issuedAtMs: authorization.issued_at_ms,
    expiresAtMs: authorization.expires_at_ms,
    authority: exportAuthorizationDigestAuthority(args.claims.authority),
  });
  if (
    !equalBytes(expectedConfirmation, authorization.confirmation_digest) ||
    !equalBytes(expectedAuthorization, authorization.authorization_digest)
  ) {
    return authorizationFailure({
      status: 403,
      code: 'export_authorization_invalid',
      message: 'Ed25519 Yao export authorization digest is invalid',
    });
  }
  return authorizeExportAdmissionFactor({
    claims: args.claims,
    input: args.input,
    confirmationDigest: authorization.confirmation_digest,
    webAuthn: args.webAuthn,
  });
}

type ResolvedWalletSessionAuthorization =
  | {
      readonly ok: true;
      readonly claims: RouterAbEd25519OwnerWalletSessionClaims;
      readonly authorizationIdentity: ServerDerivedExportAuthorizationIdentity;
    }
  | Extract<RouterAbEd25519YaoExportAuthorizationResult, { readonly ok: false }>;

async function resolveWalletSessionAuthorization(
  session: SessionAdapter,
  request: Request,
): Promise<ResolvedWalletSessionAuthorization> {
  let parsedSession: Awaited<ReturnType<SessionAdapter['parse']>>;
  try {
    parsedSession = await session.parse(headersToRecord(request.headers));
  } catch {
    return authorizationFailure({
      status: walletSessionFailureStatus('wallet_session_unavailable'),
      code: 'wallet_session_unavailable',
      message: walletSessionFailureMessage('wallet_session_unavailable'),
    });
  }
  if (!parsedSession.ok) {
    const code = walletSessionFailureCodeFromParseReason(parsedSession.reason);
    return authorizationFailure({
      status: walletSessionFailureStatus(code),
      code,
      message: walletSessionFailureMessage(code),
    });
  }
  const parsedClaims = parseRouterAbEd25519WalletSessionClaims(parsedSession.claims);
  if (!parsedClaims || parsedClaims.authorizationKind !== 'owner_wallet_session') {
    return authorizationFailure({
      status: walletSessionFailureStatus('wallet_session_claims_invalid'),
      code: 'wallet_session_claims_invalid',
      message: walletSessionFailureMessage('wallet_session_claims_invalid'),
    });
  }
  if (parsedClaims.thresholdExpiresAtMs <= Date.now()) {
    return authorizationFailure({
      status: walletSessionFailureStatus('wallet_session_expired'),
      code: 'wallet_session_expired',
      message: walletSessionFailureMessage('wallet_session_expired'),
    });
  }
  const authorizationIdentity = serverDerivedExportAuthorizationIdentity(parsedClaims);
  if (!authorizationIdentity) {
    return authorizationFailure({
      status: walletSessionFailureStatus('wallet_session_claims_invalid'),
      code: 'wallet_session_claims_invalid',
      message: walletSessionFailureMessage('wallet_session_claims_invalid'),
    });
  }
  return { ok: true, claims: parsedClaims, authorizationIdentity };
}

export class RouterAbEd25519YaoExportWalletSessionAuthorizationAdapter implements RouterAbEd25519YaoExportAuthorizationAdapter {
  constructor(
    private readonly session: SessionAdapter,
    private readonly webAuthn: Pick<RouterApiWebAuthnService, 'verifyWebAuthnAuthenticationLite'>,
  ) {}

  async authorize(
    input: RouterAbEd25519YaoExportAuthorizationInput,
  ): Promise<RouterAbEd25519YaoExportAuthorizationAdapterResult> {
    const resolved = await resolveWalletSessionAuthorization(this.session, input.request);
    if (!resolved.ok) return resolved;
    const { claims, authorizationIdentity } = resolved;
    switch (input.kind) {
      case 'admit': {
        const checked = await authorizeExportAdmission({
          claims,
          authorizationIdentity,
          input,
          webAuthn: this.webAuthn,
        });
        return checked.ok ? { ok: true, authorizationIdentity } : checked;
      }
      case 'execute': {
        const checked = authorizeExportExecution(claims, input, authorizationIdentity);
        return checked.ok ? { ok: true, authorizationIdentity } : checked;
      }
      default:
        return assertNeverExportAuthorizationInput(input);
    }
  }

  async resolveAuthorizationIdentity(
    request: Request,
  ): Promise<RouterAbEd25519YaoExportAuthorizationIdentityResolutionResult> {
    const resolved = await resolveWalletSessionAuthorization(this.session, request);
    return resolved.ok
      ? { ok: true, authorizationIdentity: resolved.authorizationIdentity }
      : resolved;
  }
}

const ROUTES = Object.freeze([
  defineRoute({
    id: 'router_ab_ed25519_yao_export_admit',
    surface: 'relay',
    method: 'POST',
    path: ROUTER_AB_ED25519_YAO_EXPORT_ADMISSION_PATH_V1,
    auth: {
      plane: 'public',
      proof: 'challenge_exchange',
      rationale:
        'Exact-seed export requires fresh passkey assertion or Email OTP factor possession.',
    },
    metering: { kind: 'none' },
    requiredServices: [],
    summary: 'Admit one exact Ed25519 Yao seed export',
  }),
  defineRoute({
    id: 'router_ab_ed25519_yao_export_execute',
    surface: 'relay',
    method: 'POST',
    path: ROUTER_AB_ED25519_YAO_EXPORT_EXECUTE_PATH_V1,
    auth: {
      plane: 'public',
      proof: 'threshold_protocol_state',
      rationale: 'Execution consumes one admitted and passkey-authorized export ceremony.',
    },
    metering: { kind: 'none' },
    requiredServices: [],
    summary: 'Execute one admitted Ed25519 Yao seed export',
  }),
]);

type ExportAdmissionAuthorizationParseResult =
  | {
      readonly ok: true;
      readonly value: RouterAbEd25519YaoExportAdmissionAuthorization;
    }
  | { readonly ok: false; readonly message: string };

export type RouterAbEd25519YaoExportAdmissionEnvelopeParseResultV1 =
  | {
      readonly ok: true;
      readonly protocol: RouterAbEd25519YaoExportAdmissionRequestV1;
      readonly authorization: RouterAbEd25519YaoExportAdmissionAuthorization;
    }
  | { readonly ok: false; readonly message: string };

export type RouterAbEd25519YaoExportExecuteEnvelopeParseResultV1 =
  | {
      readonly ok: true;
      readonly protocol: RouterAbEd25519YaoExportExecuteRequestV1;
    }
  | { readonly ok: false; readonly message: string };

function firstUnexpectedField(
  record: Record<string, unknown>,
  allowedFields: readonly string[],
): string | null {
  for (const key of Object.keys(record)) {
    if (!allowedFields.includes(key)) return key;
  }
  return null;
}

function parsePasskeyExportAdmissionAuthorization(
  authorization: Record<string, unknown>,
): ExportAdmissionAuthorizationParseResult {
  const unexpectedField = firstUnexpectedField(authorization, ['kind', 'webauthnAuthentication']);
  if (unexpectedField) {
    return {
      ok: false,
      message: `passkey export authorization has unknown field: ${unexpectedField}`,
    };
  }
  const webauthnAuthentication = parseWebAuthnAuthenticationCredential(
    authorization.webauthnAuthentication,
  );
  if (!webauthnAuthentication) {
    return { ok: false, message: 'webauthnAuthentication is invalid' };
  }
  return {
    ok: true,
    value: { kind: 'passkey', webauthnAuthentication },
  };
}

function parseEmailOtpExportAdmissionAuthorization(
  authorization: Record<string, unknown>,
): ExportAdmissionAuthorizationParseResult {
  const unexpectedField = firstUnexpectedField(authorization, ['kind', 'providerSubjectId']);
  if (unexpectedField) {
    return {
      ok: false,
      message: `Email OTP export authorization has unknown field: ${unexpectedField}`,
    };
  }
  if (typeof authorization.providerSubjectId !== 'string') {
    return { ok: false, message: 'providerSubjectId must be a string' };
  }
  const providerSubjectId = authorization.providerSubjectId.trim();
  if (!providerSubjectId) {
    return { ok: false, message: 'providerSubjectId is required' };
  }
  return {
    ok: true,
    value: { kind: 'email_otp_factor', providerSubjectId },
  };
}

function parseExportAdmissionAuthorization(
  value: unknown,
): ExportAdmissionAuthorizationParseResult {
  if (!isPlainObject(value)) {
    return { ok: false, message: 'export admission authorization must be an object' };
  }
  switch (value.kind) {
    case 'passkey':
      return parsePasskeyExportAdmissionAuthorization(value);
    case 'email_otp_factor':
      return parseEmailOtpExportAdmissionAuthorization(value);
    default:
      return { ok: false, message: 'export admission authorization kind is invalid' };
  }
}

export function parseRouterAbEd25519YaoExportAdmissionEnvelopeV1(
  value: unknown,
): RouterAbEd25519YaoExportAdmissionEnvelopeParseResultV1 {
  if (!isPlainObject(value)) {
    return { ok: false, message: 'export admission envelope must be an object' };
  }
  const record = value;
  const keys = Object.keys(record);
  if (
    keys.length !== 2 ||
    !Object.hasOwn(record, 'protocol') ||
    !Object.hasOwn(record, 'authorization')
  ) {
    return {
      ok: false,
      message: 'export admission envelope requires protocol and authorization',
    };
  }
  const protocol = parseRouterAbEd25519YaoExportAdmissionRequestV1(record.protocol);
  if (!protocol.ok) return protocol;
  const authorization = parseExportAdmissionAuthorization(record.authorization);
  if (!authorization.ok) return authorization;
  return {
    ok: true,
    protocol: protocol.value,
    authorization: authorization.value,
  };
}

export function parseRouterAbEd25519YaoExportExecuteEnvelopeV1(
  value: unknown,
): RouterAbEd25519YaoExportExecuteEnvelopeParseResultV1 {
  if (!isPlainObject(value)) {
    return { ok: false, message: 'export execute envelope must be an object' };
  }
  const keys = Object.keys(value);
  if (keys.length !== 1 || !Object.hasOwn(value, 'protocol')) {
    return {
      ok: false,
      message: 'export execute envelope requires protocol',
    };
  }
  const protocol = parseRouterAbEd25519YaoExportExecuteRequestV1(value.protocol);
  if (!protocol.ok) return protocol;
  return {
    ok: true,
    protocol: protocol.value,
  };
}

class RouterAbEd25519YaoExportRouteExtension implements RouterApiRouteExtension {
  readonly kind = 'fetch_route_extension' as const;
  readonly id = 'router_ab_ed25519_yao_export';
  readonly routes = ROUTES;

  constructor(
    private readonly service: RouterAbEd25519YaoExportService,
    private readonly authorization: RouterAbEd25519YaoExportAuthorizationAdapter,
  ) {}

  async handleFetchRoute(input: RouterApiFetchRouteExtensionInput): Promise<Response> {
    if (input.method !== 'POST') {
      return json(
        { ok: false, code: 'method_not_allowed', message: 'Method not allowed' },
        { status: 405 },
      );
    }
    const raw = await readJson(input.request);
    if (input.pathname === ROUTER_AB_ED25519_YAO_EXPORT_ADMISSION_PATH_V1) {
      const traceContext = resolveTraceContext(input.request);
      if (!traceContext.ok)
        return json(
          { ok: false, code: 'invalid_trace_id', message: traceContext.message },
          { status: 400 },
        );
      const parsed = parseRouterAbEd25519YaoExportAdmissionEnvelopeV1(raw);
      if (!parsed.ok)
        return json({ ok: false, code: 'invalid_body', message: parsed.message }, { status: 400 });
      const expectedOrigin = normalizeCorsOrigin(input.request.headers.get('origin') || undefined);
      if (!expectedOrigin) {
        return json(
          {
            ok: false,
            code: 'forbidden',
            message: 'Origin header is required and must be a valid exact origin',
          },
          { status: 403 },
        );
      }
      const authorized = await this.authorization.authorize({
        kind: 'admit',
        request: input.request,
        body: parsed.protocol,
        authorization: parsed.authorization,
        expectedOrigin,
      });
      if (!authorized.ok)
        return json(
          { ok: false, code: authorized.code, message: authorized.message },
          { status: authorized.status },
        );
      const result = await this.service.admitExport(
        parsed.protocol,
        authorized.authorizationIdentity,
        traceContext.value,
      );
      return result.ok
        ? json(result.value, { status: result.status })
        : json(
            { ok: false, code: result.code, message: result.message },
            { status: result.status },
          );
    }
    if (input.pathname === ROUTER_AB_ED25519_YAO_EXPORT_EXECUTE_PATH_V1) {
      const traceContext = resolveTraceContext(input.request);
      if (!traceContext.ok)
        return json(
          { ok: false, code: 'invalid_trace_id', message: traceContext.message },
          { status: 400 },
        );
      const parsed = parseRouterAbEd25519YaoExportExecuteEnvelopeV1(raw);
      if (!parsed.ok)
        return json({ ok: false, code: 'invalid_body', message: parsed.message }, { status: 400 });
      const authorized = await this.authorization.authorize({
        kind: 'execute',
        request: input.request,
        body: parsed.protocol,
      });
      if (!authorized.ok)
        return json(
          { ok: false, code: authorized.code, message: authorized.message },
          { status: authorized.status },
        );
      const result = await this.service.executeExport(
        parsed.protocol,
        authorized.authorizationIdentity,
        traceContext.value,
      );
      return result.ok
        ? json(result.value, { status: result.status })
        : json(
            { ok: false, code: result.code, message: result.message },
            { status: result.status },
          );
    }
    return json({ ok: false, code: 'not_found', message: 'Not found' }, { status: 404 });
  }
}

export function createRouterAbEd25519YaoExportModule(input: {
  readonly service: RouterAbEd25519YaoExportService;
  readonly authorization: RouterAbEd25519YaoExportAuthorizationAdapter;
}): RouterApiModule {
  return createRouterApiModule({
    id: 'router_ab_ed25519_yao_export',
    routeExtensions: [
      new RouterAbEd25519YaoExportRouteExtension(input.service, input.authorization),
    ],
  });
}
