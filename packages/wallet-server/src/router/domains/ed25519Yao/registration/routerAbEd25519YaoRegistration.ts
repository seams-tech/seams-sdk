import {
  ROUTER_AB_ED25519_YAO_REGISTRATION_ADMISSION_PATH_V1,
  ROUTER_AB_ED25519_YAO_REGISTRATION_EXECUTE_PATH_V1,
  parseRouterAbEd25519YaoRegistrationActivationAdmissionReceiptV1,
  parseRouterAbEd25519YaoRegistrationActivationExecuteRequestV1,
  parseRouterAbEd25519YaoRegistrationActivationResultV1,
  parseRouterAbEd25519YaoRegistrationAdmissionRequestV1,
  type RouterAbEd25519YaoActivationAdmissionReceiptV1,
  type RouterAbEd25519YaoActivationExecuteRequestV1,
  type RouterAbEd25519YaoActivationResultV1,
  type RouterAbEd25519YaoRegistrationAdmissionRequestV1,
  type RouterAbEd25519YaoBytes32V1,
} from '@shared/utils/routerAbEd25519Yao';
import {
  createRouterAbTraceContextV1,
  parseRouterAbTraceContextV1,
  ROUTER_AB_TRACE_ID_HEADER_V1,
  type RouterAbTraceContextV1,
} from '@shared/utils/routerAbTraceContext';
import { sameRouterAbMpcMaterialActivationRef } from '@shared/utils/routerAbNormalSigningIdentity';
import { json, readJson } from '../../../framework/http';
import { createRouterApiModule, type RouterApiModule } from '../../../framework/modules';
import { defineRoute, type RouteDefinition } from '../../../framework/routeDefinitions';
import type {
  RouterApiFetchRouteExtensionInput,
  RouterApiRouteExtension,
} from '../../../framework/routeExtensions';
import type { RouterAbEd25519YaoRegistrationExecuteAdmissionContextV1 } from '../routerAbEd25519YaoGatewayEnvelope';

type RouterAbEd25519YaoRegistrationAdmissionReceiptV1 =
  RouterAbEd25519YaoActivationAdmissionReceiptV1<'registration'>;
export type RouterAbEd25519YaoRegistrationExecuteRequestV1 =
  RouterAbEd25519YaoActivationExecuteRequestV1<'registration'>;
export type RouterAbEd25519YaoRegistrationResultV1 =
  RouterAbEd25519YaoActivationResultV1<'registration'>;

export type RouterAbEd25519YaoRegistrationFailureCode =
  | 'invalid_backend_response'
  | 'admission_failed'
  | 'admission_in_progress'
  | 'admission_uncertain'
  | 'unknown_registration'
  | 'binding_mismatch'
  | 'execution_in_progress'
  | 'execution_failed'
  | 'ceremony_expired';

export type RouterAbEd25519YaoRegistrationFailure = {
  ok: false;
  status: 400 | 401 | 403 | 404 | 408 | 409 | 429 | 500 | 502 | 503;
  code: RouterAbEd25519YaoRegistrationFailureCode;
  message: string;
};

export type RouterAbEd25519YaoRegistrationServiceResult<T> =
  | { ok: true; status: 200; value: T }
  | RouterAbEd25519YaoRegistrationFailure;

export type RouterAbEd25519YaoRegistrationBackendFailure = {
  ok: false;
  status: 400 | 408 | 409 | 429 | 500 | 502 | 503;
  code: string;
  message: string;
};

export type RouterAbEd25519YaoRegistrationBackendResult =
  | { ok: true; body: unknown }
  | RouterAbEd25519YaoRegistrationBackendFailure;

export interface RouterAbEd25519YaoRegistrationBackend {
  takeLastRouterServerTiming?(): string | null;
  admit(
    request: RouterAbEd25519YaoRegistrationAdmissionRequestV1,
    traceContext?: RouterAbTraceContextV1,
  ):
    | Promise<RouterAbEd25519YaoRegistrationBackendResult>
    | RouterAbEd25519YaoRegistrationBackendResult;
  execute(
    request: RouterAbEd25519YaoRegistrationExecuteRequestV1,
    admissionRequest: RouterAbEd25519YaoRegistrationExecuteAdmissionContextV1,
    traceContext?: RouterAbTraceContextV1,
  ):
    | Promise<RouterAbEd25519YaoRegistrationBackendResult>
    | RouterAbEd25519YaoRegistrationBackendResult;
}

export interface RouterAbEd25519YaoRegistrationService {
  admit(
    request: RouterAbEd25519YaoRegistrationAdmissionRequestV1,
    traceContext?: RouterAbTraceContextV1,
  ): Promise<
    RouterAbEd25519YaoRegistrationServiceResult<RouterAbEd25519YaoRegistrationAdmissionReceiptV1>
  >;
  execute(
    request: RouterAbEd25519YaoRegistrationExecuteRequestV1,
    traceContext?: RouterAbTraceContextV1,
  ): Promise<RouterAbEd25519YaoRegistrationServiceResult<RouterAbEd25519YaoRegistrationResultV1>>;
}

export type RouterAbEd25519YaoRegistrationAdmissionClaimV1 = {
  readonly kind: 'router_ab_ed25519_yao_registration_admission_claim_v1';
  readonly lifecycleId: string;
  readonly admissionFingerprint: string;
};

export type RouterAbEd25519YaoRegistrationAdmissionPreparationV1 =
  | {
      readonly kind: 'claimed';
      readonly claim: RouterAbEd25519YaoRegistrationAdmissionClaimV1;
    }
  | {
      readonly kind: 'completed';
      readonly value: RouterAbEd25519YaoRegistrationAdmissionReceiptV1;
    }
  | {
      readonly kind: 'failed';
      readonly failure: RouterAbEd25519YaoRegistrationFailure;
    };

export type RouterAbEd25519YaoRegistrationAdmissionCommitInputV1 = {
  readonly request: RouterAbEd25519YaoRegistrationAdmissionRequestV1;
  readonly claim: RouterAbEd25519YaoRegistrationAdmissionClaimV1;
  readonly outcome:
    | {
        readonly kind: 'backend_response';
        readonly result: RouterAbEd25519YaoRegistrationBackendResult;
      }
    | { readonly kind: 'backend_uncertain'; readonly message: string };
};

export interface RouterAbEd25519YaoRegistrationAdmissionBoundaryV1 {
  prepareAdmit(
    request: RouterAbEd25519YaoRegistrationAdmissionRequestV1,
  ): RouterAbEd25519YaoRegistrationAdmissionPreparationV1;
  commitAdmit(
    input: RouterAbEd25519YaoRegistrationAdmissionCommitInputV1,
  ): RouterAbEd25519YaoRegistrationServiceResult<RouterAbEd25519YaoRegistrationAdmissionReceiptV1>;
}

export type RouterAbEd25519YaoRegistrationExecuteClaimV1 = {
  readonly kind: 'router_ab_ed25519_yao_registration_execute_claim_v1';
  readonly lifecycleId: string;
  readonly sessionId: string;
  readonly executeFingerprint: string;
  readonly admissionRequest: RouterAbEd25519YaoRegistrationExecuteAdmissionContextV1;
};

export type RouterAbEd25519YaoRegistrationExecutePreparationV1 =
  | {
      readonly kind: 'claimed';
      readonly claim: RouterAbEd25519YaoRegistrationExecuteClaimV1;
    }
  | {
      readonly kind: 'completed';
      readonly value: RouterAbEd25519YaoRegistrationResultV1;
    }
  | {
      readonly kind: 'failed';
      readonly failure: RouterAbEd25519YaoRegistrationFailure;
    };

export type RouterAbEd25519YaoRegistrationExecuteCommitInputV1 = {
  readonly request: RouterAbEd25519YaoRegistrationExecuteRequestV1;
  readonly claim: RouterAbEd25519YaoRegistrationExecuteClaimV1;
  readonly outcome:
    | {
        readonly kind: 'backend_response';
        readonly result: RouterAbEd25519YaoRegistrationBackendResult;
      }
    | { readonly kind: 'backend_uncertain'; readonly message: string };
};

export interface RouterAbEd25519YaoRegistrationExecuteBoundaryV1 {
  prepareExecute(
    request: RouterAbEd25519YaoRegistrationExecuteRequestV1,
  ): RouterAbEd25519YaoRegistrationExecutePreparationV1;
  commitExecute(
    input: RouterAbEd25519YaoRegistrationExecuteCommitInputV1,
  ): RouterAbEd25519YaoRegistrationServiceResult<RouterAbEd25519YaoRegistrationResultV1>;
}

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

export type RouterAbEd25519YaoRegistrationAuthorizationInput =
  | {
      kind: 'admit';
      request: Request;
      body: RouterAbEd25519YaoRegistrationAdmissionRequestV1;
    }
  | {
      kind: 'execute';
      request: Request;
      body: RouterAbEd25519YaoRegistrationExecuteRequestV1;
    };

export type RouterAbEd25519YaoRegistrationAuthorizationResult =
  | { ok: true }
  | {
      ok: false;
      status: 401 | 403 | 409 | 429 | 503;
      code: string;
      message: string;
    };

export interface RouterAbEd25519YaoRegistrationAuthorizationAdapter {
  authorize(
    input: RouterAbEd25519YaoRegistrationAuthorizationInput,
  ):
    | Promise<RouterAbEd25519YaoRegistrationAuthorizationResult>
    | RouterAbEd25519YaoRegistrationAuthorizationResult;
}

type RegistrationAdmittedState = {
  kind: 'admitted';
  admissionRequest: RouterAbEd25519YaoRegistrationAdmissionRequestV1;
  admissionReceipt: RouterAbEd25519YaoRegistrationAdmissionReceiptV1;
};

type RegistrationExecutingState = {
  kind: 'executing';
  admissionRequest: RouterAbEd25519YaoRegistrationAdmissionRequestV1;
  admissionReceipt: RouterAbEd25519YaoRegistrationAdmissionReceiptV1;
  executeFingerprint: string;
};

type RegistrationActivatedState = {
  kind: 'activated';
  admissionRequest: RouterAbEd25519YaoRegistrationAdmissionRequestV1;
  admissionReceipt: RouterAbEd25519YaoRegistrationAdmissionReceiptV1;
  executeFingerprint: string;
  result: RouterAbEd25519YaoRegistrationResultV1;
  activationConsumerBinding: string | null;
};

type RegistrationFailedState = {
  kind: 'failed';
  admissionRequest: RouterAbEd25519YaoRegistrationAdmissionRequestV1;
  admissionReceipt: RouterAbEd25519YaoRegistrationAdmissionReceiptV1;
  executeFingerprint: string;
  failure: RouterAbEd25519YaoRegistrationFailure;
};

type RegistrationLifecycleState =
  | RegistrationAdmittedState
  | RegistrationExecutingState
  | RegistrationActivatedState
  | RegistrationFailedState;

export class InMemoryRouterAbEd25519YaoRegistrationStateV1 {
  readonly states = new Map<string, RegistrationLifecycleState>();
  readonly lifecycleSessions = new Map<string, string>();
  readonly admissionClaims = new Map<string, RouterAbEd25519YaoRegistrationAdmissionClaimV1>();
}

export type RouterAbEd25519YaoActivationReferenceV1 = {
  lifecycleId: string;
  sessionId: RouterAbEd25519YaoBytes32V1;
};

export type RouterAbEd25519YaoActivationConsumptionRequestV1 = {
  reference: RouterAbEd25519YaoActivationReferenceV1;
  consumerBinding: string;
};

export type RouterAbEd25519YaoActivatedRegistrationV1 = {
  admissionRequest: RouterAbEd25519YaoRegistrationAdmissionRequestV1;
  admissionReceipt: RouterAbEd25519YaoRegistrationAdmissionReceiptV1;
  result: RouterAbEd25519YaoRegistrationResultV1;
};

export type RouterAbEd25519YaoActivationConsumptionResultV1 =
  | { ok: true; activation: RouterAbEd25519YaoActivatedRegistrationV1 }
  | {
      ok: false;
      code:
        | 'unknown_registration'
        | 'registration_not_activated'
        | 'activation_reference_mismatch'
        | 'activation_consumed';
      message: string;
    };

export interface RouterAbEd25519YaoActivationConsumerV1 {
  consumeActivated(
    request: RouterAbEd25519YaoActivationConsumptionRequestV1,
  ):
    | Promise<RouterAbEd25519YaoActivationConsumptionResultV1>
    | RouterAbEd25519YaoActivationConsumptionResultV1;
}

function registrationSessionKey(receipt: RouterAbEd25519YaoRegistrationAdmissionReceiptV1): string {
  return bytesToHex(receipt.binding.session_id);
}

function executeSessionKey(request: RouterAbEd25519YaoRegistrationExecuteRequestV1): string {
  return bytesToHex(request.binding.session_id);
}

function bytesToHex(bytes: readonly number[]): string {
  let encoded = '';
  for (const byte of bytes) encoded += byte.toString(16).padStart(2, '0');
  return encoded;
}

function canonicalWireFingerprint(value: unknown): string {
  return JSON.stringify(value);
}

function registrationScopeMatchesReceipt(
  request: RouterAbEd25519YaoRegistrationAdmissionRequestV1,
  receipt: RouterAbEd25519YaoRegistrationAdmissionReceiptV1,
): boolean {
  const scope = request.scope;
  const lifecycle = receipt.binding.lifecycle;
  return (
    scope.lifecycle_id === lifecycle.lifecycle_id &&
    scope.root_share_epoch === lifecycle.root_share_epoch &&
    scope.account_id === lifecycle.account_id &&
    scope.threshold_session_id === lifecycle.session_id &&
    scope.signer_set_id === lifecycle.signer_set_id &&
    scope.signing_worker_id === lifecycle.selected_server_id &&
    sameRouterAbMpcMaterialActivationRef(
      scope.material_activation,
      receipt.binding.material_activation,
    )
  );
}

export function routerAbEd25519YaoExecutionMatchesAdmissionV1(
  request: RouterAbEd25519YaoRegistrationExecuteRequestV1,
  receipt: RouterAbEd25519YaoRegistrationAdmissionReceiptV1,
): boolean {
  return canonicalWireFingerprint(request.binding) === canonicalWireFingerprint(receipt.binding);
}

export function routerAbEd25519YaoResultMatchesExecutionV1(
  request: RouterAbEd25519YaoRegistrationExecuteRequestV1,
  result: RouterAbEd25519YaoRegistrationResultV1,
): boolean {
  return canonicalWireFingerprint(request.binding) === canonicalWireFingerprint(result.binding);
}

function backendFailure(
  result: RouterAbEd25519YaoRegistrationBackendFailure,
  code: 'admission_failed' | 'execution_failed',
): RouterAbEd25519YaoRegistrationFailure {
  if (result.code === 'ceremony_expired') {
    return {
      ok: false,
      status: 409,
      code: 'ceremony_expired',
      message: result.message,
    };
  }
  return {
    ok: false,
    status: result.status,
    code,
    message: `${result.code}: ${result.message}`,
  };
}

function invalidBackendResponse(message: string): RouterAbEd25519YaoRegistrationFailure {
  return {
    ok: false,
    status: 502,
    code: 'invalid_backend_response',
    message,
  };
}

function uncertainExecutionFailure(error: unknown): RouterAbEd25519YaoRegistrationFailure {
  return {
    ok: false,
    status: 503,
    code: 'execution_failed',
    message: error instanceof Error ? error.message : String(error),
  };
}

function assertNever(value: never): never {
  throw new Error(`Unhandled Ed25519 Yao registration state: ${String(value)}`);
}

const ROUTER_AB_ED25519_YAO_REGISTRATION_ROUTES = Object.freeze([
  defineRoute({
    id: 'router_ab_ed25519_yao_registration_admit',
    surface: 'relay',
    method: 'POST',
    path: ROUTER_AB_ED25519_YAO_REGISTRATION_ADMISSION_PATH_V1,
    auth: {
      plane: 'public',
      proof: 'intent_grant',
      rationale:
        'The Ed25519 Yao admission module requires its explicit registration authorization adapter.',
    },
    metering: { kind: 'none' },
    requiredServices: [],
    summary: 'Admit an Ed25519 Yao registration ceremony',
  }),
  defineRoute({
    id: 'router_ab_ed25519_yao_registration_execute',
    surface: 'relay',
    method: 'POST',
    path: ROUTER_AB_ED25519_YAO_REGISTRATION_EXECUTE_PATH_V1,
    auth: {
      plane: 'public',
      proof: 'threshold_protocol_state',
      rationale:
        'The Ed25519 Yao execution module requires its explicit registration authorization adapter.',
    },
    metering: { kind: 'none' },
    requiredServices: [],
    summary: 'Execute an admitted Ed25519 Yao registration ceremony',
  }),
]);

function routeFailureResponse(
  result:
    | RouterAbEd25519YaoRegistrationFailure
    | Extract<RouterAbEd25519YaoRegistrationAuthorizationResult, { ok: false }>,
): Response {
  return json({ ok: false, code: result.code, message: result.message }, { status: result.status });
}

class RouterAbEd25519YaoRegistrationRouteExtension implements RouterApiRouteExtension {
  readonly kind = 'fetch_route_extension' as const;
  readonly id = 'router_ab_ed25519_yao_registration';
  readonly routes = ROUTER_AB_ED25519_YAO_REGISTRATION_ROUTES;

  constructor(
    private readonly service: RouterAbEd25519YaoRegistrationService,
    private readonly authorization: RouterAbEd25519YaoRegistrationAuthorizationAdapter,
  ) {}

  async handleFetchRoute(input: RouterApiFetchRouteExtensionInput): Promise<Response> {
    if (input.method !== 'POST') {
      return json(
        { ok: false, code: 'method_not_allowed', message: 'Method not allowed' },
        { status: 405 },
      );
    }
    const rawBody = await readJson(input.request);
    switch (input.pathname) {
      case ROUTER_AB_ED25519_YAO_REGISTRATION_ADMISSION_PATH_V1:
        return await this.handleAdmission(input.request, rawBody);
      case ROUTER_AB_ED25519_YAO_REGISTRATION_EXECUTE_PATH_V1:
        return await this.handleExecution(input.request, rawBody);
      default:
        return json({ ok: false, code: 'not_found', message: 'Not found' }, { status: 404 });
    }
  }

  private async handleAdmission(request: Request, rawBody: unknown): Promise<Response> {
    const traceContext = resolveTraceContext(request);
    if (!traceContext.ok) {
      return json(
        { ok: false, code: 'invalid_trace_id', message: traceContext.message },
        { status: 400 },
      );
    }
    const parsed = parseRouterAbEd25519YaoRegistrationAdmissionRequestV1(rawBody);
    if (!parsed.ok) {
      return json({ ok: false, code: parsed.code, message: parsed.message }, { status: 400 });
    }
    const authorization = await this.authorization.authorize({
      kind: 'admit',
      request,
      body: parsed.value,
    });
    if (!authorization.ok) return routeFailureResponse(authorization);
    const result = await this.service.admit(parsed.value, traceContext.value);
    if (!result.ok) return routeFailureResponse(result);
    return json(result.value, { status: result.status });
  }

  private async handleExecution(request: Request, rawBody: unknown): Promise<Response> {
    const traceContext = resolveTraceContext(request);
    if (!traceContext.ok) {
      return json(
        { ok: false, code: 'invalid_trace_id', message: traceContext.message },
        { status: 400 },
      );
    }
    const parsed = parseRouterAbEd25519YaoRegistrationActivationExecuteRequestV1(rawBody);
    if (!parsed.ok) {
      return json({ ok: false, code: parsed.code, message: parsed.message }, { status: 400 });
    }
    const authorization = await this.authorization.authorize({
      kind: 'execute',
      request,
      body: parsed.value,
    });
    if (!authorization.ok) return routeFailureResponse(authorization);
    const result = await this.service.execute(parsed.value, traceContext.value);
    if (!result.ok) return routeFailureResponse(result);
    return json(result.value, { status: result.status });
  }
}

export function createRouterAbEd25519YaoRegistrationModule(input: {
  service: RouterAbEd25519YaoRegistrationService;
  authorization: RouterAbEd25519YaoRegistrationAuthorizationAdapter;
}): RouterApiModule {
  return createRouterApiModule({
    id: 'router_ab_ed25519_yao_registration',
    routeExtensions: [
      new RouterAbEd25519YaoRegistrationRouteExtension(input.service, input.authorization),
    ],
  });
}

export class InMemoryRouterAbEd25519YaoRegistrationService
  implements
    RouterAbEd25519YaoRegistrationService,
    RouterAbEd25519YaoRegistrationAdmissionBoundaryV1,
    RouterAbEd25519YaoRegistrationExecuteBoundaryV1,
    RouterAbEd25519YaoActivationConsumerV1
{
  private readonly states: Map<string, RegistrationLifecycleState>;
  private readonly lifecycleSessions: Map<string, string>;
  private readonly admissionClaims: Map<string, RouterAbEd25519YaoRegistrationAdmissionClaimV1>;

  constructor(
    private readonly backend: RouterAbEd25519YaoRegistrationBackend,
    state: InMemoryRouterAbEd25519YaoRegistrationStateV1 = new InMemoryRouterAbEd25519YaoRegistrationStateV1(),
  ) {
    this.states = state.states;
    this.lifecycleSessions = state.lifecycleSessions;
    this.admissionClaims = state.admissionClaims;
  }

  async admit(
    request: RouterAbEd25519YaoRegistrationAdmissionRequestV1,
    traceContext?: RouterAbTraceContextV1,
  ): Promise<
    RouterAbEd25519YaoRegistrationServiceResult<RouterAbEd25519YaoRegistrationAdmissionReceiptV1>
  > {
    const preparation = this.prepareAdmit(request);
    switch (preparation.kind) {
      case 'completed':
        return { ok: true, status: 200, value: preparation.value };
      case 'failed':
        return preparation.failure;
      case 'claimed': {
        let outcome: RouterAbEd25519YaoRegistrationAdmissionCommitInputV1['outcome'];
        try {
          outcome = {
            kind: 'backend_response',
            result: await this.backend.admit(request, traceContext),
          };
        } catch (error: unknown) {
          outcome = {
            kind: 'backend_uncertain',
            message: error instanceof Error ? error.message : String(error),
          };
        }
        return this.commitAdmit({ request, claim: preparation.claim, outcome });
      }
    }
  }

  prepareAdmit(
    request: RouterAbEd25519YaoRegistrationAdmissionRequestV1,
  ): RouterAbEd25519YaoRegistrationAdmissionPreparationV1 {
    const lifecycleId = request.scope.lifecycle_id;
    const admissionFingerprint = canonicalWireFingerprint(request);
    const existingSessionKey = this.lifecycleSessions.get(lifecycleId);
    if (existingSessionKey !== undefined) {
      const existingState = this.states.get(existingSessionKey);
      if (
        existingState !== undefined &&
        canonicalWireFingerprint(existingState.admissionRequest) === admissionFingerprint
      ) {
        return { kind: 'completed', value: existingState.admissionReceipt };
      }
      return {
        kind: 'failed',
        failure: {
          ok: false,
          status: 409,
          code: 'admission_failed',
          message: 'registration lifecycle already has an admitted Yao session',
        },
      };
    }
    const existingClaim = this.admissionClaims.get(lifecycleId);
    if (existingClaim !== undefined) {
      return {
        kind: 'failed',
        failure: {
          ok: false,
          status: 409,
          code:
            existingClaim.admissionFingerprint === admissionFingerprint
              ? 'admission_in_progress'
              : 'admission_failed',
          message:
            existingClaim.admissionFingerprint === admissionFingerprint
              ? 'registration admission is already in progress'
              : 'registration lifecycle has a conflicting admission claim',
        },
      };
    }
    const claim: RouterAbEd25519YaoRegistrationAdmissionClaimV1 = {
      kind: 'router_ab_ed25519_yao_registration_admission_claim_v1',
      lifecycleId,
      admissionFingerprint,
    };
    this.admissionClaims.set(lifecycleId, claim);
    return { kind: 'claimed', claim };
  }

  commitAdmit(
    input: RouterAbEd25519YaoRegistrationAdmissionCommitInputV1,
  ): RouterAbEd25519YaoRegistrationServiceResult<RouterAbEd25519YaoRegistrationAdmissionReceiptV1> {
    const currentClaim = this.admissionClaims.get(input.claim.lifecycleId);
    if (
      currentClaim === undefined ||
      currentClaim.admissionFingerprint !== input.claim.admissionFingerprint ||
      canonicalWireFingerprint(input.request) !== input.claim.admissionFingerprint
    ) {
      return {
        ok: false,
        status: 409,
        code: 'admission_failed',
        message: 'registration admission claim is no longer current',
      };
    }
    if (input.outcome.kind === 'backend_uncertain') {
      return {
        ok: false,
        status: 503,
        code: 'admission_uncertain',
        message: input.outcome.message,
      };
    }
    const backendResult = input.outcome.result;
    if (!backendResult.ok) {
      this.admissionClaims.delete(input.claim.lifecycleId);
      return backendFailure(backendResult, 'admission_failed');
    }
    const parsed = parseRouterAbEd25519YaoRegistrationActivationAdmissionReceiptV1(
      backendResult.body,
    );
    if (!parsed.ok) {
      this.admissionClaims.delete(input.claim.lifecycleId);
      return invalidBackendResponse(parsed.message);
    }
    if (!registrationScopeMatchesReceipt(input.request, parsed.value)) {
      this.admissionClaims.delete(input.claim.lifecycleId);
      return invalidBackendResponse('registration admission receipt scope does not match request');
    }
    const key = registrationSessionKey(parsed.value);
    if (this.states.has(key)) {
      return {
        ok: false,
        status: 409,
        code: 'admission_failed',
        message: 'registration backend reused an active session identifier',
      };
    }
    this.states.set(key, {
      kind: 'admitted',
      admissionRequest: input.request,
      admissionReceipt: parsed.value,
    });
    this.lifecycleSessions.set(input.claim.lifecycleId, key);
    this.admissionClaims.delete(input.claim.lifecycleId);
    return { ok: true, status: 200, value: parsed.value };
  }

  async execute(
    request: RouterAbEd25519YaoRegistrationExecuteRequestV1,
    traceContext?: RouterAbTraceContextV1,
  ): Promise<RouterAbEd25519YaoRegistrationServiceResult<RouterAbEd25519YaoRegistrationResultV1>> {
    const preparation = this.prepareExecute(request);
    switch (preparation.kind) {
      case 'completed':
        return { ok: true, status: 200, value: preparation.value };
      case 'failed':
        return preparation.failure;
      case 'claimed': {
        let outcome: RouterAbEd25519YaoRegistrationExecuteCommitInputV1['outcome'];
        try {
          outcome = {
            kind: 'backend_response',
            result: await this.backend.execute(
              request,
              preparation.claim.admissionRequest,
              traceContext,
            ),
          };
        } catch (error: unknown) {
          outcome = {
            kind: 'backend_uncertain',
            message: error instanceof Error ? error.message : String(error),
          };
        }
        return this.commitExecute({ request, claim: preparation.claim, outcome });
      }
    }
  }

  prepareExecute(
    request: RouterAbEd25519YaoRegistrationExecuteRequestV1,
  ): RouterAbEd25519YaoRegistrationExecutePreparationV1 {
    const admissionLifecycleId = request.binding.lifecycle.lifecycle_id;
    if (this.admissionClaims.has(admissionLifecycleId)) {
      return {
        kind: 'failed',
        failure: {
          ok: false,
          status: 409,
          code: 'admission_in_progress',
          message: 'registration execution requires a completed admission',
        },
      };
    }
    const key = executeSessionKey(request);
    const state = this.states.get(key);
    if (!state) {
      return {
        kind: 'failed',
        failure: {
          ok: false,
          status: 404,
          code: 'unknown_registration',
          message: 'registration admission was not found',
        },
      };
    }
    if (!routerAbEd25519YaoExecutionMatchesAdmissionV1(request, state.admissionReceipt)) {
      return {
        kind: 'failed',
        failure: {
          ok: false,
          status: 409,
          code: 'binding_mismatch',
          message: 'registration execution does not match the admitted binding',
        },
      };
    }

    const executeFingerprint = canonicalWireFingerprint(request);
    switch (state.kind) {
      case 'activated':
        if (state.executeFingerprint === executeFingerprint) {
          return { kind: 'completed', value: state.result };
        }
        return {
          kind: 'failed',
          failure: {
            ok: false,
            status: 409,
            code: 'binding_mismatch',
            message: 'activated registration rejects a different execution payload',
          },
        };
      case 'executing':
        return {
          kind: 'failed',
          failure: {
            ok: false,
            status: 409,
            code: 'execution_in_progress',
            message: 'registration execution is already in progress',
          },
        };
      case 'failed':
        return { kind: 'failed', failure: state.failure };
      case 'admitted': {
        this.states.set(key, {
          kind: 'executing',
          admissionRequest: state.admissionRequest,
          admissionReceipt: state.admissionReceipt,
          executeFingerprint,
        });
        return {
          kind: 'claimed',
          claim: {
            kind: 'router_ab_ed25519_yao_registration_execute_claim_v1',
            lifecycleId: request.binding.lifecycle.lifecycle_id,
            sessionId: key,
            executeFingerprint,
            admissionRequest: state.admissionRequest,
          },
        };
      }
      default:
        return assertNever(state);
    }
  }

  commitExecute(
    input: RouterAbEd25519YaoRegistrationExecuteCommitInputV1,
  ): RouterAbEd25519YaoRegistrationServiceResult<RouterAbEd25519YaoRegistrationResultV1> {
    const key = input.claim.sessionId;
    const state = this.states.get(key);
    if (!state) {
      return {
        ok: false,
        status: 404,
        code: 'unknown_registration',
        message: 'registration execution claim was not found',
      };
    }
    if (
      state.kind !== 'executing' ||
      state.executeFingerprint !== input.claim.executeFingerprint ||
      !routerAbEd25519YaoExecutionMatchesAdmissionV1(input.request, state.admissionReceipt)
    ) {
      return {
        ok: false,
        status: 409,
        code: 'execution_in_progress',
        message: 'registration execution claim is no longer current',
      };
    }
    if (input.outcome.kind === 'backend_uncertain') {
      const failure = uncertainExecutionFailure(new Error(input.outcome.message));
      this.storeFailure(state, key, failure);
      return failure;
    }
    const backendResult = input.outcome.result;
    if (!backendResult.ok) {
      const failure = backendFailure(backendResult, 'execution_failed');
      this.storeFailure(state, key, failure);
      return failure;
    }
    const parsed = parseRouterAbEd25519YaoRegistrationActivationResultV1(backendResult.body);
    if (!parsed.ok) {
      const failure = invalidBackendResponse(parsed.message);
      this.storeFailure(state, key, failure);
      return failure;
    }
    if (!routerAbEd25519YaoResultMatchesExecutionV1(input.request, parsed.value)) {
      const failure = invalidBackendResponse(
        'registration backend result binding does not match execution',
      );
      this.storeFailure(state, key, failure);
      return failure;
    }

    this.states.set(key, {
      kind: 'activated',
      admissionRequest: state.admissionRequest,
      admissionReceipt: state.admissionReceipt,
      executeFingerprint: input.claim.executeFingerprint,
      result: parsed.value,
      activationConsumerBinding: null,
    });
    return { ok: true, status: 200, value: parsed.value };
  }

  consumeActivated(
    request: RouterAbEd25519YaoActivationConsumptionRequestV1,
  ): RouterAbEd25519YaoActivationConsumptionResultV1 {
    if (
      !request ||
      typeof request.consumerBinding !== 'string' ||
      !request.reference ||
      typeof request.reference.lifecycleId !== 'string'
    ) {
      return {
        ok: false,
        code: 'activation_reference_mismatch',
        message: 'Yao activation consumption request is invalid',
      };
    }
    const reference = request.reference;
    const consumerBinding = request.consumerBinding.trim();
    if (!consumerBinding) {
      return {
        ok: false,
        code: 'activation_reference_mismatch',
        message: 'Yao activation consumption requires a finalize-consumer binding',
      };
    }
    const lifecycleId = reference.lifecycleId;
    const key = this.lifecycleSessions.get(lifecycleId);
    if (!key) {
      return {
        ok: false,
        code: 'unknown_registration',
        message: 'registration lifecycle was not found',
      };
    }
    const state = this.states.get(key);
    if (!state || state.kind !== 'activated') {
      return {
        ok: false,
        code: 'registration_not_activated',
        message: 'registration lifecycle has no verified Yao activation',
      };
    }
    const expectedSession = bytesToHex(state.result.binding.session_id);
    const actualSession = bytesToHex(reference.sessionId);
    if (
      state.admissionRequest.scope.lifecycle_id !== lifecycleId ||
      expectedSession !== actualSession
    ) {
      return {
        ok: false,
        code: 'activation_reference_mismatch',
        message: 'Yao activation reference does not match the admitted registration',
      };
    }
    if (
      state.activationConsumerBinding !== null &&
      state.activationConsumerBinding !== consumerBinding
    ) {
      return {
        ok: false,
        code: 'activation_consumed',
        message: 'Yao activation was already consumed by wallet finalization',
      };
    }
    if (state.activationConsumerBinding === null) {
      this.states.set(key, {
        kind: 'activated',
        admissionRequest: state.admissionRequest,
        admissionReceipt: state.admissionReceipt,
        executeFingerprint: state.executeFingerprint,
        result: state.result,
        activationConsumerBinding: consumerBinding,
      });
    }
    return {
      ok: true,
      activation: {
        admissionRequest: state.admissionRequest,
        admissionReceipt: state.admissionReceipt,
        result: state.result,
      },
    };
  }

  private storeFailure(
    state: RegistrationExecutingState,
    key: string,
    failure: RouterAbEd25519YaoRegistrationFailure,
  ): void {
    this.states.set(key, {
      kind: 'failed',
      admissionRequest: state.admissionRequest,
      admissionReceipt: state.admissionReceipt,
      executeFingerprint: state.executeFingerprint,
      failure,
    });
  }
}
