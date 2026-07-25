import {
  parseRouterAbEd25519YaoRecoveryActivationExecuteRequestV1,
  parseRouterAbEd25519YaoRecoveryAdmissionRequestV1,
  ROUTER_AB_ED25519_YAO_RECOVERY_ADMISSION_PATH_V1,
  ROUTER_AB_ED25519_YAO_RECOVERY_EXECUTE_PATH_V1,
  type RouterAbEd25519YaoActivationAdmissionReceiptV1,
  type RouterAbEd25519YaoActivationExecuteRequestV1,
  type RouterAbEd25519YaoActivationResultV1,
  type RouterAbEd25519YaoRecoveryAdmissionRequestV1,
} from '@shared/utils/routerAbEd25519Yao';
import {
  createRouterAbTraceContextV1,
  parseRouterAbTraceContextV1,
  ROUTER_AB_TRACE_ID_HEADER_V1,
  type RouterAbTraceContextV1,
} from '@shared/utils/routerAbTraceContext';
import { json, readJson } from './cloudflare/http';
import {
  InMemoryRouterAbEd25519YaoRecoveryService,
  type RouterAbEd25519YaoRecoveryAdmissionClaimV1,
  type RouterAbEd25519YaoRecoveryAuthorizationAdapter,
  type RouterAbEd25519YaoRecoveryAuthorizationResult,
  type RouterAbEd25519YaoRecoveryBackend,
  type RouterAbEd25519YaoRecoveryBackendResult,
  type RouterAbEd25519YaoRecoveryExecuteClaimV1,
  type RouterAbEd25519YaoRecoveryFailure,
  type RouterAbEd25519YaoRecoveryServiceResult,
} from './routerAbEd25519YaoRecovery';
import {
  runRouterAbEd25519YaoRegistrationTwoPhaseV1,
  type RouterAbEd25519YaoRegistrationTwoPhaseBackendResultV1,
  type RouterAbEd25519YaoRegistrationTwoPhaseCompletionV1,
  type RouterAbEd25519YaoRegistrationTwoPhasePrepareResultV1,
  type RouterAbEd25519YaoRegistrationTwoPhaseRunResultV1,
} from './routerAbEd25519YaoRegistrationTwoPhaseRunner';
import type {
  RouterAbEd25519YaoProductRegistrationPartitionedStateCommitResultV1,
  RouterAbEd25519YaoProductRegistrationPartitionedStateStoreV1,
} from './routerAbEd25519YaoProductRegistrationPartitionedStateStore';
import type { RouterAbEd25519YaoProductRegistrationStateV1 } from './routerAbEd25519YaoProductRegistration';

type RecoveryAdmissionReceipt = RouterAbEd25519YaoActivationAdmissionReceiptV1<'recovery'>;
type RecoveryExecuteRequest = RouterAbEd25519YaoActivationExecuteRequestV1<'recovery'>;
type RecoveryExecutionResult = RouterAbEd25519YaoActivationResultV1<'recovery'>;

type AuthorizationFailure = Extract<
  RouterAbEd25519YaoRecoveryAuthorizationResult,
  { readonly ok: false }
>;

type RecoveryRequest =
  | {
      readonly kind: 'admit';
      readonly value: RouterAbEd25519YaoRecoveryAdmissionRequestV1;
    }
  | {
      readonly kind: 'execute';
      readonly value: RecoveryExecuteRequest;
    };

type RecoveryResponse =
  | RouterAbEd25519YaoRecoveryServiceResult<RecoveryAdmissionReceipt>
  | RouterAbEd25519YaoRecoveryServiceResult<RecoveryExecutionResult>
  | AuthorizationFailure;

type TraceResolution =
  | { readonly ok: true; readonly value: RouterAbTraceContextV1 }
  | { readonly ok: false; readonly message: string };

export type RouterAbEd25519YaoRecoveryRequestScopedCloudflareInputV1 = {
  readonly request: Request;
  readonly store: RouterAbEd25519YaoProductRegistrationPartitionedStateStoreV1;
  readonly backend: RouterAbEd25519YaoRecoveryBackend;
  readonly authorization: RouterAbEd25519YaoRecoveryAuthorizationAdapter;
};

type RecoveryRequestScopedContext = {
  readonly input: RouterAbEd25519YaoRecoveryRequestScopedCloudflareInputV1;
  readonly trace: RouterAbTraceContextV1;
};

class RecoveryAdmissionRequestRun {
  constructor(
    private readonly context: RecoveryRequestScopedContext,
    private readonly request: RouterAbEd25519YaoRecoveryAdmissionRequestV1,
  ) {}

  async prepare(
    state: RouterAbEd25519YaoProductRegistrationStateV1,
  ): Promise<
    RouterAbEd25519YaoRegistrationTwoPhasePrepareResultV1<
      RouterAbEd25519YaoRecoveryAdmissionClaimV1,
      RecoveryResponse,
      AuthorizationFailure | RouterAbEd25519YaoRecoveryFailure
    >
  > {
    const authorized = await this.context.input.authorization.authorize({
      kind: 'admit',
      request: this.context.input.request,
      body: this.request,
    });
    if (!authorized.ok) return { kind: 'rejected', value: authorized };
    const service = this.service(state);
    const prepared = service.prepareAdmitRecovery(this.request);
    switch (prepared.kind) {
      case 'claimed':
        return { kind: 'claimed', state, claim: prepared.claim };
      case 'completed':
        return {
          kind: 'completed',
          value: { ok: true, status: 200, value: prepared.value },
        };
      case 'failed':
        return { kind: 'rejected', value: prepared.failure };
    }
  }

  async backend(
    _claim: RouterAbEd25519YaoRecoveryAdmissionClaimV1,
  ): Promise<
    RouterAbEd25519YaoRegistrationTwoPhaseBackendResultV1<RouterAbEd25519YaoRecoveryBackendResult>
  > {
    try {
      return {
        kind: 'response',
        value: await this.context.input.backend.admitRecovery(this.request, this.context.trace),
      };
    } catch (error: unknown) {
      return {
        kind: 'uncertain',
        message: error instanceof Error ? error.message : String(error),
      };
    }
  }

  async complete(
    state: RouterAbEd25519YaoProductRegistrationStateV1,
    claim: RouterAbEd25519YaoRecoveryAdmissionClaimV1,
    backend: RouterAbEd25519YaoRecoveryBackendResult,
  ): Promise<RouterAbEd25519YaoRegistrationTwoPhaseCompletionV1<RecoveryResponse>> {
    const value = this.service(state).commitAdmitRecovery({
      request: this.request,
      claim,
      outcome: { kind: 'backend_response', result: backend },
    });
    return { state, value };
  }

  private service(
    state: RouterAbEd25519YaoProductRegistrationStateV1,
  ): InMemoryRouterAbEd25519YaoRecoveryService {
    return new InMemoryRouterAbEd25519YaoRecoveryService(
      this.context.input.backend,
      state.recovery,
    );
  }
}

class RecoveryExecutionRequestRun {
  constructor(
    private readonly context: RecoveryRequestScopedContext,
    private readonly request: RecoveryExecuteRequest,
  ) {}

  async prepare(
    state: RouterAbEd25519YaoProductRegistrationStateV1,
  ): Promise<
    RouterAbEd25519YaoRegistrationTwoPhasePrepareResultV1<
      RouterAbEd25519YaoRecoveryExecuteClaimV1,
      RecoveryResponse,
      AuthorizationFailure | RouterAbEd25519YaoRecoveryFailure
    >
  > {
    const authorized = await this.context.input.authorization.authorize({
      kind: 'execute',
      request: this.context.input.request,
      body: this.request,
    });
    if (!authorized.ok) return { kind: 'rejected', value: authorized };
    const service = this.service(state);
    const prepared = service.prepareExecuteRecovery(this.request);
    switch (prepared.kind) {
      case 'claimed':
        return { kind: 'claimed', state, claim: prepared.claim };
      case 'completed':
        return {
          kind: 'completed',
          value: { ok: true, status: 200, value: prepared.value },
        };
      case 'failed':
        return { kind: 'rejected', value: prepared.failure };
    }
  }

  async backend(
    _claim: RouterAbEd25519YaoRecoveryExecuteClaimV1,
  ): Promise<
    RouterAbEd25519YaoRegistrationTwoPhaseBackendResultV1<RouterAbEd25519YaoRecoveryBackendResult>
  > {
    try {
      return {
        kind: 'response',
        value: await this.context.input.backend.executeRecovery(this.request, this.context.trace),
      };
    } catch (error: unknown) {
      return {
        kind: 'uncertain',
        message: error instanceof Error ? error.message : String(error),
      };
    }
  }

  async complete(
    state: RouterAbEd25519YaoProductRegistrationStateV1,
    claim: RouterAbEd25519YaoRecoveryExecuteClaimV1,
    backend: RouterAbEd25519YaoRecoveryBackendResult,
  ): Promise<RouterAbEd25519YaoRegistrationTwoPhaseCompletionV1<RecoveryResponse>> {
    const value = this.service(state).commitExecuteRecovery({
      request: this.request,
      claim,
      outcome: { kind: 'backend_response', result: backend },
    });
    return { state, value };
  }

  private service(
    state: RouterAbEd25519YaoProductRegistrationStateV1,
  ): InMemoryRouterAbEd25519YaoRecoveryService {
    return new InMemoryRouterAbEd25519YaoRecoveryService(
      this.context.input.backend,
      state.recovery,
    );
  }
}

export async function handleRouterAbEd25519YaoRecoveryRequestScopedCloudflareV1(
  input: RouterAbEd25519YaoRecoveryRequestScopedCloudflareInputV1,
): Promise<Response> {
  if (input.request.method !== 'POST') {
    return json(
      { ok: false, code: 'method_not_allowed', message: 'Method not allowed' },
      { status: 405 },
    );
  }
  const trace = resolveTrace(input.request);
  if (!trace.ok) {
    return json({ ok: false, code: 'invalid_trace_id', message: trace.message }, { status: 400 });
  }
  const parsed = await parseRecoveryRequest(input.request);
  if ('response' in parsed) return parsed.response;
  const context: RecoveryRequestScopedContext = { input, trace: trace.value };
  try {
    const result =
      parsed.kind === 'admit'
        ? await runAdmissionRequest(context, parsed.value)
        : await runExecutionRequest(context, parsed.value);
    return recoveryResponse(result);
  } catch (error: unknown) {
    return json(
      {
        ok: false,
        code: 'router_state_unavailable',
        message: error instanceof Error ? error.message : String(error),
      },
      { status: 503 },
    );
  }
}

async function runAdmissionRequest(
  context: RecoveryRequestScopedContext,
  request: RouterAbEd25519YaoRecoveryAdmissionRequestV1,
): Promise<RecoveryResponse> {
  const run = new RecoveryAdmissionRequestRun(context, request);
  const result = await runRouterAbEd25519YaoRegistrationTwoPhaseV1<
    RouterAbEd25519YaoRecoveryAdmissionClaimV1,
    RouterAbEd25519YaoRecoveryBackendResult,
    RecoveryResponse,
    AuthorizationFailure | RouterAbEd25519YaoRecoveryFailure
  >({
    lifecycleId: request.scope.lifecycle_id,
    store: context.input.store,
    prepare: run.prepare.bind(run),
    backend: run.backend.bind(run),
    complete: run.complete.bind(run),
  });
  return mapAdmissionResult(result);
}

async function runExecutionRequest(
  context: RecoveryRequestScopedContext,
  request: RecoveryExecuteRequest,
): Promise<RecoveryResponse> {
  const run = new RecoveryExecutionRequestRun(context, request);
  const result = await runRouterAbEd25519YaoRegistrationTwoPhaseV1<
    RouterAbEd25519YaoRecoveryExecuteClaimV1,
    RouterAbEd25519YaoRecoveryBackendResult,
    RecoveryResponse,
    AuthorizationFailure | RouterAbEd25519YaoRecoveryFailure
  >({
    lifecycleId: request.binding.lifecycle.lifecycle_id,
    store: context.input.store,
    prepare: run.prepare.bind(run),
    backend: run.backend.bind(run),
    complete: run.complete.bind(run),
  });
  return mapExecutionResult(result);
}

function mapAdmissionResult(
  result: RouterAbEd25519YaoRegistrationTwoPhaseRunResultV1<
    RouterAbEd25519YaoRecoveryAdmissionClaimV1,
    RecoveryResponse,
    AuthorizationFailure | RouterAbEd25519YaoRecoveryFailure
  >,
): RecoveryResponse {
  switch (result.kind) {
    case 'committed':
    case 'completed':
    case 'rejected':
      return result.value;
    case 'preclaim_version_mismatch':
      return stateConflictFailure('admission_failed', 'preclaim', result.key);
    case 'backend_uncertain':
      return backendUncertainFailure('admission_failed', result.message);
    case 'terminal_version_mismatch':
      return stateConflictFailure('admission_failed', 'terminal', result.key);
  }
}

function mapExecutionResult(
  result: RouterAbEd25519YaoRegistrationTwoPhaseRunResultV1<
    RouterAbEd25519YaoRecoveryExecuteClaimV1,
    RecoveryResponse,
    AuthorizationFailure | RouterAbEd25519YaoRecoveryFailure
  >,
): RecoveryResponse {
  switch (result.kind) {
    case 'committed':
    case 'completed':
    case 'rejected':
      return result.value;
    case 'preclaim_version_mismatch':
      return stateConflictFailure('execution_failed', 'preclaim', result.key);
    case 'backend_uncertain':
      return backendUncertainFailure('execution_failed', result.message);
    case 'terminal_version_mismatch':
      return stateConflictFailure('execution_failed', 'terminal', result.key);
  }
}

function stateConflictFailure(
  code: 'admission_failed' | 'execution_failed',
  phase: 'preclaim' | 'terminal',
  key: Extract<
    RouterAbEd25519YaoProductRegistrationPartitionedStateCommitResultV1,
    { readonly kind: 'version_mismatch' }
  >['key'],
): RouterAbEd25519YaoRecoveryFailure {
  return {
    ok: false,
    status: phase === 'preclaim' ? 409 : 503,
    code,
    message:
      phase === 'preclaim'
        ? `Yao recovery claim conflicted on ${key}`
        : `Yao recovery terminal state is uncertain after a ${key} conflict`,
  };
}

function backendUncertainFailure(
  code: 'admission_failed' | 'execution_failed',
  message: string,
): RouterAbEd25519YaoRecoveryFailure {
  return { ok: false, status: 503, code, message };
}

async function parseRecoveryRequest(
  request: Request,
): Promise<RecoveryRequest | { readonly response: Response }> {
  const raw = await readJson(request);
  const pathname = new URL(request.url).pathname;
  if (pathname === ROUTER_AB_ED25519_YAO_RECOVERY_ADMISSION_PATH_V1) {
    const parsed = parseRouterAbEd25519YaoRecoveryAdmissionRequestV1(raw);
    return parsed.ok
      ? { kind: 'admit', value: parsed.value }
      : {
          response: json(
            { ok: false, code: parsed.code, message: parsed.message },
            { status: 400 },
          ),
        };
  }
  if (pathname === ROUTER_AB_ED25519_YAO_RECOVERY_EXECUTE_PATH_V1) {
    const parsed = parseRouterAbEd25519YaoRecoveryActivationExecuteRequestV1(raw);
    return parsed.ok
      ? { kind: 'execute', value: parsed.value }
      : {
          response: json(
            { ok: false, code: parsed.code, message: parsed.message },
            { status: 400 },
          ),
        };
  }
  return {
    response: json({ ok: false, code: 'not_found', message: 'Not found' }, { status: 404 }),
  };
}

function resolveTrace(request: Request): TraceResolution {
  const parsed = parseRouterAbTraceContextV1(request.headers.get(ROUTER_AB_TRACE_ID_HEADER_V1));
  if (parsed.ok) return parsed;
  if (parsed.reason === 'missing') return { ok: true, value: createRouterAbTraceContextV1() };
  return { ok: false, message: parsed.message };
}

function recoveryResponse(result: RecoveryResponse): Response {
  return result.ok
    ? json(result.value, { status: result.status })
    : json({ ok: false, code: result.code, message: result.message }, { status: result.status });
}
