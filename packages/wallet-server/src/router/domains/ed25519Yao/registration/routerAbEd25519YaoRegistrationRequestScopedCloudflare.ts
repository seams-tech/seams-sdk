import {
  parseRouterAbEd25519YaoRegistrationActivationExecuteRequestV1,
  parseRouterAbEd25519YaoRegistrationAdmissionRequestV1,
  ROUTER_AB_ED25519_YAO_REGISTRATION_ADMISSION_PATH_V1,
  ROUTER_AB_ED25519_YAO_REGISTRATION_EXECUTE_PATH_V1,
  type RouterAbEd25519YaoActivationAdmissionReceiptV1,
  type RouterAbEd25519YaoActivationExecuteRequestV1,
  type RouterAbEd25519YaoActivationResultV1,
  type RouterAbEd25519YaoRegistrationAdmissionRequestV1,
} from '@shared/utils/routerAbEd25519Yao';
import {
  createRouterAbTraceContextV1,
  parseRouterAbTraceContextV1,
  ROUTER_AB_TRACE_ID_HEADER_V1,
  type RouterAbTraceContextV1,
} from '@shared/utils/routerAbTraceContext';
import { json, readJson } from '../../../framework/http';
import type {
  RouterAbEd25519YaoRegistrationAdmissionClaimV1,
  RouterAbEd25519YaoRegistrationBackendResult,
  RouterAbEd25519YaoRegistrationBackend,
  RouterAbEd25519YaoRegistrationFailure,
  RouterAbEd25519YaoRegistrationServiceResult,
} from './routerAbEd25519YaoRegistration';
import {
  InMemoryRouterAbEd25519YaoRegistrationStateV1,
  InMemoryRouterAbEd25519YaoRegistrationService,
} from './routerAbEd25519YaoRegistration';
import {
  InMemoryRouterAbEd25519YaoRegistrationIntentAuthorizationAdapter,
  routerAbEd25519YaoBearerCredentialDigestV1,
} from './routerAbEd25519YaoRegistrationIntentAuthorization';
import { routerAbEd25519YaoRegistrationExecutionRequestDigestV1 } from './routerAbEd25519YaoRegistrationExecutionRecord';
import {
  runRouterAbEd25519YaoRegistrationTwoPhaseV1,
  type RouterAbEd25519YaoRegistrationTwoPhaseRunResultV1,
} from './routerAbEd25519YaoRegistrationTwoPhaseRunner';
import type {
  RouterAbEd25519YaoProductRegistrationPartitionedStateStoreV1,
  RouterAbEd25519YaoProductRegistrationPartitionedStateCommitResultV1,
} from '../capabilityLifecycle/routerAbEd25519YaoProductRegistrationPartitionedStateStore';

export type RouterAbEd25519YaoRegistrationRequestScopedCloudflareInputV1 = {
  readonly request: Request;
  readonly store: RouterAbEd25519YaoProductRegistrationPartitionedStateStoreV1;
  readonly backend: RouterAbEd25519YaoRegistrationBackend;
};

type RouterAbEd25519YaoRegistrationAdmissionReceiptV1 =
  RouterAbEd25519YaoActivationAdmissionReceiptV1<'registration'>;
type RouterAbEd25519YaoRegistrationExecuteRequestV1 =
  RouterAbEd25519YaoActivationExecuteRequestV1<'registration'>;
type RouterAbEd25519YaoRegistrationResultV1 = RouterAbEd25519YaoActivationResultV1<'registration'>;

type RegistrationRequest =
  | {
      readonly kind: 'admit';
      readonly value: RouterAbEd25519YaoRegistrationAdmissionRequestV1;
    }
  | {
      readonly kind: 'execute';
      readonly value: RouterAbEd25519YaoRegistrationExecuteRequestV1;
    };

type RegistrationServiceResponse =
  | RouterAbEd25519YaoRegistrationServiceResult<RouterAbEd25519YaoRegistrationAdmissionReceiptV1>
  | RouterAbEd25519YaoRegistrationServiceResult<RouterAbEd25519YaoRegistrationResultV1>
  | AuthorizationFailure;

type AuthorizationFailure = {
  readonly ok: false;
  readonly status: 401 | 403 | 409 | 429 | 503;
  readonly code: string;
  readonly message: string;
};

type TraceResolution =
  | { readonly ok: true; readonly value: RouterAbTraceContextV1 }
  | { readonly ok: false; readonly message: string };

type RegistrationExecutionTimingV1 = {
  readonly credentialDigestMs: number;
  readonly requestDigestMs: number;
  readonly d1ClaimMs: number;
  readonly routerExecutionMs: number;
  readonly routerServerTiming: string | null;
  readonly resultReconstructionMs: number;
  readonly d1TerminalCommitMs: number;
};

type TimedRegistrationExecutionResultV1 = {
  readonly result: RegistrationServiceResponse;
  readonly timing: RegistrationExecutionTimingV1;
};

export async function handleRouterAbEd25519YaoRegistrationRequestScopedCloudflareV1(
  input: RouterAbEd25519YaoRegistrationRequestScopedCloudflareInputV1,
): Promise<Response> {
  if (input.request.method !== 'POST') {
    return json(
      { ok: false, code: 'method_not_allowed', message: 'Method not allowed' },
      { status: 405 },
    );
  }
  const trace = resolveTrace(input.request);
  if (!trace.ok)
    return json({ ok: false, code: 'invalid_trace_id', message: trace.message }, { status: 400 });
  const parsed = await parseRegistrationRequest(input.request);
  if ('response' in parsed) return parsed.response;
  const lifecycleId = registrationLifecycleId(parsed);
  if (lifecycleId === null) {
    return json(
      { ok: false, code: 'invalid_registration', message: 'registration lifecycle_id is required' },
      { status: 400 },
    );
  }
  try {
    if (parsed.kind === 'admit') {
      return registrationResultResponse(
        await runAdmissionRequest(input, parsed.value, trace.value),
      );
    }
    const execution = await runExecutionRequest(input, parsed.value, trace.value);
    return registrationResultResponse(execution.result, execution.timing);
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
  input: RouterAbEd25519YaoRegistrationRequestScopedCloudflareInputV1,
  request: RouterAbEd25519YaoRegistrationAdmissionRequestV1,
  trace: RouterAbTraceContextV1,
): Promise<RegistrationServiceResponse> {
  const lifecycleId = request.scope.lifecycle_id;
  const result = await runRouterAbEd25519YaoRegistrationTwoPhaseV1<
    RouterAbEd25519YaoRegistrationAdmissionClaimV1,
    RouterAbEd25519YaoRegistrationBackendResult,
    RegistrationServiceResponse,
    AuthorizationFailure | RouterAbEd25519YaoRegistrationFailure
  >({
    lifecycleId,
    store: input.store,
    prepare: async (state) => {
      const authorization = new InMemoryRouterAbEd25519YaoRegistrationIntentAuthorizationAdapter(
        state.authorization,
      );
      const authorizationResult = await authorizeRequest(authorization, input.request, {
        kind: 'admit',
        value: request,
      });
      if (!authorizationResult.ok) {
        return { kind: 'rejected', value: authorizationResult };
      }
      const service = new InMemoryRouterAbEd25519YaoRegistrationService(
        input.backend,
        state.registration,
      );
      const preparation = service.prepareAdmit(request);
      switch (preparation.kind) {
        case 'completed':
          return {
            kind: 'completed',
            value: { ok: true, status: 200, value: preparation.value },
          };
        case 'failed':
          return { kind: 'rejected', value: preparation.failure };
        case 'claimed':
          return { kind: 'claimed', state, claim: preparation.claim };
      }
    },
    backend: async () => {
      try {
        return { kind: 'response', value: await input.backend.admit(request, trace) };
      } catch (error: unknown) {
        return {
          kind: 'uncertain',
          message: error instanceof Error ? error.message : String(error),
        };
      }
    },
    complete: async (state, claim, backend) => {
      const service = new InMemoryRouterAbEd25519YaoRegistrationService(
        input.backend,
        state.registration,
      );
      return {
        state,
        value: service.commitAdmit({
          request,
          claim,
          outcome: { kind: 'backend_response', result: backend },
        }),
      };
    },
  });
  return mapAdmissionRunResult(result);
}

async function runExecutionRequest(
  input: RouterAbEd25519YaoRegistrationRequestScopedCloudflareInputV1,
  request: RouterAbEd25519YaoRegistrationExecuteRequestV1,
  trace: RouterAbTraceContextV1,
): Promise<TimedRegistrationExecutionResultV1> {
  const lifecycleId = request.binding.lifecycle.lifecycle_id;
  const credentialStartedAt = performance.now();
  const credential = await routerAbEd25519YaoBearerCredentialDigestV1(input.request);
  const credentialDigestMs = elapsedMs(credentialStartedAt);
  if (!credential.ok) {
    return timedExecutionResult(credential.result, {
      credentialDigestMs,
      requestDigestMs: 0,
      d1ClaimMs: 0,
      routerExecutionMs: 0,
      routerServerTiming: null,
      resultReconstructionMs: 0,
      d1TerminalCommitMs: 0,
    });
  }
  const requestDigestStartedAt = performance.now();
  const requestDigestSha256Hex =
    await routerAbEd25519YaoRegistrationExecutionRequestDigestV1(request);
  const requestDigestMs = elapsedMs(requestDigestStartedAt);
  const d1ClaimStartedAt = performance.now();
  const claim = await input.store.claimRegistrationExecution({
    lifecycleId,
    request,
    requestDigestSha256Hex,
    credentialDigestSha256Hex: credential.digestSha256Hex,
    nowMs: Date.now(),
  });
  const d1ClaimMs = elapsedMs(d1ClaimStartedAt);
  const timingBeforeRouter = {
    credentialDigestMs,
    requestDigestMs,
    d1ClaimMs,
    routerExecutionMs: 0,
    routerServerTiming: null,
    resultReconstructionMs: 0,
    d1TerminalCommitMs: 0,
  };
  switch (claim.kind) {
    case 'completed':
      return timedExecutionResult(
        { ok: true, status: 200, value: claim.value },
        timingBeforeRouter,
      );
    case 'failed':
      return timedExecutionResult(claim.value, timingBeforeRouter);
    case 'rejected':
      return timedExecutionResult(executionClaimFailure(claim), timingBeforeRouter);
    case 'claimed':
      break;
  }
  let backend: RouterAbEd25519YaoRegistrationBackendResult;
  const routerExecutionStartedAt = performance.now();
  try {
    backend = await input.backend.execute(request, claim.value.admissionRequest, trace);
  } catch (error: unknown) {
    return timedExecutionResult(
      {
        ok: false,
        status: 503,
        code: 'execution_failed',
        message: error instanceof Error ? error.message : String(error),
      },
      {
        ...timingBeforeRouter,
        routerExecutionMs: elapsedMs(routerExecutionStartedAt),
      },
    );
  }
  const routerExecutionMs = elapsedMs(routerExecutionStartedAt);
  const routerServerTiming = input.backend.takeLastRouterServerTiming?.() ?? null;
  if (isRetryableRegistrationBackendFailure(backend)) {
    return timedExecutionResult(
      {
        ok: false,
        status: 503,
        code: 'execution_failed',
        message: backend.message,
      },
      { ...timingBeforeRouter, routerExecutionMs, routerServerTiming },
    );
  }
  const reconstructionStartedAt = performance.now();
  const terminal = completeClaimedExecution(input.backend, claim.value, request, backend);
  const resultReconstructionMs = elapsedMs(reconstructionStartedAt);
  const terminalCommitStartedAt = performance.now();
  const committed = await input.store.commitRegistrationExecution({
    claimed: claim.value,
    claimedVersion: claim.version,
    outcome: terminal.ok
      ? { kind: 'completed', result: terminal.value }
      : { kind: 'failed', failure: terminal },
  });
  const d1TerminalCommitMs = elapsedMs(terminalCommitStartedAt);
  const timing = {
    ...timingBeforeRouter,
    routerExecutionMs,
    routerServerTiming,
    resultReconstructionMs,
    d1TerminalCommitMs,
  };
  if (committed.kind === 'uncertain') {
    return timedExecutionResult(
      {
        ok: false,
        status: 503,
        code: 'execution_failed',
        message: 'registration execution terminal persistence is uncertain',
      },
      timing,
    );
  }
  return timedExecutionResult(
    isRegistrationFailure(committed.value)
      ? committed.value
      : { ok: true, status: 200, value: committed.value },
    timing,
  );
}

function elapsedMs(startedAt: number): number {
  return Math.max(0, performance.now() - startedAt);
}

function timedExecutionResult(
  result: RegistrationServiceResponse,
  timing: RegistrationExecutionTimingV1,
): TimedRegistrationExecutionResultV1 {
  return { result, timing };
}

function completeClaimedExecution(
  backendAdapter: RouterAbEd25519YaoRegistrationBackend,
  claimed: Extract<
    Awaited<
      ReturnType<
        RouterAbEd25519YaoProductRegistrationPartitionedStateStoreV1['claimRegistrationExecution']
      >
    >,
    { readonly kind: 'claimed' }
  >['value'],
  request: RouterAbEd25519YaoRegistrationExecuteRequestV1,
  backend: RouterAbEd25519YaoRegistrationBackendResult,
): RouterAbEd25519YaoRegistrationServiceResult<RouterAbEd25519YaoRegistrationResultV1> {
  const state = new InMemoryRouterAbEd25519YaoRegistrationStateV1();
  const sessionKey = bytesToHex(claimed.admissionReceipt.binding.session_id);
  state.states.set(sessionKey, {
    kind: 'admitted',
    admissionRequest: claimed.admissionRequest,
    admissionReceipt: claimed.admissionReceipt,
  });
  state.lifecycleSessions.set(claimed.lifecycleId, sessionKey);
  const service = new InMemoryRouterAbEd25519YaoRegistrationService(backendAdapter, state);
  const prepared = service.prepareExecute(request);
  if (prepared.kind !== 'claimed') {
    throw new Error('claimed Yao registration execution could not be reconstructed');
  }
  return service.commitExecute({
    request,
    claim: prepared.claim,
    outcome: { kind: 'backend_response', result: backend },
  });
}

function executionClaimFailure(
  claim: Extract<
    Awaited<
      ReturnType<
        RouterAbEd25519YaoProductRegistrationPartitionedStateStoreV1['claimRegistrationExecution']
      >
    >,
    { readonly kind: 'rejected' }
  >,
): AuthorizationFailure | RouterAbEd25519YaoRegistrationFailure {
  switch (claim.code) {
    case 'unknown_registration':
      return { ok: false, status: 404, code: 'unknown_registration', message: claim.message };
    case 'binding_mismatch':
      return { ok: false, status: 409, code: 'binding_mismatch', message: claim.message };
    case 'credential_rejected':
      return {
        ok: false,
        status: 403,
        code: 'registration_intent_subject_mismatch',
        message: claim.message,
      };
    case 'credential_expired':
      return {
        ok: false,
        status: 403,
        code: 'registration_intent_credential_expired',
        message: claim.message,
      };
    case 'execution_in_progress':
      return { ok: false, status: 409, code: 'execution_in_progress', message: claim.message };
  }
}

function bytesToHex(bytes: readonly number[]): string {
  let encoded = '';
  for (const byte of bytes) encoded += byte.toString(16).padStart(2, '0');
  return encoded;
}

function isRegistrationFailure(
  value: RouterAbEd25519YaoRegistrationResultV1 | RouterAbEd25519YaoRegistrationFailure,
): value is RouterAbEd25519YaoRegistrationFailure {
  return 'ok' in value && value.ok === false;
}

function isRetryableRegistrationBackendFailure(
  result: RouterAbEd25519YaoRegistrationBackendResult,
): result is Extract<RouterAbEd25519YaoRegistrationBackendResult, { readonly ok: false }> {
  return (
    !result.ok &&
    (result.code === 'worker_unavailable' ||
      result.code === 'worker_rejected' ||
      result.code === 'router_execution_retryable')
  );
}

async function authorizeRequest(
  authorization: InMemoryRouterAbEd25519YaoRegistrationIntentAuthorizationAdapter,
  request: Request,
  input: RegistrationRequest,
): Promise<{ readonly ok: true } | AuthorizationFailure> {
  switch (input.kind) {
    case 'admit':
      return await authorization.authorize({ kind: 'admit', request, body: input.value });
    case 'execute':
      return await authorization.authorize({ kind: 'execute', request, body: input.value });
  }
}

async function parseRegistrationRequest(
  request: Request,
): Promise<RegistrationRequest | { readonly response: Response }> {
  const rawBody = await readJson(request);
  const pathname = new URL(request.url).pathname;
  if (pathname === ROUTER_AB_ED25519_YAO_REGISTRATION_ADMISSION_PATH_V1) {
    return parseAdmissionRequest(rawBody);
  }
  if (pathname === ROUTER_AB_ED25519_YAO_REGISTRATION_EXECUTE_PATH_V1) {
    const parsed = parseRouterAbEd25519YaoRegistrationActivationExecuteRequestV1(rawBody);
    if (!parsed.ok) {
      return {
        response: json({ ok: false, code: parsed.code, message: parsed.message }, { status: 400 }),
      };
    }
    return { kind: 'execute', value: parsed.value };
  }
  return {
    response: json({ ok: false, code: 'not_found', message: 'Not found' }, { status: 404 }),
  };
}

function parseAdmissionRequest(
  rawBody: unknown,
):
  | { readonly kind: 'admit'; readonly value: RouterAbEd25519YaoRegistrationAdmissionRequestV1 }
  | { readonly response: Response } {
  const parsed = parseRouterAbEd25519YaoRegistrationAdmissionRequestV1(rawBody);
  if (!parsed.ok) {
    return {
      response: json({ ok: false, code: parsed.code, message: parsed.message }, { status: 400 }),
    };
  }
  return { kind: 'admit', value: parsed.value };
}

function registrationLifecycleId(input: RegistrationRequest): string | null {
  return input.kind === 'admit'
    ? input.value.scope.lifecycle_id
    : input.value.binding.lifecycle.lifecycle_id;
}

function resolveTrace(request: Request): TraceResolution {
  const parsed = parseRouterAbTraceContextV1(request.headers.get(ROUTER_AB_TRACE_ID_HEADER_V1));
  if (parsed.ok) return parsed;
  if (parsed.reason === 'missing') return { ok: true, value: createRouterAbTraceContextV1() };
  return { ok: false, message: parsed.message };
}

function registrationFailureResponse(
  result: Extract<RegistrationServiceResponse, { ok: false }>,
): Response {
  return json({ ok: false, code: result.code, message: result.message }, { status: result.status });
}

function registrationResultResponse(
  result: RegistrationServiceResponse,
  timing?: RegistrationExecutionTimingV1,
): Response {
  const response = result.ok
    ? json(result.value, { status: result.status })
    : registrationFailureResponse(result);
  if (timing) {
    response.headers.set('Server-Timing', registrationExecutionServerTiming(timing));
    response.headers.set('Timing-Allow-Origin', '*');
  }
  return response;
}

function registrationExecutionServerTiming(timing: RegistrationExecutionTimingV1): string {
  const gatewayTiming = [
    serverTimingMetric('yao_credential_digest', timing.credentialDigestMs),
    serverTimingMetric('yao_request_digest', timing.requestDigestMs),
    serverTimingMetric('yao_d1_claim', timing.d1ClaimMs),
    serverTimingMetric('yao_router_execution', timing.routerExecutionMs),
    serverTimingMetric('yao_result_reconstruction', timing.resultReconstructionMs),
    serverTimingMetric('yao_d1_terminal_commit', timing.d1TerminalCommitMs),
  ];
  if (timing.routerServerTiming) gatewayTiming.push(timing.routerServerTiming);
  return gatewayTiming.join(', ');
}

function serverTimingMetric(name: string, durationMs: number): string {
  return `${name};dur=${durationMs.toFixed(1)}`;
}

function mapAdmissionRunResult(
  result: RouterAbEd25519YaoRegistrationTwoPhaseRunResultV1<
    RouterAbEd25519YaoRegistrationAdmissionClaimV1,
    RegistrationServiceResponse,
    AuthorizationFailure | RouterAbEd25519YaoRegistrationFailure
  >,
): RegistrationServiceResponse {
  switch (result.kind) {
    case 'committed':
    case 'completed':
    case 'rejected':
      return result.value;
    case 'preclaim_version_mismatch':
      return stateConflictFailure('admit', 'preclaim', {
        kind: 'version_mismatch',
        key: result.key,
      });
    case 'backend_uncertain':
      return {
        ok: false,
        status: 503,
        code: 'admission_uncertain',
        message: result.message,
      };
    case 'terminal_version_mismatch':
      return terminalStateConflictFailure({ kind: 'version_mismatch', key: result.key });
    default:
      return assertNever(result);
  }
}

function assertNever(value: never): never {
  throw new Error(`Unhandled registration request-scoped result: ${String(value)}`);
}

function stateConflictFailure(
  operation: 'admit' | 'execute',
  phase: 'preclaim',
  result: RouterAbEd25519YaoProductRegistrationPartitionedStateCommitResultV1,
): RouterAbEd25519YaoRegistrationFailure {
  if (result.kind !== 'version_mismatch') {
    throw new Error(`Unexpected ${phase} state commit result`);
  }
  return {
    ok: false,
    status: 409,
    code: operation === 'admit' ? 'admission_failed' : 'execution_failed',
    message: `Yao ${phase} state conflict on ${result.key}`,
  };
}

function terminalStateConflictFailure(
  result: RouterAbEd25519YaoProductRegistrationPartitionedStateCommitResultV1,
): RouterAbEd25519YaoRegistrationFailure {
  if (result.kind !== 'version_mismatch')
    throw new Error('Unexpected terminal state commit result');
  return {
    ok: false,
    status: 503,
    code: 'execution_failed',
    message: `Yao terminal state is uncertain after a ${result.key} conflict`,
  };
}
