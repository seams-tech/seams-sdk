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
import { json, readJson } from './cloudflare/http';
import type {
  RouterAbEd25519YaoRegistrationBackend,
  RouterAbEd25519YaoRegistrationFailure,
  RouterAbEd25519YaoRegistrationServiceResult,
} from './routerAbEd25519YaoRegistration';
import { InMemoryRouterAbEd25519YaoRegistrationIntentAuthorizationAdapter } from './routerAbEd25519YaoRegistrationIntentAuthorization';
import {
  InMemoryRouterAbEd25519YaoRegistrationService,
  type RouterAbEd25519YaoRegistrationAdmissionCommitInputV1,
  type RouterAbEd25519YaoRegistrationExecuteCommitInputV1,
} from './routerAbEd25519YaoRegistration';
import type {
  RouterAbEd25519YaoProductRegistrationPartitionedStateStoreV1,
  RouterAbEd25519YaoProductRegistrationPartitionedStateCommitResultV1,
} from './routerAbEd25519YaoProductRegistrationPartitionedStateStore';

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
    const result =
      parsed.kind === 'admit'
        ? await runAdmissionRequest(input, parsed.value, trace.value)
        : await runExecutionRequest(input, parsed.value, trace.value);
    return registrationResultResponse(result);
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
  const store = input.store;
  const loaded = await store.load(lifecycleId);
  const authorization = new InMemoryRouterAbEd25519YaoRegistrationIntentAuthorizationAdapter(
    loaded.state.authorization,
  );
  const authorizationResult = await authorizeRequest(authorization, input.request, {
    kind: 'admit',
    value: request,
  });
  if (!authorizationResult.ok) return authorizationResult;
  const service = new InMemoryRouterAbEd25519YaoRegistrationService(
    input.backend,
    loaded.state.registration,
  );
  const preparation = service.prepareAdmit(request);
  if (preparation.kind === 'completed') {
    return { ok: true, status: 200, value: preparation.value };
  }
  if (preparation.kind === 'failed') return preparation.failure;
  const preclaim = await store.commit({
    lifecycleId,
    state: loaded.state,
    sharedState: loaded.sharedState,
    sharedVersion: loaded.sharedVersion,
    ceremonyVersion: loaded.ceremonyVersion,
  });
  if (preclaim.kind === 'version_mismatch') {
    return stateConflictFailure('admit', 'preclaim', preclaim);
  }
  let outcome: RouterAbEd25519YaoRegistrationAdmissionCommitInputV1['outcome'];
  try {
    outcome = { kind: 'backend_response', result: await input.backend.admit(request, trace) };
  } catch (error: unknown) {
    outcome = {
      kind: 'backend_uncertain',
      message: error instanceof Error ? error.message : String(error),
    };
  }
  const terminalLoaded = await store.load(lifecycleId);
  const terminalService = new InMemoryRouterAbEd25519YaoRegistrationService(
    input.backend,
    terminalLoaded.state.registration,
  );
  const terminal = terminalService.commitAdmit({ request, claim: preparation.claim, outcome });
  const terminalCommit = await store.commit({
    lifecycleId,
    state: terminalLoaded.state,
    sharedState: terminalLoaded.sharedState,
    sharedVersion: terminalLoaded.sharedVersion,
    ceremonyVersion: terminalLoaded.ceremonyVersion,
  });
  if (terminalCommit.kind === 'version_mismatch') {
    return terminalStateConflictFailure(terminalCommit);
  }
  return terminal;
}

async function runExecutionRequest(
  input: RouterAbEd25519YaoRegistrationRequestScopedCloudflareInputV1,
  request: RouterAbEd25519YaoRegistrationExecuteRequestV1,
  trace: RouterAbTraceContextV1,
): Promise<RegistrationServiceResponse> {
  const lifecycleId = request.binding.lifecycle.lifecycle_id;
  const store = input.store;
  const loaded = await store.load(lifecycleId);
  const authorization = new InMemoryRouterAbEd25519YaoRegistrationIntentAuthorizationAdapter(
    loaded.state.authorization,
  );
  const authorizationResult = await authorizeRequest(authorization, input.request, {
    kind: 'execute',
    value: request,
  });
  if (!authorizationResult.ok) return authorizationResult;
  const service = new InMemoryRouterAbEd25519YaoRegistrationService(
    input.backend,
    loaded.state.registration,
  );
  const preparation = service.prepareExecute(request);
  if (preparation.kind === 'completed') {
    return { ok: true, status: 200, value: preparation.value };
  }
  if (preparation.kind === 'failed') return preparation.failure;
  const preclaim = await store.commit({
    lifecycleId,
    state: loaded.state,
    sharedState: loaded.sharedState,
    sharedVersion: loaded.sharedVersion,
    ceremonyVersion: loaded.ceremonyVersion,
  });
  if (preclaim.kind === 'version_mismatch') {
    return stateConflictFailure('execute', 'preclaim', preclaim);
  }
  let outcome: RouterAbEd25519YaoRegistrationExecuteCommitInputV1['outcome'];
  try {
    outcome = { kind: 'backend_response', result: await input.backend.execute(request, trace) };
  } catch (error: unknown) {
    outcome = {
      kind: 'backend_uncertain',
      message: error instanceof Error ? error.message : String(error),
    };
  }
  const terminalLoaded = await store.load(lifecycleId);
  const terminalService = new InMemoryRouterAbEd25519YaoRegistrationService(
    input.backend,
    terminalLoaded.state.registration,
  );
  const terminal = terminalService.commitExecute({ request, claim: preparation.claim, outcome });
  const terminalCommit = await store.commit({
    lifecycleId,
    state: terminalLoaded.state,
    sharedState: terminalLoaded.sharedState,
    sharedVersion: terminalLoaded.sharedVersion,
    ceremonyVersion: terminalLoaded.ceremonyVersion,
  });
  if (terminalCommit.kind === 'version_mismatch')
    return terminalStateConflictFailure(terminalCommit);
  return terminal;
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

function registrationResultResponse(result: RegistrationServiceResponse): Response {
  return result.ok
    ? json(result.value, { status: result.status })
    : registrationFailureResponse(result);
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
