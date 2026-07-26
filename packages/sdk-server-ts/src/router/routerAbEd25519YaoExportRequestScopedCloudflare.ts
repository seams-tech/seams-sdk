import { base64UrlEncode } from '@shared/utils/encoders';
import { alphabetizeStringify, sha256BytesUtf8 } from '@shared/utils/digests';
import {
  ROUTER_AB_ED25519_YAO_EXPORT_ADMISSION_PATH_V1,
  ROUTER_AB_ED25519_YAO_EXPORT_EXECUTE_PATH_V1,
  type RouterAbEd25519YaoExportAdmissionReceiptV1,
  type RouterAbEd25519YaoExportAdmissionRequestV1,
  type RouterAbEd25519YaoExportExecuteRequestV1,
  type RouterAbEd25519YaoExportResultV1,
} from '@shared/utils/routerAbEd25519Yao';
import {
  createRouterAbTraceContextV1,
  parseRouterAbTraceContextV1,
  ROUTER_AB_TRACE_ID_HEADER_V1,
  type RouterAbTraceContextV1,
} from '@shared/utils/routerAbTraceContext';
import { normalizeCorsOrigin } from '../core/SessionService';
import { json, readJson } from './cloudflare/http';
import {
  InMemoryRouterAbEd25519YaoExportService,
  parseRouterAbEd25519YaoExportAdmissionEnvelopeV1,
  parseRouterAbEd25519YaoExportExecuteEnvelopeV1,
  type RouterAbEd25519YaoExportAdmissionClaimV1,
  type RouterAbEd25519YaoExportAuthorizationAdapter,
  type RouterAbEd25519YaoExportAuthorizationClaimV1,
  type RouterAbEd25519YaoExportAuthorizationResult,
  type RouterAbEd25519YaoExportBackend,
  type RouterAbEd25519YaoExportBackendResult,
  type RouterAbEd25519YaoExportExecuteClaimV1,
  type RouterAbEd25519YaoExportFailure,
  type RouterAbEd25519YaoExportServiceResult,
  type RouterAbEd25519YaoExportAdmissionEnvelopeParseResultV1,
} from './routerAbEd25519YaoExport';
import type { RouterAbEd25519YaoActiveCapabilityResolverV1 } from './routerAbEd25519YaoRecovery';
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

type AuthorizationFailure = Extract<
  RouterAbEd25519YaoExportAuthorizationResult,
  { readonly ok: false }
>;

type ExportResponse =
  | RouterAbEd25519YaoExportServiceResult<RouterAbEd25519YaoExportAdmissionReceiptV1>
  | RouterAbEd25519YaoExportServiceResult<RouterAbEd25519YaoExportResultV1>
  | AuthorizationFailure;

type TraceResolution =
  | { readonly ok: true; readonly value: RouterAbTraceContextV1 }
  | { readonly ok: false; readonly message: string };

export type RouterAbEd25519YaoExportRequestScopedCloudflareInputV1 = {
  readonly request: Request;
  readonly store: RouterAbEd25519YaoProductRegistrationPartitionedStateStoreV1;
  readonly backend: RouterAbEd25519YaoExportBackend;
  readonly capabilities: RouterAbEd25519YaoActiveCapabilityResolverV1;
  readonly authorization: RouterAbEd25519YaoExportAuthorizationAdapter;
};

type ExportRequestScopedContext = {
  readonly input: RouterAbEd25519YaoExportRequestScopedCloudflareInputV1;
  readonly trace: RouterAbTraceContextV1;
};

type ParsedAdmission = Extract<
  RouterAbEd25519YaoExportAdmissionEnvelopeParseResultV1,
  { readonly ok: true }
>;

class ExportAuthorizationRequestRun {
  constructor(
    private readonly context: ExportRequestScopedContext,
    private readonly parsed: ParsedAdmission,
    private readonly expectedOrigin: string,
    private readonly authorizationFingerprint: string,
  ) {}

  async prepare(
    state: RouterAbEd25519YaoProductRegistrationStateV1,
  ): Promise<
    RouterAbEd25519YaoRegistrationTwoPhasePrepareResultV1<
      RouterAbEd25519YaoExportAuthorizationClaimV1,
      RouterAbEd25519YaoExportAuthorizationResult,
      never
    >
  > {
    const preparation = this.service(state).prepareAuthorizeExport(
      this.parsed.protocol,
      this.authorizationFingerprint,
    );
    switch (preparation.kind) {
      case 'claimed':
        return { kind: 'claimed', state, claim: preparation.claim };
      case 'completed':
        return { kind: 'completed', value: preparation.value };
    }
  }

  async backend(
    _claim: RouterAbEd25519YaoExportAuthorizationClaimV1,
  ): Promise<
    RouterAbEd25519YaoRegistrationTwoPhaseBackendResultV1<RouterAbEd25519YaoExportAuthorizationResult>
  > {
    try {
      return {
        kind: 'response',
        value: await this.context.input.authorization.authorize({
          kind: 'admit',
          request: this.context.input.request,
          body: this.parsed.protocol,
          authorizationIdentity: this.parsed.authorizationIdentity,
          authorization: this.parsed.authorization,
          expectedOrigin: this.expectedOrigin,
        }),
      };
    } catch (error: unknown) {
      return { kind: 'uncertain', message: errorMessage(error) };
    }
  }

  async complete(
    state: RouterAbEd25519YaoProductRegistrationStateV1,
    claim: RouterAbEd25519YaoExportAuthorizationClaimV1,
    outcome: RouterAbEd25519YaoExportAuthorizationResult,
  ): Promise<
    RouterAbEd25519YaoRegistrationTwoPhaseCompletionV1<RouterAbEd25519YaoExportAuthorizationResult>
  > {
    const value = this.service(state).commitAuthorizeExport({
      request: this.parsed.protocol,
      claim,
      outcome,
    });
    return { state, value };
  }

  private service(
    state: RouterAbEd25519YaoProductRegistrationStateV1,
  ): InMemoryRouterAbEd25519YaoExportService {
    return exportService(this.context, state);
  }
}

class ExportAdmissionRequestRun {
  constructor(
    private readonly context: ExportRequestScopedContext,
    private readonly request: RouterAbEd25519YaoExportAdmissionRequestV1,
  ) {}

  async prepare(
    state: RouterAbEd25519YaoProductRegistrationStateV1,
  ): Promise<
    RouterAbEd25519YaoRegistrationTwoPhasePrepareResultV1<
      RouterAbEd25519YaoExportAdmissionClaimV1,
      ExportResponse,
      RouterAbEd25519YaoExportFailure
    >
  > {
    const preparation = await exportService(this.context, state).prepareAdmitExport(this.request);
    switch (preparation.kind) {
      case 'claimed':
        return { kind: 'claimed', state, claim: preparation.claim };
      case 'completed':
        return { kind: 'completed', value: success(preparation.value) };
      case 'failed':
        return { kind: 'rejected', value: preparation.failure };
    }
  }

  async backend(
    _claim: RouterAbEd25519YaoExportAdmissionClaimV1,
  ): Promise<
    RouterAbEd25519YaoRegistrationTwoPhaseBackendResultV1<RouterAbEd25519YaoExportBackendResult>
  > {
    try {
      return {
        kind: 'response',
        value: await this.context.input.backend.admitExport(this.request, this.context.trace),
      };
    } catch (error: unknown) {
      return { kind: 'uncertain', message: errorMessage(error) };
    }
  }

  async complete(
    state: RouterAbEd25519YaoProductRegistrationStateV1,
    claim: RouterAbEd25519YaoExportAdmissionClaimV1,
    outcome: RouterAbEd25519YaoExportBackendResult,
  ): Promise<RouterAbEd25519YaoRegistrationTwoPhaseCompletionV1<ExportResponse>> {
    const value = exportService(this.context, state).commitAdmitExport({
      request: this.request,
      claim,
      outcome: { kind: 'backend_response', result: outcome },
    });
    return { state, value };
  }
}

class ExportExecutionRequestRun {
  constructor(
    private readonly context: ExportRequestScopedContext,
    private readonly request: RouterAbEd25519YaoExportExecuteRequestV1,
    private readonly authorizationIdentity: ParsedExecutionAuthorizationIdentity,
  ) {}

  async prepare(
    state: RouterAbEd25519YaoProductRegistrationStateV1,
  ): Promise<
    RouterAbEd25519YaoRegistrationTwoPhasePrepareResultV1<
      RouterAbEd25519YaoExportExecuteClaimV1,
      ExportResponse,
      AuthorizationFailure | RouterAbEd25519YaoExportFailure
    >
  > {
    const authorized = await this.context.input.authorization.authorize({
      kind: 'execute',
      request: this.context.input.request,
      body: this.request,
      authorizationIdentity: this.authorizationIdentity,
    });
    if (!authorized.ok) return { kind: 'rejected', value: authorized };
    const preparation = exportService(this.context, state).prepareExecuteExport(this.request);
    switch (preparation.kind) {
      case 'claimed':
        return { kind: 'claimed', state, claim: preparation.claim };
      case 'completed':
        return { kind: 'completed', value: success(preparation.value) };
      case 'failed':
        return { kind: 'rejected', value: preparation.failure };
    }
  }

  async backend(
    _claim: RouterAbEd25519YaoExportExecuteClaimV1,
  ): Promise<
    RouterAbEd25519YaoRegistrationTwoPhaseBackendResultV1<RouterAbEd25519YaoExportBackendResult>
  > {
    try {
      return {
        kind: 'response',
        value: await this.context.input.backend.executeExport(this.request, this.context.trace),
      };
    } catch (error: unknown) {
      return { kind: 'uncertain', message: errorMessage(error) };
    }
  }

  async complete(
    state: RouterAbEd25519YaoProductRegistrationStateV1,
    claim: RouterAbEd25519YaoExportExecuteClaimV1,
    outcome: RouterAbEd25519YaoExportBackendResult,
  ): Promise<RouterAbEd25519YaoRegistrationTwoPhaseCompletionV1<ExportResponse>> {
    const value = exportService(this.context, state).commitExecuteExport({
      request: this.request,
      claim,
      outcome: { kind: 'backend_response', result: outcome },
    });
    return { state, value };
  }
}

type ParsedExecutionAuthorizationIdentity = Extract<
  ReturnType<typeof parseRouterAbEd25519YaoExportExecuteEnvelopeV1>,
  { readonly ok: true }
>['authorizationIdentity'];

export async function handleRouterAbEd25519YaoExportRequestScopedCloudflareV1(
  input: RouterAbEd25519YaoExportRequestScopedCloudflareInputV1,
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
  const context: ExportRequestScopedContext = { input, trace: trace.value };
  try {
    return await handleParsedRequest(context, await readJson(input.request));
  } catch (error: unknown) {
    return json(
      { ok: false, code: 'router_state_unavailable', message: errorMessage(error) },
      { status: 503 },
    );
  }
}

async function handleParsedRequest(
  context: ExportRequestScopedContext,
  raw: unknown,
): Promise<Response> {
  const pathname = new URL(context.input.request.url).pathname;
  if (pathname === ROUTER_AB_ED25519_YAO_EXPORT_ADMISSION_PATH_V1) {
    return await handleAdmissionRequest(context, raw);
  }
  if (pathname === ROUTER_AB_ED25519_YAO_EXPORT_EXECUTE_PATH_V1) {
    return await handleExecutionRequest(context, raw);
  }
  return json({ ok: false, code: 'not_found', message: 'Not found' }, { status: 404 });
}

async function handleAdmissionRequest(
  context: ExportRequestScopedContext,
  raw: unknown,
): Promise<Response> {
  const parsed = parseRouterAbEd25519YaoExportAdmissionEnvelopeV1(raw);
  if (!parsed.ok) return invalidBody(parsed.message);
  const expectedOrigin = normalizeCorsOrigin(
    context.input.request.headers.get('origin') || undefined,
  );
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
  const fingerprint = await authorizationFingerprint(parsed);
  const authorization = await runAuthorization(context, parsed, expectedOrigin, fingerprint);
  if (!authorization.ok) return exportResponse(authorization);
  const admission = await runAdmission(context, parsed.protocol);
  return exportResponse(admission);
}

async function handleExecutionRequest(
  context: ExportRequestScopedContext,
  raw: unknown,
): Promise<Response> {
  const parsed = parseRouterAbEd25519YaoExportExecuteEnvelopeV1(raw);
  if (!parsed.ok) return invalidBody(parsed.message);
  const run = new ExportExecutionRequestRun(context, parsed.protocol, parsed.authorizationIdentity);
  const result = await runRouterAbEd25519YaoRegistrationTwoPhaseV1<
    RouterAbEd25519YaoExportExecuteClaimV1,
    RouterAbEd25519YaoExportBackendResult,
    ExportResponse,
    AuthorizationFailure | RouterAbEd25519YaoExportFailure
  >({
    lifecycleId: parsed.protocol.binding.ceremony.lifecycle.lifecycle_id,
    store: context.input.store,
    prepare: run.prepare.bind(run),
    backend: run.backend.bind(run),
    complete: run.complete.bind(run),
  });
  return exportResponse(mapExecutionResult(result));
}

async function runAuthorization(
  context: ExportRequestScopedContext,
  parsed: ParsedAdmission,
  expectedOrigin: string,
  fingerprint: string,
): Promise<RouterAbEd25519YaoExportAuthorizationResult> {
  const run = new ExportAuthorizationRequestRun(context, parsed, expectedOrigin, fingerprint);
  const result = await runRouterAbEd25519YaoRegistrationTwoPhaseV1<
    RouterAbEd25519YaoExportAuthorizationClaimV1,
    RouterAbEd25519YaoExportAuthorizationResult,
    RouterAbEd25519YaoExportAuthorizationResult,
    never
  >({
    lifecycleId: parsed.protocol.scope.lifecycle_id,
    store: context.input.store,
    prepare: run.prepare.bind(run),
    backend: run.backend.bind(run),
    complete: run.complete.bind(run),
  });
  return mapAuthorizationResult(result);
}

async function runAdmission(
  context: ExportRequestScopedContext,
  request: RouterAbEd25519YaoExportAdmissionRequestV1,
): Promise<ExportResponse> {
  const run = new ExportAdmissionRequestRun(context, request);
  const result = await runRouterAbEd25519YaoRegistrationTwoPhaseV1<
    RouterAbEd25519YaoExportAdmissionClaimV1,
    RouterAbEd25519YaoExportBackendResult,
    ExportResponse,
    RouterAbEd25519YaoExportFailure
  >({
    lifecycleId: request.scope.lifecycle_id,
    store: context.input.store,
    prepare: run.prepare.bind(run),
    backend: run.backend.bind(run),
    complete: run.complete.bind(run),
  });
  return mapAdmissionResult(result);
}

function mapAuthorizationResult(
  result: RouterAbEd25519YaoRegistrationTwoPhaseRunResultV1<
    RouterAbEd25519YaoExportAuthorizationClaimV1,
    RouterAbEd25519YaoExportAuthorizationResult,
    never
  >,
): RouterAbEd25519YaoExportAuthorizationResult {
  switch (result.kind) {
    case 'committed':
    case 'completed':
      return result.value;
    case 'rejected':
      return assertNever(result.value);
    case 'preclaim_version_mismatch':
      return authorizationFailure(
        409,
        'export_authorization_conflict',
        `Export authorization claim conflicted on ${result.key}`,
      );
    case 'backend_uncertain':
      return authorizationFailure(503, 'export_authorization_uncertain', result.message);
    case 'terminal_version_mismatch':
      return authorizationFailure(
        503,
        'export_authorization_uncertain',
        `Export authorization outcome is uncertain after a ${result.key} conflict`,
      );
  }
}

function mapAdmissionResult(
  result: RouterAbEd25519YaoRegistrationTwoPhaseRunResultV1<
    RouterAbEd25519YaoExportAdmissionClaimV1,
    ExportResponse,
    RouterAbEd25519YaoExportFailure
  >,
): ExportResponse {
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
    RouterAbEd25519YaoExportExecuteClaimV1,
    ExportResponse,
    AuthorizationFailure | RouterAbEd25519YaoExportFailure
  >,
): ExportResponse {
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

function exportService(
  context: ExportRequestScopedContext,
  state: RouterAbEd25519YaoProductRegistrationStateV1,
): InMemoryRouterAbEd25519YaoExportService {
  return new InMemoryRouterAbEd25519YaoExportService(
    context.input.backend,
    context.input.capabilities,
    state.export,
  );
}

function stateConflictFailure(
  code: 'admission_failed' | 'execution_failed',
  phase: 'preclaim' | 'terminal',
  key: Extract<
    RouterAbEd25519YaoProductRegistrationPartitionedStateCommitResultV1,
    { readonly kind: 'version_mismatch' }
  >['key'],
): RouterAbEd25519YaoExportFailure {
  return {
    ok: false,
    status: phase === 'preclaim' ? 409 : 503,
    code,
    message:
      phase === 'preclaim'
        ? `Yao export claim conflicted on ${key}`
        : `Yao export terminal state is uncertain after a ${key} conflict`,
  };
}

function backendUncertainFailure(
  code: 'admission_failed' | 'execution_failed',
  message: string,
): RouterAbEd25519YaoExportFailure {
  return { ok: false, status: 503, code, message };
}

function authorizationFailure(
  status: 409 | 503,
  code: string,
  message: string,
): AuthorizationFailure {
  return { ok: false, status, code, message };
}

function success<T>(value: T): { readonly ok: true; readonly status: 200; readonly value: T } {
  return { ok: true, status: 200, value };
}

function invalidBody(message: string): Response {
  return json({ ok: false, code: 'invalid_body', message }, { status: 400 });
}

function exportResponse(result: ExportResponse): Response {
  return result.ok
    ? json(result.value, { status: result.status })
    : json({ ok: false, code: result.code, message: result.message }, { status: result.status });
}

async function authorizationFingerprint(parsed: ParsedAdmission): Promise<string> {
  const canonical = alphabetizeStringify({
    authorizationIdentity: parsed.authorizationIdentity,
    authorization: parsed.authorization,
  });
  return base64UrlEncode(await sha256BytesUtf8(canonical));
}

function resolveTrace(request: Request): TraceResolution {
  const parsed = parseRouterAbTraceContextV1(request.headers.get(ROUTER_AB_TRACE_ID_HEADER_V1));
  if (parsed.ok) return parsed;
  if (parsed.reason === 'missing') return { ok: true, value: createRouterAbTraceContextV1() };
  return { ok: false, message: parsed.message };
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function assertNever(value: never): never {
  throw new Error(`Unhandled export request-scoped value: ${String(value)}`);
}
