import type { LinkedDeviceEnrollmentReceiptV1 } from '@shared/device-linking/contracts';
import { parseLinkedDeviceEnrollmentReceiptV1 } from '@shared/device-linking/parsers';
import { parseLinkDeviceSessionId, type LinkDeviceSessionId } from '@shared/signing-lanes/ids';
import { parseDigestB64u, type DigestB64u } from '@shared/utils/canonicalPrimitives';
import { base64UrlEncode } from '@shared/utils/base64';
import { sha256Bytes } from '@shared/utils/digests';
import type {
  LinkedDeviceSessionRecordV1,
  LinkedDeviceSessionServiceResultV1,
  LinkedDeviceSessionServiceV1,
} from '../../../../core/deviceLinking/linkedDeviceSession';
import type { FetchRouterApiContext } from '../createFetchRouter';
import { json } from '../../../framework/http';

export const LINKED_DEVICE_GATEWAY_COMPLETION_BASE_V1 =
  '/internal/gateway/device-linking/v1/sessions';

export type DeviceLinkingGatewayRequestBindingV1 = {
  readonly kind: 'linked_device_gateway_request_binding_v1';
  readonly method: 'POST';
  readonly pathname: string;
  readonly bodyDigestB64u: DigestB64u;
  readonly expiresAtMs: number;
};

export type DeviceLinkingGatewayAuthenticatedRequestV1 = {
  readonly kind: 'authorized';
  /** The Gateway verifier owns body parsing after authenticating the request. */
  readonly body: unknown;
  readonly binding: DeviceLinkingGatewayRequestBindingV1;
};

export type DeviceLinkingGatewayAuthDeniedV1 = {
  readonly kind: 'denied';
  readonly code: 'unauthorized' | 'expired' | 'invalid' | 'replayed';
  readonly message: string;
};

export type DeviceLinkingGatewayCompletionServiceV1 = {
  readonly sessionService: Pick<
    LinkedDeviceSessionServiceV1,
    'markCommittedCompletionRequiredV1' | 'recordAggregateActivationV1'
  >;
  readonly nowV1: () => number;
  authenticateGatewayRequestV1(input: {
    readonly request: Request;
    readonly method: string;
    readonly pathname: string;
    readonly bodyDigestB64u: DigestB64u;
    readonly requestedAtMs: number;
  }): Promise<
    | DeviceLinkingGatewayAuthenticatedRequestV1
    | DeviceLinkingGatewayAuthDeniedV1
  >;
};

type GatewayCommitRequestV1 = {
  readonly kind: 'linked_device_gateway_commit_request_v1';
  readonly linkSessionId: LinkDeviceSessionId;
  readonly expectedRevision: number;
  readonly transcriptSetDigestB64u: DigestB64u;
  readonly requestedAtMs: number;
};

type GatewayActivationRequestV1 = {
  readonly kind: 'linked_device_gateway_activation_request_v1';
  readonly linkSessionId: LinkDeviceSessionId;
  readonly expectedRevision: number;
  readonly receipt: LinkedDeviceEnrollmentReceiptV1;
  readonly requestedAtMs: number;
};

type GatewayCompletionRequestV1 = GatewayCommitRequestV1 | GatewayActivationRequestV1;

export async function handleDeviceLinkingGatewayCompletion(
  ctx: FetchRouterApiContext,
  service: DeviceLinkingGatewayCompletionServiceV1,
): Promise<Response | null> {
  let action: ReturnType<typeof parseGatewayCompletionPath>;
  try {
    action = parseGatewayCompletionPath(ctx.pathname);
  } catch (error: unknown) {
    return json(
      { ok: false, outcome: 'invalid_input', message: error instanceof Error ? error.message : String(error) },
      { status: 400 },
    );
  }
  if (!action) return null;
  const nowMs = service.nowV1();
  try {
    if (ctx.method !== 'POST') return methodNotAllowedResponse();
    const bodyDigestB64u = await requestBodyDigest(ctx.request);
    const authentication = await service.authenticateGatewayRequestV1({
      request: ctx.request,
      method: ctx.method,
      pathname: ctx.pathname,
      bodyDigestB64u,
      requestedAtMs: nowMs,
    });
    if (authentication.kind === 'denied') return authDeniedResponse(authentication);
    validateGatewayBinding(authentication.binding, ctx.method, ctx.pathname, bodyDigestB64u, nowMs);
    const body = parseBoundary(() => parseGatewayRequest(authentication.body));
    if (body.linkSessionId !== action.linkSessionId) {
      throw new GatewayCompletionInputError('link session id does not match the route');
    }
    if (body.requestedAtMs > nowMs) {
      throw new GatewayCompletionInputError('completion request is from the future');
    }
    if (action.kind === 'commit') {
      if (body.kind !== 'linked_device_gateway_commit_request_v1') {
        throw new GatewayCompletionInputError('gateway completion request kind is invalid');
      }
      const result = await service.sessionService.markCommittedCompletionRequiredV1({
        linkSessionId: body.linkSessionId,
        expectedRevision: body.expectedRevision,
        transcriptSetDigestB64u: body.transcriptSetDigestB64u,
        nowMs: body.requestedAtMs,
      });
      return commitResultResponse(result);
    }
    if (body.kind !== 'linked_device_gateway_activation_request_v1') {
      throw new GatewayCompletionInputError('gateway activation request kind is invalid');
    }
    const result = await service.sessionService.recordAggregateActivationV1({
      linkSessionId: body.linkSessionId,
      expectedRevision: body.expectedRevision,
      receipt: body.receipt,
      nowMs: body.requestedAtMs,
    });
    return activationResultResponse(result);
  } catch (error: unknown) {
    if (error instanceof GatewayCompletionInputError) {
      return json({ ok: false, outcome: 'invalid_input', message: error.message }, { status: 400 });
    }
    return json(
      { ok: false, outcome: 'internal', message: error instanceof Error ? error.message : String(error) },
      { status: 500 },
    );
  }
}

function parseGatewayCompletionPath(
  pathname: string,
): { readonly kind: 'commit' | 'activate'; readonly linkSessionId: LinkDeviceSessionId } | null {
  const prefix = `${LINKED_DEVICE_GATEWAY_COMPLETION_BASE_V1}/`;
  if (!pathname.startsWith(prefix)) return null;
  const parts = pathname.slice(prefix.length).split('/');
  if (parts.length !== 2 || !parts[0] || (parts[1] !== 'commit' && parts[1] !== 'activate')) {
    return null;
  }
  let rawSessionId: string;
  try {
    rawSessionId = decodeURIComponent(parts[0]);
  } catch {
    throw new GatewayCompletionInputError('link session id is invalid');
  }
  const parsed = parseLinkDeviceSessionId(rawSessionId);
  if (!parsed.ok) throw new GatewayCompletionInputError('link session id is invalid');
  return { kind: parts[1], linkSessionId: parsed.value };
}

function parseBoundary<T>(parse: () => T): T {
  try {
    return parse();
  } catch (error: unknown) {
    if (error instanceof GatewayCompletionInputError) throw error;
    throw new GatewayCompletionInputError(error instanceof Error ? error.message : String(error));
  }
}

function parseGatewayRequest(raw: unknown): GatewayCompletionRequestV1 {
  const record = requireRecord(raw, 'gateway completion request');
  const kind = requireString(record.kind, 'gateway completion request kind');
  if (kind === 'linked_device_gateway_commit_request_v1') {
    requireExactKeys(record, ['kind', 'linkSessionId', 'expectedRevision', 'transcriptSetDigestB64u', 'requestedAtMs']);
    return {
      kind,
      linkSessionId: parseSessionId(record.linkSessionId),
      expectedRevision: parseRevision(record.expectedRevision),
      transcriptSetDigestB64u: parseDigest(record.transcriptSetDigestB64u),
      requestedAtMs: parseTimestamp(record.requestedAtMs, 'requestedAtMs'),
    };
  }
  if (kind === 'linked_device_gateway_activation_request_v1') {
    requireExactKeys(record, ['kind', 'linkSessionId', 'expectedRevision', 'receipt', 'requestedAtMs']);
    return {
      kind,
      linkSessionId: parseSessionId(record.linkSessionId),
      expectedRevision: parseRevision(record.expectedRevision),
      receipt: parseLinkedDeviceEnrollmentReceiptV1(record.receipt),
      requestedAtMs: parseTimestamp(record.requestedAtMs, 'requestedAtMs'),
    };
  }
  throw new GatewayCompletionInputError('gateway completion request kind is invalid');
}

function commitResultResponse(result: LinkedDeviceSessionServiceResultV1): Response {
  switch (result.outcome) {
    case 'applied':
    case 'replayed':
      return json(
        {
          ok: true,
          outcome: result.outcome,
          state: result.record.state,
          revision: result.record.revision,
          updatedAtMs: result.record.updatedAtMs,
        },
        { status: 200 },
      );
    case 'conflict':
      return json({ ok: false, outcome: result.outcome, expectedRevision: result.expectedRevision, actualRevision: result.actualRevision }, { status: 409 });
    case 'expired':
      return json({ ok: false, outcome: result.outcome, state: result.record.state }, { status: 410 });
    case 'invalid_state':
      return json({ ok: false, outcome: result.outcome, state: result.state }, { status: 409 });
    case 'invalid_input':
      return json({ ok: false, outcome: result.outcome, message: result.message }, { status: 400 });
    case 'unauthorized':
      return json({ ok: false, outcome: result.outcome, code: result.code, message: result.message }, { status: 401 });
    default:
      return assertNever(result);
  }
}

function activationResultResponse(result: LinkedDeviceSessionServiceResultV1): Response {
  switch (result.outcome) {
    case 'applied':
    case 'replayed':
      if (!result.record.aggregateReceipt) {
        return json({ ok: false, outcome: 'invalid_state', state: result.record.state.state }, { status: 409 });
      }
      return json(
        { ok: true, outcome: result.outcome, receipt: result.record.aggregateReceipt },
        { status: 200 },
      );
    case 'conflict':
      return json({ ok: false, outcome: result.outcome, expectedRevision: result.expectedRevision, actualRevision: result.actualRevision }, { status: 409 });
    case 'expired':
      return json({ ok: false, outcome: result.outcome, state: result.record.state }, { status: 410 });
    case 'invalid_state':
      return json({ ok: false, outcome: result.outcome, state: result.state }, { status: 409 });
    case 'invalid_input':
      return json({ ok: false, outcome: result.outcome, message: result.message }, { status: 400 });
    case 'unauthorized':
      return json({ ok: false, outcome: result.outcome, code: result.code, message: result.message }, { status: 401 });
    default:
      return assertNever(result);
  }
}

function validateGatewayBinding(
  binding: DeviceLinkingGatewayRequestBindingV1,
  method: string,
  pathname: string,
  bodyDigestB64u: DigestB64u,
  nowMs: number,
): void {
  if (
    binding.kind !== 'linked_device_gateway_request_binding_v1' ||
    binding.method !== method ||
    binding.pathname !== pathname ||
    binding.bodyDigestB64u !== bodyDigestB64u ||
    binding.expiresAtMs <= nowMs
  ) {
    throw new GatewayCompletionInputError('gateway request binding is invalid or expired');
  }
}

async function requestBodyDigest(request: Request): Promise<DigestB64u> {
  return parseDigest(base64UrlEncode(await sha256Bytes(new Uint8Array(await request.clone().arrayBuffer()))));
}

function parseSessionId(raw: unknown): LinkDeviceSessionId {
  const parsed = parseLinkDeviceSessionId(raw);
  if (!parsed.ok) throw new GatewayCompletionInputError('link session id is invalid');
  return parsed.value;
}

function parseDigest(raw: unknown): DigestB64u {
  try {
    return parseDigestB64u(raw);
  } catch (error: unknown) {
    throw new GatewayCompletionInputError(error instanceof Error ? error.message : 'digest is invalid');
  }
}

function parseRevision(raw: unknown): number {
  if (typeof raw !== 'number' || !Number.isSafeInteger(raw) || raw < 1) {
    throw new GatewayCompletionInputError('expectedRevision is invalid');
  }
  return raw;
}

function parseTimestamp(raw: unknown, field: string): number {
  if (typeof raw !== 'number' || !Number.isSafeInteger(raw) || raw <= 0) {
    throw new GatewayCompletionInputError(`${field} is invalid`);
  }
  return raw;
}

function requireRecord(raw: unknown, label: string): Record<string, unknown> {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new GatewayCompletionInputError(`${label} must be an object`);
  }
  return raw as Record<string, unknown>;
}

function requireString(raw: unknown, field: string): string {
  if (typeof raw !== 'string' || !raw || raw.trim() !== raw) {
    throw new GatewayCompletionInputError(`${field} is invalid`);
  }
  return raw;
}

function requireExactKeys(record: Record<string, unknown>, keys: readonly string[]): void {
  const actual = Object.keys(record).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new GatewayCompletionInputError('gateway completion request fields are invalid');
  }
}

function authDeniedResponse(result: DeviceLinkingGatewayAuthDeniedV1): Response {
  return json(
    { ok: false, outcome: 'unauthorized', code: result.code, message: result.message },
    { status: result.code === 'expired' ? 410 : 401 },
  );
}

function methodNotAllowedResponse(): Response {
  return json({ ok: false, outcome: 'method_not_allowed' }, { status: 405 });
}

function assertNever(value: never): never {
  throw new Error(`unsupported gateway completion result: ${String(value)}`);
}

class GatewayCompletionInputError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'GatewayCompletionInputError';
  }
}
