import {
  VoiceIdService,
  type StartEnrollmentResult,
  type StartVerificationResult,
  type SubmitEnrollmentRecordingResult,
  type VoiceIdServiceError,
} from './VoiceIdService.ts';
import { jsonResponse, serviceResultResponse } from './http/jsonResponses.ts';
import {
  parseEnrollmentDisableRequest,
  parseEnrollmentRecordingRequest,
  parseEnrollmentStartRequest,
  parseVerificationRecordingRequest,
  parseVerificationStartRequest,
} from './http/requestParsing.ts';
import {
  assertNever,
  type VoiceIdEnrollmentDisableApiValue,
  type VoiceIdEnrollmentRecord,
  type VoiceIdEnrollmentStartApiValue,
  type VoiceIdEnrollmentSubmitApiValue,
  type VoiceIdVerificationResult,
  type VoiceIdVerificationStartApiValue,
} from '../../shared/src/index.ts';

export type VoiceIdFetchHandler = (request: Request) => Promise<Response>;

export type VoiceIdHttpSecurityConfig = {
  allowedOrigins: readonly string[];
};

type VoiceIdHttpContext = {
  service: VoiceIdService;
  allowedOrigins: ReadonlySet<string>;
};

export function createVoiceIdFetchHandler(
  service: VoiceIdService,
  security: VoiceIdHttpSecurityConfig,
): VoiceIdFetchHandler {
  const context: VoiceIdHttpContext = {
    service,
    allowedOrigins: parseAllowedOrigins(security.allowedOrigins),
  };
  return handleVoiceIdRequest.bind(null, context);
}

async function handleVoiceIdRequest(
  context: VoiceIdHttpContext,
  request: Request,
): Promise<Response> {
  const origin = request.headers.get('Origin');
  if (origin !== null && !context.allowedOrigins.has(origin)) {
    return jsonResponse(
      {
        kind: 'error',
        error: { kind: 'origin_forbidden', message: 'request origin is not allowed' },
      },
      403,
    );
  }
  try {
    const response = await dispatchVoiceIdRequest(context.service, request);
    return origin === null ? response : addCorsHeaders(response, origin);
  } catch (error) {
    const serviceError: VoiceIdServiceError = {
      kind: 'malformed_request',
      message: error instanceof Error ? error.message : String(error),
    };
    const response = jsonResponse({ kind: 'error', error: serviceError }, 400);
    return origin === null ? response : addCorsHeaders(response, origin);
  }
}

async function dispatchVoiceIdRequest(
  service: VoiceIdService,
  request: Request,
): Promise<Response> {
  const url = new URL(request.url);
  if (request.method === 'OPTIONS') {
    return jsonResponse({ kind: 'ok' });
  }
  if (
    request.method === 'GET' &&
    (url.pathname === '/' || url.pathname === '/health' || url.pathname === '/voice-id/health')
  ) {
    return jsonResponse({
      kind: 'ok',
      service: 'voice-id-e0-evidence-api',
      evidenceTier: 'experimental_browser_evidence',
      signingEligible: false,
      routes: [
        'POST /voice-id/evidence/enrollment/start',
        'POST /voice-id/evidence/enrollment/recording',
        'POST /voice-id/evidence/enrollment/disable',
        'POST /voice-id/evidence/verification/start',
        'POST /voice-id/evidence/verification/recording',
      ],
    });
  }
  if (request.method === 'POST' && url.pathname === '/voice-id/evidence/enrollment/start') {
    const input = await parseEnrollmentStartRequest(request);
    return serviceResultResponse(await service.startEnrollment(input), serializeEnrollmentStart);
  }
  if (request.method === 'POST' && url.pathname === '/voice-id/evidence/enrollment/recording') {
    const recording = await parseEnrollmentRecordingRequest(request);
    return serviceResultResponse(
      await service.submitEnrollmentRecording(recording),
      serializeEnrollmentSubmission,
    );
  }
  if (request.method === 'POST' && url.pathname === '/voice-id/evidence/enrollment/disable') {
    const input = await parseEnrollmentDisableRequest(request);
    return serviceResultResponse(
      await service.disableEnrollment(input),
      serializeEnrollmentDisable,
    );
  }
  if (request.method === 'POST' && url.pathname === '/voice-id/evidence/verification/start') {
    const input = await parseVerificationStartRequest(request);
    return serviceResultResponse(
      await service.startVerification(input),
      serializeVerificationStart,
    );
  }
  if (request.method === 'POST' && url.pathname === '/voice-id/evidence/verification/recording') {
    const recording = await parseVerificationRecordingRequest(request);
    return serviceResultResponse(
      await service.submitVerificationRecording(recording),
      serializeVerificationSubmission,
    );
  }
  return jsonResponse(
    {
      kind: 'error',
      error: { kind: 'not_found', message: 'VoiceID route does not exist' },
    },
    404,
  );
}

function serializeEnrollmentStart(value: StartEnrollmentResult): VoiceIdEnrollmentStartApiValue {
  return {
    enrollmentId: value.record.enrollmentId,
    promptSetId: value.record.promptSetId,
    promptSequence: value.record.promptSequence,
    modelVersion: value.record.modelVersion,
    expiresAt: value.record.expiresAt,
    minimumCaptureMs: value.record.minimumCaptureMs,
    targetCaptureMs: value.record.targetCaptureMs,
    maximumCaptureMs: value.record.maximumCaptureMs,
  };
}

function serializeEnrollmentSubmission(
  value: SubmitEnrollmentRecordingResult,
): VoiceIdEnrollmentSubmitApiValue {
  switch (value.kind) {
    case 'enrolled':
      return {
        kind: 'enrolled',
        enrollmentId: value.record.enrollmentId,
        modelVersion: value.record.modelVersion,
        templateVersion: value.record.templateVersion,
        thresholdVersion: value.record.thresholdVersion,
        enrolledAt: value.record.enrolledAt,
        quality: value.quality,
        phrase: value.phrase,
      };
    case 'rejected':
      return {
        kind: 'rejected',
        enrollmentId: value.record.enrollmentId,
        failedAt: value.record.failedAt,
        reason: value.reason,
      };
    default:
      return assertNever(value);
  }
}

function serializeEnrollmentDisable(
  value: Extract<VoiceIdEnrollmentRecord, { state: 'disabled' }>,
): VoiceIdEnrollmentDisableApiValue {
  return {
    kind: 'disabled',
    enrollmentId: value.enrollmentId,
    disabledAt: value.disabledAt,
  };
}

function serializeVerificationStart(
  value: StartVerificationResult,
): VoiceIdVerificationStartApiValue {
  return {
    enrollmentId: value.record.enrollmentId,
    verificationId: value.record.verificationId,
    prompt: value.prompt,
    expiresAt: value.record.expiresAt,
  };
}

function serializeVerificationSubmission(
  value: VoiceIdVerificationResult,
): VoiceIdVerificationResult {
  return value;
}

function parseAllowedOrigins(origins: readonly string[]): ReadonlySet<string> {
  const parsed = new Set<string>();
  for (const origin of origins) {
    const normalized = new URL(origin).origin;
    if (normalized !== origin) throw new Error(`allowed origin must be canonical: ${origin}`);
    parsed.add(normalized);
  }
  return parsed;
}

function addCorsHeaders(response: Response, origin: string): Response {
  const headers = new Headers(response.headers);
  headers.set('Access-Control-Allow-Origin', origin);
  headers.set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  headers.set('Access-Control-Allow-Headers', 'Content-Type');
  headers.append('Vary', 'Origin');
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}
