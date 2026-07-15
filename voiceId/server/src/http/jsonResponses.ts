import type { VoiceIdServiceError, VoiceIdServiceResult } from '../VoiceIdService.ts';
import { assertNever } from '../../../shared/src/assertNever.ts';

export function jsonResponse(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: {
      'Content-Type': 'application/json',
    },
  });
}

export function serviceResultResponse<TValue>(
  result: VoiceIdServiceResult<TValue>,
  serialize: (value: TValue) => unknown,
): Response {
  if (result.kind === 'ok') {
    return jsonResponse({ kind: 'ok', value: serialize(result.value) });
  }

  return jsonResponse({ kind: 'error', error: result.error }, statusForServiceError(result.error));
}

export function statusForServiceError(error: VoiceIdServiceError): number {
  switch (error.kind) {
    case 'malformed_request':
      return 400;
    case 'missing_enrollment':
    case 'missing_verification':
      return 404;
    case 'invalid_state':
    case 'identity_mismatch':
    case 'expired':
      return 409;
    default:
      return assertNever(error);
  }
}
