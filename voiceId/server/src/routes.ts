import {
  parseEnrollmentId,
  parsePromptPhrase,
  parseUserId,
} from '../../shared/src/index.ts';
import { VoiceIdService, type VoiceIdServiceError } from './VoiceIdService.ts';
import { jsonResponse, serviceResultResponse } from './http/jsonResponses.ts';
import {
  parseEnrollmentSampleRequest,
  parseJsonRequest,
  parseVerificationSampleRequest,
} from './http/requestParsing.ts';

export type VoiceIdFetchHandler = (request: Request) => Promise<Response>;

export function createVoiceIdFetchHandler(service: VoiceIdService): VoiceIdFetchHandler {
  return async (request: Request) => {
    const url = new URL(request.url);

    try {
      if (request.method === 'OPTIONS') {
        return jsonResponse({ kind: 'ok' });
      }

      if (request.method === 'GET' && (url.pathname === '/' || url.pathname === '/health')) {
        return jsonResponse({
          kind: 'ok',
          service: 'voice-id-api',
          demoUrl: 'http://127.0.0.1:5173/',
          routes: [
            'POST /voice-id/enrollment/start',
            'POST /voice-id/enrollment/sample',
            'POST /voice-id/enrollment/finalize',
            'POST /voice-id/enrollment/disable',
            'POST /voice-id/verification/start',
            'POST /voice-id/verification/sample',
          ],
        });
      }

      if (request.method === 'POST' && url.pathname === '/voice-id/enrollment/start') {
        const body = await parseJsonRequest(request);
        return serviceResultResponse(
          await service.startEnrollment({
            userId: parseUserId(body.userId),
            phrase: parsePromptPhrase(body.phrase),
          }),
        );
      }

      if (request.method === 'POST' && url.pathname === '/voice-id/enrollment/sample') {
        return serviceResultResponse(await service.addEnrollmentSample(await parseEnrollmentSampleRequest(request)));
      }

      if (request.method === 'POST' && url.pathname === '/voice-id/enrollment/finalize') {
        const body = await parseJsonRequest(request);
        return serviceResultResponse(
          await service.finalizeEnrollment({
            userId: parseUserId(body.userId),
            enrollmentId: parseEnrollmentId(body.enrollmentId),
          }),
        );
      }

      if (request.method === 'POST' && url.pathname === '/voice-id/enrollment/disable') {
        const body = await parseJsonRequest(request);
        return serviceResultResponse(
          await service.disableEnrollment({
            userId: parseUserId(body.userId),
            enrollmentId: parseEnrollmentId(body.enrollmentId),
          }),
        );
      }

      if (request.method === 'POST' && url.pathname === '/voice-id/verification/start') {
        const body = await parseJsonRequest(request);
        return serviceResultResponse(
          await service.startVerification({
            userId: parseUserId(body.userId),
            enrollmentId: parseEnrollmentId(body.enrollmentId),
            phrase: parsePromptPhrase(body.phrase),
          }),
        );
      }

      if (request.method === 'POST' && url.pathname === '/voice-id/verification/sample') {
        return serviceResultResponse(await service.verifySample(await parseVerificationSampleRequest(request)));
      }

      return jsonResponse({ kind: 'error', error: { kind: 'not_found' } }, 404);
    } catch (error) {
      const serviceError: VoiceIdServiceError = {
        kind: 'malformed_request',
        message: error instanceof Error ? error.message : String(error),
      };
      return jsonResponse({ kind: 'error', error: serviceError }, 400);
    }
  };
}
