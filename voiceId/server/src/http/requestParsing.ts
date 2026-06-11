import {
  buildAudioInput,
  parseEnrollmentId,
  parseJsonObject,
  parsePromptPhrase,
  parseUserId,
  parseVerificationId,
  parseVoiceIdAudioMetadata,
  type VoiceIdAudioInput,
} from '../../../shared/src/index.ts';
import type {
  VoiceIdEnrollmentSample,
  VoiceIdVerificationSample,
} from '../../../shared/src/samples.ts';

export async function parseJsonRequest(request: Request): Promise<Record<string, unknown>> {
  try {
    return parseJsonObject(await request.json(), 'request body');
  } catch (error) {
    throw new Error(`invalid JSON request: ${getErrorMessage(error)}`);
  }
}

export async function parseEnrollmentSampleRequest(request: Request): Promise<VoiceIdEnrollmentSample> {
  const form = await parseFormData(request);
  const metadata = parseVoiceIdAudioMetadata(parseJsonFormField(form, 'metadata'));
  const bytes = await parseAudioBytes(form);
  const fields = parseJsonObject(parseJsonFormField(form, 'fields'), 'fields');

  return {
    userId: parseUserId(fields.userId),
    enrollmentId: parseEnrollmentId(fields.enrollmentId),
    expectedPhrase: parsePromptPhrase(fields.expectedPhrase),
    spokenPhrase: parsePromptPhrase(fields.spokenPhrase),
    attemptNumber: parseAttemptNumber(fields.attemptNumber),
    audio: buildAudioInput(bytes, metadata),
  };
}

export async function parseVerificationSampleRequest(request: Request): Promise<VoiceIdVerificationSample> {
  const form = await parseFormData(request);
  const metadata = parseVoiceIdAudioMetadata(parseJsonFormField(form, 'metadata'));
  const bytes = await parseAudioBytes(form);
  const fields = parseJsonObject(parseJsonFormField(form, 'fields'), 'fields');

  return {
    userId: parseUserId(fields.userId),
    enrollmentId: parseEnrollmentId(fields.enrollmentId),
    verificationId: parseVerificationId(fields.verificationId),
    expectedPhrase: parsePromptPhrase(fields.expectedPhrase),
    spokenPhrase: parsePromptPhrase(fields.spokenPhrase),
    attemptNumber: parseAttemptNumber(fields.attemptNumber),
    audio: buildAudioInput(bytes, metadata),
  };
}

async function parseFormData(request: Request): Promise<FormData> {
  try {
    return await request.formData();
  } catch (error) {
    throw new Error(`invalid multipart request: ${getErrorMessage(error)}`);
  }
}

function parseJsonFormField(form: FormData, fieldName: string): unknown {
  const value = form.get(fieldName);
  if (typeof value !== 'string') {
    throw new Error(`${fieldName} must be a JSON string form field`);
  }

  return JSON.parse(value) as unknown;
}

async function parseAudioBytes(form: FormData): Promise<Uint8Array> {
  const audio = form.get('audio');
  if (!(audio instanceof Blob)) {
    throw new Error('audio must be a Blob form field');
  }

  return new Uint8Array(await audio.arrayBuffer());
}

function parseAttemptNumber(value: unknown): number {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 1) {
    throw new Error('attemptNumber must be a positive integer');
  }

  return value;
}

function getErrorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
