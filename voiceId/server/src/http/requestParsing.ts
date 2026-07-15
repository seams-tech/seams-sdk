import {
  assertExactObjectKeys,
  buildAudioInput,
  parseEnrollmentId,
  parseJsonObject,
  parseUserId,
  parseVerificationId,
  parseVoiceIdAudioMetadata,
} from '../../../shared/src/index.ts';
import type {
  VoiceIdEnrollmentRecording,
  VoiceIdVerificationRecording,
} from '../../../shared/src/samples.ts';

const maximumVoiceIdAudioByteLength = 32 * 1024 * 1024;

export async function parseJsonRequest(request: Request): Promise<Record<string, unknown>> {
  try {
    return parseJsonObject(await request.json(), 'request body');
  } catch (error) {
    throw new Error(`invalid JSON request: ${getErrorMessage(error)}`);
  }
}

export async function parseEnrollmentStartRequest(request: Request): Promise<{ userId: ReturnType<typeof parseUserId> }> {
  const body = await parseJsonRequest(request);
  assertExactObjectKeys(body, ['userId'], 'enrollment start request');
  return { userId: parseUserId(body.userId) };
}

export async function parseEnrollmentDisableRequest(request: Request): Promise<{
  userId: ReturnType<typeof parseUserId>;
  enrollmentId: ReturnType<typeof parseEnrollmentId>;
}> {
  const body = await parseJsonRequest(request);
  assertExactObjectKeys(body, ['userId', 'enrollmentId'], 'enrollment disable request');
  return {
    userId: parseUserId(body.userId),
    enrollmentId: parseEnrollmentId(body.enrollmentId),
  };
}

export async function parseVerificationStartRequest(request: Request): Promise<{
  userId: ReturnType<typeof parseUserId>;
  enrollmentId: ReturnType<typeof parseEnrollmentId>;
}> {
  const body = await parseJsonRequest(request);
  assertExactObjectKeys(body, ['userId', 'enrollmentId'], 'verification start request');
  return {
    userId: parseUserId(body.userId),
    enrollmentId: parseEnrollmentId(body.enrollmentId),
  };
}

export async function parseEnrollmentRecordingRequest(
  request: Request,
): Promise<VoiceIdEnrollmentRecording> {
  const form = await parseFormData(request);
  const metadata = parseVoiceIdAudioMetadata(parseJsonFormField(form, 'metadata'));
  const bytes = await parseAudioBytes(form);
  const fields = parseJsonObject(parseJsonFormField(form, 'fields'), 'fields');
  assertExactObjectKeys(fields, ['userId', 'enrollmentId'], 'enrollment recording fields');
  return {
    userId: parseUserId(fields.userId),
    enrollmentId: parseEnrollmentId(fields.enrollmentId),
    audio: buildAudioInput(bytes, metadata),
  };
}

export async function parseVerificationRecordingRequest(
  request: Request,
): Promise<VoiceIdVerificationRecording> {
  const form = await parseFormData(request);
  const metadata = parseVoiceIdAudioMetadata(parseJsonFormField(form, 'metadata'));
  const bytes = await parseAudioBytes(form);
  const fields = parseJsonObject(parseJsonFormField(form, 'fields'), 'fields');
  assertExactObjectKeys(
    fields,
    ['userId', 'enrollmentId', 'verificationId'],
    'verification recording fields',
  );
  return {
    userId: parseUserId(fields.userId),
    enrollmentId: parseEnrollmentId(fields.enrollmentId),
    verificationId: parseVerificationId(fields.verificationId),
    audio: buildAudioInput(bytes, metadata),
  };
}

async function parseFormData(request: Request): Promise<FormData> {
  try {
    const form = await request.formData();
    assertExactFormFields(form);
    return form;
  } catch (error) {
    throw new Error(`invalid multipart request: ${getErrorMessage(error)}`);
  }
}

function assertExactFormFields(form: FormData): void {
  const allowed = new Set(['audio', 'metadata', 'fields']);
  const counts = new Map<string, number>();
  for (const key of form.keys()) {
    if (!allowed.has(key)) throw new Error(`multipart request contains unexpected field: ${key}`);
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  for (const key of allowed) {
    if (counts.get(key) !== 1) throw new Error(`multipart request must contain exactly one ${key} field`);
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
  if (audio.size <= 0 || audio.size > maximumVoiceIdAudioByteLength) {
    throw new Error(`audio byte length must be between 1 and ${maximumVoiceIdAudioByteLength}`);
  }
  return new Uint8Array(await audio.arrayBuffer());
}

function getErrorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
