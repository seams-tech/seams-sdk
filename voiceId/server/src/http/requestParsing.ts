import {
  buildAudioInput,
  defaultVoiceIdAudioLivenessPolicy,
  parseEnrollmentId,
  parseIsoDateTime,
  parseJsonObject,
  parsePromptPhrase,
  parseUserId,
  parseVerificationId,
  parseVoiceIdAudioMetadata,
  parseVoiceIdIntentDigest,
  parseVoiceIdPolicyVersion,
  type VoiceIdAudioCaptureSource,
  type VoiceIdAudioLivenessPolicy,
  type VoiceIdAudioLivenessSignals,
  type VoiceIdAudioReplayRisk,
  type VoiceIdAuthPolicyUseCase,
  type VoiceIdIntentDigest,
  type VoiceIdLocalDeviceContext,
  type VoiceIdPolicyVersion,
  type VoiceIdVerificationId,
} from '../../../shared/src/index.ts';
import type {
  VoiceIdEnrollmentSample,
  VoiceIdVerificationSample,
} from '../../../shared/src/samples.ts';

export type ParsedOwnerPresenceAuthorizationRequest = {
  verificationId: VoiceIdVerificationId;
  intentDigest: VoiceIdIntentDigest;
  useCase: VoiceIdAuthPolicyUseCase;
  policyVersion: VoiceIdPolicyVersion;
  audio: VoiceIdAudioLivenessSignals;
  context: VoiceIdLocalDeviceContext;
  policy: VoiceIdAudioLivenessPolicy;
};

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

export async function parseOwnerPresenceAuthorizationRequest(
  request: Request,
): Promise<ParsedOwnerPresenceAuthorizationRequest> {
  const body = await parseJsonRequest(request);

  return {
    verificationId: parseVerificationId(body.verificationId),
    intentDigest: parseVoiceIdIntentDigest(body.intentDigest),
    useCase: parseAuthPolicyUseCase(body.useCase),
    policyVersion: parseVoiceIdPolicyVersion(body.policyVersion),
    audio: parseAudioLivenessSignals(body.audio),
    context: parseLocalDeviceContext(body.context),
    policy: parseAudioLivenessPolicy(body.policy),
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

function parseAudioLivenessSignals(value: unknown): VoiceIdAudioLivenessSignals {
  const input = parseJsonObject(value, 'audio');
  assertKind(input.kind, 'audio_liveness_signals_v1', 'audio.kind');

  return {
    kind: 'audio_liveness_signals_v1',
    promptOpenedAt: parseIsoDateTime(input.promptOpenedAt),
    speechStartedAt: parseIsoDateTime(input.speechStartedAt),
    speechEndedAt: parseIsoDateTime(input.speechEndedAt),
    captureSource: parseAudioCaptureSource(input.captureSource),
    replayRisk: parseAudioReplayRisk(input.replayRisk),
  };
}

function parseAudioCaptureSource(value: unknown): VoiceIdAudioCaptureSource {
  const input = parseJsonObject(value, 'audio.captureSource');
  switch (input.kind) {
    case 'trusted_microphone':
      return {
        kind: 'trusted_microphone',
        deviceId: parseString(input.deviceId, 'audio.captureSource.deviceId'),
      };
    case 'unknown_microphone':
      return {
        kind: 'unknown_microphone',
        reason: parseUnknownMicrophoneReason(input.reason),
      };
    case 'loopback_or_speaker':
      return {
        kind: 'loopback_or_speaker',
        reason: parseLoopbackOrSpeakerReason(input.reason),
      };
    default:
      throw new Error('audio.captureSource.kind is invalid');
  }
}

function parseAudioReplayRisk(value: unknown): VoiceIdAudioReplayRisk {
  const input = parseJsonObject(value, 'audio.replayRisk');
  switch (input.kind) {
    case 'low':
      return { kind: 'low' };
    case 'high':
      return {
        kind: 'high',
        reason: parseHighReplayRiskReason(input.reason),
      };
    case 'uncertain':
      return {
        kind: 'uncertain',
        reason: parseUncertainReplayRiskReason(input.reason),
      };
    default:
      throw new Error('audio.replayRisk.kind is invalid');
  }
}

function parseLocalDeviceContext(value: unknown): VoiceIdLocalDeviceContext {
  const input = parseJsonObject(value, 'context');
  assertKind(input.kind, 'local_device_context_v1', 'context.kind');

  return {
    kind: 'local_device_context_v1',
    deviceId: parseString(input.deviceId, 'context.deviceId'),
    sidecarId: parseString(input.sidecarId, 'context.sidecarId'),
    captureStartedAt: parseIsoDateTime(input.captureStartedAt),
    evaluatedAt: parseIsoDateTime(input.evaluatedAt),
    localPolicyVersion: parseString(input.localPolicyVersion, 'context.localPolicyVersion'),
  };
}

function parseAudioLivenessPolicy(value: unknown): VoiceIdAudioLivenessPolicy {
  if (value === undefined) {
    return defaultVoiceIdAudioLivenessPolicy();
  }

  const input = parseJsonObject(value, 'policy');
  assertKind(input.kind, 'audio_liveness_policy_v1', 'policy.kind');

  return {
    kind: 'audio_liveness_policy_v1',
    minSpeechDurationMs: parsePositiveNumber(input.minSpeechDurationMs, 'policy.minSpeechDurationMs'),
    maxSpeechDurationMs: parsePositiveNumber(input.maxSpeechDurationMs, 'policy.maxSpeechDurationMs'),
    maxPromptToSpeechStartMs: parsePositiveNumber(
      input.maxPromptToSpeechStartMs,
      'policy.maxPromptToSpeechStartMs',
    ),
    requireTrustedMicrophone: parseBoolean(input.requireTrustedMicrophone, 'policy.requireTrustedMicrophone'),
  };
}

function parseAuthPolicyUseCase(value: unknown): VoiceIdAuthPolicyUseCase {
  switch (value) {
    case 'wallet_mpc_signing':
    case 'wallet_session':
    case 'robot_command':
      return value;
    default:
      throw new Error('useCase is invalid');
  }
}

function parseUnknownMicrophoneReason(
  value: unknown,
): Extract<VoiceIdAudioCaptureSource, { kind: 'unknown_microphone' }>['reason'] {
  switch (value) {
    case 'browser_device_label_unavailable':
    case 'robot_source_unattested':
      return value;
    default:
      throw new Error('audio.captureSource.reason is invalid');
  }
}

function parseLoopbackOrSpeakerReason(
  value: unknown,
): Extract<VoiceIdAudioCaptureSource, { kind: 'loopback_or_speaker' }>['reason'] {
  switch (value) {
    case 'loopback_device':
    case 'speaker_playback_detected':
      return value;
    default:
      throw new Error('audio.captureSource.reason is invalid');
  }
}

function parseHighReplayRiskReason(value: unknown): Extract<VoiceIdAudioReplayRisk, { kind: 'high' }>['reason'] {
  switch (value) {
    case 'reused_capture_hash':
    case 'synthetic_artifacts':
    case 'channel_replay_artifacts':
      return value;
    default:
      throw new Error('audio.replayRisk.reason is invalid');
  }
}

function parseUncertainReplayRiskReason(
  value: unknown,
): Extract<VoiceIdAudioReplayRisk, { kind: 'uncertain' }>['reason'] {
  switch (value) {
    case 'missing_source_attestation':
    case 'channel_artifacts_unclear':
      return value;
    default:
      throw new Error('audio.replayRisk.reason is invalid');
  }
}

function assertKind(value: unknown, expected: string, fieldName: string): void {
  if (value !== expected) {
    throw new Error(`${fieldName} must be ${expected}`);
  }
}

function parseString(value: unknown, fieldName: string): string {
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new Error(`${fieldName} must be a non-empty string`);
  }

  return value;
}

function parsePositiveNumber(value: unknown, fieldName: string): number {
  if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0) {
    throw new Error(`${fieldName} must be a positive number`);
  }

  return value;
}

function parseBoolean(value: unknown, fieldName: string): boolean {
  if (typeof value !== 'boolean') {
    throw new Error(`${fieldName} must be a boolean`);
  }

  return value;
}

function getErrorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
