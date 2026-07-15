import type { VoiceIdAudioQualityResult } from './audio.ts';
import {
  parseEnrollmentId,
  parseIsoDateTime,
  parseModelVersion,
  parseThresholdVersion,
  parseVerificationId,
} from './ids.ts';
import { assertExactObjectKeys, parseJsonObject } from './parsers.ts';
import type { VoiceIdEnrollmentRecord } from './records.ts';
import type {
  VoiceIdPhraseMatchResult,
  VoiceIdSpeakerMatchResult,
  VoiceIdVerificationChecks,
  VoiceIdVerificationResult,
} from './results.ts';

type JsonObject = Record<string, unknown>;

export function parseVoiceIdVerificationResult(value: unknown): VoiceIdVerificationResult {
  const result = parseJsonObject(value, 'verification result');
  switch (result.kind) {
    case 'evidence_observed':
      return parseEvidenceObservedObject(result);
    case 'rejected':
      return parseRejectedObject(result);
    case 'uncertain':
      return parseUncertainObject(result);
    default:
      throw new Error('verification result kind is invalid');
  }
}

export function parseVoiceIdEvidenceObservedResult(
  value: unknown,
): Extract<VoiceIdVerificationResult, { kind: 'evidence_observed' }> {
  return parseEvidenceObservedObject(parseJsonObject(value, 'evidence observed result'));
}

export function parseVoiceIdRejectedResult(
  value: unknown,
): Extract<VoiceIdVerificationResult, { kind: 'rejected' }> {
  return parseRejectedObject(parseJsonObject(value, 'rejected verification result'));
}

export function parseVoiceIdUncertainResult(
  value: unknown,
): Extract<VoiceIdVerificationResult, { kind: 'uncertain' }> {
  return parseUncertainObject(parseJsonObject(value, 'uncertain verification result'));
}

export function parseVoiceIdVerificationChecks(value: unknown): VoiceIdVerificationChecks {
  const checks = parseJsonObject(value, 'verification checks');
  assertExactObjectKeys(checks, ['phrase', 'speaker', 'quality'], 'verification checks');
  return {
    phrase: parseVoiceIdPhraseMatchResult(checks.phrase),
    speaker: parseVoiceIdSpeakerMatchResult(checks.speaker),
    quality: parseVoiceIdAudioQualityResult(checks.quality),
  };
}

export function parseVoiceIdPhraseMatchResult(value: unknown): VoiceIdPhraseMatchResult {
  const phrase = parseJsonObject(value, 'phrase result');
  const expectedNormalized = parseString(phrase.expectedNormalized, 'expectedNormalized');
  const spokenNormalized = parseStringAllowEmpty(phrase.spokenNormalized, 'spokenNormalized');
  const confidence = parseProbability(phrase.confidence, 'phrase confidence');
  switch (phrase.kind) {
    case 'accepted':
      assertExactObjectKeys(
        phrase,
        ['kind', 'expectedNormalized', 'spokenNormalized', 'confidence'],
        'accepted phrase result',
      );
      return { kind: 'accepted', expectedNormalized, spokenNormalized, confidence };
    case 'rejected':
      assertExactObjectKeys(
        phrase,
        ['kind', 'reason', 'expectedNormalized', 'spokenNormalized', 'confidence'],
        'rejected phrase result',
      );
      return {
        kind: 'rejected',
        reason: parseOneOf(
          phrase.reason,
          ['phrase_mismatch', 'ambiguous_transcript'],
          'phrase rejection',
        ),
        expectedNormalized,
        spokenNormalized,
        confidence,
      };
    case 'uncertain':
      assertExactObjectKeys(
        phrase,
        ['kind', 'reason', 'expectedNormalized', 'spokenNormalized', 'confidence'],
        'uncertain phrase result',
      );
      return {
        kind: 'uncertain',
        reason: parseOneOf(
          phrase.reason,
          ['transcript_low_confidence', 'transcript_unavailable'],
          'phrase uncertainty',
        ),
        expectedNormalized,
        spokenNormalized,
        confidence,
      };
    default:
      throw new Error('phrase result kind is invalid');
  }
}

export function parseVoiceIdSpeakerMatchResult(value: unknown): VoiceIdSpeakerMatchResult {
  const speaker = parseJsonObject(value, 'speaker result');
  const score = parseProbability(speaker.score, 'speaker score');
  const threshold = parseProbability(speaker.threshold, 'speaker threshold');
  const modelVersion = parseModelVersion(speaker.modelVersion);
  const thresholdVersion = parseThresholdVersion(speaker.thresholdVersion);
  switch (speaker.kind) {
    case 'accepted':
      assertExactObjectKeys(
        speaker,
        ['kind', 'score', 'threshold', 'modelVersion', 'thresholdVersion'],
        'accepted speaker result',
      );
      return { kind: 'accepted', score, threshold, modelVersion, thresholdVersion };
    case 'rejected':
      assertExactObjectKeys(
        speaker,
        ['kind', 'reason', 'score', 'threshold', 'modelVersion', 'thresholdVersion'],
        'rejected speaker result',
      );
      assertKind(speaker.reason, 'speaker_mismatch', 'speaker rejection');
      return {
        kind: 'rejected',
        reason: 'speaker_mismatch',
        score,
        threshold,
        modelVersion,
        thresholdVersion,
      };
    case 'uncertain':
      assertExactObjectKeys(
        speaker,
        ['kind', 'reason', 'score', 'threshold', 'modelVersion', 'thresholdVersion'],
        'uncertain speaker result',
      );
      return {
        kind: 'uncertain',
        reason: parseOneOf(
          speaker.reason,
          ['model_low_confidence', 'verifier_unavailable', 'low_audio_quality'],
          'speaker uncertainty',
        ),
        score,
        threshold,
        modelVersion,
        thresholdVersion,
      };
    default:
      throw new Error('speaker result kind is invalid');
  }
}

export function parseVoiceIdAudioQualityResult(value: unknown): VoiceIdAudioQualityResult {
  const quality = parseJsonObject(value, 'quality result');
  const durationMs = parsePositiveNumber(quality.durationMs, 'quality durationMs');
  switch (quality.kind) {
    case 'accepted':
      assertExactObjectKeys(
        quality,
        ['kind', 'durationMs', 'signalScore'],
        'accepted quality result',
      );
      return {
        kind: 'accepted',
        durationMs,
        signalScore: parseProbability(quality.signalScore, 'quality signalScore'),
      };
    case 'rejected':
      assertExactObjectKeys(quality, ['kind', 'durationMs', 'reason'], 'rejected quality result');
      return {
        kind: 'rejected',
        durationMs,
        reason: parseOneOf(quality.reason, ['too_short', 'empty_audio'], 'quality rejection'),
      };
    case 'uncertain':
      assertExactObjectKeys(quality, ['kind', 'durationMs', 'reason'], 'uncertain quality result');
      return {
        kind: 'uncertain',
        durationMs,
        reason: parseOneOf(
          quality.reason,
          [
            'noisy_audio',
            'too_short',
            'model_low_confidence',
            'verifier_unavailable',
            'undecodable_audio',
            'clipped_audio',
            'low_speech',
            'low_snr',
            'metadata_mismatch',
          ],
          'quality uncertainty',
        ),
      };
    default:
      throw new Error('quality result kind is invalid');
  }
}

export function parseVoiceIdEnrollmentFailureReason(
  value: unknown,
): Extract<VoiceIdEnrollmentRecord, { state: 'failed' }>['failureReason'] {
  return parseOneOf(
    value,
    [
      'expired',
      'capture_too_short',
      'capture_too_long',
      'phrase_rejected',
      'transcript_uncertain',
      'decoder_failure',
      'metadata_mismatch',
      'interrupted_capture',
      'insufficient_speech',
      'insufficient_windows',
      'duplicate_windows',
      'multi_speaker',
      'clipped_audio',
      'low_snr',
      'incoherent_windows',
      'template_build_failed',
      'analysis_timeout',
      'verifier_unavailable',
    ],
    'enrollment failure reason',
  );
}

function parseEvidenceObservedObject(
  result: JsonObject,
): Extract<VoiceIdVerificationResult, { kind: 'evidence_observed' }> {
  assertExactObjectKeys(result, ['kind', 'evidence'], 'evidence observed result');
  assertKind(result.kind, 'evidence_observed', 'verification result');
  const evidence = parseJsonObject(result.evidence, 'experimental browser evidence');
  assertExactObjectKeys(
    evidence,
    [
      'kind',
      'verificationId',
      'enrollmentId',
      'observedChecks',
      'modelVersion',
      'thresholdVersion',
      'completedAt',
    ],
    'experimental browser evidence',
  );
  assertKind(evidence.kind, 'experimental_browser_evidence', 'evidence');
  const checks = parseJsonObject(evidence.observedChecks, 'observed checks');
  assertExactObjectKeys(
    checks,
    ['phrase', 'speaker', 'quality', 'captureFreshness', 'pad', 'captureProfile'],
    'observed checks',
  );
  const phrase = parseVoiceIdPhraseMatchResult(checks.phrase);
  const speaker = parseVoiceIdSpeakerMatchResult(checks.speaker);
  const quality = parseVoiceIdAudioQualityResult(checks.quality);
  if (phrase.kind !== 'accepted' || speaker.kind !== 'accepted' || quality.kind !== 'accepted') {
    throw new Error('observed evidence requires accepted phrase, speaker, and quality checks');
  }
  const freshness = parseJsonObject(checks.captureFreshness, 'capture freshness');
  assertExactObjectKeys(
    freshness,
    ['kind', 'challengeIssuedAt', 'captureReceivedAt', 'serverVerifiedFreshness'],
    'capture freshness',
  );
  assertKind(freshness.kind, 'browser_timing_observation', 'capture freshness');
  if (freshness.serverVerifiedFreshness !== false) {
    throw new Error('experimental capture freshness must remain unverified');
  }
  const pad = parseJsonObject(checks.pad, 'pad result');
  assertExactObjectKeys(pad, ['kind', 'reason'], 'pad result');
  assertKind(pad.kind, 'pad_unavailable', 'pad result');
  assertKind(pad.reason, 'ordinary_browser_capture', 'pad reason');
  const captureProfile = parseJsonObject(checks.captureProfile, 'capture profile');
  assertExactObjectKeys(
    captureProfile,
    ['kind', 'source', 'microphoneIntegrity'],
    'capture profile',
  );
  assertKind(captureProfile.kind, 'ordinary_browser_capture', 'capture profile');
  assertKind(captureProfile.source, 'media_recorder', 'capture source');
  assertKind(captureProfile.microphoneIntegrity, 'unverified', 'microphone integrity');
  return {
    kind: 'evidence_observed',
    evidence: {
      kind: 'experimental_browser_evidence',
      verificationId: parseVerificationId(evidence.verificationId),
      enrollmentId: parseEnrollmentId(evidence.enrollmentId),
      observedChecks: {
        phrase,
        speaker,
        quality,
        captureFreshness: {
          kind: 'browser_timing_observation',
          challengeIssuedAt: parseIsoDateTime(freshness.challengeIssuedAt),
          captureReceivedAt: parseIsoDateTime(freshness.captureReceivedAt),
          serverVerifiedFreshness: false,
        },
        pad: { kind: 'pad_unavailable', reason: 'ordinary_browser_capture' },
        captureProfile: {
          kind: 'ordinary_browser_capture',
          source: 'media_recorder',
          microphoneIntegrity: 'unverified',
        },
      },
      modelVersion: parseModelVersion(evidence.modelVersion),
      thresholdVersion: parseThresholdVersion(evidence.thresholdVersion),
      completedAt: parseIsoDateTime(evidence.completedAt),
    },
  };
}

function parseRejectedObject(
  result: JsonObject,
): Extract<VoiceIdVerificationResult, { kind: 'rejected' }> {
  assertExactObjectKeys(
    result,
    ['kind', 'verificationId', 'reason', 'checks'],
    'rejected verification result',
  );
  assertKind(result.kind, 'rejected', 'verification result');
  return {
    kind: 'rejected',
    verificationId: parseVerificationId(result.verificationId),
    reason: parseOneOf(
      result.reason,
      ['phrase_mismatch', 'speaker_mismatch', 'low_audio_quality'],
      'rejection reason',
    ),
    checks: parseVoiceIdVerificationChecks(result.checks),
  };
}

function parseUncertainObject(
  result: JsonObject,
): Extract<VoiceIdVerificationResult, { kind: 'uncertain' }> {
  assertExactObjectKeys(
    result,
    ['kind', 'verificationId', 'reason', 'checks'],
    'uncertain verification result',
  );
  assertKind(result.kind, 'uncertain', 'verification result');
  return {
    kind: 'uncertain',
    verificationId: parseVerificationId(result.verificationId),
    reason: parseOneOf(
      result.reason,
      ['noisy_audio', 'too_short', 'model_low_confidence', 'verifier_unavailable'],
      'uncertain reason',
    ),
    checks: parseVoiceIdVerificationChecks(result.checks),
  };
}

function assertKind(value: unknown, expected: string, fieldName: string): void {
  if (value !== expected) throw new Error(`${fieldName} must be ${expected}`);
}

function parseOneOf<const TValue extends string>(
  value: unknown,
  allowed: readonly TValue[],
  fieldName: string,
): TValue {
  if (typeof value !== 'string') throw new Error(`${fieldName} is invalid`);
  for (const candidate of allowed) {
    if (candidate === value) return candidate;
  }
  throw new Error(`${fieldName} is invalid`);
}

function parseString(value: unknown, fieldName: string): string {
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`${fieldName} must be a non-empty string`);
  }
  return value;
}

function parseStringAllowEmpty(value: unknown, fieldName: string): string {
  if (typeof value !== 'string') throw new Error(`${fieldName} must be a string`);
  return value;
}

function parsePositiveNumber(value: unknown, fieldName: string): number {
  if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0) {
    throw new Error(`${fieldName} must be positive`);
  }
  return value;
}

function parseProbability(value: unknown, fieldName: string): number {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0 || value > 1) {
    throw new Error(`${fieldName} must be a probability`);
  }
  return value;
}
