import { buildVoiceIdAudioFormData } from './capture/audioBlob.ts';
import type { VoiceIdAudioMetadata } from '../../shared/src/audio.ts';
import type {
  VoiceIdAudioLivenessSignals,
  VoiceIdAudioLivenessPolicy,
  VoiceIdAuthPolicyUseCase,
  VoiceIdLocalDeviceContext,
} from '../../shared/src/index.ts';

export type VoiceIdApiClientConfig = {
  baseUrl: string;
  fetch: typeof fetch;
};

export type AuthorizeVoiceIdOwnerPresenceClientInput = {
  verificationId: string;
  intentDigest: string;
  useCase: VoiceIdAuthPolicyUseCase;
  policyVersion: string;
  audio: VoiceIdAudioLivenessSignals;
  context: VoiceIdLocalDeviceContext;
  policy?: VoiceIdAudioLivenessPolicy;
};

export class VoiceIdClient {
  private readonly boundFetch: typeof fetch;

  constructor(private readonly config: VoiceIdApiClientConfig) {
    this.boundFetch = config.fetch.bind(globalThis);
  }

  async startEnrollment(input: {
    userId: string;
    phrase: string;
  }): Promise<unknown> {
    return await this.postJson('/voice-id/enrollment/start', input);
  }

  async uploadEnrollmentSample(input: {
    blob: Blob;
    metadata: VoiceIdAudioMetadata;
    userId: string;
    enrollmentId: string;
    expectedPhrase: string;
    spokenPhrase: string;
    attemptNumber: number;
  }): Promise<unknown> {
    return await this.postForm('/voice-id/enrollment/sample', {
      blob: input.blob,
      metadata: input.metadata,
      fields: {
        userId: input.userId,
        enrollmentId: input.enrollmentId,
        expectedPhrase: input.expectedPhrase,
        spokenPhrase: input.spokenPhrase,
        attemptNumber: input.attemptNumber,
      },
    });
  }

  async finalizeEnrollment(input: {
    userId: string;
    enrollmentId: string;
  }): Promise<unknown> {
    return await this.postJson('/voice-id/enrollment/finalize', input);
  }

  async startVerification(input: {
    userId: string;
    enrollmentId: string;
    phrase: string;
    intentDigest: string;
    intentExpiresAt: string;
    intentNonce: string;
  }): Promise<unknown> {
    return await this.postJson('/voice-id/verification/start', input);
  }

  async uploadVerificationSample(input: {
    blob: Blob;
    metadata: VoiceIdAudioMetadata;
    userId: string;
    enrollmentId: string;
    verificationId: string;
    expectedPhrase: string;
    spokenPhrase: string;
    attemptNumber: number;
  }): Promise<unknown> {
    return await this.postForm('/voice-id/verification/sample', {
      blob: input.blob,
      metadata: input.metadata,
      fields: {
        userId: input.userId,
        enrollmentId: input.enrollmentId,
        verificationId: input.verificationId,
        expectedPhrase: input.expectedPhrase,
        spokenPhrase: input.spokenPhrase,
        attemptNumber: input.attemptNumber,
      },
    });
  }

  async authorizeOwnerPresence(input: AuthorizeVoiceIdOwnerPresenceClientInput): Promise<unknown> {
    return await this.postJson('/voice-id/owner-presence/authorize', {
      verificationId: input.verificationId,
      intentDigest: input.intentDigest,
      useCase: input.useCase,
      policyVersion: input.policyVersion,
      audio: input.audio,
      context: input.context,
      ...(input.policy !== undefined ? { policy: input.policy } : {}),
    });
  }

  private async postJson(path: string, body: unknown): Promise<unknown> {
    const response = await this.boundFetch(new URL(path, this.config.baseUrl), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    return await response.json();
  }

  private async postForm(path: string, input: {
    blob: Blob;
    metadata: VoiceIdAudioMetadata;
    fields: Record<string, unknown>;
  }): Promise<unknown> {
    const response = await this.boundFetch(new URL(path, this.config.baseUrl), {
      method: 'POST',
      body: buildVoiceIdAudioFormData(input),
    });
    return await response.json();
  }
}
