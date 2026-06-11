import { buildVoiceIdAudioFormData } from './capture/audioBlob.ts';
import type { VoiceIdAudioMetadata } from '../../shared/src/audio.ts';

export type VoiceIdApiClientConfig = {
  baseUrl: string;
  fetch: typeof fetch;
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
