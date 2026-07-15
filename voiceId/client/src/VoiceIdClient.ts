import { buildVoiceIdAudioFormData } from './capture/audioBlob.ts';
import type { VoiceIdAudioMetadata } from '../../shared/src/audio.ts';
import {
  parseVoiceIdEnrollmentDisableApiResponse,
  parseVoiceIdEnrollmentStartApiResponse,
  parseVoiceIdEnrollmentSubmitApiResponse,
  parseVoiceIdVerificationStartApiResponse,
  parseVoiceIdVerificationSubmitApiResponse,
  type VoiceIdApiResponse,
  type VoiceIdEnrollmentDisableApiValue,
  type VoiceIdEnrollmentStartApiValue,
  type VoiceIdEnrollmentSubmitApiValue,
  type VoiceIdVerificationStartApiValue,
  type VoiceIdVerificationSubmitApiValue,
} from '../../shared/src/api.ts';

export type VoiceIdApiClientConfig = {
  baseUrl: string;
  fetch: typeof fetch;
};

type VoiceIdResponseParser<TValue> = (value: unknown) => VoiceIdApiResponse<TValue>;

export class VoiceIdClient {
  private readonly boundFetch: typeof fetch;

  constructor(private readonly config: VoiceIdApiClientConfig) {
    this.boundFetch = config.fetch.bind(globalThis);
  }

  async startEnrollment(input: {
    userId: string;
  }): Promise<VoiceIdApiResponse<VoiceIdEnrollmentStartApiValue>> {
    return await this.postJson(
      '/voice-id/evidence/enrollment/start',
      input,
      parseVoiceIdEnrollmentStartApiResponse,
    );
  }

  async submitEnrollmentRecording(input: {
    blob: Blob;
    metadata: VoiceIdAudioMetadata;
    userId: string;
    enrollmentId: string;
  }): Promise<VoiceIdApiResponse<VoiceIdEnrollmentSubmitApiValue>> {
    return await this.postForm(
      '/voice-id/evidence/enrollment/recording',
      {
        blob: input.blob,
        metadata: input.metadata,
        fields: { userId: input.userId, enrollmentId: input.enrollmentId },
      },
      parseVoiceIdEnrollmentSubmitApiResponse,
    );
  }

  async disableEnrollment(input: {
    userId: string;
    enrollmentId: string;
  }): Promise<VoiceIdApiResponse<VoiceIdEnrollmentDisableApiValue>> {
    return await this.postJson(
      '/voice-id/evidence/enrollment/disable',
      input,
      parseVoiceIdEnrollmentDisableApiResponse,
    );
  }

  async startVerification(input: {
    userId: string;
    enrollmentId: string;
  }): Promise<VoiceIdApiResponse<VoiceIdVerificationStartApiValue>> {
    return await this.postJson(
      '/voice-id/evidence/verification/start',
      input,
      parseVoiceIdVerificationStartApiResponse,
    );
  }

  async submitVerificationRecording(input: {
    blob: Blob;
    metadata: VoiceIdAudioMetadata;
    userId: string;
    enrollmentId: string;
    verificationId: string;
  }): Promise<VoiceIdApiResponse<VoiceIdVerificationSubmitApiValue>> {
    return await this.postForm(
      '/voice-id/evidence/verification/recording',
      {
        blob: input.blob,
        metadata: input.metadata,
        fields: {
          userId: input.userId,
          enrollmentId: input.enrollmentId,
          verificationId: input.verificationId,
        },
      },
      parseVoiceIdVerificationSubmitApiResponse,
    );
  }

  private async postJson<TValue>(
    path: string,
    body: unknown,
    parseResponse: VoiceIdResponseParser<TValue>,
  ): Promise<VoiceIdApiResponse<TValue>> {
    const response = await this.boundFetch(new URL(path, this.config.baseUrl), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    return parseResponse(await response.json());
  }

  private async postForm<TValue>(
    path: string,
    input: {
      blob: Blob;
      metadata: VoiceIdAudioMetadata;
      fields: Record<string, unknown>;
    },
    parseResponse: VoiceIdResponseParser<TValue>,
  ): Promise<VoiceIdApiResponse<TValue>> {
    const response = await this.boundFetch(new URL(path, this.config.baseUrl), {
      method: 'POST',
      body: buildVoiceIdAudioFormData(input),
    });
    return parseResponse(await response.json());
  }
}
