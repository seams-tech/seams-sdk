import {
  defaultVoiceIdServiceConfig,
  parseVoiceIdSpeakerScoreThreshold,
  VoiceIdService,
  voiceIdEcapaLocalDevSpeakerScoreThreshold,
  voiceIdFakeSpeakerScoreThreshold,
  type VoiceIdAuditEvent,
  type VoiceIdServiceConfig,
} from './VoiceIdService.ts';
import {
  InMemoryVoiceIdEnrollmentStore,
  InMemoryVoiceIdVerificationStore,
} from './store/VoiceIdStores.ts';
import {
  CloudflareWorkersAiRestBinding,
  CloudflareWorkersAiTranscriptProvider,
  parseCloudflareWorkersAiAsrModel,
} from './transcript/CloudflareWorkersAiTranscriptProvider.ts';
import { FakeTranscriptProvider } from './transcript/FakeTranscriptProvider.ts';
import type { VoiceIdTranscriptProvider } from './transcript/VoiceIdTranscriptProvider.ts';
import { FakeVoiceIdVerifier } from './verifier/FakeVoiceIdVerifier.ts';
import {
  PythonHttpVoiceIdVerifierTransport,
  type PythonHttpVoiceIdVerifierTransportConfig,
} from './verifier/PythonHttpVoiceIdVerifierTransport.ts';
import {
  PythonSubprocessVoiceIdVerifierTransport,
  type PythonSubprocessVoiceIdVerifierTransportConfig,
} from './verifier/PythonSubprocessVoiceIdVerifierTransport.ts';
import { PythonVoiceIdVerifier } from './verifier/PythonVoiceIdVerifier.ts';
import type { VoiceIdVerifier } from './verifier/VoiceIdVerifier.ts';

export * from './VoiceIdService.ts';
export * from './capability.ts';
export * from './routes.ts';
export * from './sdkRouterApiExtension.ts';
export * from './store/VoiceIdStores.ts';
export * from './store/CloudflareVoiceIdD1Stores.ts';
export * from './store/CloudflareVoiceIdStorageRows.ts';
export * from './store/VoiceIdDiagnosticRetentionConfig.ts';
export * from './store/VoiceIdTemplateEncryption.ts';
export * from './store/VoiceIdTemplateEncryptionConfig.ts';
export * from './transcript/FakeTranscriptProvider.ts';
export * from './transcript/CloudflareWorkersAiTranscriptProvider.ts';
export * from './transcript/VoiceIdTranscriptProvider.ts';
export * from './verifier/FakeVoiceIdVerifier.ts';
export * from './verifier/PythonHttpVoiceIdVerifierTransport.ts';
export * from './verifier/PythonSubprocessVoiceIdVerifierTransport.ts';
export * from './verifier/PythonVoiceIdVerifier.ts';
export * from './verifier/VoiceIdVerifier.ts';
export * from '../../shared/src/policy.ts';
export { parseVoiceIdIntentDigest } from '../../shared/src/ids.ts';

export type VoiceIdVerifierTransportMode =
  | 'fake'
  | 'python-subprocess'
  | 'python-http';

export type VoiceIdTranscriptProviderMode =
  | 'fake'
  | 'cloudflare-workers-ai';

export function createDefaultVoiceIdService(input: {
  auditEvents?: VoiceIdAuditEvent[];
  verifierMode?: VoiceIdVerifierTransportMode;
} = {}): VoiceIdService {
  const auditEvents = input.auditEvents ?? [];
  const verifierMode = input.verifierMode ?? verifierTransportModeFromEnv();
  return new VoiceIdService({
    enrollmentStore: new InMemoryVoiceIdEnrollmentStore(),
    verificationStore: new InMemoryVoiceIdVerificationStore(),
    verifier: createVoiceIdVerifierFromEnv(verifierMode),
    transcriptProvider: createVoiceIdTranscriptProviderFromEnv(),
    config: voiceIdServiceConfigFromEnv({
      env: process.env,
      verifierMode,
    }),
    now: () => new Date(),
    emitAuditEvent: (event) => {
      auditEvents.push(event);
    },
  });
}

export function voiceIdServiceConfigFromEnv(input: {
  env: Readonly<Record<string, string | undefined>>;
  verifierMode: VoiceIdVerifierTransportMode;
}): VoiceIdServiceConfig {
  return defaultVoiceIdServiceConfig({
    speakerScoreThreshold: voiceIdSpeakerScoreThresholdFromEnv(input),
  });
}

export function voiceIdSpeakerScoreThresholdFromEnv(input: {
  env: Readonly<Record<string, string | undefined>>;
  verifierMode: VoiceIdVerifierTransportMode;
}): number {
  const configured = input.env.VOICEID_SPEAKER_SCORE_THRESHOLD;
  if (configured !== undefined && configured.length > 0) {
    return parseVoiceIdSpeakerScoreThreshold(configured, 'VOICEID_SPEAKER_SCORE_THRESHOLD');
  }
  if (input.verifierMode !== 'fake' && verifierBackendFromEnv(input.env) === 'ecapa') {
    return voiceIdEcapaLocalDevSpeakerScoreThreshold;
  }
  return voiceIdFakeSpeakerScoreThreshold;
}

export function createVoiceIdVerifierFromEnv(mode: VoiceIdVerifierTransportMode): VoiceIdVerifier {
  switch (mode) {
    case 'fake':
      return new FakeVoiceIdVerifier();
    case 'python-subprocess':
      return new PythonVoiceIdVerifier({
        transport: new PythonSubprocessVoiceIdVerifierTransport(pythonSubprocessConfigFromEnv()),
      });
    case 'python-http':
      return new PythonVoiceIdVerifier({
        transport: new PythonHttpVoiceIdVerifierTransport(pythonHttpConfigFromEnv()),
      });
  }
}

export function verifierTransportModeFromEnv(): VoiceIdVerifierTransportMode {
  const value = process.env.VOICEID_VERIFIER_TRANSPORT ?? 'fake';
  if (value === 'fake' || value === 'python-subprocess' || value === 'python-http') {
    return value;
  }
  throw new Error("VOICEID_VERIFIER_TRANSPORT must be 'fake', 'python-subprocess', or 'python-http'");
}

export function createVoiceIdTranscriptProviderFromEnv(): VoiceIdTranscriptProvider {
  switch (transcriptProviderModeFromEnv()) {
    case 'fake':
      return new FakeTranscriptProvider();
    case 'cloudflare-workers-ai':
      return new CloudflareWorkersAiTranscriptProvider({
        ai: new CloudflareWorkersAiRestBinding({
          accountId: requiredEnv('CLOUDFLARE_ACCOUNT_ID'),
          apiToken: requiredEnv('CLOUDFLARE_API_TOKEN'),
          fetch,
          ...(process.env.VOICEID_CLOUDFLARE_AI_API_BASE_URL !== undefined
            ? { apiBaseUrl: process.env.VOICEID_CLOUDFLARE_AI_API_BASE_URL }
            : {}),
        }),
        model: parseCloudflareWorkersAiAsrModel(process.env.VOICEID_CLOUDFLARE_ASR_MODEL),
      });
  }
}

export function transcriptProviderModeFromEnv(): VoiceIdTranscriptProviderMode {
  const value = process.env.VOICEID_TRANSCRIPT_PROVIDER ?? 'fake';
  if (value === 'fake' || value === 'cloudflare-workers-ai') {
    return value;
  }
  throw new Error("VOICEID_TRANSCRIPT_PROVIDER must be 'fake' or 'cloudflare-workers-ai'");
}

function pythonSubprocessConfigFromEnv(): PythonSubprocessVoiceIdVerifierTransportConfig {
  const timeoutMs = optionalPositiveIntegerEnv('VOICEID_VERIFIER_TIMEOUT_MS');
  return {
    ...(process.env.VOICEID_PYTHON_EXECUTABLE !== undefined
      ? { pythonExecutable: process.env.VOICEID_PYTHON_EXECUTABLE }
      : {}),
    ...(process.env.VOICEID_PYTHON_APP_PATH !== undefined
      ? { appScriptPath: process.env.VOICEID_PYTHON_APP_PATH }
      : {}),
    ...(process.env.VOICEID_PYTHON_PACKAGE_PATH !== undefined
      ? { verifierPackagePath: process.env.VOICEID_PYTHON_PACKAGE_PATH }
      : {}),
    ...(timeoutMs !== null ? { timeoutMs } : {}),
    env: verifierBackendEnv(),
  };
}

function pythonHttpConfigFromEnv(): PythonHttpVoiceIdVerifierTransportConfig {
  const timeoutMs = optionalPositiveIntegerEnv('VOICEID_VERIFIER_TIMEOUT_MS');
  return {
    baseUrl: process.env.VOICEID_PYTHON_VERIFIER_URL ?? 'http://127.0.0.1:5051/voice-id/verifier/',
    ...(timeoutMs !== null ? { timeoutMs } : {}),
  };
}

function verifierBackendEnv(): Readonly<Record<string, string>> {
  return process.env.VOICEID_VERIFIER_BACKEND !== undefined
    ? { VOICEID_VERIFIER_BACKEND: process.env.VOICEID_VERIFIER_BACKEND }
    : {};
}

function verifierBackendFromEnv(env: Readonly<Record<string, string | undefined>>): 'placeholder' | 'ecapa' {
  const backend = env.VOICEID_VERIFIER_BACKEND ?? 'placeholder';
  if (backend === 'placeholder' || backend === 'ecapa') {
    return backend;
  }
  throw new Error("VOICEID_VERIFIER_BACKEND must be 'placeholder' or 'ecapa'");
}

function optionalPositiveIntegerEnv(name: string): number | null {
  const value = process.env[name];
  if (value === undefined || value.length === 0) {
    return null;
  }
  const parsed = Number.parseInt(value, 10);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw new Error(`${name} must be a positive integer`);
  }
  return parsed;
}

function requiredEnv(name: string): string {
  const value = process.env[name];
  if (value === undefined || value.trim().length === 0) {
    throw new Error(`${name} must be set`);
  }
  return value;
}
