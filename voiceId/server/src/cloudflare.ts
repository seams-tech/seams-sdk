import {
  defaultVoiceIdServiceConfig,
  parseVoiceIdSpeakerScoreThreshold,
  VoiceIdService,
  voiceIdEcapaLocalDevSpeakerScoreThreshold,
  type VoiceIdAuditEvent,
} from './VoiceIdService.ts';
import { createVoiceIdFetchHandler, type VoiceIdFetchHandler } from './routes.ts';
import {
  CloudflareD1VoiceIdEnrollmentStore,
  CloudflareD1VoiceIdVerificationStore,
  type VoiceIdCloudflareD1Database,
} from './store/CloudflareVoiceIdD1Stores.ts';
import {
  parseVoiceIdTemplateEncryptionKeyConfigFromEnv,
  type VoiceIdTemplateEncryptionKeyConfig,
} from './store/VoiceIdTemplateEncryptionConfig.ts';
import {
  resolveVoiceIdTemplateEncryptionSecretFromEnv,
  VoiceIdAesGcmTemplateCipher,
  VoiceIdTemplateWrappingEnrollmentStore,
  type VoiceIdTemplateEncryptionSecretEnv,
} from './store/VoiceIdTemplateEncryption.ts';
import { createRandomId, parseVoiceIdChallengeNonce } from '../../shared/src/ids.ts';
import { assertNever } from '../../shared/src/assertNever.ts';
import {
  InMemoryVoiceIdEnrollmentStore,
  InMemoryVoiceIdVerificationStore,
  type VoiceIdEnrollmentStore,
  type VoiceIdVerificationStore,
} from './store/VoiceIdStores.ts';
import { FakeTranscriptProvider } from './transcript/FakeTranscriptProvider.ts';
import { PythonMoonshineTranscriptProvider } from './transcript/PythonMoonshineTranscriptProvider.ts';
import {
  CloudflareWorkersAiTranscriptProvider,
  parseCloudflareWorkersAiAsrModel,
  requireCloudflareWorkersAiBinding,
  type VoiceIdCloudflareWorkersAiAsrModel,
  type VoiceIdCloudflareWorkersAiBinding,
} from './transcript/CloudflareWorkersAiTranscriptProvider.ts';
import type { VoiceIdTranscriptProvider } from './transcript/VoiceIdTranscriptProvider.ts';
import {
  PythonHttpVoiceIdVerifierTransport,
  type PythonHttpVoiceIdVerifierFetch,
} from './verifier/PythonHttpVoiceIdVerifierTransport.ts';
import { PythonVoiceIdVerifier } from './verifier/PythonVoiceIdVerifier.ts';
import { PythonMoonshineAnalysisProvider } from './analysis/PythonMoonshineAnalysisProvider.ts';
import { SplitVoiceIdAnalysisProvider } from './analysis/VoiceIdAnalysisProvider.ts';

export type VoiceIdCloudflareEnv = {
  readonly AI?: VoiceIdCloudflareWorkersAiBinding;
  readonly VOICEID_PYTHON_VERIFIER_URL: string;
  readonly VOICEID_ALLOWED_ORIGINS: string;
  readonly VOICEID_VERIFIER_TIMEOUT_MS?: string;
  readonly VOICEID_SPEAKER_SCORE_THRESHOLD?: string;
  readonly VOICEID_TRANSCRIPT_PROVIDER?: string;
  readonly VOICEID_CLOUDFLARE_ASR_MODEL?: string;
  readonly VOICEID_MOONSHINE_INTENT_NAME?: string;
  readonly VOICEID_STORAGE_KIND?: string;
  readonly VOICEID_D1_DATABASE?: VoiceIdCloudflareD1Database;
  readonly VOICEID_TEMPLATE_KEY_SOURCE?: string;
  readonly VOICEID_TEMPLATE_KEY_ALGORITHM?: string;
  readonly VOICEID_TEMPLATE_KEY_ID?: string;
  readonly VOICEID_TEMPLATE_KEY_SECRET_BINDING?: string;
  readonly VOICEID_TEMPLATE_KEY_SECRET_ENV?: string;
  readonly VOICEID_TEMPLATE_KEY_ROTATION_VERSION?: string;
  readonly VOICEID_TEMPLATE_KEY_AAD_LABEL?: string;
} & VoiceIdTemplateEncryptionSecretEnv;

export type VoiceIdCloudflareConfig = {
  readonly http: {
    readonly allowedOrigins: readonly string[];
  };
  readonly verifier: {
    readonly kind: 'python_http';
    readonly baseUrl: string;
    readonly timeoutMs: number;
  };
  readonly speakerScoreThreshold: number;
  readonly storage:
    | {
        readonly kind: 'memory';
      }
    | {
        readonly kind: 'cloudflare_d1';
        readonly databaseBindingName: 'VOICEID_D1_DATABASE';
        readonly templateKeyConfig: VoiceIdTemplateEncryptionKeyConfig;
      };
  readonly transcript:
    | {
        readonly kind: 'fake';
      }
    | {
        readonly kind: 'cloudflare_workers_ai';
        readonly aiBindingName: 'AI';
        readonly model: VoiceIdCloudflareWorkersAiAsrModel;
      }
    | {
        readonly kind: 'python_moonshine';
        readonly intentName: string;
      };
};

export type VoiceIdCloudflareFactoryInput = {
  readonly auditEvents?: VoiceIdAuditEvent[];
  readonly enrollmentStore?: VoiceIdEnrollmentStore;
  readonly verificationStore?: VoiceIdVerificationStore;
  readonly transcriptProvider?: VoiceIdTranscriptProvider;
  readonly verifierFetch?: PythonHttpVoiceIdVerifierFetch;
  readonly now?: () => Date;
};

export function createVoiceIdCloudflareFetchHandler(
  env: VoiceIdCloudflareEnv,
  input: VoiceIdCloudflareFactoryInput = {},
): VoiceIdFetchHandler {
  const config = parseVoiceIdCloudflareEnv(env);
  return createVoiceIdFetchHandler(
    createVoiceIdCloudflareServiceFromConfig(env, config, input),
    config.http,
  );
}

export function createVoiceIdCloudflareService(
  env: VoiceIdCloudflareEnv,
  input: VoiceIdCloudflareFactoryInput = {},
): VoiceIdService {
  const config = parseVoiceIdCloudflareEnv(env);
  return createVoiceIdCloudflareServiceFromConfig(env, config, input);
}

function createVoiceIdCloudflareServiceFromConfig(
  env: VoiceIdCloudflareEnv,
  config: VoiceIdCloudflareConfig,
  input: VoiceIdCloudflareFactoryInput,
): VoiceIdService {
  const auditEvents = input.auditEvents ?? [];
  const stores = createVoiceIdCloudflareStores(env, config);
  const transportConfig = {
    baseUrl: config.verifier.baseUrl,
    timeoutMs: config.verifier.timeoutMs,
    ...(input.verifierFetch !== undefined ? { fetchJson: input.verifierFetch } : {}),
  };
  const verifierTransport = new PythonHttpVoiceIdVerifierTransport(transportConfig);
  const verifier = new PythonVoiceIdVerifier({ transport: verifierTransport });
  const transcriptProvider =
    input.transcriptProvider ?? createVoiceIdCloudflareTranscriptProvider(env, config);

  return new VoiceIdService({
    enrollmentStore: input.enrollmentStore ?? stores.enrollmentStore,
    verificationStore: input.verificationStore ?? stores.verificationStore,
    verifier,
    transcriptProvider,
    analysisProvider:
      input.transcriptProvider === undefined && config.transcript.kind === 'python_moonshine'
        ? new PythonMoonshineAnalysisProvider(verifierTransport, config.transcript.intentName)
        : new SplitVoiceIdAnalysisProvider(transcriptProvider, verifier),
    config: defaultVoiceIdServiceConfig({
      speakerScoreThreshold: config.speakerScoreThreshold,
    }),
    now: input.now ?? currentDate,
    createChallengeNonce: createCloudflareVoiceIdChallengeNonce,
    emitAuditEvent: auditEvents.push.bind(auditEvents),
  });
}

function createCloudflareVoiceIdChallengeNonce() {
  return parseVoiceIdChallengeNonce(createRandomId('voice_challenge'));
}

function currentDate(): Date {
  return new Date();
}

export function parseVoiceIdCloudflareEnv(env: VoiceIdCloudflareEnv): VoiceIdCloudflareConfig {
  return {
    http: {
      allowedOrigins: parseAllowedOriginsEnv(env.VOICEID_ALLOWED_ORIGINS),
    },
    verifier: {
      kind: 'python_http',
      baseUrl: parseHttpUrl(env.VOICEID_PYTHON_VERIFIER_URL, 'VOICEID_PYTHON_VERIFIER_URL'),
      timeoutMs: parseOptionalPositiveInteger(
        env.VOICEID_VERIFIER_TIMEOUT_MS,
        'VOICEID_VERIFIER_TIMEOUT_MS',
        10_000,
      ),
    },
    speakerScoreThreshold: parseOptionalSpeakerScoreThreshold(
      env.VOICEID_SPEAKER_SCORE_THRESHOLD,
      'VOICEID_SPEAKER_SCORE_THRESHOLD',
      voiceIdEcapaLocalDevSpeakerScoreThreshold,
    ),
    storage: parseCloudflareStorageConfig(env),
    transcript: parseCloudflareTranscriptConfig(env),
  };
}

function createVoiceIdCloudflareTranscriptProvider(
  env: VoiceIdCloudflareEnv,
  config: VoiceIdCloudflareConfig,
): VoiceIdTranscriptProvider {
  const transcript = config.transcript;
  switch (transcript.kind) {
    case 'fake':
      return new FakeTranscriptProvider();
    case 'cloudflare_workers_ai':
      return new CloudflareWorkersAiTranscriptProvider({
        ai: requireCloudflareWorkersAiBinding(env.AI),
        model: transcript.model,
      });
    case 'python_moonshine':
      return new PythonMoonshineTranscriptProvider(
        new PythonHttpVoiceIdVerifierTransport({
          baseUrl: config.verifier.baseUrl,
          timeoutMs: config.verifier.timeoutMs,
        }),
        transcript.intentName,
      );
    default:
      return assertNever(transcript);
  }
}

function createVoiceIdCloudflareStores(
  env: VoiceIdCloudflareEnv,
  config: VoiceIdCloudflareConfig,
): {
  enrollmentStore: VoiceIdEnrollmentStore;
  verificationStore: VoiceIdVerificationStore;
} {
  const storage = config.storage;
  switch (storage.kind) {
    case 'memory':
      return {
        enrollmentStore: new InMemoryVoiceIdEnrollmentStore(),
        verificationStore: new InMemoryVoiceIdVerificationStore(),
      };
    case 'cloudflare_d1': {
      const database = requireD1Database(env.VOICEID_D1_DATABASE);
      const secret = resolveVoiceIdTemplateEncryptionSecretFromEnv(storage.templateKeyConfig, env);
      const cipher = new VoiceIdAesGcmTemplateCipher({
        keyConfig: storage.templateKeyConfig,
        secret,
      });
      return {
        enrollmentStore: new VoiceIdTemplateWrappingEnrollmentStore(
          new CloudflareD1VoiceIdEnrollmentStore(database),
          cipher,
        ),
        verificationStore: new CloudflareD1VoiceIdVerificationStore(database),
      };
    }
    default:
      return assertNever(storage);
  }
}

function parseHttpUrl(value: unknown, fieldName: string): string {
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new Error(`${fieldName} must be a non-empty URL`);
  }
  const url = new URL(value);
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    throw new Error(`${fieldName} must use http or https`);
  }
  return url.toString();
}

function parseAllowedOriginsEnv(value: unknown): readonly string[] {
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new Error('VOICEID_ALLOWED_ORIGINS must be a comma-separated origin list');
  }
  const origins: string[] = [];
  for (const candidate of value.split(',')) {
    const trimmed = candidate.trim();
    if (trimmed.length === 0) throw new Error('VOICEID_ALLOWED_ORIGINS contains an empty origin');
    const origin = new URL(trimmed).origin;
    if (origin !== trimmed)
      throw new Error(`VOICEID_ALLOWED_ORIGINS must contain canonical origins: ${trimmed}`);
    if (origins.includes(origin))
      throw new Error(`VOICEID_ALLOWED_ORIGINS contains a duplicate origin: ${origin}`);
    origins.push(origin);
  }
  return origins;
}

function parseOptionalPositiveInteger(
  value: unknown,
  fieldName: string,
  defaultValue: number,
): number {
  if (value === undefined || value === '') {
    return defaultValue;
  }
  if (typeof value !== 'string') {
    throw new Error(`${fieldName} must be a positive integer string`);
  }
  const parsed = Number.parseInt(value, 10);
  if (!Number.isSafeInteger(parsed) || parsed <= 0 || String(parsed) !== value) {
    throw new Error(`${fieldName} must be a positive integer string`);
  }
  return parsed;
}

function parseOptionalSpeakerScoreThreshold(
  value: unknown,
  fieldName: string,
  defaultValue: number,
): number {
  if (value === undefined || value === '') {
    return defaultValue;
  }
  return parseVoiceIdSpeakerScoreThreshold(value, fieldName);
}

function parseCloudflareStorageConfig(
  env: VoiceIdCloudflareEnv,
): VoiceIdCloudflareConfig['storage'] {
  const storageKind = env.VOICEID_STORAGE_KIND;
  if (storageKind === 'memory') {
    return { kind: 'memory' };
  }
  if (storageKind === 'cloudflare-d1') {
    requireD1Database(env.VOICEID_D1_DATABASE);
    return {
      kind: 'cloudflare_d1',
      databaseBindingName: 'VOICEID_D1_DATABASE',
      templateKeyConfig: parseVoiceIdTemplateEncryptionKeyConfigFromEnv({
        VOICEID_TEMPLATE_KEY_SOURCE: env.VOICEID_TEMPLATE_KEY_SOURCE,
        VOICEID_TEMPLATE_KEY_ALGORITHM: env.VOICEID_TEMPLATE_KEY_ALGORITHM,
        VOICEID_TEMPLATE_KEY_ID: env.VOICEID_TEMPLATE_KEY_ID,
        VOICEID_TEMPLATE_KEY_SECRET_BINDING: env.VOICEID_TEMPLATE_KEY_SECRET_BINDING,
        VOICEID_TEMPLATE_KEY_SECRET_ENV: env.VOICEID_TEMPLATE_KEY_SECRET_ENV,
        VOICEID_TEMPLATE_KEY_ROTATION_VERSION: env.VOICEID_TEMPLATE_KEY_ROTATION_VERSION,
        VOICEID_TEMPLATE_KEY_AAD_LABEL: env.VOICEID_TEMPLATE_KEY_AAD_LABEL,
      }),
    };
  }

  throw new Error("VOICEID_STORAGE_KIND must explicitly be 'memory' or 'cloudflare-d1'");
}

function parseCloudflareTranscriptConfig(
  env: VoiceIdCloudflareEnv,
): VoiceIdCloudflareConfig['transcript'] {
  const provider = env.VOICEID_TRANSCRIPT_PROVIDER;
  if (provider === 'fake') {
    return { kind: 'fake' };
  }
  if (provider === 'cloudflare-workers-ai') {
    requireCloudflareWorkersAiBinding(env.AI);
    return {
      kind: 'cloudflare_workers_ai',
      aiBindingName: 'AI',
      model: parseCloudflareWorkersAiAsrModel(env.VOICEID_CLOUDFLARE_ASR_MODEL),
    };
  }
  if (provider === 'python-moonshine') {
    return {
      kind: 'python_moonshine',
      intentName: parseMoonshineIntentName(env.VOICEID_MOONSHINE_INTENT_NAME),
    };
  }

  throw new Error(
    "VOICEID_TRANSCRIPT_PROVIDER must explicitly be 'fake', 'cloudflare-workers-ai', or 'python-moonshine'",
  );
}

function parseMoonshineIntentName(value: string | undefined): string {
  const intentName = value?.trim() ?? 'expected_phrase';
  if (intentName.length === 0) {
    throw new Error('VOICEID_MOONSHINE_INTENT_NAME must be a non-empty string');
  }
  return intentName;
}

function requireD1Database(value: unknown): VoiceIdCloudflareD1Database {
  if (typeof value !== 'object' || value === null || !('prepare' in value)) {
    throw new Error('VOICEID_D1_DATABASE binding must be a D1 database');
  }
  const database = value as { readonly prepare: unknown };
  if (typeof database.prepare !== 'function') {
    throw new Error('VOICEID_D1_DATABASE binding must be a D1 database');
  }

  return value as VoiceIdCloudflareD1Database;
}
