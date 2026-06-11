import {
  defaultVoiceIdServiceConfig,
  VoiceIdService,
  type VoiceIdAuditEvent,
} from './VoiceIdService.ts';
import {
  InMemoryVoiceIdEnrollmentStore,
  InMemoryVoiceIdVerificationStore,
} from './store/VoiceIdStores.ts';
import { FakeTranscriptProvider } from './transcript/FakeTranscriptProvider.ts';
import { FakeVoiceIdVerifier } from './verifier/FakeVoiceIdVerifier.ts';

export * from './VoiceIdService.ts';
export * from './routes.ts';
export * from './store/VoiceIdStores.ts';
export * from './transcript/FakeTranscriptProvider.ts';
export * from './transcript/VoiceIdTranscriptProvider.ts';
export * from './verifier/FakeVoiceIdVerifier.ts';
export * from './verifier/PythonVoiceIdVerifier.ts';
export * from './verifier/VoiceIdVerifier.ts';

export function createDefaultVoiceIdService(input: {
  auditEvents?: VoiceIdAuditEvent[];
} = {}): VoiceIdService {
  const auditEvents = input.auditEvents ?? [];
  return new VoiceIdService({
    enrollmentStore: new InMemoryVoiceIdEnrollmentStore(),
    verificationStore: new InMemoryVoiceIdVerificationStore(),
    verifier: new FakeVoiceIdVerifier(),
    transcriptProvider: new FakeTranscriptProvider(),
    config: defaultVoiceIdServiceConfig(),
    now: () => new Date(),
    emitAuditEvent: (event) => {
      auditEvents.push(event);
    },
  });
}
