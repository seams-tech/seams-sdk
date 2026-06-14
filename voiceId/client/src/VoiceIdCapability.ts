import { VoiceIdClient, type VoiceIdApiClientConfig } from './VoiceIdClient.ts';
import type { VoiceIdRecorder } from './VoiceIdRecorder.ts';

export type VoiceIdCapabilityVersion = 'voice_id_client_capability_v1';

export type VoiceIdRecorderLike = Pick<
  VoiceIdRecorder,
  'state' | 'recordClip' | 'buildMetadata'
>;

export type VoiceIdRecorderConstructor = new () => VoiceIdRecorderLike;
export type VoiceIdRecorderLoader = () => Promise<VoiceIdRecorderConstructor>;

export type VoiceIdApiOnlyCapability = {
  kind: VoiceIdCapabilityVersion;
  mode: 'api_only';
  client: VoiceIdClient;
  createRecorder?: never;
};

export type VoiceIdBrowserCaptureCapability = {
  kind: VoiceIdCapabilityVersion;
  mode: 'browser_capture';
  client: VoiceIdClient;
  createRecorder(): Promise<VoiceIdRecorderLike>;
};

export type VoiceIdCapability =
  | VoiceIdApiOnlyCapability
  | VoiceIdBrowserCaptureCapability;

export function createVoiceIdApiOnlyCapability(input: {
  clientConfig: VoiceIdApiClientConfig;
}): VoiceIdApiOnlyCapability {
  return {
    kind: 'voice_id_client_capability_v1',
    mode: 'api_only',
    client: new VoiceIdClient(input.clientConfig),
  };
}

export function createVoiceIdBrowserCaptureCapability(input: {
  clientConfig: VoiceIdApiClientConfig;
  recorderLoader?: VoiceIdRecorderLoader;
}): VoiceIdBrowserCaptureCapability {
  const recorderLoader = input.recorderLoader ?? defaultVoiceIdRecorderLoader;
  return {
    kind: 'voice_id_client_capability_v1',
    mode: 'browser_capture',
    client: new VoiceIdClient(input.clientConfig),
    async createRecorder() {
      const Recorder = await recorderLoader();
      return new Recorder();
    },
  };
}

async function defaultVoiceIdRecorderLoader(): Promise<VoiceIdRecorderConstructor> {
  const module = await import('./VoiceIdRecorder.ts');
  return module.VoiceIdRecorder;
}
