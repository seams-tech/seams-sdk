import { buildBrowserAudioMetadata } from './capture/audioBlob.ts';
import { recordVoiceIdClip } from './capture/mediaRecorder.ts';
import {
  requestVoiceIdMicrophone,
  stopVoiceIdMicrophone,
} from './capture/microphone.ts';

export type VoiceIdRecorderState =
  | { kind: 'idle' }
  | { kind: 'recording' }
  | { kind: 'recorded'; blob: Blob; durationMs: number; recorder: string }
  | { kind: 'error'; reason: string };

export class VoiceIdRecorder {
  state: VoiceIdRecorderState = { kind: 'idle' };

  async recordClip(input: {
    durationMs: number;
    timeoutMs: number;
    fixtureSpeakerLabel: string;
  }): Promise<VoiceIdRecorderState> {
    const microphone = await requestVoiceIdMicrophone();
    if (microphone.kind === 'denied') {
      this.state = { kind: 'error', reason: microphone.reason };
      return this.state;
    }

    this.state = { kind: 'recording' };
    try {
      const result = await recordVoiceIdClip({
        stream: microphone.stream,
        durationMs: input.durationMs,
        timeoutMs: input.timeoutMs,
      });
      if (result.kind === 'error') {
        this.state = { kind: 'error', reason: result.reason };
        return this.state;
      }

      this.state = {
        kind: 'recorded',
        blob: result.blob,
        durationMs: result.durationMs,
        recorder: result.recorder,
      };
      return this.state;
    } finally {
      stopVoiceIdMicrophone(microphone.stream);
    }
  }

  buildMetadata(input: {
    fixtureSpeakerLabel: string;
  }) {
    if (this.state.kind !== 'recorded') {
      throw new Error('metadata can only be built after a recording');
    }

    return buildBrowserAudioMetadata({
      blob: this.state.blob,
      durationMs: this.state.durationMs,
      recorder: this.state.recorder,
      fixtureSpeakerLabel: input.fixtureSpeakerLabel,
    });
  }
}
