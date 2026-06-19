import { buildBrowserAudioMetadata } from './capture/audioBlob.ts';
import {
  recordVoiceIdClip,
  startVoiceIdClipRecording,
  type VoiceIdRecordingResult,
} from './capture/mediaRecorder.ts';
import {
  requestVoiceIdMicrophone,
  stopVoiceIdMicrophone,
} from './capture/microphone.ts';

export type VoiceIdRecorderState =
  | { kind: 'idle' }
  | { kind: 'recording' }
  | { kind: 'recorded'; blob: Blob; durationMs: number; recorder: string }
  | { kind: 'error'; reason: string };

export type VoiceIdRecorderSession =
  | {
      kind: 'recording';
      stop(): Promise<VoiceIdRecorderState>;
      cancel(): Promise<VoiceIdRecorderState>;
    }
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

  async startRecording(input: {
    maxDurationMs: number;
    timeoutMs: number;
  }): Promise<VoiceIdRecorderSession> {
    const microphone = await requestVoiceIdMicrophone();
    if (microphone.kind === 'denied') {
      this.state = { kind: 'error', reason: microphone.reason };
      return this.state;
    }

    const session = startVoiceIdClipRecording({
      stream: microphone.stream,
      maxDurationMs: input.maxDurationMs,
      timeoutMs: input.timeoutMs,
    });
    if (session.kind === 'error') {
      stopVoiceIdMicrophone(microphone.stream);
      this.state = { kind: 'error', reason: session.reason };
      return this.state;
    }

    this.state = { kind: 'recording' };
    let settled = false;
    const settle = async (
      action: () => Promise<VoiceIdRecordingResult>,
    ): Promise<VoiceIdRecorderState> => {
      if (settled) return this.state;
      settled = true;
      try {
        return this.applyRecordingResult(await action());
      } finally {
        stopVoiceIdMicrophone(microphone.stream);
      }
    };

    return {
      kind: 'recording',
      stop: async () => await settle(session.stop),
      cancel: async () => await settle(session.cancel),
    };
  }

  clearRecording(): void {
    if (this.state.kind === 'recorded') {
      this.state = { kind: 'idle' };
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

  private applyRecordingResult(result: VoiceIdRecordingResult): VoiceIdRecorderState {
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
  }
}
