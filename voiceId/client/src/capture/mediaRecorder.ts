export type VoiceIdRecordingResult =
  | {
      kind: 'recorded';
      blob: Blob;
      durationMs: number;
      recorder: string;
    }
  | {
      kind: 'error';
      reason:
        | 'recording_cancelled'
        | 'empty_recording'
        | 'media_recorder_unsupported'
        | 'recording_failed'
        | 'recording_timeout';
    };

export type VoiceIdRecordingSession =
  | {
      kind: 'recording';
      stop(): Promise<VoiceIdRecordingResult>;
      cancel(): Promise<VoiceIdRecordingResult>;
    }
  | {
      kind: 'error';
      reason: 'media_recorder_unsupported' | 'recording_failed';
    };

const minimumUsefulRecordingBytes = 1024;
const recorderChunkIntervalMs = 250;

export async function recordVoiceIdClip(input: {
  stream: MediaStream;
  durationMs: number;
  timeoutMs: number;
  onRecordingStart?: () => void;
}): Promise<VoiceIdRecordingResult> {
  const session = startVoiceIdClipRecording({
    stream: input.stream,
    maxDurationMs: input.durationMs,
    timeoutMs: input.timeoutMs,
  });
  if (session.kind === 'error') return session;

  input.onRecordingStart?.();
  return await session.stopAfter(input.durationMs);
}

export type VoiceIdTimedRecordingSession =
  | (Extract<VoiceIdRecordingSession, { kind: 'recording' }> & {
      stopAfter(durationMs: number): Promise<VoiceIdRecordingResult>;
    })
  | Extract<VoiceIdRecordingSession, { kind: 'error' }>;

export function startVoiceIdClipRecording(input: {
  stream: MediaStream;
  maxDurationMs: number;
  timeoutMs: number;
}): VoiceIdTimedRecordingSession {
  if (typeof MediaRecorder === 'undefined') {
    return { kind: 'error', reason: 'media_recorder_unsupported' };
  }

  const chunks: Blob[] = [];
  const mimeType = selectMediaRecorderMimeType();
  let recorder: MediaRecorder;
  try {
    recorder = mimeType
      ? new MediaRecorder(input.stream, { mimeType })
      : new MediaRecorder(input.stream);
  } catch {
    return { kind: 'error', reason: 'recording_failed' };
  }
  const startedAt = performance.now();

  let cancelled = false;
  const result = new Promise<VoiceIdRecordingResult>((resolve) => {
    let settled = false;
    const settle = (result: VoiceIdRecordingResult): void => {
      if (settled) return;
      settled = true;
      window.clearTimeout(timeout);
      window.clearTimeout(maxDurationStop);
      resolve(result);
    };
    const timeout = window.setTimeout(() => {
      if (recorder.state !== 'inactive') {
        recorder.stop();
      }
      settle({ kind: 'error', reason: 'recording_timeout' });
    }, input.timeoutMs);
    const maxDurationStop = window.setTimeout(() => {
      stopRecorder(recorder);
    }, input.maxDurationMs);

    recorder.addEventListener('dataavailable', (event) => {
      if (event.data.size > 0) {
        chunks.push(event.data);
      }
    });
    recorder.addEventListener('stop', () => {
      if (cancelled) {
        settle({ kind: 'error', reason: 'recording_cancelled' });
        return;
      }

      const blob = new Blob(chunks, { type: recorder.mimeType || mimeType || 'audio/webm' });
      if (blob.size < minimumUsefulRecordingBytes) {
        settle({ kind: 'error', reason: 'empty_recording' });
        return;
      }
      settle({
        kind: 'recorded',
        blob,
        durationMs: Math.round(performance.now() - startedAt),
        recorder: 'MediaRecorder',
      });
    });
    recorder.addEventListener('error', () => {
      settle({ kind: 'error', reason: 'recording_failed' });
    });

    recorder.start(recorderChunkIntervalMs);
  });

  return {
    kind: 'recording',
    stop: async () => {
      stopRecorder(recorder);
      return await result;
    },
    cancel: async () => {
      cancelled = true;
      stopRecorder(recorder);
      return await result;
    },
    stopAfter: async (durationMs: number) => {
      window.setTimeout(() => {
        stopRecorder(recorder);
      }, durationMs);
      return await result;
    },
  };
}

function stopRecorder(recorder: MediaRecorder): void {
  if (recorder.state === 'inactive') return;
  try {
    recorder.requestData();
  } catch {
    // Some browsers throw if final data is already queued.
  }
  recorder.stop();
}

function selectMediaRecorderMimeType(): string | undefined {
  const candidates = ['audio/webm;codecs=opus', 'audio/webm', 'audio/mp4', 'audio/ogg;codecs=opus'];
  if (typeof MediaRecorder.isTypeSupported !== 'function') {
    return undefined;
  }
  return candidates.find((candidate) => MediaRecorder.isTypeSupported(candidate));
}
