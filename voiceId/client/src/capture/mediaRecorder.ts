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
        | 'empty_recording'
        | 'media_recorder_unsupported'
        | 'recording_failed'
        | 'recording_timeout';
    };

const minimumUsefulRecordingBytes = 1024;
const recorderChunkIntervalMs = 250;

export async function recordVoiceIdClip(input: {
  stream: MediaStream;
  durationMs: number;
  timeoutMs: number;
}): Promise<VoiceIdRecordingResult> {
  if (typeof MediaRecorder === 'undefined') {
    return { kind: 'error', reason: 'media_recorder_unsupported' };
  }

  const chunks: Blob[] = [];
  const mimeType = selectMediaRecorderMimeType();
  const recorder = mimeType
    ? new MediaRecorder(input.stream, { mimeType })
    : new MediaRecorder(input.stream);
  const startedAt = performance.now();

  return await new Promise<VoiceIdRecordingResult>((resolve) => {
    let settled = false;
    const settle = (result: VoiceIdRecordingResult): void => {
      if (settled) return;
      settled = true;
      window.clearTimeout(timeout);
      window.clearTimeout(stopRecording);
      resolve(result);
    };
    const timeout = window.setTimeout(() => {
      if (recorder.state !== 'inactive') {
        recorder.stop();
      }
      settle({ kind: 'error', reason: 'recording_timeout' });
    }, input.timeoutMs);
    const stopRecording = window.setTimeout(() => {
      stopRecorder(recorder);
    }, input.durationMs);

    recorder.addEventListener('dataavailable', (event) => {
      if (event.data.size > 0) {
        chunks.push(event.data);
      }
    });
    recorder.addEventListener('stop', () => {
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
  const candidates = [
    'audio/webm;codecs=opus',
    'audio/webm',
    'audio/mp4',
    'audio/ogg;codecs=opus',
  ];
  if (typeof MediaRecorder.isTypeSupported !== 'function') {
    return undefined;
  }
  return candidates.find((candidate) => MediaRecorder.isTypeSupported(candidate));
}
