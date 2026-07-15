import assert from 'node:assert/strict';
import test from 'node:test';
import {
  recordVoiceIdClip,
  startVoiceIdClipRecording,
} from '../../client/src/capture/mediaRecorder.ts';

let recordingStartNotifications = 0;

test('recordVoiceIdClip requests periodic chunks and returns useful recordings', async () => {
  const restore = installFakeBrowserRecording({ chunks: [new Blob([new Uint8Array(2048)])] });
  recordingStartNotifications = 0;
  try {
    const result = await recordVoiceIdClip({
      stream: fakeMediaStream(),
      durationMs: 1,
      timeoutMs: 1000,
      onRecordingStart: countRecordingStart,
    });

    assert.equal(result.kind, 'recorded');
    if (result.kind === 'recorded') {
      assert.equal(result.blob.size, 2048);
      assert.equal(result.blob.type, 'audio/webm;codecs=opus');
    }
    assert.equal(FakeMediaRecorder.instances[0].startTimesliceMs, 250);
    assert.equal(FakeMediaRecorder.instances[0].requestDataCount, 1);
    assert.equal(recordingStartNotifications, 1);
  } finally {
    restore();
  }
});

test('recordVoiceIdClip rejects header-only recordings', async () => {
  const restore = installFakeBrowserRecording({ chunks: [new Blob([new Uint8Array(110)])] });
  try {
    const result = await recordVoiceIdClip({
      stream: fakeMediaStream(),
      durationMs: 1,
      timeoutMs: 1000,
    });

    assert.deepEqual(result, { kind: 'error', reason: 'empty_recording' });
  } finally {
    restore();
  }
});

test('startVoiceIdClipRecording stops when requested', async () => {
  const restore = installFakeBrowserRecording({ chunks: [new Blob([new Uint8Array(2048)])] });
  try {
    const session = startVoiceIdClipRecording({
      stream: fakeMediaStream(),
      maxDurationMs: 1000,
      timeoutMs: 1500,
    });

    assert.equal(session.kind, 'recording');
    if (session.kind !== 'recording') return;

    const result = await session.stop();
    assert.equal(result.kind, 'recorded');
    if (result.kind === 'recorded') {
      assert.equal(result.blob.size, 2048);
    }
    assert.equal(FakeMediaRecorder.instances[0].requestDataCount, 1);
  } finally {
    restore();
  }
});

test('startVoiceIdClipRecording can be cancelled', async () => {
  const restore = installFakeBrowserRecording({ chunks: [new Blob([new Uint8Array(2048)])] });
  try {
    const session = startVoiceIdClipRecording({
      stream: fakeMediaStream(),
      maxDurationMs: 1000,
      timeoutMs: 1500,
    });

    assert.equal(session.kind, 'recording');
    if (session.kind !== 'recording') return;

    const result = await session.cancel();
    assert.deepEqual(result, { kind: 'error', reason: 'recording_cancelled' });
  } finally {
    restore();
  }
});

type FakeRecordingInput = {
  chunks: readonly Blob[];
};

class FakeMediaRecorder extends EventTarget {
  static instances: FakeMediaRecorder[] = [];
  static chunks: readonly Blob[] = [];

  static isTypeSupported(mimeType: string): boolean {
    return mimeType === 'audio/webm;codecs=opus';
  }

  readonly mimeType: string;
  state: RecordingState = 'inactive';
  startTimesliceMs = 0;
  requestDataCount = 0;

  constructor(_stream: MediaStream, options: MediaRecorderOptions = {}) {
    super();
    this.mimeType = options.mimeType ?? 'audio/webm';
    FakeMediaRecorder.instances.push(this);
  }

  start(timesliceMs?: number): void {
    this.state = 'recording';
    this.startTimesliceMs = timesliceMs ?? 0;
  }

  requestData(): void {
    this.requestDataCount += 1;
    for (const chunk of FakeMediaRecorder.chunks) {
      const event = new Event('dataavailable');
      Object.defineProperty(event, 'data', { value: chunk });
      this.dispatchEvent(event);
    }
  }

  stop(): void {
    this.state = 'inactive';
    this.dispatchEvent(new Event('stop'));
  }
}

function installFakeBrowserRecording(input: FakeRecordingInput): () => void {
  FakeMediaRecorder.instances = [];
  FakeMediaRecorder.chunks = input.chunks;
  const originalMediaRecorder = globalThis.MediaRecorder;
  const originalWindow = globalThis.window;
  Object.defineProperty(globalThis, 'MediaRecorder', {
    configurable: true,
    value: FakeMediaRecorder,
  });
  Object.defineProperty(globalThis, 'window', {
    configurable: true,
    value: {
      clearTimeout: globalThis.clearTimeout.bind(globalThis),
      setTimeout: globalThis.setTimeout.bind(globalThis),
    },
  });
  return () => {
    Object.defineProperty(globalThis, 'MediaRecorder', {
      configurable: true,
      value: originalMediaRecorder,
    });
    Object.defineProperty(globalThis, 'window', {
      configurable: true,
      value: originalWindow,
    });
  };
}

function fakeMediaStream(): MediaStream {
  return {} as MediaStream;
}

function countRecordingStart(): void {
  recordingStartNotifications += 1;
}
