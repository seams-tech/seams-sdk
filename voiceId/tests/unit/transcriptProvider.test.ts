import assert from 'node:assert/strict';
import test from 'node:test';
import {
  CloudflareWorkersAiTranscriptProvider,
  parseCloudflareWorkersAiWhisperResponse,
  type VoiceIdCloudflareWorkersAiBinding,
} from '../../server/src/transcript/CloudflareWorkersAiTranscriptProvider.ts';
import { FakeTranscriptProvider } from '../../server/src/transcript/FakeTranscriptProvider.ts';
import {
  buildAudioInput,
  nowIsoDateTime,
  parsePromptPhrase,
} from '../../shared/src/index.ts';

test('fake transcript provider accepts matching phrases', async () => {
  const provider = new FakeTranscriptProvider();
  const result = await provider.matchPhrase({
    audio: makeTranscriptAudio('normal'),
    expectedPhrase: parsePromptPhrase('Walking on clouds'),
    spokenPhrase: parsePromptPhrase('walking on clouds'),
  });

  assert.equal(result.kind, 'accepted');
});

test('fake transcript provider rejects mismatched phrases', async () => {
  const provider = new FakeTranscriptProvider();
  const result = await provider.matchPhrase({
    audio: makeTranscriptAudio('normal'),
    expectedPhrase: parsePromptPhrase('Walking on clouds'),
    spokenPhrase: parsePromptPhrase('Send 1 USDC to Bob'),
  });

  assert.equal(result.kind, 'rejected');
});

test('fake transcript provider returns uncertain for noisy audio', async () => {
  const provider = new FakeTranscriptProvider();
  const result = await provider.matchPhrase({
    audio: makeTranscriptAudio('noisy'),
    expectedPhrase: parsePromptPhrase('Walking on clouds'),
    spokenPhrase: parsePromptPhrase('Walking on clouds'),
  });

  assert.equal(result.kind, 'uncertain');
});

test('Cloudflare Workers AI transcript provider accepts matching ASR text', async () => {
  const ai = new FakeCloudflareAiBinding({ text: 'Walking on clouds.' });
  const provider = new CloudflareWorkersAiTranscriptProvider({
    ai,
    model: '@cf/openai/whisper',
  });

  const result = await provider.matchPhrase({
    audio: makeTranscriptAudio('normal'),
    expectedPhrase: parsePromptPhrase('Walking on clouds'),
    spokenPhrase: parsePromptPhrase('ignored client phrase'),
  });

  assert.equal(result.kind, 'accepted');
  assert.equal(result.spokenNormalized, 'walking on clouds');
  assert.deepEqual(ai.calls, [
    {
      model: '@cf/openai/whisper',
      audio: [1, 2, 3],
    },
  ]);
});

test('Cloudflare Workers AI transcript provider rejects mismatched ASR text', async () => {
  const provider = new CloudflareWorkersAiTranscriptProvider({
    ai: new FakeCloudflareAiBinding({ text: 'Walking through crowds' }),
    model: '@cf/openai/whisper',
  });

  const result = await provider.matchPhrase({
    audio: makeTranscriptAudio('normal'),
    expectedPhrase: parsePromptPhrase('Walking on clouds'),
    spokenPhrase: parsePromptPhrase('Walking on clouds'),
  });

  assert.equal(result.kind, 'rejected');
  assert.equal(result.reason, 'phrase_mismatch');
  assert.equal(result.spokenNormalized, 'walking through crowds');
});

test('Cloudflare Workers AI transcript parser accepts current response shapes', () => {
  assert.equal(parseCloudflareWorkersAiWhisperResponse({ text: ' Walking on clouds ' }), 'Walking on clouds');
  assert.equal(
    parseCloudflareWorkersAiWhisperResponse({
      transcription_info: { text: 'Send 1 USDC to Bob' },
    }),
    'Send 1 USDC to Bob',
  );
  assert.throws(
    () => parseCloudflareWorkersAiWhisperResponse({ word_count: 0 }),
    /response text is missing/,
  );
});

function makeTranscriptAudio(fixtureBehavior: 'normal' | 'noisy') {
  const bytes = new Uint8Array([1, 2, 3]);
  return buildAudioInput(bytes, {
    mimeType: 'audio/webm',
    durationMs: 1500,
    sampleRate: { kind: 'unknown' },
    channelCount: { kind: 'unknown' },
    byteLength: bytes.byteLength,
    capturedAt: nowIsoDateTime(),
    recorder: 'test',
    fixtureBehavior:
      fixtureBehavior === 'noisy'
        ? { kind: 'noisy', speakerLabel: 'owner' }
        : { kind: 'speaker_label', speakerLabel: 'owner' },
  });
}

class FakeCloudflareAiBinding implements VoiceIdCloudflareWorkersAiBinding {
  readonly calls: Array<{ model: '@cf/openai/whisper'; audio: number[] }> = [];

  constructor(private readonly response: unknown) {}

  async run(model: '@cf/openai/whisper', input: { audio: number[] }): Promise<unknown> {
    this.calls.push({ model, audio: input.audio });
    return this.response;
  }
}
