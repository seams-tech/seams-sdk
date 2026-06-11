import assert from 'node:assert/strict';
import test from 'node:test';
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
