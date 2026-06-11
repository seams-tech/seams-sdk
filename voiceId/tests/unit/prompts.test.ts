import assert from 'node:assert/strict';
import test from 'node:test';
import { normalizePromptPhrase, parsePromptPhrase } from '../../shared/src/index.ts';

test('normalizes digit phrase variants', () => {
  assert.equal(normalizePromptPhrase(parsePromptPhrase('one one six five five four')), '116554');
  assert.equal(normalizePromptPhrase(parsePromptPhrase('1, 1, 6, 5, 5, 4')), '116554');
});

test('normalizes command phrases', () => {
  assert.equal(
    normalizePromptPhrase(parsePromptPhrase('Send 50 USDC to Bob.NEAR')),
    'send 50 usdc to bob.near',
  );
});
