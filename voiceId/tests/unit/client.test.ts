import assert from 'node:assert/strict';
import test from 'node:test';
import { VoiceIdClient } from '../../client/src/index.ts';

test('VoiceIdClient binds fetch before invoking it', async () => {
  const client = new VoiceIdClient({
    baseUrl: 'http://localhost',
    fetch(input, init) {
      assert.equal(this, globalThis);
      assert.equal(String(input), 'http://localhost/voice-id/enrollment/start');
      assert.equal(init?.method, 'POST');

      return Promise.resolve(
        new Response(JSON.stringify({ kind: 'ok', value: { ok: true } }), {
          headers: { 'Content-Type': 'application/json' },
        }),
      );
    },
  });

  const response = await client.startEnrollment({
    userId: 'owner',
    phrase: 'Walking on clouds',
  });

  assert.deepEqual(response, { kind: 'ok', value: { ok: true } });
});
