import assert from 'node:assert/strict';
import test from 'node:test';
import {
  createVoiceIdCloudflareFetchHandler,
  parseVoiceIdCloudflareEnv,
} from '../../server/src/cloudflare.ts';

const env = {
  VOICEID_PYTHON_VERIFIER_URL: 'https://verifier.example.test/voice-id/verifier/',
  VOICEID_ALLOWED_ORIGINS: 'https://app.example.test',
  VOICEID_STORAGE_KIND: 'memory',
  VOICEID_TRANSCRIPT_PROVIDER: 'fake',
};

test('Cloudflare config keeps E0 verifier and storage settings explicit', () => {
  const config = parseVoiceIdCloudflareEnv(env);
  assert.equal(config.verifier.kind, 'python_http');
  assert.deepEqual(config.http.allowedOrigins, ['https://app.example.test']);
  assert.equal(config.storage.kind, 'memory');
  assert.equal(config.transcript.kind, 'fake');
});

test('Cloudflare handler advertises signing-ineligible evidence', async () => {
  const handler = createVoiceIdCloudflareFetchHandler(env);
  const response = await handler(new Request('https://voice.example.test/voice-id/health'));
  const body = await response.json() as Record<string, unknown>;
  assert.equal(response.status, 200);
  assert.equal(body.evidenceTier, 'experimental_browser_evidence');
  assert.equal(body.signingEligible, false);
});
