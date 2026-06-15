import { expect, test } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';

const WEB_SERVER_INDEX = (() => {
  const fromRoot = path.resolve(process.cwd(), 'apps/web-server/src/index.ts');
  if (fs.existsSync(fromRoot)) return fromRoot;
  return path.resolve(process.cwd(), '../apps/web-server/src/index.ts');
})();

function extractFunctionBody(source: string, functionName: string): string {
  const marker = `function ${functionName}`;
  const start = source.indexOf(marker);
  if (start < 0) throw new Error(`${functionName} not found`);
  let parenDepth = 0;
  let sawSignature = false;
  let open = -1;
  for (let i = start + marker.length; i < source.length; i += 1) {
    const ch = source[i];
    if (ch === '(') {
      sawSignature = true;
      parenDepth += 1;
      continue;
    }
    if (ch === ')') {
      parenDepth -= 1;
      continue;
    }
    if (sawSignature && parenDepth === 0 && ch === '{') {
      open = i;
      break;
    }
  }
  if (open < 0) throw new Error(`${functionName} body start not found`);
  let depth = 0;
  for (let i = open; i < source.length; i += 1) {
    const ch = source[i];
    if (ch === '{') depth += 1;
    if (ch === '}') {
      depth -= 1;
      if (depth === 0) return source.slice(open + 1, i);
    }
  }
  throw new Error(`${functionName} body end not found`);
}

test.describe('Router A/B public keyset env boundary', () => {
  test('self-host production parser accepts only canonical ROUTER_AB keyset env', () => {
    const source = fs.readFileSync(WEB_SERVER_INDEX, 'utf8');
    const body = extractFunctionBody(source, 'resolveCanonicalRouterAbPublicKeysetFromEnv');

    for (const required of [
      'ROUTER_AB_SIGNER_A_ENVELOPE_HPKE_PUBLIC_KEY',
      'ROUTER_AB_SIGNER_B_ENVELOPE_HPKE_PUBLIC_KEY',
      'ROUTER_AB_SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY',
      'ROUTER_AB_SIGNER_A_PEER_VERIFYING_KEY_HEX',
      'ROUTER_AB_SIGNER_B_PEER_VERIFYING_KEY_HEX',
    ]) {
      expect(body).toContain(required);
    }

    for (const legacyAliasUsage of [
      "requireEnv(env, 'SIGNER_A_ENVELOPE_HPKE_PUBLIC_KEY')",
      "requireEnv(env, 'SIGNER_B_ENVELOPE_HPKE_PUBLIC_KEY')",
      "requireEnv(env, 'SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY')",
      "requireEnv(env, 'DERIVER_A_PEER_VERIFYING_KEY')",
      "requireEnv(env, 'DERIVER_B_PEER_VERIFYING_KEY')",
    ]) {
      expect(body).not.toContain(legacyAliasUsage);
    }
  });

  test('local-dev keyset defaults cannot activate under NODE_ENV production', () => {
    const source = fs.readFileSync(WEB_SERVER_INDEX, 'utf8');
    const localDevBody = extractFunctionBody(source, 'shouldUseLocalDevRouterAbPublicKeyset');
    const resolverBody = extractFunctionBody(source, 'resolveRouterAbPublicKeysetFromEnv');

    expect(localDevBody).toContain('NODE_ENV');
    expect(localDevBody).toContain('production');
    expect(localDevBody).toContain('ROUTER_AB_NORMAL_SIGNING_WORKER_ID');
    expect(resolverBody).toContain('canonical ROUTER_AB_* public keyset env is required');
  });
});
