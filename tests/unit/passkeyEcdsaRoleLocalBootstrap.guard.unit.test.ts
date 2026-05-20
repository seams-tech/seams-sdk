import { expect, test } from '@playwright/test';
import { readFileSync } from 'node:fs';

const BOOTSTRAP_SESSION_URL = new URL(
  '../../client/src/core/signingEngine/threshold/ecdsa/bootstrapSession.ts',
  import.meta.url,
);
const EXPRESS_ROUTE_URL = new URL(
  '../../server/src/router/express/routes/thresholdEcdsa.ts',
  import.meta.url,
);
const CLOUDFLARE_ROUTE_URL = new URL(
  '../../server/src/router/cloudflare/routes/thresholdEcdsa.ts',
  import.meta.url,
);

test.describe('Passkey ECDSA role-local first bootstrap guard', () => {
  test('client computes passkey challenge and reaches role-local bootstrap before hidden-eval fallback', () => {
    const source = readFileSync(BOOTSTRAP_SESSION_URL, 'utf8');
    const functionStart = source.indexOf('export async function bootstrapEcdsaSession');
    expect(functionStart).toBeGreaterThan(-1);
    const roleLocalBlock = source.slice(functionStart);

    expect(roleLocalBlock).toContain(
      'computeEcdsaHssRoleLocalPasskeyFirstBootstrapAuthDigest32B64u',
    );
    expect(roleLocalBlock).toContain('passkeyFirstBootstrapIdentity');
    expect(roleLocalBlock).toContain('passkeyFirstBootstrapAuthorization');
    expect(roleLocalBlock).toContain("kind: 'passkey_first_bootstrap'");
    expect(roleLocalBlock).toContain('thresholdEcdsaHssRoleLocalBootstrap');
    expect(roleLocalBlock).toContain("code: 'role_local_required'");
    expect(roleLocalBlock).not.toContain('thresholdEcdsaHssPrepare(');
    expect(roleLocalBlock).not.toContain('thresholdEcdsaHssRespond(');
    expect(roleLocalBlock).not.toContain('thresholdEcdsaHssFinalize(');
  });

  test('server verifies passkey WebAuthn authorization before role-local bootstrap persistence', () => {
    for (const routeUrl of [EXPRESS_ROUTE_URL, CLOUDFLARE_ROUTE_URL]) {
      const source = readFileSync(routeUrl, 'utf8');
      const functionStart = source.indexOf('async function authorizeEcdsaHssRoleLocalFirstBootstrap');
      expect(functionStart).toBeGreaterThan(-1);
      const functionEnd = source.indexOf('const presignPriorityGate', functionStart);
      expect(functionEnd).toBeGreaterThan(functionStart);
      const authorizeBlock = source.slice(functionStart, functionEnd);

      expect(authorizeBlock).toContain('passkeyFirstBootstrapAuthorization');
      expect(authorizeBlock).toContain(
        'computeEcdsaHssRoleLocalPasskeyFirstBootstrapAuthDigest32B64u',
      );
      expect(authorizeBlock).toContain('signingRootScopeFromRuntimePolicyScope');
      expect(authorizeBlock).toContain('verifyWebAuthnAuthenticationLite');
      expect(authorizeBlock).toContain('Invalid passkey bootstrap authorization');
    }
  });
});
