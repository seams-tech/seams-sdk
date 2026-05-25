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
      'computeEcdsaHssRoleLocalPasskeyBootstrapAuthDigest32B64u',
    );
    expect(roleLocalBlock).toContain('passkeyBootstrapIdentity');
    expect(roleLocalBlock).toContain('passkeyBootstrapAuthorization');
    expect(roleLocalBlock).toContain("kind: 'passkey_bootstrap'");
    expect(roleLocalBlock).toContain('thresholdEcdsaHssRoleLocalBootstrap');
    expect(roleLocalBlock).toContain("code: 'role_local_required'");
    expect(roleLocalBlock).not.toContain('thresholdEcdsaHssPrepare(');
    expect(roleLocalBlock).not.toContain('thresholdEcdsaHssRespond(');
    expect(roleLocalBlock).not.toContain('thresholdEcdsaHssFinalize(');
  });

  test('exact shared-key bootstrap derives role-local relayer id without chain-scoping HSS identity', () => {
    const source = readFileSync(BOOTSTRAP_SESSION_URL, 'utf8');
    const functionStart = source.indexOf('export async function bootstrapEcdsaSession');
    expect(functionStart).toBeGreaterThan(-1);
    const roleLocalBlock = source.slice(functionStart);

    expect(roleLocalBlock).toContain('const exactBootstrapRelayerKeyId = exactSessionBootstrap');
    expect(roleLocalBlock).toContain('computeEcdsaHssRoleLocalRelayerKeyId({');
    expect(roleLocalBlock).toContain(
      'computeEcdsaHssRoleLocalPasskeyBootstrapAuthDigest32B64u',
    );
    expect(roleLocalBlock).toContain('passkeyBootstrapAuthorization');
    expect(roleLocalBlock).toContain('walletSessionUserId: userId');
    expect(roleLocalBlock).toContain('exactBootstrapRelayerKeyId ||');
    expect(roleLocalBlock).not.toContain('relayerKeyIdFromHssAuth');
    expect(roleLocalBlock).toContain('clientAdditiveShare32B64u: clientBootstrap.clientShare32B64u');
    expect(roleLocalBlock).not.toContain(
      'clientAdditiveShare32B64u: clientBootstrap.clientCaitSithInput.mappedPrivateShare32B64u',
    );

    const requestStart = roleLocalBlock.indexOf('const bootstrapRequestBase = {');
    expect(requestStart).toBeGreaterThan(-1);
    const requestEnd = roleLocalBlock.indexOf(
      '} satisfies ThresholdEcdsaHssRoleLocalBootstrapRequest;',
      requestStart,
    );
    expect(requestEnd).toBeGreaterThan(requestStart);
    const hssRequestBlock = roleLocalBlock.slice(requestStart, requestEnd);

    expect(hssRequestBlock).not.toContain('chainTarget');
    expect(hssRequestBlock).not.toContain('chainTargetKey');
  });

  test('server verifies passkey WebAuthn authorization before role-local bootstrap persistence', () => {
    for (const routeUrl of [EXPRESS_ROUTE_URL, CLOUDFLARE_ROUTE_URL]) {
      const source = readFileSync(routeUrl, 'utf8');
      const functionStart = source.indexOf('async function authorizeEcdsaHssRoleLocalBootstrap');
      expect(functionStart).toBeGreaterThan(-1);
      const functionEnd = source.indexOf('const presignPriorityGate', functionStart);
      expect(functionEnd).toBeGreaterThan(functionStart);
      const authorizeBlock = source.slice(functionStart, functionEnd);

      expect(authorizeBlock).toContain('passkeyBootstrapAuthorization');
      expect(authorizeBlock).toContain(
        'computeEcdsaHssRoleLocalPasskeyBootstrapAuthDigest32B64u',
      );
      expect(authorizeBlock).toContain('signingRootScopeFromRuntimePolicyScope');
      expect(authorizeBlock).toContain('verifyWebAuthnAuthenticationLite');
      expect(authorizeBlock).toContain('Invalid passkey bootstrap authorization');
      expect(authorizeBlock).not.toContain('parseRegistrationContinuationClaims');
      expect(authorizeBlock).not.toContain('validateRegistrationContinuationBootstrapScope');
      expect(source).not.toContain('registration continuation signing root mismatch');
    }
  });
});
