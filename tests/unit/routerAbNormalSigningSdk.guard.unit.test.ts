import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

function readRepoSource(relativePath: string): string {
  return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}

test.describe('Router A/B normal-signing SDK source guards', () => {
  test('SDK helper surface uses Wallet Session v2 request builders only', () => {
    const sources = [
      'packages/sdk-web/src/core/rpcClients/relayer/routerAbNormalSigning.ts',
      'packages/sdk-web/src/core/signingEngine/flows/signNear/shared/ed25519PresignFinalize.ts',
      'packages/sdk-web/src/core/signingEngine/flows/signNear/shared/routerAbWalletSessionCredential.ts',
    ].map((relativePath) => ({
      relativePath,
      source: readRepoSource(relativePath),
    }));

    const forbiddenMarkers = [
      'ThresholdEd25519PresignPoolRouteAuth',
      'routerAbNormalSigningGrant',
      'prepareRouterAbNormalSigningV1',
      'finalizeRouterAbNormalSigningV1',
      'intentDigestInput',
      'useWalletSessionCookie',
      "kind: 'cookie'",
    ] as const;
    const offenders = sources.flatMap(({ relativePath, source }) =>
      forbiddenMarkers
        .filter((marker) => source.includes(marker))
        .map((marker) => `${relativePath} contains ${marker}`),
    );

    expect(offenders).toEqual([]);
    expect(sources[0].source).not.toContain('thresholdSessionAuthToken');
    expect(sources[0].source).toContain('RouterAbWalletSessionCredential');
    expect(sources[0].source).toContain('prepareRouterAbNormalSigningV2');
    expect(sources[0].source).toContain('finalizeRouterAbNormalSigningV2');
    expect(sources[0].source).toContain("credentials: 'omit'");
    expect(sources[0].source).toContain('Authorization: `Bearer');
    expect(sources[0].source).toContain("path: '/v2/hss/sign/prepare'");
    expect(sources[0].source).toContain("path: '/v2/hss/sign'");
    expect(sources[0].source).not.toContain("'/v1/hss/sign/prepare'");
    expect(sources[0].source).not.toContain("'/v1/hss/sign'");
    expect(sources[1].source).not.toContain('walletSessionCredentialFromThresholdSessionState');
    expect(sources[1].source).toContain(
      'routerAbWalletSessionCredentialFromResolvedThresholdSessionState',
    );
    expect(sources[2].source).toContain('RouterAbWalletSessionCredential');
    expect(sources[2].source).toContain('walletSessionJwt');
  });
});
