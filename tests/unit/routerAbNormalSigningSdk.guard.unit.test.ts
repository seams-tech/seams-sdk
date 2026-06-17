import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

function readRepoSource(relativePath: string): string {
  return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}

function listRepoSourceFiles(relativePath: string): string[] {
  const absolutePath = path.join(repoRoot, relativePath);
  const stat = fs.statSync(absolutePath);
  if (stat.isFile()) {
    return /\.(ts|tsx)$/.test(relativePath) ? [relativePath] : [];
  }
  return fs.readdirSync(absolutePath, { withFileTypes: true }).flatMap((entry) => {
    const childPath = path.join(relativePath, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === 'dist' || entry.name === 'node_modules') return [];
      return listRepoSourceFiles(childPath);
    }
    return /\.(ts|tsx)$/.test(entry.name) ? [childPath] : [];
  });
}

const currentRouterAbV1RouteLiterals = [
  '/v1/hss/ecdsa/register',
  '/v1/hss/ecdsa/export',
  '/v1/hss/ecdsa/recover',
  '/v1/hss/ecdsa/refresh',
  '/v1/hss/ecdsa/healthz',
  '/v1/hss/ecdsa/key-identities',
  '/v1/hss/ecdsa/bootstrap',
  '/v1/hss/ecdsa/export/share',
  '/v1/hss/ecdsa/sign/prepare',
  '/v1/hss/ecdsa/sign',
  '/v1/hss/ecdsa/presignature-pool/fill/init',
  '/v1/hss/ecdsa/presignature-pool/fill/step',
  '/router-ab/v1/signing-worker/ecdsa-hss/presignature-pool/put',
] as const;

function extractRouterAbV1RouteLiterals(source: string): string[] {
  const routes: string[] = [];
  const literalPattern = /(['"`])([^'"`]*(?:\/v1\/hss|\/router-ab\/v1)[^'"`]*)\1/g;
  let match: RegExpExecArray | null;
  while ((match = literalPattern.exec(source))) {
    const literal = match[2] || '';
    const hssIndex = literal.indexOf('/v1/hss');
    const privateIndex = literal.indexOf('/router-ab/v1');
    const pathStart =
      hssIndex >= 0 && privateIndex >= 0
        ? Math.min(hssIndex, privateIndex)
        : hssIndex >= 0
          ? hssIndex
          : privateIndex;
    if (pathStart < 0) continue;
    routes.push(literal.slice(pathStart));
  }
  return routes;
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
      'routerAbWalletSessionCredentialFromResolvedWalletSessionState',
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
    expect(sources[1].source).not.toContain('walletSessionCredentialFromWalletSessionState');
    expect(sources[1].source).toContain(
      'requireRouterAbEd25519NormalSigningReadyState',
    );
    expect(sources[2].source).toContain('RouterAbWalletSessionCredential');
    expect(sources[2].source).toContain('requireRouterAbEd25519NormalSigningReadyState');
    expect(sources[2].source).toContain('walletSessionJwt');
  });

  test('ECDSA active signing reads Wallet Session auth from Router A/B ready state only', () => {
    const activeEcdsaSigningPaths = [
      'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/signEvmFamily.ts',
      'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/authPlanning.ts',
      'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/ecdsaLanes.ts',
      'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/preparedSigning.ts',
      'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/readySecp256k1Material.ts',
      'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/signers/secp256k1.ts',
      'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/signingFlowRuntime.ts',
      'packages/sdk-web/src/core/signingEngine/routerAb/ecdsaHss/presignaturePool.ts',
    ];
    const forbiddenMarkers = [
      'signerSession.transport.auth',
      'thresholdSessionAuthToken',
      'useThresholdSessionCookie',
      "kind: 'cookie'",
      'sessionKind',
    ] as const;
    const offenders = activeEcdsaSigningPaths.flatMap((relativePath) => {
      const source = readRepoSource(relativePath);
      return forbiddenMarkers
        .filter((marker) => source.includes(marker))
        .map((marker) => `${relativePath} contains ${marker}`);
    });

    expect(offenders, offenders.join('\n')).toEqual([]);
    const activeSigningSource = readRepoSource(
      'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/signEvmFamily.ts',
    );
    expect(activeSigningSource).toContain('routerAbEcdsaHssNormalSigning');
    expect(activeSigningSource).toContain('walletSessionJwt');
  });

  test('Ed25519 active signing reads Wallet Session auth from Router A/B ready state only', () => {
    const activeEd25519SigningPaths = [
      'packages/sdk-web/src/core/signingEngine/flows/signNear/signNear.ts',
      'packages/sdk-web/src/core/signingEngine/flows/signNear/signTransactions.ts',
      'packages/sdk-web/src/core/signingEngine/flows/signNear/signDelegate.ts',
      'packages/sdk-web/src/core/signingEngine/flows/signNear/signNep413.ts',
    ];
    const forbiddenMarkers = [
      'thresholdSessionAuthToken',
      'thresholdSessionKind',
      'ThresholdSignerConfig',
      'buildNearWorkerSigningEnvelope',
    ] as const;
    const offenders = activeEd25519SigningPaths.flatMap((relativePath) => {
      const source = readRepoSource(relativePath);
      return forbiddenMarkers
        .filter((marker) => source.includes(marker))
        .map((marker) => `${relativePath} contains ${marker}`);
    });

    expect(offenders, offenders.join('\n')).toEqual([]);
    const routerAbExecutorPaths = activeEd25519SigningPaths.filter(
      (relativePath) => !relativePath.endsWith('/signNear.ts'),
    );
    for (const relativePath of routerAbExecutorPaths) {
      const source = readRepoSource(relativePath);
      expect(source).toContain('requireRouterAbEd25519NormalSigningReadyState');
      expect(source).toContain('walletSessionJwt');
    }
  });

  test('Ed25519 missing-key repair retries Router A/B signing executors', () => {
    const repairPaths = [
      {
        relativePath: 'packages/sdk-web/src/core/signingEngine/flows/signNear/signTransactions.ts',
        retryMarkers: ['signPreparedTransactionOperation', 'sign: executeSignRequest'],
      },
      {
        relativePath: 'packages/sdk-web/src/core/signingEngine/flows/signNear/signDelegate.ts',
        retryMarkers: ['return await executeDelegateRequest(requestPayload);'],
      },
      {
        relativePath: 'packages/sdk-web/src/core/signingEngine/flows/signNear/signNep413.ts',
        retryMarkers: ['return await executeNep413Request(requestPayload);'],
      },
    ];
    const offenders: string[] = [];
    for (const { relativePath, retryMarkers } of repairPaths) {
      const source = readRepoSource(relativePath);
      if (!source.includes('repairThresholdEd25519MissingRelayerKey')) {
        offenders.push(`${relativePath} does not call the HSS client-base repair helper`);
      }
      if (!source.includes('requestPayload = buildRequestPayload(repairedXClientBaseB64u);')) {
        offenders.push(`${relativePath} does not rebuild the Router A/B request payload after repair`);
      }
      if (!source.includes('walletSessionJwt: routerAbReadyState.credential.walletSessionJwt')) {
        offenders.push(`${relativePath} does not pass Wallet Session JWT from ready state to repair`);
      }
      for (const marker of retryMarkers) {
        if (!source.includes(marker)) {
          offenders.push(`${relativePath} missing Router A/B repair retry marker ${marker}`);
        }
      }
      if (source.includes('/threshold-ed25519/')) {
        offenders.push(`${relativePath} repair path can reference old threshold Ed25519 routes`);
      }
      if (source.includes('thresholdSessionAuthToken')) {
        offenders.push(`${relativePath} repair path can read legacy threshold session auth`);
      }
    }

    expect(offenders, offenders.join('\n')).toEqual([]);
  });

  test('legacy public threshold signing surfaces stay confined to known deletion blockers', () => {
    const scannedPaths = [
      ...listRepoSourceFiles('packages/sdk-web/src/core/rpcClients/relayer'),
      ...listRepoSourceFiles('packages/sdk-web/src/core/signingEngine'),
      ...listRepoSourceFiles('packages/sdk-web/src/core/types'),
      ...listRepoSourceFiles('packages/sdk-web/src/threshold.ts'),
      ...listRepoSourceFiles('packages/sdk-server-ts/src/core/ThresholdService'),
      ...listRepoSourceFiles('packages/sdk-server-ts/src/router'),
    ];
    const zeroToleranceLegacyTokens = [
      '/threshold-ecdsa/authorize',
      '/threshold-ecdsa/presign/init',
      '/threshold-ecdsa/presign/step',
      '/threshold-ecdsa/sign/init',
      '/threshold-ecdsa/sign/finalize',
      '/threshold-ed25519/presign/refill',
      '/threshold-ed25519/authorize',
      '/threshold-ed25519/sign/init',
      '/threshold-ed25519/sign/finalize',
      '/threshold-ed25519/sign/finalize-and-dispatch',
      '/threshold-ed25519/session',
      '/threshold-ed25519/hss/prepare',
      '/threshold-ed25519/hss/respond',
      '/threshold-ed25519/hss/finalize',
      '/threshold-ed25519/internal/cosign/init',
      '/threshold-ed25519/internal/cosign/finalize',
      '/threshold-ecdsa/key-identities',
      '/threshold-ecdsa/hss/bootstrap',
      '/threshold-ecdsa/hss/export/share',
      '/threshold-ecdsa/internal/cosign/init',
      '/threshold-ecdsa/internal/cosign/finalize',
      '/threshold/signing-session-seal',
      'authorizeEcdsaWithSession',
      'ecdsaPresignInit',
      'ecdsaPresignStep',
      'ecdsaSignInit',
      'ecdsaSignFinalize',
      'signThresholdEcdsaDigestWithPool',
      'refillThresholdEd25519PresignPool',
      'finalizeThresholdEd25519Presign',
      'tryFinalizeThresholdEd25519NearTransactionPresign',
      'tryFinalizeThresholdEd25519SignatureOnlyPresign',
      'ThresholdEd25519PresignPoolRouteAuth',
      'buildNearWorkerSigningEnvelope',
      'poolFill?: never',
    ] as const;
    const localEcdsaPoolFillAllowedFiles = [
      'packages/sdk-server-ts/src/core/ThresholdService/routerAb/ecdsaHssPoolFillHandlers.ts',
      'packages/sdk-server-ts/src/core/ThresholdService/stores/EcdsaSigningStore.ts',
      'packages/sdk-server-ts/src/core/ThresholdService/validation.ts',
    ] as const;
    const offenders: string[] = [];

    for (const relativePath of scannedPaths) {
      const source = readRepoSource(relativePath);
      for (const token of zeroToleranceLegacyTokens) {
        if (source.includes(token)) {
          offenders.push(`${relativePath} contains removed legacy signing token ${token}`);
        }
      }
      if (
        source.includes('local_threshold_ecdsa_presignature_pool') &&
        !localEcdsaPoolFillAllowedFiles.includes(
          relativePath as (typeof localEcdsaPoolFillAllowedFiles)[number],
        )
      ) {
        offenders.push(
          `${relativePath} contains local_threshold_ecdsa_presignature_pool outside persisted ECDSA presign record cleanup surfaces`,
        );
      }
    }

    const thresholdEntrypoint = readRepoSource('packages/sdk-web/src/threshold.ts');
    for (const token of ['connectEd25519Session', 'connectEcdsaSession'] as const) {
      if (thresholdEntrypoint.includes(token)) {
        offenders.push(`packages/sdk-web/src/threshold.ts re-exports internal ${token}`);
      }
    }

    expect(offenders, offenders.join('\n')).toEqual([]);
  });

  test('Router A/B v1 route literals stay confined to current protocol contracts', () => {
    const scannedPaths = [
      ...listRepoSourceFiles('packages/shared-ts/src'),
      ...listRepoSourceFiles('packages/sdk-web/src/core/rpcClients/relayer'),
      ...listRepoSourceFiles('packages/sdk-web/src/core/signingEngine'),
      ...listRepoSourceFiles('packages/sdk-server-ts/src/core/ThresholdService'),
      ...listRepoSourceFiles('packages/sdk-server-ts/src/router'),
      ...listRepoSourceFiles('tests/unit'),
    ].filter((relativePath) => relativePath !== 'tests/unit/routerAbNormalSigningSdk.guard.unit.test.ts');
    const allowed = new Set<string>(currentRouterAbV1RouteLiterals);
    const offenders = scannedPaths.flatMap((relativePath) => {
      const source = readRepoSource(relativePath);
      return extractRouterAbV1RouteLiterals(source)
        .filter((route) => !allowed.has(route))
        .map((route) => `${relativePath} contains unclassified Router A/B v1 route ${route}`);
    });

    expect(offenders, offenders.join('\n')).toEqual([]);
  });
});
