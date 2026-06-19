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
  '/router-ab/v1/signing-worker/sign/prepare',
  '/router-ab/v1/signing-worker/sign/presign-pool/prepare',
  '/router-ab/v1/signing-worker/sign/presign-pool',
  '/router-ab/v1/signing-worker/sign',
  '/router-ab/v1/signing-worker/ecdsa-hss/sign/prepare',
  '/router-ab/v1/signing-worker/ecdsa-hss/sign',
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
    const route = literal.slice(pathStart).split(/\s/)[0];
    if (route) routes.push(route);
  }
  return routes;
}

function constArraySource(source: string, constName: string): string {
  const match = new RegExp(`const\\s+${constName}\\s*=\\s*\\[([\\s\\S]*?)\\];`).exec(source);
  expect(match, `${constName} array is required`).not.toBeNull();
  return match?.[1] || '';
}

function singleQuotedFieldValues(source: string, field: string): string[] {
  return [...source.matchAll(new RegExp(`\\b${field}:\\s*'([^']+)'`, 'g'))].map(
    (match) => match[1] || '',
  );
}

test.describe('Router A/B normal-signing SDK source guards', () => {
  test('local Caddy keeps the Router origin on one upstream', () => {
    const source = readRepoSource('apps/web-client/Caddyfile');
    const routerOriginMatch = source.match(/localhost:9444\s*\{[\s\S]*?\n\}/);
    expect(routerOriginMatch, 'localhost:9444 site block is required').not.toBeNull();

    const routerOriginBlock = routerOriginMatch?.[0] || '';
    const forbiddenMarkers = [
      '@router_ab_public_signing',
      '/v2/router-ab/ed25519/sign',
      '/v1/hss/ecdsa/sign',
      'handle @router_ab',
      'handle_path /v2/router-ab',
      'handle_path /v1/hss/ecdsa',
    ] as const;
    const offenders = forbiddenMarkers.filter((marker) => routerOriginBlock.includes(marker));
    const proxyCount = [...routerOriginBlock.matchAll(/\breverse_proxy\b/g)].length;

    expect(offenders, offenders.join('\n')).toEqual([]);
    expect(proxyCount).toBe(1);
  });

  test('local Router topology docs agree on Caddy and Router server ports', () => {
    const staleRouterServerPort = ['127.0.0.1', '8444'].join(':');
    const sources = [
      'README.md',
      'docs/router-a-b-local-dev.md',
      'apps/web-client/README.md',
      'apps/web-client/env.example',
    ].map((relativePath) => ({
      relativePath,
      source: readRepoSource(relativePath),
    }));

    const offenders = sources.flatMap(({ relativePath, source }) => {
      const fileOffenders: string[] = [];
      if (source.includes(staleRouterServerPort)) {
        fileOffenders.push(`${relativePath} still documents the old Router server port`);
      }
      if (/\brelay (?:API base|API origin|origin|server|upstream)\b/i.test(source)) {
        fileOffenders.push(`${relativePath} still describes the public Router origin as relay`);
      }
      return fileOffenders;
    });

    expect(offenders, offenders.join('\n')).toEqual([]);
    expect(readRepoSource('apps/web-client/Caddyfile')).toContain('reverse_proxy 127.0.0.1:9090');
  });

  test('pnpm router launches one public Router server and three private workers', () => {
    const packageJson = JSON.parse(readRepoSource('package.json')) as {
      scripts?: Record<string, string>;
    };
    expect(packageJson.scripts?.router).toBe(
      'node ./crates/router-ab-dev/scripts/dev-local-workers.mjs --mode logs',
    );
    expect(packageJson.scripts?.['router:multiplex']).toBe(
      'node ./crates/router-ab-dev/scripts/dev-local-workers.mjs --mode multiplex',
    );
    expect(packageJson.scripts).not.toHaveProperty('router:bundled');
    expect(packageJson.scripts).not.toHaveProperty('router:smoke');
    expect(packageJson.scripts).not.toHaveProperty('router:smoke:bundled');
    expect(packageJson.scripts).not.toHaveProperty('site:router');
    expect(packageJson.scripts?.site).toContain(
      'VITE_ROUTER_AB_NORMAL_SIGNING_WORKER_ID=local-signing-worker',
    );

    const source = readRepoSource('crates/router-ab-dev/scripts/dev-local-workers.mjs');
    const workerRolesSource = constArraySource(source, 'workerRoles');
    const staleWorkerRolesSource = constArraySource(source, 'staleWorkerRoles');
    expect(singleQuotedFieldValues(workerRolesSource, 'role')).toEqual([
      'deriver-a',
      'deriver-b',
      'signing-worker',
    ]);
    expect(workerRolesSource).toContain("defaultUrl: 'http://127.0.0.1:9091'");
    expect(workerRolesSource).toContain("defaultUrl: 'http://127.0.0.1:9092'");
    expect(workerRolesSource).toContain("defaultUrl: 'http://127.0.0.1:9093'");
    expect(singleQuotedFieldValues(staleWorkerRolesSource, 'role')).toEqual(['router']);
    expect(source).toContain('const routerServerPort = 9090;');
    expect(source).toContain('const routerServerPublicPort = 9444;');
    expect(source).toContain("spawn('pnpm', ['run', 'server']");
    expect(source).toContain("spawn('pnpm', ['run', 'caddy']");
    expect(source).toContain('const panes = [routerServerPane, ...workerPanes];');
    expect([...source.matchAll(/role: 'router-server'/g)]).toHaveLength(1);
    expect(source).not.toContain("spawn(workerBinary, ['--role', 'router'");
    expect(workerRolesSource).not.toContain("role: 'router'");

    const workerSource = readRepoSource(
      'crates/router-ab-dev/src/bin/router_ab_local_worker.rs',
    );
    expect(workerSource).toContain(
      'router_ab_local_worker no longer exposes a public router role',
    );
  });

  test('local Router A/B runtime files do not own committed smoke fixtures', () => {
    const runtimePaths = [
      'crates/router-ab-dev/src/lib.rs',
      'crates/router-ab-dev/src/bin/router_ab_local_worker.rs',
    ] as const;
    const forbiddenPatterns = [
      {
        label: 'committed fixture account id',
        pattern: /\b(?:alpha|beta|gamma)\.test\.near\b/,
      },
      {
        label: 'committed fixture name',
        pattern: /\bderived-(?:alpha|beta|gamma)\b/,
      },
    ] as const;
    const offenders = runtimePaths.flatMap((relativePath) => {
      const source = readRepoSource(relativePath);
      return forbiddenPatterns
        .filter(({ pattern }) => pattern.test(source))
        .map(({ label }) => `${relativePath} contains ${label}`);
    });

    expect(offenders, offenders.join('\n')).toEqual([]);
  });

  test('SDK helper surface uses Wallet Session v2 request builders only', () => {
    const relayerHttpSource = readRepoSource(
      'packages/sdk-web/src/core/rpcClients/relayer/relayerHttp.ts',
    );
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
    expect(sources[0].source).toContain('buildRelayerJsonPostRequestInit');
    expect(relayerHttpSource).toContain("credentials: 'omit'");
    expect(relayerHttpSource).toContain('Authorization: `Bearer');
    expect(sources[0].source).toContain("path: '/v2/router-ab/ed25519/sign/prepare'");
    expect(sources[0].source).toContain("path: '/v2/router-ab/ed25519/sign'");
    expect(sources[0].source).not.toContain("'/v1/hss/sign/prepare'");
    expect(sources[0].source).not.toContain("'/v1/hss/sign'");
    expect(sources[1].source).not.toContain('walletSessionCredentialFromWalletSessionState');
    expect(sources[1].source).toContain('requireRouterAbEd25519NormalSigningReadyState');
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
    const ecdsaAuthPlanningSource = readRepoSource(
      'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/authPlanning.ts',
    );
    expect(activeSigningSource).toContain('routerAbEcdsaHssNormalSigning');
    expect(activeSigningSource).toContain('walletSessionJwt');
    expect(ecdsaAuthPlanningSource).toContain('resolveEmailOtpEcdsaReadinessSource');
    expect(ecdsaAuthPlanningSource).not.toContain('role_local_ready_state_blob');
    expect(ecdsaAuthPlanningSource).not.toContain(
      'classifyThresholdEcdsaSessionRecordRoleLocalState',
    );
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
      'payload.xClientBaseB64u',
      'payloadForWorker.xClientBaseB64u',
      'persistClientBase',
      'ed25519HssMaterialCacheFromWalletSessionState',
      'repairThresholdEd25519MissingRelayerKey',
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

  test('Ed25519 passkey reconnect prepare binds Router A/B normal-signing state', () => {
    const source = readRepoSource(
      'packages/sdk-web/src/core/signingEngine/flows/signNear/signNear.ts',
    );
    const prepareStart = source.indexOf('prepare: async ({ requiredSignatureUses }');
    const reconnectStart = source.indexOf('reconnect: async ({ authorization, requiredSignatureUses })');
    expect(prepareStart).toBeGreaterThan(0);
    expect(reconnectStart).toBeGreaterThan(prepareStart);
    const prepareSource = source.slice(prepareStart, reconnectStart);

    expect(prepareSource).toContain('thresholdSessionRecord.routerAbNormalSigning');
    expect(prepareSource).toContain(
      'routerAbNormalSigning: thresholdSessionRecord.routerAbNormalSigning',
    );
  });

  test('Ed25519 Router A/B final signing consumes worker material handles', () => {
    const activeSigningSources = [
      'packages/sdk-web/src/core/signingEngine/flows/signNear/signTransactions.ts',
      'packages/sdk-web/src/core/signingEngine/flows/signNear/signDelegate.ts',
      'packages/sdk-web/src/core/signingEngine/flows/signNear/signNep413.ts',
    ].map((relativePath) => ({
      relativePath,
      source: readRepoSource(relativePath),
    }));
    activeSigningSources.push({
      relativePath:
        'packages/sdk-web/src/core/signingEngine/flows/signNear/shared/ed25519PresignFinalize.ts',
      source: readRepoSource(
        'packages/sdk-web/src/core/signingEngine/flows/signNear/shared/ed25519PresignFinalize.ts',
      ).slice(
        readRepoSource(
          'packages/sdk-web/src/core/signingEngine/flows/signNear/shared/ed25519PresignFinalize.ts',
        ).indexOf('async function tryFinalizeRouterAbEd25519NormalSigningSignature'),
      ),
    });
    const offenders = activeSigningSources.flatMap(({ relativePath, source }) =>
      [
        'existingXClientBaseB64u',
        'existingClientVerifyingShareB64u',
        'repairedXClientBaseB64u',
        'xClientBaseB64u: payload.xClientBaseB64u',
        'xClientBaseB64u: payloadForWorker.xClientBaseB64u',
        'xClientBaseB64u: args.xClientBaseB64u',
        'xClientBaseB64u: requestPayload.xClientBaseB64u',
      ]
        .filter((marker) => source.includes(marker))
        .map((marker) => `${relativePath} passes raw client-base material with ${marker}`),
    );

    expect(offenders, offenders.join('\n')).toEqual([]);
    const activeFinalSigningSources = activeSigningSources.filter(
      ({ relativePath }) => !relativePath.includes('/shared/'),
    );
    const finalSigningOffenders: string[] = [];
    for (const { relativePath, source } of activeFinalSigningSources) {
      const firstSigningMaterialLoad = source.indexOf('const signingMaterial = await');
      const firstRepairBranch = source.indexOf('if (isThresholdSignerRepairableMaterialError(err))');
      if (firstSigningMaterialLoad < 0 || firstRepairBranch < 0) {
        finalSigningOffenders.push(`${relativePath} is missing final-signing or repair markers`);
        continue;
      }
      const finalSigningSlice = source.slice(firstSigningMaterialLoad, firstRepairBranch);
      if (!finalSigningSlice.includes('requireThresholdEd25519HssSigningMaterialHandle(')) {
        finalSigningOffenders.push(
          `${relativePath} does not load final signing material from a worker handle`,
        );
      }
      if (finalSigningSlice.includes('ensureThresholdEd25519HssSigningMaterial(')) {
        finalSigningOffenders.push(
          `${relativePath} uses reconstruction-capable material loading before repair`,
        );
      }
    }
    expect(finalSigningOffenders, finalSigningOffenders.join('\n')).toEqual([]);
    for (const { relativePath, source } of activeSigningSources) {
      expect(source, relativePath).toContain('RouterAbEd25519SigningMaterialReady');
    }
    expect(
      readRepoSource(
        'packages/sdk-web/src/core/signingEngine/flows/signNear/shared/ed25519PresignFinalize.ts',
      ),
    ).toContain('createThresholdEd25519RoleSeparatedNormalSigningClientShareFromMaterialHandleWasm');
    const ed25519PresignFinalizeSource = readRepoSource(
      'packages/sdk-web/src/core/signingEngine/flows/signNear/shared/ed25519PresignFinalize.ts',
    );
    expect(ed25519PresignFinalizeSource).not.toContain('xClientBaseB64u');
    expect(ed25519PresignFinalizeSource).toContain(
      'createThresholdEd25519ClientPresignFromMaterialHandleWasm',
    );
    expect(ed25519PresignFinalizeSource).toContain(
      'signThresholdEd25519ClientPresignFromMaterialHandleWasm',
    );
  });

  test('ECDSA-HSS Router A/B presign and signing consume worker material handles', () => {
    const poolSource = readRepoSource(
      'packages/sdk-web/src/core/signingEngine/routerAb/ecdsaHss/presignaturePool.ts',
    );
    const secp256k1Source = readRepoSource(
      'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/signers/secp256k1.ts',
    );
    const loginPrefillSource = readRepoSource(
      'packages/sdk-web/src/core/signingEngine/session/warmCapabilities/ecdsaLoginPrefill.ts',
    );
    const loginPrefillMaterialSource = readRepoSource(
      'packages/sdk-web/src/core/signingEngine/session/warmCapabilities/ecdsaLoginPrefillSigningMaterialSource.ts',
    );
    const materialSource = readRepoSource(
      'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/signers/ecdsaHssClientSigningMaterialSource.ts',
    );

    expect(poolSource).toContain('RouterAbEcdsaHssClientSigningMaterialSource');
    expect(poolSource).toContain('computeSignatureShareFromPresignatureHandle');
    expect(poolSource).not.toContain('thresholdEcdsaComputeSignatureShareFromPresignatureHandleWasm');
    expect(poolSource).not.toContain('thresholdEcdsaComputeSignatureShareWasm');
    expect(poolSource).not.toContain('clientSigningShare32');
    expect(poolSource).not.toContain('mapAdditiveShareToThresholdSignaturesShare2pWasm');
    expect(poolSource).not.toContain('thresholdEcdsaPresignSessionInitWasm');
    expect(poolSource).not.toContain('thresholdEcdsaPresignSessionStepWasm');
    expect(poolSource).not.toContain('thresholdEcdsaPresignSessionAbortWasm');
    expect(poolSource).not.toContain('kShare32');
    expect(poolSource).not.toContain('sigmaShare32');

    const publicSigningInputMatches = [
      ...poolSource.matchAll(
        /export async function signRouterAbEcdsaHssDigestWithPool(?:Hit)?\(args: \{[\s\S]*?\n\}/g,
      ),
    ].map((match) => match[0]);
    expect(publicSigningInputMatches).toHaveLength(2);
    expect(publicSigningInputMatches.join('\n')).toContain(
      'clientSigningMaterial: RouterAbEcdsaHssClientSigningMaterialSource',
    );
    for (const publicInput of publicSigningInputMatches) {
      expect(publicInput).not.toContain('clientSigningShare32:');
    }

    expect(materialSource).toContain(
      "kind: 'router_ab_ecdsa_hss_client_signing_material_source_v1'",
    );
    expect(materialSource).toContain('initRouterAbEcdsaHssClientPresignSessionFromAdditiveShare');
    expect(materialSource).toContain('thresholdEcdsaRoleLocalPresignSessionInitFromMaterialHandleWasm');
    expect(materialSource).toContain(
      'thresholdEcdsaRoleLocalComputeSignatureShareFromPresignatureHandleWasm',
    );
    expect(secp256k1Source).toContain('loadRouterAbEcdsaHssSigningMaterialSource');
    expect(secp256k1Source).toContain('signRouterAbEcdsaHssDigestWithPool');
    expect(secp256k1Source).not.toContain('clientSigningShare32: req');
    expect(secp256k1Source).not.toContain('clientSigningShare32');
    expect(secp256k1Source).not.toContain('openEcdsaRoleLocalSigningShareFromMaterialHandleWasm');
    expect(secp256k1Source).not.toContain('role_local_ready_state_blob');

    expect(loginPrefillSource).toContain('clientSigningMaterial');
    expect(loginPrefillSource).toContain('resolveClientSigningMaterialSource');
    expect(loginPrefillSource).not.toContain('initClientPresignSession');
    expect(loginPrefillSource).not.toContain('resolveClientSigningShare32');
    expect(loginPrefillMaterialSource).toContain('initClientPresignSession');
    expect(loginPrefillMaterialSource).toContain(
      'initRouterAbEcdsaHssClientPresignSessionFromAdditiveShare',
    );
    expect(loginPrefillMaterialSource).toContain(
      'thresholdEcdsaRoleLocalPresignSessionInitFromMaterialHandleWasm',
    );
    expect(loginPrefillMaterialSource).toContain(
      'thresholdEcdsaRoleLocalComputeSignatureShareFromPresignatureHandleWasm',
    );
    const warmSigningSource = readRepoSource(
      'packages/sdk-web/src/core/signingEngine/assembly/ports/warmSigning.ts',
    );
    expect(warmSigningSource).toContain('createEcdsaLoginPrefillClientSigningMaterialSource');
    expect(warmSigningSource).not.toContain('resolveClientSigningShare32');
    expect(loginPrefillSource).not.toContain('openClientSigningShare32');
  });

  test('ECDSA-HSS raw client signing share references stay in named temporary boundaries', () => {
    const allowedRawSharePaths = new Set([
      'packages/sdk-web/src/core/signingEngine/chains/evm/ethSignerWasm.ts',
      'packages/sdk-web/src/core/signingEngine/routerAb/ecdsaHss/clientSigningMaterialBoundary.ts',
      'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/signers/ecdsaHssClientSigningMaterialSource.ts',
      'packages/sdk-web/src/core/signingEngine/session/emailOtp/workerRequests.ts',
      'packages/sdk-web/src/core/signingEngine/session/routerAbSigningWalletSession.typecheck.ts',
      'packages/sdk-web/src/core/signingEngine/session/warmCapabilities/ecdsaLoginPrefillSigningMaterialSource.ts',
      'packages/sdk-web/src/core/signingEngine/threshold/crypto/hssClientSignerWasm.ts',
      'packages/sdk-web/src/core/signingEngine/workerManager/workerTypes.ts',
      'packages/sdk-web/src/core/signingEngine/workerManager/workers/email-otp.worker.ts',
      'packages/sdk-web/src/core/signingEngine/workerManager/workers/hss-client.worker.ts',
    ]);
    const rawShareMarkers = [
      'clientSigningShare32',
      'openClientSigningShare32',
      'mapAdditiveShareToThresholdSignaturesShare2pWasm',
      'thresholdEcdsaPresignSessionInitWasm',
      'thresholdEcdsaPresignSessionStepWasm',
      'thresholdEcdsaPresignSessionAbortWasm',
      'OpenThresholdEcdsaRoleLocalSigningShareFromMaterialHandle',
      'openEcdsaRoleLocalSigningShareFromMaterialHandleWasm',
    ] as const;
    const sourcePaths = listRepoSourceFiles('packages/sdk-web/src/core/signingEngine');
    const offenders = sourcePaths.flatMap((relativePath) => {
      if (allowedRawSharePaths.has(relativePath)) return [];
      const source = readRepoSource(relativePath);
      return rawShareMarkers
        .filter((marker) => source.includes(marker))
        .map((marker) => `${relativePath} contains raw ECDSA-HSS share marker ${marker}`);
    });

    expect(offenders, offenders.join('\n')).toEqual([]);
  });

  test('browser registration clients use shared Router A/B claim boundaries', () => {
    const source = readRepoSource(
      'packages/sdk-web/src/core/rpcClients/relayer/walletRegistration.ts',
    );
    const forbiddenMarkers = [
      'decodeJwtPayloadRecord',
      'payload.routerAbEcdsaHssNormalSigning',
      'payload.routerAbEcdsaHssIssuerBinding',
      'walletSessionJwt.kind',
      'walletSessionJwt.sub',
    ] as const;
    const offenders = forbiddenMarkers
      .filter((marker) => source.includes(marker))
      .map((marker) => `walletRegistration.ts contains inline Wallet Session claim parsing marker ${marker}`);

    expect(offenders, offenders.join('\n')).toEqual([]);
    expect(source).toContain('parseRouterAbEcdsaHssNormalSigningFromWalletRegistrationJwtV1');
  });

  test('SDK Wallet Session route auth uses current bearer-only discriminators', () => {
    const activeAuthBoundaryPaths = [
      'packages/shared-ts/src/utils/sessionTokens.ts',
      'packages/sdk-web/src/core/platform/ports.ts',
      'packages/sdk-web/src/core/rpcClients/relayer/thresholdEcdsa.ts',
      'packages/sdk-web/src/core/rpcClients/relayer/ecdsaUseCaseClient.ts',
      'packages/sdk-web/src/core/signingEngine/threshold/ecdsa/bootstrapSession.ts',
      'packages/sdk-web/src/SeamsWeb/operations/auth/login.ts',
    ];
    const forbiddenMarkers = [
      "kind: 'threshold_session'",
      "case 'threshold_session'",
      "kind === 'threshold_session'",
      "kind !== 'threshold_session'",
    ] as const;
    const ecdsaBearerOnlyBoundaryPaths = activeAuthBoundaryPaths.filter(
      (relativePath) => relativePath !== 'packages/shared-ts/src/utils/sessionTokens.ts',
    );
    const cookieForbiddenMarkers = [
      'CookieSessionAuth',
      "kind: 'cookie'",
      "sessionKind?: 'jwt' | 'cookie'",
      "sessionKind: 'jwt' | 'cookie'",
      "sessionKind === 'cookie'",
      'normalizeJwtCookieSessionKind',
    ] as const;
    const legacyDiscriminatorOffenders = activeAuthBoundaryPaths.flatMap((relativePath) => {
      const source = readRepoSource(relativePath);
      return forbiddenMarkers
        .filter((marker) => source.includes(marker))
        .map((marker) => `${relativePath} contains ${marker}`);
    });
    const cookieAuthOffenders = ecdsaBearerOnlyBoundaryPaths.flatMap((relativePath) => {
      const source = readRepoSource(relativePath);
      return cookieForbiddenMarkers
        .filter((marker) => source.includes(marker))
        .map((marker) => `${relativePath} contains ${marker}`);
    });
    const offenders = [...legacyDiscriminatorOffenders, ...cookieAuthOffenders];

    expect(offenders, offenders.join('\n')).toEqual([]);
    expect(readRepoSource('packages/shared-ts/src/utils/sessionTokens.ts')).toContain(
      "kind: 'wallet_session'",
    );
  });

  test('signing-capable Wallet Session issuance stays JWT-only inside SDK internals', () => {
    const signingWalletSessionPaths = [
      'packages/sdk-web/src/core/signingEngine/session/routerAbSigningWalletSession.ts',
      'packages/sdk-web/src/core/signingEngine/session/emailOtp/ecdsaEnrollment.ts',
      'packages/sdk-web/src/core/signingEngine/session/emailOtp/ecdsaLogin.ts',
      'packages/sdk-web/src/core/signingEngine/session/emailOtp/workerRequests.ts',
      'packages/sdk-web/src/core/signingEngine/session/passkey/ed25519SessionProvision.ts',
      'packages/sdk-web/src/core/signingEngine/session/passkey/ecdsaSessionProvision.ts',
      'packages/sdk-web/src/core/signingEngine/session/warmCapabilities/persistence.ts',
      'packages/sdk-web/src/core/signingEngine/session/warmCapabilities/ecdsaProvisionPlan.ts',
      'packages/sdk-web/src/core/signingEngine/threshold/ecdsa/activation.ts',
      'packages/sdk-web/src/core/signingEngine/threshold/ecdsa/bootstrapSession.ts',
      'packages/sdk-web/src/core/signingEngine/threshold/ecdsa/connectSession.ts',
      'packages/sdk-web/src/core/signingEngine/threshold/ed25519/connectSession.ts',
      'packages/sdk-web/src/core/signingEngine/threshold/ed25519/walletSession.ts',
      'packages/sdk-web/src/core/signingEngine/workerManager/workerTypes.ts',
      'packages/sdk-web/src/core/signingEngine/workerManager/workers/email-otp.worker.ts',
    ];
    const forbiddenMarkers = [
      'cookie_passkey',
      "sessionKind: 'cookie'",
      "sessionKind?: 'jwt' | 'cookie'",
      "payload.sessionKind === 'cookie'",
      "sessionKind === 'cookie'",
    ] as const;
    const offenders = signingWalletSessionPaths.flatMap((relativePath) => {
      const source = readRepoSource(relativePath);
      return forbiddenMarkers
        .filter((marker) => source.includes(marker))
        .map((marker) => `${relativePath} contains ${marker}`);
    });

    expect(offenders, offenders.join('\n')).toEqual([]);
    expect(
      readRepoSource(
        'packages/sdk-web/src/core/signingEngine/session/routerAbSigningWalletSession.ts',
      ),
    ).toContain("record.thresholdSessionKind !== 'jwt'");
  });

  test('Ed25519 missing-key repair refreshes worker-owned material handles before retry', () => {
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
      if (source.includes('repairThresholdEd25519MissingRelayerKey')) {
        offenders.push(`${relativePath} still calls the raw HSS client-base repair helper`);
      }
      if (!source.includes('forceRefresh: true')) {
        offenders.push(`${relativePath} does not force-refresh worker signing material on repair`);
      }
      if (!source.includes('requestPayload = buildRequestPayload(repairedSigningMaterial);')) {
        offenders.push(
          `${relativePath} does not rebuild the Router A/B request payload from repaired material`,
        );
      }
      if (!source.includes('walletSessionJwt: routerAbReadyState.credential.walletSessionJwt')) {
        offenders.push(
          `${relativePath} does not pass Wallet Session JWT from ready state to material refresh`,
        );
      }
      if (!source.includes('persistSigningMaterial: walletSessionState.persistSigningMaterial')) {
        offenders.push(`${relativePath} does not persist the refreshed worker material handle`);
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

  test('Ed25519 registration prewarm and passkey reconnect require signable Router A/B state', () => {
    const offenders: string[] = [];
    const warmBootstrap = readRepoSource(
      'packages/sdk-web/src/SeamsWeb/operations/session/thresholdWarmSessionBootstrap.ts',
    );
    if (!warmBootstrap.includes('parseRouterAbEd25519SigningWalletSessionFromRecord(sessionRecord)')) {
      offenders.push('Ed25519 prewarm does not use the strict Router A/B signable parser');
    }
    if (!warmBootstrap.includes('material prewarm requires signable Router A/B Wallet Session state')) {
      offenders.push('Ed25519 prewarm can still return without Wallet Session auth diagnostics');
    }
    if (!warmBootstrap.includes('Threshold Ed25519 registration warm session missing Router A/B Wallet Session state')) {
      offenders.push('Ed25519 registration persistence does not fail closed on missing Router A/B state');
    }

    const signTransactions = readRepoSource(
      'packages/sdk-web/src/core/signingEngine/flows/signNear/signTransactions.ts',
    );
    if (!signTransactions.includes('classifyRouterAbEd25519PersistedSigningRecord(refreshedRecord)')) {
      offenders.push('Passkey reconnect does not classify the refreshed Ed25519 record');
    }
    if (!signTransactions.includes("refreshedRecordState.kind === 'pending_material'")) {
      offenders.push('Passkey reconnect does not repair pending Ed25519 worker material');
    }
    if (!signTransactions.includes('passkey Ed25519 reconnect did not produce signable Router A/B state')) {
      offenders.push('Passkey reconnect does not fail closed with explicit Router A/B diagnostics');
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
    ].filter(
      (relativePath) => relativePath !== 'tests/unit/routerAbNormalSigningSdk.guard.unit.test.ts',
    );
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
