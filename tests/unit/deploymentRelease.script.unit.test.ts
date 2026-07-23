import { expect, test } from '@playwright/test';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

type ComponentDto = {
  readonly name: string;
  readonly kind: string;
  readonly artifactName: string;
  readonly contentDigestSha256: string;
  readonly sourceSha: string;
  readonly target: string;
  readonly releaseId: string;
};

type FixtureOptions = {
  readonly components?: readonly unknown[];
  readonly target?: string;
  readonly sourceSha?: string;
  readonly acceptedValidationRunId?: string;
  readonly artifactRunId?: string;
  readonly createdAt?: string;
};

type CommandResult = {
  readonly status: number | null;
  readonly stdout: string;
  readonly stderr: string;
};

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const releaseScript = path.join(repoRoot, 'scripts/deployment-release.mjs');
const sourceSha = 'a'.repeat(40);
const contentDigest = 'b'.repeat(64);
const createdAt = '2026-07-23T00:00:00.000Z';
const tempRoots = new Set<string>();

test.afterEach(cleanupTempRoots);

function createComponent(
  name: string,
  kind: string,
  index: number,
  input: { readonly sourceSha?: string; readonly target?: string } = {},
): ComponentDto {
  return {
    name,
    kind,
    artifactName: `release-artifact-${index}`,
    contentDigestSha256: contentDigest,
    sourceSha: input.sourceSha ?? sourceSha,
    target: input.target ?? 'staging',
    releaseId: `worker-release-${index}`,
  };
}

function validComponents(): ComponentDto[] {
  return [
    createComponent('mpc-router', 'router', 1),
    createComponent('deriver-a', 'deriver-a', 2),
    createComponent('deriver-b', 'deriver-b', 3),
    createComponent('signing-worker', 'signing-worker', 4),
    createComponent('gateway', 'gateway-wasm', 5),
    createComponent('site', 'pages', 6),
    createComponent('signer-iframe', 'sdk-r2', 7),
  ];
}

function createFixture(options: FixtureOptions = {}) {
  const root = mkdtempSync(path.join(os.tmpdir(), 'seams-deployment-release-'));
  tempRoots.add(root);
  const fixture = {
    root,
    components: options.components ?? validComponents(),
    target: options.target ?? 'staging',
    sourceSha: options.sourceSha ?? sourceSha,
    acceptedValidationRunId: options.acceptedValidationRunId ?? '1001',
    artifactRunId: options.artifactRunId ?? '2002',
    createdAt: options.createdAt ?? createdAt,
  };
  const selectedComponents = fixture.components
    .map((component) => componentNameForKind(String(component.kind)))
    .sort();
  const componentsFile = path.join(root, 'components.json');
  const buildIdentityFile = path.join(root, 'build-identity.json');
  const migrationsFile = path.join(root, 'migrations.json');
  const output = path.join(root, 'release-set.json');
  writeJson(componentsFile, fixture.components);
  writeJson(buildIdentityFile, {
    node: 'v22.0.0',
    rust: '1.96.0',
    selectedComponents,
  });
  writeJson(migrationsFile, {
    gateway: { fingerprint: 'c'.repeat(64), migrations: ['0001_init.sql'] },
  });
  return { ...fixture, componentsFile, buildIdentityFile, migrationsFile, output };
}

function componentNameForKind(kind: string): string {
  const componentNamesByKind: Record<string, string> = {
    router: 'router',
    'deriver-a': 'deriver-a',
    'deriver-b': 'deriver-b',
    'signing-worker': 'signing-worker',
    'gateway-wasm': 'gateway',
    pages: 'site',
    'sdk-r2': 'signer-iframe',
  };
  return componentNamesByKind[kind] ?? kind;
}

function createArgs(
  fixture: ReturnType<typeof createFixture>,
  overrides: {
    readonly target?: string;
    readonly sourceSha?: string;
    readonly acceptedValidationRunId?: string;
    readonly artifactRunId?: string;
  } = {},
): string[] {
  return [
    'create',
    '--components-file',
    fixture.componentsFile,
    '--target',
    overrides.target ?? fixture.target,
    '--source-sha',
    overrides.sourceSha ?? fixture.sourceSha,
    '--accepted-validation-run-id',
    overrides.acceptedValidationRunId ?? fixture.acceptedValidationRunId,
    '--artifact-run-id',
    overrides.artifactRunId ?? fixture.artifactRunId,
    '--created-at',
    fixture.createdAt,
    '--build-identity-file',
    fixture.buildIdentityFile,
    '--migrations-file',
    fixture.migrationsFile,
    '--output',
    fixture.output,
  ];
}

function verifyArgs(
  fixture: ReturnType<typeof createFixture>,
  overrides: {
    readonly target?: string;
    readonly sourceSha?: string;
    readonly acceptedValidationRunId?: string;
    readonly artifactRunId?: string;
  } = {},
): string[] {
  return [
    'verify',
    '--manifest',
    fixture.output,
    '--target',
    overrides.target ?? fixture.target,
    '--source-sha',
    overrides.sourceSha ?? fixture.sourceSha,
    '--accepted-validation-run-id',
    overrides.acceptedValidationRunId ?? fixture.acceptedValidationRunId,
    '--artifact-run-id',
    overrides.artifactRunId ?? fixture.artifactRunId,
  ];
}

function runRelease(args: readonly string[]): CommandResult {
  const result = spawnSync(process.execPath, [releaseScript, ...args], {
    cwd: repoRoot,
    encoding: 'utf8',
  });
  return {
    status: result.status,
    stdout: String(result.stdout ?? ''),
    stderr: String(result.stderr ?? ''),
  };
}

function readJson(filePath: string): any {
  return JSON.parse(readFileSync(filePath, 'utf8'));
}

function writeJson(filePath: string, value: unknown): void {
  writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

function expectFailure(result: CommandResult, message: RegExp): void {
  expect(result.status).not.toBe(0);
  expect(`${result.stdout}\n${result.stderr}`).toMatch(message);
}

function cleanupTempRoots(): void {
  for (const root of tempRoots) rmSync(root, { recursive: true, force: true });
  tempRoots.clear();
}

test('release-set create and verify cover the full immutable manifest contract', () => {
  const fixture = createFixture();
  const created = runRelease(createArgs(fixture));

  expect(created.status).toBe(0);
  const manifest = readJson(fixture.output);
  expect(manifest).toMatchObject({
    schemaVersion: 1,
    target: 'staging',
    sourceSha,
    acceptedValidationRunId: '1001',
    artifactRunId: '2002',
    createdAt,
  });
  expect(manifest.manifestDigestSha256).toMatch(/^[a-f0-9]{64}$/u);
  expect(manifest.releaseSetId).toBe(`rs_${manifest.manifestDigestSha256}`);
  expect(manifest.components.map(componentKind)).toEqual([
    'router',
    'deriver-a',
    'deriver-b',
    'signing-worker',
    'gateway-wasm',
    'pages',
    'sdk-r2',
  ]);

  const verified = runRelease(verifyArgs(fixture));
  expect(verified.status).toBe(0);
  expect(verified.stdout).toContain(`verified release set ${manifest.releaseSetId}`);
});

test('release-set create canonicalizes component order and produces a full-digest ID', () => {
  const canonicalFixture = createFixture();
  const reversedFixture = createFixture({ components: validComponents().reverse() });

  expect(runRelease(createArgs(canonicalFixture)).status).toBe(0);
  expect(runRelease(createArgs(reversedFixture)).status).toBe(0);

  const canonicalManifest = readJson(canonicalFixture.output);
  const reversedManifest = readJson(reversedFixture.output);
  expect(reversedManifest.components).toEqual(canonicalManifest.components);
  expect(reversedManifest.manifestDigestSha256).toBe(canonicalManifest.manifestDigestSha256);
  expect(reversedManifest.releaseSetId).toBe(`rs_${reversedManifest.manifestDigestSha256}`);
  expect(reversedManifest.releaseSetId).toHaveLength(67);
});

test('release-set verify rejects tampered immutable fields', () => {
  const fixture = createFixture();
  expect(runRelease(createArgs(fixture)).status).toBe(0);
  const manifest = readJson(fixture.output);
  manifest.components[0].contentDigestSha256 = 'd'.repeat(64);
  writeJson(fixture.output, manifest);

  expectFailure(runRelease(['verify', '--manifest', fixture.output]), /manifest digest mismatch/u);
});

test('release-set verify rejects a non-canonical component order', () => {
  const fixture = createFixture();
  expect(runRelease(createArgs(fixture)).status).toBe(0);
  const manifest = readJson(fixture.output);
  manifest.components.reverse();
  writeJson(fixture.output, manifest);

  expectFailure(
    runRelease(['verify', '--manifest', fixture.output]),
    /components are not in canonical order/u,
  );
});

test('release-set verify rejects target, source SHA, and artifact run mismatches', () => {
  const fixture = createFixture();
  expect(runRelease(createArgs(fixture)).status).toBe(0);

  expectFailure(
    runRelease(verifyArgs(fixture, { target: 'production' })),
    /target mismatch: expected production, received staging/u,
  );
  expectFailure(
    runRelease(verifyArgs(fixture, { sourceSha: 'e'.repeat(40) })),
    /source SHA mismatch: expected/u,
  );
  expectFailure(
    runRelease(verifyArgs(fixture, { artifactRunId: '3003' })),
    /artifact run mismatch: expected 3003, received 2002/u,
  );
});

test('release-set boundaries reject uppercase or short SHAs and malformed run IDs', () => {
  const fixture = createFixture();

  expectFailure(
    runRelease(createArgs(fixture, { sourceSha: sourceSha.toUpperCase() })),
    /source SHA must be exactly 40 lowercase/u,
  );
  expectFailure(
    runRelease(createArgs(fixture, { sourceSha: sourceSha.slice(0, 39) })),
    /source SHA must be exactly 40 lowercase/u,
  );
  expectFailure(
    runRelease(createArgs(fixture, { artifactRunId: '0002002' })),
    /artifact run ID must be a positive decimal/u,
  );
  expectFailure(
    runRelease(createArgs(fixture, { acceptedValidationRunId: 'run-1001' })),
    /accepted validation run ID must be a positive decimal/u,
  );
});

test('release-set boundaries reject unsupported targets and component kinds', () => {
  const unsupportedTargetFixture = createFixture({ target: 'qa' });
  expectFailure(
    runRelease(createArgs(unsupportedTargetFixture)),
    /unsupported release-set target: qa/u,
  );

  const unsupportedKindComponents = validComponents();
  unsupportedKindComponents[0] = {
    ...unsupportedKindComponents[0],
    kind: 'unsupported-worker',
  };
  const unsupportedKindFixture = createFixture({ components: unsupportedKindComponents });
  expectFailure(
    runRelease(createArgs(unsupportedKindFixture)),
    /release-set component record is invalid/u,
  );

  const unsupportedComponentTarget = validComponents();
  unsupportedComponentTarget[0] = {
    ...unsupportedComponentTarget[0],
    target: 'qa',
  };
  const unsupportedComponentTargetFixture = createFixture({
    components: unsupportedComponentTarget,
  });
  expectFailure(
    runRelease(createArgs(unsupportedComponentTargetFixture)),
    /release-set component record is invalid/u,
  );
});

test('release-set boundaries reject missing fields, mapping drift, and duplicate components', () => {
  const missingFieldComponent: Record<string, unknown> = { ...validComponents()[0] };
  delete missingFieldComponent.releaseId;
  const missingFieldFixture = createFixture({ components: [missingFieldComponent] });
  expectFailure(
    runRelease(createArgs(missingFieldFixture)),
    /release-set component fields are invalid/u,
  );

  const mappingDriftComponents = validComponents();
  mappingDriftComponents[0] = createComponent('mpc-router', 'router', 1, {
    sourceSha: 'f'.repeat(40),
  });
  const mappingDriftFixture = createFixture({ components: mappingDriftComponents });
  expectFailure(
    runRelease(createArgs(mappingDriftFixture)),
    /component mapping is invalid: mpc-router/u,
  );

  const duplicateComponents = validComponents();
  duplicateComponents[1] = { ...duplicateComponents[1], name: duplicateComponents[0].name };
  const duplicateFixture = createFixture({ components: duplicateComponents });
  expectFailure(
    runRelease(createArgs(duplicateFixture)),
    /duplicate release-set component name: mpc-router/u,
  );
});

test('release-set verify rejects unknown manifest fields', () => {
  const fixture = createFixture();
  expect(runRelease(createArgs(fixture)).status).toBe(0);
  const manifest = readJson(fixture.output);
  manifest.deploymentReceipt = { workerVersionId: 'post-deployment-data' };
  writeJson(fixture.output, manifest);

  expectFailure(
    runRelease(['verify', '--manifest', fixture.output]),
    /manifest fields are invalid/u,
  );
});

function componentKind(component: ComponentDto): string {
  return component.kind;
}
