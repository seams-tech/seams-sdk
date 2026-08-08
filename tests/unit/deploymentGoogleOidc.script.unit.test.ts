import { expect, test } from '@playwright/test';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

type DeploymentTargetsModule = {
  readonly parseDeploymentTargets: (value: unknown) => unknown;
};

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const deploymentTargetsModule = import(
  pathToFileURL(path.join(repoRoot, 'scripts/deployment-targets.mjs')).href
) as Promise<DeploymentTargetsModule>;

function targetsWithMismatchedGoogleClient(): Record<string, unknown> {
  const targets = JSON.parse(
    readFileSync(path.join(repoRoot, 'deployment/targets.json'), 'utf8'),
  ) as Record<string, unknown>;
  const staging = (targets.staging as Record<string, unknown>).site as Record<string, unknown>;
  staging.googleOidcClientId =
    '971053349716-p10qdg7lsjh24lcocbsckt4f85is5igs.apps.googleusercontent.com';
  return targets;
}

test('deployment targets reject a gateway using another site Google client', async () => {
  const module = await deploymentTargetsModule;

  expect(() => module.parseDeploymentTargets(targetsWithMismatchedGoogleClient())).toThrow(
    /Google OIDC client does not match frontend site staging/u,
  );
});
