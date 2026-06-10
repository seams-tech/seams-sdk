import { expect, test } from '@playwright/test';
import {
  deriveSigningRootId,
  normalizeRuntimePolicyScope,
  normalizeSigningRootScope,
  signingRootScopeFromRuntimePolicyScope,
} from '../../packages/shared-ts/src/threshold/signingRootScope';
import { createInMemoryConsoleOrgProjectEnvService } from '../../packages/sdk-server-ts/src/console/orgProjectEnv';
import { resolveThresholdRuntimePolicyScope } from '../../packages/sdk-server-ts/src/router/commonRouterUtils';

test('deriveSigningRootId composes projectId and envId without orgId', () => {
  expect(deriveSigningRootId({ projectId: 'proj_alpha', envId: 'dev' })).toBe(
    'proj_alpha:dev',
  );
  expect(deriveSigningRootId({ projectId: ' proj_alpha ', envId: ' production ' })).toBe(
    'proj_alpha:production',
  );
});

test('signingRootScopeFromRuntimePolicyScope ignores orgId', () => {
  const first = signingRootScopeFromRuntimePolicyScope({
    orgId: 'org_alpha',
    projectId: 'proj_alpha',
    envId: 'dev',
    signingRootVersion: 'root-v1',
  });
  const second = signingRootScopeFromRuntimePolicyScope({
    orgId: 'org_beta',
    projectId: 'proj_alpha',
    envId: 'dev',
    signingRootVersion: 'root-v1',
  });

  expect(first).toEqual({ signingRootId: 'proj_alpha:dev', signingRootVersion: 'root-v1' });
  expect(second).toEqual(first);
});

test('normalizeRuntimePolicyScope requires explicit orgId, projectId, envId, and signingRootVersion', () => {
  expect(
    normalizeRuntimePolicyScope({
      orgId: ' org_alpha ',
      projectId: ' proj_alpha ',
      envId: ' dev ',
      signingRootVersion: ' root-v1 ',
    }),
  ).toEqual({
    orgId: 'org_alpha',
    projectId: 'proj_alpha',
    envId: 'dev',
    signingRootVersion: 'root-v1',
  });
  expect(() => normalizeRuntimePolicyScope({ projectId: 'proj_alpha', envId: 'dev' })).toThrow(
    'orgId is required',
  );
  expect(() => normalizeRuntimePolicyScope({ orgId: 'org_alpha', envId: 'dev' })).toThrow(
    'projectId is required',
  );
  expect(() =>
    normalizeRuntimePolicyScope({ orgId: 'org_alpha', projectId: 'proj_alpha' }),
  ).toThrow('envId is required');
  expect(() =>
    normalizeRuntimePolicyScope({
      orgId: 'org_alpha',
      projectId: 'proj_alpha',
      envId: 'dev',
    }),
  ).toThrow('signingRootVersion is required');
});

test('normalizeRuntimePolicyScope rejects stale signing runtime scope fields', () => {
  expect(() =>
    normalizeRuntimePolicyScope({
      orgId: 'org_alpha',
      projectId: 'proj_alpha',
      envId: 'dev',
      signingRootVersion: 'root-v1',
      environmentId: 'dev',
    }),
  ).toThrow('runtimePolicyScope.environmentId is stale; use envId');
  expect(() =>
    normalizeRuntimePolicyScope({
      orgId: 'org_alpha',
      projectId: 'proj_alpha',
      envId: 'dev',
      signingRootVersion: 'root-v1',
      runtimeSnapshotScope: { orgId: 'org_alpha', projectId: 'proj_alpha', envId: 'dev' },
    }),
  ).toThrow('runtimePolicyScope.runtimeSnapshotScope is stale; use runtimePolicyScope');
});

test('normalizeSigningRootScope trims signing-root fields and rejects missing id', () => {
  expect(
    normalizeSigningRootScope({
      signingRootId: ' proj_alpha:dev ',
      signingRootVersion: ' root-v1 ',
    }),
  ).toEqual({
    signingRootId: 'proj_alpha:dev',
    signingRootVersion: 'root-v1',
  });
  expect(normalizeSigningRootScope({ signingRootId: 'proj_alpha:dev' })).toEqual({
    signingRootId: 'proj_alpha:dev',
  });
  expect(() => normalizeSigningRootScope({ signingRootId: '' })).toThrow(
    'signingRootId is required',
  );
});

test('resolveThresholdRuntimePolicyScope loads active signingRootVersion from environment metadata', async () => {
  const orgProjectEnv = createInMemoryConsoleOrgProjectEnvService({
    now: () => new Date('2026-01-01T00:00:00.000Z'),
  });
  const ctx = {
    orgId: 'org_alpha',
    actorUserId: 'test-admin',
    roles: ['admin'],
  };
  await orgProjectEnv.upsertOrganization(ctx, { name: 'Alpha' });
  await orgProjectEnv.createProject(ctx, { id: 'proj_alpha', name: 'Alpha Project' });
  await orgProjectEnv.updateEnvironment(ctx, 'proj_alpha:dev', {
    signingRootVersion: 'root-v2',
  });

  const resolved = await resolveThresholdRuntimePolicyScope({
    explicitScopeRaw: {
      orgId: 'org_alpha',
      projectId: 'proj_alpha',
      envId: 'dev',
      signingRootVersion: 'stale-client-value',
    },
    headers: {},
    orgProjectEnv,
  });

  expect(resolved).toEqual({
    ok: true,
    scope: {
      orgId: 'org_alpha',
      projectId: 'proj_alpha',
      envId: 'dev',
      signingRootVersion: 'root-v2',
    },
  });
});
