import { expect, test } from '@playwright/test';
import {
  deriveSigningRootId,
  normalizeRuntimePolicyScope,
  normalizeSigningRootScope,
  signingRootScopeFromRuntimePolicyScope,
} from '../../shared/src/threshold/signingRootScope';

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
  });
  const second = signingRootScopeFromRuntimePolicyScope({
    orgId: 'org_beta',
    projectId: 'proj_alpha',
    envId: 'dev',
  });

  expect(first).toEqual({ signingRootId: 'proj_alpha:dev' });
  expect(second).toEqual(first);
});

test('normalizeRuntimePolicyScope requires explicit orgId, projectId, and envId', () => {
  expect(
    normalizeRuntimePolicyScope({
      orgId: ' org_alpha ',
      projectId: ' proj_alpha ',
      envId: ' dev ',
    }),
  ).toEqual({
    orgId: 'org_alpha',
    projectId: 'proj_alpha',
    envId: 'dev',
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
});

test('normalizeRuntimePolicyScope rejects stale signing runtime scope fields', () => {
  expect(() =>
    normalizeRuntimePolicyScope({
      orgId: 'org_alpha',
      projectId: 'proj_alpha',
      envId: 'dev',
      environmentId: 'dev',
    }),
  ).toThrow('runtimePolicyScope.environmentId is stale; use envId');
  expect(() =>
    normalizeRuntimePolicyScope({
      orgId: 'org_alpha',
      projectId: 'proj_alpha',
      envId: 'dev',
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
