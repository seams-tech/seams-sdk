import { expect, test } from '@playwright/test';
import { resolveTenantRootIdentityV1 } from '../../packages/wallet-server/src/router/domains/tenantRoot/tenantRootIdentityResolution';
import {
  buildActiveEcdsaMaterialFixture,
  buildActiveEd25519MaterialFixture,
  TENANT_ROOT_RUNTIME_POLICY_SCOPE_FIXTURE,
} from './helpers/tenantRootB5Material.fixtures';

const EXPECTED_IDENTITY = {
  orgId: TENANT_ROOT_RUNTIME_POLICY_SCOPE_FIXTURE.orgId,
  projectId: TENANT_ROOT_RUNTIME_POLICY_SCOPE_FIXTURE.projectId,
  envId: TENANT_ROOT_RUNTIME_POLICY_SCOPE_FIXTURE.envId,
  signingRootId: `${TENANT_ROOT_RUNTIME_POLICY_SCOPE_FIXTURE.projectId}:${TENANT_ROOT_RUNTIME_POLICY_SCOPE_FIXTURE.envId}`,
  signingRootVersion: TENANT_ROOT_RUNTIME_POLICY_SCOPE_FIXTURE.signingRootVersion,
};

test('resolves the exact Ed25519 tenant-root identity from B5 active material', async () => {
  const result = resolveTenantRootIdentityV1({
    kind: 'ed25519_b5_active_material',
    activeMaterial: await buildActiveEd25519MaterialFixture(),
  });

  expect(result).toEqual({ ok: true, identity: EXPECTED_IDENTITY });
  expect(JSON.stringify(result)).not.toContain('tenantRootShareEpoch');
});

test('resolves the exact ECDSA tenant-root identity from B5 active material', () => {
  const result = resolveTenantRootIdentityV1({
    kind: 'ecdsa_b5_active_material',
    activeMaterial: buildActiveEcdsaMaterialFixture(),
  });

  expect(result).toEqual({ ok: true, identity: EXPECTED_IDENTITY });
});

test('rejects an Ed25519 B5 signing-root ID mismatch', async () => {
  const activeMaterial = await buildActiveEd25519MaterialFixture();
  const result = resolveTenantRootIdentityV1({
    kind: 'ed25519_b5_active_material',
    activeMaterial: {
      ...activeMaterial,
      exportIdentity: {
        ...activeMaterial.exportIdentity,
        application_binding: {
          ...activeMaterial.exportIdentity.application_binding,
          signing_root_id: 'other-project:env-a',
        },
      },
    },
  });

  expect(result).toEqual({
    ok: false,
    code: 'signing_root_id_mismatch',
    message: 'B5 signing-root ID does not match authenticated deployment configuration',
  });
});

test('rejects an Ed25519 B5 stable signing-root version mismatch', async () => {
  const activeMaterial = await buildActiveEd25519MaterialFixture();
  const result = resolveTenantRootIdentityV1({
    kind: 'ed25519_b5_active_material',
    activeMaterial: {
      ...activeMaterial,
      exportIdentity: {
        ...activeMaterial.exportIdentity,
        scope: {
          ...activeMaterial.exportIdentity.scope,
          root_share_epoch: 'root-v2',
        },
      },
    },
  });

  expect(result).toEqual({
    ok: false,
    code: 'signing_root_version_mismatch',
    message: 'B5 signing-root version does not match authenticated deployment configuration',
  });
});

test('rejects an ECDSA B5 stable signing-root version mismatch', () => {
  const activeMaterial = buildActiveEcdsaMaterialFixture();
  const normalSigning = activeMaterial.routerAbEcdsaDerivationNormalSigning;
  const result = resolveTenantRootIdentityV1({
    kind: 'ecdsa_b5_active_material',
    activeMaterial: {
      ...activeMaterial,
      routerAbEcdsaDerivationNormalSigning: {
        ...normalSigning,
        scope: {
          ...normalSigning.scope,
          signing_root_version: 'root-v2',
        },
      },
    },
  });

  expect(result).toEqual({
    ok: false,
    code: 'signing_root_version_mismatch',
    message: 'B5 signing-root version does not match authenticated deployment configuration',
  });
});

test('rejects a B5 result whose nested material activation changed', () => {
  const activeMaterial = buildActiveEcdsaMaterialFixture();
  const normalSigning = activeMaterial.routerAbEcdsaDerivationNormalSigning;
  const result = resolveTenantRootIdentityV1({
    kind: 'ecdsa_b5_active_material',
    activeMaterial: {
      ...activeMaterial,
      routerAbEcdsaDerivationNormalSigning: {
        ...normalSigning,
        scope: {
          ...normalSigning.scope,
          material_activation: {
            ...normalSigning.scope.material_activation,
            activation_id: 'activation:substituted',
          },
        },
      },
    },
  });

  expect(result).toEqual({
    ok: false,
    code: 'material_activation_mismatch',
    message: 'B5 material activation does not match its established material identity',
  });
});
