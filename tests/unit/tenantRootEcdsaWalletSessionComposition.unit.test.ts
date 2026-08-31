import { expect, test } from '@playwright/test';
import {
  resolveTenantRootEcdsaWalletSessionCompositionV1,
  type TenantRootEcdsaMaterialActivationResolutionV1,
  type TenantRootEcdsaWalletSessionCompositionResultV1,
} from '../../packages/wallet-server/src/router/domains/tenantRoot/tenantRootEcdsaWalletSessionComposition';
import {
  buildTenantRootEcdsaWalletSessionCompositionFixture,
  materialActivationWithActivationId,
  RecordingTenantRootEcdsaMaterialActivationResolverV1,
  type TenantRootEcdsaWalletSessionCompositionFixture,
} from './helpers/tenantRootEcdsaWalletSessionComposition.fixtures';

const EXPECTED_IDENTITY = {
  orgId: 'org-a',
  projectId: 'project-a',
  envId: 'env-a',
  signingRootId: 'project-a:env-a',
  signingRootVersion: 'root-v1',
};

function compose(
  fixture: TenantRootEcdsaWalletSessionCompositionFixture,
  resolver: RecordingTenantRootEcdsaMaterialActivationResolverV1 = fixture.resolver,
): Promise<TenantRootEcdsaWalletSessionCompositionResultV1> {
  return resolveTenantRootEcdsaWalletSessionCompositionV1({
    admission: fixture.admission,
    resolveEcdsaMaterialActivation: resolver.resolveEcdsaMaterialActivation.bind(resolver),
  });
}

function failedMaterialResolution(
  code: 'not_found' | 'internal',
): TenantRootEcdsaMaterialActivationResolutionV1 {
  return {
    ok: false,
    code,
    message: `fixture B5 ${code}`,
  };
}

test('composes exact B4 ECDSA admission with B5 material and tenant-root identity', async () => {
  const fixture = await buildTenantRootEcdsaWalletSessionCompositionFixture();
  const result = await compose(fixture);

  expect(fixture.resolver.calls).toEqual([
    {
      walletId: String(fixture.admission.context.authorization.session.walletId),
      materialActivation: fixture.activeMaterial.materialActivation,
    },
  ]);
  expect(result).toEqual({
    ok: true,
    admission: fixture.admission,
    activeMaterial: fixture.activeMaterial,
    tenantRootIdentity: EXPECTED_IDENTITY,
  });
  if (result.ok) {
    expect(result.admission).toBe(fixture.admission);
    expect(JSON.stringify(result)).not.toContain('tenantRootShareEpoch');
  }
});

test('rejects B5 not_found without resolving tenant-root identity', async () => {
  const fixture = await buildTenantRootEcdsaWalletSessionCompositionFixture();
  const resolver = new RecordingTenantRootEcdsaMaterialActivationResolverV1(
    failedMaterialResolution('not_found'),
  );

  await expect(compose(fixture, resolver)).resolves.toEqual({
    ok: false,
    code: 'not_found',
    message: 'fixture B5 not_found',
  });
});

test('rejects B5 internal failure without resolving tenant-root identity', async () => {
  const fixture = await buildTenantRootEcdsaWalletSessionCompositionFixture();
  const resolver = new RecordingTenantRootEcdsaMaterialActivationResolverV1(
    failedMaterialResolution('internal'),
  );

  await expect(compose(fixture, resolver)).resolves.toEqual({
    ok: false,
    code: 'internal',
    message: 'fixture B5 internal',
  });
});

test('rejects a B5 top-level activation substitution', async () => {
  const fixture = await buildTenantRootEcdsaWalletSessionCompositionFixture();
  const substituted = {
    ...fixture.activeMaterial,
    materialActivation: materialActivationWithActivationId(
      fixture.activeMaterial.materialActivation,
      'activation:substituted',
    ),
  };
  const resolver = new RecordingTenantRootEcdsaMaterialActivationResolverV1(substituted);

  await expect(compose(fixture, resolver)).resolves.toEqual({
    ok: false,
    code: 'material_activation_mismatch',
    message: 'B5 material activation does not match the exact B4 admission',
  });
});

test('rejects a B5 normal-signing wallet mismatch against the B4 signer', async () => {
  const fixture = await buildTenantRootEcdsaWalletSessionCompositionFixture();
  const normalSigning = fixture.activeMaterial.routerAbEcdsaDerivationNormalSigning;
  const mismatchedMaterial = {
    ...fixture.activeMaterial,
    routerAbEcdsaDerivationNormalSigning: {
      ...normalSigning,
      scope: { ...normalSigning.scope, wallet_id: 'wallet:other' },
    },
  };
  const resolver = new RecordingTenantRootEcdsaMaterialActivationResolverV1(mismatchedMaterial);

  await expect(compose(fixture, resolver)).resolves.toEqual({
    ok: false,
    code: 'wallet_mismatch',
    message: 'B5 normal-signing wallet ID does not match the B4 signer',
  });
});

test('rejects a B5 threshold public-key mismatch against the B4 signer', async () => {
  const fixture = await buildTenantRootEcdsaWalletSessionCompositionFixture();
  const normalSigning = fixture.activeMaterial.routerAbEcdsaDerivationNormalSigning;
  const mismatchedMaterial = {
    ...fixture.activeMaterial,
    routerAbEcdsaDerivationNormalSigning: {
      ...normalSigning,
      scope: {
        ...normalSigning.scope,
        public_identity: {
          ...normalSigning.scope.public_identity,
          threshold_public_key33_b64u: 'AwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        },
      },
    },
  };
  const resolver = new RecordingTenantRootEcdsaMaterialActivationResolverV1(mismatchedMaterial);

  await expect(compose(fixture, resolver)).resolves.toEqual({
    ok: false,
    code: 'threshold_public_key_mismatch',
    message: 'B5 normal-signing threshold public key does not match the B4 signer',
  });
});

test('delegates B5 signing-root ID mismatch to the tenant-root identity resolver', async () => {
  const fixture = await buildTenantRootEcdsaWalletSessionCompositionFixture();
  const normalSigning = fixture.activeMaterial.routerAbEcdsaDerivationNormalSigning;
  const mismatchedMaterial = {
    ...fixture.activeMaterial,
    routerAbEcdsaDerivationNormalSigning: {
      ...normalSigning,
      scope: { ...normalSigning.scope, signing_root_id: 'other-project:env-a' },
    },
  };
  const resolver = new RecordingTenantRootEcdsaMaterialActivationResolverV1(mismatchedMaterial);

  await expect(compose(fixture, resolver)).resolves.toEqual({
    ok: false,
    code: 'signing_root_id_mismatch',
    message: 'B5 signing-root ID does not match authenticated deployment configuration',
  });
});

test('delegates B5 signing-root version mismatch to the tenant-root identity resolver', async () => {
  const fixture = await buildTenantRootEcdsaWalletSessionCompositionFixture();
  const normalSigning = fixture.activeMaterial.routerAbEcdsaDerivationNormalSigning;
  const mismatchedMaterial = {
    ...fixture.activeMaterial,
    routerAbEcdsaDerivationNormalSigning: {
      ...normalSigning,
      scope: { ...normalSigning.scope, signing_root_version: 'root-v2' },
    },
  };
  const resolver = new RecordingTenantRootEcdsaMaterialActivationResolverV1(mismatchedMaterial);

  await expect(compose(fixture, resolver)).resolves.toEqual({
    ok: false,
    code: 'signing_root_version_mismatch',
    message: 'B5 signing-root version does not match authenticated deployment configuration',
  });
});
