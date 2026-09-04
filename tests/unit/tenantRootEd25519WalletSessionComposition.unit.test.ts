import { expect, test } from '@playwright/test';
import { base64UrlEncode } from '../../packages/shared-ts/src/utils/base64';
import {
  resolveTenantRootEd25519WalletSessionCompositionV1,
  type TenantRootEd25519MaterialActivationResolutionV1,
  type TenantRootEd25519WalletSessionCompositionResultV1,
} from '../../packages/wallet-server/src/router/domains/tenantRoot/tenantRootEd25519WalletSessionComposition';
import {
  buildTenantRootEd25519WalletSessionCompositionFixture,
  ed25519MaterialActivationWithActivationId,
  RecordingTenantRootEd25519MaterialActivationResolverV1,
  type TenantRootEd25519WalletSessionCompositionFixture,
} from './helpers/tenantRootEd25519WalletSessionComposition.fixtures';

const EXPECTED_IDENTITY = {
  orgId: 'org-a',
  projectId: 'project-a',
  envId: 'env-a',
  signingRootId: 'project-a:env-a',
  signingRootVersion: 'root-v1',
};

function compose(
  fixture: TenantRootEd25519WalletSessionCompositionFixture,
  resolver: RecordingTenantRootEd25519MaterialActivationResolverV1 = fixture.resolver,
): Promise<TenantRootEd25519WalletSessionCompositionResultV1> {
  return resolveTenantRootEd25519WalletSessionCompositionV1({
    admission: fixture.admission,
    resolveEd25519MaterialActivation: resolver.resolveEd25519MaterialActivation.bind(resolver),
  });
}

function failedMaterialResolution(
  code: 'not_found' | 'internal',
): TenantRootEd25519MaterialActivationResolutionV1 {
  return {
    ok: false,
    code,
    message: `fixture B5 ${code}`,
  };
}

test('composes exact B4 Ed25519 admission with B5 material and tenant-root identity', async () => {
  const fixture = await buildTenantRootEd25519WalletSessionCompositionFixture();
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

test('rejects a runtime caller-selected epoch before B5 resolution', async () => {
  const fixture = await buildTenantRootEd25519WalletSessionCompositionFixture();
  const input = {
    admission: fixture.admission,
    resolveEd25519MaterialActivation: fixture.resolver.resolveEd25519MaterialActivation.bind(
      fixture.resolver,
    ),
  };
  Reflect.set(input, 'tenantRootShareEpoch', 2);

  await expect(resolveTenantRootEd25519WalletSessionCompositionV1(input)).resolves.toEqual({
    ok: false,
    code: 'caller_selected_tenant_root',
    message: 'Caller-supplied tenant-root selector field is forbidden: tenantRootShareEpoch',
  });
  expect(fixture.resolver.calls).toEqual([]);
});

test('rejects B5 not_found without resolving tenant-root identity', async () => {
  const fixture = await buildTenantRootEd25519WalletSessionCompositionFixture();
  const resolver = new RecordingTenantRootEd25519MaterialActivationResolverV1(
    failedMaterialResolution('not_found'),
  );

  await expect(compose(fixture, resolver)).resolves.toEqual({
    ok: false,
    code: 'not_found',
    message: 'fixture B5 not_found',
  });
});

test('rejects B5 internal failure without resolving tenant-root identity', async () => {
  const fixture = await buildTenantRootEd25519WalletSessionCompositionFixture();
  const resolver = new RecordingTenantRootEd25519MaterialActivationResolverV1(
    failedMaterialResolution('internal'),
  );

  await expect(compose(fixture, resolver)).resolves.toEqual({
    ok: false,
    code: 'internal',
    message: 'fixture B5 internal',
  });
});

test('rejects a B5 top-level activation substitution', async () => {
  const fixture = await buildTenantRootEd25519WalletSessionCompositionFixture();
  const substituted = {
    ...fixture.activeMaterial,
    materialActivation: ed25519MaterialActivationWithActivationId(
      fixture.activeMaterial.materialActivation,
      'activation:substituted',
    ),
  };
  const resolver = new RecordingTenantRootEd25519MaterialActivationResolverV1(substituted);

  await expect(compose(fixture, resolver)).resolves.toEqual({
    ok: false,
    code: 'material_activation_mismatch',
    message: 'B5 material activation does not match the exact B4 admission',
  });
});

test('rejects a B5 wallet mismatch against the B4 signer', async () => {
  const fixture = await buildTenantRootEd25519WalletSessionCompositionFixture();
  const exportIdentity = fixture.activeMaterial.exportIdentity;
  const mismatchedMaterial = {
    ...fixture.activeMaterial,
    exportIdentity: {
      ...exportIdentity,
      application_binding: {
        ...exportIdentity.application_binding,
        wallet_id: 'wallet:other',
      },
    },
  };
  const resolver = new RecordingTenantRootEd25519MaterialActivationResolverV1(mismatchedMaterial);

  await expect(compose(fixture, resolver)).resolves.toEqual({
    ok: false,
    code: 'wallet_mismatch',
    message: 'B5 Ed25519 wallet ID does not match the B4 signer',
  });
});

test('rejects a B5 registered public-key mismatch against the B4 signer', async () => {
  const fixture = await buildTenantRootEd25519WalletSessionCompositionFixture();
  const exportIdentity = fixture.activeMaterial.exportIdentity;
  const mismatchedMaterial = {
    ...fixture.activeMaterial,
    exportIdentity: {
      ...exportIdentity,
      registered_public_key: new Array<number>(32).fill(9),
    },
  };
  const resolver = new RecordingTenantRootEd25519MaterialActivationResolverV1(mismatchedMaterial);

  await expect(compose(fixture, resolver)).resolves.toEqual({
    ok: false,
    code: 'registered_public_key_mismatch',
    message: 'B5 Ed25519 public key does not match the B4 signer',
  });
  expect(
    base64UrlEncode(Uint8Array.from(mismatchedMaterial.exportIdentity.registered_public_key)),
  ).not.toBe(fixture.admission.admission.signer.registeredPublicKeyB64u);
});

test('delegates B5 signing-root ID mismatch to the tenant-root identity resolver', async () => {
  const fixture = await buildTenantRootEd25519WalletSessionCompositionFixture();
  const exportIdentity = fixture.activeMaterial.exportIdentity;
  const mismatchedMaterial = {
    ...fixture.activeMaterial,
    exportIdentity: {
      ...exportIdentity,
      application_binding: {
        ...exportIdentity.application_binding,
        signing_root_id: 'other-project:env-a',
      },
    },
  };
  const resolver = new RecordingTenantRootEd25519MaterialActivationResolverV1(mismatchedMaterial);

  await expect(compose(fixture, resolver)).resolves.toEqual({
    ok: false,
    code: 'signing_root_id_mismatch',
    message: 'B5 signing-root ID does not match authenticated deployment configuration',
  });
});

test('delegates B5 signing-root version mismatch to the tenant-root identity resolver', async () => {
  const fixture = await buildTenantRootEd25519WalletSessionCompositionFixture();
  const exportIdentity = fixture.activeMaterial.exportIdentity;
  const mismatchedMaterial = {
    ...fixture.activeMaterial,
    exportIdentity: {
      ...exportIdentity,
      scope: {
        ...exportIdentity.scope,
        root_share_epoch: 'root-v2',
      },
    },
  };
  const resolver = new RecordingTenantRootEd25519MaterialActivationResolverV1(mismatchedMaterial);

  await expect(compose(fixture, resolver)).resolves.toEqual({
    ok: false,
    code: 'signing_root_version_mismatch',
    message: 'B5 signing-root version does not match authenticated deployment configuration',
  });
});
