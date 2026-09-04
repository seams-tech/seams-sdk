import {
  resolveTenantRootIdentityV1,
  type ActiveEcdsaMaterialActivationV1,
  type ActiveEd25519MaterialActivationV1,
} from '../../packages/wallet-server/src/router/domains/tenantRoot/tenantRootIdentityResolution';

declare const activeEd25519Material: ActiveEd25519MaterialActivationV1;
declare const activeEcdsaMaterial: ActiveEcdsaMaterialActivationV1;

resolveTenantRootIdentityV1({
  kind: 'ed25519_b5_active_material',
  activeMaterial: activeEd25519Material,
});

resolveTenantRootIdentityV1({
  kind: 'ecdsa_b5_active_material',
  activeMaterial: activeEcdsaMaterial,
});

resolveTenantRootIdentityV1({
  kind: 'ed25519_b5_active_material',
  activeMaterial: activeEd25519Material,
  // @ts-expect-error Wallet Session state cannot select a tenant root.
  walletSession: {},
});

resolveTenantRootIdentityV1({
  kind: 'ecdsa_b5_active_material',
  activeMaterial: activeEcdsaMaterial,
  // @ts-expect-error A caller cannot supply the active tenant-root epoch.
  tenantRootShareEpoch: 2,
});

resolveTenantRootIdentityV1({
  kind: 'ecdsa_b5_active_material',
  activeMaterial: activeEcdsaMaterial,
  // @ts-expect-error A caller cannot select the Deriver role.
  role: 'deriver_a',
});

resolveTenantRootIdentityV1({
  kind: 'ecdsa_b5_active_material',
  activeMaterial: activeEcdsaMaterial,
  // @ts-expect-error A caller cannot override the stable signing-root identity.
  signingRootId: 'caller-selected-root',
});

resolveTenantRootIdentityV1({
  kind: 'ed25519_b5_active_material',
  activeMaterial: activeEd25519Material,
  // @ts-expect-error Credential identity cannot select a tenant root.
  credentialIdB64u: 'credential-from-request',
});

resolveTenantRootIdentityV1({
  kind: 'ed25519_b5_active_material',
  activeMaterial: activeEd25519Material,
  // @ts-expect-error Request bodies cannot carry an R120 identity override.
  tenantRootIdentity: {
    orgId: 'org-a',
    projectId: 'project-a',
    envId: 'env-a',
    signingRootId: 'project-a:env-a',
    signingRootVersion: 'root-v1',
  },
});

// @ts-expect-error The curve discriminator must match the successful B5 branch.
resolveTenantRootIdentityV1({
  kind: 'ed25519_b5_active_material',
  activeMaterial: activeEcdsaMaterial,
});
