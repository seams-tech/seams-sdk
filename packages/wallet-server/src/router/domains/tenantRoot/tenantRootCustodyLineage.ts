import type { TenantRootIdentityV1 } from './tenantRootIdentityResolution';

export type TenantRootActiveLineageV1 = {
  readonly identityDigestB64u: string;
  readonly custodyLineageB64u: string;
};

export interface TenantRootCustodyLineageResolverV1 {
  resolveActiveLineage(identity: TenantRootIdentityV1): Promise<TenantRootActiveLineageV1 | null>;
}
