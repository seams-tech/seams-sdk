export type TenantRootIdentityV1 = {
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
  readonly signingRootId: string;
  readonly signingRootVersion: string;
};

export type TenantRootCreationGrantReadyV1 = {
  readonly revision: number;
  readonly rootCommitmentB64u: string;
  readonly journalDigestB64u: string;
  readonly capabilityDigestB64u: string;
};

export type TenantRootCreationGrantIssueV1 = {
  readonly operationId: string;
  readonly identity: TenantRootIdentityV1;
  readonly identityDigestB64u: string;
  readonly custodyLineageB64u: string;
  readonly grantNonceB64u: string;
  readonly grantKeyId: string;
  readonly grantB64u: string;
  readonly grantDigestB64u: string;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
};

export type TenantRootCreationGrantRecordBaseV1 = TenantRootCreationGrantIssueV1 & {
  readonly namespace: string;
  readonly createdAtMs: number;
  readonly updatedAtMs: number;
};

export type TenantRootCreationGrantRecordV1 =
  | (TenantRootCreationGrantRecordBaseV1 & {
      readonly status: 'ISSUED';
      readonly ready: null;
    })
  | (TenantRootCreationGrantRecordBaseV1 & {
      readonly status: 'ACTIVE';
      readonly ready: TenantRootCreationGrantReadyV1;
    });

export type TenantRootCreationGrantReadyInputV1 = {
  readonly operationId: string;
  readonly identity: TenantRootIdentityV1;
  readonly identityDigestB64u: string;
  readonly custodyLineageB64u: string;
  readonly ready: TenantRootCreationGrantReadyV1;
};

export type TenantRootActiveLineageLookupV1 = {
  readonly identity: TenantRootIdentityV1;
  readonly identityDigestB64u: string;
};

export interface TenantRootCreationGrantStoreV1 {
  findGrantByOperationId(operationId: string): Promise<TenantRootCreationGrantRecordV1 | null>;
  putOrGetGrant(input: TenantRootCreationGrantIssueV1): Promise<TenantRootCreationGrantRecordV1>;
  markActiveFromReady(
    input: TenantRootCreationGrantReadyInputV1,
  ): Promise<TenantRootCreationGrantRecordV1>;
  findActiveLineageByIdentity(
    input: TenantRootActiveLineageLookupV1,
  ): Promise<TenantRootCreationGrantRecordV1 | null>;
}
