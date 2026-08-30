import { expect, test } from '@playwright/test';
import {
  discoverLanesForWalletWithResolver,
  type SigningSessionReadinessExactAuthorizationResolver,
  type WalletSessionReadinessDeps,
} from '@/core/signingEngine/session/availability/readiness';
import type { WalletSessionAuthorizationExactOperationCredentialReadResult } from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import {
  parseMpcWalletSigningQuotaId,
  parseWalletSessionAuthorizationId,
  parseWalletSessionId,
} from '@shared/authorization/capabilityKinds';
import { buildFullOwnerPermissionsV1 } from '@shared/authorization/delegatedAuthority';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import { base64UrlEncode } from '@shared/utils/base64';
import { parseWalletAuthMethodId } from '@shared/utils/domainIds';
import { buildWalletAuthMethodRecordV2 } from '@shared/utils/registrationIntent';
import { buildLinkedDeviceManagementAuthorityFixture } from './helpers/linkedDeviceManagement.fixtures';
import { buildLinkedDeviceActiveWalletSessionFixture } from './helpers/linkedDeviceUnlockRuntime.fixtures';
import { buildPasskeyEd25519SealedSessionRecordFixture } from './helpers/sealedSigningSession.fixtures';
import { buildMpcMaterialActivationRefFixture } from './helpers/ecdsaMaterialRef.fixtures';

type SelectedAuthorityResult = Awaited<
  ReturnType<SigningSessionReadinessExactAuthorizationResolver['resolveSelectedWalletAuthority']>
>;

function required<T>(
  result:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
): T {
  if (!result.ok) throw new Error(result.error.message);
  return result.value;
}

class SealedSessionListFixture {
  constructor(
    private readonly record: ReturnType<typeof buildPasskeyEd25519SealedSessionRecordFixture>,
  ) {}

  async list(
    input: Parameters<
      NonNullable<WalletSessionReadinessDeps['listExactSealedSessionsForWallet']>
    >[0],
  ) {
    return input.filter.authMethod === 'passkey' ? [this.record] : [];
  }
}

class ExactAuthorizationResolverFixture implements SigningSessionReadinessExactAuthorizationResolver {
  readonly selectedWalletIds: string[] = [];
  readonly exactReads: Array<
    Parameters<
      SigningSessionReadinessExactAuthorizationResolver['readExactWithOperationCredential']
    >[0]
  > = [];

  constructor(
    private readonly selected: SelectedAuthorityResult,
    private readonly authorization:
      | WalletSessionAuthorizationExactOperationCredentialReadResult
      | Error,
  ) {}

  async resolveSelectedWalletAuthority(walletId: string): Promise<SelectedAuthorityResult> {
    this.selectedWalletIds.push(walletId);
    return this.selected;
  }

  async readExactWithOperationCredential(
    input: Parameters<
      SigningSessionReadinessExactAuthorizationResolver['readExactWithOperationCredential']
    >[0],
  ): Promise<WalletSessionAuthorizationExactOperationCredentialReadResult> {
    this.exactReads.push(input);
    if (this.authorization instanceof Error) throw this.authorization;
    return this.authorization;
  }
}

async function buildReadinessHarness() {
  const walletId = 'ed25519-readiness-exact-wallet';
  const expiresAtMs = 1_900_000_000_000;
  const materialActivation = buildMpcMaterialActivationRefFixture('readiness-exact', walletId);
  const authorityFixture = await buildLinkedDeviceManagementAuthorityFixture({
    label: 'readiness-exact',
    permissions: buildFullOwnerPermissionsV1(),
    provenance: 'device_link',
    materialActivation,
    expiresAtMs,
    identity: {
      walletId,
      authorityId: 'authority:readiness-exact',
      walletAuthMethodId: 'auth-method:readiness-exact',
      rpId: 'wallet.example.test',
    },
  });
  const sealed = buildPasskeyEd25519SealedSessionRecordFixture({
    walletId,
    materialActivation,
    credentialIdB64u: authorityFixture.authMethod.credentialIdB64u,
    expiresAtMs,
  });
  const selected: SelectedAuthorityResult = {
    kind: 'resolved',
    selection: authorityFixture.selection,
    authMethod: authorityFixture.authMethod,
    authority: authorityFixture.authority,
    signerMaterials: [],
    exportRoot: null,
  };
  const sealedSessions = new SealedSessionListFixture(sealed);
  const deps: WalletSessionReadinessDeps = {
    listExactSealedSessionsForWallet: sealedSessions.list.bind(sealedSessions),
  };
  return { authorityFixture, deps, sealed, selected };
}

async function discoverWithAuthorization(
  harness: Awaited<ReturnType<typeof buildReadinessHarness>>,
  authorization: WalletSessionAuthorizationExactOperationCredentialReadResult | Error,
  selected: SelectedAuthorityResult = harness.selected,
) {
  const resolver = new ExactAuthorizationResolverFixture(selected, authorization);
  const lanes = await discoverLanesForWalletWithResolver(
    harness.deps,
    harness.authorityFixture.authority.walletId,
    resolver,
  );
  return { lanes, resolver };
}

test('discovers readiness from the selected exact V5 Ed25519 session', async () => {
  const harness = await buildReadinessHarness();
  const exact: WalletSessionAuthorizationExactOperationCredentialReadResult = {
    kind: 'found',
    record: harness.authorityFixture.activeWalletSession,
    operationCredential: harness.authorityFixture.operationCredential,
  };
  const { lanes, resolver } = await discoverWithAuthorization(harness, exact);

  expect(lanes).toHaveLength(1);
  expect(lanes[0]).toMatchObject({
    source: 'passkey',
    thresholdSessionId: harness.sealed.thresholdSessionIds.ed25519,
    walletSessionId: harness.authorityFixture.operationCredential.walletSessionId,
    quotaId: harness.authorityFixture.activeWalletSession.quotaId,
    materialActivation: harness.sealed.ed25519Restore.materialActivation,
  });
  expect(resolver.exactReads).toEqual([
    {
      walletId: harness.authorityFixture.authority.walletId,
      authorityId: harness.authorityFixture.authority.authorityId,
      authMethodId: harness.authorityFixture.authMethod.walletAuthMethodId,
    },
  ]);
});

test('skips exact readiness when authority, lifecycle, credential, or material drifts', async () => {
  const harness = await buildReadinessHarness();
  const record = harness.authorityFixture.activeWalletSession;
  const sibling = await buildLinkedDeviceManagementAuthorityFixture({
    label: 'readiness-exact-sibling',
    permissions: buildFullOwnerPermissionsV1(),
    provenance: 'device_link',
  });
  const otherMaterial = buildMpcMaterialActivationRefFixture(
    'readiness-exact-other',
    harness.authorityFixture.authority.walletId,
  );
  const cases: ReadonlyArray<WalletSessionAuthorizationExactOperationCredentialReadResult> = [
    {
      kind: 'found',
      record: { ...record, walletId: sibling.activeWalletSession.walletId },
      operationCredential: harness.authorityFixture.operationCredential,
    },
    {
      kind: 'found',
      record: { ...record, authorityId: sibling.activeWalletSession.authorityId },
      operationCredential: harness.authorityFixture.operationCredential,
    },
    {
      kind: 'found',
      record: { ...record, authMethodId: sibling.activeWalletSession.authMethodId },
      operationCredential: harness.authorityFixture.operationCredential,
    },
    {
      kind: 'found',
      record: {
        ...record,
        authorityDigestB64u: parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(91))),
      },
      operationCredential: harness.authorityFixture.operationCredential,
    },
    {
      kind: 'found',
      record: {
        ...record,
        authorityRevocationEpoch: record.authorityRevocationEpoch + 1,
      },
      operationCredential: harness.authorityFixture.operationCredential,
    },
    {
      kind: 'found',
      record: { ...record, expiresAtMs: 1 },
      operationCredential: harness.authorityFixture.operationCredential,
    },
    {
      kind: 'found',
      record: {
        ...record,
        capabilitySubjects: [
          { kind: 'sign', keyFamily: 'ed25519', materialActivation: otherMaterial },
        ],
      },
      operationCredential: harness.authorityFixture.operationCredential,
    },
    {
      kind: 'found',
      record,
      operationCredential: { ...harness.authorityFixture.operationCredential, token: '' },
    },
  ];

  for (const authorization of cases) {
    const { lanes } = await discoverWithAuthorization(harness, authorization);
    expect(lanes).toEqual([]);
  }
});

test('maps missing, upgrade-required, and corrupt exact persistence to no ready lanes', async () => {
  const harness = await buildReadinessHarness();
  const cases: ReadonlyArray<WalletSessionAuthorizationExactOperationCredentialReadResult | Error> =
    [
      { kind: 'missing' },
      { kind: 'upgrade_required' },
      new Error('Stored Wallet Session authorization v5 is corrupt'),
    ];

  for (const authorization of cases) {
    const { lanes } = await discoverWithAuthorization(harness, authorization);
    expect(lanes).toEqual([]);
  }
});

test('discovers each active same-wallet sibling method from its exact readiness session', async () => {
  const harness = await buildReadinessHarness();
  const siblingAuthMethodId = required(
    parseWalletAuthMethodId('auth-method:readiness-exact-sibling'),
  );
  const siblingSealed = buildPasskeyEd25519SealedSessionRecordFixture({
    walletId: String(harness.authorityFixture.authority.walletId),
    nearAccountId: harness.sealed.ed25519Restore.nearAccountId,
    nearEd25519SigningKeyId: harness.sealed.ed25519Restore.nearEd25519SigningKeyId,
    thresholdSessionId: 'ed25519-readiness-exact-sibling-session',
    materialActivation: harness.sealed.ed25519Restore.materialActivation,
    credentialIdB64u: base64UrlEncode(new Uint8Array(32).fill(92)),
    expiresAtMs: harness.sealed.expiresAtMs,
  });
  const siblingAuthMethod = buildWalletAuthMethodRecordV2({
    ...harness.authorityFixture.authMethod,
    walletAuthMethodId: siblingAuthMethodId,
    credentialIdB64u: siblingSealed.ed25519Restore.credentialIdB64u,
    updatedAtMs: harness.authorityFixture.authMethod.updatedAtMs + 1,
  });
  if (siblingAuthMethod.kind !== 'passkey' || siblingAuthMethod.status !== 'active') {
    throw new Error('readiness sibling fixture changed auth-method branch');
  }
  const siblingSession = buildLinkedDeviceActiveWalletSessionFixture({
    source: harness.authorityFixture.activeWalletSession,
    authMethodId: siblingAuthMethodId,
    authorizationId: required(
      parseWalletSessionAuthorizationId('authorization:readiness-exact-sibling'),
    ),
    quotaId: required(parseMpcWalletSigningQuotaId('wallet-quota:readiness-exact-sibling')),
    authorityDigestB64u: harness.authorityFixture.authority.authorityDigestB64u,
    authorityRevocationEpoch: harness.authorityFixture.authority.revocationEpoch,
  });
  const siblingOperationCredential = {
    kind: 'opaque_wallet_session_operation_credential_v1' as const,
    token: `wst_${'R'.repeat(43)}`,
    walletSessionId: required(parseWalletSessionId('wallet-session:readiness-exact-sibling')),
  };
  const siblingSelected: SelectedAuthorityResult = {
    ...harness.selected,
    selection: {
      ...harness.selected.selection,
      walletAuthMethodId: siblingAuthMethodId,
    },
    authMethod: siblingAuthMethod,
  };
  harness.deps.listExactSealedSessionsForWallet = async () => [harness.sealed, siblingSealed];

  const primaryAuthorization: WalletSessionAuthorizationExactOperationCredentialReadResult = {
    kind: 'found',
    record: harness.authorityFixture.activeWalletSession,
    operationCredential: harness.authorityFixture.operationCredential,
  };
  const siblingAuthorization: WalletSessionAuthorizationExactOperationCredentialReadResult = {
    kind: 'found',
    record: siblingSession,
    operationCredential: siblingOperationCredential,
  };
  const primary = await discoverWithAuthorization(harness, primaryAuthorization);
  const sibling = await discoverWithAuthorization(harness, siblingAuthorization, siblingSelected);

  expect(primary.lanes).toHaveLength(1);
  expect(primary.lanes[0]).toMatchObject({
    source: 'passkey',
    thresholdSessionId: harness.sealed.thresholdSessionIds.ed25519,
    walletSessionId: harness.authorityFixture.operationCredential.walletSessionId,
    quotaId: harness.authorityFixture.activeWalletSession.quotaId,
  });
  expect(primary.lanes[0]?.walletSessionId).not.toBe(siblingOperationCredential.walletSessionId);
  expect(sibling.lanes).toHaveLength(1);
  expect(sibling.lanes[0]).toMatchObject({
    source: 'passkey',
    thresholdSessionId: siblingSealed.thresholdSessionIds.ed25519,
    walletSessionId: siblingOperationCredential.walletSessionId,
    quotaId: siblingSession.quotaId,
  });
  expect(sibling.lanes[0]?.walletSessionId).not.toBe(
    harness.authorityFixture.operationCredential.walletSessionId,
  );
  expect(primary.resolver.exactReads).toEqual([
    {
      walletId: harness.authorityFixture.authority.walletId,
      authorityId: harness.authorityFixture.authority.authorityId,
      authMethodId: harness.authorityFixture.authMethod.walletAuthMethodId,
    },
  ]);
  expect(sibling.resolver.exactReads).toEqual([
    {
      walletId: harness.authorityFixture.authority.walletId,
      authorityId: harness.authorityFixture.authority.authorityId,
      authMethodId: siblingAuthMethodId,
    },
  ]);
});
