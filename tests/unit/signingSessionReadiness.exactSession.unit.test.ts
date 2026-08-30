import { expect, test } from '@playwright/test';
import {
  discoverLanesForWalletWithResolver,
  type SigningSessionReadinessExactAuthorizationResolver,
  type WalletSessionReadinessDeps,
} from '@/core/signingEngine/session/availability/readiness';
import type { WalletSessionAuthorizationExactOperationCredentialReadResult } from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import { buildFullOwnerPermissionsV1 } from '@shared/authorization/delegatedAuthority';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import { base64UrlEncode } from '@shared/utils/base64';
import { buildLinkedDeviceManagementAuthorityFixture } from './helpers/linkedDeviceManagement.fixtures';
import { buildPasskeyEd25519SealedSessionRecordFixture } from './helpers/sealedSigningSession.fixtures';
import { buildMpcMaterialActivationRefFixture } from './helpers/ecdsaMaterialRef.fixtures';

type SelectedAuthorityResult = Awaited<
  ReturnType<SigningSessionReadinessExactAuthorizationResolver['resolveSelectedWalletAuthority']>
>;

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
) {
  const resolver = new ExactAuthorizationResolverFixture(harness.selected, authorization);
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
