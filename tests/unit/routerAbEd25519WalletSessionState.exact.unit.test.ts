import { expect, test } from '@playwright/test';
import {
  buildPasskeyRouterAbEd25519WalletSessionState,
  resolveActiveAuthorizedRouterAbEd25519WalletSessionStateWithResolver,
  type ResolvedRouterAbEd25519WalletSessionState,
  type RouterAbEd25519WalletSessionAuthorizationResolver,
} from '@/core/signingEngine/session/warmCapabilities/routerAbEd25519WalletSessionState';
import { buildRouterAbEd25519SigningWalletSession } from '@/core/signingEngine/session/routerAbSigningWalletSession';
import { parseExactEd25519SealedSessionRuntime } from '@/core/signingEngine/session/warmCapabilities/ed25519SealedSessionRuntime';
import { SigningSessionIds } from '@/core/signingEngine/session/operationState/types';
import { toAccountId } from '@/core/types/accountIds';
import { toRpId } from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import { nearEd25519SigningKeyIdFromString } from '@shared/utils/registrationIntent';
import { signingRootScopeFromRuntimePolicyScope } from '@shared/threshold/signingRootScope';
import { walletAuthAuthorityRef } from '@shared/utils/walletAuthAuthority';
import { buildFullOwnerPermissionsV1 } from '@shared/authorization/delegatedAuthority';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import { base64UrlEncode } from '@shared/utils/base64';
import { parseWalletSessionId } from '@shared/authorization/capabilityKinds';
import type {
  ActiveWalletSessionV1,
  WalletSessionAuthorizationExactOperationCredentialReadResult,
  WalletSessionOperationCredentialV1,
} from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import { buildLinkedDeviceManagementAuthorityFixture } from './helpers/linkedDeviceManagement.fixtures';
import { buildPasskeyEd25519SealedSessionRecordFixture } from './helpers/sealedSigningSession.fixtures';
import { buildMpcMaterialActivationRefFixture } from './helpers/ecdsaMaterialRef.fixtures';

type SelectedAuthorityResult = Awaited<
  ReturnType<RouterAbEd25519WalletSessionAuthorizationResolver['resolveSelectedWalletAuthority']>
>;

function requireWalletSessionId(value: string) {
  const parsed = parseWalletSessionId(value);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

class ExactSessionResolverFixture implements RouterAbEd25519WalletSessionAuthorizationResolver {
  readonly selectedWalletIds: string[] = [];
  readonly exactReads: Array<
    Parameters<
      RouterAbEd25519WalletSessionAuthorizationResolver['readExactWithOperationCredential']
    >[0]
  > = [];

  constructor(
    private readonly selected: SelectedAuthorityResult,
    private readonly exact: WalletSessionAuthorizationExactOperationCredentialReadResult | Error,
  ) {}

  async resolveSelectedWalletAuthority(walletId: string): Promise<SelectedAuthorityResult> {
    this.selectedWalletIds.push(walletId);
    return this.selected;
  }

  async readExactWithOperationCredential(
    input: Parameters<
      RouterAbEd25519WalletSessionAuthorizationResolver['readExactWithOperationCredential']
    >[0],
  ): Promise<WalletSessionAuthorizationExactOperationCredentialReadResult> {
    this.exactReads.push(input);
    if (this.exact instanceof Error) throw this.exact;
    return this.exact;
  }
}

async function buildExactSessionHarness() {
  const sealed = buildPasskeyEd25519SealedSessionRecordFixture();
  const runtime = parseExactEd25519SealedSessionRuntime(sealed);
  if (!runtime || runtime.factor.kind !== 'passkey') {
    throw new Error('exact state fixture requires a passkey Ed25519 runtime');
  }
  const fixture = await buildLinkedDeviceManagementAuthorityFixture({
    label: 'ed25519-exact-state',
    permissions: buildFullOwnerPermissionsV1(),
    provenance: 'device_link',
    materialActivation: sealed.ed25519Restore.materialActivation,
    expiresAtMs: sealed.expiresAtMs,
    identity: {
      walletId: sealed.walletId,
      authorityId: 'authority:ed25519-exact-state',
      walletAuthMethodId: 'auth-method:ed25519-exact-state',
      rpId: runtime.factor.rpId,
    },
  });
  const runtimePolicyScope = runtime.runtimePolicyScope;
  const signingRoot = signingRootScopeFromRuntimePolicyScope(runtimePolicyScope);
  const thresholdSessionId = SigningSessionIds.thresholdEd25519Session(
    sealed.thresholdSessionIds.ed25519,
  );
  const originalToken = `wst_${'A'.repeat(43)}`;
  const signingWalletSession = buildRouterAbEd25519SigningWalletSession({
    walletId: fixture.authority.walletId,
    nearAccountId: runtime.nearAccountId,
    nearEd25519SigningKeyId: runtime.nearEd25519SigningKeyId,
    walletSessionId: fixture.operationCredential.walletSessionId,
    authorizationId: fixture.activeWalletSession.authorizationId,
    quotaId: fixture.issuedSession.session.quotaId,
    thresholdSessionId,
    remainingUses: 5,
    expiresAtMs: sealed.expiresAtMs,
    runtimePolicyScope,
    signingRootId: signingRoot.signingRootId,
    signingRootVersion: runtime.signingRootVersion,
    routerAbNormalSigning: runtime.routerAbNormalSigning,
    walletSessionToken: originalToken,
    nowMs: sealed.expiresAtMs - 1,
  });
  if (!signingWalletSession.ok) {
    throw new Error(`exact state fixture session is invalid: ${signingWalletSession.reason}`);
  }
  const authority = await walletAuthAuthorityRef({
    authority: {
      walletId: fixture.authority.walletId,
      factor: {
        kind: 'passkey',
        credentialIdB64u: fixture.authMethod.credentialIdB64u,
      },
      verifier: {
        kind: 'webauthn',
        rpId: fixture.authMethod.rpId,
      },
      bindingId: fixture.authMethod.walletAuthMethodId,
    },
  });
  const state = buildPasskeyRouterAbEd25519WalletSessionState({
    walletId: fixture.authority.walletId,
    nearAccountId: toAccountId(runtime.nearAccountId),
    nearEd25519SigningKeyId: nearEd25519SigningKeyIdFromString(runtime.nearEd25519SigningKeyId),
    signerSlot: runtime.signerSlot,
    rpId: toRpId(fixture.authMethod.rpId),
    credentialIdB64u: fixture.authMethod.credentialIdB64u,
    relayerUrl: runtime.relayerUrl,
    authority,
    signingWalletSession: signingWalletSession.value,
  });
  const selected: SelectedAuthorityResult = {
    kind: 'resolved',
    selection: fixture.selection,
    authMethod: fixture.authMethod,
    authority: fixture.authority,
    signerMaterials: [],
    exportRoot: null,
  };
  return { fixture, originalToken, selected, state };
}

function exactFound(
  record: ActiveWalletSessionV1,
  operationCredential: WalletSessionOperationCredentialV1,
): WalletSessionAuthorizationExactOperationCredentialReadResult {
  return { kind: 'found', record, operationCredential };
}

async function resolveWithExact(
  state: ResolvedRouterAbEd25519WalletSessionState,
  selected: SelectedAuthorityResult,
  exact: WalletSessionAuthorizationExactOperationCredentialReadResult | Error,
  nowMs: number,
) {
  const resolver = new ExactSessionResolverFixture(selected, exact);
  const result = await resolveActiveAuthorizedRouterAbEd25519WalletSessionStateWithResolver(
    { state, nowMs },
    resolver,
  );
  return { resolver, result };
}

test('authorizes from the selected exact Ed25519 V5 operation credential', async () => {
  const harness = await buildExactSessionHarness();
  const { resolver, result } = await resolveWithExact(
    harness.state,
    harness.selected,
    exactFound(harness.fixture.activeWalletSession, harness.fixture.operationCredential),
    harness.fixture.activeWalletSession.expiresAtMs - 1,
  );

  expect(result?.signingWalletSession.auth.walletSessionToken).toBe(
    harness.fixture.operationCredential.token,
  );
  expect(result?.signingWalletSession.auth.walletSessionToken).not.toBe(harness.originalToken);
  expect(result?.walletSessionAuthorization).toBe(harness.fixture.activeWalletSession);
  expect(result?.walletSessionOperationCredential).toBe(harness.fixture.operationCredential);
  expect(resolver.exactReads).toEqual([
    {
      walletId: harness.fixture.authority.walletId,
      authorityId: harness.fixture.authority.authorityId,
      authMethodId: harness.fixture.authMethod.walletAuthMethodId,
    },
  ]);
});

test('skips exact Ed25519 sessions whose authority, lifecycle, credential, or material drifts', async () => {
  const harness = await buildExactSessionHarness();
  const record = harness.fixture.activeWalletSession;
  const otherMaterial = buildMpcMaterialActivationRefFixture(
    'ed25519-exact-state-other',
    harness.fixture.authority.walletId,
  );
  const cases: ReadonlyArray<WalletSessionAuthorizationExactOperationCredentialReadResult> = [
    exactFound(
      {
        ...record,
        authorityDigestB64u: parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(99))),
      },
      harness.fixture.operationCredential,
    ),
    exactFound(
      { ...record, authorityRevocationEpoch: record.authorityRevocationEpoch + 1 },
      harness.fixture.operationCredential,
    ),
    exactFound({ ...record, expiresAtMs: 1 }, harness.fixture.operationCredential),
    exactFound(
      {
        ...record,
        capabilitySubjects: [
          { kind: 'sign', keyFamily: 'ed25519', materialActivation: otherMaterial },
        ],
      },
      harness.fixture.operationCredential,
    ),
    exactFound(record, {
      ...harness.fixture.operationCredential,
      walletSessionId: requireWalletSessionId(
        `${harness.fixture.operationCredential.walletSessionId}-changed`,
      ),
    }),
  ];

  for (const exact of cases) {
    const { result } = await resolveWithExact(
      harness.state,
      harness.selected,
      exact,
      record.expiresAtMs - 1,
    );
    expect(result).toBeNull();
  }
});

test('treats unavailable or corrupt exact persistence as a skipped shell read', async () => {
  const harness = await buildExactSessionHarness();
  const cases: ReadonlyArray<
    WalletSessionAuthorizationExactOperationCredentialReadResult | Error
  > = [
    { kind: 'missing' },
    { kind: 'upgrade_required' },
    new Error('Stored Wallet Session authorization v5 is corrupt'),
  ];
  for (const exact of cases) {
    const { result } = await resolveWithExact(
      harness.state,
      harness.selected,
      exact,
      harness.fixture.activeWalletSession.expiresAtMs - 1,
    );
    expect(result).toBeNull();
  }
});
