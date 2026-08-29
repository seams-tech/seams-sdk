import { expect, test } from '@playwright/test';
import {
  reconcileWalletIframeExactSessions,
  type WalletIframeExactSessionReconciliationDependencies,
} from '@/SeamsWeb/walletIframe/shared/exactSessionReconciliation';
import type {
  ActiveWalletSessionV1,
  WalletSessionOperationCredentialV1,
} from '@shared/device-linking';
import {
  parseMpcWalletSigningQuotaId,
  parseWalletSessionAuthorizationId,
  parseWalletSessionId,
} from '@shared/authorization/capabilityKinds';
import { parseWalletAuthMethodId } from '@shared/utils/domainIds';
import { base64UrlEncode } from '@shared/utils/base64';
import { parseDigestB64u, type DigestB64u } from '@shared/utils/canonicalPrimitives';
import {
  buildWalletAuthMethodRecordV2,
  type WalletAuthMethodRecordV2,
} from '@shared/utils/registrationIntent';
import type { WalletIframeExactSessionStatus } from '@/SeamsWeb/walletIframe/shared/exactSessionState';
import {
  buildLinkedDeviceActiveWalletSessionFixture,
  buildLinkedDeviceUnlockRuntimeFixture,
  type LinkedDeviceUnlockRuntimeFixture,
} from './helpers/linkedDeviceUnlockRuntime.fixtures';

function required<T>(
  result:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
): T {
  if (!result.ok) throw new Error(result.error.message);
  return result.value;
}

function promotedDigest(): DigestB64u {
  return parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(199)));
}

function promotedSession(local: ActiveWalletSessionV1, digest: DigestB64u): ActiveWalletSessionV1 {
  return buildLinkedDeviceActiveWalletSessionFixture({
    source: local,
    authMethodId: local.authMethodId,
    authorizationId: local.authorizationId,
    quotaId: local.quotaId,
    authorityDigestB64u: digest,
    authorityRevocationEpoch: local.authorityRevocationEpoch + 1,
  });
}

function siblingMethod(fixture: LinkedDeviceUnlockRuntimeFixture) {
  const walletAuthMethodId = required(parseWalletAuthMethodId('wallet-auth-method:linked-sibling'));
  const credentialIdB64u = base64UrlEncode(new Uint8Array(32).fill(23));
  const record = buildWalletAuthMethodRecordV2({
    version: 'wallet_auth_method_v2',
    walletAuthMethodId,
    walletId: fixture.walletId,
    walletAuthorityId: fixture.authority.authorityId,
    kind: 'passkey',
    status: 'active',
    rpId: fixture.authMethod.rpId,
    credentialIdB64u,
    credentialPublicKeyB64u: fixture.authMethod.credentialPublicKeyB64u,
    counter: 0,
    createdAtMs: fixture.authMethod.createdAtMs,
    updatedAtMs: fixture.authMethod.updatedAtMs,
    activatedAtMs: fixture.authMethod.activatedAtMs,
  });
  if (record.kind !== 'passkey' || record.status !== 'active') {
    throw new Error('sibling method fixture has the wrong branch');
  }
  return record;
}

function siblingSession(
  fixture: LinkedDeviceUnlockRuntimeFixture,
  authMethodId: ReturnType<typeof parseWalletAuthMethodId> extends {
    ok: true;
    value: infer T;
  }
    ? T
    : never,
): ActiveWalletSessionV1 {
  return buildLinkedDeviceActiveWalletSessionFixture({
    source: fixture.activeWalletSession,
    authMethodId,
    authorizationId: required(parseWalletSessionAuthorizationId('authorization:linked-sibling')),
    quotaId: required(parseMpcWalletSigningQuotaId('wallet-quota:linked-sibling')),
    authorityDigestB64u: fixture.activeWalletSession.authorityDigestB64u,
    authorityRevocationEpoch: fixture.activeWalletSession.authorityRevocationEpoch,
  });
}

function siblingCredential(
  walletSessionId: ReturnType<typeof parseWalletSessionId> extends {
    ok: true;
    value: infer T;
  }
    ? T
    : never,
): WalletSessionOperationCredentialV1 {
  return {
    kind: 'opaque_wallet_session_operation_credential_v1',
    token: `wst_${'B'.repeat(43)}`,
    walletSessionId,
  };
}

function resolvedFor(fixture: LinkedDeviceUnlockRuntimeFixture, authorityDigestB64u: DigestB64u) {
  return {
    kind: 'resolved' as const,
    selection: fixture.selection,
    authMethod: fixture.authMethod,
    authority: {
      ...fixture.authority,
      authorityDigestB64u,
      revocationEpoch: fixture.authority.revocationEpoch + 1,
    },
    signerMaterials: fixture.signerMaterials,
    exportRoot: null,
  };
}

function activeStatus(
  authorization: ActiveWalletSessionV1,
  operationCredential: WalletSessionOperationCredentialV1,
): WalletIframeExactSessionStatus {
  return {
    status: 'active',
    walletSessionId: operationCredential.walletSessionId,
    quotaId: authorization.quotaId,
    remainingUses: 10,
    expiresAtMs: authorization.expiresAtMs,
    quotaLifecycle: 'active',
    authorization,
  };
}

function reconciliationDependencies(
  fixture: LinkedDeviceUnlockRuntimeFixture,
  promotedAuthority: ReturnType<typeof resolvedFor>,
  sibling: WalletAuthMethodRecordV2,
  localSessions: readonly {
    readonly record: ActiveWalletSessionV1;
    readonly operationCredential: WalletSessionOperationCredentialV1;
  }[],
  authoritativeSessions: readonly ActiveWalletSessionV1[],
): {
  readonly dependencies: WalletIframeExactSessionReconciliationDependencies;
  readonly writes: {
    readonly record: ActiveWalletSessionV1;
    readonly operationCredential: WalletSessionOperationCredentialV1;
  }[];
} {
  const sessionByMethod = new Map(
    localSessions.map((session) => [String(session.record.authMethodId), session]),
  );
  const authoritativeByMethod = new Map(
    authoritativeSessions.map((session) => [String(session.authMethodId), session]),
  );
  const writes: (typeof localSessions)[number][] = [];
  const dependencies: WalletIframeExactSessionReconciliationDependencies = {
    resolveSelectedWalletAuthority: async () => promotedAuthority,
    listWalletAuthMethodsV2ForWallet: async () => [fixture.authMethod, sibling],
    resolveWalletAuthorityForMethod: async (_walletId, authMethodId) => {
      if (authMethodId === String(sibling.walletAuthMethodId)) {
        return {
          ...promotedAuthority,
          authMethod: sibling,
        };
      }
      return promotedAuthority;
    },
    readExactActiveForWallet: async ({ authMethodId }) => {
      const session = sessionByMethod.get(String(authMethodId));
      return session ? { kind: 'found' as const, ...session } : { kind: 'missing' as const };
    },
    readStatus: async ({ authorization, operationCredential }) => {
      const authoritative = authoritativeByMethod.get(String(authorization.authMethodId));
      if (!authoritative) throw new Error('missing authoritative sibling fixture');
      return activeStatus(authoritative, operationCredential);
    },
    writeExactWithOperationCredential: async ({ record, operationCredential }) => {
      writes.push({ record, operationCredential });
      return record;
    },
  };
  return { dependencies, writes };
}

test.describe('wallet iframe exact session reconciliation', () => {
  test('reconciles both sibling methods when the initiating promotion response is lost', async () => {
    const fixture = await buildLinkedDeviceUnlockRuntimeFixture();
    const sibling = siblingMethod(fixture);
    const siblingSessionRecord = siblingSession(fixture, sibling.walletAuthMethodId);
    const siblingWalletSessionId = required(parseWalletSessionId('wallet-session:linked-sibling'));
    const siblingCredentialValue = siblingCredential(siblingWalletSessionId);
    const digest = promotedDigest();
    const selectedAuthority = resolvedFor(fixture, digest);
    const selectedAuthoritative = promotedSession(fixture.activeWalletSession, digest);
    const siblingAuthoritative = promotedSession(siblingSessionRecord, digest);
    const { dependencies, writes } = reconciliationDependencies(
      fixture,
      selectedAuthority,
      sibling,
      [
        {
          record: fixture.activeWalletSession,
          operationCredential: fixture.operationCredential,
        },
        { record: siblingSessionRecord, operationCredential: siblingCredentialValue },
      ],
      [selectedAuthoritative, siblingAuthoritative],
    );

    const result = await reconcileWalletIframeExactSessions(
      { walletId: fixture.walletId },
      dependencies,
    );

    expect(result).toEqual({ kind: 'reconciled', updatedSessionCount: 2 });
    expect(writes).toHaveLength(2);
    expect(writes.map((write) => write.record)).toEqual(
      expect.arrayContaining([selectedAuthoritative, siblingAuthoritative]),
    );
    expect(new Set(writes.map((write) => write.operationCredential.token))).toEqual(
      new Set([fixture.operationCredential.token, siblingCredentialValue.token]),
    );
  });

  test('preserves an inactive sibling while reconciling the selected method', async () => {
    const fixture = await buildLinkedDeviceUnlockRuntimeFixture();
    const sibling = siblingMethod(fixture);
    const inactiveSibling = { ...sibling, status: 'revoked' as const, revokedAtMs: 500 };
    const digest = promotedDigest();
    const promotedAuthority = resolvedFor(fixture, digest);
    const authoritative = promotedSession(fixture.activeWalletSession, digest);
    const { dependencies } = reconciliationDependencies(
      fixture,
      promotedAuthority,
      inactiveSibling,
      [
        {
          record: fixture.activeWalletSession,
          operationCredential: fixture.operationCredential,
        },
      ],
      [authoritative],
    );

    await expect(
      reconcileWalletIframeExactSessions({ walletId: fixture.walletId }, dependencies),
    ).resolves.toEqual({ kind: 'reconciled', updatedSessionCount: 1 });
  });
});
