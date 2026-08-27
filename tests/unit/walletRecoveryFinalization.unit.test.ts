import { expect, test } from '@playwright/test';
import {
  buildActiveWalletAuthorityV1,
  buildFullOwnerPermissionsV1,
  computeWalletAuthorityDigestB64u,
  type ActiveWalletAuthorityV1,
} from '@shared/authorization';
import {
  buildWalletRecoveryEnvelopeSetRecord,
  buildWalletRecoveryManifestKekWrap,
  parseWalletRecoveryEnvelopeSetRecord,
  type WalletRecoveryEnvelopeSetRecord,
} from '@shared/wallet-recovery';
import { parseRecoveryCodeReservationId } from '@shared/wallet-recovery/recoveryCodeReservation';
import { parseDeviceId } from '@shared/authorization/capabilityKinds';
import {
  parseWalletAuthMethodId,
  parseWalletAuthorityId,
  parseWalletId,
  parseWalletRecoveryOperationId,
  parseWebAuthnCredentialIdB64u,
  parseWebAuthnRpId,
  type WalletAuthMethodId,
  type WalletAuthorityId,
  type WalletId,
  type WebAuthnCredentialIdB64u,
  type WebAuthnRpId,
} from '@shared/utils/domainIds';
import { alphabetizeStringify } from '@shared/utils/digests';
import {
  buildWalletAuthMethodRecordV2,
  type WalletAuthMethodRecordV2,
} from '@shared/utils/registrationIntent';
import {
  buildActiveMethodBoundPasskeyCustodyEnvelopeFixture,
  CREDENTIAL_ID_B64U,
  rawWalletRecoveryEnvelopeSet,
  RP_ID,
  WALLET_ID,
} from './helpers/passkeyCustodyEnvelope.fixtures';
import {
  buildLinkedDeviceManagementAuthorityFixture,
  fullOwnerPermissionsForManagementFixture,
} from './helpers/linkedDeviceManagement.fixtures';
import {
  testWebAuthnAuthenticatorRecord,
  testWebAuthnCredentialBindingRecord,
} from './helpers/webauthnAuthenticatorListing.fixtures';
import {
  CloudflareD1PasskeyCustodyEnvelopeStore,
  type PasskeyCustodyEnvelopeLookupResult,
  type PasskeyCustodyEnvelopeLocator,
} from '../../packages/wallet-server/src/router/cloudflare/d1/passkeyCustody/d1PasskeyCustodyEnvelopeStore';
import {
  CloudflareD1WalletCustodyCommitStore,
  type WalletRecoveryCodeLocatorRecord,
} from '../../packages/wallet-server/src/router/cloudflare/d1/passkeyCustody/d1WalletCustodyCommitStore';
import { resolveCommittedRecoveryReplayV1 } from '../../packages/wallet-server/src/router/domains/passkeyCustody/walletRecoveryFinalization';
import { CloudflareD1WebAuthnStore } from '../../packages/wallet-server/src/router/cloudflare/d1/webauthn/d1WebAuthnStore';
import type {
  WebAuthnAuthenticatorRecord,
  WebAuthnCredentialBindingRecord,
} from '../../packages/wallet-server/src/router/cloudflare/d1/webauthn/d1WebAuthnRecords';
import type { D1WalletAuthorityStore } from '../../packages/wallet-server/src/router/cloudflare/d1/wallet/d1WalletAuthorityStore';
import { cleanupTemporaryD1Database, createTemporaryD1Database } from '../helpers/sqliteD1';

const WALLET = required(parseWalletId(WALLET_ID));
const RP = required(parseWebAuthnRpId(RP_ID));
const RESERVATION_ID = parseRecoveryCodeReservationId('recovery-operation:replay');
const RECOVERY_OPERATION_ID = required(
  parseWalletRecoveryOperationId('recovery-operation:replay-target'),
);
const TARGET_DEVICE_ID = required(parseDeviceId('device:recovery-target'));
const TARGET_AUTHORITY_ID = required(parseWalletAuthorityId('wallet-authority:recovery-target'));
const TARGET_METHOD_ID = required(parseWalletAuthMethodId('wallet-auth-method:recovery-target'));
const TARGET_CREDENTIAL_ID = required(parseWebAuthnCredentialIdB64u(CREDENTIAL_ID_B64U));
const TARGET_PUBLIC_KEY = 'recovery-target-public-key';

const temporaryDatabase = createTemporaryD1Database();
const TEST_SCOPE = {
  namespace: 'wallet-recovery-finalization-test',
  orgId: 'org-a',
  projectId: 'project-a',
  envId: 'env-a',
} as const;

test.afterAll(() => {
  cleanupTemporaryD1Database(temporaryDatabase.tempDir);
});

function required<T>(
  result:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
): T {
  if (!result.ok) throw new Error(result.error.message);
  return result.value;
}

type ActivePasskeyWalletAuthMethodRecordV2 = Extract<
  WalletAuthMethodRecordV2,
  { readonly kind: 'passkey'; readonly status: 'active' }
>;

function buildActivePasskeyWalletAuthMethod(input: {
  readonly walletId: WalletId;
  readonly walletAuthorityId: WalletAuthorityId;
  readonly walletAuthMethodId: WalletAuthMethodId;
  readonly rpId: WebAuthnRpId;
  readonly credentialIdB64u: WebAuthnCredentialIdB64u;
  readonly credentialPublicKeyB64u: string;
  readonly createdAtMs: number;
}): ActivePasskeyWalletAuthMethodRecordV2 {
  const record = buildWalletAuthMethodRecordV2({
    version: 'wallet_auth_method_v2',
    walletAuthMethodId: input.walletAuthMethodId,
    walletId: input.walletId,
    walletAuthorityId: input.walletAuthorityId,
    kind: 'passkey',
    status: 'active',
    rpId: input.rpId,
    credentialIdB64u: input.credentialIdB64u,
    credentialPublicKeyB64u: input.credentialPublicKeyB64u,
    counter: 0,
    createdAtMs: input.createdAtMs,
    updatedAtMs: input.createdAtMs,
    activatedAtMs: input.createdAtMs,
  });
  if (record.kind !== 'passkey' || record.status !== 'active') {
    throw new Error('recovery target fixture unexpectedly changed auth-method branch');
  }
  return record;
}

async function buildRecoveredAuthority(
  continuityAuthority: ActiveWalletAuthorityV1,
): Promise<ActiveWalletAuthorityV1> {
  const draft = buildActiveWalletAuthorityV1({
    kind: continuityAuthority.kind,
    authorityId: TARGET_AUTHORITY_ID,
    walletId: WALLET,
    principal: { kind: 'owner_device', deviceId: TARGET_DEVICE_ID },
    provenance: {
      kind: 'wallet_recovery',
      recoveryOperationId: RECOVERY_OPERATION_ID,
      continuityAuthorityId: continuityAuthority.authorityId,
    },
    permissions: buildFullOwnerPermissionsV1(),
    signerActivations: continuityAuthority.signerActivations,
    signerActivationSetDigestB64u: continuityAuthority.signerActivationSetDigestB64u,
    authorityDigestB64u: continuityAuthority.authorityDigestB64u,
    revocationEpoch: 0,
    createdAtMs: 500,
    updatedAtMs: 500,
    state: 'active',
    activatedAtMs: 500,
  });
  return buildActiveWalletAuthorityV1({
    ...draft,
    authorityDigestB64u: await computeWalletAuthorityDigestB64u(draft),
  });
}

function buildConsumedRecoverySet(): {
  readonly record: WalletRecoveryEnvelopeSetRecord;
  readonly recoveryKeyId: WalletRecoveryEnvelopeSetRecord['manifestKekWraps'][number]['recoveryKeyId'];
} {
  const activeSet = parseWalletRecoveryEnvelopeSetRecord(rawWalletRecoveryEnvelopeSet(), {
    expectedWalletId: WALLET,
  });
  const selected = activeSet.manifestKekWraps[0];
  if (!selected || selected.lifecycle.state !== 'active') {
    throw new Error('recovery replay fixture has no active wrap');
  }
  const consumedWrap = buildWalletRecoveryManifestKekWrap({
    recoveryKeyId: selected.recoveryKeyId,
    nonceB64u: selected.nonceB64u,
    wrappedManifestKekB64u: selected.wrappedManifestKekB64u,
    aadHashB64u: selected.aadHashB64u,
    lifecycle: {
      state: 'consumed',
      issuedAtMs: selected.lifecycle.issuedAtMs,
      reservationId: RESERVATION_ID,
      consumedAtMs: 500,
    },
  });
  const manifestKekWraps = activeSet.manifestKekWraps.map((wrap, index) =>
    index === 0 ? consumedWrap : wrap,
  );
  return {
    record: buildWalletRecoveryEnvelopeSetRecord({
      walletId: activeSet.walletId,
      manifestKekWraps,
      entries: activeSet.entries,
      issuedAtMs: activeSet.issuedAtMs,
      updatedAtMs: 500,
    }),
    recoveryKeyId: selected.recoveryKeyId,
  };
}

type ReplayCoreFixture = {
  readonly targetInstalled: boolean;
  readonly sourceAuthority: ActiveWalletAuthorityV1;
  readonly sourceMethod: ActivePasskeyWalletAuthMethodRecordV2;
  readonly sourceEnvelope: ReturnType<typeof buildActiveMethodBoundPasskeyCustodyEnvelopeFixture>;
  readonly sourceSession: Awaited<
    ReturnType<typeof buildLinkedDeviceManagementAuthorityFixture>
  >['issuedSession'];
  readonly targetAuthority: ActiveWalletAuthorityV1;
  readonly targetMethod: ActivePasskeyWalletAuthMethodRecordV2;
  readonly targetEnvelope: ReturnType<typeof buildActiveMethodBoundPasskeyCustodyEnvelopeFixture>;
  readonly recoverySet: WalletRecoveryEnvelopeSetRecord;
  readonly recoveryKeyId: WalletRecoveryEnvelopeSetRecord['manifestKekWraps'][number]['recoveryKeyId'];
  readonly authenticator: WebAuthnAuthenticatorRecord;
  readonly binding: WebAuthnCredentialBindingRecord;
};

class ReplayEnvelopeStore extends CloudflareD1PasskeyCustodyEnvelopeStore {
  private readonly replacementEnvelope: ReplayCoreFixture['targetEnvelope'];

  constructor(replacementEnvelope: ReplayCoreFixture['targetEnvelope']) {
    super({ database: temporaryDatabase.database, scope: TEST_SCOPE });
    this.replacementEnvelope = replacementEnvelope;
  }

  override async lookupEnvelope(
    _locator: PasskeyCustodyEnvelopeLocator,
  ): Promise<PasskeyCustodyEnvelopeLookupResult> {
    return {
      kind: 'active',
      envelope: this.replacementEnvelope,
      storeVersion: 'v2',
    };
  }
}

class ReplayCommitStore extends CloudflareD1WalletCustodyCommitStore {
  private readonly fixture: ReplayCoreFixture;

  constructor(fixture: ReplayCoreFixture) {
    super({ database: temporaryDatabase.database, scope: TEST_SCOPE });
    this.fixture = fixture;
  }

  override async readRecoveryEnvelopeSet(walletId: WalletId): Promise<{
    readonly record: WalletRecoveryEnvelopeSetRecord;
    readonly storeVersion: string;
  } | null> {
    if (walletId !== WALLET) return null;
    return { record: this.fixture.recoverySet, storeVersion: 'recovery-v1' };
  }

  override async readRecoveryCodeLocatorByRecoveryKey(_input: {
    readonly walletId: WalletId;
    readonly recoveryKeyId: ReplayCoreFixture['recoveryKeyId'];
  }): Promise<WalletRecoveryCodeLocatorRecord | null> {
    return null;
  }

  override async readWalletAuthMethodById(
    walletAuthMethodId: WalletAuthMethodId,
  ): Promise<WalletAuthMethodRecordV2 | null> {
    if (!this.fixture.targetInstalled) return null;
    if (walletAuthMethodId === this.fixture.targetMethod.walletAuthMethodId) {
      return this.fixture.targetMethod;
    }
    if (walletAuthMethodId === this.fixture.sourceMethod.walletAuthMethodId) {
      return this.fixture.sourceMethod;
    }
    return null;
  }
}

class ReplayWebAuthnStore extends CloudflareD1WebAuthnStore {
  private readonly fixture: ReplayCoreFixture;

  constructor(fixture: ReplayCoreFixture) {
    super({
      database: temporaryDatabase.database,
      namespace: TEST_SCOPE.namespace,
      orgId: TEST_SCOPE.orgId,
      projectId: TEST_SCOPE.projectId,
      envId: TEST_SCOPE.envId,
    });
    this.fixture = fixture;
  }

  override async readAuthenticator(input: {
    readonly userId: string;
    readonly credentialIdB64u: string;
  }): Promise<WebAuthnAuthenticatorRecord | null> {
    if (
      !this.fixture.targetInstalled ||
      input.userId !== String(WALLET) ||
      input.credentialIdB64u !== String(this.fixture.authenticator.credentialIdB64u)
    ) {
      return null;
    }
    return this.fixture.authenticator;
  }

  override async readBindingByCredential(input: {
    readonly rpId: string;
    readonly credentialIdB64u: string;
  }): Promise<WebAuthnCredentialBindingRecord | null> {
    if (
      !this.fixture.targetInstalled ||
      input.rpId !== String(RP) ||
      input.credentialIdB64u !== String(this.fixture.binding.credentialIdB64u)
    ) {
      return null;
    }
    return this.fixture.binding;
  }
}

async function buildReplayFixture(targetInstalled: boolean): Promise<ReplayFixture> {
  const source = await buildLinkedDeviceManagementAuthorityFixture({
    label: 'owner',
    permissions: fullOwnerPermissionsForManagementFixture(),
    provenance: 'wallet_registration',
    identity: {
      walletId: WALLET_ID,
      authorityId: 'wallet-authority:recovery-source',
      walletAuthMethodId: 'wallet-auth-method:recovery-source',
      rpId: RP_ID,
    },
  });
  const sourceEnvelope = buildActiveMethodBoundPasskeyCustodyEnvelopeFixture({
    walletId: WALLET_ID,
    envelopeId: 'passkey-envelope:recovery-source',
    rpId: RP_ID,
    credentialIdB64u: String(source.authMethod.credentialIdB64u),
    walletAuthMethodId: String(source.authMethod.walletAuthMethodId),
  });
  const targetAuthority = await buildRecoveredAuthority(source.authority);
  const targetMethod = buildActivePasskeyWalletAuthMethod({
    walletId: WALLET,
    walletAuthorityId: TARGET_AUTHORITY_ID,
    walletAuthMethodId: TARGET_METHOD_ID,
    rpId: RP,
    credentialIdB64u: TARGET_CREDENTIAL_ID,
    credentialPublicKeyB64u: TARGET_PUBLIC_KEY,
    createdAtMs: 500,
  });
  const targetEnvelope = buildActiveMethodBoundPasskeyCustodyEnvelopeFixture({
    walletId: WALLET_ID,
    envelopeId: 'passkey-envelope:recovery-target',
    rpId: RP_ID,
    credentialIdB64u: String(TARGET_CREDENTIAL_ID),
    walletAuthMethodId: String(TARGET_METHOD_ID),
  });
  const recovery = buildConsumedRecoverySet();
  const authenticator = testWebAuthnAuthenticatorRecord({
    credentialIdB64u: String(TARGET_CREDENTIAL_ID),
    credentialPublicKeyB64u: TARGET_PUBLIC_KEY,
    counter: 0,
    createdAtMs: 500,
    updatedAtMs: 500,
  });
  const binding = testWebAuthnCredentialBindingRecord({
    credentialIdB64u: String(TARGET_CREDENTIAL_ID),
    userId: WALLET_ID,
    rpId: RP_ID,
    createdAtMs: 500,
    updatedAtMs: 500,
  });
  const fixtureCore = {
    targetInstalled,
    sourceAuthority: source.authority,
    sourceMethod: source.authMethod,
    sourceEnvelope,
    sourceSession: source.issuedSession,
    targetAuthority,
    targetMethod,
    targetEnvelope,
    recoverySet: recovery.record,
    recoveryKeyId: recovery.recoveryKeyId,
    authenticator,
    binding,
  } satisfies ReplayCoreFixture;
  const authorities = new Map<string, ActiveWalletAuthorityV1>([
    [String(source.authority.authorityId), source.authority],
    ...(targetInstalled ? [[String(targetAuthority.authorityId), targetAuthority] as const] : []),
  ]);
  const walletAuthorityStore: Pick<D1WalletAuthorityStore, 'readById'> = {
    readById: async (authorityId) => authorities.get(String(authorityId)) ?? null,
  };
  const sourceSnapshot = alphabetizeStringify({
    authority: source.authority,
    method: source.authMethod,
    envelope: sourceEnvelope,
    session: source.issuedSession,
  });
  return {
    ...fixtureCore,
    envelopeStore: new ReplayEnvelopeStore(fixtureCore.targetEnvelope),
    walletCustodyCommits: new ReplayCommitStore(fixtureCore),
    walletAuthorityStore,
    webAuthnStore: new ReplayWebAuthnStore(fixtureCore),
    sourceSnapshot,
  };
}

type ReplayFixture = ReplayCoreFixture & {
  readonly envelopeStore: ReplayEnvelopeStore;
  readonly walletCustodyCommits: ReplayCommitStore;
  readonly walletAuthorityStore: Pick<D1WalletAuthorityStore, 'readById'>;
  readonly webAuthnStore: ReplayWebAuthnStore;
  readonly sourceSnapshot: string;
};

async function replay(fixture: ReplayFixture) {
  return await resolveCommittedRecoveryReplayV1({
    envelopeStore: fixture.envelopeStore,
    walletCustodyCommits: fixture.walletCustodyCommits,
    walletAuthorityStore: fixture.walletAuthorityStore,
    webAuthnStore: fixture.webAuthnStore,
    walletId: WALLET_ID,
    reservationId: RESERVATION_ID,
    recoveryOperationId: RECOVERY_OPERATION_ID,
    targetDeviceId: TARGET_DEVICE_ID,
    targetAuthorityId: TARGET_AUTHORITY_ID,
    targetWalletAuthMethodId: TARGET_METHOD_ID,
    replacementId: String(fixture.targetEnvelope.envelopeId),
    replacementEnvelope: fixture.targetEnvelope,
  });
}

test('an incomplete additive replay remains a conflict and leaves continuity state intact', async () => {
  const fixture = await buildReplayFixture(false);
  const result = await replay(fixture);

  expect(result).toEqual({
    kind: 'conflict',
    reason: 'the recovery commit is incomplete; retry finalization or contact support',
  });
  expect(fixture.sourceAuthority.state).toBe('active');
  expect(fixture.sourceMethod.status).toBe('active');
  expect(fixture.sourceEnvelope.lifecycle.state).toBe('active');
  expect(fixture.sourceSession.session.authorityId).toBe(fixture.sourceAuthority.authorityId);
  expect(fixture.sourceSession.session.walletAuthMethodId).toBe(
    fixture.sourceMethod.walletAuthMethodId,
  );
  expect(
    alphabetizeStringify({
      authority: fixture.sourceAuthority,
      method: fixture.sourceMethod,
      envelope: fixture.sourceEnvelope,
      session: fixture.sourceSession,
    }),
  ).toBe(fixture.sourceSnapshot);
});

test('exact additive replay recognizes the fresh recovery authority and preserves source state', async () => {
  const fixture = await buildReplayFixture(true);
  const result = await replay(fixture);

  expect(result).toEqual({
    kind: 'promoted',
    storeVersion: 'v2',
    credential: {
      credentialIdB64u: String(TARGET_CREDENTIAL_ID),
      credentialPublicKeyB64u: TARGET_PUBLIC_KEY,
      counter: 0,
    },
    walletAuthMethodId: TARGET_METHOD_ID,
    walletAuthorityId: TARGET_AUTHORITY_ID,
  });
  expect(fixture.targetAuthority.authorityId).not.toBe(fixture.sourceAuthority.authorityId);
  expect(fixture.targetAuthority.walletId).toBe(fixture.sourceAuthority.walletId);
  expect(fixture.targetAuthority.principal.deviceId).toBe(TARGET_DEVICE_ID);
  expect(fixture.targetAuthority.provenance).toEqual({
    kind: 'wallet_recovery',
    recoveryOperationId: RECOVERY_OPERATION_ID,
    continuityAuthorityId: fixture.sourceAuthority.authorityId,
  });
  expect(fixture.targetAuthority.permissions).toEqual(buildFullOwnerPermissionsV1());
  expect(alphabetizeStringify(fixture.targetAuthority.signerActivations)).toBe(
    alphabetizeStringify(fixture.sourceAuthority.signerActivations),
  );
  expect(fixture.targetMethod.status).toBe('active');
  expect(fixture.targetMethod.walletAuthorityId).toBe(TARGET_AUTHORITY_ID);
  expect(fixture.targetMethod.walletAuthMethodId).toBe(TARGET_METHOD_ID);
  expect(fixture.targetEnvelope.lifecycle.state).toBe('active');
  expect(fixture.targetEnvelope.ownership).toEqual({
    kind: 'method_bound',
    walletAuthMethodId: TARGET_METHOD_ID,
  });

  expect(await replay(fixture)).toEqual(result);
  expect(
    alphabetizeStringify({
      authority: fixture.sourceAuthority,
      method: fixture.sourceMethod,
      envelope: fixture.sourceEnvelope,
      session: fixture.sourceSession,
    }),
  ).toBe(fixture.sourceSnapshot);
});
