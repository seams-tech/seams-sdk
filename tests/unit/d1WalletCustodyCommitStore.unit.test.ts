import { expect, test } from '@playwright/test';
import {
  buildActiveWalletAuthorityV1,
  computeWalletAuthorityDigestB64u,
} from '@shared/authorization/walletAuthority';
import {
  buildWalletRecoveryEnvelopeSetRecord,
  buildWalletRecoveryManifestKekWrap,
  parseWalletRecoveryEnvelopeSetRecord,
  type WalletRecoveryEnvelopeSetRecord,
} from '@shared/wallet-recovery';
import { parseRecoveryCodeReservationId } from '@shared/wallet-recovery/recoveryCodeReservation';
import { CloudflareD1PasskeyCustodyEnvelopeStore } from '../../packages/wallet-server/src/router/cloudflare/d1/passkeyCustody/d1PasskeyCustodyEnvelopeStore';
import { CloudflareD1WalletCustodyCommitStore } from '../../packages/wallet-server/src/router/cloudflare/d1/passkeyCustody/d1WalletCustodyCommitStore';
import { D1WalletAuthorityStore } from '../../packages/wallet-server/src/router/cloudflare/d1/wallet/d1WalletAuthorityStore';
import { CloudflareD1WebAuthnStore } from '../../packages/wallet-server/src/router/cloudflare/d1/webauthn/d1WebAuthnStore';
import { resolveCommittedRecoveryReplayV1 } from '../../packages/wallet-server/src/router/domains/passkeyCustody/walletRecoveryFinalization';
import type { D1DatabaseLike } from '../../packages/wallet-server/src/storage/tenantRoute';
import type {
  PasskeyEnvelopeId,
  WalletId,
  WalletRecoveryOperationId,
  WebAuthnCredentialIdB64u,
  WebAuthnRpId,
} from '../../packages/shared-ts/src/utils/domainIds';
import { parseWalletRecoveryOperationId } from '../../packages/shared-ts/src/utils/domainIds';
import { cleanupTemporaryD1Database, createTemporaryD1Database } from '../helpers/sqliteD1';
import { webAuthnRecoveryRegistrationChallengeFixture } from './helpers/walletRecovery.fixtures';
import { buildWalletRecoveryBackupAcknowledgementV1 } from '../../packages/shared-ts/src/wallet-recovery/backupAcknowledgement';
import { parseRecoveryCodeLocatorV1 } from '../../packages/shared-ts/src/wallet-recovery/recoveryCodeLocator';
import { applySignerMigrations } from './helpers/cloudflareD1RouterApiAuthService.fixtures';
import {
  CREDENTIAL_ID_B64U,
  ALT_DIGEST_B64U,
  DIGEST_B64U,
  ENVELOPE_ID,
  OTHER_WALLET_ID,
  RP_ID,
  WALLET_ID,
  passkeyCustodyEnvelope,
  rawEmailOtpFactor,
  rawWalletCustodySeedBinding,
  rawWalletRecoveryEnvelopeSet,
  rawWalletRecoveryCodeLocators,
} from './helpers/passkeyCustodyEnvelope.fixtures';
import { buildActiveMethodBoundPasskeyCustodyEnvelopeFixture } from './helpers/passkeyCustodyEnvelope.fixtures';
import {
  buildLinkedDeviceManagementAuthorityFixture,
  fullOwnerPermissionsForManagementFixture,
} from './helpers/linkedDeviceManagement.fixtures';
import {
  testWebAuthnAuthenticatorRecord,
  testWebAuthnCredentialBindingRecord,
} from './helpers/webauthnAuthenticatorListing.fixtures';

/**
 * The registration commit writes a custody envelope and a recovery envelope set
 * together. These own the property that makes that worth a dedicated store: the
 * pair is all-or-nothing, so a wallet is never left working without the
 * recovery codes its owner believes they hold.
 */

const TEST_SCOPE = {
  namespace: 'wallet-custody-commit-test',
  orgId: 'org-a',
  projectId: 'project-a',
  envId: 'env-a',
} as const;

const LOCATOR = {
  walletId: WALLET_ID as WalletId,
  factor: {
    kind: 'passkey',
    rpId: RP_ID as WebAuthnRpId,
    credentialIdB64u: CREDENTIAL_ID_B64U as WebAuthnCredentialIdB64u,
  },
  envelopeId: ENVELOPE_ID as PasskeyEnvelopeId,
} as const;

function recoverySet(overrides: Record<string, unknown> = {}) {
  return parseWalletRecoveryEnvelopeSetRecord(rawWalletRecoveryEnvelopeSet(overrides), {
    expectedWalletId: String(overrides.walletId ?? WALLET_ID) as WalletId,
  });
}

function registrationCommit(input: {
  readonly envelope: ReturnType<typeof passkeyCustodyEnvelope>;
  readonly recoverySet: ReturnType<typeof recoverySet>;
}) {
  return {
    ...input,
    recoveryBackupAcknowledgement: buildWalletRecoveryBackupAcknowledgementV1({
      walletId: String(input.recoverySet.walletId),
      issuedAtMs: input.recoverySet.issuedAtMs,
      acknowledgedAtMs: input.recoverySet.issuedAtMs + 1,
    }),
    recoveryCodeLocators: rawWalletRecoveryCodeLocators().map((locator, index) => ({
      locatorB64u: (String(input.recoverySet.walletId) === String(WALLET_ID)
        ? locator.locatorB64u
        : `${String.fromCharCode(75 + index)}${ALT_DIGEST_B64U.slice(1)}`) as never,
      walletId: input.recoverySet.walletId,
      recoveryKeyId: locator.recoveryKeyId as never,
    })),
  };
}

function consumeFirstRecoveryCode(input: {
  readonly record: WalletRecoveryEnvelopeSetRecord;
  readonly reservationId: ReturnType<typeof parseRecoveryCodeReservationId>;
  readonly consumedAtMs: number;
}): {
  readonly record: WalletRecoveryEnvelopeSetRecord;
  readonly recoveryKeyId: WalletRecoveryEnvelopeSetRecord['manifestKekWraps'][number]['recoveryKeyId'];
} {
  const selected = input.record.manifestKekWraps[0];
  if (!selected || selected.lifecycle.state !== 'active') {
    throw new Error('recovery fixture has no active code');
  }
  const consumed = buildWalletRecoveryManifestKekWrap({
    recoveryKeyId: selected.recoveryKeyId,
    nonceB64u: selected.nonceB64u,
    wrappedManifestKekB64u: selected.wrappedManifestKekB64u,
    aadHashB64u: selected.aadHashB64u,
    lifecycle: {
      state: 'consumed',
      issuedAtMs: selected.lifecycle.issuedAtMs,
      reservationId: input.reservationId,
      consumedAtMs: input.consumedAtMs,
    },
  });
  return {
    record: buildWalletRecoveryEnvelopeSetRecord({
      walletId: input.record.walletId,
      manifestKekWraps: input.record.manifestKekWraps.map((wrap, index) =>
        index === 0 ? consumed : wrap,
      ),
      entries: input.record.entries,
      issuedAtMs: input.record.issuedAtMs,
      updatedAtMs: input.consumedAtMs,
    }),
    recoveryKeyId: selected.recoveryKeyId,
  };
}

async function withStores(
  run: (stores: {
    commit: CloudflareD1WalletCustodyCommitStore;
    envelopes: CloudflareD1PasskeyCustodyEnvelopeStore;
    database: D1DatabaseLike;
  }) => Promise<void>,
): Promise<void> {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    await run({
      commit: new CloudflareD1WalletCustodyCommitStore({ database, scope: TEST_SCOPE }),
      envelopes: new CloudflareD1PasskeyCustodyEnvelopeStore({ database, scope: TEST_SCOPE }),
      database,
    });
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
}

test('a registration commit stores the envelope and the recovery set together', async () => {
  await withStores(async ({ commit, envelopes }) => {
    const result = await commit.commitRegistration(
      registrationCommit({
        envelope: passkeyCustodyEnvelope(),
        recoverySet: recoverySet(),
      }),
    );
    expect(result.kind).toBe('committed');

    // The envelope is addressed by the same key the retrieval store uses, so a
    // committed envelope is one an authenticated lookup can actually find.
    const lookup = await envelopes.lookupEnvelope(LOCATOR);
    expect(lookup.kind).toBe('active');

    const stored = await commit.readRecoveryEnvelopeSet(WALLET_ID as WalletId);
    expect(stored?.record.manifestKekWraps.length).toBe(10);
    expect(stored?.record.entries[0]?.custodySecretKind).toBe('wallet_custody_seed_v1');

    const locator = parseRecoveryCodeLocatorV1(rawWalletRecoveryCodeLocators()[0]?.locatorB64u);
    await expect(commit.readRecoveryCodeLocator(locator)).resolves.toMatchObject({
      locatorB64u: locator,
      walletId: WALLET_ID,
    });
    await expect(
      commit.readRecoveryCodeLocator(parseRecoveryCodeLocatorV1(ALT_DIGEST_B64U)),
    ).resolves.toBeNull();
  });
});

test('a wallet that already has custody is never overwritten', async () => {
  await withStores(async ({ commit }) => {
    expect(
      (
        await commit.commitRegistration(
          registrationCommit({
            envelope: passkeyCustodyEnvelope(),
            recoverySet: recoverySet(),
          }),
        )
      ).kind,
    ).toBe('committed');

    // A second ceremony for the same wallet would strand every key the first
    // seed controls, so both keys refuse to be replaced.
    const again = await commit.commitRegistration(
      registrationCommit({
        envelope: passkeyCustodyEnvelope(),
        recoverySet: recoverySet(),
      }),
    );
    expect(again.kind).toBe('already_exists');
  });
});

test('a commit whose recovery set already exists writes no envelope', async () => {
  await withStores(async ({ commit, envelopes }) => {
    // First wallet registers with a passkey factor.
    await commit.commitRegistration(
      registrationCommit({
        envelope: passkeyCustodyEnvelope(),
        recoverySet: recoverySet(),
      }),
    );

    // A second ceremony for the same wallet under a *different* factor: its
    // envelope key is free, but the wallet-scoped recovery-set key is taken.
    const otherFactorEnvelope = passkeyCustodyEnvelope({
      envelopeId: 'passkey-envelope-2',
      factor: rawEmailOtpFactor(),
    });
    const conflicted = await commit.commitRegistration(
      registrationCommit({
        envelope: otherFactorEnvelope,
        recoverySet: recoverySet(),
      }),
    );
    expect(conflicted.kind).toBe('custody_already_established');

    // The batch rolled back: no envelope was written for the second factor.
    const orphan = await envelopes.lookupEnvelope({
      walletId: WALLET_ID as WalletId,
      factor: {
        kind: 'email_otp',
        enrollmentId: 'enrollment-1',
        enrollmentSealKeyVersion: 'seal-v1',
      },
      envelopeId: 'passkey-envelope-2' as PasskeyEnvelopeId,
    });
    expect(orphan.kind).toBe('missing');
  });
});

test('a mismatched pair is refused before anything is written', async () => {
  await withStores(async ({ commit, envelopes }) => {
    const otherWalletSet = await commit.commitRegistration(
      registrationCommit({
        envelope: passkeyCustodyEnvelope(),
        recoverySet: recoverySet({ walletId: OTHER_WALLET_ID }),
      }),
    );
    expect(otherWalletSet.kind).toBe('inconsistent');

    expect((await envelopes.lookupEnvelope(LOCATOR)).kind).toBe('missing');
    expect(await commit.readRecoveryEnvelopeSet(WALLET_ID as WalletId)).toBeNull();
  });
});

test('a recovery set is readable only under the wallet it names', async () => {
  await withStores(async ({ commit }) => {
    await commit.commitRegistration(
      registrationCommit({
        envelope: passkeyCustodyEnvelope(),
        recoverySet: recoverySet(),
      }),
    );
    expect(await commit.readRecoveryEnvelopeSet(WALLET_ID as WalletId)).not.toBeNull();
    expect(await commit.readRecoveryEnvelopeSet(OTHER_WALLET_ID as WalletId)).toBeNull();
  });
});

test('locator lookup is isolated to its tenant scope', async () => {
  await withStores(async ({ commit, database }) => {
    const initial = registrationCommit({
      envelope: passkeyCustodyEnvelope(),
      recoverySet: recoverySet(),
    });
    await commit.commitRegistration(initial);

    const otherTenant = new CloudflareD1WalletCustodyCommitStore({
      database,
      scope: { ...TEST_SCOPE, orgId: 'org-b' },
    });
    const locator = parseRecoveryCodeLocatorV1(rawWalletRecoveryCodeLocators()[0]?.locatorB64u);
    await expect(otherTenant.readRecoveryCodeLocator(locator)).resolves.toBeNull();
  });
});

test('a backup acknowledgement round-trips through the custody record store', async () => {
  await withStores(async ({ commit }) => {
    const acknowledgement = buildWalletRecoveryBackupAcknowledgementV1({
      walletId: WALLET_ID,
      issuedAtMs: 1_000,
      acknowledgedAtMs: 2_000,
    });

    expect(await commit.writeBackupAcknowledgement(acknowledgement)).toEqual({ kind: 'stored' });
    expect(await commit.readBackupAcknowledgement(WALLET_ID as WalletId)).toEqual(acknowledgement);
  });
});

test('two wallets keep separate custody', async () => {
  await withStores(async ({ commit }) => {
    await commit.commitRegistration(
      registrationCommit({
        envelope: passkeyCustodyEnvelope(),
        recoverySet: recoverySet(),
      }),
    );
    const second = await commit.commitRegistration(
      registrationCommit({
        envelope: passkeyCustodyEnvelope({ walletId: OTHER_WALLET_ID }),
        recoverySet: recoverySet({ walletId: OTHER_WALLET_ID }),
      }),
    );
    expect(second.kind).toBe('committed');

    const first = await commit.readRecoveryEnvelopeSet(WALLET_ID as WalletId);
    const other = await commit.readRecoveryEnvelopeSet(OTHER_WALLET_ID as WalletId);
    expect(String(first?.record.walletId)).toBe(WALLET_ID);
    expect(String(other?.record.walletId)).toBe(OTHER_WALLET_ID);
  });
});

test('a locator collision rejects the second registration atomically', async () => {
  await withStores(async ({ commit }) => {
    const first = await commit.commitRegistration(
      registrationCommit({
        envelope: passkeyCustodyEnvelope(),
        recoverySet: recoverySet(),
      }),
    );
    expect(first.kind).toBe('committed');

    const other = registrationCommit({
      envelope: passkeyCustodyEnvelope({ walletId: OTHER_WALLET_ID }),
      recoverySet: recoverySet({ walletId: OTHER_WALLET_ID }),
    });
    const colliding = {
      ...other,
      recoveryCodeLocators: other.recoveryCodeLocators.map((locator, index) => ({
        ...locator,
        locatorB64u: rawWalletRecoveryCodeLocators()[index]?.locatorB64u as never,
      })),
    };

    await expect(commit.commitRegistration(colliding)).resolves.toEqual({
      kind: 'inconsistent',
      reason: 'recovery code locator already exists',
    });
    expect(await commit.readRecoveryEnvelopeSet(OTHER_WALLET_ID as WalletId)).toBeNull();
  });
});

test('a rotation rejects reusing an existing locator before replacing the set', async () => {
  await withStores(async ({ commit }) => {
    const initial = registrationCommit({
      envelope: passkeyCustodyEnvelope(),
      recoverySet: recoverySet(),
    });
    expect((await commit.commitRegistration(initial)).kind).toBe('committed');

    const replacement = recoverySet({ issuedAtMs: 3_000, updatedAtMs: 3_000 });
    await expect(
      commit.replaceRecoveryEnvelopeSetAndPreserveBackupAcknowledgement({
        record: replacement,
        expectedRecoverySetVersion: '1',
        recoveryCodeLocators: initial.recoveryCodeLocators,
      }),
    ).resolves.toEqual({ kind: 'collision' });

    const stored = await commit.readRecoveryEnvelopeSet(WALLET_ID as WalletId);
    expect(stored?.record.issuedAtMs).toBe(1_000);
  });
});

test('a real recovery commit retains the consumed locator tombstone for exact replay', async () => {
  await withStores(async ({ commit, envelopes, database }) => {
    const source = await buildLinkedDeviceManagementAuthorityFixture({
      label: 'recovery-real-source',
      permissions: fullOwnerPermissionsForManagementFixture(),
      provenance: 'wallet_registration',
      identity: {
        walletId: WALLET_ID,
        authorityId: 'wallet-authority:recovery-real-source',
        walletAuthMethodId: 'wallet-auth-method:recovery-real-source',
        rpId: RP_ID,
      },
    });
    const target = await buildLinkedDeviceManagementAuthorityFixture({
      label: 'recovery-real-target',
      permissions: fullOwnerPermissionsForManagementFixture(),
      provenance: 'wallet_recovery',
      sourceAuthorityId: source.authority.authorityId,
      identity: {
        walletId: WALLET_ID,
        authorityId: 'wallet-authority:recovery-real-target',
        walletAuthMethodId: 'wallet-auth-method:recovery-real-target',
        rpId: RP_ID,
      },
    });
    const targetAuthorityDraft = buildActiveWalletAuthorityV1({
      ...source.authority,
      authorityId: target.authority.authorityId,
      principal: target.authority.principal,
      provenance: target.authority.provenance,
      createdAtMs: 500,
      updatedAtMs: 500,
      activatedAtMs: 500,
      authorityDigestB64u: source.authority.authorityDigestB64u,
    });
    const targetAuthority = buildActiveWalletAuthorityV1({
      ...targetAuthorityDraft,
      authorityDigestB64u: await computeWalletAuthorityDigestB64u(targetAuthorityDraft),
    });
    const sourceEnvelope = buildActiveMethodBoundPasskeyCustodyEnvelopeFixture({
      walletId: WALLET_ID,
      envelopeId: 'passkey-envelope:recovery-real-source',
      rpId: String(source.authMethod.rpId),
      credentialIdB64u: String(source.authMethod.credentialIdB64u),
      walletAuthMethodId: String(source.authMethod.walletAuthMethodId),
    });
    const targetEnvelope = buildActiveMethodBoundPasskeyCustodyEnvelopeFixture({
      walletId: WALLET_ID,
      envelopeId: 'passkey-envelope:recovery-real-target',
      rpId: String(target.authMethod.rpId),
      credentialIdB64u: String(target.authMethod.credentialIdB64u),
      walletAuthMethodId: String(target.authMethod.walletAuthMethodId),
    });
    const targetCredentialIdB64u = String(target.authMethod.credentialIdB64u);
    const targetRpId = String(target.authMethod.rpId);
    const authenticator = testWebAuthnAuthenticatorRecord({
      credentialIdB64u: targetCredentialIdB64u,
      credentialPublicKeyB64u: target.authMethod.credentialPublicKeyB64u,
      counter: target.authMethod.counter,
      createdAtMs: 500,
      updatedAtMs: 500,
    });
    const binding = testWebAuthnCredentialBindingRecord({
      credentialIdB64u: targetCredentialIdB64u,
      userId: WALLET_ID,
      rpId: targetRpId,
      createdAtMs: 500,
      updatedAtMs: 500,
    });
    const reservationId = parseRecoveryCodeReservationId('recovery-operation:real-replay');
    const parsedRecoveryOperationId = parseWalletRecoveryOperationId(
      'wallet-recovery-operation:recovery-real-target',
    );
    if (!parsedRecoveryOperationId.ok) throw new Error(parsedRecoveryOperationId.error.message);
    const recoveryOperationId: WalletRecoveryOperationId = parsedRecoveryOperationId.value;
    const initialRecoverySet = recoverySet();
    const committedRecovery = consumeFirstRecoveryCode({
      record: initialRecoverySet,
      reservationId,
      consumedAtMs: 3_000,
    });
    const registration = await commit.commitRegistration(
      registrationCommit({ envelope: passkeyCustodyEnvelope(), recoverySet: initialRecoverySet }),
    );
    expect(registration.kind).toBe('committed');
    const storedRecoverySet = await commit.readRecoveryEnvelopeSet(WALLET_ID as WalletId);
    if (!storedRecoverySet) throw new Error('recovery fixture was not stored');

    const webAuthn = new CloudflareD1WebAuthnStore({
      database,
      namespace: TEST_SCOPE.namespace,
      orgId: TEST_SCOPE.orgId,
      projectId: TEST_SCOPE.projectId,
      envId: TEST_SCOPE.envId,
    });
    const challengeId = 'recovery-registration-real-replay';
    const sourceFactor = sourceEnvelope.factor;
    if (sourceFactor.kind !== 'passkey') throw new Error('source fixture is not passkey-bound');
    const challenge = webAuthnRecoveryRegistrationChallengeFixture({
      challengeId,
      walletId: WALLET_ID as WalletId,
      reservationId,
      recoveryOperationId,
      targetDeviceId: targetAuthority.principal.deviceId,
      targetAuthorityId: targetAuthority.authorityId,
      targetWalletAuthMethodId: target.authMethod.walletAuthMethodId,
      rpId: target.authMethod.rpId,
      replacementId: String(targetEnvelope.envelopeId),
      continuityAnchor: {
        kind: 'wallet_recovery_continuity_anchor_v1',
        authority: source.authority,
        method: source.authMethod,
        envelope: {
          kind: 'passkey',
          envelopeId: sourceEnvelope.envelopeId,
          walletId: WALLET_ID as WalletId,
          rpId: sourceFactor.rpId,
          credentialIdB64u: sourceFactor.credentialIdB64u,
          envelopeRevision: sourceEnvelope.envelopeRevision,
          updatedAtMs: sourceEnvelope.updatedAtMs,
          bindingKind: 'wallet_custody_seed_v1',
        },
      },
    });
    await webAuthn.writeChallenge({
      challengeId,
      challengeKind: 'recovery_registration',
      record: challenge,
      createdAtMs: challenge.createdAtMs,
      expiresAtMs: challenge.expiresAtMs,
    });
    const commitResult = await commit.commitRecoveryAuthorityInstall({
      continuityAuthority: source.authority,
      authority: targetAuthority,
      recoverySet: committedRecovery.record,
      expectedRecoverySetVersion: storedRecoverySet.storeVersion,
      replacementEnvelope: targetEnvelope,
      reservationId,
      recoveryKeyId: committedRecovery.recoveryKeyId,
      authenticatorCommit: {
        userId: WALLET_ID,
        authenticator,
        binding,
        walletAuthMethod: target.authMethod,
        challengeDeleteStatement: webAuthn.prepareRecoveryRegistrationChallengeDeleteStatement({
          challengeId,
          record: challenge,
          nowMs: 3_000,
        }),
      },
    });
    expect(commitResult.kind).toBe('committed');
    await expect(
      commit.readRecoveryCodeLocatorByRecoveryKey({
        walletId: WALLET_ID as WalletId,
        recoveryKeyId: committedRecovery.recoveryKeyId,
      }),
    ).resolves.toMatchObject({
      walletId: WALLET_ID,
      recoveryKeyId: committedRecovery.recoveryKeyId,
    });
    await expect(
      webAuthn.readRecoveryRegistrationChallenge(challengeId, 3_000),
    ).resolves.toBeNull();

    const authorityStore = new D1WalletAuthorityStore({ database, scope: TEST_SCOPE });
    const replay = await resolveCommittedRecoveryReplayV1({
      envelopeStore: envelopes,
      walletCustodyCommits: commit,
      walletAuthorityStore: {
        readById: async (authorityId) =>
          authorityId === source.authority.authorityId
            ? source.authority
            : authorityStore.readById(authorityId),
      },
      webAuthnStore: webAuthn,
      walletId: WALLET_ID,
      reservationId,
      recoveryOperationId,
      targetDeviceId: targetAuthority.principal.deviceId,
      targetAuthorityId: targetAuthority.authorityId,
      targetWalletAuthMethodId: target.authMethod.walletAuthMethodId,
      replacementId: String(targetEnvelope.envelopeId),
      replacementEnvelope: targetEnvelope,
    });
    expect(replay).toMatchObject({
      kind: 'promoted',
      credential: {
        credentialIdB64u: targetCredentialIdB64u,
        credentialPublicKeyB64u: target.authMethod.credentialPublicKeyB64u,
        counter: target.authMethod.counter,
      },
      walletAuthMethodId: target.authMethod.walletAuthMethodId,
      walletAuthorityId: targetAuthority.authorityId,
    });
  });
});
