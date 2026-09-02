import { expect, test } from '@playwright/test';
import { sdkEsmPath, setupBasicPasskeyTest } from '../setup';
import {
  buildPendingWalletRecoveryCommitV1,
  parsePendingWalletRecoveryCommitAppStateRow,
  parsePendingWalletRecoveryCommitV1,
  toPendingWalletRecoveryCommitAppStateRow,
} from '../../packages/wallet/src/core/indexedDB/pendingWalletRecoveryCommit';
import {
  buildWalletRecoveryCommittedProjectionV1,
  type WalletRecoveryCommittedProjectionV1,
} from '../../packages/shared-ts/src/wallet-recovery/walletRecoveryCommittedProjection';
import { buildFullOwnerDelegatedWalletAuthorityV1 } from '../../packages/shared-ts/src/authorization/delegatedAuthority';
import { buildWalletAuthMethodRecordV2 } from '../../packages/shared-ts/src/utils/registrationIntent';
import { parseEmailOtpProviderUserId } from '../../packages/shared-ts/src/utils/domainIds';
import { sha256HexUtf8 } from '../../packages/shared-ts/src/utils/digests';
import { base64UrlDecode, base64UrlEncode } from '../../packages/shared-ts/src/utils/base64';
import {
  buildPasskeyWalletAuthAuthority,
  buildEmailOtpWalletAuthAuthority,
  type EmailOtpWalletAuthAuthority,
  walletAuthAuthorityRef,
} from '../../packages/shared-ts/src/utils/walletAuthAuthority';
import { deriveEvmFamilySigningKeySlotId } from '../../packages/shared-ts/src/signing-lanes';
import { ecdsaCapabilityActivationFixture } from './helpers/ecdsaCapabilityManifest.fixtures';
import { buildLinkedDeviceManagementAuthorityFixture } from './helpers/linkedDeviceManagement.fixtures';
import {
  buildActiveMethodBoundEmailOtpCustodyEnvelopeFixture,
  buildActiveMethodBoundPasskeyCustodyEnvelopeFixture,
} from './helpers/passkeyCustodyEnvelope.fixtures';
import type { StoreWalletRegistrationPublicationInputV1 } from '../../packages/wallet/src/core/indexedDB/seamsWalletDB/repositories';

const IMPORT_PATHS = {
  indexedDB: sdkEsmPath('core/indexedDB/index.js'),
  pending: sdkEsmPath('core/indexedDB/pendingWalletRecoveryCommit.js'),
  ecdsa: sdkEsmPath('core/indexedDB/seamsWalletDB/ecdsaCapabilityManifestStore.js'),
  journal: sdkEsmPath('SeamsWeb/operations/recovery/walletRecoveryJournal.js'),
  durable: sdkEsmPath('SeamsWeb/operations/recovery/walletRecoveryDurablePayload.js'),
  finalize: sdkEsmPath('core/rpcClients/relayer/walletRecoveryFinalize.js'),
  commit: sdkEsmPath('SeamsWeb/operations/recovery/walletRecoveryCommit.js'),
  seamsWeb: sdkEsmPath('SeamsWeb/index.js'),
} as const;

function required<T>(result: { readonly ok: true; readonly value: T } | { readonly ok: false }): T {
  if (!result.ok) throw new Error('invalid recovery fixture identity');
  return result.value;
}

async function encryptedMaterial(fill: number) {
  const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, [
    'encrypt',
    'decrypt',
  ]);
  if (!(key instanceof CryptoKey)) throw new Error('recovery fixture key was not generated');
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new Uint8Array([fill])),
  );
  return {
    kind: 'wallet_recovery_encrypted_material_v1' as const,
    key,
    iv,
    ciphertext,
  };
}

async function passkeyProjectionFixture(
  input: {
    readonly label?: string;
    readonly walletId?: string;
    readonly authorityId?: string;
    readonly walletAuthMethodId?: string;
    readonly rpId?: string;
    readonly credentialIdB64u?: string;
  } = {},
): Promise<{
  readonly authority: Awaited<
    ReturnType<typeof buildLinkedDeviceManagementAuthorityFixture>
  >['authority'];
  readonly projection: Extract<WalletRecoveryCommittedProjectionV1, { readonly kind: 'passkey' }>;
}> {
  const fixture = await buildLinkedDeviceManagementAuthorityFixture({
    label: input.label ?? 'pending-recovery-passkey',
    permissions: buildFullOwnerDelegatedWalletAuthorityV1().permissions,
    provenance: 'wallet_recovery',
    identity: {
      walletId: input.walletId ?? 'wallet:pending-recovery-passkey',
      authorityId: input.authorityId ?? 'authority:pending-recovery-passkey',
      walletAuthMethodId: input.walletAuthMethodId ?? 'auth-method:pending-recovery-passkey',
      rpId: input.rpId ?? 'wallet.pending-recovery.example',
      credentialIdB64u: input.credentialIdB64u ?? 'Y3JlZGVudGlhbC1wZW5kaW5nLXJlY292ZXJ5',
    },
  });
  if (fixture.authority.provenance.kind !== 'wallet_recovery') {
    throw new Error('Passkey recovery fixture lost recovery provenance');
  }
  const projection = buildWalletRecoveryCommittedProjectionV1({
    kind: 'passkey',
    storeVersion: 'store-pending-recovery-passkey',
    walletId: fixture.authority.walletId,
    recoveryOperationId: fixture.authority.provenance.recoveryOperationId,
    targetDeviceId: fixture.authority.principal.deviceId,
    targetAuthorityId: fixture.authority.authorityId,
    targetWalletAuthMethodId: fixture.authMethod.walletAuthMethodId,
    authority: fixture.authority,
    authMethod: fixture.authMethod,
  });
  return { authority: fixture.authority, projection };
}

async function startupRecoveryPayloadParts(input: {
  readonly projection: WalletRecoveryCommittedProjectionV1;
  readonly authorityRef: Awaited<ReturnType<typeof walletAuthAuthorityRef>>;
  readonly reservationId: string;
  readonly replacementId: string;
  readonly replacementEnvelope: ReturnType<
    typeof buildActiveMethodBoundPasskeyCustodyEnvelopeFixture
  >;
}) {
  const { projection, authorityRef, reservationId, replacementId, replacementEnvelope } = input;
  const ecdsa = ecdsaCapabilityActivationFixture({
    walletId: String(projection.walletId),
    authority: authorityRef,
  });
  const signer = ecdsa.prepareInput.activationBinding.signer;
  const facts = ecdsa.sealInput.roleLocalPublicFacts;
  const publicCapability = facts.publicCapability;
  const keyHandle = String(facts.keyHandle);
  const keySetId = `evm_family_ecdsa:${keyHandle}` as const;
  const recordedKeyManifestDigestB64u = base64UrlEncode(new Uint8Array(32).fill(9));
  const possessionChallenge = {
    kind: 'wallet_recovery_ecdsa_possession_challenge_v1' as const,
    walletId: String(projection.walletId),
    reservationId,
    replacementId,
    keySetId,
    keyHandle,
    recordedKeyManifestDigestB64u,
    publicCapabilityDigestB64u: recordedKeyManifestDigestB64u,
    authorityRefDigestB64u: String(authorityRef.authorityDigest),
    derivationClientSharePublicKey33B64u:
      publicCapability.public_identity.derivation_client_share_public_key33_b64u,
    expectedServerGeneration: String(ecdsa.serverGeneration),
    expiresAtMs: 1_900_000_000_000,
    serverNonceB64u: recordedKeyManifestDigestB64u,
  };
  const ecdsaEntry = {
    kind: 'evm_family_ecdsa' as const,
    keySetId,
    keyHandle,
    evmFamilySigningKeySlotId: deriveEvmFamilySigningKeySlotId({
      walletId: String(projection.walletId),
      signingRootId: String(signer.signingRootId),
      signingRootVersion: String(signer.signingRootVersion),
    }),
    recordedKeyManifestDigestB64u,
    recoveryBasis: {
      publicCapability,
      activationReceipt: ecdsa.serverCommit.protocolReceipt,
      serverGeneration: String(ecdsa.serverGeneration),
      clientRootPublicKey33B64u: String(ecdsa.sealInput.registeredPublicFacts.publicKeyB64u),
      chainTargets: signer.scope.targetMemberships,
      ecdsaThresholdKeyId: String(facts.ecdsaThresholdKeyId),
      signingRootId: String(signer.signingRootId),
      signingRootVersion: String(signer.signingRootVersion),
      runtimePolicyScope: ecdsa.sealInput.runtimePolicyScope,
      participantIds: [1, 2] as const,
      possessionChallenge,
    },
  };
  const publicFacts = {
    contextBinding32B64u: facts.contextBinding32B64u,
    derivationClientSharePublicKey33B64u: facts.derivationClientSharePublicKey33B64u,
    clientVerifyingShare33B64u:
      publicCapability.public_identity.derivation_client_share_public_key33_b64u,
    relayerPublicKey33B64u: facts.relayerPublicKey33B64u,
    groupPublicKey33B64u: facts.groupPublicKey33B64u,
    ethereumAddress: facts.ethereumAddress,
    clientShareRetryCounter: publicCapability.public_identity.client_share_retry_counter,
    relayerShareRetryCounter: publicCapability.public_identity.server_share_retry_counter,
  };
  return {
    recoveryOperationId: String(projection.recoveryOperationId),
    walletId: projection.walletId,
    reservationId,
    targetDeviceId: projection.targetDeviceId,
    targetAuthorityId: projection.targetAuthorityId,
    targetWalletAuthMethodId: projection.targetWalletAuthMethodId,
    replacementEnvelope,
    keyManifest: {
      version: 'wallet_recovery_preparation_key_manifest_v1' as const,
      walletId: String(projection.walletId),
      entries: [ecdsaEntry],
    },
    nearKeySets: [],
    ecdsaKeySets: [
      {
        kind: 'evm_family_ecdsa' as const,
        keySetId,
        possessionProof: {
          kind: 'wallet_recovery_ecdsa_possession_proof_v1' as const,
          scheme: 'secp256k1_bip340_sha256_v1' as const,
          signature64B64u: base64UrlEncode(new Uint8Array(64).fill(7)),
        },
        readyStateBlobB64u: ecdsa.sealInput.readyStateBlobB64u,
        publicFacts,
      },
    ],
  };
}

async function startupRecoveryPayloadFixture(
  projection: Extract<WalletRecoveryCommittedProjectionV1, { readonly kind: 'passkey' }>,
) {
  const recoveryAuthority = buildPasskeyWalletAuthAuthority({
    walletId: String(projection.walletId),
    rpId: String(projection.target.rpId),
    credentialIdB64u: String(projection.target.credentialIdB64u),
  });
  const authorityRef = await walletAuthAuthorityRef({ authority: recoveryAuthority });
  const replacementId = 'passkey-envelope:pending-recovery-startup';
  const replacementEnvelope = buildActiveMethodBoundPasskeyCustodyEnvelopeFixture({
    walletId: String(projection.walletId),
    envelopeId: replacementId,
    rpId: String(projection.target.rpId),
    credentialIdB64u: String(projection.target.credentialIdB64u),
    walletAuthMethodId: String(projection.targetWalletAuthMethodId),
  });
  const parts = await startupRecoveryPayloadParts({
    projection,
    authorityRef,
    reservationId: 'reservation:pending-recovery-startup',
    replacementId,
    replacementEnvelope,
  });
  return {
    kind: 'wallet_recovery_durable_payload_v1' as const,
    version: 1 as const,
    recoveryOperationId: parts.recoveryOperationId,
    walletId: parts.walletId,
    reservationId: parts.reservationId,
    targetDeviceId: parts.targetDeviceId,
    targetAuthorityId: parts.targetAuthorityId,
    targetWalletAuthMethodId: parts.targetWalletAuthMethodId,
    replacementEnvelope: parts.replacementEnvelope,
    keyManifest: parts.keyManifest,
    nearKeySets: [],
    ecdsaKeySets: parts.ecdsaKeySets,
    target: { kind: 'passkey' as const, rpId: projection.target.rpId },
    replacementId: parts.replacementId,
    challengeId: 'challenge:pending-recovery-startup',
    registration: {
      kind: 'wallet_recovery_redacted_registration_v1' as const,
      id: String(projection.target.credentialIdB64u),
      rawId: String(projection.target.credentialIdB64u),
      type: 'public-key',
      authenticatorAttachment: null,
      response: {
        clientDataJSON: 'Y2xpZW50LWRhdGE',
        attestationObject: 'YXR0ZXN0YXR0aW9u',
        transports: [],
      },
    },
  };
}

async function startupGoogleRecoveryPayloadFixture(
  projection: Extract<WalletRecoveryCommittedProjectionV1, { readonly kind: 'google_email_otp' }>,
  authAuthority: EmailOtpWalletAuthAuthority,
  verifiedEmail: string,
) {
  const authorityRef = await walletAuthAuthorityRef({ authority: authAuthority });
  const replacementId = 'email-otp-envelope:pending-recovery-google-startup';
  const replacementEnvelope = buildActiveMethodBoundEmailOtpCustodyEnvelopeFixture({
    walletId: String(projection.walletId),
    envelopeId: replacementId,
    enrollmentId: projection.target.enrollment.enrollmentId,
    enrollmentSealKeyVersion: projection.target.enrollment.enrollmentSealKeyVersion,
    walletAuthMethodId: String(projection.targetWalletAuthMethodId),
  });
  const parts = await startupRecoveryPayloadParts({
    projection,
    authorityRef,
    reservationId: 'reservation:pending-recovery-google-startup',
    replacementId,
    replacementEnvelope,
  });
  return {
    kind: 'wallet_recovery_durable_payload_v1' as const,
    version: 1 as const,
    recoveryOperationId: parts.recoveryOperationId,
    walletId: parts.walletId,
    reservationId: parts.reservationId,
    targetDeviceId: parts.targetDeviceId,
    targetAuthorityId: parts.targetAuthorityId,
    targetWalletAuthMethodId: parts.targetWalletAuthMethodId,
    replacementEnvelope: parts.replacementEnvelope,
    keyManifest: parts.keyManifest,
    nearKeySets: [],
    ecdsaKeySets: parts.ecdsaKeySets,
    target: { kind: 'google_email_otp' as const },
    providerSubject: projection.target.providerSubject,
    verifiedEmail,
    emailHashHex: projection.target.emailHashHex,
    registrationAuthorityId: projection.target.registrationAuthorityId,
    replacementId: parts.replacementId,
    enrollment: {
      kind: 'existing' as const,
      enrollmentId: projection.target.enrollment.enrollmentId,
      enrollmentSealKeyVersion: projection.target.enrollment.enrollmentSealKeyVersion,
    },
  };
}

async function emailProjectionFixture(): Promise<{
  readonly authority: Awaited<
    ReturnType<typeof buildLinkedDeviceManagementAuthorityFixture>
  >['authority'];
  readonly authAuthority: EmailOtpWalletAuthAuthority;
  readonly projection: Extract<
    WalletRecoveryCommittedProjectionV1,
    { readonly kind: 'google_email_otp' }
  >;
  readonly verifiedEmail: string;
}> {
  const fixture = await buildLinkedDeviceManagementAuthorityFixture({
    label: 'pending-recovery-email',
    permissions: buildFullOwnerDelegatedWalletAuthorityV1().permissions,
    provenance: 'wallet_recovery',
    identity: {
      walletId: 'wallet:pending-recovery-email',
      authorityId: 'authority:pending-recovery-email',
      walletAuthMethodId: 'auth-method:pending-recovery-email',
      rpId: 'wallet.pending-recovery.example',
    },
  });
  if (fixture.authority.provenance.kind !== 'wallet_recovery') {
    throw new Error('Email OTP recovery fixture lost recovery provenance');
  }
  const verifiedEmail = 'pending-recovery-email@example.test';
  const emailHashHex = await sha256HexUtf8(verifiedEmail);
  const providerSubject = required(parseEmailOtpProviderUserId('google:pending-recovery-email'));
  const authAuthority = buildEmailOtpWalletAuthAuthority({
    walletId: fixture.authority.walletId,
    provider: 'google',
    providerUserId: providerSubject,
    emailHashHex,
  });
  const authMethod = buildWalletAuthMethodRecordV2({
    version: 'wallet_auth_method_v2',
    walletAuthMethodId: authAuthority.bindingId,
    walletId: fixture.authority.walletId,
    walletAuthorityId: fixture.authority.authorityId,
    kind: 'email_otp',
    status: 'active',
    emailHashHex,
    registrationAuthorityId: 'challenge:pending-recovery-email',
    createdAtMs: fixture.authMethod.createdAtMs,
    updatedAtMs: fixture.authMethod.updatedAtMs,
    activatedAtMs: fixture.authMethod.activatedAtMs,
  });
  const projection = buildWalletRecoveryCommittedProjectionV1({
    kind: 'google_email_otp',
    storeVersion: 'store-pending-recovery-email',
    walletId: fixture.authority.walletId,
    recoveryOperationId: fixture.authority.provenance.recoveryOperationId,
    targetDeviceId: fixture.authority.principal.deviceId,
    targetAuthorityId: fixture.authority.authorityId,
    targetWalletAuthMethodId: authMethod.walletAuthMethodId,
    authority: fixture.authority,
    authMethod,
    providerSubject,
    emailHashHex: authMethod.emailHashHex,
    registrationAuthorityId: authMethod.registrationAuthorityId,
    enrollment: {
      kind: 'email_otp_enrollment_reference_v1',
      enrollmentId: 'enrollment:pending-recovery-email',
      enrollmentSealKeyVersion: 'email-otp-seal-v1',
    },
  });
  return { authority: fixture.authority, authAuthority, projection, verifiedEmail };
}

async function buildPendingRecord(projection: WalletRecoveryCommittedProjectionV1, fill: number) {
  const localMaterial = await encryptedMaterial(fill);
  if (projection.kind === 'passkey') {
    return await buildPendingWalletRecoveryCommitV1({
      kind: 'pending_wallet_recovery_commit_v1',
      version: 1,
      stage: 'server_promoted',
      recoveryOperationId: projection.recoveryOperationId,
      walletId: projection.walletId,
      reservationId: `reservation:pending-recovery-${fill}`,
      targetDeviceId: projection.targetDeviceId,
      targetAuthorityId: projection.targetAuthorityId,
      targetWalletAuthMethodId: projection.targetWalletAuthMethodId,
      target: {
        kind: 'passkey',
        rpId: projection.target.rpId,
        credentialIdB64u: projection.target.credentialIdB64u,
      },
      localMaterial,
      createdAtMs: 1,
      updatedAtMs: 2,
      projection,
    });
  }
  return await buildPendingWalletRecoveryCommitV1({
    kind: 'pending_wallet_recovery_commit_v1',
    version: 1,
    stage: 'server_promoted',
    recoveryOperationId: projection.recoveryOperationId,
    walletId: projection.walletId,
    reservationId: `reservation:pending-recovery-${fill}`,
    targetDeviceId: projection.targetDeviceId,
    targetAuthorityId: projection.targetAuthorityId,
    targetWalletAuthMethodId: projection.targetWalletAuthMethodId,
    target: {
      kind: 'google_email_otp',
      providerSubject: projection.target.providerSubject,
      emailHashHex: projection.target.emailHashHex,
      registrationAuthorityId: projection.target.registrationAuthorityId,
      enrollment: projection.target.enrollment,
    },
    localMaterial,
    createdAtMs: 1,
    updatedAtMs: 2,
    projection,
  });
}

function passkeyRecoveryRegistrationFixture(
  projection: Extract<WalletRecoveryCommittedProjectionV1, { readonly kind: 'passkey' }>,
  credentialPublicKey: Uint8Array,
): StoreWalletRegistrationPublicationInputV1 {
  return {
    profiles: [
      {
        profileId: projection.walletId,
        defaultSignerSlot: 1,
        passkeyCredential: {
          id: projection.target.credentialIdB64u,
          rawId: projection.target.credentialIdB64u,
        },
      },
    ],
    initialAuthMethod: {
      version: 'wallet_auth_method_v1',
      kind: 'passkey',
      status: 'active',
      localStatus: 'synced',
      walletId: projection.walletId,
      rpId: projection.target.rpId,
      credentialIdB64u: projection.target.credentialIdB64u,
      credentialPublicKeyB64u: projection.authMethod.credentialPublicKeyB64u,
      counter: projection.authMethod.counter,
      createdAtMs: projection.authMethod.createdAtMs,
      updatedAtMs: projection.authMethod.updatedAtMs,
    },
    authenticators: [
      {
        profileId: projection.walletId,
        signerSlot: 1,
        credentialId: projection.target.credentialIdB64u,
        credentialPublicKey,
        registered: new Date(1).toISOString(),
        syncedAt: new Date(2).toISOString(),
      },
    ],
    signerActivations: [],
    keyMaterials: [],
    lastProfileState: {
      profileId: projection.walletId,
      activeSignerSlot: 1,
      scope: null,
    },
  };
}

test('persists strict encrypted pending records for Passkey and Google Email OTP', async () => {
  const passkey = await passkeyProjectionFixture();
  const email = await emailProjectionFixture();
  const passkeyPending = await buildPendingRecord(passkey.projection, 1);
  const emailPending = await buildPendingRecord(email.projection, 2);

  for (const pending of [passkeyPending, emailPending]) {
    const row = await toPendingWalletRecoveryCommitAppStateRow(pending);
    const parsedRow = await parsePendingWalletRecoveryCommitAppStateRow(row);
    expect(parsedRow?.record.stage).toBe('server_promoted');
    expect(parsedRow?.record.target.kind).toBe(pending.target.kind);
    expect(parsedRow?.record.projection?.kind).toBe(pending.projection?.kind);
    expect(JSON.stringify(row)).not.toContain('factorSecret');
    expect(JSON.stringify(row)).not.toContain('operationCredential');
  }

  const rawWithSecret = {
    ...passkeyPending,
    factorSecret: 'raw-secret-must-be-rejected',
  };
  await expect(parsePendingWalletRecoveryCommitV1(rawWithSecret)).resolves.toBeNull();

  const mismatchedBranches = {
    ...emailPending,
    target: passkeyPending.target,
  };
  await expect(parsePendingWalletRecoveryCommitV1(mismatchedBranches)).resolves.toBeNull();
});

test('resumes the same pending record after reload and makes promotion retry idempotent', async ({
  page,
}) => {
  const { projection } = await passkeyProjectionFixture();
  await setupBasicPasskeyTest(page, { skipSeamsWebInit: true });
  const result = await page.evaluate(
    async ({ paths, projection }) => {
      const { UnifiedIndexedDBManager, SeamsWalletDBManager, createSeamsTestWalletDbName } =
        await import(paths.indexedDB);
      const { buildPendingWalletRecoveryCommitV1 } = await import(paths.pending);
      const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, [
        'encrypt',
        'decrypt',
      ]);
      if (!(key instanceof CryptoKey)) throw new Error('recovery fixture key was not generated');
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const ciphertext = new Uint8Array(
        await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new Uint8Array([8])),
      );
      const localMaterial = {
        kind: 'wallet_recovery_encrypted_material_v1' as const,
        key,
        iv,
        ciphertext,
      };
      const awaiting = await buildPendingWalletRecoveryCommitV1({
        kind: 'pending_wallet_recovery_commit_v1',
        version: 1,
        stage: 'awaiting_server_promotion',
        recoveryOperationId: projection.recoveryOperationId,
        walletId: projection.walletId,
        reservationId: 'reservation:pending-recovery-awaiting-reload',
        targetDeviceId: projection.targetDeviceId,
        targetAuthorityId: projection.targetAuthorityId,
        targetWalletAuthMethodId: projection.targetWalletAuthMethodId,
        target: {
          kind: 'passkey',
          rpId: projection.target.rpId,
          credentialIdB64u: projection.target.credentialIdB64u,
        },
        localMaterial,
        createdAtMs: 1,
        updatedAtMs: 1,
      });
      const promoted = await buildPendingWalletRecoveryCommitV1({
        ...awaiting,
        stage: 'server_promoted',
        updatedAtMs: 2,
        projection,
      });
      const dbName = createSeamsTestWalletDbName(`pending-recovery-reload-${crypto.randomUUID()}`);
      const firstDbManager = new SeamsWalletDBManager();
      firstDbManager.setDbName(dbName);
      const firstManager = new UnifiedIndexedDBManager({ seamsWalletDB: firstDbManager });
      await firstManager.putPendingWalletRecoveryCommit(awaiting);

      const reloadedDbManager = new SeamsWalletDBManager();
      reloadedDbManager.setDbName(dbName);
      const reloadedManager = new UnifiedIndexedDBManager({ seamsWalletDB: reloadedDbManager });
      const reloaded = await reloadedManager.getPendingWalletRecoveryCommit(
        awaiting.recoveryOperationId,
      );
      if (!reloaded || reloaded.stage !== 'awaiting_server_promotion') {
        throw new Error('awaiting recovery commit was not recovered after reload');
      }
      const firstAdvance = await reloadedManager.advancePendingWalletRecoveryCommit({
        awaiting: reloaded,
        promoted,
      });
      const retryAdvance = await reloadedManager.advancePendingWalletRecoveryCommit({
        awaiting: reloaded,
        promoted,
      });
      const stored = await reloadedManager.getPendingWalletRecoveryCommit(
        awaiting.recoveryOperationId,
      );
      return {
        reloadedStage: reloaded.stage,
        firstAdvanceStage: firstAdvance.stage,
        retryStage: retryAdvance.stage,
        storedStage: stored?.stage ?? null,
        storedUpdatedAtMs: stored?.updatedAtMs ?? null,
      };
    },
    { paths: IMPORT_PATHS, projection },
  );
  expect(result).toEqual({
    reloadedStage: 'awaiting_server_promotion',
    firstAdvanceStage: 'server_promoted',
    retryStage: 'server_promoted',
    storedStage: 'server_promoted',
    storedUpdatedAtMs: 2,
  });
});

test('deletes a definite server refusal from either pending recovery stage', async ({ page }) => {
  const { projection } = await passkeyProjectionFixture({
    label: 'pending-recovery-refusal',
    walletId: 'client-fixture',
    authorityId: 'authority:pending-recovery-refusal',
    rpId: 'wallet.pending-recovery.example',
    credentialIdB64u: 'Y3JlZGVudGlhbC1wZW5kaW5nLXJlZnVzYWw',
    walletAuthMethodId:
      'passkey:wallet.pending-recovery.example:Y3JlZGVudGlhbC1wZW5kaW5nLXJlZnVzYWw',
  });
  const payload = await startupRecoveryPayloadFixture(projection);
  await setupBasicPasskeyTest(page, { skipSeamsWebInit: true });
  const result = await page.evaluate(
    async ({ paths, payload, projection }) => {
      const {
        IndexedDBManager,
        SeamsWalletDBManager,
        SEAMS_WALLET_DB_NAME,
        UnifiedIndexedDBManager,
        seamsWalletDB,
      } = await import(paths.indexedDB);
      const { resumePendingWalletRecoveries } = await import(paths.commit);
      const { promotedPendingWalletRecoveryCommit, encryptWalletRecoveryDurablePayload } =
        await import(paths.journal);
      const { buildPendingWalletRecoveryCommitV1 } = await import(paths.pending);
      const dbManager = new SeamsWalletDBManager();
      dbManager.setDbName(SEAMS_WALLET_DB_NAME);
      const db = new UnifiedIndexedDBManager({ seamsWalletDB: dbManager });
      const localMaterial = await encryptWalletRecoveryDurablePayload(payload);
      const awaiting = await buildPendingWalletRecoveryCommitV1({
        kind: 'pending_wallet_recovery_commit_v1',
        version: 1,
        stage: 'awaiting_server_promotion',
        recoveryOperationId: projection.recoveryOperationId,
        walletId: projection.walletId,
        reservationId: payload.reservationId,
        targetDeviceId: projection.targetDeviceId,
        targetAuthorityId: projection.targetAuthorityId,
        targetWalletAuthMethodId: projection.targetWalletAuthMethodId,
        target: {
          kind: 'passkey',
          rpId: projection.target.rpId,
          credentialIdB64u: projection.target.credentialIdB64u,
        },
        localMaterial,
        createdAtMs: 1,
        updatedAtMs: 1,
      });
      const refusalFetch: typeof fetch = async () => new Response('{}', { status: 400 });
      seamsWalletDB.setDbName(SEAMS_WALLET_DB_NAME);
      await db.putPendingWalletRecoveryCommit(awaiting);
      const awaitingResult = await resumePendingWalletRecoveries({
        relayUrl: 'https://relay.example.test',
        fetchImpl: refusalFetch,
      });
      const awaitingRemaining = await IndexedDBManager.getPendingWalletRecoveryCommit(
        projection.recoveryOperationId,
      );

      const promoted = promotedPendingWalletRecoveryCommit(awaiting, payload, projection, 2);
      await db.putPendingWalletRecoveryCommit(promoted);
      const promotedResult = await resumePendingWalletRecoveries({
        relayUrl: 'https://relay.example.test',
        fetchImpl: refusalFetch,
      });
      const promotedRemaining = await IndexedDBManager.getPendingWalletRecoveryCommit(
        projection.recoveryOperationId,
      );
      return {
        awaitingResult,
        awaitingRemaining: awaitingRemaining?.stage ?? null,
        promotedResult,
        promotedRemaining: promotedRemaining?.stage ?? null,
      };
    },
    { paths: IMPORT_PATHS, payload, projection },
  );
  expect(result).toEqual({
    awaitingResult: [{ kind: 'discarded', recoveryOperationId: projection.recoveryOperationId }],
    awaitingRemaining: null,
    promotedResult: [{ kind: 'discarded', recoveryOperationId: projection.recoveryOperationId }],
    promotedRemaining: null,
  });
});

test('a parsed durable payload round-trips through journal encryption', async ({ page }) => {
  const { projection } = await passkeyProjectionFixture({
    label: 'pending-recovery-roundtrip',
    walletId: 'client-fixture',
    authorityId: 'authority:pending-recovery-roundtrip',
    rpId: 'wallet.pending-recovery.example',
    credentialIdB64u: 'Y3JlZGVudGlhbC1wZW5kaW5nLXJvdW5kdHJpcA',
    walletAuthMethodId:
      'passkey:wallet.pending-recovery.example:Y3JlZGVudGlhbC1wZW5kaW5nLXJvdW5kdHJpcA',
  });
  const payload = await startupRecoveryPayloadFixture(projection);
  await setupBasicPasskeyTest(page, { skipSeamsWebInit: true });
  /* Parsing enriches the key sets with manifest-derived facts, so the journal
     must serialize the wire projection rather than the parsed record - the
     resume path otherwise reports every awaiting record as corrupt. */
  const result = await page.evaluate(
    async ({ paths, payload, projection }) => {
      const { encryptWalletRecoveryDurablePayload, decryptWalletRecoveryDurablePayload } =
        await import(paths.journal);
      const { parseWalletRecoveryDurablePayload } = await import(paths.durable);
      const { buildPendingWalletRecoveryCommitV1 } = await import(paths.pending);
      const parsed = parseWalletRecoveryDurablePayload(payload);
      const localMaterial = await encryptWalletRecoveryDurablePayload(parsed);
      const awaiting = await buildPendingWalletRecoveryCommitV1({
        kind: 'pending_wallet_recovery_commit_v1',
        version: 1,
        stage: 'awaiting_server_promotion',
        recoveryOperationId: projection.recoveryOperationId,
        walletId: projection.walletId,
        reservationId: payload.reservationId,
        targetDeviceId: projection.targetDeviceId,
        targetAuthorityId: projection.targetAuthorityId,
        targetWalletAuthMethodId: projection.targetWalletAuthMethodId,
        target: {
          kind: 'passkey',
          rpId: projection.target.rpId,
          credentialIdB64u: projection.target.credentialIdB64u,
        },
        localMaterial,
        createdAtMs: 1,
        updatedAtMs: 1,
      });
      const decrypted = await decryptWalletRecoveryDurablePayload(awaiting);
      return {
        recoveryOperationId: String(decrypted.recoveryOperationId),
        ecdsaKeySetIds: decrypted.ecdsaKeySets.map((keySet) => String(keySet.entry.keySetId)),
      };
    },
    { paths: IMPORT_PATHS, payload, projection },
  );
  expect(result.recoveryOperationId).toBe(projection.recoveryOperationId);
  expect(result.ecdsaKeySetIds).toHaveLength(1);
});

test('SeamsWeb startup resumes a valid server-promoted recovery row after reload', async ({
  page,
}) => {
  const { projection } = await passkeyProjectionFixture({
    label: 'pending-recovery-startup',
    walletId: 'client-fixture',
    authorityId: 'authority:pending-recovery-startup',
    rpId: 'wallet.pending-recovery.example',
    credentialIdB64u: 'Y3JlZGVudGlhbC1wZW5kaW5nLXJlY292ZXJ5',
    walletAuthMethodId:
      'passkey:wallet.pending-recovery.example:Y3JlZGVudGlhbC1wZW5kaW5nLXJlY292ZXJ5',
  });
  const payload = await startupRecoveryPayloadFixture(projection);
  let replayCalls = 0;
  let replayRequestKind: string | null = null;
  await page.route('**/wallets/recovery/finalize', async (route) => {
    replayCalls += 1;
    const requestBody = route.request().postDataJSON() as { readonly kind?: unknown };
    replayRequestKind = typeof requestBody.kind === 'string' ? requestBody.kind : null;
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ ok: true, projection }),
    });
  });
  await setupBasicPasskeyTest(page, { skipSeamsWebInit: true });
  const result = await page.evaluate(
    async ({ paths, payload, projection }) => {
      const {
        IndexedDBManager,
        SeamsWalletDBManager,
        SEAMS_WALLET_DB_NAME,
        UnifiedIndexedDBManager,
        seamsWalletDB,
      } = await import(paths.indexedDB);
      const { promotedPendingWalletRecoveryCommit, encryptWalletRecoveryDurablePayload } =
        await import(paths.journal);
      const { buildPendingWalletRecoveryCommitV1 } = await import(paths.pending);
      const { SeamsWeb } = await import(paths.seamsWeb);
      const dbName = SEAMS_WALLET_DB_NAME;
      const dbManager = new SeamsWalletDBManager();
      dbManager.setDbName(dbName);
      const localMaterial = await encryptWalletRecoveryDurablePayload(payload);
      const awaiting = await buildPendingWalletRecoveryCommitV1({
        kind: 'pending_wallet_recovery_commit_v1',
        version: 1,
        stage: 'awaiting_server_promotion',
        recoveryOperationId: projection.recoveryOperationId,
        walletId: projection.walletId,
        reservationId: payload.reservationId,
        targetDeviceId: projection.targetDeviceId,
        targetAuthorityId: projection.targetAuthorityId,
        targetWalletAuthMethodId: projection.targetWalletAuthMethodId,
        target: {
          kind: 'passkey',
          rpId: projection.target.rpId,
          credentialIdB64u: projection.target.credentialIdB64u,
        },
        localMaterial,
        createdAtMs: 1,
        updatedAtMs: 1,
      });
      const record = promotedPendingWalletRecoveryCommit(awaiting, payload, projection, 2);
      await new UnifiedIndexedDBManager({
        seamsWalletDB: dbManager,
      }).putPendingWalletRecoveryCommit(record);
      dbManager.close();

      seamsWalletDB.setDbName(dbName);
      const reloaded = await IndexedDBManager.getPendingWalletRecoveryCommit(
        record.recoveryOperationId,
      );
      if (!reloaded || reloaded.stage !== 'server_promoted') {
        throw new Error('server-promoted recovery commit was not recovered after reload');
      }
      let seams: { dispose(): void; configs: { network: { relayer: { url: string } } } } | null =
        null;
      try {
        seams = new SeamsWeb(
          {
            relayer: { url: 'https://relay.example.test' },
          },
          undefined,
          { kind: 'wallet_host' },
        );
        for (let attempt = 0; attempt < 100; attempt += 1) {
          if (
            (await IndexedDBManager.getPendingWalletRecoveryCommit(record.recoveryOperationId)) ===
            null
          ) {
            break;
          }
          await new Promise((resolve) => setTimeout(resolve, 100));
        }
      } finally {
        seams?.dispose();
      }
      const { IndexedDbEcdsaCapabilityManifestStore } = await import(paths.ecdsa);
      const ecdsaSubjects = await new IndexedDbEcdsaCapabilityManifestStore(
        seamsWalletDB,
      ).listActiveWalletCapabilitySubjects(projection.walletId);
      return {
        reloadedStage: reloaded.stage,
        pending:
          (await IndexedDBManager.getPendingWalletRecoveryCommit(record.recoveryOperationId)) !==
          null,
        profile: (await IndexedDBManager.getProfile(projection.walletId)) !== null,
        authority:
          (await IndexedDBManager.getWalletAuthority(projection.targetAuthorityId)) !== null,
        authMethod:
          (await IndexedDBManager.getWalletAuthMethodV2(projection.targetWalletAuthMethodId)) !==
          null,
        ecdsaSubjectCount: ecdsaSubjects.kind === 'resolved' ? ecdsaSubjects.subjects.length : 0,
      };
    },
    { paths: IMPORT_PATHS, payload, projection },
  );
  expect({ replayCalls, replayRequestKind, result }).toMatchObject({
    replayCalls: 1,
    replayRequestKind: 'replay',
  });
  expect(result).toEqual({
    reloadedStage: 'server_promoted',
    pending: false,
    profile: true,
    authority: true,
    authMethod: true,
    ecdsaSubjectCount: 1,
  });
});

test('probes credential-free replay before retrying an awaiting Google recovery', async ({ page }) => {
  const fixture = await emailProjectionFixture();
  const payload = await startupGoogleRecoveryPayloadFixture(
    fixture.projection,
    fixture.authAuthority,
    fixture.verifiedEmail,
  );
  const requestKinds: string[] = [];
  await setupBasicPasskeyTest(page, { skipSeamsWebInit: true });
  await page.route('**/wallets/recovery/google-email-otp/finalize', async (route) => {
    const body = route.request().postDataJSON() as { readonly kind?: unknown };
    requestKinds.push(typeof body.kind === 'string' ? body.kind : 'missing');
    await route.fulfill({
      status: 400,
      contentType: 'application/json',
      body: JSON.stringify({ ok: false }),
    });
  });
  const result = await page.evaluate(
    async ({ paths, payload }) => {
      const {
        IndexedDBManager,
        SeamsWalletDBManager,
        UnifiedIndexedDBManager,
        createSeamsTestWalletDbName,
        seamsWalletDB,
      } = await import(paths.indexedDB);
      const { resumePendingWalletRecoveries } = await import(paths.commit);
      const { encryptWalletRecoveryDurablePayload } = await import(paths.journal);
      const { buildPendingWalletRecoveryCommitV1 } = await import(paths.pending);
      const dbName = createSeamsTestWalletDbName(`pending-recovery-google-${crypto.randomUUID()}`);
      seamsWalletDB.setDbName(dbName);
      const dbManager = new SeamsWalletDBManager();
      dbManager.setDbName(dbName);
      const db = new UnifiedIndexedDBManager({ seamsWalletDB: dbManager });
      const localMaterial = await encryptWalletRecoveryDurablePayload(payload);
      const awaiting = await buildPendingWalletRecoveryCommitV1({
        kind: 'pending_wallet_recovery_commit_v1',
        version: 1,
        stage: 'awaiting_server_promotion',
        recoveryOperationId: payload.recoveryOperationId,
        walletId: payload.walletId,
        reservationId: payload.reservationId,
        targetDeviceId: payload.targetDeviceId,
        targetAuthorityId: payload.targetAuthorityId,
        targetWalletAuthMethodId: payload.targetWalletAuthMethodId,
        target: {
          kind: 'google_email_otp',
          providerSubject: payload.providerSubject,
          emailHashHex: payload.emailHashHex,
          registrationAuthorityId: payload.registrationAuthorityId,
          enrollment: {
            kind: 'email_otp_enrollment_reference_v1' as const,
            enrollmentId: payload.enrollment.enrollmentId,
            enrollmentSealKeyVersion:
              payload.enrollment.kind === 'existing'
                ? payload.enrollment.enrollmentSealKeyVersion
                : payload.enrollment.material.enrollmentSealKeyVersion,
          },
        },
        localMaterial,
        createdAtMs: 1,
        updatedAtMs: 1,
      });
      await db.putPendingWalletRecoveryCommit(awaiting);
      const resumeResult = await resumePendingWalletRecoveries({
        relayUrl: 'https://relay.example.test',
      });
      return {
        resumeResult,
        remaining: await IndexedDBManager.getPendingWalletRecoveryCommit(
          payload.recoveryOperationId,
        ),
      };
    },
    { paths: IMPORT_PATHS, payload },
  );
  expect(requestKinds).toEqual(['replay', 'finalize']);
  expect(result.resumeResult).toEqual([
    { kind: 'discarded', recoveryOperationId: payload.recoveryOperationId },
  ]);
  expect(result.remaining).toBeNull();
});

test.describe('atomic pending recovery publication', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipSeamsWebInit: true });
  });

  test('consumes the exact Passkey pending row while publishing local projections atomically', async ({
    page,
  }) => {
    const fixture = await passkeyProjectionFixture();
    const credentialPublicKey = base64UrlDecode(
      fixture.projection.authMethod.credentialPublicKeyB64u,
    );
    const registration = passkeyRecoveryRegistrationFixture(
      fixture.projection,
      credentialPublicKey,
    );
    const result = await page.evaluate(
      async ({ paths, authority, projection, registration }) => {
        const { UnifiedIndexedDBManager, SeamsWalletDBManager, createSeamsTestWalletDbName } =
          await import(paths.indexedDB);
        const dbManager = new SeamsWalletDBManager();
        dbManager.setDbName(createSeamsTestWalletDbName(`pending-recovery-${crypto.randomUUID()}`));
        const db = new UnifiedIndexedDBManager({ seamsWalletDB: dbManager });
        const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, [
          'encrypt',
          'decrypt',
        ]);
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const ciphertext = new Uint8Array(
          await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new Uint8Array([7])),
        );
        const { buildPendingWalletRecoveryCommitV1 } = await import(paths.pending);
        const record = await buildPendingWalletRecoveryCommitV1({
          kind: 'pending_wallet_recovery_commit_v1',
          version: 1,
          stage: 'server_promoted',
          recoveryOperationId: projection.recoveryOperationId,
          walletId: projection.walletId,
          reservationId: 'reservation:pending-recovery-atomic',
          targetDeviceId: projection.targetDeviceId,
          targetAuthorityId: projection.targetAuthorityId,
          targetWalletAuthMethodId: projection.targetWalletAuthMethodId,
          target: {
            kind: 'passkey',
            rpId: projection.target.rpId,
            credentialIdB64u: projection.target.credentialIdB64u,
          },
          localMaterial: {
            kind: 'wallet_recovery_encrypted_material_v1',
            key,
            iv,
            ciphertext,
          },
          createdAtMs: 1,
          updatedAtMs: 2,
          projection,
        });
        await db.putPendingWalletRecoveryCommit(record);
        const published = await db.publishPendingWalletRecoveryCommit({
          pending: record,
          authority,
          authMethod: projection.authMethod,
          ecdsaContinuity: [],
          ed25519PublicCapabilityReferences: [],
          registration,
        });
        const profile = await db.getProfile(projection.walletId);
        const storedAuthMethod = await db.getWalletAuthMethodV2(
          projection.targetWalletAuthMethodId,
        );
        const storedAuthority = await db.getWalletAuthority(projection.targetAuthorityId);
        const selections = await db.listWalletSelections();
        return {
          signerActivationCount: published.signerActivations.length,
          pendingRemaining:
            (await db.getPendingWalletRecoveryCommit(projection.recoveryOperationId)) !== null,
          profileId: profile?.profileId ?? null,
          authMethodId: storedAuthMethod?.walletAuthMethodId ?? null,
          authorityId: storedAuthority?.authorityId ?? null,
          selection: selections.find((item) => item.walletId === projection.walletId) ?? null,
        };
      },
      {
        paths: IMPORT_PATHS,
        authority: fixture.authority,
        projection: fixture.projection,
        registration,
      },
    );

    expect(result).toMatchObject({
      signerActivationCount: 0,
      pendingRemaining: false,
      profileId: fixture.projection.walletId,
      authMethodId: fixture.projection.targetWalletAuthMethodId,
      authorityId: fixture.projection.targetAuthorityId,
      selection: {
        walletId: fixture.projection.walletId,
        walletAuthMethodId: fixture.projection.targetWalletAuthMethodId,
        lockState: 'locked',
      },
    });
  });

  test('rolls back every projection when a late reference write fails', async ({ page }) => {
    const fixture = await passkeyProjectionFixture({ label: 'pending-recovery-rollback' });
    const credentialPublicKey = base64UrlDecode(
      fixture.projection.authMethod.credentialPublicKeyB64u,
    );
    const registration = passkeyRecoveryRegistrationFixture(
      fixture.projection,
      credentialPublicKey,
    );
    const result = await page.evaluate(
      async ({ paths, authority, projection, registration }) => {
        const { UnifiedIndexedDBManager, SeamsWalletDBManager, createSeamsTestWalletDbName } =
          await import(paths.indexedDB);
        const dbManager = new SeamsWalletDBManager();
        dbManager.setDbName(
          createSeamsTestWalletDbName(`pending-recovery-rollback-${crypto.randomUUID()}`),
        );
        const db = new UnifiedIndexedDBManager({ seamsWalletDB: dbManager });
        const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, [
          'encrypt',
          'decrypt',
        ]);
        if (!(key instanceof CryptoKey)) throw new Error('recovery fixture key was not generated');
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const ciphertext = new Uint8Array(
          await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new Uint8Array([11])),
        );
        const { buildPendingWalletRecoveryCommitV1 } = await import(paths.pending);
        const pending = await buildPendingWalletRecoveryCommitV1({
          kind: 'pending_wallet_recovery_commit_v1',
          version: 1,
          stage: 'server_promoted',
          recoveryOperationId: projection.recoveryOperationId,
          walletId: projection.walletId,
          reservationId: 'reservation:pending-recovery-rollback',
          targetDeviceId: projection.targetDeviceId,
          targetAuthorityId: projection.targetAuthorityId,
          targetWalletAuthMethodId: projection.targetWalletAuthMethodId,
          target: {
            kind: 'passkey',
            rpId: projection.target.rpId,
            credentialIdB64u: projection.target.credentialIdB64u,
          },
          localMaterial: {
            kind: 'wallet_recovery_encrypted_material_v1',
            key,
            iv,
            ciphertext,
          },
          createdAtMs: 1,
          updatedAtMs: 2,
          projection,
        });
        await db.putPendingWalletRecoveryCommit(pending);
        let failed = false;
        try {
          await db.publishPendingWalletRecoveryCommit({
            pending,
            authority,
            authMethod: projection.authMethod,
            registration,
            ecdsaContinuity: [],
            ed25519PublicCapabilityReferences: [{}],
          });
        } catch {
          failed = true;
        }
        const { IndexedDbEcdsaCapabilityManifestStore } = await import(paths.ecdsa);
        const ecdsaSubjects = await new IndexedDbEcdsaCapabilityManifestStore(
          dbManager,
        ).listActiveWalletCapabilitySubjects(projection.walletId);
        const references = await db.getAppState('ed25519YaoPublicCapabilityReferencesV1');
        return {
          failed,
          pending:
            (await db.getPendingWalletRecoveryCommit(projection.recoveryOperationId)) !== null,
          profile: await db.getProfile(projection.walletId),
          authMethod: await db.getWalletAuthMethodV2(projection.targetWalletAuthMethodId),
          authority: await db.getWalletAuthority(projection.targetAuthorityId),
          authenticators: await db.listProfileAuthenticators(projection.walletId),
          selection: (await db.listWalletSelections()).find(
            (item) => item.walletId === projection.walletId,
          ),
          ecdsaSubjectCount: ecdsaSubjects.kind === 'resolved' ? ecdsaSubjects.subjects.length : -1,
          references: references ?? null,
        };
      },
      {
        paths: IMPORT_PATHS,
        authority: fixture.authority,
        projection: fixture.projection,
        registration,
      },
    );

    expect(result).toMatchObject({
      failed: true,
      pending: true,
      profile: null,
      authMethod: null,
      authority: null,
      authenticators: [],
      selection: undefined,
      ecdsaSubjectCount: 0,
      references: null,
    });
  });

  test('consumes the exact Google Email OTP pending row while publishing local projections atomically', async ({
    page,
  }) => {
    const fixture = await emailProjectionFixture();
    const result = await page.evaluate(
      async ({ paths, authority, authAuthority, projection }) => {
        const { UnifiedIndexedDBManager, SeamsWalletDBManager, createSeamsTestWalletDbName } =
          await import(paths.indexedDB);
        const dbManager = new SeamsWalletDBManager();
        dbManager.setDbName(createSeamsTestWalletDbName(`pending-recovery-${crypto.randomUUID()}`));
        const db = new UnifiedIndexedDBManager({ seamsWalletDB: dbManager });
        const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, [
          'encrypt',
          'decrypt',
        ]);
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const ciphertext = new Uint8Array(
          await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new Uint8Array([9])),
        );
        const { buildPendingWalletRecoveryCommitV1 } = await import(paths.pending);
        const record = await buildPendingWalletRecoveryCommitV1({
          kind: 'pending_wallet_recovery_commit_v1',
          version: 1,
          stage: 'server_promoted',
          recoveryOperationId: projection.recoveryOperationId,
          walletId: projection.walletId,
          reservationId: 'reservation:pending-recovery-email-atomic',
          targetDeviceId: projection.targetDeviceId,
          targetAuthorityId: projection.targetAuthorityId,
          targetWalletAuthMethodId: projection.targetWalletAuthMethodId,
          target: {
            kind: 'google_email_otp',
            providerSubject: projection.target.providerSubject,
            emailHashHex: projection.target.emailHashHex,
            registrationAuthorityId: projection.target.registrationAuthorityId,
            enrollment: projection.target.enrollment,
          },
          localMaterial: {
            kind: 'wallet_recovery_encrypted_material_v1',
            key,
            iv,
            ciphertext,
          },
          createdAtMs: 1,
          updatedAtMs: 2,
          projection,
        });
        await db.putPendingWalletRecoveryCommit(record);
        const initialAuthMethod = {
          version: 'wallet_auth_method_v1',
          kind: 'email_otp',
          status: 'active',
          localStatus: 'synced',
          walletId: projection.walletId,
          emailHashHex: projection.target.emailHashHex,
          registrationAuthorityId: projection.target.registrationAuthorityId,
          authority: authAuthority,
          createdAtMs: projection.authMethod.createdAtMs,
          updatedAtMs: projection.authMethod.updatedAtMs,
        };
        const published = await db.publishPendingWalletRecoveryCommit({
          pending: record,
          authority,
          authMethod: projection.authMethod,
          ecdsaContinuity: [],
          ed25519PublicCapabilityReferences: [],
          registration: {
            profiles: [
              {
                profileId: projection.walletId,
                defaultSignerSlot: 1,
              },
            ],
            initialAuthMethod,
            authenticators: [],
            signerActivations: [],
            keyMaterials: [],
            lastProfileState: {
              profileId: projection.walletId,
              activeSignerSlot: 1,
              scope: null,
            },
          },
        });
        const profile = await db.getProfile(projection.walletId);
        const storedAuthMethod = await db.getWalletAuthMethodV2(
          projection.targetWalletAuthMethodId,
        );
        const storedAuthority = await db.getWalletAuthority(projection.targetAuthorityId);
        const localMethods = await db.listWalletAuthMethodsForWallet(projection.walletId);
        const selections = await db.listWalletSelections();
        const localEmailMethod = localMethods.find((method) => method.kind === 'email_otp');
        return {
          signerActivationCount: published.signerActivations.length,
          pendingRemaining:
            (await db.getPendingWalletRecoveryCommit(projection.recoveryOperationId)) !== null,
          profileId: profile?.profileId ?? null,
          authMethodId: storedAuthMethod?.walletAuthMethodId ?? null,
          authorityId: storedAuthority?.authorityId ?? null,
          localEmailMethod: localEmailMethod
            ? {
                status: localEmailMethod.status,
                emailHashHex: localEmailMethod.emailHashHex,
                registrationAuthorityId: localEmailMethod.registrationAuthorityId,
              }
            : null,
          selection: selections.find((item) => item.walletId === projection.walletId) ?? null,
        };
      },
      {
        paths: IMPORT_PATHS,
        authority: fixture.authority,
        authAuthority: fixture.authAuthority,
        projection: fixture.projection,
      },
    );

    expect(result).toMatchObject({
      signerActivationCount: 0,
      pendingRemaining: false,
      profileId: fixture.projection.walletId,
      authMethodId: fixture.projection.targetWalletAuthMethodId,
      authorityId: fixture.projection.targetAuthorityId,
      localEmailMethod: {
        status: 'active',
        emailHashHex: fixture.projection.target.emailHashHex,
        registrationAuthorityId: fixture.projection.target.registrationAuthorityId,
      },
      selection: {
        walletId: fixture.projection.walletId,
        walletAuthMethodId: fixture.projection.targetWalletAuthMethodId,
        lockState: 'locked',
      },
    });
  });
});
