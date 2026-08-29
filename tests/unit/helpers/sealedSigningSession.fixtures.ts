import {
  SIGNING_SESSION_SEALED_RECORD_VERSION,
  SIGNING_SESSION_SEAL_ALG,
  SIGNING_SESSION_SEAL_GROUP_ID,
  SIGNING_SESSION_SEAL_STORAGE_SCOPE,
  SIGNING_SESSION_SECRET_KIND,
  type SealedSigningSessionRecord,
} from '@shared/utils/signingSessionSeal';
import {
  ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_STATE_KIND_V1,
  requireRouterAbEcdsaDerivationNormalSigningStateV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import { routerAbMpcMaterialActivationRefToWire } from '@shared/utils/routerAbNormalSigningIdentity';
import {
  requireAuthoritativeExpiredWalletSessionAuthorizationBoundary,
  type ExpiredWalletSessionAuthorizationState,
} from '@/core/signingEngine/session/identity/clientSessionPersistenceState';
import type { ExactEd25519SigningLaneIdentity } from '@/core/signingEngine/session/identity/exactSigningLaneIdentity';
import { createThresholdEcdsaBootstrapFixture } from './ecdsaBootstrap.fixtures';
import { buildEcdsaRoleLocalPersistedMaterialRefFixture } from './ecdsaMaterialRef.fixtures';
import { buildWalletAuthAuthorityRefForAuthorityFixture } from './ecdsaMaterialRef.fixtures';
import {
  buildEmailOtpWalletAuthAuthority,
  buildPasskeyWalletAuthAuthority,
  type WalletAuthAuthority,
} from '@shared/utils/walletAuthAuthority';
import {
  buildActiveWalletAuthorityV1,
  buildWalletSignerActivationSetV1,
  type ActiveWalletAuthorityV1,
} from '@shared/authorization/walletAuthority';
import { buildSigningOnlyPermissionsV1 } from '@shared/authorization/delegatedAuthority';
import { parseExactAdministeredSignerManifestV1 } from '@shared/device-linking/delegatedActivationPlan';
import {
  parseActiveWalletSessionV1,
  parseWalletSessionOperationCredentialV1,
} from '@shared/device-linking/parsers';
import type { ActiveEcdsaCapabilityManifest } from '@/core/signingEngine/session/material/ecdsaCapabilityManifest';
import {
  buildEcdsaInactiveMaterialPublicRestore,
  buildCurrentSealedSessionRecord,
  classifyRawSealedSessionRecord,
  type CurrentEd25519SealedSessionRecord,
  type CurrentEcdsaSealedSessionRecord,
  type EcdsaInactiveSealedMaterialRecord,
} from '@/core/signingEngine/session/persistence/sealedSessionStore';
import { parseEcdsaRoleLocalPersistedMaterialRef } from '@/core/signingEngine/session/keyMaterialBrands';
import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { thresholdEcdsaChainTargetKey } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { ecdsaSealedRecordStoreKey } from '@/core/signingEngine/session/persistence/ecdsaSealedRecordKey';
import { buildMpcMaterialActivationRefFixture } from './ecdsaMaterialRef.fixtures';
import {
  parseDeviceId,
  parseMpcWalletSigningQuotaId,
  parseWalletSessionAuthorizationId,
  parseWalletSessionId,
} from '@shared/authorization/capabilityKinds';
import { parseWalletAuthorityId, type MpcMaterialActivationRef } from '@shared/utils/domainIds';
import type { RouterAbEd25519YaoActiveClientMetadataV1 } from '@/core/signingEngine/threshold/ed25519/yaoClient';
import { base64UrlEncode } from '@shared/utils/base64';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import { buildWalletAuthMethodRecordV2 } from '@shared/utils/registrationIntent';
import { buildActiveNearEd25519WalletSessionAuthorization } from '@/core/signingEngine/session/material/nearEd25519YaoSigningPreparation';
import type { ActiveWalletAuthMethodV2 } from '@/core/signingEngine/session/identity/ownerLaneScope';

function requireFixtureDomainId<T>(
  result: { ok: true; value: T } | { ok: false; error: unknown },
): T {
  if (!result.ok) throw new Error('invalid sealed-session fixture domain id');
  return result.value;
}

function fixtureWalletSessionToken(label: string): string {
  const encoded = base64UrlEncode(new TextEncoder().encode(label));
  return `wst_${encoded.padEnd(43, 'A').slice(0, 43)}`;
}

function buildActiveEd25519WalletAuthorityFixture(args: {
  record: CurrentEd25519SealedSessionRecord;
  factorAuthority: WalletAuthAuthority;
}): ActiveWalletAuthorityV1 {
  const { record, factorAuthority } = args;
  const authorityRef = buildWalletAuthAuthorityRefForAuthorityFixture(factorAuthority);
  const walletAuthorityId = requireFixtureDomainId(
    parseWalletAuthorityId(`authority:sealed-ed25519:${record.thresholdSessionIds.ed25519}`),
  );
  const signerManifest = parseExactAdministeredSignerManifestV1({
    kind: 'exact_administered_signer_manifest_v1',
    keyFamilies: ['ed25519'],
    signers: [
      {
        kind: 'exact_administered_ed25519_signer_v1',
        keyFamily: 'ed25519',
        walletId: factorAuthority.walletId,
        walletKeyId: `wallet-key:sealed-ed25519:${record.thresholdSessionIds.ed25519}`,
        registeredPublicKeyB64u: base64UrlEncode(new Uint8Array(32).fill(7)),
      },
    ],
  });
  const signerActivations = buildWalletSignerActivationSetV1({
    manifest: signerManifest,
    materialActivations: {
      keyFamilies: ['ed25519'],
      ed25519: record.ed25519Restore.materialActivation,
    },
  });
  return buildActiveWalletAuthorityV1({
    kind: 'wallet_authority_v1',
    authorityId: walletAuthorityId,
    walletId: factorAuthority.walletId,
    principal: {
      kind: 'owner_device',
      deviceId: requireFixtureDomainId(
        parseDeviceId(`device:sealed-ed25519:${record.thresholdSessionIds.ed25519}`),
      ),
    },
    provenance: { kind: 'wallet_registration' },
    permissions: buildSigningOnlyPermissionsV1(),
    signerActivations,
    signerActivationSetDigestB64u: parseDigestB64u(String(authorityRef.authorityDigest)),
    authorityDigestB64u: parseDigestB64u(String(authorityRef.authorityDigest)),
    revocationEpoch: 0,
    createdAtMs: 1,
    updatedAtMs: 2,
    state: 'active',
    activatedAtMs: 2,
  });
}

function buildExactEd25519AuthorizationFixture(args: {
  record: CurrentEd25519SealedSessionRecord;
  selectedAuthority: ActiveWalletAuthorityV1;
  selectedAuthMethod: ActiveWalletAuthMethodV2;
  selectedFactorAuthority: WalletAuthAuthority;
  authorizationId?: string;
  walletSessionId?: string;
  quotaId?: string;
  authorizationExpiresAtMs?: number;
  remainingUses?: number;
}) {
  const authorizationExpiresAtMs = args.authorizationExpiresAtMs ?? args.record.expiresAtMs;
  const walletSessionId = requireFixtureDomainId(
    parseWalletSessionId(
      args.walletSessionId ?? `wallet-session:${args.record.thresholdSessionIds.ed25519}`,
    ),
  );
  const quotaId = requireFixtureDomainId(
    parseMpcWalletSigningQuotaId(
      args.quotaId ?? `quota:${args.record.thresholdSessionIds.ed25519}`,
    ),
  );
  const session = parseActiveWalletSessionV1({
    kind: 'active_wallet_session_v1',
    walletId: args.selectedAuthority.walletId,
    authorityId: args.selectedAuthority.authorityId,
    authMethodId: args.selectedAuthMethod.walletAuthMethodId,
    authorizationId: requireFixtureDomainId(
      parseWalletSessionAuthorizationId(
        args.authorizationId ??
          `wallet-session-authorization:${args.record.thresholdSessionIds.ed25519}`,
      ),
    ),
    quotaId,
    authorityDigestB64u: args.selectedAuthority.authorityDigestB64u,
    authorityRevocationEpoch: args.selectedAuthority.revocationEpoch,
    capabilitySubjects: [
      {
        kind: 'sign',
        keyFamily: 'ed25519',
        materialActivation: args.record.ed25519Restore.materialActivation,
      },
    ],
    issuedAtMs: 1,
    expiresAtMs: authorizationExpiresAtMs,
  });
  const operationCredential = parseWalletSessionOperationCredentialV1({
    kind: 'opaque_wallet_session_operation_credential_v1',
    token: fixtureWalletSessionToken(args.record.thresholdSessionIds.ed25519),
    walletSessionId,
  });
  return buildActiveNearEd25519WalletSessionAuthorization({
    selectedAuthority: args.selectedAuthority,
    selectedAuthMethod: args.selectedAuthMethod,
    selectedFactorAuthority: args.selectedFactorAuthority,
    session,
    operationCredential,
    status: {
      status: 'active',
      walletSessionId,
      quotaId,
      remainingUses: args.remainingUses ?? args.record.remainingUses,
      expiresAtMs: authorizationExpiresAtMs,
      quotaLifecycle: 'active',
      authorization: session,
    },
    nowMs: Math.max(0, Math.min(authorizationExpiresAtMs - 1, Date.now())),
  });
}

export function buildPasskeyEd25519SealedSessionRecordFixture(
  args: {
    walletId?: string;
    nearAccountId?: string;
    nearEd25519SigningKeyId?: string;
    thresholdSessionId?: string;
    materialActivation?: MpcMaterialActivationRef;
    expiresAtMs?: number;
    remainingUses?: number;
    /** R103C sibling-owner coverage: a second owner is a different credential and slot. */
    credentialIdB64u?: string;
    signerSlot?: number;
  } = {},
): CurrentEd25519SealedSessionRecord {
  const walletId = args.walletId ?? 'ed25519-sealed-runtime-wallet';
  const nearAccountId = args.nearAccountId ?? 'ed25519-sealed-runtime.testnet';
  const nearEd25519SigningKeyId = args.nearEd25519SigningKeyId ?? 'ed25519-sealed-runtime-key';
  const thresholdSessionId = args.thresholdSessionId ?? 'ed25519-sealed-runtime-session';
  const record = buildCurrentSealedSessionRecord({
    curve: 'ed25519',
    authMethod: 'passkey',
    thresholdSessionId,
    thresholdSessionIds: { ed25519: thresholdSessionId },
    walletId,
    signingRootId: 'ed25519-sealed-runtime-project:test',
    signingRootVersion: 'v1',
    relayerUrl: 'https://relay.example.test',
    sealedSecretB64u: 'ed25519-sealed-runtime-secret',
    keyVersion: 'ed25519-sealed-runtime-kek',
    groupId: SIGNING_SESSION_SEAL_GROUP_ID,
    issuedAtMs: 1,
    expiresAtMs: args.expiresAtMs ?? 1_900_000_000_000,
    remainingUses: args.remainingUses ?? 3,
    updatedAtMs: 2,
    ed25519Restore: {
      nearAccountId,
      nearEd25519SigningKeyId,
      rpId: 'wallet.example.test',
      credentialIdB64u: args.credentialIdB64u ?? 'ed25519-sealed-runtime-credential',
      materialActivation:
        args.materialActivation ??
        buildMpcMaterialActivationRefFixture('ed25519-sealed-runtime-material', walletId),
      relayerKeyId: 'ed25519-sealed-runtime-worker',
      participantIds: [1, 2],
      runtimePolicyScope: {
        orgId: 'ed25519-sealed-runtime-org',
        projectId: 'ed25519-sealed-runtime-project',
        envId: 'test',
        signingRootVersion: 'v1',
      },
      signerSlot: args.signerSlot ?? 1,
      routerAbNormalSigning: {
        kind: 'router_ab_ed25519_normal_signing_v1',
        signingWorkerId: 'ed25519-sealed-runtime-worker',
      },
    },
  });
  if (!record || record.curve !== 'ed25519') {
    throw new Error('Failed to build Passkey Ed25519 sealed-session fixture');
  }
  return record;
}

export function buildPasskeyEd25519AuthorizationProjectionFixture(
  record: CurrentEd25519SealedSessionRecord,
  args: {
    authorizationId?: string;
    walletSessionId?: string;
    quotaId?: string;
    authorizationExpiresAtMs?: number;
    remainingUses?: number;
  } = {},
) {
  if (!('credentialIdB64u' in record.ed25519Restore)) {
    throw new Error('passkey Ed25519 authorization fixture requires passkey restore metadata');
  }
  const authority = buildPasskeyWalletAuthAuthority({
    walletId: record.walletId,
    rpId: record.ed25519Restore.rpId,
    credentialIdB64u: record.ed25519Restore.credentialIdB64u,
  });
  const selectedAuthority = buildActiveEd25519WalletAuthorityFixture({
    record,
    factorAuthority: authority,
  });
  const selectedAuthMethod = buildWalletAuthMethodRecordV2({
    version: 'wallet_auth_method_v2',
    walletAuthMethodId: authority.bindingId,
    walletId: authority.walletId,
    walletAuthorityId: selectedAuthority.authorityId,
    kind: 'passkey',
    status: 'active',
    rpId: authority.verifier.rpId,
    credentialIdB64u: authority.factor.credentialIdB64u,
    credentialPublicKeyB64u: base64UrlEncode(new Uint8Array(65).fill(8)),
    counter: 0,
    createdAtMs: 1,
    updatedAtMs: 2,
    activatedAtMs: 2,
  });
  if (selectedAuthMethod.status !== 'active') {
    throw new Error('sealed Ed25519 authorization fixture requires an active method');
  }
  return buildExactEd25519AuthorizationFixture({
    record,
    selectedAuthority,
    selectedAuthMethod,
    selectedFactorAuthority: authority,
    ...args,
  });
}

export function buildEmailOtpEd25519SealedSessionRecordFixture(
  args: {
    walletId?: string;
    nearAccountId?: string;
    nearEd25519SigningKeyId?: string;
    thresholdSessionId?: string;
    expiresAtMs?: number;
    remainingUses?: number;
    materialActivation?: MpcMaterialActivationRef;
  } = {},
): CurrentEd25519SealedSessionRecord {
  const walletId = args.walletId ?? 'email-otp-ed25519-sealed-runtime-wallet';
  const thresholdSessionId = args.thresholdSessionId ?? 'email-otp-ed25519-sealed-runtime-session';
  const record = buildCurrentSealedSessionRecord({
    curve: 'ed25519',
    authMethod: 'email_otp',
    thresholdSessionId,
    thresholdSessionIds: { ed25519: thresholdSessionId },
    walletId,
    signingRootId: 'email-otp-ed25519-sealed-runtime-project:test',
    signingRootVersion: 'v1',
    relayerUrl: 'https://relay.example.test',
    sealedSecretB64u: 'email-otp-ed25519-sealed-runtime-secret',
    keyVersion: 'email-otp-ed25519-sealed-runtime-kek',
    groupId: SIGNING_SESSION_SEAL_GROUP_ID,
    issuedAtMs: 1,
    expiresAtMs: args.expiresAtMs ?? 1_900_000_000_000,
    remainingUses: args.remainingUses ?? 3,
    updatedAtMs: 2,
    ed25519Restore: {
      nearAccountId: args.nearAccountId ?? 'email-otp-ed25519-runtime.testnet',
      nearEd25519SigningKeyId: args.nearEd25519SigningKeyId ?? 'email-otp-ed25519-runtime-key',
      rpId: 'wallet.example.test',
      provider: 'google',
      providerSubjectId: 'google:email-otp-ed25519-runtime',
      emailHashHex: 'email-otp-ed25519-runtime-hash',
      materialActivation:
        args.materialActivation ??
        buildMpcMaterialActivationRefFixture('email-otp-ed25519-runtime-material', walletId),
      relayerKeyId: 'email-otp-ed25519-runtime-worker',
      participantIds: [1, 2],
      runtimePolicyScope: {
        orgId: 'email-otp-ed25519-runtime-org',
        projectId: 'email-otp-ed25519-sealed-runtime-project',
        envId: 'test',
        signingRootVersion: 'v1',
      },
      signerSlot: 1,
      routerAbNormalSigning: {
        kind: 'router_ab_ed25519_normal_signing_v1',
        signingWorkerId: 'email-otp-ed25519-runtime-worker',
      },
    },
  });
  if (!record || record.curve !== 'ed25519') {
    throw new Error('Failed to build Email OTP Ed25519 sealed-session fixture');
  }
  return record;
}

export function buildEmailOtpEd25519AuthorizationProjectionFixture(
  record: CurrentEd25519SealedSessionRecord,
  args: {
    authorizationId?: string;
    walletSessionId?: string;
    quotaId?: string;
    authorizationExpiresAtMs?: number;
    remainingUses?: number;
  } = {},
) {
  if (!('provider' in record.ed25519Restore)) {
    throw new Error('Email OTP Ed25519 authorization fixture requires provider restore metadata');
  }
  const authority = buildEmailOtpWalletAuthAuthority({
    walletId: record.walletId,
    provider: record.ed25519Restore.provider,
    providerUserId: record.ed25519Restore.providerSubjectId,
    emailHashHex: record.ed25519Restore.emailHashHex,
  });
  const selectedAuthority = buildActiveEd25519WalletAuthorityFixture({
    record,
    factorAuthority: authority,
  });
  const selectedAuthMethod = buildWalletAuthMethodRecordV2({
    version: 'wallet_auth_method_v2',
    walletAuthMethodId: authority.bindingId,
    walletId: authority.walletId,
    walletAuthorityId: selectedAuthority.authorityId,
    kind: 'email_otp',
    status: 'active',
    emailHashHex: authority.verifier.emailHashHex,
    registrationAuthorityId: String(selectedAuthority.authorityId),
    createdAtMs: 1,
    updatedAtMs: 2,
    activatedAtMs: 2,
  });
  if (selectedAuthMethod.status !== 'active') {
    throw new Error('sealed Ed25519 authorization fixture requires an active method');
  }
  return buildExactEd25519AuthorizationFixture({
    record,
    selectedAuthority,
    selectedAuthMethod,
    selectedFactorAuthority: authority,
    ...args,
  });
}

export function buildEmailOtpEd25519YaoActiveClientMetadataFixture(
  record: CurrentEd25519SealedSessionRecord,
): RouterAbEd25519YaoActiveClientMetadataV1 {
  const restore = record.ed25519Restore;
  if (
    !('provider' in restore) ||
    !record.signingRootId ||
    !record.signingRootVersion ||
    restore.participantIds.length !== 2
  ) {
    throw new Error('Email OTP fixture is missing exact Ed25519 publication metadata');
  }
  const participantIds = [restore.participantIds[0], restore.participantIds[1]] as const;
  return {
    kind: 'router_ab_ed25519_yao_active_client_v1',
    scope: {
      lifecycle_id: 'email-otp-sealed-publication-test',
      root_share_epoch: record.signingRootVersion,
      account_id: record.walletId,
      threshold_session_id: record.thresholdSessionIds.ed25519,
      signer_set_id: `near_ed25519:slot:${restore.signerSlot}`,
      signing_worker_id: restore.relayerKeyId,
      material_activation: routerAbMpcMaterialActivationRefToWire(restore.materialActivation),
    },
    applicationBinding: {
      wallet_id: record.walletId,
      near_ed25519_signing_key_id: restore.nearEd25519SigningKeyId,
      signing_root_id: record.signingRootId,
      key_creation_signer_slot: restore.signerSlot,
    },
    participantIds,
    registeredPublicKey: new Uint8Array(32),
    signingWorkerVerifyingShare: new Uint8Array(32),
    stateEpoch: 1n,
    transcript: new Uint8Array(32),
    activeCapabilityBinding: new Array<number>(32).fill(0),
    materialActivation: restore.materialActivation,
  };
}

export type EmailOtpEcdsaSealedSigningSessionRecord = Extract<
  SealedSigningSessionRecord,
  { curve: 'ecdsa' }
>;

export type EmailOtpEcdsaSealedRestorePayload = NonNullable<
  EmailOtpEcdsaSealedSigningSessionRecord['ecdsaRestore']
>;

type EmailOtpEcdsaSealedFixtureParts = {
  walletId: string;
  thresholdSessionId: string;
  relayerUrl: string;
  restore: EmailOtpEcdsaSealedRestorePayload;
};

function fixtureSealedEcdsaWalletSessionToken(args: {
  walletId: string;
  keyHandle: string;
  thresholdSessionId: string;
}): string {
  return `opaque-wallet-session-token:ecdsa:${args.walletId}:${args.keyHandle}:${args.thresholdSessionId}`;
}

function emailOtpEcdsaSealedFixtureParts(
  args: { walletId?: string } = {},
): EmailOtpEcdsaSealedFixtureParts {
  const walletId = args.walletId ?? 'alice.testnet';
  const providerSubjectId = `google:${walletId.split('.')[0]}`;
  const emailOtpAuthority = buildEmailOtpWalletAuthAuthority({
    walletId,
    provider: 'google',
    providerUserId: providerSubjectId,
    emailHashHex: 'email-hash',
  });
  const signingRootId = 'root:dev';
  const signingRootVersion = 'v1';
  const bootstrap = createThresholdEcdsaBootstrapFixture({
    nearAccountId: walletId,
    chain: 'tempo',
    roleLocalAuthMethod: 'email_otp',
    emailOtpAuthSubjectId: providerSubjectId,
    signingRootId,
    signingRootVersion,
    keyHandle: 'key-handle',
    relayerKeyId: 'relayer-key',
    sessionId: 'ec-session',
    walletSessionToken: fixtureSealedEcdsaWalletSessionToken({
      walletId,
      keyHandle: 'key-handle',
      thresholdSessionId: 'ec-session',
    }),
  });
  const keyRef = bootstrap.thresholdEcdsaKeyRef;
  const backendBinding = keyRef.backendBinding;
  if (backendBinding?.materialKind !== 'role_local_ready_state_blob') {
    throw new Error('Sealed-session fixture requires a role-local ready ECDSA backend binding');
  }
  const routerAbEcdsaDerivationNormalSigning = keyRef.routerAbEcdsaDerivationNormalSigning;
  if (!routerAbEcdsaDerivationNormalSigning) {
    throw new Error('Sealed-session fixture requires Router A/B ECDSA normal-signing state');
  }
  if (!keyRef.keyHandle || !keyRef.ethereumAddress) {
    throw new Error('Sealed-session fixture requires ECDSA bootstrap facts');
  }
  return {
    walletId,
    thresholdSessionId: bootstrap.session.thresholdSessionId,
    relayerUrl: keyRef.relayerUrl,
    restore: {
      chainTarget: keyRef.chainTarget,
      source: 'email_otp',
      signingRootId,
      signingRootVersion,
      provider: 'google',
      providerSubjectId,
      emailHashHex: 'email-hash',
      authority: buildWalletAuthAuthorityRefForAuthorityFixture(emailOtpAuthority),
      emailOtpAuthority,
      keyHandle: keyRef.keyHandle,
      ecdsaThresholdKeyId: keyRef.ecdsaThresholdKeyId,
      ethereumAddress: keyRef.ethereumAddress,
      relayerKeyId: backendBinding.relayerKeyId,
      roleLocalMaterialRef: buildEcdsaRoleLocalPersistedMaterialRefFixture({
        durableMaterialRef: 'role-local-material',
        bindingDigest: backendBinding.ecdsaRoleLocalReadyRecord.publicFacts.contextBinding32B64u,
        materialOwner: walletId,
      }),
      participantIds: [...(keyRef.participantIds || [1, 2])],
      routerAbEcdsaDerivationNormalSigning,
      publicCapability: backendBinding.ecdsaRoleLocalReadyRecord.publicFacts.publicCapability,
    },
  };
}

/**
 * Email OTP + ECDSA sealed restore payload (the `ecdsaRestore` sub-object of a
 * current sealed signing-session record), for tests that drive the production
 * `buildCurrentSealedSessionRecord` path with per-test session identity. The
 * embedded Wallet Session JWT claims follow `walletId`, which must match the
 * sealed record's `walletId` for current-record classification.
 */
export function seedEmailOtpEcdsaSealedRestorePayload(
  args: { walletId?: string } = {},
): EmailOtpEcdsaSealedRestorePayload {
  return emailOtpEcdsaSealedFixtureParts(args).restore;
}

/**
 * Email OTP + ECDSA sealed signing-session record on the current
 * `SealedSigningSessionRecord` shape (mirrors the canonical type fixture in
 * `packages/shared-ts/src/utils/signingSessionSeal.typecheck.ts`). The Router A/B
 * ECDSA normal-signing state and public capability come from the shared bootstrap
 * fixture, which builds them through the production parse functions.
 */
export function seedEmailOtpEcdsaSealedSigningSessionRecord(
  overrides: Partial<EmailOtpEcdsaSealedSigningSessionRecord> = {},
): EmailOtpEcdsaSealedSigningSessionRecord {
  const { walletId, thresholdSessionId, relayerUrl, restore } = emailOtpEcdsaSealedFixtureParts();
  const record: EmailOtpEcdsaSealedSigningSessionRecord = {
    v: SIGNING_SESSION_SEALED_RECORD_VERSION,
    alg: SIGNING_SESSION_SEAL_ALG,
    storageScope: SIGNING_SESSION_SEAL_STORAGE_SCOPE,
    authMethod: 'email_otp',
    secretKind: SIGNING_SESSION_SECRET_KIND,
    storeKey: ecdsaSealedRecordStoreKey({
      walletId,
      authMethod: 'email_otp',
      chainTarget: restore.chainTarget,
      materialActivation: restore.roleLocalMaterialRef.materialActivation,
    }),
    thresholdSessionIds: {
      ecdsa: thresholdSessionId,
    },
    sealedSecretB64u: 'sealed-k',
    curve: 'ecdsa',
    walletId,
    relayerUrl,
    ecdsaRestore: restore,
    keyVersion: 'signing-session-seal-kek-test-r1',
    groupId: SIGNING_SESSION_SEAL_GROUP_ID,
    issuedAtMs: 1,
    expiresAtMs: 2,
    remainingUses: 3,
    updatedAtMs: 4,
  };
  return { ...record, ...overrides };
}

type EmailOtpEcdsaSealedRuntimeFixtureCorruption =
  | { kind: 'blank_binding_digest' }
  | { kind: 'blank_relayer_url' }
  | {
      kind: 'foreign_material_activation';
      materialActivation: CurrentEcdsaSealedSessionRecord['ecdsaRestore']['roleLocalMaterialRef']['materialActivation'];
    }
  | {
      kind: 'authority_mismatch';
      authority: CurrentEcdsaSealedSessionRecord['ecdsaRestore']['authority'];
    }
  | { kind: 'participant_ids'; participantIds: number[] }
  | { kind: 'remaining_uses'; remainingUses: number }
  | { kind: 'expires_at_ms'; expiresAtMs: number }
  | { kind: 'normal_signing_wallet_id'; walletId: string }
  | { kind: 'relayer_key_id'; relayerKeyId: string };

/** The scope the relayer issues at bootstrap and the sealed store persists.
 * Production requires it at the hydration boundary -- a signing session cannot
 * be built without one -- so a sealed runtime fixture without it can only ever
 * resolve to `runtime_policy_scope_missing`.
 *
 * Derived from the manifest's own signing root rather than hard-coded:
 * `normalizeSealedEcdsaRestore` drops any record whose explicit root ids
 * disagree with the ones this scope derives. */
function fixtureRuntimePolicyScope(publicFacts: {
  readonly signingRootId: unknown;
  readonly signingRootVersion: unknown;
}): { orgId: string; projectId: string; envId: string; signingRootVersion: string } {
  const signingRootId = String(publicFacts.signingRootId || '');
  const [projectId, envId] = signingRootId.split(':');
  if (!projectId || !envId) {
    throw new Error(
      `sealed runtime fixture requires a <projectId>:<envId> signing root id, got "${signingRootId}"`,
    );
  }
  return {
    orgId: 'org-sealed-runtime-fixture',
    projectId,
    envId,
    signingRootVersion: String(publicFacts.signingRootVersion || ''),
  };
}

export function buildEmailOtpEcdsaSealedRuntimeRecordFixture(args: {
  manifest: ActiveEcdsaCapabilityManifest;
  chainTarget?: ThresholdEcdsaChainTarget;
  thresholdSessionId?: string;
  expiresAtMs?: number;
  remainingUses?: number;
  corruption?: EmailOtpEcdsaSealedRuntimeFixtureCorruption;
}): CurrentEcdsaSealedSessionRecord {
  const manifest = args.manifest;
  const walletId = String(manifest.signer.walletId);
  const publicFacts = manifest.durableMaterial.roleLocalPublicFacts;
  const binding = manifest.durableMaterial.roleLocalBinding;
  const publicCapability = publicFacts.publicCapability;
  const chainTarget = args.chainTarget ?? publicFacts.chainTarget;
  const thresholdSessionId = args.thresholdSessionId ?? 'ec-session';
  const providerSubjectId = `google:${walletId}`;
  const emailOtpAuthority = buildEmailOtpWalletAuthAuthority({
    walletId,
    provider: 'google',
    providerUserId: providerSubjectId,
    emailHashHex: 'email-hash',
  });
  const roleLocalMaterialRef = parseEcdsaRoleLocalPersistedMaterialRef({
    kind: 'ecdsa_role_local_persisted_material_ref_v1',
    durableMaterialRef: manifest.durableMaterial.durableMaterialRef,
    bindingDigest: manifest.durableMaterial.bindingDigest,
    materialActivation: manifest.durableMaterial.materialActivation,
  });
  const normalSigning = requireRouterAbEcdsaDerivationNormalSigningStateV1({
    kind: ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_STATE_KIND_V1,
    scope: {
      wallet_id: walletId,
      ecdsa_threshold_key_id: publicFacts.ecdsaThresholdKeyId,
      signing_root_id: publicFacts.signingRootId,
      signing_root_version: publicFacts.signingRootVersion,
      context: publicCapability.context,
      public_identity: publicCapability.public_identity,
      signing_worker: publicCapability.signer_set.selected_server,
      activation_epoch: publicCapability.activation_epoch,
      material_activation: routerAbMpcMaterialActivationRefToWire(
        manifest.durableMaterial.materialActivation,
      ),
    },
  });
  const record = buildCurrentSealedSessionRecord({
    curve: 'ecdsa',
    thresholdSessionId,
    thresholdSessionIds: { ecdsa: thresholdSessionId },
    sealedSecretB64u: 'sealed-k',
    authMethod: 'email_otp',
    keyVersion: 'signing-session-seal-kek-test-r1',
    groupId: 'rfc2409-group2',
    issuedAtMs: 1,
    expiresAtMs: args.expiresAtMs ?? Date.now() + 5 * 60_000,
    remainingUses: args.remainingUses ?? 4,
    updatedAtMs: 4,
    walletId,
    relayerUrl: 'https://relayer.example.test',
    ecdsaRestore: {
      chainTarget,
      source: 'email_otp',
      signingRootId: publicFacts.signingRootId,
      signingRootVersion: publicFacts.signingRootVersion,
      runtimePolicyScope: fixtureRuntimePolicyScope(publicFacts),
      provider: 'google',
      providerSubjectId,
      emailHashHex: 'email-hash',
      authority: manifest.signer.authority,
      emailOtpAuthority,
      keyHandle: binding.keyHandle,
      ecdsaThresholdKeyId: binding.ecdsaThresholdKeyId,
      ethereumAddress: publicFacts.ethereumAddress,
      relayerKeyId: binding.relayerKeyId,
      clientVerifyingShareB64u: binding.clientVerifyingPublicKey33B64u,
      thresholdEcdsaPublicKeyB64u: publicFacts.groupPublicKey33B64u,
      roleLocalMaterialRef,
      participantIds: [...binding.participantIds],
      routerAbEcdsaDerivationNormalSigning: normalSigning,
      publicCapability,
    },
  });
  if (!record || record.curve !== 'ecdsa') {
    throw new Error('Failed to build exact Email OTP ECDSA sealed runtime fixture');
  }
  return corruptEmailOtpEcdsaSealedRuntimeRecordFixture(record, args.corruption);
}

export function buildEmailOtpInactiveEcdsaMaterialRecordFixture(args: {
  manifest: ActiveEcdsaCapabilityManifest;
  authorizationRetirementReason?: 'expired' | 'exhausted';
  corruption?: EmailOtpEcdsaSealedRuntimeFixtureCorruption;
}): EcdsaInactiveSealedMaterialRecord {
  const current = buildEmailOtpEcdsaSealedRuntimeRecordFixture(args);
  return inactiveEcdsaMaterialRecordFixture({
    current,
    authorizationRetirementReason: args.authorizationRetirementReason ?? 'expired',
  });
}

export function buildPasskeyInactiveEcdsaMaterialRecordFixture(args: {
  manifest: ActiveEcdsaCapabilityManifest;
  authorizationRetirementReason?: 'expired' | 'exhausted';
}): EcdsaInactiveSealedMaterialRecord {
  return inactiveEcdsaMaterialRecordFixture({
    current: buildPasskeyEcdsaSealedRuntimeRecordFixture(args),
    authorizationRetirementReason: args.authorizationRetirementReason ?? 'expired',
  });
}

function inactiveEcdsaMaterialRecordFixture(args: {
  current: CurrentEcdsaSealedSessionRecord;
  authorizationRetirementReason: 'expired' | 'exhausted';
}): EcdsaInactiveSealedMaterialRecord {
  const current = args.current;
  const restore = buildEcdsaInactiveMaterialPublicRestore(current.ecdsaRestore, current.relayerUrl);
  if (!restore) {
    throw new Error('Failed to build inactive Email OTP ECDSA restore fixture');
  }
  const storeKey = [
    'inactive-material',
    current.walletId,
    current.authMethod,
    'ecdsa',
    thresholdEcdsaChainTargetKey(restore.chainTarget),
    restore.roleLocalMaterialRef.materialActivation.activationId,
  ]
    .map((part) => encodeURIComponent(String(part).trim()))
    .join(':');
  const classification = classifyRawSealedSessionRecord({
    recordKind: 'ecdsa_inactive_sealed_material_v1',
    storeKey,
    curve: 'ecdsa',
    walletId: current.walletId,
    relayerUrl: current.relayerUrl,
    alg: current.alg,
    storageScope: current.storageScope,
    secretKind: current.secretKind,
    sealedSecretB64u: current.sealedSecretB64u,
    keyVersion: current.keyVersion,
    groupId: current.groupId,
    updatedAtMs: current.updatedAtMs,
    authorizationRetirementReason: args.authorizationRetirementReason,
    authMethod: current.authMethod,
    ecdsaRestore: restore,
  });
  if (classification.kind !== 'ecdsa_inactive_material') {
    throw new Error('Failed to classify inactive Email OTP ECDSA material fixture');
  }
  return classification.record;
}

/** Passkey counterpart of the Email OTP sealed runtime fixture. The sealed
 * record differs only in its auth binding -- rpId and credential rather than a
 * provider subject -- because the material it names is the same. */
export function buildPasskeyEcdsaSealedRuntimeRecordFixture(args: {
  manifest: ActiveEcdsaCapabilityManifest;
  chainTarget?: ThresholdEcdsaChainTarget;
  thresholdSessionId?: string;
  expiresAtMs?: number;
  remainingUses?: number;
}): CurrentEcdsaSealedSessionRecord {
  const manifest = args.manifest;
  const walletId = String(manifest.signer.walletId);
  const publicFacts = manifest.durableMaterial.roleLocalPublicFacts;
  const binding = manifest.durableMaterial.roleLocalBinding;
  const publicCapability = publicFacts.publicCapability;
  const chainTarget = args.chainTarget ?? publicFacts.chainTarget;
  const thresholdSessionId = args.thresholdSessionId ?? 'ec-session-passkey';
  const roleLocalMaterialRef = parseEcdsaRoleLocalPersistedMaterialRef({
    kind: 'ecdsa_role_local_persisted_material_ref_v1',
    durableMaterialRef: manifest.durableMaterial.durableMaterialRef,
    bindingDigest: manifest.durableMaterial.bindingDigest,
    materialActivation: manifest.durableMaterial.materialActivation,
  });
  const normalSigning = requireRouterAbEcdsaDerivationNormalSigningStateV1({
    kind: ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_STATE_KIND_V1,
    scope: {
      wallet_id: walletId,
      ecdsa_threshold_key_id: publicFacts.ecdsaThresholdKeyId,
      signing_root_id: publicFacts.signingRootId,
      signing_root_version: publicFacts.signingRootVersion,
      context: publicCapability.context,
      public_identity: publicCapability.public_identity,
      signing_worker: publicCapability.signer_set.selected_server,
      activation_epoch: publicCapability.activation_epoch,
      material_activation: routerAbMpcMaterialActivationRefToWire(
        manifest.durableMaterial.materialActivation,
      ),
    },
  });
  const record = buildCurrentSealedSessionRecord({
    curve: 'ecdsa',
    thresholdSessionId,
    thresholdSessionIds: { ecdsa: thresholdSessionId },
    sealedSecretB64u: 'sealed-k',
    authMethod: 'passkey',
    keyVersion: 'signing-session-seal-kek-test-r1',
    groupId: 'rfc2409-group2',
    issuedAtMs: 1,
    expiresAtMs: args.expiresAtMs ?? Date.now() + 5 * 60_000,
    remainingUses: args.remainingUses ?? 4,
    updatedAtMs: 4,
    walletId,
    relayerUrl: 'https://relayer.example.test',
    ecdsaRestore: {
      chainTarget,
      source: 'login',
      signingRootId: publicFacts.signingRootId,
      signingRootVersion: publicFacts.signingRootVersion,
      runtimePolicyScope: fixtureRuntimePolicyScope(publicFacts),
      rpId: 'example.localhost',
      credentialIdB64u: 'credential-passkey-fixture',
      authority: manifest.signer.authority,
      keyHandle: binding.keyHandle,
      ecdsaThresholdKeyId: binding.ecdsaThresholdKeyId,
      ethereumAddress: publicFacts.ethereumAddress,
      relayerKeyId: binding.relayerKeyId,
      clientVerifyingShareB64u: binding.clientVerifyingPublicKey33B64u,
      thresholdEcdsaPublicKeyB64u: publicFacts.groupPublicKey33B64u,
      roleLocalMaterialRef,
      participantIds: [...binding.participantIds],
      routerAbEcdsaDerivationNormalSigning: normalSigning,
      publicCapability,
    },
  });
  if (!record || record.curve !== 'ecdsa') {
    throw new Error('Failed to build exact passkey ECDSA sealed runtime fixture');
  }
  return record;
}

function corruptEmailOtpEcdsaSealedRuntimeRecordFixture(
  record: CurrentEcdsaSealedSessionRecord,
  corruption: EmailOtpEcdsaSealedRuntimeFixtureCorruption | undefined,
): CurrentEcdsaSealedSessionRecord {
  if (!corruption) return record;
  switch (corruption.kind) {
    case 'blank_binding_digest':
      return {
        ...record,
        ecdsaRestore: {
          ...record.ecdsaRestore,
          roleLocalMaterialRef: {
            ...record.ecdsaRestore.roleLocalMaterialRef,
            bindingDigest: '',
          },
        },
      };
    case 'blank_relayer_url':
      return { ...record, relayerUrl: '   ' };
    case 'foreign_material_activation':
      return {
        ...record,
        ecdsaRestore: {
          ...record.ecdsaRestore,
          roleLocalMaterialRef: {
            ...record.ecdsaRestore.roleLocalMaterialRef,
            materialActivation: corruption.materialActivation,
          },
        },
      };
    case 'authority_mismatch':
      return {
        ...record,
        ecdsaRestore: { ...record.ecdsaRestore, authority: corruption.authority },
      };
    case 'participant_ids':
      return {
        ...record,
        ecdsaRestore: { ...record.ecdsaRestore, participantIds: corruption.participantIds },
      };
    case 'remaining_uses':
      return { ...record, remainingUses: corruption.remainingUses };
    case 'expires_at_ms':
      return { ...record, expiresAtMs: corruption.expiresAtMs };
    case 'normal_signing_wallet_id':
      return {
        ...record,
        ecdsaRestore: {
          ...record.ecdsaRestore,
          routerAbEcdsaDerivationNormalSigning: {
            ...record.ecdsaRestore.routerAbEcdsaDerivationNormalSigning,
            scope: {
              ...record.ecdsaRestore.routerAbEcdsaDerivationNormalSigning.scope,
              wallet_id: corruption.walletId,
            },
          },
        },
      };
    case 'relayer_key_id':
      return {
        ...record,
        ecdsaRestore: { ...record.ecdsaRestore, relayerKeyId: corruption.relayerKeyId },
      };
  }
}

/**
 * Expired Wallet Session authorization state built through the production
 * boundary parser, so identity fields (walletId, walletSessionId, authMethod)
 * always derive from the supplied lane identity.
 */
export function seedExpiredWalletSessionAuthorizationState(args: {
  identity: ExactEd25519SigningLaneIdentity;
  expiresAtMs?: number;
  detectedAtMs?: number;
}): ExpiredWalletSessionAuthorizationState {
  const expiresAtMs = args.expiresAtMs ?? 1_000;
  return requireAuthoritativeExpiredWalletSessionAuthorizationBoundary({
    source: { kind: 'ed25519', laneIdentity: args.identity },
    expiresAtMs,
    detectedAtMs: args.detectedAtMs ?? expiresAtMs + 1,
  });
}
