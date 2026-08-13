import {
  SIGNING_SESSION_SEALED_RECORD_VERSION,
  SIGNING_SESSION_SEAL_ALG,
  SIGNING_SESSION_SEAL_GROUP_ID,
  SIGNING_SESSION_SEAL_STORAGE_SCOPE,
  SIGNING_SESSION_SECRET_KIND,
  type SealedSigningSessionRecord,
} from '@shared/utils/signingSessionSeal';
import {
  ROUTER_AB_ECDSA_DERIVATION_WALLET_SESSION_JWT_KIND,
  ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND,
} from '@shared/utils/sessionTokens';
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
} from '@shared/utils/walletAuthAuthority';
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
import { buildActiveWalletSessionAuthorizationProjection } from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import {
  parseMpcWalletSigningQuotaId,
  parseSeamsSessionId,
  parseWalletSessionAuthorizationId,
  parseWalletSessionId,
} from '@shared/authorization/capabilityKinds';
import type { MpcMaterialActivationRef } from '@shared/utils/domainIds';
import type { RouterAbEd25519YaoActiveClientMetadataV1 } from '@/core/signingEngine/threshold/ed25519/yaoClient';

function requireFixtureDomainId<T>(
  result: { ok: true; value: T } | { ok: false; error: unknown },
): T {
  if (!result.ok) throw new Error('invalid sealed-session fixture domain id');
  return result.value;
}

function encodeFixtureJwtPart(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString('base64url');
}

function fixtureJwt(kind: string, claims: Record<string, unknown>): string {
  return [
    encodeFixtureJwtPart({ alg: 'none', typ: 'JWT' }),
    encodeFixtureJwtPart({ kind, ...claims }),
    'fixture',
  ].join('.');
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
      credentialIdB64u: 'ed25519-sealed-runtime-credential',
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
      signerSlot: 1,
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
    authorizationSessionId?: string;
    walletSessionId?: string;
    quotaId?: string;
    authorizationExpiresAtMs?: number;
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
  const authorizationSessionId =
    args.authorizationSessionId ?? `authorization:${record.thresholdSessionIds.ed25519}`;
  const authorizationId = `wallet-session-authorization:${record.thresholdSessionIds.ed25519}`;
  const walletSessionId =
    args.walletSessionId ?? `wallet-session:${record.thresholdSessionIds.ed25519}`;
  const quotaId = args.quotaId ?? `quota:${record.thresholdSessionIds.ed25519}`;
  const authorizationExpiresAtMs = args.authorizationExpiresAtMs ?? record.expiresAtMs;
  return buildActiveWalletSessionAuthorizationProjection({
    walletId: authority.walletId,
    seamsSessionId: requireFixtureDomainId(parseSeamsSessionId(authorizationSessionId)),
    authorizationId: requireFixtureDomainId(parseWalletSessionAuthorizationId(authorizationId)),
    walletSessionId: requireFixtureDomainId(parseWalletSessionId(walletSessionId)),
    quotaId: requireFixtureDomainId(parseMpcWalletSigningQuotaId(quotaId)),
    walletSessionTokens: {
      kind: 'near_ed25519',
      ed25519: {
        walletSessionJwt: fixtureJwt(ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND, {
          authorizationKind: 'owner_wallet_session',
          walletId: record.walletId,
          authorizationId,
          nearAccountId: record.ed25519Restore.nearAccountId,
          nearEd25519SigningKeyId: record.ed25519Restore.nearEd25519SigningKeyId,
          walletSessionId,
          quotaId,
          thresholdSessionId: record.thresholdSessionIds.ed25519,
          sid: authorizationSessionId,
          thresholdExpiresAtMs: authorizationExpiresAtMs,
          exp: Math.floor(authorizationExpiresAtMs / 1_000),
        }),
      },
    },
    authMethod: 'passkey',
    authority: buildWalletAuthAuthorityRefForAuthorityFixture(authority),
    expiresAtMs: authorizationExpiresAtMs,
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
  return buildActiveWalletSessionAuthorizationProjection({
    walletId: authority.walletId,
    seamsSessionId: requireFixtureDomainId(
      parseSeamsSessionId(`authorization:${record.thresholdSessionIds.ed25519}`),
    ),
    authorizationId: requireFixtureDomainId(
      parseWalletSessionAuthorizationId(
        `wallet-session-authorization:${record.thresholdSessionIds.ed25519}`,
      ),
    ),
    walletSessionId: requireFixtureDomainId(
      parseWalletSessionId(`wallet-session:${record.thresholdSessionIds.ed25519}`),
    ),
    quotaId: requireFixtureDomainId(
      parseMpcWalletSigningQuotaId(`quota:${record.thresholdSessionIds.ed25519}`),
    ),
    walletSessionTokens: {
      kind: 'near_ed25519',
      ed25519: {
        walletSessionJwt: fixtureJwt(ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND, {
          authorizationKind: 'owner_wallet_session',
          walletId: record.walletId,
          authorizationId: `wallet-session-authorization:${record.thresholdSessionIds.ed25519}`,
          nearAccountId: record.ed25519Restore.nearAccountId,
          nearEd25519SigningKeyId: record.ed25519Restore.nearEd25519SigningKeyId,
          walletSessionId: `wallet-session:${record.thresholdSessionIds.ed25519}`,
          quotaId: `quota:${record.thresholdSessionIds.ed25519}`,
          thresholdSessionId: record.thresholdSessionIds.ed25519,
          sid: `authorization:${record.thresholdSessionIds.ed25519}`,
          thresholdExpiresAtMs: record.expiresAtMs,
          exp: Math.floor(record.expiresAtMs / 1_000),
        }),
      },
    },
    authMethod: 'email_otp',
    authority: buildWalletAuthAuthorityRefForAuthorityFixture(authority),
    expiresAtMs: record.expiresAtMs,
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

/** ECDSA bootstrap still needs a transport JWT; restore metadata does not. */
function fixtureSealedEcdsaWalletSessionJwt(args: {
  walletId: string;
  keyHandle: string;
  thresholdSessionId: string;
}): string {
  const encode = (value: unknown): string =>
    Buffer.from(JSON.stringify(value)).toString('base64url');
  return [
    encode({ alg: 'none', typ: 'JWT' }),
    encode({
      kind: ROUTER_AB_ECDSA_DERIVATION_WALLET_SESSION_JWT_KIND,
      authorizationKind: 'owner_wallet_session',
      sub: args.walletId,
      walletId: args.walletId,
      keyHandle: args.keyHandle,
      thresholdSessionId: args.thresholdSessionId,
      thresholdExpiresAtMs: Date.now() + 120_000,
    }),
    'fixture',
  ].join('.');
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
    walletSessionJwt: fixtureSealedEcdsaWalletSessionJwt({
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
