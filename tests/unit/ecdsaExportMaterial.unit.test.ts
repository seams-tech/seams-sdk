import { expect, test } from '@playwright/test';
import { base64UrlEncode } from '@shared/utils/base64';
import { deriveEvmFamilySigningKeySlotId } from '@shared/signing-lanes';
import { ROUTER_AB_ECDSA_HSS_WALLET_SESSION_JWT_KIND } from '@shared/utils/sessionTokens';
import {
  toWalletId,
  type ThresholdEcdsaChainTarget,
} from '../../packages/sdk-web/src/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  buildEcdsaRoleLocalEmailOtpAuthMethod,
  buildEcdsaRoleLocalPasskeyAuthMethod,
  buildEcdsaRoleLocalPublicFacts,
  buildEcdsaRoleLocalReadyRecord,
} from '../../packages/sdk-web/src/core/platform';
import {
  buildVerifiedEcdsaPublicFacts,
  buildEvmFamilyEcdsaKeyIdentityFromRecord,
  toEvmFamilyEcdsaKeyHandle,
  toRpId,
  toThresholdOwnerAddress,
  toVerifiedEcdsaPublicFactsFromRecord,
} from '../../packages/sdk-web/src/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import { SigningSessionIds } from '../../packages/sdk-web/src/core/signingEngine/session/operationState/types';
import {
  buildEvmFamilyEcdsaSignerBinding,
  exactEcdsaSigningLaneIdentity,
} from '../../packages/sdk-web/src/core/signingEngine/session/identity/exactSigningLaneIdentity';
import {
  deriveThresholdEcdsaRuntimeLaneKey,
  type ThresholdEcdsaSessionRecord,
} from '../../packages/sdk-web/src/core/signingEngine/session/persistence/records';
import type {
  ThresholdEcdsaEmailOtpAuthContext,
  ThresholdEcdsaSessionStoreSource,
} from '../../packages/sdk-web/src/core/signingEngine/session/identity/laneIdentity';
import {
  buildEmailOtpAuthContextForWalletAuthMethod,
  emailOtpAuthContextProviderUserId,
} from '../../packages/sdk-web/src/core/signingEngine/session/identity/laneIdentity';
import {
  resolveEcdsaExportMaterialForLane,
  resolveFreshEmailOtpEcdsaExportMaterialForLane,
  type EcdsaExportSessionStoreDeps,
  type ExactEcdsaExportLane,
} from '../../packages/sdk-web/src/core/signingEngine/flows/recovery/ecdsaExportMaterial';
import {
  buildEcdsaHssExportAuthorizationDigestInput,
} from '../../packages/sdk-web/src/core/signingEngine/flows/recovery/ecdsaHssExport';
import { exportThresholdEcdsaKeyWithFreshEmailOtpRouteAuth } from '../../packages/sdk-web/src/core/signingEngine/flows/recovery/ecdsaExportFlow';
import type { ThresholdEcdsaCanonicalExportArtifact } from '../../packages/sdk-web/src/core/signingEngine/interfaces/signing';
import type { RouterAbEcdsaHssNormalSigningStateV1 } from '../../packages/shared-ts/src/utils/routerAbEcdsaHss';
import { markRouterAbEcdsaHssWorkerMaterialRuntimeValidated } from '../../packages/sdk-web/src/core/signingEngine/session/routerAbSigningWalletSession';

const WALLET_ID = toWalletId('alice.testnet');
const RP_ID = 'localhost';
const SIGNING_ROOT_ID = 'project-export:env-export';
const SIGNING_ROOT_VERSION = 'default';
const EMAIL_OTP_EMAIL_HASH_HEX = 'email-hash-export';
const EVM_FAMILY_SIGNING_KEY_SLOT_ID = deriveEvmFamilySigningKeySlotId({
  walletId: WALLET_ID,
  signingRootId: SIGNING_ROOT_ID,
  signingRootVersion: SIGNING_ROOT_VERSION,
});
const OWNER_ADDRESS = '0x1111111111111111111111111111111111111111';
const PUBLIC_KEY_B64U = 'AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const PASSKEY_EXPORT_CREDENTIAL_ID_B64U = 'export-passkey-credential';
const HSS_CLIENT_PUBLIC_KEY_B64U = base64UrlEncode(Uint8Array.from([2, ...Array(32).fill(1)]));
const RELAYER_PUBLIC_KEY_B64U = base64UrlEncode(Uint8Array.from([3, ...Array(32).fill(2)]));
const CONTEXT_BINDING_32_B64U = base64UrlEncode(new Uint8Array(32).fill(5));
const APPLICATION_BINDING_DIGEST_B64U = base64UrlEncode(new Uint8Array(32).fill(7));
const READY_STATE_BLOB_B64U = base64UrlEncode(new Uint8Array(96).fill(6));

const EVM_TARGET: ThresholdEcdsaChainTarget = {
  kind: 'evm',
  namespace: 'eip155',
  chainId: 5042002,
  networkSlug: 'arc-testnet',
};

function ethereumAddress20B64u(address: string): string {
  return Buffer.from(address.replace(/^0x/i, ''), 'hex').toString('base64url');
}

function unsignedJwt(payload: Record<string, unknown>): string {
  const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  return `${header}.${body}.sig`;
}

function thresholdEcdsaSessionJwtFixture(args: {
  thresholdSessionId: string;
  signingGrantId: string;
  keyHandle: string;
  thresholdExpiresAtMs?: number;
  participantIds?: readonly number[];
}): string {
  return unsignedJwt({
    kind: ROUTER_AB_ECDSA_HSS_WALLET_SESSION_JWT_KIND,
    sub: WALLET_ID,
    walletId: WALLET_ID,
    keyHandle: args.keyHandle,
    keyScope: 'evm-family',
    chainTarget: EVM_TARGET,
    relayerKeyId: 'relayer-key',
    evmFamilySigningKeySlotId: EVM_FAMILY_SIGNING_KEY_SLOT_ID,
    thresholdSessionId: args.thresholdSessionId,
    signingGrantId: args.signingGrantId,
    thresholdExpiresAtMs: args.thresholdExpiresAtMs ?? 1_900_000_000_000,
    participantIds: args.participantIds ?? [1, 2],
    exp: Math.floor(Date.now() / 1000) + 3600,
  });
}

function makeRouterAbEcdsaHssNormalSigningState(record: {
  walletId: ThresholdEcdsaSessionRecord['walletId'];
  ecdsaThresholdKeyId: ThresholdEcdsaSessionRecord['ecdsaThresholdKeyId'];
  signingRootId: ThresholdEcdsaSessionRecord['signingRootId'];
  signingRootVersion?: ThresholdEcdsaSessionRecord['signingRootVersion'];
}): RouterAbEcdsaHssNormalSigningStateV1 {
  return {
    kind: 'router_ab_ecdsa_hss_normal_signing_v1',
    scope: {
      wallet_key_id: EVM_FAMILY_SIGNING_KEY_SLOT_ID,
      wallet_id: String(record.walletId),
      ecdsa_threshold_key_id: String(record.ecdsaThresholdKeyId),
      signing_root_id: String(record.signingRootId),
      signing_root_version: String(record.signingRootVersion || SIGNING_ROOT_VERSION),
      context: {
        application_binding_digest_b64u: 'BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc',
      },
      public_identity: {
        context_binding_b64u: CONTEXT_BINDING_32_B64U,
        client_public_key33_b64u: HSS_CLIENT_PUBLIC_KEY_B64U,
        server_public_key33_b64u: RELAYER_PUBLIC_KEY_B64U,
        threshold_public_key33_b64u: PUBLIC_KEY_B64U,
        ethereum_address20_b64u: ethereumAddress20B64u(OWNER_ADDRESS),
        client_share_retry_counter: 0,
        server_share_retry_counter: 0,
      },
      signing_worker: {
        server_id: 'signing-worker-1',
        key_epoch: 'worker-epoch-1',
        recipient_encryption_key:
          'x25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      },
      activation_epoch: 'activation-1',
    },
  };
}

function makeVerifiedPublicFacts(keyHandle: string) {
  return buildVerifiedEcdsaPublicFacts({
    keyHandle: toEvmFamilyEcdsaKeyHandle(keyHandle),
    publicKeyB64u: PUBLIC_KEY_B64U,
    participantIds: [1, 2],
    thresholdOwnerAddress: OWNER_ADDRESS,
  });
}

function runtimeValidatedExportRecord<T extends ThresholdEcdsaSessionRecord>(record: T): T {
  if (record.thresholdSessionKind !== 'jwt') return record;
  if (!markRouterAbEcdsaHssWorkerMaterialRuntimeValidated(record)) {
    throw new Error('export fixture record failed Router A/B ECDSA runtime validation');
  }
  return record;
}

type EmailOtpEcdsaSessionRecord = Extract<ThresholdEcdsaSessionRecord, { source: 'email_otp' }>;
type PasskeyEcdsaSessionRecord = Exclude<ThresholdEcdsaSessionRecord, { source: 'email_otp' }>;
type EmailOtpExportRecordFixtureInput = {
  ecdsaThresholdKeyId?: EmailOtpEcdsaSessionRecord['ecdsaThresholdKeyId'];
  walletSessionJwt?: EmailOtpEcdsaSessionRecord['walletSessionJwt'];
  thresholdSessionKind?: EmailOtpEcdsaSessionRecord['thresholdSessionKind'];
  thresholdSessionId?: EmailOtpEcdsaSessionRecord['thresholdSessionId'];
  signingGrantId?: EmailOtpEcdsaSessionRecord['signingGrantId'];
  thresholdEcdsaPublicKeyB64u?: EmailOtpEcdsaSessionRecord['thresholdEcdsaPublicKeyB64u'];
};
type PasskeyExportRecordFixtureInput = {
  expiresAtMs?: PasskeyEcdsaSessionRecord['expiresAtMs'];
  walletSessionJwt?: PasskeyEcdsaSessionRecord['walletSessionJwt'];
  thresholdExpiresAtMs?: number;
  participantIds?: readonly number[];
};

function makeReadyRecordForExport(record: {
  walletId: ThresholdEcdsaSessionRecord['walletId'];
  chainTarget: ThresholdEcdsaSessionRecord['chainTarget'];
  keyHandle: ThresholdEcdsaSessionRecord['keyHandle'];
  ecdsaThresholdKeyId: ThresholdEcdsaSessionRecord['ecdsaThresholdKeyId'];
  signingRootId: ThresholdEcdsaSessionRecord['signingRootId'];
  signingRootVersion?: ThresholdEcdsaSessionRecord['signingRootVersion'];
  source: ThresholdEcdsaSessionStoreSource;
  emailOtpAuthContext?: ThresholdEcdsaEmailOtpAuthContext;
}) {
  const authMethod =
    record.source === 'email_otp'
      ? buildEcdsaRoleLocalEmailOtpAuthMethod({
          authSubjectId: record.emailOtpAuthContext
            ? emailOtpAuthContextProviderUserId(record.emailOtpAuthContext)
            : undefined,
        })
      : buildEcdsaRoleLocalPasskeyAuthMethod({
          credentialIdB64u: PASSKEY_EXPORT_CREDENTIAL_ID_B64U,
          rpId: RP_ID,
        });
  return buildEcdsaRoleLocalReadyRecord({
    stateBlob: {
      kind: 'ecdsa_role_local_state_blob_v1',
      curve: 'secp256k1',
      encoding: 'base64url',
      producer: 'signer_core',
      stateBlobB64u: READY_STATE_BLOB_B64U,
    },
    publicFacts: buildEcdsaRoleLocalPublicFacts({
      walletId: record.walletId,
      evmFamilySigningKeySlotId: EVM_FAMILY_SIGNING_KEY_SLOT_ID,
      chainTarget: record.chainTarget,
      keyHandle: record.keyHandle,
      ecdsaThresholdKeyId: record.ecdsaThresholdKeyId,
      signingRootId: record.signingRootId,
      signingRootVersion: String(record.signingRootVersion || SIGNING_ROOT_VERSION),
      applicationBindingDigestB64u: APPLICATION_BINDING_DIGEST_B64U,
      clientParticipantId: 1,
      relayerParticipantId: 2,
      participantIds: [1, 2],
      hssClientSharePublicKey33B64u: HSS_CLIENT_PUBLIC_KEY_B64U,
      relayerPublicKey33B64u: RELAYER_PUBLIC_KEY_B64U,
      groupPublicKey33B64u: PUBLIC_KEY_B64U,
      ethereumAddress: OWNER_ADDRESS,
      contextBinding32B64u: CONTEXT_BINDING_32_B64U,
    }),
    authMethod,
  });
}

function makeRecord(input: EmailOtpExportRecordFixtureInput = {}): EmailOtpEcdsaSessionRecord {
  const emailOtpAuthContext = buildEmailOtpAuthContextForWalletAuthMethod({
    policy: 'per_operation',
    walletId: WALLET_ID,
    emailHashHex: EMAIL_OTP_EMAIL_HASH_HEX,
    provider: 'google',
    providerUserId: 'google:alice',
  });
  const thresholdEcdsaPublicKeyB64u =
    'thresholdEcdsaPublicKeyB64u' in input
      ? input.thresholdEcdsaPublicKeyB64u
      : PUBLIC_KEY_B64U;
  const thresholdSessionId = input.thresholdSessionId ?? 'threshold-session-1';
  const signingGrantId = input.signingGrantId ?? 'signing-grant-1';
  const keyHandle = toEvmFamilyEcdsaKeyHandle('key-handle-export');
  const walletSessionJwt =
    'walletSessionJwt' in input
      ? input.walletSessionJwt
      : thresholdEcdsaSessionJwtFixture({
          thresholdSessionId,
          signingGrantId,
          keyHandle,
        });
  const record = {
    walletId: WALLET_ID,
    chainTarget: EVM_TARGET,
    relayerUrl: 'https://relay.localhost',
    ecdsaThresholdKeyId: input.ecdsaThresholdKeyId ?? 'ehss-export-key',
    signingRootId: SIGNING_ROOT_ID,
    signingRootVersion: SIGNING_ROOT_VERSION,
    relayerKeyId: 'relayer-key',
    clientVerifyingShareB64u: HSS_CLIENT_PUBLIC_KEY_B64U,
    relayerVerifyingShareB64u: RELAYER_PUBLIC_KEY_B64U,
    clientAdditiveShareHandle: {
      kind: 'email_otp_worker_session' as const,
      sessionId: 'email-otp-worker-session-1',
    },
    participantIds: [1, 2],
    thresholdSessionKind: input.thresholdSessionKind ?? 'jwt',
    thresholdSessionId,
    signingGrantId,
    walletSessionJwt,
    expiresAtMs: 1_900_000_000_000,
    remainingUses: 1,
    thresholdEcdsaPublicKeyB64u,
    verifiedPublicFacts: makeVerifiedPublicFacts(keyHandle),
    ethereumAddress: OWNER_ADDRESS,
    emailOtpAuthContext,
    runtimePolicyScope: {
      orgId: 'org-export',
      projectId: 'project-export',
      envId: 'env-export',
      signingRootVersion: 'default',
    },
    updatedAtMs: 1_800_000_000_000,
    source: 'email_otp' as const,
    keyHandle,
    evmFamilySigningKeySlotId: EVM_FAMILY_SIGNING_KEY_SLOT_ID,
  };
  return runtimeValidatedExportRecord({
    ...record,
    routerAbEcdsaHssNormalSigning: makeRouterAbEcdsaHssNormalSigningState(record),
    ecdsaRoleLocalReadyRecord: makeReadyRecordForExport(record),
  });
}

function makePasskeyRecord(input: PasskeyExportRecordFixtureInput = {}): PasskeyEcdsaSessionRecord {
  const thresholdSessionId = 'threshold-session-1';
  const signingGrantId = 'signing-grant-1';
  const keyHandle = toEvmFamilyEcdsaKeyHandle('key-handle-export');
  const expiresAtMs = input.expiresAtMs ?? 1_900_000_000_000;
  const walletSessionJwt =
    'walletSessionJwt' in input
      ? input.walletSessionJwt
      : thresholdEcdsaSessionJwtFixture({
          thresholdSessionId,
          signingGrantId,
          keyHandle,
          thresholdExpiresAtMs: input.thresholdExpiresAtMs ?? expiresAtMs,
          participantIds: input.participantIds ?? [1, 2],
        });
  const record = {
    walletId: WALLET_ID,
    chainTarget: EVM_TARGET,
    relayerUrl: 'https://relay.localhost',
    ecdsaThresholdKeyId: 'ehss-export-key',
    signingRootId: SIGNING_ROOT_ID,
    signingRootVersion: SIGNING_ROOT_VERSION,
    relayerKeyId: 'relayer-key',
    clientVerifyingShareB64u: HSS_CLIENT_PUBLIC_KEY_B64U,
    relayerVerifyingShareB64u: RELAYER_PUBLIC_KEY_B64U,
    participantIds: [1, 2],
    thresholdSessionKind: 'jwt' as const,
    thresholdSessionId,
    signingGrantId,
    walletSessionJwt,
    expiresAtMs,
    remainingUses: 1,
    thresholdEcdsaPublicKeyB64u: PUBLIC_KEY_B64U,
    verifiedPublicFacts: makeVerifiedPublicFacts(keyHandle),
    ethereumAddress: OWNER_ADDRESS,
    runtimePolicyScope: {
      orgId: 'org-export',
      projectId: 'project-export',
      envId: 'env-export',
      signingRootVersion: 'default',
    },
    updatedAtMs: 1_800_000_000_000,
    source: 'registration' as const,
    keyHandle,
    evmFamilySigningKeySlotId: EVM_FAMILY_SIGNING_KEY_SLOT_ID,
  };
  return runtimeValidatedExportRecord({
    ...record,
    routerAbEcdsaHssNormalSigning: makeRouterAbEcdsaHssNormalSigningState(record),
    ecdsaRoleLocalReadyRecord: makeReadyRecordForExport(record),
  });
}

async function exactExportLane(record: ThresholdEcdsaSessionRecord): Promise<ExactEcdsaExportLane> {
  const key = buildEvmFamilyEcdsaKeyIdentityFromRecord({ record });
  const publicFacts = await toVerifiedEcdsaPublicFactsFromRecord({ record });
  return {
    curve: 'ecdsa',
    laneIdentity: exactEcdsaSigningLaneIdentity({
      signer: buildEvmFamilyEcdsaSignerBinding({
        walletId: record.walletId,
        chainTarget: record.chainTarget,
        keyHandle: publicFacts.keyHandle,
        key,
      }),
      auth:
        record.source === 'email_otp'
          ? {
              kind: 'email_otp',
              providerSubjectId: record.emailOtpAuthContext
                ? emailOtpAuthContextProviderUserId(record.emailOtpAuthContext)
                : 'google:export',
            }
          : {
              kind: 'passkey',
              rpId: toRpId(RP_ID),
              credentialIdB64u: PASSKEY_EXPORT_CREDENTIAL_ID_B64U,
            },
      signingGrantId: record.signingGrantId,
      thresholdSessionId: record.thresholdSessionId,
    }),
    key,
    publicFacts,
    session: {
      chainTarget: record.chainTarget,
      authMethod: record.source === 'email_otp' ? 'email_otp' : 'passkey',
      signingGrantId: SigningSessionIds.signingGrant(record.signingGrantId),
      thresholdSessionId: SigningSessionIds.thresholdEcdsaSession(record.thresholdSessionId),
      state: 'ready',
      source: 'runtime_session_record',
    },
  };
}

function depsForRecord(
  record: ThresholdEcdsaSessionRecord,
  cachedExportArtifact?: ThresholdEcdsaCanonicalExportArtifact,
): EcdsaExportSessionStoreDeps {
  const laneKey = deriveThresholdEcdsaRuntimeLaneKey(record);
  return {
    recordsByLane: new Map([[laneKey, record]]),
    exportArtifactsByLane: cachedExportArtifact
      ? new Map([[laneKey, cachedExportArtifact]])
      : new Map(),
  };
}

test.describe('ECDSA export material', () => {
  test('ready export material composes signer material with verified public facts', async () => {
    const record = makePasskeyRecord();
    const material = await resolveEcdsaExportMaterialForLane(
      depsForRecord(record),
      await exactExportLane(record),
    );

    expect(material.kind).toBe('ready_threshold_ecdsa_export_material');
    if (material.kind !== 'ready_threshold_ecdsa_export_material') {
      throw new Error(`expected ready threshold export material, got ${material.kind}`);
    }
    expect(material.signerSession.kind).toBe('ready_ecdsa_signer_session');
    expect(material.signerSession.session.thresholdSessionId).toBe(record.thresholdSessionId);
    expect(material.cachedExportArtifact).toBeNull();
    expect(material.authMethod).toBe('passkey');
    expect(material.publicFacts.kind).toBe('verified_ecdsa_public_facts');
    expect(material.publicFacts.publicKeyB64u).toBe(PUBLIC_KEY_B64U);
    expect(material.publicFacts.participantIds.map(Number)).toEqual([1, 2]);
    expect(material.publicFacts.thresholdOwnerAddress).toBe(OWNER_ADDRESS);
    expect('ecdsaThresholdKeyId' in material.publicFacts).toBe(false);
    expect('participantIds' in material).toBe(false);
    expect('keyRef' in material).toBe(false);
    expect('readyMaterial' in material).toBe(false);
    expect('record' in material).toBe(false);
    expect(material.committedLane.authority.factor.kind).toBe('passkey');
    expect(material.committedLane.source).toBe(record.source);
    expect(material.committedLane.record).toBe(record);
    expect(material.committedLane.authLane).toBeUndefined();
    expect(material.committedLane.walletSessionAuthority.kind).toBe('wallet_session_authority');
    expect(material.committedLane.walletSessionAuthority.walletSessionJwt).toBe(
      record.walletSessionJwt,
    );
    expect(material.committedLane.walletSessionAuthority.signingGrantId).toBe(
      record.signingGrantId,
    );
  });

  test('passkey HSS export authorization uses Wallet Session JWT policy claims', async () => {
    const jwtThresholdExpiresAtMs = 1_900_000_600_000;
    const record = makePasskeyRecord({
      expiresAtMs: 1_900_000_100_000,
      thresholdExpiresAtMs: jwtThresholdExpiresAtMs,
      participantIds: [1, 2],
    });
    const material = await resolveEcdsaExportMaterialForLane(
      depsForRecord(record),
      await exactExportLane(record),
    );

    expect(material.kind).toBe('ready_threshold_ecdsa_export_material');
    if (material.kind !== 'ready_threshold_ecdsa_export_material') {
      throw new Error(`expected ready threshold export material, got ${material.kind}`);
    }
    const walletSessionAuthority = material.committedLane.walletSessionAuthority;
    expect(walletSessionAuthority.kind).toBe('wallet_session_authority');
    if (walletSessionAuthority.kind !== 'wallet_session_authority') {
      throw new Error('expected Wallet Session JWT authority');
    }
    const digestInput = buildEcdsaHssExportAuthorizationDigestInput({
      ecdsaThresholdKeyId: String(record.ecdsaThresholdKeyId),
      signingRootId: String(record.signingRootId),
      signingRootVersion: String(record.signingRootVersion),
      contextBinding32B64u: CONTEXT_BINDING_32_B64U,
      publicIdentity: {
        hssClientSharePublicKey33B64u: HSS_CLIENT_PUBLIC_KEY_B64U,
        relayerPublicKey33B64u: RELAYER_PUBLIC_KEY_B64U,
        groupPublicKey33B64u: PUBLIC_KEY_B64U,
        ethereumAddress: OWNER_ADDRESS,
      },
      exportRequestNonce32B64u: base64UrlEncode(new Uint8Array(32).fill(9)),
      confirmationDigest32B64u: base64UrlEncode(new Uint8Array(32).fill(10)),
      issuedAtUnixMs: 1_800_000_000_000,
      expiresAtUnixMs: 1_800_000_060_000,
      walletSessionAuthority,
    });

    expect(digestInput.thresholdExpiresAtMs).toBe(jwtThresholdExpiresAtMs);
    expect(digestInput.thresholdExpiresAtMs).not.toBe(record.expiresAtMs);
    expect(digestInput.participantIds).toEqual([1, 2]);
  });

  test('ready Email OTP export material carries committed lane authority', async () => {
    const record = makeRecord();
    const material = await resolveEcdsaExportMaterialForLane(
      depsForRecord(record),
      await exactExportLane(record),
    );

    expect(material.kind).toBe('ready_threshold_ecdsa_export_material');
    if (material.kind !== 'ready_threshold_ecdsa_export_material') {
      throw new Error(`expected ready threshold export material, got ${material.kind}`);
    }
    expect(material.authMethod).toBe('email_otp');
    if (material.authMethod !== 'email_otp') {
      throw new Error(`expected Email OTP export material, got ${material.authMethod}`);
    }
    expect(material.committedLane.authority.factor.kind).toBe('email_otp');
    expect(material.committedLane.source).toBe('record_backed');
    expect(material.committedLane.record).toBe(record);
    expect(material.committedLane.authLane.kind).toBe('signing_session');
    expect(material.committedLane.walletSessionAuthority.walletSessionJwt).toBe(
      record.walletSessionJwt,
    );
    expect(material.committedLane.walletSessionAuthority.signingGrantId).toBe(
      record.signingGrantId,
    );
  });

  test('ready export material uses cached artifact from ready material provenance', async () => {
    const record = makePasskeyRecord();
    const cachedExportArtifact: ThresholdEcdsaCanonicalExportArtifact = {
      artifactKind: 'ecdsa-hss-secp256k1-export',
      chainTarget: EVM_TARGET,
      signingRootId: String(record.signingRootId || 'project:dev'),
      signingRootVersion: String(record.signingRootVersion || 'default'),
      publicKeyHex: '02'.padEnd(66, '0'),
      privateKeyHex: '11'.repeat(32),
      ethereumAddress: OWNER_ADDRESS,
    };
    const material = await resolveEcdsaExportMaterialForLane(
      depsForRecord(record, cachedExportArtifact),
      await exactExportLane(record),
    );

    expect(material.kind).toBe('ready_threshold_ecdsa_export_material');
    if (material.kind !== 'ready_threshold_ecdsa_export_material') {
      throw new Error(`expected ready threshold export material, got ${material.kind}`);
    }
    expect(material.cachedExportArtifact).toEqual(cachedExportArtifact);
  });

  test('fresh Email OTP export material uses route auth when runtime auth is available', async () => {
    const record = makeRecord();
    const material = await resolveFreshEmailOtpEcdsaExportMaterialForLane(
      depsForRecord(record),
      await exactExportLane(record),
    );

    expect(material.kind).toBe('fresh_email_otp_route_auth_ready');
    if (material.kind !== 'fresh_email_otp_route_auth_ready') {
      throw new Error(`expected route-auth-ready fresh material, got ${material.kind}`);
    }
    expect(material.publicFacts.kind).toBe('verified_ecdsa_public_facts');
    expect(material.publicFacts.publicKeyB64u).toBe(PUBLIC_KEY_B64U);
    expect(material.publicFacts.participantIds.map(Number)).toEqual([1, 2]);
    expect(material.publicFacts.thresholdOwnerAddress).toBe(OWNER_ADDRESS);
    expect(material.committedLane.authLane.kind).toBe('signing_session');
    if (material.committedLane.authLane.kind !== 'signing_session') {
      throw new Error(
        `expected signing-session auth lane, got ${material.committedLane.authLane.kind}`,
      );
    }
    expect(material.committedLane.authLane.thresholdSessionId).toBe(record.thresholdSessionId);
    expect(material.committedLane.record).toBe(record);
    expect(material.runtimePolicyScope.orgId).toBe('org-export');
    expect('publicKey' in material).toBe(false);
    expect('participantIds' in material).toBe(false);
    expect('record' in material).toBe(false);
    expect('authLane' in material).toBe(false);
  });

  test('fresh Email OTP route-auth export requests challenge with signing-session lane', async () => {
    const record = makeRecord();
    const exportLane = await exactExportLane(record);
    const material = await resolveFreshEmailOtpEcdsaExportMaterialForLane(
      depsForRecord(record),
      exportLane,
    );
    expect(material.kind).toBe('fresh_email_otp_route_auth_ready');
    if (material.kind !== 'fresh_email_otp_route_auth_ready') {
      throw new Error(`expected route-auth-ready fresh material, got ${material.kind}`);
    }
    const { authLane } = material.committedLane;
    const challengeRequests: unknown[] = [];
    const exportRequests: unknown[] = [];
    const confirmationRequests: unknown[] = [];
    const exportOrder: string[] = [];

    await exportThresholdEcdsaKeyWithFreshEmailOtpRouteAuth(
      {
        sessionStore: depsForRecord(record),
        touchConfirm: {
          requestUserConfirmation: async (request) => {
            confirmationRequests.push(request);
            if (request.type === 'showSecurePrivateKeyUi') {
              exportOrder.push('viewer-loading');
            }
            return {
              confirmed: true,
              requestId: 'export-confirmation-1',
              otpCode: '123456',
              emailOtpChallengeId: 'export-challenge-1',
            };
          },
        },
        emailOtp: {
          requestExportChallenge: async (request) => {
            challengeRequests.push(request);
            return { challengeId: 'export-challenge-1' };
          },
          exportEcdsaKeyWithFreshEmailOtpLane: async () => {
            throw new Error('unexpected fresh-lane export');
          },
          exportEcdsaKeyWithAuthorization: async (request) => {
            exportOrder.push('material-export');
            exportRequests.push(request);
            return {
              publicKeyHex: '02',
              privateKeyHex: '01',
              ethereumAddress: OWNER_ADDRESS,
            };
          },
        },
        warmSessionPolicy: {
          getWarmSession: async () => ({
            capabilities: {
              ecdsa: {
                evm: { record: null },
                tempo: { record: null },
              },
            },
          }),
          resolveExactEcdsaRecord: () => ({ kind: 'not_found' }),
        },
        getSignerWorkerContext: () => {
          throw new Error('unexpected worker context read');
        },
      },
      {
        walletId: String(WALLET_ID),
        exportLane,
        material,
        options: {},
        flowId: 'flow-export-route-auth',
      },
    );

    expect(challengeRequests).toHaveLength(1);
    expect(challengeRequests[0]).toMatchObject({
      kind: 'wallet_session_challenge',
      authLane,
    });
    expect(exportRequests).toHaveLength(1);
    expect(exportRequests[0]).toMatchObject({
      challengeId: 'export-challenge-1',
      otpCode: '123456',
      committedLane: expect.objectContaining({
        authLane,
      }),
    });
    expect(exportOrder).toEqual(['viewer-loading', 'material-export']);
    expect(confirmationRequests).toContainEqual(
      expect.objectContaining({
        type: 'showSecurePrivateKeyUi',
        payload: expect.objectContaining({
          loading: true,
          viewerSessionId: expect.any(String),
        }),
      }),
    );
  });

  test('fresh Email OTP export material can challenge from exact no-route-auth runtime records', async () => {
    const record = makeRecord({
      walletSessionJwt: undefined,
      thresholdSessionKind: 'cookie',
    });
    const material = await resolveFreshEmailOtpEcdsaExportMaterialForLane(
      depsForRecord(record),
      await exactExportLane(record),
    );

    expect(material.kind).toBe('fresh_email_otp_needs_challenge');
    if (material.kind !== 'fresh_email_otp_needs_challenge') {
      throw new Error(`expected needs-challenge fresh material, got ${material.kind}`);
    }
    expect(material.providerIdentityMode).toBe('explicit_provider_user');
    if (material.providerIdentityMode !== 'explicit_provider_user') {
      throw new Error(`expected explicit provider user, got ${material.providerIdentityMode}`);
    }
    expect(material.providerUserId).toBe('google:alice');
    expect(material.runtimePolicyScope.projectId).toBe('project-export');
  });

  test('fresh Email OTP export material rejects missing verified public key facts', async () => {
    const record = makeRecord({
      ecdsaThresholdKeyId: 'ehss-export-key-missing-public-key',
      thresholdEcdsaPublicKeyB64u: undefined,
      thresholdSessionId: 'threshold-session-2',
      signingGrantId: 'signing-grant-2',
    });
    const selectedLane = await exactExportLane(
      makeRecord({
        ecdsaThresholdKeyId: record.ecdsaThresholdKeyId,
        thresholdSessionId: record.thresholdSessionId,
        signingGrantId: record.signingGrantId,
      }),
    );

    await expect(
      resolveFreshEmailOtpEcdsaExportMaterialForLane(depsForRecord(record), selectedLane),
    ).rejects.toThrow(/thresholdEcdsaPublicKeyB64u is required/);
  });

  test('ready export material rejects lane public facts that do not match stored record', async () => {
    const record = makePasskeyRecord();
    const lane = await exactExportLane(record);
    const mismatchedLane: ExactEcdsaExportLane = {
      ...lane,
      publicFacts: {
        ...lane.publicFacts,
        thresholdOwnerAddress: toThresholdOwnerAddress(
          '0x2222222222222222222222222222222222222222',
        ),
      },
    };

    await expect(
      resolveEcdsaExportMaterialForLane(depsForRecord(record), mismatchedLane),
    ).rejects.toThrow(/ready export lane public facts mismatch: thresholdOwnerAddress/);
  });

  test('fresh Email OTP export material rejects lane public facts that do not match resolved material', async () => {
    const record = makeRecord();
    const lane = await exactExportLane(record);
    const mismatchedLane: ExactEcdsaExportLane = {
      ...lane,
      publicFacts: {
        ...lane.publicFacts,
        thresholdOwnerAddress: toThresholdOwnerAddress(
          '0x2222222222222222222222222222222222222222',
        ),
      },
    };

    await expect(
      resolveFreshEmailOtpEcdsaExportMaterialForLane(depsForRecord(record), mismatchedLane),
    ).rejects.toThrow(/fresh Email OTP export lane public facts mismatch: thresholdOwnerAddress/);
  });
});
