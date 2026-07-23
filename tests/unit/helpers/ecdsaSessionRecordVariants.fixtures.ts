import { deriveEvmFamilySigningKeySlotId } from '@shared/signing-lanes';
import { parseRootShareEpoch, type RootShareEpoch } from '@shared/utils/domainIds';
import { ROUTER_AB_ECDSA_DERIVATION_WALLET_SESSION_JWT_KIND } from '@shared/utils/sessionTokens';
import type { RouterAbEcdsaDerivationNormalSigningStateV1 } from '@shared/utils/routerAbEcdsaDerivation';
import {
  toWalletId,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  buildVerifiedEcdsaPublicFacts,
  toEvmFamilyEcdsaKeyHandle,
} from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import {
  buildEmailOtpAuthContextForWalletAuthMethod,
  emailOtpAuthContextProviderUserId,
  type ThresholdEcdsaEmailOtpAuthContext,
} from '@/core/signingEngine/session/identity/laneIdentity';
import {
  buildEcdsaRoleLocalEmailOtpAuthMethod,
  buildEcdsaRoleLocalPasskeyAuthMethod,
  buildEcdsaRoleLocalPublicFacts,
  buildEcdsaRoleLocalReadyRecord,
} from '@/core/signingEngine/session/persistence/ecdsaRoleLocalRecords';
import type { ThresholdEcdsaSessionRecord } from '@/core/signingEngine/session/persistence/records';
import {
  parseEcdsaRoleLocalBindingDigest,
  parseEcdsaRoleLocalDurableMaterialRef,
  parseEcdsaRoleLocalMaterialHandle,
  parseEcdsaRoleLocalWorkerHandle,
} from '@/core/signingEngine/session/keyMaterialBrands';
import {
  bindLiveEcdsaRoleLocalMaterial,
  buildPersistedEcdsaRoleLocalMaterial,
} from '@/core/signingEngine/session/material/ecdsaRoleLocalMaterialResolver';
import { markRouterAbEcdsaDerivationWorkerMaterialRuntimeValidated } from '@/core/signingEngine/session/routerAbSigningWalletSession';
import { fixtureRouterAbEcdsaDerivationPublicCapability } from './ecdsaBootstrap.fixtures';

export type PasskeyEcdsaSessionRecord = Exclude<ThresholdEcdsaSessionRecord, { source: 'email_otp' }>;
export type EmailOtpEcdsaSessionRecord = Extract<ThresholdEcdsaSessionRecord, { source: 'email_otp' }>;

const FIXTURE_WALLET_ID = toWalletId('alice.testnet');

/** Brands a fixture activation epoch via the production parser. */
function fixtureRootShareEpoch(value: string): RootShareEpoch {
  const parsed = parseRootShareEpoch(value);
  if (!parsed.ok) {
    throw new Error(`invalid fixture activation epoch: ${value}`);
  }
  return parsed.value;
}
const FIXTURE_RP_ID = 'localhost';
const FIXTURE_OWNER_ADDRESS = '0x1111111111111111111111111111111111111111';
const FIXTURE_PUBLIC_KEY_B64U = 'AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const FIXTURE_RELAYER_PUBLIC_KEY_B64U = 'AwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const FIXTURE_SHARE_32_B64U = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const FIXTURE_APPLICATION_BINDING_DIGEST_32_B64U = 'CAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg';
const FIXTURE_RUNTIME_POLICY_SCOPE = {
  orgId: 'org-test',
  projectId: 'project',
  envId: 'dev',
  signingRootVersion: 'default',
};
const FIXTURE_SIGNING_ROOT_ID = `${FIXTURE_RUNTIME_POLICY_SCOPE.projectId}:${FIXTURE_RUNTIME_POLICY_SCOPE.envId}`;
const FIXTURE_SIGNING_ROOT_VERSION = FIXTURE_RUNTIME_POLICY_SCOPE.signingRootVersion;

const FIXTURE_EVM_TARGET: ThresholdEcdsaChainTarget = {
  kind: 'evm',
  namespace: 'eip155',
  chainId: 5042002,
  networkSlug: 'arc-testnet',
};

/**
 * Variation axes shared by the passkey and Email OTP branch builders. Defaults
 * describe the generic identity-suite lane (signing root `project:dev`, wallet
 * `alice.testnet`); export-flow suites override the scenario axes they exercise.
 */
type EcdsaSessionRecordScenarioInput = {
  signingRootId?: string;
  signingRootVersion?: string;
  runtimePolicyScope?: PasskeyEcdsaSessionRecord['runtimePolicyScope'];
  chainTarget?: ThresholdEcdsaChainTarget;
  keyHandle?: PasskeyEcdsaSessionRecord['keyHandle'];
  ecdsaThresholdKeyId?: string;
  participantIds?: number[];
  thresholdSessionId?: string;
  signingGrantId?: string;
  expiresAtMs?: number;
  remainingUses?: number;
  /** Also drives the relayer public key in the role-local facts and normal-signing state. */
  relayerVerifyingShareB64u?: string;
  /** Explicit Wallet Session JWT override; when absent a claims-consistent fixture JWT is built. */
  walletSessionJwt?: string;
  /** `thresholdExpiresAtMs` claim of the fixture Wallet Session JWT (defaults to `expiresAtMs`). */
  jwtThresholdExpiresAtMs?: number;
  /** Mark the record's Router A/B ECDSA worker material runtime-validated (throws if marking fails). */
  runtimeValidated?: boolean;
};

export type PasskeyEcdsaSessionRecordFixtureInput = EcdsaSessionRecordScenarioInput & {
  walletId?: PasskeyEcdsaSessionRecord['walletId'];
  ethereumAddress?: string;
  /** `in`-sensitive: pass `undefined` explicitly to build a record without a verified public key. */
  thresholdEcdsaPublicKeyB64u?: string;
  source?: PasskeyEcdsaSessionRecord['source'];
  /** Role-local passkey credential id (defaults to the key handle, matching identity-suite lanes). */
  passkeyCredentialIdB64u?: string;
  roleLocalDurableMaterialRef?: string;
  /** Bind live role-local worker material for the durable ref (export-flow lanes). */
  bindLiveRoleLocalWorkerMaterial?: boolean;
};

export type EmailOtpEcdsaSessionRecordFixtureInput = EcdsaSessionRecordScenarioInput & {
  /** `in`-sensitive: pass `undefined` explicitly to build a record without a verified public key. */
  thresholdEcdsaPublicKeyB64u?: string;
  emailOtpAuthContext?: ThresholdEcdsaEmailOtpAuthContext;
  clientAdditiveShareSessionId?: string;
};

function ethereumAddress20B64u(address: string): string {
  return Buffer.from(address.replace(/^0x/i, ''), 'hex').toString('base64url');
}

function makeEcdsaWalletSessionJwtFixture(args: {
  walletId: string;
  keyHandle: string;
  chainTarget: ThresholdEcdsaChainTarget;
  relayerKeyId: string;
  evmFamilySigningKeySlotId: string;
  thresholdSessionId: string;
  signingGrantId: string;
  thresholdExpiresAtMs: number;
  participantIds: readonly number[];
}): string {
  const encode = (value: unknown): string =>
    Buffer.from(JSON.stringify(value)).toString('base64url');
  return [
    encode({ alg: 'none', typ: 'JWT' }),
    encode({
      kind: ROUTER_AB_ECDSA_DERIVATION_WALLET_SESSION_JWT_KIND,
      sub: args.walletId,
      walletId: args.walletId,
      keyHandle: args.keyHandle,
      keyScope: 'evm-family',
      chainTarget: args.chainTarget,
      relayerKeyId: args.relayerKeyId,
      evmFamilySigningKeySlotId: args.evmFamilySigningKeySlotId,
      thresholdSessionId: args.thresholdSessionId,
      signingGrantId: args.signingGrantId,
      thresholdExpiresAtMs: args.thresholdExpiresAtMs,
      participantIds: args.participantIds,
      exp: Math.floor(Date.now() / 1000) + 3600,
    }),
    'test-signature',
  ].join('.');
}

export function makeRouterAbEcdsaDerivationNormalSigningStateFixture(
  input: {
    walletId?: string;
    walletKeyId?: string;
    ecdsaThresholdKeyId?: string;
    signingRootId?: string;
    signingRootVersion?: string;
    clientPublicKey33B64u?: string;
    serverPublicKey33B64u?: string;
    thresholdPublicKey33B64u?: string;
    ethereumAddress?: string;
    activationEpoch?: string;
  } = {},
): RouterAbEcdsaDerivationNormalSigningStateV1 {
  const signingRootId = input.signingRootId ?? FIXTURE_SIGNING_ROOT_ID;
  const signingRootVersion = input.signingRootVersion ?? FIXTURE_SIGNING_ROOT_VERSION;
  const walletId = input.walletId ?? FIXTURE_WALLET_ID;
  return {
    kind: 'router_ab_ecdsa_derivation_normal_signing_v1',
    scope: {
      wallet_key_id:
        input.walletKeyId ??
        deriveEvmFamilySigningKeySlotId({
          walletId: toWalletId(walletId),
          signingRootId,
          signingRootVersion,
        }),
      wallet_id: walletId,
      ecdsa_threshold_key_id: input.ecdsaThresholdKeyId ?? 'ederivation-shared-key',
      signing_root_id: signingRootId,
      signing_root_version: signingRootVersion,
      context: {
        application_binding_digest_b64u: FIXTURE_APPLICATION_BINDING_DIGEST_32_B64U,
      },
      public_identity: {
        context_binding_b64u: FIXTURE_SHARE_32_B64U,
        derivation_client_share_public_key33_b64u:
          input.clientPublicKey33B64u ?? FIXTURE_PUBLIC_KEY_B64U,
        server_public_key33_b64u: input.serverPublicKey33B64u ?? FIXTURE_RELAYER_PUBLIC_KEY_B64U,
        threshold_public_key33_b64u: input.thresholdPublicKey33B64u ?? FIXTURE_PUBLIC_KEY_B64U,
        ethereum_address20_b64u: ethereumAddress20B64u(
          input.ethereumAddress ?? FIXTURE_OWNER_ADDRESS,
        ),
        client_share_retry_counter: 0,
        server_share_retry_counter: 0,
      },
      signing_worker: {
        server_id: 'signing-worker-1',
        key_epoch: 'worker-epoch-1',
        recipient_encryption_key:
          'x25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      },
      activation_epoch: fixtureRootShareEpoch(input.activationEpoch ?? 'activation-1'),
    },
  };
}

export function makeEcdsaRoleLocalReadyRecordFixture(
  args: {
    walletId?: PasskeyEcdsaSessionRecord['walletId'];
    walletKeyId?: string;
    keyHandle?: string;
    chainTarget?: ThresholdEcdsaChainTarget;
    ecdsaThresholdKeyId?: string;
    signingRootId?: string;
    signingRootVersion?: string;
    ethereumAddress?: string;
    authMethod?: Parameters<typeof buildEcdsaRoleLocalReadyRecord>[0]['authMethod'];
    normalSigning?: RouterAbEcdsaDerivationNormalSigningStateV1;
  } = {},
) {
  const recordWalletId = args.walletId ?? FIXTURE_WALLET_ID;
  const signingRootId = args.signingRootId ?? FIXTURE_SIGNING_ROOT_ID;
  const signingRootVersion = args.signingRootVersion ?? FIXTURE_SIGNING_ROOT_VERSION;
  const recordKeyHandle = args.keyHandle ?? toEvmFamilyEcdsaKeyHandle('key-handle-shared');
  const recordChainTarget = args.chainTarget ?? FIXTURE_EVM_TARGET;
  const recordWalletKeyId =
    args.walletKeyId ??
    deriveEvmFamilySigningKeySlotId({
      walletId: recordWalletId,
      signingRootId,
      signingRootVersion,
    });
  const ecdsaThresholdKeyId = args.ecdsaThresholdKeyId ?? 'ederivation-shared-key';
  const ethereumAddress = args.ethereumAddress ?? FIXTURE_OWNER_ADDRESS;
  const normalSigning =
    args.normalSigning ??
    makeRouterAbEcdsaDerivationNormalSigningStateFixture({
      walletId: recordWalletId,
      walletKeyId: recordWalletKeyId,
      ecdsaThresholdKeyId,
      signingRootId,
      signingRootVersion,
      ethereumAddress,
    });
  return buildEcdsaRoleLocalReadyRecord({
    stateBlob: {
      kind: 'ecdsa_role_local_state_blob_v1',
      curve: 'secp256k1',
      encoding: 'base64url',
      producer: 'signer_core',
      stateBlobB64u: FIXTURE_SHARE_32_B64U,
    },
    publicFacts: buildEcdsaRoleLocalPublicFacts({
      walletId: recordWalletId,
      evmFamilySigningKeySlotId: recordWalletKeyId,
      chainTarget: recordChainTarget,
      keyHandle: recordKeyHandle,
      ecdsaThresholdKeyId,
      signingRootId,
      signingRootVersion,
      clientParticipantId: 1,
      relayerParticipantId: 2,
      participantIds: [1, 2],
      applicationBindingDigestB64u: FIXTURE_APPLICATION_BINDING_DIGEST_32_B64U,
      contextBinding32B64u: FIXTURE_SHARE_32_B64U,
      derivationClientSharePublicKey33B64u:
        normalSigning.scope.public_identity.derivation_client_share_public_key33_b64u,
      relayerPublicKey33B64u: normalSigning.scope.public_identity.server_public_key33_b64u,
      groupPublicKey33B64u: FIXTURE_PUBLIC_KEY_B64U,
      ethereumAddress,
      publicCapability: fixtureRouterAbEcdsaDerivationPublicCapability({
        walletId: String(recordWalletId),
        sessionId: normalSigning.scope.activation_epoch,
        normalSigning,
      }),
    }),
    authMethod:
      args.authMethod ??
      buildEcdsaRoleLocalPasskeyAuthMethod({
        credentialIdB64u: recordKeyHandle,
        rpId: FIXTURE_RP_ID,
      }),
  });
}

export function makePasskeyEcdsaSessionRecord(
  input: PasskeyEcdsaSessionRecordFixtureInput = {},
): PasskeyEcdsaSessionRecord {
  const walletId = input.walletId ?? FIXTURE_WALLET_ID;
  const signingRootId = input.signingRootId ?? FIXTURE_SIGNING_ROOT_ID;
  const signingRootVersion = input.signingRootVersion ?? FIXTURE_SIGNING_ROOT_VERSION;
  const keyHandleForRecord = input.keyHandle ?? toEvmFamilyEcdsaKeyHandle('key-handle-shared');
  const walletKeyId = deriveEvmFamilySigningKeySlotId({
    walletId,
    signingRootId,
    signingRootVersion,
  });
  const chainTarget = input.chainTarget ?? FIXTURE_EVM_TARGET;
  const ecdsaThresholdKeyId = input.ecdsaThresholdKeyId ?? 'ederivation-shared-key';
  const ethereumAddress = input.ethereumAddress ?? FIXTURE_OWNER_ADDRESS;
  const participantIds = input.participantIds ?? [2, 1];
  const thresholdSessionId = input.thresholdSessionId ?? 'threshold-session-1';
  const signingGrantId = input.signingGrantId ?? 'signing-grant-1';
  const expiresAtMs = input.expiresAtMs ?? 1_900_000_000_000;
  const thresholdEcdsaPublicKeyB64u =
    'thresholdEcdsaPublicKeyB64u' in input
      ? input.thresholdEcdsaPublicKeyB64u
      : FIXTURE_PUBLIC_KEY_B64U;
  const normalSigning = makeRouterAbEcdsaDerivationNormalSigningStateFixture({
    walletId,
    walletKeyId,
    ecdsaThresholdKeyId,
    signingRootId,
    signingRootVersion,
    clientPublicKey33B64u: FIXTURE_PUBLIC_KEY_B64U,
    serverPublicKey33B64u: input.relayerVerifyingShareB64u ?? FIXTURE_RELAYER_PUBLIC_KEY_B64U,
    thresholdPublicKey33B64u: thresholdEcdsaPublicKeyB64u || FIXTURE_PUBLIC_KEY_B64U,
    ethereumAddress,
  });
  const roleLocalReadyRecord = makeEcdsaRoleLocalReadyRecordFixture({
    walletId,
    walletKeyId,
    keyHandle: keyHandleForRecord,
    chainTarget,
    ecdsaThresholdKeyId,
    signingRootId,
    signingRootVersion,
    ethereumAddress,
    normalSigning,
    ...(input.passkeyCredentialIdB64u
      ? {
          authMethod: buildEcdsaRoleLocalPasskeyAuthMethod({
            credentialIdB64u: input.passkeyCredentialIdB64u,
            rpId: FIXTURE_RP_ID,
          }),
        }
      : {}),
  });
  const roleLocalDurableMaterialRef = parseEcdsaRoleLocalDurableMaterialRef(
    input.roleLocalDurableMaterialRef ??
      `router-ab-ecdsa-role-local:${keyHandleForRecord}:${chainTarget.kind}:${chainTarget.chainId}`,
  );
  const record: PasskeyEcdsaSessionRecord = {
    purpose: 'transaction_signing' as const,
    walletId,
    chainTarget,
    relayerUrl: 'https://relay.localhost',
    ecdsaThresholdKeyId,
    signingRootId,
    signingRootVersion,
    relayerKeyId: 'relayer-key',
    clientVerifyingShareB64u: FIXTURE_PUBLIC_KEY_B64U,
    ...(input.relayerVerifyingShareB64u
      ? { relayerVerifyingShareB64u: input.relayerVerifyingShareB64u }
      : {}),
    roleLocalDurableMaterialRef,
    ecdsaRoleLocalAuthMethod: roleLocalReadyRecord.authMethod as Extract<
      typeof roleLocalReadyRecord.authMethod,
      { kind: 'passkey' }
    >,
    ecdsaRoleLocalPublicFacts: roleLocalReadyRecord.publicFacts,
    participantIds,
    thresholdSessionKind: 'jwt' as const,
    thresholdSessionId,
    signingGrantId,
    walletSessionJwt:
      input.walletSessionJwt ??
      makeEcdsaWalletSessionJwtFixture({
        walletId,
        keyHandle: keyHandleForRecord,
        chainTarget,
        relayerKeyId: 'relayer-key',
        evmFamilySigningKeySlotId: walletKeyId,
        thresholdSessionId,
        signingGrantId,
        thresholdExpiresAtMs: input.jwtThresholdExpiresAtMs ?? expiresAtMs,
        participantIds,
      }),
    expiresAtMs,
    remainingUses: input.remainingUses ?? 3,
    runtimePolicyScope: input.runtimePolicyScope ?? {
      ...FIXTURE_RUNTIME_POLICY_SCOPE,
      signingRootVersion: input.signingRootVersion ?? FIXTURE_RUNTIME_POLICY_SCOPE.signingRootVersion,
    },
    thresholdEcdsaPublicKeyB64u,
    verifiedPublicFacts: buildVerifiedEcdsaPublicFacts({
      keyHandle: keyHandleForRecord,
      publicKeyB64u: thresholdEcdsaPublicKeyB64u || FIXTURE_PUBLIC_KEY_B64U,
      participantIds,
      thresholdOwnerAddress: ethereumAddress,
    }),
    ethereumAddress,
    routerAbEcdsaDerivationNormalSigning: normalSigning,
    updatedAtMs: 1_800_000_000_000,
    source: input.source ?? ('login' as const),
    keyHandle: keyHandleForRecord,
    evmFamilySigningKeySlotId: walletKeyId,
  };
  if (input.bindLiveRoleLocalWorkerMaterial) {
    const persistedMaterial = buildPersistedEcdsaRoleLocalMaterial({
      durableMaterialRef: roleLocalDurableMaterialRef,
      publicFacts: roleLocalReadyRecord.publicFacts,
    });
    bindLiveEcdsaRoleLocalMaterial({
      persistedMaterial,
      liveHandle: parseEcdsaRoleLocalWorkerHandle({
        kind: 'ecdsa_role_local_worker_handle_v1',
        materialHandle: parseEcdsaRoleLocalMaterialHandle(
          `role-local-live:${roleLocalDurableMaterialRef}`,
        ),
        bindingDigest: parseEcdsaRoleLocalBindingDigest(
          roleLocalReadyRecord.publicFacts.contextBinding32B64u,
        ),
        durableMaterialRef: roleLocalDurableMaterialRef,
      }),
    });
  }
  if (input.runtimeValidated && !markRouterAbEcdsaDerivationWorkerMaterialRuntimeValidated(record)) {
    throw new Error('passkey ECDSA fixture record failed Router A/B runtime validation');
  }
  return record;
}

export function makeEmailOtpEcdsaSessionRecord(
  input: EmailOtpEcdsaSessionRecordFixtureInput = {},
): EmailOtpEcdsaSessionRecord {
  const keyHandleForRecord = input.keyHandle ?? toEvmFamilyEcdsaKeyHandle('key-handle-email-otp');
  const chainTarget = input.chainTarget ?? FIXTURE_EVM_TARGET;
  const emailOtpAuthContext =
    input.emailOtpAuthContext ??
    buildEmailOtpAuthContextForWalletAuthMethod({
      policy: 'session',
      walletId: FIXTURE_WALLET_ID,
      emailHashHex: 'aa'.repeat(32),
      retention: 'session',
      reason: 'login',
      provider: 'google',
      providerUserId: 'google:alice',
    });
  const base = makePasskeyEcdsaSessionRecord({
    keyHandle: keyHandleForRecord,
    chainTarget,
    thresholdSessionId: input.thresholdSessionId ?? 'threshold-session-email-otp',
    signingGrantId: input.signingGrantId ?? 'signing-grant-email-otp',
    ...(input.signingRootId !== undefined ? { signingRootId: input.signingRootId } : {}),
    ...(input.signingRootVersion !== undefined
      ? { signingRootVersion: input.signingRootVersion }
      : {}),
    ...(input.runtimePolicyScope !== undefined
      ? { runtimePolicyScope: input.runtimePolicyScope }
      : {}),
    ...(input.ecdsaThresholdKeyId !== undefined
      ? { ecdsaThresholdKeyId: input.ecdsaThresholdKeyId }
      : {}),
    ...(input.participantIds !== undefined ? { participantIds: input.participantIds } : {}),
    ...(input.expiresAtMs !== undefined ? { expiresAtMs: input.expiresAtMs } : {}),
    ...(input.remainingUses !== undefined ? { remainingUses: input.remainingUses } : {}),
    ...(input.relayerVerifyingShareB64u !== undefined
      ? { relayerVerifyingShareB64u: input.relayerVerifyingShareB64u }
      : {}),
    ...(input.jwtThresholdExpiresAtMs !== undefined
      ? { jwtThresholdExpiresAtMs: input.jwtThresholdExpiresAtMs }
      : {}),
    ...('walletSessionJwt' in input ? { walletSessionJwt: input.walletSessionJwt } : {}),
    ...('thresholdEcdsaPublicKeyB64u' in input
      ? { thresholdEcdsaPublicKeyB64u: input.thresholdEcdsaPublicKeyB64u }
      : {}),
  });
  const {
    roleLocalDurableMaterialRef: _roleLocalDurableMaterialRef,
    ecdsaRoleLocalAuthMethod: _ecdsaRoleLocalAuthMethod,
    ecdsaRoleLocalPublicFacts: _ecdsaRoleLocalPublicFacts,
    ...emailOtpBase
  } = base;
  // The passkey base always builds a JWT wallet session, but its type widens to
  // optional; the Email OTP arm requires a present walletSessionJwt.
  const walletSessionJwt = base.walletSessionJwt;
  if (walletSessionJwt === undefined) {
    throw new Error('Email OTP ECDSA fixture requires a wallet-session JWT');
  }
  const roleLocalReadyRecord = makeEcdsaRoleLocalReadyRecordFixture({
    walletId: base.walletId,
    walletKeyId: base.evmFamilySigningKeySlotId,
    keyHandle: keyHandleForRecord,
    chainTarget,
    ecdsaThresholdKeyId: base.ecdsaThresholdKeyId,
    signingRootId: base.signingRootId,
    signingRootVersion: base.signingRootVersion,
    ethereumAddress: base.ethereumAddress,
    normalSigning: base.routerAbEcdsaDerivationNormalSigning,
    authMethod: buildEcdsaRoleLocalEmailOtpAuthMethod({
      authSubjectId: emailOtpAuthContextProviderUserId(emailOtpAuthContext),
    }),
  });
  const record: EmailOtpEcdsaSessionRecord = {
    ...emailOtpBase,
    // Re-pin the literals: the passkey base always builds a 'jwt' session, but its
    // type widens to 'jwt' | 'cookie', while the Email OTP arm requires 'jwt'.
    thresholdSessionKind: 'jwt',
    walletSessionJwt,
    source: 'email_otp',
    emailOtpAuthContext,
    clientAdditiveShareHandle: {
      kind: 'email_otp_worker_session',
      sessionId: input.clientAdditiveShareSessionId ?? 'email-otp-worker-share-1',
    },
    ecdsaRoleLocalAuthMethod: roleLocalReadyRecord.authMethod as Extract<
      typeof roleLocalReadyRecord.authMethod,
      { kind: 'email_otp' }
    >,
    ecdsaRoleLocalPublicFacts: roleLocalReadyRecord.publicFacts,
    ecdsaRoleLocalReadyRecord: roleLocalReadyRecord as Extract<
      typeof roleLocalReadyRecord,
      { kind: 'ecdsa_role_local_ready_email_otp_v1' }
    >,
  };
  if (input.runtimeValidated && !markRouterAbEcdsaDerivationWorkerMaterialRuntimeValidated(record)) {
    throw new Error('Email OTP ECDSA fixture record failed Router A/B runtime validation');
  }
  return record;
}
