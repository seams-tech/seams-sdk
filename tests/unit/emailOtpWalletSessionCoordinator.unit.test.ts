import { expect, test } from '@playwright/test';
import { EmailOtpWalletSessionCoordinator } from '@/core/signingEngine/session/emailOtp/EmailOtpWalletSessionCoordinator';
import { requestEmailOtpExportAuthorization } from '@/core/signingEngine/stepUpConfirmation/otpPrompt/exportAuthorization';
import {
  toAuthorizingSigningGrantId,
  type EmailOtpRoutePlan,
} from '@/core/signingEngine/stepUpConfirmation/otpPrompt/authLane';
import {
  WALLET_EMAIL_OTP_EXPORT_OPERATION,
  WALLET_EMAIL_OTP_UNLOCK_OPERATION,
} from '@shared/utils/emailOtpDomain';
import { deriveEvmFamilySigningKeySlotId, requireWalletKeyId } from '@shared/signing-lanes';
import { ROUTER_AB_ECDSA_HSS_WALLET_SESSION_JWT_KIND } from '@shared/utils/sessionTokens';
import { persistWarmSessionEd25519Capability } from '@/core/signingEngine/session/warmCapabilities/persistence';
import {
  clearAllStoredThresholdEd25519SessionRecords,
  clearAllThresholdEcdsaSessionRecords,
  getStoredThresholdEd25519SessionRecordByThresholdSessionId,
  thresholdEcdsaLaneCandidateFromSessionRecord,
  type ThresholdEcdsaSessionRecord,
  upsertThresholdEcdsaSessionFact,
} from '@/core/signingEngine/session/persistence/records';
import {
  buildCurrentSealedSessionRecord,
  type BuildCurrentEcdsaSealedSessionRecordInput,
  clearAllSealedSessions,
  type CurrentSealedSessionRecord,
  type listExactSealedSessionsForWallet,
  publishResolvedIdentity,
} from '@/core/signingEngine/session/persistence/sealedSessionStore';
import {
  thresholdEcdsaChainTargetFromChainFamily,
  thresholdEcdsaChainTargetsEqual,
  toWalletId,
  walletSessionRefFromSession,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  buildEvmFamilyEcdsaKeyIdentity,
  buildVerifiedEcdsaPublicFacts,
  deriveEvmFamilyEcdsaKeyHandle,
  toEvmFamilyEcdsaKeyHandle,
  toThresholdOwnerAddress,
  toRpId,
} from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import {
  buildEcdsaRoleLocalEmailOtpAuthMethod,
  buildEcdsaRoleLocalPublicFacts,
  buildEcdsaRoleLocalReadyRecord,
} from '@/core/signingEngine/session/persistence/ecdsaRoleLocalRecords';
import type { EmailOtpEd25519SessionReconstructionPlan } from '@/core/signingEngine/session/emailOtp/provisioning';
import { selectEmailOtpEcdsaCompanionLaneForEd25519Signing } from '@/core/signingEngine/session/emailOtp/companionSessions';
import { buildEd25519SigningLane } from '@/core/signingEngine/session/emailOtp/ed25519Warmup';
import { buildEmailOtpEd25519SigningSessionAuthority } from '@/core/signingEngine/session/emailOtp/ed25519SigningSessionAuthority';
import {
  commitEmailOtpEcdsaLaneFromRecordForMaterial,
  resolvedEvmFamilyEcdsaSigningLaneFromCandidate,
} from '@/core/signingEngine/flows/signEvmFamily/ecdsaSelection';
import { buildEcdsaMaterialStateForCandidate } from '@/core/signingEngine/flows/signEvmFamily/ecdsaMaterialState';
import { buildEmailOtpAuthContextForWalletAuthMethod } from '@/core/signingEngine/session/identity/laneIdentity';
import { computeEcdsaHssRoleLocalThresholdKeyId } from '@shared/threshold/ecdsaHssRoleLocalBootstrap';
import {
  parseEd25519WorkerMaterialBindingDigest,
  parseEd25519WorkerMaterialKeyId,
  parseSigningSessionSealKeyVersion,
} from '@/core/signingEngine/session/keyMaterialBrands';
import {
  buildEvmFamilyEcdsaSignerBinding,
  exactEcdsaSigningLaneIdentity,
  exactEd25519SigningLaneIdentity,
  nearEd25519SignerBindingFromBoundaryFields,
} from '@/core/signingEngine/session/identity/exactSigningLaneIdentity';
import type { RestorePersistedSessionForSigningInput } from '@/core/signingEngine/session/sealedRecovery/sealedRecovery.types';
import { nearEd25519SigningKeyIdFromString } from '@shared/utils/registrationIntent';
import {
  nearEd25519SignerBindingFromRaw,
  type NearEd25519SignerBinding,
} from '@shared/utils/walletCapabilityBindings';

const TEST_SUBJECT_ID = toWalletId('alice.testnet');
const TEST_SIGNING_SESSION_SEAL_KEY_VERSION = parseSigningSessionSealKeyVersion(
  'signing-session-seal-kek-test-r1',
);
const TEST_ED25519_MATERIAL_BINDING_DIGEST = 'ed25519-worker-material-binding-digest-email-otp';
const TEST_ED25519_MATERIAL_KEY_ID = 'ed25519-worker-material-key-email-otp';
const ROUTER_AB_NORMAL_SIGNING = {
  kind: 'router_ab_ed25519_normal_signing_v1',
  signingWorkerId: 'local-signing-worker',
} as const;

function loginRoutePlanFromAppSessionJwt(jwt: string): EmailOtpRoutePlan {
  return {
    routeFamily: 'login',
    authLane: { kind: 'app_session', jwt },
    operation: WALLET_EMAIL_OTP_UNLOCK_OPERATION,
  };
}

function registrationRoutePlanFromAppSessionJwt(jwt: string): EmailOtpRoutePlan {
  return {
    routeFamily: 'registration',
    authLane: { kind: 'app_session', jwt },
    operation: WALLET_EMAIL_OTP_UNLOCK_OPERATION,
  };
}

function ecdsaRestoreInput(args: {
  chainTarget: ReturnType<typeof thresholdEcdsaChainTargetFromChainFamily>;
  authMethod?: 'email_otp' | 'passkey';
  walletId?: string;
  signingGrantId?: string;
  thresholdSessionId?: string;
}): Extract<RestorePersistedSessionForSigningInput, { curve: 'ecdsa' }> {
  const walletId = args.walletId || 'alice.testnet';
  const wallet = toWalletId(walletId);
  const authMethod = args.authMethod || 'email_otp';
  const signingGrantId = args.signingGrantId || 'wallet-session-1';
  const thresholdSessionId = args.thresholdSessionId || 'ecdsa-session';
  const key = buildEvmFamilyEcdsaKeyIdentity({
    walletId: wallet,
    evmFamilySigningKeySlotId: deriveEvmFamilySigningKeySlotId({
      walletId: wallet,
      signingRootId: 'signing-root:dev',
      signingRootVersion: 'root-v1',
    }),
    ecdsaThresholdKeyId: 'ecdsa-key',
    signingRootId: 'signing-root:dev',
    signingRootVersion: 'root-v1',
    participantIds: [1, 3],
    thresholdOwnerAddress: toThresholdOwnerAddress(`0x${'33'.repeat(20)}`),
  });
  const keyHandle = toEvmFamilyEcdsaKeyHandle('key-handle-ecdsa');
  return {
    walletId,
    authMethod,
    curve: 'ecdsa',
    chainTarget: args.chainTarget,
    signingGrantId,
    thresholdSessionId,
    reason: 'transaction',
    materialRestoreIdentity: {
      kind: 'ecdsa_role_local_restore',
      lane: exactEcdsaSigningLaneIdentity({
        signer: buildEvmFamilyEcdsaSignerBinding({
          walletId: wallet,
          chainTarget: args.chainTarget,
          keyHandle,
          key,
        }),
        auth:
          authMethod === 'passkey'
            ? { kind: 'passkey', rpId: toRpId('example.com'), credentialIdB64u: 'credential-id' }
            : { kind: 'email_otp', providerSubjectId: 'google:subject' },
        signingGrantId,
        thresholdSessionId,
      }),
      ecdsaThresholdKeyId: key.ecdsaThresholdKeyId,
    },
  };
}

function emailOtpEcdsaCommittedLaneFromRecord(record: ThresholdEcdsaSessionRecord) {
  const candidate = thresholdEcdsaLaneCandidateFromSessionRecord({ record });
  return commitEmailOtpEcdsaLaneFromRecordForMaterial({
    lane: resolvedEvmFamilyEcdsaSigningLaneFromCandidate(candidate),
    record,
    material: buildEcdsaMaterialStateForCandidate({
      candidate,
      record,
      authMethod: 'email_otp',
      source: 'email_otp',
      chainTarget: record.chainTarget,
      materialChainTarget: record.chainTarget,
    }),
  });
}

function ed25519RestoreInput(
  args: {
    authMethod?: 'email_otp' | 'passkey';
    walletId?: string;
    signingGrantId?: string;
    thresholdSessionId?: string;
  } = {},
): Extract<RestorePersistedSessionForSigningInput, { curve: 'ed25519' }> {
  const walletId = args.walletId || 'alice.testnet';
  const wallet = toWalletId(walletId);
  const authMethod = args.authMethod || 'email_otp';
  const signingGrantId = args.signingGrantId || 'wallet-session-1';
  const thresholdSessionId = args.thresholdSessionId || 'ed25519-session';
  const nearEd25519SigningKeyId = nearEd25519SigningKeyIdFromString(walletId);
  return {
    walletId,
    authMethod,
    curve: 'ed25519',
    chain: 'near',
    signingGrantId,
    thresholdSessionId,
    reason: 'transaction',
    materialRestoreIdentity: {
      kind: 'ed25519_worker_material_restore',
      lane: exactEd25519SigningLaneIdentity({
        signer: nearEd25519SignerBindingFromBoundaryFields({
          walletId: wallet,
          nearAccountId: walletId,
          nearEd25519SigningKeyId,
          signerSlot: 1,
        }),
        auth:
          authMethod === 'passkey'
            ? { kind: 'passkey', rpId: toRpId('example.com'), credentialIdB64u: 'credential-id' }
            : { kind: 'email_otp', providerSubjectId: 'google:alice' },
        signingGrantId,
        thresholdSessionId,
      }),
      materialBindingDigest: parseEd25519WorkerMaterialBindingDigest(
        TEST_ED25519_MATERIAL_BINDING_DIGEST,
      ),
      materialKeyId: parseEd25519WorkerMaterialKeyId(TEST_ED25519_MATERIAL_KEY_ID),
    },
  };
}
const TEMPO_CHAIN_TARGET = thresholdEcdsaChainTargetFromChainFamily({
  chain: 'tempo',
  chainId: 42431,
  networkSlug: 'tempo-testnet',
});
const EVM_CHAIN_TARGET = thresholdEcdsaChainTargetFromChainFamily({
  chain: 'evm',
  chainId: 5042002,
  networkSlug: 'arc-testnet',
});
const TEST_WALLET_SESSION = walletSessionRefFromSession({
  walletId: 'alice.testnet',
  walletSessionUserId: 'alice.testnet',
});
const TEST_ED25519_KEY_SCOPE_ID = 'ed25519-scope-email-otp-test';
function requireTestEd25519SignerBinding(): NearEd25519SignerBinding {
  const parsed = nearEd25519SignerBindingFromRaw({
    account: {
      kind: 'named_near_account',
      wallet: { walletId: TEST_WALLET_SESSION.walletId },
      nearAccountId: 'alice.testnet',
    },
    nearEd25519SigningKeyId: TEST_ED25519_KEY_SCOPE_ID,
    signerSlot: 1,
  });
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

const TEST_ED25519_SIGNER = requireTestEd25519SignerBinding();
const TEST_ECDSA_BACKEND_BINDING = {
  relayerKeyId: 'relayer-key',
  clientVerifyingShareB64u: 'verifying-share',
};
const VALID_ECDSA_PUBLIC_KEY_B64U = Buffer.from(new Uint8Array([2, ...Array(32).fill(1)])).toString(
  'base64url',
);
const VALID_ECDSA_RELAYER_PUBLIC_KEY_B64U = Buffer.from(
  new Uint8Array([2, ...Array(32).fill(2)]),
).toString('base64url');
const VALID_ECDSA_CLIENT_PUBLIC_KEY_B64U = Buffer.from(
  new Uint8Array([2, ...Array(32).fill(3)]),
).toString('base64url');
const VALID_ECDSA_PRIVATE_SHARE_B64U = Buffer.from(new Uint8Array(32).fill(4)).toString(
  'base64url',
);
const VALID_ECDSA_CONTEXT_BINDING_B64U = Buffer.from(new Uint8Array(32).fill(5)).toString(
  'base64url',
);
const VALID_ECDSA_APPLICATION_BINDING_DIGEST_B64U = Buffer.from(
  new Uint8Array(32).fill(6),
).toString('base64url');
const DEFER_ED25519_RECONSTRUCTION_FOR_ECDSA = {
  kind: 'defer',
  reason: 'not_needed_for_ecdsa',
} satisfies EmailOtpEd25519SessionReconstructionPlan;

function emailOtpAuthContextFixture(
  args: {
    policy?: 'session' | 'per_operation';
    retention?: 'session' | 'single_use';
    reason?: 'login' | 'sign';
    walletId?: string;
    providerUserId?: string;
    emailHashHex?: string;
  } = {},
) {
  const retention = args.retention || 'session';
  const walletId = args.walletId || TEST_SUBJECT_ID;
  const emailHashHex = args.emailHashHex || 'email-hash';
  if (retention === 'single_use') {
    return buildEmailOtpAuthContextForWalletAuthMethod({
      policy: args.policy || 'per_operation',
      walletId,
      provider: 'google',
      providerUserId: args.providerUserId || 'alice.testnet',
      emailHashHex,
    });
  }
  return buildEmailOtpAuthContextForWalletAuthMethod({
    policy: args.policy || 'session',
    retention: 'session',
    reason: args.reason || 'login',
    walletId,
    provider: 'google',
    providerUserId: args.providerUserId || 'alice.testnet',
    emailHashHex,
  });
}

type RuntimePolicyScopeFixture = NonNullable<
  BuildCurrentEcdsaSealedSessionRecordInput['ecdsaRestore']['runtimePolicyScope']
>;

function jsonB64u(value: unknown): string {
  return Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');
}

function makeEmailOtpRoleLocalReadyRecord(args: {
  walletId: string;
  rpId: string;
  chainTarget: ReturnType<typeof thresholdEcdsaChainTargetFromChainFamily>;
  keyHandle: string;
  ecdsaThresholdKeyId: string;
  signingRootId: string;
  signingRootVersion: string;
  ethereumAddress: `0x${string}`;
}) {
  return buildEcdsaRoleLocalReadyRecord({
    stateBlob: {
      kind: 'ecdsa_role_local_state_blob_v1',
      curve: 'secp256k1',
      encoding: 'base64url',
      producer: 'signer_core',
      stateBlobB64u: VALID_ECDSA_PRIVATE_SHARE_B64U,
    },
    publicFacts: buildEcdsaRoleLocalPublicFacts({
      walletId: toWalletId(args.walletId),
      evmFamilySigningKeySlotId: deriveEvmFamilySigningKeySlotId({
        walletId: args.walletId,
        signingRootId: args.signingRootId,
        signingRootVersion: args.signingRootVersion,
      }),
      chainTarget: args.chainTarget,
      keyHandle: args.keyHandle,
      ecdsaThresholdKeyId: args.ecdsaThresholdKeyId,
      signingRootId: args.signingRootId,
      signingRootVersion: args.signingRootVersion,
      clientParticipantId: 1,
      relayerParticipantId: 2,
      participantIds: [1, 2],
      applicationBindingDigestB64u: VALID_ECDSA_APPLICATION_BINDING_DIGEST_B64U,
      contextBinding32B64u: VALID_ECDSA_CONTEXT_BINDING_B64U,
      hssClientSharePublicKey33B64u: VALID_ECDSA_CLIENT_PUBLIC_KEY_B64U,
      relayerPublicKey33B64u: VALID_ECDSA_RELAYER_PUBLIC_KEY_B64U,
      groupPublicKey33B64u: VALID_ECDSA_PUBLIC_KEY_B64U,
      ethereumAddress: args.ethereumAddress,
    }),
    authMethod: buildEcdsaRoleLocalEmailOtpAuthMethod({
      authSubjectId: args.walletId,
    }),
  });
}

function makeEmailOtpEcdsaRecordForSelection(args: {
  thresholdSessionId: string;
  signingGrantId: string;
  chainTarget?: ReturnType<typeof thresholdEcdsaChainTargetFromChainFamily>;
  keyHandle: string;
  ecdsaThresholdKeyId: string;
  relayerKeyId: string;
  clientVerifyingShareB64u: string;
  updatedAtMs: number;
}): ThresholdEcdsaSessionRecord {
  const chainTarget = args.chainTarget || TEMPO_CHAIN_TARGET;
  const keyHandle = toEvmFamilyEcdsaKeyHandle(args.keyHandle);
  const ethereumAddress = '0x'.padEnd(42, 'a') as `0x${string}`;
  const signingRootId = 'signing-root';
  const signingRootVersion = 'root-v1';
  const evmFamilySigningKeySlotId = deriveEvmFamilySigningKeySlotId({
    walletId: TEST_SUBJECT_ID,
    signingRootId,
    signingRootVersion,
  });
  return {
    walletId: TEST_SUBJECT_ID,
    evmFamilySigningKeySlotId,
    chainTarget,
    relayerUrl: 'https://relay.example',
    keyHandle,
    ecdsaThresholdKeyId: args.ecdsaThresholdKeyId,
    signingRootId,
    signingRootVersion,
    relayerKeyId: args.relayerKeyId,
    clientVerifyingShareB64u: args.clientVerifyingShareB64u,
    ecdsaRoleLocalReadyRecord: makeEmailOtpRoleLocalReadyRecord({
      walletId: TEST_SUBJECT_ID,
      rpId: 'localhost',
      chainTarget,
      keyHandle,
      ecdsaThresholdKeyId: args.ecdsaThresholdKeyId,
      signingRootId: 'signing-root',
      signingRootVersion: 'root-v1',
      ethereumAddress,
    }),
    participantIds: [1, 3],
    thresholdEcdsaPublicKeyB64u: VALID_ECDSA_PUBLIC_KEY_B64U,
    verifiedPublicFacts: buildVerifiedEcdsaPublicFacts({
      keyHandle,
      publicKeyB64u: VALID_ECDSA_PUBLIC_KEY_B64U,
      participantIds: [1, 3],
      thresholdOwnerAddress: ethereumAddress,
    }),
    ethereumAddress,
    thresholdSessionKind: 'jwt',
    thresholdSessionId: args.thresholdSessionId,
    signingGrantId: args.signingGrantId,
    walletSessionJwt: `${args.thresholdSessionId}-jwt`,
    expiresAtMs: Date.now() + 60_000,
    remainingUses: 1,
    emailOtpAuthContext: buildEmailOtpAuthContextForWalletAuthMethod({
      policy: 'per_operation',
      walletId: TEST_SUBJECT_ID,
      provider: 'google',
      providerUserId: 'google:subject',
      emailHashHex: 'email-hash',
    }),
    updatedAtMs: args.updatedAtMs,
    source: 'email_otp',
  };
}

function emailOtpAuthorityFromEcdsaRecord(record: ThresholdEcdsaSessionRecord) {
  if (record.source !== 'email_otp' || !record.emailOtpAuthContext) {
    throw new Error('Email OTP ECDSA fixture requires Email OTP auth context');
  }
  return record.emailOtpAuthContext.authority;
}

function appSessionJwt(expSeconds = Math.floor(Date.now() / 1000) + 3600): string {
  return `${jsonB64u({ alg: 'none', typ: 'JWT' })}.${jsonB64u({
    kind: 'app_session_v1',
    exp: expSeconds,
  })}.sig`;
}

function appSessionJwtWithRuntimePolicyScope(
  runtimePolicyScope: RuntimePolicyScopeFixture,
  expSeconds = Math.floor(Date.now() / 1000) + 3600,
): string {
  return `${jsonB64u({ alg: 'none', typ: 'JWT' })}.${jsonB64u({
    kind: 'app_session_v1',
    runtimePolicyScope,
    exp: expSeconds,
  })}.sig`;
}

function signingRootFromRuntimePolicyScope(
  runtimePolicyScope:
    | { projectId?: unknown; envId?: unknown; signingRootVersion?: unknown }
    | null
    | undefined,
): { signingRootId: string; signingRootVersion: string } {
  const projectId = String(runtimePolicyScope?.projectId || '').trim();
  const envId = String(runtimePolicyScope?.envId || '').trim();
  const signingRootVersion = String(runtimePolicyScope?.signingRootVersion || '').trim();
  if (!projectId || !envId || !signingRootVersion) {
    return { signingRootId: 'signing-root', signingRootVersion: 'root-v1' };
  }
  return {
    signingRootId: `${projectId}:${envId}`,
    signingRootVersion,
  };
}

function emailOtpEcdsaClientRootHandleFromWorkerCall(call: any) {
  const binding = call.request?.payload?.ecdsaClientRootHandleBinding;
  return {
    kind: 'email_otp_worker_session_handle_v1',
    sessionId: 'email-otp-ecdsa-root-test',
    walletId: call.request?.payload?.walletId || 'alice.testnet',
    rpId: binding?.rpId || 'localhost',
    authSubjectId: binding?.authSubjectId || call.request?.payload?.userId || 'alice.testnet',
    action: 'threshold_ecdsa_bootstrap',
    operation: binding?.operation || 'wallet_unlock',
    chainTarget: binding?.chainTarget || TEMPO_CHAIN_TARGET,
  };
}

function thresholdEcdsaSessionJwt(args: {
  walletId: string;
  keyHandle: string;
  thresholdSessionId: string;
  signingGrantId: string;
  chainTarget?: BuildCurrentEcdsaSealedSessionRecordInput['ecdsaRestore']['chainTarget'];
  runtimePolicyScope?: RuntimePolicyScopeFixture;
}): string {
  return `${jsonB64u({ alg: 'none', typ: 'JWT' })}.${jsonB64u({
    kind: ROUTER_AB_ECDSA_HSS_WALLET_SESSION_JWT_KIND,
    sub: args.walletId,
    walletId: args.walletId,
    keyScope: 'evm-family',
    keyHandle: args.keyHandle,
    thresholdSessionId: args.thresholdSessionId,
    signingGrantId: args.signingGrantId,
    ...(args.chainTarget ? { chainTarget: args.chainTarget } : {}),
    ...(args.runtimePolicyScope ? { runtimePolicyScope: args.runtimePolicyScope } : {}),
  })}.sig`;
}

async function roleLocalEcdsaKeyHandle(args: {
  walletId: string;
  rpId: string;
  projectId: string;
  envId: string;
  signingRootVersion: string;
}): Promise<string> {
  const signingRootId = `${args.projectId}:${args.envId}`;
  const walletKeyId = `wallet-key-${args.walletId}-${args.projectId}-${args.envId}`;
  const ecdsaThresholdKeyId = await computeEcdsaHssRoleLocalThresholdKeyId({
    walletId: args.walletId,
    walletKeyId,
    signingRootId,
    signingRootVersion: args.signingRootVersion,
  });
  return String(
    await deriveEvmFamilyEcdsaKeyHandle({
      ecdsaThresholdKeyId,
      signingRootId,
      signingRootVersion: args.signingRootVersion,
    }),
  );
}

type EcdsaSealedRecordFixtureArgs = {
  expiresAtMs: number;
  thresholdSessionId?: string;
  thresholdSessionIds?: BuildCurrentEcdsaSealedSessionRecordInput['thresholdSessionIds'];
  signingGrantId?: string;
  walletId?: string;
  signingRootId?: string;
  signingRootVersion?: string;
  relayerUrl?: string;
  keyVersion?: string;
  shamirPrimeB64u?: string;
  sealedSecretB64u?: string;
  chainTarget?: BuildCurrentEcdsaSealedSessionRecordInput['ecdsaRestore']['chainTarget'];
  ecdsaRestore?: Partial<BuildCurrentEcdsaSealedSessionRecordInput['ecdsaRestore']>;
  ed25519Restore?: Partial<
    NonNullable<BuildCurrentEcdsaSealedSessionRecordInput['ed25519Restore']>
  >;
  issuedAtMs?: number;
  remainingUses?: number;
  updatedAtMs?: number;
};

function buildEcdsaSealedRecordFixture(
  args: EcdsaSealedRecordFixtureArgs,
): CurrentSealedSessionRecord {
  const chainTarget = args.ecdsaRestore?.chainTarget || args.chainTarget || TEMPO_CHAIN_TARGET;
  const thresholdSessionId =
    args.thresholdSessionId || args.thresholdSessionIds?.ecdsa || 'ecdsa-session';
  const walletId = args.walletId || 'alice.testnet';
  const signingGrantId = args.signingGrantId || 'wallet-session-1';
  const keyHandle = args.ecdsaRestore?.keyHandle || 'key-handle-ecdsa';
  const signingRootId = args.signingRootId || 'signing-root';
  const signingRootParts = signingRootId.includes(':')
    ? signingRootId.split(':')
    : [signingRootId, 'dev'];
  const runtimePolicyScope = {
    orgId: 'org-test',
    projectId: signingRootParts[0] || 'signing-root',
    envId: signingRootParts[1] || 'dev',
    signingRootVersion: args.signingRootVersion || 'root-v1',
  };
  const ecdsaRestore: BuildCurrentEcdsaSealedSessionRecordInput['ecdsaRestore'] = {
    chainTarget,
    evmFamilySigningKeySlotId:
      args.ecdsaRestore?.evmFamilySigningKeySlotId ||
      deriveEvmFamilySigningKeySlotId({
        walletId: toWalletId(walletId),
        signingRootId,
        signingRootVersion: args.signingRootVersion || 'root-v1',
      }),
    providerSubjectId: args.ecdsaRestore?.providerSubjectId || 'google:subject',
    emailHashHex: args.ecdsaRestore?.emailHashHex || 'email-hash',
    walletSessionJwt:
      args.ecdsaRestore?.walletSessionJwt ||
      thresholdEcdsaSessionJwt({
        walletId,
        keyHandle,
        thresholdSessionId,
        signingGrantId,
        chainTarget,
        runtimePolicyScope: args.ecdsaRestore?.runtimePolicyScope || runtimePolicyScope,
      }),
    sessionKind: args.ecdsaRestore?.sessionKind || 'jwt',
    keyHandle,
    ecdsaThresholdKeyId: args.ecdsaRestore?.ecdsaThresholdKeyId || 'ecdsa-key',
    ethereumAddress: args.ecdsaRestore?.ethereumAddress || `0x${'33'.repeat(20)}`,
    relayerKeyId: args.ecdsaRestore?.relayerKeyId || 'relayer-key',
    clientVerifyingShareB64u:
      args.ecdsaRestore?.clientVerifyingShareB64u || VALID_ECDSA_CLIENT_PUBLIC_KEY_B64U,
    thresholdEcdsaPublicKeyB64u:
      args.ecdsaRestore?.thresholdEcdsaPublicKeyB64u || VALID_ECDSA_PUBLIC_KEY_B64U,
    participantIds: args.ecdsaRestore?.participantIds || [1, 3],
    runtimePolicyScope: args.ecdsaRestore?.runtimePolicyScope || runtimePolicyScope,
  };
  const ed25519ThresholdSessionId = args.thresholdSessionIds?.ed25519;
  const ed25519Restore =
    args.ed25519Restore || ed25519ThresholdSessionId
      ? {
          nearAccountId: args.ed25519Restore?.nearAccountId || walletId,
          nearEd25519SigningKeyId: args.ed25519Restore?.nearEd25519SigningKeyId || walletId,
          rpId: args.ed25519Restore?.rpId || 'localhost',
          relayerKeyId: args.ed25519Restore?.relayerKeyId || 'ed25519-relayer-key',
          participantIds: args.ed25519Restore?.participantIds || [1, 3],
          walletSessionJwt: args.ed25519Restore?.walletSessionJwt || 'threshold-session-jwt',
          sessionKind: args.ed25519Restore?.sessionKind || 'jwt',
          signerSlot: args.ed25519Restore?.signerSlot || 1,
          ...(args.ed25519Restore?.runtimePolicyScope === undefined
            ? {}
            : { runtimePolicyScope: args.ed25519Restore.runtimePolicyScope }),
          ...(args.ed25519Restore?.routerAbNormalSigning
            ? { routerAbNormalSigning: args.ed25519Restore.routerAbNormalSigning }
            : {}),
        }
      : undefined;
  const record = buildCurrentSealedSessionRecord({
    curve: 'ecdsa',
    authMethod: 'email_otp',
    walletId,
    relayerUrl: args.relayerUrl || 'https://relay.example',
    keyVersion: args.keyVersion || 'signing-session-seal-kek-test-r1',
    shamirPrimeB64u: args.shamirPrimeB64u || 'prime-b64u',
    signingGrantId,
    thresholdSessionId,
    thresholdSessionIds: args.thresholdSessionIds,
    sealedSecretB64u: args.sealedSecretB64u || 'sealed-session-secret',
    ecdsaRestore,
    ...(ed25519Restore ? { ed25519Restore } : {}),
    issuedAtMs: args.issuedAtMs || Date.now(),
    expiresAtMs: args.expiresAtMs,
    remainingUses: args.remainingUses ?? 2,
    updatedAtMs: args.updatedAtMs || Date.now(),
  });
  if (!record) {
    throw new Error('invalid ECDSA sealed session fixture');
  }
  return record;
}

function createCoordinator(overrides?: {
  requestWorkerOperation?: (call: any) => Promise<any>;
  refreshAppSessionJwt?: () => Promise<string>;
  getRpId?: () => string | null;
  configs?: Record<string, any>;
  writeExactSealedSession?: (args: any) => Promise<void>;
  readExactSealedSession?: (thresholdSessionId: string, purpose?: any) => Promise<any>;
  listExactSealedSessionsForWallet?: typeof listExactSealedSessionsForWallet;
  listThresholdEcdsaSessionRecordsForWallet?: (walletId: string) => any[];
  getThresholdEcdsaSessionRecordByThresholdSessionId?: (thresholdSessionId: string) => any;
  acquireSigningSessionRestoreLease?: (args: any) => Promise<any>;
  releaseSigningSessionRestoreLease?: (lease: any) => Promise<void>;
  reconstructEd25519Session?: (args: any) => Promise<any>;
}) {
  const workerCalls: any[] = [];
  let refreshCount = 0;
  const buildWorkerEcdsaBootstrap = (call: any, chainTarget: any) => {
    const walletId = call.request.payload.walletId || 'alice.testnet';
    const thresholdSessionId = call.request.payload.sessionId || 'ecdsa-session';
    const signingGrantId = call.request.payload.signingGrantId || thresholdSessionId;
    const keyHandle = 'key-handle-ecdsa';
    const walletSessionJwt = thresholdEcdsaSessionJwt({
      walletId,
      keyHandle,
      thresholdSessionId,
      signingGrantId,
      chainTarget,
    });
    return {
      thresholdEcdsaKeyRef: {
        type: 'threshold-ecdsa-secp256k1',
        userId: walletId,
        subjectId: call.request.payload.subjectId,
        relayerUrl: call.request.payload.relayUrl,
        keyHandle,
        ecdsaThresholdKeyId: 'ecdsa-key',
        chainTarget,
        signingRootId: 'signing-root',
        signingRootVersion: 'root-v1',
        ethereumAddress: `0x${'33'.repeat(20)}`,
        thresholdEcdsaPublicKeyB64u: VALID_ECDSA_PUBLIC_KEY_B64U,
        thresholdSessionId,
        signingGrantId,
        thresholdSessionKind: 'jwt',
        walletSessionJwt,
        participantIds: [1, 3],
        backendBinding: TEST_ECDSA_BACKEND_BINDING,
      },
      keygen: {
        ok: true,
        evmFamilySigningKeySlotId: call.request.payload.evmFamilySigningKeySlotId,
      },
      session: {
        ok: true,
        sessionId: thresholdSessionId,
        signingGrantId,
        expiresAtMs: Date.now() + 60_000,
        remainingUses: 3,
        jwt: walletSessionJwt,
      },
    };
  };
  const worker = {
    requestWorkerOperation: async (call: any) => {
      workerCalls.push(call);
      if (overrides?.requestWorkerOperation) {
        return overrides.requestWorkerOperation(call);
      }
      if (call.request?.type === 'requestEmailOtpChallenge') {
        return { challengeId: 'challenge-1', emailHint: 'a***@example.com' };
      }
      if (call.request?.type === 'loginWithEmailOtpWallet') {
        return {
          recovery: { thresholdEd25519RecoveryCodeSecret32B64u: 'prf-first-ecdsa-login' },
          clientRootShareHandle: emailOtpEcdsaClientRootHandleFromWorkerCall(call),
        };
      }
      if (call.request?.type === 'exportEmailOtpEd25519SeedWithAuthorization') {
        return {
          publicKey: 'ed25519:public',
          privateKey: 'ed25519:private',
        };
      }
      if (call.request?.type === 'exportThresholdEcdsaHssKeyWithEmailOtpAuthorization') {
        return {
          publicKeyHex: '02'.padEnd(66, '1'),
          privateKeyHex: '11'.repeat(32),
          ethereumAddress: '0x'.padEnd(42, 'a'),
        };
      }
      if (call.request?.type === 'bootstrapEmailOtpEcdsaSessionsFromWorkerHandle') {
        return {
          bootstraps: call.request.payload.publicationChainTargets.map((chainTarget: any) =>
            buildWorkerEcdsaBootstrap(call, chainTarget),
          ),
        };
      }
      if (call.request?.type === 'sealEmailOtpWarmSessionMaterial') {
        return {
          ok: true,
          sealedSecretB64u: 'sealed-email-otp-session-secret',
          keyVersion: 'signing-session-seal-kek-test-r1',
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 3,
        };
      }
      if (call.request?.type === 'rehydrateEmailOtpEcdsaWarmSessionMaterial') {
        const ed25519Restore = call.request.payload.restore.ed25519;
        if (ed25519Restore) {
          expect(ed25519Restore).toHaveProperty('runtimePolicyScope');
          expect(ed25519Restore).not.toHaveProperty('signingRootId');
          expect(ed25519Restore).not.toHaveProperty('signingRootVersion');
        }
        return {
          ok: true,
          remainingUses: 2,
          expiresAtMs: Date.now() + 60_000,
          bootstrap: {
            thresholdEcdsaKeyRef: {
              type: 'threshold-ecdsa-secp256k1',
              userId: call.request.payload.restore.walletId,
              subjectId: TEST_SUBJECT_ID,
              relayerUrl: call.request.payload.transport.relayerUrl,
              keyHandle: 'key-handle-ecdsa',
              ecdsaThresholdKeyId: 'ecdsa-key',
              chainTarget: call.request.payload.restore.chainTarget,
              ...signingRootFromRuntimePolicyScope(
                call.request.payload.restore.ed25519?.runtimePolicyScope,
              ),
              thresholdSessionId: call.request.payload.restore.sessionId,
              signingGrantId: call.request.payload.restore.signingGrantId,
              walletSessionJwt: call.request.payload.transport.walletSessionJwt,
            },
            keygen: {
              ok: true,
              evmFamilySigningKeySlotId: call.request.payload.restore.evmFamilySigningKeySlotId,
            },
            session: {
              ok: true,
              sessionId: call.request.payload.restore.sessionId,
              signingGrantId: call.request.payload.restore.signingGrantId,
              expiresAtMs: Date.now() + 60_000,
              remainingUses: 2,
              jwt: call.request.payload.transport.walletSessionJwt,
            },
          },
        };
      }
      if (call.request?.type === 'enrollEmailOtpWallet') {
        return {
          thresholdEcdsaClientVerifyingShareB64u: 'verifying-share',
          challengeId: call.request.payload.challengeId,
          otpChannel: 'email_otp',
          enrollmentSealKeyVersion: 'email-v1',
          clientUnlockPublicKeyB64u: 'unlock-public',
          unlockKeyVersion: 'unlock-v1',
          thresholdEd25519RecoveryCodeSecret32B64u: 'prf-first-ecdsa-enroll',
          clientRootShareHandle: emailOtpEcdsaClientRootHandleFromWorkerCall(call),
        };
      }
      return { ok: true };
    },
  };
  const ecdsaCommitCalls: any[] = [];
  const ed25519ReconstructionCalls: any[] = [];
  const ed25519MetadataWrites: any[] = [];
  const ed25519WarmSessionWrites: any[] = [];
  const hydratedSessions: any[] = [];
  const sealedRecordWrites: CurrentSealedSessionRecord[] = [];
  const toSealedRecordReadback = (record: CurrentSealedSessionRecord): CurrentSealedSessionRecord =>
    record;
  const recordMatchesSealedPurpose = (
    write: any,
    thresholdSessionId: string | undefined,
    purpose?: any,
  ) => {
    if (
      thresholdSessionId &&
      write.thresholdSessionIds?.ed25519 !== thresholdSessionId &&
      write.thresholdSessionIds?.ecdsa !== thresholdSessionId
    ) {
      return false;
    }
    if (purpose?.authMethod && write.authMethod !== purpose.authMethod) return false;
    if (purpose?.curve && write.curve !== purpose.curve) return false;
    if (
      purpose?.chainTarget &&
      (!write.ecdsaRestore?.chainTarget ||
        !thresholdEcdsaChainTargetsEqual(write.ecdsaRestore.chainTarget, purpose.chainTarget))
    ) {
      return false;
    }
    return true;
  };
  const defaultReadExactSealedSession = async (thresholdSessionId: string, purpose?: any) => {
    const record = sealedRecordWrites.find((write) =>
      recordMatchesSealedPurpose(write, thresholdSessionId, purpose),
    );
    return record ? toSealedRecordReadback(record) : null;
  };
  const defaultListExactSealedSessionsForWallet: typeof listExactSealedSessionsForWallet = async ({
    walletId,
    filter,
  }) =>
    sealedRecordWrites
      .filter((write) => {
        if (write.walletId !== walletId && write.userId !== walletId) {
          return false;
        }
        return recordMatchesSealedPurpose(write, undefined, filter);
      })
      .map(toSealedRecordReadback);
  const baseConfigs = {
    registration: {
      mode: 'backend_proxy',
      bootstrapUrl: 'https://relay.example/registration/bootstrap',
    },
    network: {
      relayer: { url: 'https://relay.example' },
      chains: [
        {
          network: 'tempo-testnet',
          rpcUrl: 'https://rpc.tempo.test',
          explorerUrl: 'https://explorer.tempo.test',
          chainId: 42431,
        },
        {
          network: 'arc-testnet',
          rpcUrl: 'https://rpc.arc.test',
          explorerUrl: 'https://explorer.arc.test',
          chainId: 5042002,
        },
      ],
    },
    signing: {
      emailOtp: { authPolicy: 'per_operation' },
      routerAb: {
        normalSigning: {
          mode: 'enabled',
          signingWorkerId: 'local-signing-worker',
        },
      },
      sessionPersistenceMode: 'none',
      sessionSeal: { shamirPrimeB64u: 'prime-b64u' },
    },
  };
  const defaultEcdsaRecord = {
    walletId: 'alice.testnet',
    subjectId: TEST_SUBJECT_ID,
    chainTarget: TEMPO_CHAIN_TARGET,
    source: 'email_otp',
    relayerUrl: 'https://relay.example',
    keyHandle: 'key-handle-ecdsa',
    ecdsaThresholdKeyId: 'ecdsa-key',
    signingRootId: 'signing-root',
    signingRootVersion: 'default',
    relayerKeyId: 'relayer-key',
    clientVerifyingShareB64u: VALID_ECDSA_CLIENT_PUBLIC_KEY_B64U,
    participantIds: [1, 3],
    thresholdSessionKind: 'jwt',
    thresholdSessionId: 'ecdsa-session',
    signingGrantId: 'wallet-session-ecdsa',
    walletSessionJwt: thresholdEcdsaSessionJwt({
      walletId: 'alice.testnet',
      keyHandle: 'key-handle-ecdsa',
      thresholdSessionId: 'ecdsa-session',
      signingGrantId: 'wallet-session-ecdsa',
      chainTarget: TEMPO_CHAIN_TARGET,
    }),
    expiresAtMs: Date.now() + 60_000,
    remainingUses: 1,
    updatedAtMs: Date.now(),
  };
  const coordinator = new EmailOtpWalletSessionCoordinator({
    configs: {
      ...baseConfigs,
      ...(overrides?.configs || {}),
      registration: {
        ...baseConfigs.registration,
        ...(overrides?.configs?.registration || {}),
      },
      network: {
        ...baseConfigs.network,
        ...(overrides?.configs?.network || {}),
      },
      signing: {
        ...baseConfigs.signing,
        ...(overrides?.configs?.signing || {}),
        emailOtp: {
          ...baseConfigs.signing.emailOtp,
          ...(overrides?.configs?.signing?.emailOtp || {}),
        },
        routerAb: {
          ...baseConfigs.signing.routerAb,
          ...(overrides?.configs?.signing?.routerAb || {}),
          normalSigning: {
            ...baseConfigs.signing.routerAb.normalSigning,
            ...(overrides?.configs?.signing?.routerAb?.normalSigning || {}),
          },
        },
        sessionSeal: {
          ...baseConfigs.signing.sessionSeal,
          ...(overrides?.configs?.signing?.sessionSeal || {}),
        },
      },
    } as any,
    signerWorkerManager: worker as any,
    getRpId: overrides?.getRpId || (() => 'localhost'),
    getSignerWorkerContext: () => worker as any,
    refreshAppSessionJwt: async () => {
      refreshCount += 1;
      return overrides?.refreshAppSessionJwt ? overrides.refreshAppSessionJwt() : appSessionJwt();
    },
    commitEvmFamilyThresholdEcdsaSessions: async (args) => {
      ecdsaCommitCalls.push(args);
      return {
        bootstrap: args.bootstrap,
        warmCapability: { capability: 'ecdsa', state: 'ready' } as any,
      };
    },
    listThresholdEcdsaSessionRecordsForWallet:
      overrides?.listThresholdEcdsaSessionRecordsForWallet ||
      ((walletId) => [{ ...defaultEcdsaRecord, walletId }]),
    getThresholdEcdsaSessionRecordByThresholdSessionId:
      overrides?.getThresholdEcdsaSessionRecordByThresholdSessionId ||
      ((thresholdSessionId) =>
        thresholdSessionId === defaultEcdsaRecord.thresholdSessionId ? defaultEcdsaRecord : null),
    getThresholdEd25519SessionRecordByThresholdSessionId: (thresholdSessionId) =>
      getStoredThresholdEd25519SessionRecordByThresholdSessionId(thresholdSessionId),
    persistEmailOtpThresholdEd25519LocalMetadata: async (args) => {
      ed25519MetadataWrites.push(args);
    },
    persistWarmSessionEd25519Capability: async (args) => {
      ed25519WarmSessionWrites.push(args);
    },
    hydrateSigningSession: async (args) => {
      hydratedSessions.push(args);
    },
    writeExactSealedSession: async (args) => {
      sealedRecordWrites.push(args);
      if (overrides?.writeExactSealedSession) {
        await overrides.writeExactSealedSession(args);
      }
    },
    readExactSealedSession: overrides?.readExactSealedSession || defaultReadExactSealedSession,
    listExactSealedSessionsForWallet:
      overrides?.listExactSealedSessionsForWallet || defaultListExactSealedSessionsForWallet,
    acquireSigningSessionRestoreLease:
      overrides?.acquireSigningSessionRestoreLease || (async () => null),
    releaseSigningSessionRestoreLease:
      overrides?.releaseSigningSessionRestoreLease || (async () => {}),
    deleteDurableSealedSessionRecord: async () => {},
    updateExactSealedSessionPolicy: async () => {},
  });
  if (overrides?.reconstructEd25519Session) {
    (coordinator as any).runtime.reconstructEd25519Session = overrides.reconstructEd25519Session;
  }

  return {
    coordinator,
    workerCalls,
    ecdsaCommitCalls,
    ed25519ReconstructionCalls,
    ed25519MetadataWrites,
    ed25519WarmSessionWrites,
    hydratedSessions,
    sealedRecordWrites,
    getRefreshCount: () => refreshCount,
  };
}

test.describe('EmailOtpWalletSessionCoordinator', () => {
  test('normalizes warm-session status requests and maps worker failures', async () => {
    const invalid = createCoordinator();
    await expect(invalid.coordinator.readWarmSessionStatusOnly('   ')).resolves.toMatchObject({
      ok: false,
      code: 'invalid_args',
    });
    expect(invalid.workerCalls).toHaveLength(0);

    const failing = createCoordinator({
      requestWorkerOperation: async () => {
        throw new Error('worker unavailable');
      },
    });
    await expect(
      failing.coordinator.readWarmSessionStatusOnly(' session-1 '),
    ).resolves.toMatchObject({
      ok: false,
      code: 'worker_error',
      message: 'worker unavailable',
    });
    expect(failing.workerCalls[0].request.payload.sessionId).toBe('session-1');
  });

  test('consumes warm-session uses without returning secret material', async () => {
    const { coordinator, workerCalls } = createCoordinator({
      requestWorkerOperation: async () => ({
        ok: true,
        remainingUses: 2,
        expiresAtMs: Date.now() + 60_000,
      }),
    });

    const result = await coordinator.consumeWarmSessionUses({ sessionId: ' session-1 ', uses: 2 });

    expect(result).toMatchObject({ ok: true, remainingUses: 2 });
    expect(JSON.stringify(result)).not.toContain('prfFirstB64u');
    expect(workerCalls[0]).toMatchObject({
      kind: 'emailOtp',
      request: {
        type: 'consumeEmailOtpWarmSessionUses',
        payload: {
          sessionId: 'session-1',
          uses: 2,
        },
      },
    });
  });

  test('requests transaction challenges with signing-session auth only', async () => {
    const { coordinator, workerCalls, getRefreshCount } = createCoordinator();
    const walletSessionJwt = 'threshold-session-jwt';

    const challenge = await coordinator.requestTransactionSigningChallenge({
      kind: 'near_account_challenge',
      walletSession: TEST_WALLET_SESSION,
      nearAccountId: 'alice.testnet',
      chain: 'near',
      authLane: {
        kind: 'signing_session',
        jwt: walletSessionJwt,
        thresholdSessionId: 'ed25519-session',
        authorizingSigningGrantId: toAuthorizingSigningGrantId('signing-grant'),
        curve: 'ed25519',
      },
    });

    expect(challenge).toMatchObject({
      challengeId: 'challenge-1',
      emailHint: 'a***@example.com',
    });
    expect(getRefreshCount()).toBe(0);
    expect(workerCalls[0]).toMatchObject({
      kind: 'emailOtp',
      request: {
        type: 'requestEmailOtpChallenge',
        payload: {
          relayUrl: 'https://relay.example',
          walletId: 'alice.testnet',
          routePlan: {
            routeFamily: 'signing_session',
            authLane: {
              kind: 'signing_session',
              jwt: walletSessionJwt,
              thresholdSessionId: 'ed25519-session',
              authorizingSigningGrantId: 'signing-grant',
              curve: 'ed25519',
            },
            operation: 'transaction_sign',
          },
          otpChannel: 'email_otp',
        },
      },
    });
  });

  test('transaction challenges reject missing signing-session authority', async () => {
    const { coordinator, workerCalls, getRefreshCount } = createCoordinator();

    await expect(
      coordinator.requestTransactionSigningChallenge({
        kind: 'near_account_challenge',
        walletSession: TEST_WALLET_SESSION,
        nearAccountId: 'alice.testnet',
        chain: 'near',
      } as never),
    ).rejects.toThrow(
      'Email OTP ed25519 signing-session auth lane is unavailable at provided_route_auth',
    );

    expect(getRefreshCount()).toBe(0);
    expect(workerCalls).toHaveLength(0);
  });

  test('Email OTP export resend updates the challenge used for authorization', async () => {
    const challengeRequests: Array<Record<string, unknown>> = [];
    const walletSessionJwt = 'threshold-session-jwt';
    const { coordinator } = createCoordinator({
      requestWorkerOperation: async (call) => {
        if (call.request?.type !== 'requestEmailOtpChallenge') return { ok: true };
        challengeRequests.push(call.request.payload);
        const issueNumber = challengeRequests.length;
        return {
          challengeId: `export-challenge-${issueNumber}`,
          emailHint: `a***${issueNumber}@example.test`,
        };
      },
    });

    await expect(
      requestEmailOtpExportAuthorization({
        identity: {
          kind: 'wallet_session',
          walletId: TEST_WALLET_SESSION.walletId,
        },
        chain: 'evm',
        publicKey: '02'.padEnd(66, '1'),
        curve: 'ecdsa',
        challengeSource: {
          requestChallenge: async () =>
            await coordinator.requestExportChallenge({
              kind: 'wallet_session_challenge',
              walletSession: TEST_WALLET_SESSION,
              chain: 'evm',
              authLane: {
                kind: 'signing_session',
                jwt: walletSessionJwt,
                thresholdSessionId: 'ecdsa-session',
                authorizingSigningGrantId: toAuthorizingSigningGrantId('signing-grant'),
                curve: 'ecdsa',
                chainTarget: EVM_CHAIN_TARGET,
              },
            }),
        },
        confirmer: {
          requestUserConfirmation: async (request: any) => {
            expect(request.payload.signingAuthPlan.emailOtpPrompt.challengeId).toBe(
              'export-challenge-1',
            );
            const resent = await request.payload.signingAuthPlan.emailOtpPrompt.onResend();
            expect(resent).toEqual({
              challengeId: 'export-challenge-2',
              emailHint: 'a***2@example.test',
            });
            return {
              requestId: request.requestId,
              confirmed: true,
              otpCode: '654321',
              emailOtpChallengeId: resent.challengeId,
            };
          },
        },
      }),
    ).resolves.toEqual({
      challengeId: 'export-challenge-2',
      otpCode: '654321',
    });
    expect(challengeRequests).toEqual([
      {
        relayUrl: 'https://relay.example',
        walletId: 'alice.testnet',
        routePlan: {
          routeFamily: 'signing_session',
          authLane: {
            kind: 'signing_session',
            jwt: walletSessionJwt,
            thresholdSessionId: 'ecdsa-session',
            authorizingSigningGrantId: 'signing-grant',
            curve: 'ecdsa',
            chainTarget: EVM_CHAIN_TARGET,
          },
          operation: 'export_key',
        },
        otpChannel: 'email_otp',
      },
      {
        relayUrl: 'https://relay.example',
        walletId: 'alice.testnet',
        routePlan: {
          routeFamily: 'signing_session',
          authLane: {
            kind: 'signing_session',
            jwt: walletSessionJwt,
            thresholdSessionId: 'ecdsa-session',
            authorizingSigningGrantId: 'signing-grant',
            curve: 'ecdsa',
            chainTarget: EVM_CHAIN_TARGET,
          },
          operation: 'export_key',
        },
        otpChannel: 'email_otp',
      },
    ]);
  });

  test('transaction challenges reject app-session route auth instead of resolving it', async () => {
    const { coordinator, getRefreshCount, workerCalls } = createCoordinator();
    const jwt = appSessionJwt();

    await expect(
      coordinator.requestTransactionSigningChallenge({
        kind: 'near_account_challenge',
        walletSession: TEST_WALLET_SESSION,
        nearAccountId: 'alice.testnet',
        chain: 'near',
        routeAuth: { kind: 'app_session', jwt },
      } as never),
    ).rejects.toThrow(
      'Email OTP ed25519 signing-session auth lane is unavailable at provided_route_auth',
    );

    expect(getRefreshCount()).toBe(0);
    expect(workerCalls).toHaveLength(0);
  });

  test('Email OTP ECDSA companion selection chooses current authority after signing-grant rotation', () => {
    const nowMs = Date.now();
    const records: ThresholdEcdsaSessionRecord[] = [
      {
        ...makeEmailOtpEcdsaRecordForSelection({
          thresholdSessionId: 'ecdsa-session-old',
          signingGrantId: 'ed25519-stale-wallet-session',
          keyHandle: 'key-handle-ecdsa',
          ecdsaThresholdKeyId: 'ecdsa-key',
          relayerKeyId: 'relayer-key',
          clientVerifyingShareB64u: 'verifying-share',
          updatedAtMs: nowMs,
        }),
        expiresAtMs: nowMs + 60_000,
      },
      {
        ...makeEmailOtpEcdsaRecordForSelection({
          thresholdSessionId: 'ecdsa-session-current',
          signingGrantId: 'current-ecdsa-wallet-session',
          keyHandle: 'key-handle-ecdsa',
          ecdsaThresholdKeyId: 'ecdsa-key',
          relayerKeyId: 'relayer-key',
          clientVerifyingShareB64u: 'verifying-share',
          updatedAtMs: nowMs + 1,
        }),
        expiresAtMs: nowMs + 120_000,
      },
    ];

    expect(
      selectEmailOtpEcdsaCompanionLaneForEd25519Signing({
        kind: 'current_wallet_authority',
        walletId: TEST_SUBJECT_ID,
        authority: emailOtpAuthorityFromEcdsaRecord(records[0]),
        listThresholdEcdsaSessionRecordsForWallet: () => records,
      }),
    ).toMatchObject({
      kind: 'ready',
      companion: {
        kind: 'single_companion_lane',
        lane: {
          committedLane: {
            record: {
              thresholdSessionId: 'ecdsa-session-current',
              signingGrantId: 'current-ecdsa-wallet-session',
            },
          },
        },
      },
    });

    expect(
      selectEmailOtpEcdsaCompanionLaneForEd25519Signing({
        kind: 'latest_wallet_record',
        walletId: TEST_SUBJECT_ID,
        listThresholdEcdsaSessionRecordsForWallet: () => records,
      }),
    ).toMatchObject({
      kind: 'display_only_fallback',
      lane: {
        committedLane: {
          record: {
            thresholdSessionId: 'ecdsa-session-current',
          },
        },
      },
    });
  });

  test('Email OTP ECDSA companion selection returns committed lanes', () => {
    const records: ThresholdEcdsaSessionRecord[] = [
      makeEmailOtpEcdsaRecordForSelection({
        thresholdSessionId: 'ecdsa-session',
        signingGrantId: 'wallet-session-ed25519',
        keyHandle: 'key-handle-ecdsa',
        ecdsaThresholdKeyId: 'ecdsa-key',
        relayerKeyId: 'relayer-key',
        clientVerifyingShareB64u: 'verifying-share',
        updatedAtMs: Date.now(),
      }),
    ];

    expect(
      selectEmailOtpEcdsaCompanionLaneForEd25519Signing({
        kind: 'current_wallet_authority',
        walletId: TEST_SUBJECT_ID,
        authority: emailOtpAuthorityFromEcdsaRecord(records[0]),
        listThresholdEcdsaSessionRecordsForWallet: () => records,
      }),
    ).toMatchObject({
      kind: 'ready',
      companion: {
        kind: 'single_companion_lane',
        lane: {
          committedLane: {
            source: 'record_backed',
            record: {
              thresholdSessionId: 'ecdsa-session',
            },
            authLane: {
              kind: 'signing_session',
              curve: 'ecdsa',
            },
            walletSessionAuthority: {
              walletSessionJwt: expect.any(String),
              signingGrantId: 'wallet-session-ed25519',
            },
          },
        },
      },
    });
  });

  test('Email OTP ECDSA companion selection skips records missing wallet authority', () => {
    const records: ThresholdEcdsaSessionRecord[] = [
      {
        ...makeEmailOtpEcdsaRecordForSelection({
          thresholdSessionId: 'ecdsa-session',
          signingGrantId: 'wallet-session-ed25519',
          keyHandle: 'key-handle-ecdsa',
          ecdsaThresholdKeyId: 'ecdsa-key',
          relayerKeyId: 'relayer-key',
          clientVerifyingShareB64u: 'verifying-share',
          updatedAtMs: Date.now(),
        }),
        walletSessionJwt: '',
      },
    ];

    expect(
      selectEmailOtpEcdsaCompanionLaneForEd25519Signing({
        kind: 'current_wallet_authority',
        walletId: TEST_SUBJECT_ID,
        authority: emailOtpAuthorityFromEcdsaRecord(records[0]),
        listThresholdEcdsaSessionRecordsForWallet: () => records,
      }),
    ).toMatchObject({ kind: 'not_found' });
  });

  test('Email OTP ECDSA companion selection rejects multiple same-chain authority key groups', () => {
    const records: ThresholdEcdsaSessionRecord[] = [
      makeEmailOtpEcdsaRecordForSelection({
        thresholdSessionId: 'ecdsa-session-a',
        signingGrantId: 'wallet-session-ed25519',
        keyHandle: 'key-handle-ecdsa-a',
        ecdsaThresholdKeyId: 'ecdsa-key-a',
        relayerKeyId: 'relayer-key-a',
        clientVerifyingShareB64u: 'verifying-share-a',
        updatedAtMs: Date.now(),
      }),
      makeEmailOtpEcdsaRecordForSelection({
        thresholdSessionId: 'ecdsa-session-b',
        signingGrantId: 'wallet-session-ed25519',
        keyHandle: 'key-handle-ecdsa-b',
        ecdsaThresholdKeyId: 'ecdsa-key-b',
        relayerKeyId: 'relayer-key-b',
        clientVerifyingShareB64u: 'verifying-share-b',
        updatedAtMs: Date.now() + 1,
      }),
    ];

    expect(
      selectEmailOtpEcdsaCompanionLaneForEd25519Signing({
        kind: 'current_wallet_authority',
        walletId: TEST_SUBJECT_ID,
        authority: emailOtpAuthorityFromEcdsaRecord(records[0]),
        listThresholdEcdsaSessionRecordsForWallet: () => records,
      }),
    ).toMatchObject({
      kind: 'ambiguous_material',
      count: 2,
    });
  });

  test('Email OTP ECDSA companion selection canonicalizes same-chain records for one authority key', () => {
    const nowMs = Date.now();
    const records: ThresholdEcdsaSessionRecord[] = [
      makeEmailOtpEcdsaRecordForSelection({
        thresholdSessionId: 'ecdsa-session-old',
        signingGrantId: 'wallet-session-ed25519',
        keyHandle: 'key-handle-ecdsa-shared',
        ecdsaThresholdKeyId: 'ecdsa-key-shared',
        relayerKeyId: 'relayer-key-shared',
        clientVerifyingShareB64u: 'verifying-share-shared',
        updatedAtMs: nowMs,
      }),
      makeEmailOtpEcdsaRecordForSelection({
        thresholdSessionId: 'ecdsa-session-current',
        signingGrantId: 'wallet-session-ed25519',
        keyHandle: 'key-handle-ecdsa-shared',
        ecdsaThresholdKeyId: 'ecdsa-key-shared',
        relayerKeyId: 'relayer-key-shared',
        clientVerifyingShareB64u: 'verifying-share-shared',
        updatedAtMs: nowMs + 1,
      }),
    ];

    expect(
      selectEmailOtpEcdsaCompanionLaneForEd25519Signing({
        kind: 'current_wallet_authority',
        walletId: TEST_SUBJECT_ID,
        authority: emailOtpAuthorityFromEcdsaRecord(records[0]),
        listThresholdEcdsaSessionRecordsForWallet: () => records,
      }),
    ).toMatchObject({
      kind: 'ready',
      companion: {
        kind: 'single_companion_lane',
        lane: {
          committedLane: {
            record: {
              thresholdSessionId: 'ecdsa-session-current',
            },
          },
        },
      },
    });
  });

  test('Email OTP ECDSA companion selection keeps same provider subject wallet-scoped', () => {
    const otherWallet = toWalletId('bob.testnet');
    const records: ThresholdEcdsaSessionRecord[] = [
      makeEmailOtpEcdsaRecordForSelection({
        thresholdSessionId: 'ecdsa-session-alice',
        signingGrantId: 'wallet-session-ed25519',
        chainTarget: TEMPO_CHAIN_TARGET,
        keyHandle: 'key-handle-ecdsa-alice',
        ecdsaThresholdKeyId: 'ecdsa-key-alice',
        relayerKeyId: 'relayer-key-alice',
        clientVerifyingShareB64u: 'verifying-share-alice',
        updatedAtMs: Date.now(),
      }),
      {
        ...makeEmailOtpEcdsaRecordForSelection({
          thresholdSessionId: 'ecdsa-session-bob',
          signingGrantId: 'wallet-session-ed25519',
          chainTarget: TEMPO_CHAIN_TARGET,
          keyHandle: 'key-handle-ecdsa-bob',
          ecdsaThresholdKeyId: 'ecdsa-key-bob',
          relayerKeyId: 'relayer-key-bob',
          clientVerifyingShareB64u: 'verifying-share-bob',
          updatedAtMs: Date.now() + 1,
        }),
        walletId: otherWallet,
      },
    ];

    expect(
      selectEmailOtpEcdsaCompanionLaneForEd25519Signing({
        kind: 'current_wallet_authority',
        walletId: TEST_SUBJECT_ID,
        authority: emailOtpAuthorityFromEcdsaRecord(records[0]),
        listThresholdEcdsaSessionRecordsForWallet: () => records,
      }),
    ).toMatchObject({
      kind: 'ready',
      companion: {
        kind: 'single_companion_lane',
        lane: {
          committedLane: {
            record: {
              thresholdSessionId: 'ecdsa-session-alice',
            },
          },
        },
      },
    });
  });

  test('Email OTP ECDSA companion selection allows exact signing-grant matches across chain targets', () => {
    const records: ThresholdEcdsaSessionRecord[] = [
      makeEmailOtpEcdsaRecordForSelection({
        thresholdSessionId: 'ecdsa-session-tempo',
        signingGrantId: 'wallet-session-ed25519',
        chainTarget: TEMPO_CHAIN_TARGET,
        keyHandle: 'key-handle-ecdsa-tempo',
        ecdsaThresholdKeyId: 'ecdsa-key-tempo',
        relayerKeyId: 'relayer-key-tempo',
        clientVerifyingShareB64u: 'verifying-share-tempo',
        updatedAtMs: Date.now(),
      }),
      makeEmailOtpEcdsaRecordForSelection({
        thresholdSessionId: 'ecdsa-session-evm',
        signingGrantId: 'wallet-session-ed25519',
        chainTarget: EVM_CHAIN_TARGET,
        keyHandle: 'key-handle-ecdsa-evm',
        ecdsaThresholdKeyId: 'ecdsa-key-evm',
        relayerKeyId: 'relayer-key-evm',
        clientVerifyingShareB64u: 'verifying-share-evm',
        updatedAtMs: Date.now() + 1,
      }),
    ];

    expect(
      selectEmailOtpEcdsaCompanionLaneForEd25519Signing({
        kind: 'current_wallet_authority',
        walletId: TEST_SUBJECT_ID,
        authority: emailOtpAuthorityFromEcdsaRecord(records[0]),
        listThresholdEcdsaSessionRecordsForWallet: () => records,
      }),
    ).toMatchObject({
      kind: 'ready',
      companion: {
        kind: 'chain_distinct_companion_lanes',
        primaryLane: {
          committedLane: {
            record: {
              thresholdSessionId: 'ecdsa-session-evm',
            },
          },
        },
      },
    });
  });

  test('logs in Ed25519 Email OTP capability with normalized auth context', async () => {
    const ed25519ReconstructionCalls: any[] = [];
    const ecdsaWalletSessionJwt = thresholdEcdsaSessionJwt({
      walletId: 'alice.testnet',
      keyHandle: 'key-handle-ecdsa',
      thresholdSessionId: 'ecdsa-session',
      signingGrantId: 'wallet-session-ed25519',
      chainTarget: TEMPO_CHAIN_TARGET,
    });
    const { coordinator, workerCalls } = createCoordinator({
      listThresholdEcdsaSessionRecordsForWallet: () => [
        {
          ...makeEmailOtpEcdsaRecordForSelection({
            thresholdSessionId: 'ecdsa-session',
            signingGrantId: 'wallet-session-ed25519',
            keyHandle: 'key-handle-ecdsa',
            ecdsaThresholdKeyId: 'ecdsa-key',
            relayerKeyId: 'relayer-key',
            clientVerifyingShareB64u: 'verifying-share',
            updatedAtMs: Date.now(),
          }),
          walletSessionJwt: ecdsaWalletSessionJwt,
        },
      ],
      reconstructEd25519Session: async (args) => {
        ed25519ReconstructionCalls.push(args);
        return {
          relayerKeyId: 'relayer-key',
          keyVersion: 'v1',
          sessionId: 'ed-session',
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 1,
          participantIds: [1, 2],
          jwt: 'threshold-jwt',
        };
      },
    });
    const walletSessionJwt = 'threshold-ed25519-jwt';
    const ed25519Record = {
      walletId: TEST_SUBJECT_ID,
      nearAccountId: 'alice.testnet',
      nearEd25519SigningKeyId: 'alice.testnet',
      thresholdSessionId: 'old-session',
      signingGrantId: 'wallet-session-ed25519',
      curve: 'ed25519' as const,
      relayerUrl: '',
      rpId: '',
      relayerKeyId: 'relayer-key',
      keyVersion: 'v1',
      signerSlot: 1,
      participantIds: [1, 2],
      thresholdSessionKind: 'jwt' as const,
      walletSessionJwt,
      expiresAtMs: Date.now() + 60_000,
      remainingUses: 1,
      runtimePolicyScope: {
        orgId: 'org',
        projectId: 'project',
        envId: 'dev',
        signingRootVersion: 'root',
      },
      emailOtpAuthContext: emailOtpAuthContextFixture({
        policy: 'per_operation',
        retention: 'single_use',
        providerUserId: 'google:subject',
      }),
      source: 'email_otp' as const,
    };

    const ed25519SigningAuthority = buildEmailOtpEd25519SigningSessionAuthority({
      authLane: {
        kind: 'signing_session',
        jwt: walletSessionJwt,
        thresholdSessionId: 'old-session',
        authorizingSigningGrantId: toAuthorizingSigningGrantId('wallet-session-ed25519'),
        curve: 'ed25519',
      },
      authority: ed25519Record.emailOtpAuthContext.authority,
    });
    if (!ed25519SigningAuthority) {
      throw new Error('expected Ed25519 signing authority fixture');
    }

    const result = await coordinator.loginWithEd25519CapabilityForSigning({
      nearAccountId: 'alice.testnet',
      challengeId: 'challenge-1',
      otpCode: '123456',
      committedLane: buildEd25519SigningLane({
        record: ed25519Record,
        authority: ed25519SigningAuthority,
      }),
    });

    expect(result.sessionId).toBe('ed-session');
    expect(ed25519ReconstructionCalls).toHaveLength(1);
    expect(ed25519ReconstructionCalls[0]).toMatchObject({
      relayUrl: 'https://relay.example',
      rpId: 'localhost',
      recoveryCodeSecret32B64u: 'prf-first-ecdsa-login',
      routeAuth: { kind: 'wallet_session', jwt: expect.any(String) },
      ed25519Key: {
        signer: {
          account: {
            kind: 'named_near_account',
            wallet: { walletId: 'alice.testnet' },
            nearAccountId: 'alice.testnet',
          },
          nearEd25519SigningKeyId: 'alice.testnet',
          signerSlot: 1,
        },
        relayerKeyId: 'relayer-key',
        keyVersion: 'threshold-ed25519-hss-v1',
        participantIds: [1, 2],
      },
      remainingUses: 1,
      ecdsaThresholdSessionId: 'ecdsa-session',
      emailOtpAuthContext: emailOtpAuthContextFixture({
        policy: 'per_operation',
        retention: 'single_use',
        providerUserId: 'google:subject',
      }),
    });
    const loginCall = workerCalls.find((call) => call.request?.type === 'loginWithEmailOtpWallet');
    expect(loginCall?.request?.payload?.routePlan?.authLane).toMatchObject({
      kind: 'signing_session',
      jwt: walletSessionJwt,
      thresholdSessionId: 'old-session',
      curve: 'ed25519',
    });
    const bootstrapCall = workerCalls.find(
      (call) => call.request?.type === 'bootstrapEmailOtpEcdsaSessionsFromWorkerHandle',
    );
    expect(bootstrapCall?.request?.payload?.routeAuth).toEqual({
      kind: 'wallet_session',
      jwt: ecdsaWalletSessionJwt,
    });
  });

  test('exports Ed25519 seed material in the Email OTP worker without hydrating a signing session', async () => {
    const { coordinator, workerCalls, hydratedSessions, getRefreshCount } = createCoordinator();
    const runtimePolicyScope = {
      orgId: 'org',
      projectId: 'signing-root',
      envId: 'dev',
      signingRootVersion: 'v1',
    };
    const walletSessionJwt = `${jsonB64u({ alg: 'none', typ: 'JWT' })}.${jsonB64u({
      kind: 'threshold_ed25519_session_v1',
      sessionId: 'ed25519-restored-session',
      sub: 'alice.testnet',
      walletId: 'alice.testnet',
      exp: Math.floor(Date.now() / 1000) + 3600,
    })}.sig`;
    const record = {
      walletId: TEST_SUBJECT_ID,
      nearAccountId: 'alice.testnet',
      nearEd25519SigningKeyId: 'alice.testnet',
      thresholdSessionId: 'ed25519-restored-session',
      signingGrantId: 'signing-grant-1',
      relayerUrl: 'https://relay.example',
      rpId: 'localhost',
      relayerKeyId: 'relayer-key',
      keyVersion: 'v1',
      participantIds: [1, 2],
      thresholdSessionKind: 'jwt',
      walletSessionJwt,
      runtimePolicyScope,
      expiresAtMs: Date.now() + 60_000,
      remainingUses: 4,
      emailOtpAuthContext: emailOtpAuthContextFixture(),
      source: 'email_otp',
    } as any;
    const authLane = {
      kind: 'signing_session' as const,
      jwt: walletSessionJwt,
      thresholdSessionId: 'ed25519-restored-session',
      authorizingSigningGrantId: toAuthorizingSigningGrantId('signing-grant-1'),
      curve: 'ed25519' as const,
    };
    const result = await coordinator.exportEd25519SeedWithAuthorization({
      nearAccountId: 'alice.testnet',
      challengeId: 'challenge-1',
      otpCode: '123456',
      committedLane: {
        source: 'record_backed',
        record,
        authLane,
        walletSessionAuthority: {
          kind: 'wallet_session_authority',
          walletSessionJwt,
          thresholdSessionId: 'ed25519-restored-session',
          signingGrantId: 'signing-grant-1',
        },
        participantIds: [1, 2],
        relayerKeyId: 'relayer-key',
        expectedPublicKey: 'ed25519:public',
      },
    });

    expect(result).toEqual({ publicKey: 'ed25519:public', privateKey: 'ed25519:private' });
    expect(getRefreshCount()).toBe(0);
    expect(workerCalls[0].request).toMatchObject({
      type: 'exportEmailOtpEd25519SeedWithAuthorization',
      payload: {
        walletId: 'alice.testnet',
        nearAccountId: 'alice.testnet',
        challengeId: 'challenge-1',
        otpCode: '123456',
        runtimePolicyScope,
        participantIds: [1, 2],
        thresholdSessionId: 'ed25519-restored-session',
        walletSessionJwt: walletSessionJwt,
        relayerKeyId: 'relayer-key',
        expectedPublicKey: 'ed25519:public',
        routePlan: {
          routeFamily: 'signing_session',
          authLane: {
            kind: 'signing_session',
            jwt: walletSessionJwt,
            thresholdSessionId: 'ed25519-restored-session',
            authorizingSigningGrantId: 'signing-grant-1',
            curve: 'ed25519',
          },
          operation: 'export_key',
        },
      },
    });
    expect(workerCalls[0].request.payload).not.toHaveProperty('signingRootId');
    expect(workerCalls[0].request.payload).not.toHaveProperty('signingRootVersion');
    expect(hydratedSessions).toEqual([]);
  });

  test('logs in ECDSA Email OTP capability with normalized worker payload and persistence callback', async () => {
    const { coordinator, workerCalls, ecdsaCommitCalls } = createCoordinator();

    const runtimePolicyScope = {
      orgId: 'org',
      projectId: 'proj',
      envId: 'dev',
      signingRootVersion: 'v1',
    };
    const jwt = appSessionJwtWithRuntimePolicyScope(runtimePolicyScope);
    const keyHandle = await roleLocalEcdsaKeyHandle({
      walletId: 'alice.testnet',
      rpId: 'localhost',
      projectId: runtimePolicyScope.projectId,
      envId: runtimePolicyScope.envId,
      signingRootVersion: runtimePolicyScope.signingRootVersion,
    });
    const result = await coordinator.loginWithEcdsaCapabilityInternal({
      walletSession: TEST_WALLET_SESSION,
      chainTarget: TEMPO_CHAIN_TARGET,
      challengeId: 'challenge-1',
      otpCode: '123456',
      emailHashHex: 'email-hash',
      routePlan: loginRoutePlanFromAppSessionJwt(jwt),
      keyHandle,
      participantIds: [1, 3],
      ecdsaBootstrapAuthorization: { kind: 'route_plan_auth' },
      runtimePolicyScope,
      ed25519ReconstructionMode: 'skip',
      ed25519SessionReconstruction: DEFER_ED25519_RECONSTRUCTION_FOR_ECDSA,
      providerIdentity: { kind: 'derive_from_route_auth' },
    });

    expect(result.bootstrap.thresholdEcdsaKeyRef.ecdsaThresholdKeyId).toBe('ecdsa-key');
    expect(workerCalls.at(-2)).toMatchObject({
      kind: 'emailOtp',
      request: {
        type: 'loginWithEmailOtpWallet',
        payload: {
          relayUrl: 'https://relay.example',
          walletId: 'alice.testnet',
          userId: 'alice.testnet',
          challengeId: 'challenge-1',
          otpCode: '123456',
          routePlan: {
            routeFamily: 'login',
            authLane: { kind: 'app_session', jwt },
            operation: 'wallet_unlock',
          },
        },
      },
    });
    expect(workerCalls.at(-1)).toMatchObject({
      kind: 'emailOtp',
      request: {
        type: 'bootstrapEmailOtpEcdsaSessionsFromWorkerHandle',
        payload: {
          relayUrl: 'https://relay.example',
          walletId: 'alice.testnet',
          userId: 'alice.testnet',
          evmFamilySigningKeySlotId: 'wallet-key:evm-family:alice.testnet:proj%3Adev:v1',
          keyHandle,
          participantIds: [1, 3],
          sessionKind: 'jwt',
          remainingUses: 3,
          routeAuth: { kind: 'app_session', jwt },
        },
      },
    });
    expect(workerCalls.at(-1)?.request.payload).not.toHaveProperty('rpId');
    expect(ecdsaCommitCalls[0]).toMatchObject({
      walletId: 'alice.testnet',
      chainTarget: { kind: 'tempo', chainId: 42431 },
      source: 'email_otp',
      emailOtpAuthContext: emailOtpAuthContextFixture(),
    });
    expect(result.ed25519Reconstruction).toMatchObject({
      kind: 'deferred',
      reason: 'not_needed_for_ecdsa',
    });
  });

  test('normal ECDSA Email OTP login derives app-session route auth from appSessionJwt', async () => {
    const { coordinator, workerCalls } = createCoordinator();
    const runtimePolicyScope = {
      orgId: 'org',
      projectId: 'proj',
      envId: 'dev',
      signingRootVersion: 'v1',
    };
    const jwt = appSessionJwtWithRuntimePolicyScope(runtimePolicyScope);
    const keyHandle = await roleLocalEcdsaKeyHandle({
      walletId: 'alice.testnet',
      rpId: 'localhost',
      projectId: runtimePolicyScope.projectId,
      envId: runtimePolicyScope.envId,
      signingRootVersion: runtimePolicyScope.signingRootVersion,
    });
    await coordinator.loginWithEcdsaCapabilityInternal({
      walletSession: TEST_WALLET_SESSION,
      chainTarget: TEMPO_CHAIN_TARGET,
      challengeId: 'challenge-1',
      otpCode: '123456',
      emailHashHex: 'email-hash',
      routePlan: loginRoutePlanFromAppSessionJwt(jwt),
      keyHandle,
      participantIds: [1, 3],
      ecdsaBootstrapAuthorization: { kind: 'route_plan_auth' },
      ed25519ReconstructionMode: 'skip',
      ed25519SessionReconstruction: DEFER_ED25519_RECONSTRUCTION_FOR_ECDSA,
      providerIdentity: { kind: 'derive_from_route_auth' },
    });

    expect(workerCalls.at(-1)).toMatchObject({
      kind: 'emailOtp',
      request: {
        type: 'bootstrapEmailOtpEcdsaSessionsFromWorkerHandle',
        payload: {
          routeAuth: { kind: 'app_session', jwt },
        },
      },
    });
  });

  test('ECDSA Email OTP login rejects missing runtime scope before worker unlock', async () => {
    const { coordinator, workerCalls } = createCoordinator();
    const jwt = appSessionJwt();

    await expect(
      coordinator.loginWithEcdsaCapabilityInternal({
        walletSession: TEST_WALLET_SESSION,
        chainTarget: TEMPO_CHAIN_TARGET,
        challengeId: 'challenge-1',
        otpCode: '123456',
        emailHashHex: 'email-hash',
        routePlan: loginRoutePlanFromAppSessionJwt(jwt),
        keyHandle: 'ehss-key-handle-1',
        participantIds: [1, 3],
        ecdsaBootstrapAuthorization: { kind: 'route_plan_auth' },
        ed25519ReconstructionMode: 'skip',
        ed25519SessionReconstruction: DEFER_ED25519_RECONSTRUCTION_FOR_ECDSA,
        providerIdentity: { kind: 'derive_from_route_auth' },
      }),
    ).rejects.toThrow('Email OTP ECDSA login requires runtimePolicyScope');

    expect(workerCalls.some((call) => call.request?.type === 'loginWithEmailOtpWallet')).toBe(
      false,
    );
    expect(
      workerCalls.some(
        (call) => call.request?.type === 'bootstrapEmailOtpEcdsaSessionsFromWorkerHandle',
      ),
    ).toBe(false);
  });

  test('Email OTP registration bootstrap uses the committed registration route plan', async () => {
    const { coordinator, workerCalls } = createCoordinator();
    const runtimePolicyScope = {
      orgId: 'org',
      projectId: 'proj',
      envId: 'dev',
      signingRootVersion: 'v1',
    };
    const jwt = appSessionJwtWithRuntimePolicyScope(runtimePolicyScope);

    await coordinator.enrollAndLoginWithEcdsaCapabilityInternal({
      walletSession: TEST_WALLET_SESSION,
      chainTarget: TEMPO_CHAIN_TARGET,
      challengeId: 'challenge-1',
      otpCode: '123456',
      emailHashHex: 'email-hash',
      routePlan: registrationRoutePlanFromAppSessionJwt(jwt),
      participantIds: [1, 3],
      registrationAttemptId: 'registration-attempt-1',
    });

    expect(workerCalls.at(-2)).toMatchObject({
      kind: 'emailOtp',
      request: {
        type: 'enrollEmailOtpWallet',
        payload: {
          routePlan: {
            routeFamily: 'registration',
            authLane: { kind: 'app_session', jwt },
            operation: 'wallet_unlock',
          },
        },
      },
    });
    expect(workerCalls.at(-1)).toMatchObject({
      kind: 'emailOtp',
      request: {
        type: 'bootstrapEmailOtpEcdsaSessionsFromWorkerHandle',
        payload: {
          routeAuth: { kind: 'app_session', jwt },
        },
      },
    });
  });

  test('Email OTP ECDSA registration skips Ed25519 reconstruction', async () => {
    const { coordinator } = createCoordinator();
    const runtimePolicyScope = {
      orgId: 'org',
      projectId: 'proj',
      envId: 'dev',
      signingRootVersion: 'v1',
    };
    const jwt = appSessionJwtWithRuntimePolicyScope(runtimePolicyScope);
    const result = await coordinator.enrollAndLoginWithEcdsaCapabilityInternal({
      walletSession: TEST_WALLET_SESSION,
      chainTarget: TEMPO_CHAIN_TARGET,
      challengeId: 'challenge-1',
      otpCode: '123456',
      emailHashHex: 'email-hash',
      routePlan: registrationRoutePlanFromAppSessionJwt(jwt),
      participantIds: [1, 3],
      registrationAttemptId: 'registration-attempt-1',
    });

    expect(result.bootstrap.thresholdEcdsaKeyRef.keyHandle).toBe('key-handle-ecdsa');
  });

  test('persists sealed Email OTP signing-session refresh only for session-retained ECDSA login', async () => {
    const { coordinator, workerCalls, sealedRecordWrites } = createCoordinator({
      configs: {
        signing: {
          emailOtp: { authPolicy: 'session' },
          sessionPersistenceMode: 'sealed_refresh_v1',
          sessionSeal: {
            signingSessionSealKeyVersion: TEST_SIGNING_SESSION_SEAL_KEY_VERSION,
            shamirPrimeB64u: 'prime-b64u',
          },
        },
      },
      requestWorkerOperation: async (call) => {
        if (call.request?.type === 'loginWithEmailOtpWallet') {
          return {
            recovery: {
              loginGrant: 'login-grant',
              challengeId: 'challenge-1',
              enrollmentSealKeyVersion: 'email-v1',
              unlockChallengeId: 'unlock-challenge',
              unlockChallengeB64u: 'unlock-challenge-b64u',
              clientUnlockPublicKeyB64u: 'unlock-public',
              unlockSignatureB64u: 'unlock-sig',
              thresholdEd25519RecoveryCodeSecret32B64u: 'prf-first-ecdsa-login',
            },
            clientRootShareHandle: emailOtpEcdsaClientRootHandleFromWorkerCall(call),
          };
        }
        if (call.request?.type === 'bootstrapEmailOtpEcdsaSessionsFromWorkerHandle') {
          return {
            bootstraps: call.request.payload.publicationChainTargets.map((chainTarget: any) => ({
              thresholdEcdsaKeyRef: {
                type: 'threshold-ecdsa-secp256k1',
                userId: 'alice.testnet',
                subjectId: call.request.payload.subjectId,
                relayerUrl: 'https://relay.example',
                keyHandle: 'key-handle-ecdsa',
                ecdsaThresholdKeyId: 'ecdsa-key',
                chainTarget,
                signingRootId: 'signing-root',
                signingRootVersion: 'root-v1',
                ethereumAddress: `0x${'33'.repeat(20)}`,
                thresholdEcdsaPublicKeyB64u: 'threshold-public-key',
                thresholdSessionId: 'ecdsa-session',
                signingGrantId: call.request.payload.signingGrantId,
                thresholdSessionKind: 'jwt',
                walletSessionJwt: thresholdEcdsaSessionJwt({
                  walletId: 'alice.testnet',
                  keyHandle: 'key-handle-ecdsa',
                  thresholdSessionId: 'ecdsa-session',
                  signingGrantId: call.request.payload.signingGrantId,
                  chainTarget,
                }),
                participantIds: [1, 3],
                backendBinding: TEST_ECDSA_BACKEND_BINDING,
              },
              keygen: {
                ok: true,
                evmFamilySigningKeySlotId: call.request.payload.evmFamilySigningKeySlotId,
              },
              session: {
                ok: true,
                sessionId: 'ecdsa-session',
                signingGrantId: call.request.payload.signingGrantId,
                expiresAtMs: Date.now() + 60_000,
                remainingUses: 9,
                jwt: thresholdEcdsaSessionJwt({
                  walletId: 'alice.testnet',
                  keyHandle: 'key-handle-ecdsa',
                  thresholdSessionId: 'ecdsa-session',
                  signingGrantId: call.request.payload.signingGrantId,
                  chainTarget,
                }),
              },
            })),
          };
        }
        if (call.request?.type === 'sealEmailOtpWarmSessionMaterial') {
          return {
            ok: true,
            sealedSecretB64u: 'sealed-email-otp-session-secret',
            keyVersion: 'signing-session-seal-kek-test-r1',
            expiresAtMs: Date.now() + 60_000,
            remainingUses: 9,
          };
        }
        return { ok: true };
      },
    });
    const runtimePolicyScope = {
      orgId: 'org',
      projectId: 'proj',
      envId: 'dev',
      signingRootVersion: 'v1',
    };
    const jwt = appSessionJwtWithRuntimePolicyScope(runtimePolicyScope);
    const keyHandle = await roleLocalEcdsaKeyHandle({
      walletId: 'alice.testnet',
      rpId: 'localhost',
      projectId: runtimePolicyScope.projectId,
      envId: runtimePolicyScope.envId,
      signingRootVersion: runtimePolicyScope.signingRootVersion,
    });

    await coordinator.loginWithEcdsaCapabilityInternal({
      walletSession: TEST_WALLET_SESSION,
      chainTarget: TEMPO_CHAIN_TARGET,
      challengeId: 'challenge-1',
      otpCode: '123456',
      emailHashHex: 'email-hash',
      routePlan: loginRoutePlanFromAppSessionJwt(jwt),
      keyHandle,
      participantIds: [1, 3],
      ecdsaBootstrapAuthorization: { kind: 'route_plan_auth' },
      ed25519ReconstructionMode: 'skip',
      ed25519SessionReconstruction: DEFER_ED25519_RECONSTRUCTION_FOR_ECDSA,
      providerIdentity: { kind: 'derive_from_route_auth' },
    });

    const sealCall = workerCalls.find(
      (call) => call.request?.type === 'sealEmailOtpWarmSessionMaterial',
    );
    expect(sealCall).toMatchObject({
      kind: 'emailOtp',
      request: {
        type: 'sealEmailOtpWarmSessionMaterial',
        payload: {
          sessionId: 'ecdsa-session',
          transport: {
            relayerUrl: 'https://relay.example',
            walletSessionJwt: expect.any(String),
            signingSessionSealKeyVersion: TEST_SIGNING_SESSION_SEAL_KEY_VERSION,
            shamirPrimeB64u: 'prime-b64u',
          },
        },
      },
    });
    expect(sealedRecordWrites).toHaveLength(2);
    expect(
      sealedRecordWrites.map((record) => record.ecdsaRestore?.chainTarget?.kind).sort(),
    ).toEqual(['evm', 'tempo']);
    for (const sealedRecordWrite of sealedRecordWrites) {
      expect(sealedRecordWrite).toMatchObject({
        sealedSecretB64u: 'sealed-email-otp-session-secret',
        curve: 'ecdsa',
        authMethod: 'email_otp',
        thresholdSessionIds: { ecdsa: 'ecdsa-session' },
        walletId: 'alice.testnet',
        relayerUrl: 'https://relay.example',
        keyVersion: 'signing-session-seal-kek-test-r1',
        shamirPrimeB64u: 'prime-b64u',
        remainingUses: 9,
      });
    }
  });

  test('fails session-retained Email OTP login when sealed refresh is not durably readable', async () => {
    const { coordinator } = createCoordinator({
      configs: {
        signing: {
          emailOtp: { authPolicy: 'session' },
          sessionPersistenceMode: 'sealed_refresh_v1',
          sessionSeal: {
            signingSessionSealKeyVersion: TEST_SIGNING_SESSION_SEAL_KEY_VERSION,
            shamirPrimeB64u: 'prime-b64u',
          },
        },
      },
      readExactSealedSession: async () => null,
    });

    const runtimePolicyScope = {
      orgId: 'org',
      projectId: 'proj',
      envId: 'dev',
      signingRootVersion: 'v1',
    };
    const jwt = appSessionJwtWithRuntimePolicyScope(runtimePolicyScope);
    const keyHandle = await roleLocalEcdsaKeyHandle({
      walletId: 'alice.testnet',
      rpId: 'localhost',
      projectId: runtimePolicyScope.projectId,
      envId: runtimePolicyScope.envId,
      signingRootVersion: runtimePolicyScope.signingRootVersion,
    });

    await expect(
      coordinator.loginWithEcdsaCapabilityInternal({
        walletSession: TEST_WALLET_SESSION,
        chainTarget: TEMPO_CHAIN_TARGET,
        challengeId: 'challenge-1',
        otpCode: '123456',
        emailHashHex: 'email-hash',
        routePlan: loginRoutePlanFromAppSessionJwt(jwt),
        keyHandle,
        participantIds: [1, 3],
        ecdsaBootstrapAuthorization: { kind: 'route_plan_auth' },
        ed25519ReconstructionMode: 'skip',
        ed25519SessionReconstruction: DEFER_ED25519_RECONSTRUCTION_FOR_ECDSA,
        providerIdentity: { kind: 'derive_from_route_auth' },
      }),
    ).rejects.toThrow('Email OTP sealed refresh tempo:42431 record was not durably persisted');
  });

  test('persists sealed Email OTP refresh records for wallet-unlock ECDSA login under per-operation policy', async () => {
    const { coordinator, workerCalls, sealedRecordWrites } = createCoordinator({
      configs: {
        signing: {
          emailOtp: { authPolicy: 'per_operation' },
          sessionPersistenceMode: 'sealed_refresh_v1',
          sessionSeal: {
            signingSessionSealKeyVersion: TEST_SIGNING_SESSION_SEAL_KEY_VERSION,
            shamirPrimeB64u: 'prime-b64u',
          },
        },
      },
    });
    const runtimePolicyScope = {
      orgId: 'org',
      projectId: 'proj',
      envId: 'dev',
      signingRootVersion: 'v1',
    };
    const jwt = appSessionJwtWithRuntimePolicyScope(runtimePolicyScope);
    const keyHandle = await roleLocalEcdsaKeyHandle({
      walletId: 'alice.testnet',
      rpId: 'localhost',
      projectId: runtimePolicyScope.projectId,
      envId: runtimePolicyScope.envId,
      signingRootVersion: runtimePolicyScope.signingRootVersion,
    });

    await coordinator.loginWithEcdsaCapabilityInternal({
      walletSession: TEST_WALLET_SESSION,
      chainTarget: TEMPO_CHAIN_TARGET,
      challengeId: 'challenge-1',
      otpCode: '123456',
      emailHashHex: 'email-hash',
      routePlan: loginRoutePlanFromAppSessionJwt(jwt),
      keyHandle,
      participantIds: [1, 3],
      ecdsaBootstrapAuthorization: { kind: 'route_plan_auth' },
      ed25519ReconstructionMode: 'skip',
      ed25519SessionReconstruction: DEFER_ED25519_RECONSTRUCTION_FOR_ECDSA,
      providerIdentity: { kind: 'derive_from_route_auth' },
    });

    expect(
      workerCalls.some((call) => call.request?.type === 'sealEmailOtpWarmSessionMaterial'),
    ).toBe(true);
    expect(sealedRecordWrites.length).toBeGreaterThan(0);
  });

  test('Email OTP per-operation ECDSA signing mints a fresh signing grant id', async () => {
    const { coordinator, workerCalls } = createCoordinator({
      configs: {
        signing: {
          emailOtp: { authPolicy: 'per_operation' },
          sessionPersistenceMode: 'sealed_refresh_v1',
          sessionSeal: {
            signingSessionSealKeyVersion: TEST_SIGNING_SESSION_SEAL_KEY_VERSION,
            shamirPrimeB64u: 'prime-b64u',
          },
        },
      },
    });
    const walletSessionJwt = 'exhausted-threshold-session-jwt';
    const authorizingSigningGrantId = 'exhausted-signing-grant';
    const runtimePolicyScope = {
      orgId: 'org',
      projectId: 'proj',
      envId: 'dev',
      signingRootVersion: 'v1',
    };
    const keyHandle = await roleLocalEcdsaKeyHandle({
      walletId: 'alice.testnet',
      rpId: 'localhost',
      projectId: runtimePolicyScope.projectId,
      envId: runtimePolicyScope.envId,
      signingRootVersion: runtimePolicyScope.signingRootVersion,
    });

    const record = {
      walletId: toWalletId('alice.testnet'),
      evmFamilySigningKeySlotId: deriveEvmFamilySigningKeySlotId({
        walletId: 'alice.testnet',
        signingRootId: 'signing-root',
        signingRootVersion: 'root-v1',
      }),
      chainTarget: TEMPO_CHAIN_TARGET,
      relayerUrl: 'https://relay.example',
      keyHandle: toEvmFamilyEcdsaKeyHandle(keyHandle),
      ecdsaThresholdKeyId: 'ecdsa-key',
      signingRootId: 'signing-root',
      signingRootVersion: 'root-v1',
      relayerKeyId: 'relayer-key',
      clientVerifyingShareB64u: 'client-verifying-share',
      ecdsaRoleLocalReadyRecord: makeEmailOtpRoleLocalReadyRecord({
        walletId: 'alice.testnet',
        rpId: 'localhost',
        chainTarget: TEMPO_CHAIN_TARGET,
        keyHandle: toEvmFamilyEcdsaKeyHandle(keyHandle),
        ecdsaThresholdKeyId: 'ecdsa-key',
        signingRootId: 'signing-root',
        signingRootVersion: 'root-v1',
        ethereumAddress: '0x'.padEnd(42, 'a') as `0x${string}`,
      }),
      clientAdditiveShareHandle: {
        kind: 'email_otp_worker_session',
        sessionId: 'exhausted-threshold-session',
      },
      participantIds: [1, 3],
      thresholdEcdsaPublicKeyB64u: VALID_ECDSA_PUBLIC_KEY_B64U,
      verifiedPublicFacts: buildVerifiedEcdsaPublicFacts({
        keyHandle: toEvmFamilyEcdsaKeyHandle(keyHandle),
        publicKeyB64u: VALID_ECDSA_PUBLIC_KEY_B64U,
        participantIds: [1, 3],
        thresholdOwnerAddress: '0x'.padEnd(42, 'a'),
      }),
      ethereumAddress: '0x'.padEnd(42, 'a'),
      thresholdSessionKind: 'jwt',
      thresholdSessionId: 'exhausted-threshold-session',
      signingGrantId: authorizingSigningGrantId,
      walletSessionJwt,
      runtimePolicyScope,
      expiresAtMs: Date.now() - 1_000,
      remainingUses: 0,
      emailOtpAuthContext: emailOtpAuthContextFixture({
        policy: 'per_operation',
        retention: 'single_use',
      }),
      updatedAtMs: Date.now(),
      source: 'email_otp',
    } satisfies ThresholdEcdsaSessionRecord;

    const result = await coordinator.loginWithEcdsaCapabilityForSigning({
      walletSession: TEST_WALLET_SESSION,
      chainTarget: TEMPO_CHAIN_TARGET,
      challengeId: 'challenge-1',
      otpCode: '123456',
      committedLane: emailOtpEcdsaCommittedLaneFromRecord(record),
    });

    const loginCall = workerCalls.find((call) => call.request?.type === 'loginWithEmailOtpWallet');
    const bootstrapCall = workerCalls.find(
      (call) => call.request?.type === 'bootstrapEmailOtpEcdsaSessionsFromWorkerHandle',
    );
    expect(loginCall?.request.payload.routePlan).toMatchObject({
      routeFamily: 'signing_session',
      authLane: {
        kind: 'signing_session',
        jwt: walletSessionJwt,
        thresholdSessionId: 'exhausted-threshold-session',
        authorizingSigningGrantId,
        curve: 'ecdsa',
        chainTarget: TEMPO_CHAIN_TARGET,
      },
      operation: 'transaction_sign',
    });
    const mintedSigningGrantId = String(bootstrapCall?.request.payload.signingGrantId || '');
    expect(mintedSigningGrantId).toBeTruthy();
    expect(mintedSigningGrantId).not.toBe(authorizingSigningGrantId);
    expect(result.bootstrap.session.signingGrantId).toBe(mintedSigningGrantId);
  });

  test('export ECDSA reauth uses operation-scoped auth without replacing transaction sealed refresh', async () => {
    const { coordinator, workerCalls, sealedRecordWrites, ecdsaCommitCalls } = createCoordinator({
      configs: {
        signing: {
          emailOtp: { authPolicy: 'session' },
          sessionPersistenceMode: 'sealed_refresh_v1',
          sessionSeal: {
            signingSessionSealKeyVersion: TEST_SIGNING_SESSION_SEAL_KEY_VERSION,
            shamirPrimeB64u: 'prime-b64u',
          },
        },
      },
    });
    const walletSessionJwt = 'transaction-threshold-session-jwt';
    const tempoChainTarget = thresholdEcdsaChainTargetFromChainFamily({
      chain: 'tempo',
      chainId: 42431,
      networkSlug: 'tempo-testnet',
    });
    const keyHandle = toEvmFamilyEcdsaKeyHandle('key-handle-transaction');
    const thresholdOwnerAddress = '0x'.padEnd(42, 'a') as `0x${string}`;

    const record = {
      walletId: toWalletId('alice.testnet'),
      evmFamilySigningKeySlotId: deriveEvmFamilySigningKeySlotId({
        walletId: 'alice.testnet',
        signingRootId: 'signing-root',
        signingRootVersion: 'root-v1',
      }),
      chainTarget: tempoChainTarget,
      relayerUrl: 'https://relay.example',
      keyHandle,
      ecdsaThresholdKeyId: 'ecdsa-key',
      signingRootId: 'signing-root',
      signingRootVersion: 'root-v1',
      relayerKeyId: 'relayer-key',
      clientVerifyingShareB64u: 'client-verifying-share',
      ecdsaRoleLocalReadyRecord: makeEmailOtpRoleLocalReadyRecord({
        walletId: 'alice.testnet',
        rpId: 'localhost',
        chainTarget: tempoChainTarget,
        keyHandle,
        ecdsaThresholdKeyId: 'ecdsa-key',
        signingRootId: 'signing-root',
        signingRootVersion: 'root-v1',
        ethereumAddress: thresholdOwnerAddress,
      }),
      clientAdditiveShareHandle: {
        kind: 'email_otp_worker_session',
        sessionId: 'transaction-ecdsa-session',
      },
      participantIds: [1, 2],
      thresholdEcdsaPublicKeyB64u: VALID_ECDSA_PUBLIC_KEY_B64U,
      verifiedPublicFacts: buildVerifiedEcdsaPublicFacts({
        keyHandle,
        publicKeyB64u: VALID_ECDSA_PUBLIC_KEY_B64U,
        participantIds: [1, 2],
        thresholdOwnerAddress,
      }),
      ethereumAddress: thresholdOwnerAddress,
      thresholdSessionKind: 'jwt',
      thresholdSessionId: 'transaction-ecdsa-session',
      signingGrantId: 'transaction-signing-grant',
      walletSessionJwt,
      expiresAtMs: Date.now() + 60_000,
      remainingUses: 7,
      emailOtpAuthContext: emailOtpAuthContextFixture(),
      updatedAtMs: Date.now(),
      source: 'email_otp',
    } satisfies ThresholdEcdsaSessionRecord;

    const artifact = await coordinator.exportEcdsaKeyWithAuthorization({
      walletSession: {
        walletId: toWalletId('alice.testnet'),
        walletSessionUserId: 'alice.testnet',
      },
      challengeId: 'export-challenge-1',
      otpCode: '123456',
      committedLane: emailOtpEcdsaCommittedLaneFromRecord(record),
    });

    expect(artifact).toMatchObject({
      publicKeyHex: '02'.padEnd(66, '1'),
      privateKeyHex: '11'.repeat(32),
      ethereumAddress: '0x'.padEnd(42, 'a'),
    });
    const exportCall = workerCalls.find(
      (call) => call.request?.type === 'exportThresholdEcdsaHssKeyWithEmailOtpAuthorization',
    );
    expect(exportCall).toMatchObject({
      request: {
        payload: {
          challengeId: 'export-challenge-1',
          otpCode: '123456',
          walletSessionJwt: walletSessionJwt,
          routePlan: {
            routeFamily: 'signing_session',
            authLane: {
              kind: 'signing_session',
              jwt: walletSessionJwt,
              thresholdSessionId: 'transaction-ecdsa-session',
              authorizingSigningGrantId: 'transaction-signing-grant',
              curve: 'ecdsa',
              chainTarget: tempoChainTarget,
            },
            operation: WALLET_EMAIL_OTP_EXPORT_OPERATION,
          },
        },
      },
    });
    expect(exportCall.request.payload).not.toHaveProperty('sessionId', 'transaction-ecdsa-session');
    expect(exportCall.request.payload).not.toHaveProperty('signingRootId');
    expect(exportCall.request.payload).not.toHaveProperty('signingRootVersion');
    expect(
      workerCalls.some((call) => call.request?.type === 'sealEmailOtpWarmSessionMaterial'),
    ).toBe(false);
    expect(ecdsaCommitCalls).toEqual([]);
    expect(sealedRecordWrites).toHaveLength(0);
  });

  test('explicit signing restore rehydrates session-retained ECDSA Email OTP material from sealed refresh record', async () => {
    const expiresAtMs = Date.now() + 60_000;
    const tempoChainTarget = thresholdEcdsaChainTargetFromChainFamily({
      chain: 'tempo',
      chainId: 42431,
      networkSlug: 'tempo-testnet',
    });
    const sealedRecord = buildEcdsaSealedRecordFixture({
      expiresAtMs,
      chainTarget: tempoChainTarget,
    });
    const { coordinator, workerCalls, ecdsaCommitCalls } = createCoordinator({
      configs: {
        signing: {
          emailOtp: { authPolicy: 'session' },
          sessionPersistenceMode: 'sealed_refresh_v1',
          sessionSeal: {
            signingSessionSealKeyVersion: TEST_SIGNING_SESSION_SEAL_KEY_VERSION,
            shamirPrimeB64u: 'prime-b64u',
          },
        },
      },
      requestWorkerOperation: async (call: any) => {
        if (call.request?.type === 'getEmailOtpWarmSessionStatus') {
          return { ok: false, code: 'not_found', message: 'missing after reload' };
        }
        if (call.request?.type === 'rehydrateEmailOtpEcdsaWarmSessionMaterial') {
          return {
            ok: true,
            remainingUses: 2,
            expiresAtMs,
            bootstrap: {
              thresholdEcdsaKeyRef: {
                type: 'threshold-ecdsa-secp256k1',
                userId: call.request.payload.restore.walletId,
                subjectId: TEST_SUBJECT_ID,
                relayerUrl: call.request.payload.transport.relayerUrl,
                keyHandle: 'key-handle-ecdsa',
                ecdsaThresholdKeyId: 'ecdsa-key',
                chainTarget: call.request.payload.restore.chainTarget,
                ...signingRootFromRuntimePolicyScope(
                  call.request.payload.restore.ed25519?.runtimePolicyScope,
                ),
                thresholdSessionId: call.request.payload.restore.sessionId,
                signingGrantId: call.request.payload.restore.signingGrantId,
                walletSessionJwt: call.request.payload.transport.walletSessionJwt,
              },
              keygen: {
                ok: true,
                evmFamilySigningKeySlotId: call.request.payload.restore.evmFamilySigningKeySlotId,
              },
              session: {
                ok: true,
                sessionId: call.request.payload.restore.sessionId,
                signingGrantId: call.request.payload.restore.signingGrantId,
                expiresAtMs,
                remainingUses: 2,
                jwt: call.request.payload.transport.walletSessionJwt,
              },
            },
          };
        }
        return { ok: true };
      },
      listExactSealedSessionsForWallet: async ({ walletId, filter }) =>
        walletId === 'alice.testnet' &&
        filter?.authMethod === 'email_otp' &&
        filter?.curve === 'ecdsa' &&
        filter?.chainTarget?.kind === 'tempo'
          ? [sealedRecord]
          : [],
      readExactSealedSession: async (thresholdSessionId, purpose) =>
        thresholdSessionId === 'ecdsa-session' &&
        purpose?.authMethod === 'email_otp' &&
        purpose?.curve === 'ecdsa' &&
        purpose?.chainTarget?.kind === 'tempo'
          ? sealedRecord
          : null,
      getThresholdEcdsaSessionRecordByThresholdSessionId: () => null,
      acquireSigningSessionRestoreLease: async (args) => ({
        ...args,
        v: 1,
        signingGrantId: 'wallet-session-1',
        ownerId: 'unit-test',
        attemptId: 'restore-attempt-1',
        startedAtMs: Date.now(),
        expiresAtMs,
      }),
      releaseSigningSessionRestoreLease: async () => {},
    });

    const result = await coordinator.restorePersistedSessionForSigning(
      ecdsaRestoreInput({ chainTarget: tempoChainTarget }),
    );

    expect(result).toMatchObject({
      attempted: 1,
      restored: 1,
      deferred: 0,
    });
    const restoreCall = workerCalls.find(
      (call) => call.request?.type === 'rehydrateEmailOtpEcdsaWarmSessionMaterial',
    );
    expect(restoreCall).toMatchObject({
      kind: 'emailOtp',
      request: {
        type: 'rehydrateEmailOtpEcdsaWarmSessionMaterial',
        payload: {
          sealedSecretB64u: 'sealed-session-secret',
          remainingUses: 2,
          expiresAtMs,
          transport: {
            relayerUrl: 'https://relay.example',
            walletSessionJwt: expect.any(String),
            signingSessionSealKeyVersion: TEST_SIGNING_SESSION_SEAL_KEY_VERSION,
            shamirPrimeB64u: 'prime-b64u',
          },
          restore: {
            sessionId: 'ecdsa-session',
            walletId: 'alice.testnet',
            evmFamilySigningKeySlotId: sealedRecord.ecdsaRestore.evmFamilySigningKeySlotId,
            chainTarget: tempoChainTarget,
            signingGrantId: 'wallet-session-1',
            keyHandle: 'key-handle-ecdsa',
            relayerKeyId: 'relayer-key',
            participantIds: [1, 3],
            sessionKind: 'jwt',
          },
        },
      },
    });
    expect(ecdsaCommitCalls[0]).toMatchObject({
      walletId: 'alice.testnet',
      source: 'email_otp',
      emailOtpAuthContext: emailOtpAuthContextFixture({
        providerUserId: sealedRecord.ecdsaRestore.providerSubjectId,
      }),
    });
  });

  test('does not resolve ECDSA sealed refresh from an Ed25519 status read', async () => {
    const expiresAtMs = Date.now() + 60_000;
    const sealedRecord = buildEcdsaSealedRecordFixture({
      expiresAtMs,
      thresholdSessionIds: {
        ed25519: 'ed25519-session',
        ecdsa: 'ecdsa-session',
      },
    });
    const sealedReads: Array<{ thresholdSessionId: string; curve?: string }> = [];
    const { coordinator, workerCalls, ecdsaCommitCalls } = createCoordinator({
      configs: {
        signing: {
          emailOtp: { authPolicy: 'session' },
          sessionPersistenceMode: 'sealed_refresh_v1',
          sessionSeal: {
            signingSessionSealKeyVersion: TEST_SIGNING_SESSION_SEAL_KEY_VERSION,
            shamirPrimeB64u: 'prime-b64u',
          },
        },
      },
      requestWorkerOperation: async (call: any) => {
        if (call.request?.type === 'getEmailOtpWarmSessionStatus') {
          return { ok: false, code: 'not_found', message: 'missing after reload' };
        }
        if (call.request?.type === 'rehydrateEmailOtpEcdsaWarmSessionMaterial') {
          return {
            ok: true,
            remainingUses: 2,
            expiresAtMs,
            bootstrap: {
              thresholdEcdsaKeyRef: {
                type: 'threshold-ecdsa-secp256k1',
                userId: call.request.payload.restore.walletId,
                subjectId: TEST_SUBJECT_ID,
                relayerUrl: call.request.payload.transport.relayerUrl,
                keyHandle: 'key-handle-ecdsa',
                ecdsaThresholdKeyId: 'ecdsa-key',
                chainTarget: call.request.payload.restore.chainTarget,
                ...signingRootFromRuntimePolicyScope(
                  call.request.payload.restore.ed25519?.runtimePolicyScope,
                ),
                thresholdSessionId: call.request.payload.restore.sessionId,
                signingGrantId: call.request.payload.restore.signingGrantId,
                walletSessionJwt: call.request.payload.transport.walletSessionJwt,
              },
              keygen: {
                ok: true,
                evmFamilySigningKeySlotId: call.request.payload.restore.evmFamilySigningKeySlotId,
              },
              session: {
                ok: true,
                sessionId: call.request.payload.restore.sessionId,
                signingGrantId: call.request.payload.restore.signingGrantId,
                expiresAtMs,
                remainingUses: 2,
                jwt: call.request.payload.transport.walletSessionJwt,
              },
            },
          };
        }
        return { ok: true };
      },
      readExactSealedSession: async (thresholdSessionId, purpose) => {
        sealedReads.push({ thresholdSessionId, curve: purpose?.curve });
        if (purpose?.curve === 'ed25519' && thresholdSessionId === 'ed25519-session') {
          return sealedRecord;
        }
        if (purpose?.curve === 'ecdsa' && thresholdSessionId === 'ecdsa-session') {
          return sealedRecord;
        }
        return null;
      },
      getThresholdEcdsaSessionRecordByThresholdSessionId: (thresholdSessionId) =>
        thresholdSessionId === 'ecdsa-session'
          ? {
              nearAccountId: 'alice.testnet' as any,
              chain: 'tempo',
              relayerUrl: 'https://relay.example',
              keyHandle: 'key-handle-ecdsa',
              ecdsaThresholdKeyId: 'ecdsa-key' as any,
              signingRootId: 'signing-root',
              signingRootVersion: 'root-v1',
              relayerKeyId: 'relayer-key',
              clientVerifyingShareB64u: 'client-verifying-share',
              clientAdditiveShareHandle: {
                kind: 'email_otp_worker_session',
                sessionId: 'ed25519-session',
              },
              participantIds: [1, 3],
              thresholdSessionKind: 'jwt',
              thresholdSessionId: 'ecdsa-session',
              signingGrantId: 'wallet-session-1',
              walletSessionJwt: 'threshold-session-jwt',
              signingSessionSealKeyVersion: 'signing-session-seal-kek-test-r1',
              signingSessionSealShamirPrimeB64u: 'prime-b64u',
              expiresAtMs,
              remainingUses: 2,
              emailOtpAuthContext: emailOtpAuthContextFixture(),
              updatedAtMs: Date.now(),
              source: 'email_otp',
            }
          : null,
      acquireSigningSessionRestoreLease: async (args) => ({
        ...args,
        v: 1,
        signingGrantId: 'wallet-session-1',
        ownerId: 'unit-test',
        attemptId: 'restore-attempt-1',
        startedAtMs: Date.now(),
        expiresAtMs,
      }),
      releaseSigningSessionRestoreLease: async () => {},
    });

    try {
      persistWarmSessionEd25519Capability({
        kind: 'jwt_email_otp',
        walletId: 'alice.testnet',
        nearAccountId: 'alice.testnet',
        nearEd25519SigningKeyId: 'alice.testnet',
        rpId: 'localhost',
        relayerUrl: 'https://relay.example',
        relayerKeyId: 'relayer-key',
        participantIds: [1, 2],
        sessionId: 'ed25519-session',
        signingGrantId: 'wallet-session-1',
        expiresAtMs,
        remainingUses: 2,
        signerSlot: 1,
        sessionKind: 'jwt',
        jwt: appSessionJwt(),
        routerAbNormalSigning: ROUTER_AB_NORMAL_SIGNING,
        emailOtpAuthContext: emailOtpAuthContextFixture(),
        source: 'email_otp',
      });

      const status = await coordinator.readWarmSessionStatusOnly('ed25519-session');

      expect(status).toMatchObject({ ok: false, code: 'not_found' });
      expect(
        sealedReads.some(
          (read) => read.thresholdSessionId === 'ed25519-session' && read.curve === 'ecdsa',
        ),
      ).toBe(false);
      expect(
        workerCalls.some(
          (call) => call.request?.type === 'rehydrateEmailOtpEcdsaWarmSessionMaterial',
        ),
      ).toBe(false);
      expect(ecdsaCommitCalls).toHaveLength(0);
    } finally {
      clearAllStoredThresholdEd25519SessionRecords();
    }
  });

  test('status reads do not probe sealed ECDSA records while session records are indexing', async () => {
    const expiresAtMs = Date.now() + 60_000;
    const sealedRecord = buildEcdsaSealedRecordFixture({ expiresAtMs });
    const warnCalls: any[][] = [];
    const debugCalls: any[][] = [];
    const originalWarn = console.warn;
    const originalDebug = console.debug;
    console.warn = (...args: any[]) => {
      warnCalls.push(args);
    };
    console.debug = (...args: any[]) => {
      debugCalls.push(args);
    };
    const { coordinator } = createCoordinator({
      configs: {
        signing: {
          emailOtp: { authPolicy: 'session' },
          sessionPersistenceMode: 'sealed_refresh_v1',
          sessionSeal: {
            signingSessionSealKeyVersion: TEST_SIGNING_SESSION_SEAL_KEY_VERSION,
            shamirPrimeB64u: 'prime-b64u',
          },
        },
      },
      requestWorkerOperation: async (call: any) => {
        if (call.request?.type === 'getEmailOtpWarmSessionStatus') {
          return { ok: false, code: 'not_found', message: 'missing after reload' };
        }
        return { ok: true };
      },
      readExactSealedSession: async (thresholdSessionId, purpose) => {
        if (thresholdSessionId === 'ecdsa-session' && purpose?.curve === 'ecdsa') {
          return sealedRecord;
        }
        return null;
      },
      getThresholdEcdsaSessionRecordByThresholdSessionId: () => null,
    });

    try {
      await coordinator.readWarmSessionStatusOnly('ecdsa-session');
      await coordinator.readWarmSessionStatusOnly('ecdsa-session');
    } finally {
      console.warn = originalWarn;
      console.debug = originalDebug;
    }

    expect(
      warnCalls.some((args) =>
        String(args[0] || '').includes(
          'sealed refresh restore missing session-retained ECDSA record',
        ),
      ),
    ).toBe(false);
    expect(
      debugCalls.filter((args) =>
        String(args[0] || '').includes('sealed refresh restore waiting for ECDSA record'),
      ),
    ).toHaveLength(0);
  });

  test('does not probe ECDSA sealed restore for an Ed25519 status miss', async () => {
    const expiresAtMs = Date.now() + 60_000;
    const sealedReads: Array<{ thresholdSessionId: string; curve?: string }> = [];
    const { coordinator, workerCalls } = createCoordinator({
      configs: {
        signing: {
          emailOtp: { authPolicy: 'session' },
          sessionPersistenceMode: 'sealed_refresh_v1',
          sessionSeal: {
            signingSessionSealKeyVersion: TEST_SIGNING_SESSION_SEAL_KEY_VERSION,
            shamirPrimeB64u: 'prime-b64u',
          },
        },
      },
      requestWorkerOperation: async (call: any) => {
        if (call.request?.type === 'getEmailOtpWarmSessionStatus') {
          return { ok: false, code: 'not_found', message: 'worker reloaded' };
        }
        return { ok: true };
      },
      readExactSealedSession: async (thresholdSessionId, purpose) => {
        sealedReads.push({ thresholdSessionId, curve: purpose?.curve });
        return null;
      },
    });

    try {
      persistWarmSessionEd25519Capability({
        kind: 'jwt_email_otp',
        walletId: 'alice.testnet',
        nearAccountId: 'alice.testnet',
        nearEd25519SigningKeyId: 'alice.testnet',
        rpId: 'localhost',
        relayerUrl: 'https://relay.example',
        relayerKeyId: 'relayer-key',
        participantIds: [1, 2],
        sessionId: 'ed25519-session',
        signingGrantId: 'wallet-session-1',
        expiresAtMs,
        remainingUses: 2,
        signerSlot: 1,
        sessionKind: 'jwt',
        jwt: appSessionJwt(),
        routerAbNormalSigning: ROUTER_AB_NORMAL_SIGNING,
        emailOtpAuthContext: emailOtpAuthContextFixture(),
        source: 'email_otp',
      });

      const status = await coordinator.readWarmSessionStatusOnly('ed25519-session');

      expect(status).toMatchObject({ ok: false, code: 'not_found' });
      expect(sealedReads).toEqual([]);
      expect(
        workerCalls.some(
          (call) => call.request?.type === 'rehydrateEmailOtpEcdsaWarmSessionMaterial',
        ),
      ).toBe(false);
    } finally {
      clearAllStoredThresholdEd25519SessionRecords();
    }
  });

  test('explicit signing restore restores sealed ECDSA Email OTP session from durable metadata', async () => {
    const expiresAtMs = Date.now() + 60_000;
    const tempoChainTarget = thresholdEcdsaChainTargetFromChainFamily({
      chain: 'tempo',
      chainId: 42431,
      networkSlug: 'tempo-testnet',
    });
    const sealedRecord = buildEcdsaSealedRecordFixture({
      expiresAtMs,
      chainTarget: tempoChainTarget,
    });
    const { coordinator, workerCalls, ecdsaCommitCalls } = createCoordinator({
      configs: {
        signing: {
          emailOtp: { authPolicy: 'session' },
          sessionPersistenceMode: 'sealed_refresh_v1',
          sessionSeal: {
            signingSessionSealKeyVersion: TEST_SIGNING_SESSION_SEAL_KEY_VERSION,
            shamirPrimeB64u: 'prime-b64u',
          },
        },
      },
      requestWorkerOperation: async (call: any) => {
        if (call.request?.type === 'getEmailOtpWarmSessionStatus') {
          return { ok: false, code: 'not_found', message: 'missing after reload' };
        }
        if (call.request?.type === 'rehydrateEmailOtpEcdsaWarmSessionMaterial') {
          return {
            ok: true,
            remainingUses: 2,
            expiresAtMs,
            bootstrap: {
              thresholdEcdsaKeyRef: {
                type: 'threshold-ecdsa-secp256k1',
                userId: call.request.payload.restore.walletId,
                subjectId: TEST_SUBJECT_ID,
                relayerUrl: call.request.payload.transport.relayerUrl,
                keyHandle: 'key-handle-ecdsa',
                ecdsaThresholdKeyId: 'ecdsa-key',
                chainTarget: call.request.payload.restore.chainTarget,
                ...signingRootFromRuntimePolicyScope(
                  call.request.payload.restore.ed25519?.runtimePolicyScope,
                ),
                thresholdSessionId: call.request.payload.restore.sessionId,
                signingGrantId: call.request.payload.restore.signingGrantId,
                walletSessionJwt: call.request.payload.transport.walletSessionJwt,
              },
              keygen: {
                ok: true,
                evmFamilySigningKeySlotId: call.request.payload.restore.evmFamilySigningKeySlotId,
              },
              session: {
                ok: true,
                sessionId: call.request.payload.restore.sessionId,
                signingGrantId: call.request.payload.restore.signingGrantId,
                expiresAtMs,
                remainingUses: 2,
                jwt: call.request.payload.transport.walletSessionJwt,
              },
            },
          };
        }
        return { ok: true };
      },
      readExactSealedSession: async (thresholdSessionId, purpose) => {
        if (thresholdSessionId === 'ecdsa-session' && purpose?.curve === 'ecdsa') {
          return sealedRecord;
        }
        return null;
      },
      listExactSealedSessionsForWallet: async ({ walletId, filter }) =>
        walletId === 'alice.testnet' &&
        filter?.authMethod === 'email_otp' &&
        filter?.curve === 'ecdsa' &&
        filter?.chainTarget?.kind === 'tempo'
          ? [sealedRecord]
          : [],
      getThresholdEcdsaSessionRecordByThresholdSessionId: () => null,
      acquireSigningSessionRestoreLease: async (args) => ({
        ...args,
        v: 1,
        signingGrantId: 'wallet-session-1',
        ownerId: 'unit-test',
        attemptId: 'restore-attempt-1',
        startedAtMs: Date.now(),
        expiresAtMs,
      }),
      releaseSigningSessionRestoreLease: async () => {},
    });

    const restoreResult = await coordinator.restorePersistedSessionForSigning(
      ecdsaRestoreInput({ chainTarget: tempoChainTarget }),
    );
    const restoreCall = workerCalls.find(
      (call) => call.request?.type === 'rehydrateEmailOtpEcdsaWarmSessionMaterial',
    );

    expect(restoreResult).toMatchObject({ attempted: 1, restored: 1, deferred: 0 });
    expect(restoreCall).toMatchObject({
      request: {
        payload: {
          transport: {
            walletSessionJwt: expect.any(String),
          },
          restore: {
            sessionId: 'ecdsa-session',
            chainTarget: tempoChainTarget,
            signingGrantId: 'wallet-session-1',
            relayerKeyId: 'relayer-key',
            participantIds: [1, 3],
            sessionKind: 'jwt',
          },
        },
      },
    });
    expect(ecdsaCommitCalls).toHaveLength(1);
  });

  test('Ed25519 signing restore without durable Ed25519 metadata defers without worker restore', async () => {
    const expiresAtMs = Date.now() + 60_000;
    const { coordinator, workerCalls } = createCoordinator({
      configs: {
        signing: {
          emailOtp: { authPolicy: 'session' },
          sessionPersistenceMode: 'sealed_refresh_v1',
          sessionSeal: {
            signingSessionSealKeyVersion: TEST_SIGNING_SESSION_SEAL_KEY_VERSION,
            shamirPrimeB64u: 'prime-b64u',
          },
        },
      },
      requestWorkerOperation: async (call) => {
        if (call.request?.type === 'rehydrateEmailOtpEcdsaWarmSessionMaterial') {
          throw new Error('worker restore should not run without Ed25519 metadata');
        }
        return { ok: true };
      },
      listExactSealedSessionsForWallet: async ({ walletId, filter }) =>
        walletId === 'alice.testnet' &&
        filter?.authMethod === 'email_otp' &&
        filter?.curve === 'ed25519'
          ? []
          : [],
      getThresholdEcdsaSessionRecordByThresholdSessionId: () => null,
      acquireSigningSessionRestoreLease: async (args) => ({
        ...args,
        v: 1,
        signingGrantId: 'wallet-session-1',
        ownerId: 'unit-test',
        attemptId: 'restore-attempt-1',
        startedAtMs: Date.now(),
        expiresAtMs,
      }),
      releaseSigningSessionRestoreLease: async () => {},
    });

    const first = await coordinator.restorePersistedSessionForSigning(ed25519RestoreInput());
    const second = await coordinator.restorePersistedSessionForSigning(ed25519RestoreInput());

    expect(first).toMatchObject({ attempted: 0, restored: 0, deferred: 0 });
    expect(second).toMatchObject({ attempted: 0, restored: 0, deferred: 0 });
    expect(
      workerCalls.some(
        (call) => call.request?.type === 'rehydrateEmailOtpEcdsaWarmSessionMaterial',
      ),
    ).toBe(false);
  });

  test('wallet-scoped discovery enumerates durable sealed ECDSA records after reload', async () => {
    const expiresAtMs = Date.now() + 60_000;
    const tempoChainTarget = thresholdEcdsaChainTargetFromChainFamily({
      chain: 'tempo',
      chainId: 42431,
      networkSlug: 'tempo-testnet',
    });
    const evmChainTarget = thresholdEcdsaChainTargetFromChainFamily({
      chain: 'evm',
      chainId: 5042002,
      networkSlug: 'arc-testnet',
    });
    const sealedRecord = buildEcdsaSealedRecordFixture({
      expiresAtMs,
      chainTarget: tempoChainTarget,
    });
    const listFilters: unknown[] = [];
    const { coordinator, workerCalls, ecdsaCommitCalls } = createCoordinator({
      configs: {
        signing: {
          emailOtp: { authPolicy: 'session' },
          sessionPersistenceMode: 'sealed_refresh_v1',
          sessionSeal: {
            signingSessionSealKeyVersion: TEST_SIGNING_SESSION_SEAL_KEY_VERSION,
            shamirPrimeB64u: 'prime-b64u',
          },
        },
      },
      listExactSealedSessionsForWallet: async (args) => {
        listFilters.push(args.filter);
        expect(args).toMatchObject({
          walletId: 'alice.testnet',
          filter: { authMethod: 'email_otp' },
        });
        return args.filter?.curve === 'ecdsa' &&
          thresholdEcdsaChainTargetsEqual(args.filter.chainTarget, tempoChainTarget)
          ? [sealedRecord]
          : [];
      },
    });

    const first = await coordinator.discoverPersistedSessionsForWallet({
      kind: 'discover_wallet_all_signing_sessions',
      walletId: 'alice.testnet',
      authMethod: 'email_otp',
      ecdsaChainTargets: [tempoChainTarget, evmChainTarget],
    });
    const second = await coordinator.discoverPersistedSessionsForWallet({
      kind: 'discover_wallet_all_signing_sessions',
      walletId: 'alice.testnet',
      authMethod: 'email_otp',
      ecdsaChainTargets: [tempoChainTarget, evmChainTarget],
    });

    expect(first).toMatchObject({ listed: 1, discovered: 1, truncated: 0 });
    expect(second).toMatchObject({ listed: 1, discovered: 1, truncated: 0 });
    expect(listFilters).toHaveLength(6);
    expect(ecdsaCommitCalls).toHaveLength(0);
    expect(
      workerCalls.filter(
        (call) => call.request?.type === 'rehydrateEmailOtpEcdsaWarmSessionMaterial',
      ),
    ).toHaveLength(0);
  });

  test('does not restore sealed Email OTP session when worker status throws during status read', async () => {
    const expiresAtMs = Date.now() + 60_000;
    const sealedRecord = buildEcdsaSealedRecordFixture({ expiresAtMs });
    const ecdsaRecord = {
      nearAccountId: 'alice.testnet',
      chain: 'tempo',
      relayerUrl: 'https://relay.example',
      keyHandle: 'key-handle-ecdsa',
      ecdsaThresholdKeyId: 'ecdsa-key',
      signingRootId: 'signing-root',
      signingRootVersion: 'root-v1',
      relayerKeyId: 'relayer-key',
      participantIds: [1, 3],
      thresholdSessionKind: 'jwt',
      thresholdSessionId: 'ecdsa-session',
      signingGrantId: 'wallet-session-1',
      walletSessionJwt: 'threshold-session-jwt',
      expiresAtMs,
      remainingUses: 2,
      emailOtpAuthContext: emailOtpAuthContextFixture(),
      updatedAtMs: Date.now(),
      source: 'email_otp',
    };
    const { coordinator, workerCalls } = createCoordinator({
      configs: {
        signing: {
          emailOtp: { authPolicy: 'session' },
          sessionPersistenceMode: 'sealed_refresh_v1',
          sessionSeal: {
            signingSessionSealKeyVersion: TEST_SIGNING_SESSION_SEAL_KEY_VERSION,
            shamirPrimeB64u: 'prime-b64u',
          },
        },
      },
      requestWorkerOperation: async (call) => {
        if (call.request?.type === 'getEmailOtpWarmSessionStatus') {
          throw new Error('worker still booting');
        }
        if (call.request?.type === 'rehydrateEmailOtpEcdsaWarmSessionMaterial') {
          return {
            ok: true,
            remainingUses: 2,
            expiresAtMs,
            bootstrap: {
              thresholdEcdsaKeyRef: {
                type: 'threshold-ecdsa-secp256k1',
                userId: 'alice.testnet',
                relayerUrl: 'https://relay.example',
                keyHandle: 'key-handle-ecdsa',
                ecdsaThresholdKeyId: 'ecdsa-key',
                signingRootId: 'signing-root',
                signingRootVersion: 'root-v1',
                thresholdSessionId: 'ecdsa-session',
                signingGrantId: 'wallet-session-1',
                walletSessionJwt: 'threshold-session-jwt',
              },
              keygen: {
                ok: true,
                evmFamilySigningKeySlotId: deriveEvmFamilySigningKeySlotId({
                  walletId: toWalletId('alice.testnet'),
                  signingRootId: 'signing-root',
                  signingRootVersion: 'root-v1',
                }),
              },
              session: {
                ok: true,
                sessionId: 'ecdsa-session',
                signingGrantId: 'wallet-session-1',
                expiresAtMs,
                remainingUses: 2,
                jwt: 'threshold-session-jwt',
              },
            },
          };
        }
        return { ok: true };
      },
      readExactSealedSession: async () => sealedRecord,
      getThresholdEcdsaSessionRecordByThresholdSessionId: () => ecdsaRecord,
      acquireSigningSessionRestoreLease: async () => ({
        v: 1,
        thresholdSessionId: 'ecdsa-session',
        signingGrantId: 'wallet-session-1',
        ownerId: 'unit-test',
        attemptId: 'unit-test-attempt',
        startedAtMs: Date.now(),
        expiresAtMs: Date.now() + 15_000,
      }),
    });

    await expect(coordinator.readWarmSessionStatusOnly('ecdsa-session')).resolves.toMatchObject({
      ok: false,
      code: 'worker_error',
    });
    expect(workerCalls.map((call) => call.request?.type)).toEqual(['getEmailOtpWarmSessionStatus']);
  });

  test('fails closed before worker restore when sealed signing-root metadata mismatches session state', async () => {
    const expiresAtMs = Date.now() + 60_000;
    const tempoChainTarget = thresholdEcdsaChainTargetFromChainFamily({
      chain: 'tempo',
      chainId: 42431,
      networkSlug: 'tempo-testnet',
    });
    const sealedRecord = buildEcdsaSealedRecordFixture({
      expiresAtMs,
      chainTarget: tempoChainTarget,
      signingRootId: 'other-signing-root',
      thresholdSessionIds: {
        ecdsa: 'ecdsa-session',
        ed25519: 'ed25519-session',
      },
      ed25519Restore: {
        nearAccountId: 'alice.testnet',
        nearEd25519SigningKeyId: 'alice.testnet',
        rpId: 'localhost',
        relayerKeyId: 'ed25519-relayer-key',
        participantIds: [1, 3],
        walletSessionJwt: 'threshold-session-jwt',
        sessionKind: 'jwt',
      },
    });
    const ecdsaRecord = {
      nearAccountId: 'alice.testnet' as any,
      chain: 'tempo',
      subjectId: toWalletId('alice.testnet'),
      chainTarget: tempoChainTarget,
      relayerUrl: 'https://relay.example',
      keyHandle: 'key-handle-ecdsa',
      ecdsaThresholdKeyId: 'ecdsa-key' as any,
      signingRootId: 'signing-root',
      relayerKeyId: 'relayer-key',
      clientVerifyingShareB64u: 'client-verifying-share',
      clientAdditiveShareHandle: {
        kind: 'email_otp_worker_session',
        sessionId: 'ecdsa-session',
      },
      participantIds: [1, 3],
      thresholdSessionKind: 'jwt',
      thresholdSessionId: 'ecdsa-session',
      signingGrantId: 'wallet-session-1',
      walletSessionJwt: 'threshold-session-jwt',
      signingSessionSealKeyVersion: 'signing-session-seal-kek-test-r1',
      signingSessionSealShamirPrimeB64u: 'prime-b64u',
      expiresAtMs,
      remainingUses: 2,
      emailOtpAuthContext: emailOtpAuthContextFixture(),
      updatedAtMs: Date.now(),
      source: 'email_otp',
    };
    const { coordinator, workerCalls } = createCoordinator({
      configs: {
        signing: {
          emailOtp: { authPolicy: 'session' },
          sessionPersistenceMode: 'sealed_refresh_v1',
          sessionSeal: {
            signingSessionSealKeyVersion: TEST_SIGNING_SESSION_SEAL_KEY_VERSION,
            shamirPrimeB64u: 'prime-b64u',
          },
        },
      },
      requestWorkerOperation: async (call) => {
        if (call.request?.type === 'getEmailOtpWarmSessionStatus') {
          return { ok: false, code: 'not_found', message: 'missing after reload' };
        }
        if (call.request?.type === 'rehydrateEmailOtpEcdsaWarmSessionMaterial') {
          throw new Error('worker restore should not run');
        }
        return { ok: true };
      },
      listExactSealedSessionsForWallet: async ({ walletId, filter }) =>
        walletId === 'alice.testnet' &&
        filter?.authMethod === 'email_otp' &&
        filter?.curve === 'ecdsa' &&
        filter?.chainTarget?.kind === 'tempo'
          ? [sealedRecord]
          : [],
      getThresholdEcdsaSessionRecordByThresholdSessionId: () => ecdsaRecord,
      acquireSigningSessionRestoreLease: async (args) => ({
        ...args,
        v: 1,
        signingGrantId: 'wallet-session-1',
        ownerId: 'unit-test',
        attemptId: 'restore-attempt-1',
        startedAtMs: Date.now(),
        expiresAtMs,
      }),
      releaseSigningSessionRestoreLease: async () => {},
    });

    const restoreResult = await coordinator.restorePersistedSessionForSigning(
      ecdsaRestoreInput({ chainTarget: tempoChainTarget }),
    );

    expect(restoreResult).toMatchObject({ attempted: 0, restored: 0, deferred: 0 });
    expect(
      workerCalls.some(
        (call) => call.request?.type === 'rehydrateEmailOtpEcdsaWarmSessionMaterial',
      ),
    ).toBe(false);
  });

  test('does not attach Ed25519 sealed companion metadata without handle-backed material', async () => {
    const expiresAtMs = Date.now() + 60_000;
    const ecdsaRecord = {
      nearAccountId: 'alice.testnet',
      chain: 'tempo',
      relayerUrl: 'https://relay.example',
      keyHandle: 'key-handle-ecdsa',
      ecdsaThresholdKeyId: 'ecdsa-key',
      signingRootId: 'signing-root',
      signingRootVersion: 'root-v1',
      relayerKeyId: 'relayer-key',
      clientVerifyingShareB64u: 'verifying-share',
      participantIds: [1, 3],
      thresholdSessionKind: 'jwt',
      thresholdSessionId: 'ecdsa-session',
      signingGrantId: 'wallet-session-1',
      walletSessionJwt: thresholdEcdsaSessionJwt({
        walletId: 'alice.testnet',
        keyHandle: 'key-handle-ecdsa',
        thresholdSessionId: 'ecdsa-session',
        signingGrantId: 'wallet-session-1',
        chainTarget: thresholdEcdsaChainTargetFromChainFamily({
          chain: 'tempo',
          chainId: 42431,
          networkSlug: 'tempo-testnet',
        }),
      }),
      expiresAtMs,
      remainingUses: 2,
      emailOtpAuthContext: emailOtpAuthContextFixture(),
      source: 'email_otp',
      subjectId: toWalletId('alice.testnet'),
      chainTarget: thresholdEcdsaChainTargetFromChainFamily({
        chain: 'tempo',
        chainId: 42431,
        networkSlug: 'tempo-testnet',
      }),
      updatedAtMs: Date.now(),
    };
    const { coordinator, sealedRecordWrites } = createCoordinator({
      configs: {
        signing: {
          emailOtp: { authPolicy: 'session' },
          sessionPersistenceMode: 'sealed_refresh_v1',
          sessionSeal: {
            signingSessionSealKeyVersion: TEST_SIGNING_SESSION_SEAL_KEY_VERSION,
            shamirPrimeB64u: 'prime-b64u',
          },
        },
      },
      readExactSealedSession: async (thresholdSessionId) => ({
        v: 1,
        alg: 'shamir3pass-v1',
        storageScope: 'iframe_origin_indexeddb',
        runtimeSessionId: 'runtime-1',
        authMethod: 'email_otp',
        secretKind: 'signing_session_secret32',
        signingGrantId: 'wallet-session-1',
        thresholdSessionIds: { ecdsa: thresholdSessionId },
        sealedSecretB64u: 'sealed-session-secret',
        curve: 'ecdsa',
        walletId: 'alice.testnet',
        relayerUrl: 'https://relay.example',
        keyVersion: 'signing-session-seal-kek-test-r1',
        shamirPrimeB64u: 'prime-b64u',
        ecdsaRestore: {
          chainTarget: ecdsaRecord.chainTarget,
          source: 'email_otp',
          rpId: 'example.com',
          walletSessionJwt: thresholdEcdsaSessionJwt({
            walletId: 'alice.testnet',
            keyHandle: 'key-handle-ecdsa',
            thresholdSessionId,
            signingGrantId: 'wallet-session-1',
            chainTarget: ecdsaRecord.chainTarget,
          }),
          sessionKind: 'jwt',
          keyHandle: 'key-handle-ecdsa',
          ecdsaThresholdKeyId: 'ecdsa-key',
          ethereumAddress: `0x${'33'.repeat(20)}`,
          relayerKeyId: 'relayer-key',
          clientVerifyingShareB64u: VALID_ECDSA_CLIENT_PUBLIC_KEY_B64U,
          thresholdEcdsaPublicKeyB64u: VALID_ECDSA_PUBLIC_KEY_B64U,
          participantIds: [1, 3],
        },
        issuedAtMs: Date.now(),
        expiresAtMs,
        remainingUses: 2,
        updatedAtMs: Date.now(),
      }),
      getThresholdEcdsaSessionRecordByThresholdSessionId: () => ecdsaRecord,
    });

    try {
      persistWarmSessionEd25519Capability({
        kind: 'jwt_email_otp',
        walletId: 'alice.testnet',
        nearAccountId: 'alice.testnet',
        nearEd25519SigningKeyId: 'alice.testnet',
        rpId: 'localhost',
        relayerUrl: 'https://relay.example',
        relayerKeyId: 'relayer-key',
        participantIds: [1, 2],
        sessionId: 'ed25519-session',
        signingGrantId: 'wallet-session-1',
        expiresAtMs,
        remainingUses: 2,
        signerSlot: 1,
        sessionKind: 'jwt',
        jwt: appSessionJwt(),
        routerAbNormalSigning: ROUTER_AB_NORMAL_SIGNING,
        emailOtpAuthContext: emailOtpAuthContextFixture(),
        source: 'email_otp',
      });

      const result = await (coordinator as any).attachEd25519SessionToEmailOtpSigningSessionSeal({
        ecdsaThresholdSessionId: 'ecdsa-session',
        ed25519ThresholdSessionId: 'ed25519-session',
      });
      expect(result).toEqual({
        kind: 'not_required',
        reason: 'handle_backed_companion_not_supported',
      });
    } finally {
      clearAllStoredThresholdEd25519SessionRecords();
    }

    expect(sealedRecordWrites).toHaveLength(0);
  });

  test('login reconstructs Ed25519 when route auth supplies the deferred runtime scope', async () => {
    const reconstructionCalls: any[] = [];
    const { coordinator, ecdsaCommitCalls } = createCoordinator({
      reconstructEd25519Session: async (args) => {
        reconstructionCalls.push(args);
        return {
          relayerKeyId: args.ed25519Key.relayerKeyId,
          keyVersion: args.ed25519Key.keyVersion,
          sessionId: 'ed25519-reconstructed-session',
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 3,
          participantIds: args.ed25519Key.participantIds,
          jwt: 'ed25519-reconstructed-jwt',
          clientVerifyingShareB64u: 'ed25519-reconstructed-client-verifying-share',
        };
      },
    });
    const runtimePolicyScope = {
      orgId: 'org',
      projectId: 'proj',
      envId: 'dev',
      signingRootVersion: 'v1',
    };
    const routeJwt = appSessionJwtWithRuntimePolicyScope(runtimePolicyScope);

    const result = await coordinator.loginWithEcdsaCapabilityInternal({
      walletSession: TEST_WALLET_SESSION,
      chainTarget: TEMPO_CHAIN_TARGET,
      challengeId: 'challenge-1',
      otpCode: '123456',
      emailHashHex: 'email-hash',
      routePlan: loginRoutePlanFromAppSessionJwt(routeJwt),
      participantIds: [1, 3],
      ecdsaBootstrapAuthorization: { kind: 'route_plan_auth' },
      ed25519ReconstructionMode: 'await',
      ed25519SessionReconstruction: {
        kind: 'defer',
        reason: 'missing_runtime_policy_scope',
        ed25519Key: {
          signer: TEST_ED25519_SIGNER,
          relayerKeyId: 'ed25519-relayer-key',
          keyVersion: 'threshold-ed25519-hss-v1',
          participantIds: [1, 2],
        },
      },
      providerIdentity: { kind: 'derive_from_route_auth' },
    });

    expect(result.ed25519Reconstruction.kind).toBe('completed');
    expect(reconstructionCalls).toHaveLength(1);
    expect(reconstructionCalls[0]).toMatchObject({
      kind: 'session_ed25519_reconstruction',
      relayUrl: 'https://relay.example',
      rpId: 'localhost',
      recoveryCodeSecret32B64u: 'prf-first-ecdsa-login',
      routeAuth: {
        kind: 'wallet_session',
        jwt: expect.any(String),
      },
      runtimePolicyScope,
      ed25519Key: {
        signer: TEST_ED25519_SIGNER,
        relayerKeyId: 'ed25519-relayer-key',
        keyVersion: 'threshold-ed25519-hss-v1',
        participantIds: [1, 2],
      },
      signingGrantId: expect.any(String),
      ecdsaThresholdSessionId: 'ecdsa-session',
      emailOtpAuthContext: emailOtpAuthContextFixture(),
    });
    expect(ecdsaCommitCalls[0].emailOtpAuthContext).toMatchObject({
      policy: 'session',
      authMethod: 'email_otp',
      use: {
        kind: 'session',
        reason: 'login',
      },
    });
    expect(String(reconstructionCalls[0].signingGrantId || '')).toBeTruthy();
  });

  test('login reconstructs Ed25519 when runtime scope is supplied out-of-band', async () => {
    const reconstructionCalls: any[] = [];
    const { coordinator } = createCoordinator({
      configs: {
        signing: {
          emailOtp: { authPolicy: 'session' },
        },
      },
      reconstructEd25519Session: async (args) => {
        reconstructionCalls.push(args);
        return {
          relayerKeyId: args.ed25519Key.relayerKeyId,
          keyVersion: args.ed25519Key.keyVersion,
          sessionId: 'ed25519-reconstructed-session',
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 3,
          participantIds: args.ed25519Key.participantIds,
          jwt: 'ed25519-reconstructed-jwt',
          clientVerifyingShareB64u: 'ed25519-reconstructed-client-verifying-share',
        };
      },
    });
    const runtimePolicyScope = {
      orgId: 'org',
      projectId: 'proj',
      envId: 'dev',
      signingRootVersion: 'v1',
    };
    const result = await coordinator.loginWithEcdsaCapabilityInternal({
      walletSession: TEST_WALLET_SESSION,
      chainTarget: TEMPO_CHAIN_TARGET,
      challengeId: 'challenge-1',
      otpCode: '123456',
      emailHashHex: 'email-hash',
      routePlan: loginRoutePlanFromAppSessionJwt(appSessionJwt()),
      participantIds: [1, 3],
      ecdsaBootstrapAuthorization: { kind: 'route_plan_auth' },
      runtimePolicyScope,
      ed25519ReconstructionMode: 'await',
      ed25519SessionReconstruction: {
        kind: 'defer',
        reason: 'missing_runtime_policy_scope',
        ed25519Key: {
          signer: TEST_ED25519_SIGNER,
          relayerKeyId: 'ed25519-relayer-key',
          keyVersion: 'threshold-ed25519-hss-v1',
          participantIds: [1, 2],
        },
      },
      providerIdentity: { kind: 'derive_from_route_auth' },
    });

    expect(result.ed25519Reconstruction.kind).toBe('completed');
    expect(reconstructionCalls).toHaveLength(1);
    expect(reconstructionCalls[0]).toMatchObject({
      kind: 'session_ed25519_reconstruction',
      routeAuth: {
        kind: 'wallet_session',
        jwt: expect.any(String),
      },
      runtimePolicyScope,
      ed25519Key: {
        signer: TEST_ED25519_SIGNER,
        relayerKeyId: 'ed25519-relayer-key',
        keyVersion: 'threshold-ed25519-hss-v1',
        participantIds: [1, 2],
      },
    });
  });

  test('enrolls ECDSA Email OTP capability without Ed25519 reconstruction', async () => {
    const { coordinator, ecdsaCommitCalls } = createCoordinator();
    const runtimePolicyScope = {
      orgId: 'org',
      projectId: 'proj',
      envId: 'dev',
      signingRootVersion: 'v1',
    };
    const jwt = appSessionJwtWithRuntimePolicyScope(runtimePolicyScope);
    const result = await coordinator.enrollAndLoginWithEcdsaCapabilityInternal({
      walletSession: TEST_WALLET_SESSION,
      chainTarget: TEMPO_CHAIN_TARGET,
      challengeId: 'challenge-1',
      otpCode: '123456',
      emailHashHex: 'email-hash',
      routePlan: registrationRoutePlanFromAppSessionJwt(jwt),
      clientSecret32: new Uint8Array(32).fill(7),
      registrationAttemptId: 'registration-attempt-1',
    });

    expect(result.enrollment.thresholdEcdsaClientVerifyingShareB64u).toBe('verifying-share');
    expect(ecdsaCommitCalls).toHaveLength(2);
    expect(ecdsaCommitCalls.map((call) => call.chainTarget.kind).sort()).toEqual(['evm', 'tempo']);
  });
});
