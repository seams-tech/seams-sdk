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
import { deriveEvmFamilySigningKeySlotId } from '@shared/signing-lanes';
import { ROUTER_AB_ECDSA_HSS_WALLET_SESSION_JWT_KIND } from '@shared/utils/sessionTokens';
import {
  thresholdEcdsaLaneCandidateFromSessionRecord,
  type ThresholdEcdsaSessionRecord,
} from '@/core/signingEngine/session/persistence/records';
import {
  buildCurrentSealedSessionRecord,
  type BuildCurrentEcdsaSealedSessionRecordInput,
  type CurrentSealedSessionRecord,
  type listExactSealedSessionsForWallet,
} from '@/core/signingEngine/session/persistence/sealedSessionStore';
import {
  thresholdEcdsaChainTargetFromChainFamily,
  thresholdEcdsaChainTargetKey,
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
import {
  commitEmailOtpEcdsaLaneFromRecordForMaterial,
  resolvedEvmFamilyEcdsaSigningLaneFromCandidate,
} from '@/core/signingEngine/flows/signEvmFamily/ecdsaSelection';
import { buildEcdsaMaterialStateForCandidate } from '@/core/signingEngine/flows/signEvmFamily/ecdsaMaterialState';
import { buildEmailOtpAuthContextForWalletAuthMethod } from '@/core/signingEngine/session/identity/laneIdentity';
import { computeEcdsaHssRoleLocalThresholdKeyId } from '@shared/threshold/ecdsaHssRoleLocalBootstrap';
import { parseSigningSessionSealKeyVersion } from '@/core/signingEngine/session/keyMaterialBrands';
import {
  buildEvmFamilyEcdsaSignerBinding,
  exactEcdsaSigningLaneIdentity,
} from '@/core/signingEngine/session/identity/exactSigningLaneIdentity';
import type { RestorePersistedSessionForSigningInput } from '@/core/signingEngine/session/sealedRecovery/sealedRecovery.types';
import type { RouterAbEcdsaHssNormalSigningStateV1 } from '@shared/utils/routerAbEcdsaHss';

const TEST_SUBJECT_ID = toWalletId('alice.testnet');
const TEST_SIGNING_SESSION_SEAL_KEY_VERSION = parseSigningSessionSealKeyVersion(
  'signing-session-seal-kek-test-r1',
);

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
      chainTargetKey: thresholdEcdsaChainTargetKey(args.chainTarget),
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
      providerUserId: args.providerUserId || 'google:subject',
      emailHashHex,
    });
  }
  return buildEmailOtpAuthContextForWalletAuthMethod({
    policy: args.policy || 'session',
    retention: 'session',
    reason: args.reason || 'login',
    walletId,
    provider: 'google',
    providerUserId: args.providerUserId || 'google:subject',
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
  evmFamilySigningKeySlotId?: string;
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
      evmFamilySigningKeySlotId:
        args.evmFamilySigningKeySlotId ||
        deriveEvmFamilySigningKeySlotId({
          walletId: args.walletId,
          signingRootId: args.signingRootId,
          signingRootVersion: args.signingRootVersion,
          chainTargetKey: thresholdEcdsaChainTargetKey(args.chainTarget),
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
function appSessionJwt(expSeconds = Math.floor(Date.now() / 1000) + 3600): string {
  return `${jsonB64u({ alg: 'none', typ: 'JWT' })}.${jsonB64u({
    kind: 'app_session_v1',
    sub: 'google:subject',
    exp: expSeconds,
  })}.sig`;
}

function appSessionJwtWithRuntimePolicyScope(
  runtimePolicyScope: RuntimePolicyScopeFixture,
  expSeconds = Math.floor(Date.now() / 1000) + 3600,
): string {
  return `${jsonB64u({ alg: 'none', typ: 'JWT' })}.${jsonB64u({
    kind: 'app_session_v1',
    sub: 'google:subject',
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
  evmFamilySigningKeySlotId?: string;
  relayerKeyId?: string;
  thresholdExpiresAtMs?: number;
  participantIds?: readonly number[];
  chainTarget?: BuildCurrentEcdsaSealedSessionRecordInput['ecdsaRestore']['chainTarget'];
  runtimePolicyScope?: RuntimePolicyScopeFixture;
}): string {
  const evmFamilySigningKeySlotId =
    args.evmFamilySigningKeySlotId ||
    deriveEvmFamilySigningKeySlotId({
      walletId: toWalletId(args.walletId),
      signingRootId: 'signing-root',
      signingRootVersion: 'root-v1',
      ...(args.chainTarget
        ? { chainTargetKey: thresholdEcdsaChainTargetKey(args.chainTarget) }
        : {}),
    });
  return `${jsonB64u({ alg: 'none', typ: 'JWT' })}.${jsonB64u({
    kind: ROUTER_AB_ECDSA_HSS_WALLET_SESSION_JWT_KIND,
    sub: args.walletId,
    walletId: args.walletId,
    keyScope: 'evm-family',
    keyHandle: args.keyHandle,
    evmFamilySigningKeySlotId,
    relayerKeyId: args.relayerKeyId || 'relayer-key',
    thresholdSessionId: args.thresholdSessionId,
    signingGrantId: args.signingGrantId,
    thresholdExpiresAtMs: args.thresholdExpiresAtMs ?? Date.now() + 60_000,
    participantIds: args.participantIds || [1, 2],
    ...(args.chainTarget ? { chainTarget: args.chainTarget } : {}),
    ...(args.runtimePolicyScope ? { runtimePolicyScope: args.runtimePolicyScope } : {}),
  })}.sig`;
}

function hexAddress20B64u(address: `0x${string}`): string {
  const hex = address.replace(/^0x/, '');
  if (hex.length !== 40) {
    throw new Error(`invalid ECDSA address fixture: ${address}`);
  }
  const bytes = new Uint8Array(20);
  for (let index = 0; index < bytes.length; index += 1) {
    const hexByte = hex.slice(index * 2, index * 2 + 2);
    const value = Number.parseInt(hexByte, 16);
    if (!Number.isFinite(value)) {
      throw new Error(`invalid ECDSA address fixture: ${address}`);
    }
    bytes[index] = value;
  }
  return Buffer.from(bytes).toString('base64url');
}

function routerAbEcdsaHssNormalSigningFixture(args: {
  walletId: string;
  evmFamilySigningKeySlotId: string;
  ecdsaThresholdKeyId: string;
  signingRootId: string;
  signingRootVersion: string;
  ethereumAddress: `0x${string}`;
  thresholdSessionId: string;
  clientVerifyingShareB64u?: string;
  thresholdEcdsaPublicKeyB64u?: string;
}): RouterAbEcdsaHssNormalSigningStateV1 {
  const clientPublicKey33B64u = args.clientVerifyingShareB64u || VALID_ECDSA_CLIENT_PUBLIC_KEY_B64U;
  const thresholdPublicKey33B64u = args.thresholdEcdsaPublicKeyB64u || VALID_ECDSA_PUBLIC_KEY_B64U;
  return {
    kind: 'router_ab_ecdsa_hss_normal_signing_v1',
    scope: {
      wallet_key_id: args.evmFamilySigningKeySlotId,
      wallet_id: args.walletId,
      ecdsa_threshold_key_id: args.ecdsaThresholdKeyId,
      signing_root_id: args.signingRootId,
      signing_root_version: args.signingRootVersion,
      context: {
        application_binding_digest_b64u: VALID_ECDSA_APPLICATION_BINDING_DIGEST_B64U,
      },
      public_identity: {
        context_binding_b64u: VALID_ECDSA_CONTEXT_BINDING_B64U,
        client_public_key33_b64u: clientPublicKey33B64u,
        server_public_key33_b64u: VALID_ECDSA_RELAYER_PUBLIC_KEY_B64U,
        threshold_public_key33_b64u: thresholdPublicKey33B64u,
        ethereum_address20_b64u: hexAddress20B64u(args.ethereumAddress),
        client_share_retry_counter: 0,
        server_share_retry_counter: 0,
      },
      signing_worker: {
        server_id: 'signing-worker-test',
        key_epoch: 'worker-epoch-test',
        recipient_encryption_key:
          'x25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      },
      activation_epoch: args.thresholdSessionId,
    },
  };
}

function emailOtpWorkerBackendBindingFixture(args: {
  walletId: string;
  chainTarget: ReturnType<typeof thresholdEcdsaChainTargetFromChainFamily>;
  keyHandle: string;
  evmFamilySigningKeySlotId: string;
  ecdsaThresholdKeyId: string;
  signingRootId: string;
  signingRootVersion: string;
  ethereumAddress: `0x${string}`;
  thresholdSessionId: string;
}) {
  return {
    materialKind: 'email_otp_worker_handle' as const,
    relayerKeyId: 'relayer-key',
    clientVerifyingShareB64u: VALID_ECDSA_CLIENT_PUBLIC_KEY_B64U,
    clientAdditiveShareHandle: {
      kind: 'email_otp_worker_session' as const,
      sessionId: `email-otp-worker-${args.thresholdSessionId}`,
    },
    ecdsaRoleLocalReadyRecord: makeEmailOtpRoleLocalReadyRecord({
      walletId: args.walletId,
      rpId: 'localhost',
      chainTarget: args.chainTarget,
      keyHandle: args.keyHandle,
      evmFamilySigningKeySlotId: args.evmFamilySigningKeySlotId,
      ecdsaThresholdKeyId: args.ecdsaThresholdKeyId,
      signingRootId: args.signingRootId,
      signingRootVersion: args.signingRootVersion,
      ethereumAddress: args.ethereumAddress,
    }),
  };
}

function publicationTargetPlanForChainTarget(args: {
  plans: unknown;
  chainTarget: ReturnType<typeof thresholdEcdsaChainTargetFromChainFamily>;
}): any | null {
  if (!Array.isArray(args.plans)) return null;
  for (const plan of args.plans) {
    if (thresholdEcdsaChainTargetsEqual(plan.chainTarget, args.chainTarget)) {
      return plan;
    }
  }
  return null;
}

function emailOtpWorkerEcdsaBootstrapFixture(args: {
  call: any;
  chainTarget: ReturnType<typeof thresholdEcdsaChainTargetFromChainFamily>;
  evmFamilySigningKeySlotId?: string;
  remainingUses?: number;
}) {
  const payload = args.call.request.payload;
  const publicationTargetPlan = publicationTargetPlanForChainTarget({
    plans: payload.publicationTargetPlans,
    chainTarget: args.chainTarget,
  });
  const walletId = payload.walletId || 'alice.testnet';
  const thresholdSessionId = payload.sessionId || 'ecdsa-session';
  const signingGrantId = payload.signingGrantId || thresholdSessionId;
  const keyHandle = publicationTargetPlan?.keyHandle || payload.keyHandle || 'key-handle-ecdsa';
  const ecdsaThresholdKeyId = 'ecdsa-key';
  const runtimePolicyScope = payload.runtimePolicyScope;
  const signingRootId =
    runtimePolicyScope?.projectId && runtimePolicyScope?.envId
      ? `${runtimePolicyScope.projectId}:${runtimePolicyScope.envId}`
      : 'signing-root';
  const signingRootVersion = runtimePolicyScope?.signingRootVersion || 'root-v1';
  const ethereumAddress = `0x${'33'.repeat(20)}` as `0x${string}`;
  const evmFamilySigningKeySlotId =
    args.evmFamilySigningKeySlotId ||
    publicationTargetPlan?.evmFamilySigningKeySlotId ||
    deriveEvmFamilySigningKeySlotId({
      walletId: toWalletId(walletId),
      signingRootId,
      signingRootVersion,
      chainTargetKey: thresholdEcdsaChainTargetKey(args.chainTarget),
    });
  const routerAbEcdsaHssNormalSigning = routerAbEcdsaHssNormalSigningFixture({
    walletId,
    evmFamilySigningKeySlotId,
    ecdsaThresholdKeyId,
    signingRootId,
    signingRootVersion,
    ethereumAddress,
    thresholdSessionId,
  });
  const walletSessionJwt = thresholdEcdsaSessionJwt({
    walletId,
    keyHandle,
    thresholdSessionId,
    signingGrantId,
    evmFamilySigningKeySlotId,
    relayerKeyId: 'relayer-key',
    thresholdExpiresAtMs: Date.now() + 60_000,
    participantIds: [1, 2],
    chainTarget: args.chainTarget,
    ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
  });
  const remainingUses = args.remainingUses ?? 3;
  return {
    thresholdEcdsaKeyRef: {
      type: 'threshold-ecdsa-secp256k1',
      userId: walletId,
      subjectId: payload.subjectId,
      relayerUrl: payload.relayUrl || 'https://relay.example',
      keyHandle,
      evmFamilySigningKeySlotId,
      ecdsaThresholdKeyId,
      chainTarget: args.chainTarget,
      ethereumAddress,
      thresholdEcdsaPublicKeyB64u: VALID_ECDSA_PUBLIC_KEY_B64U,
      relayerVerifyingShareB64u: VALID_ECDSA_RELAYER_PUBLIC_KEY_B64U,
      thresholdSessionId,
      signingGrantId,
      thresholdSessionKind: 'jwt',
      walletSessionJwt,
      participantIds: [1, 3],
      routerAbEcdsaHssNormalSigning,
      backendBinding: emailOtpWorkerBackendBindingFixture({
        walletId,
        chainTarget: args.chainTarget,
        keyHandle,
        evmFamilySigningKeySlotId,
        ecdsaThresholdKeyId,
        signingRootId,
        signingRootVersion,
        ethereumAddress,
        thresholdSessionId,
      }),
    },
    keygen: {
      ok: true,
      evmFamilySigningKeySlotId,
    },
    session: {
      ok: true,
      thresholdSessionId,
      sessionId: thresholdSessionId,
      signingGrantId,
      expiresAtMs: Date.now() + 60_000,
      remainingUses,
      jwt: walletSessionJwt,
    },
  };
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
  const signingRootId = args.signingRootId || 'signing-root:dev';
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
    source: 'email_otp',
    evmFamilySigningKeySlotId:
      args.ecdsaRestore?.evmFamilySigningKeySlotId ||
      deriveEvmFamilySigningKeySlotId({
        walletId: toWalletId(walletId),
        signingRootId,
        signingRootVersion: args.signingRootVersion || 'root-v1',
        chainTargetKey: thresholdEcdsaChainTargetKey(chainTarget),
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
    routerAbEcdsaHssNormalSigning:
      args.ecdsaRestore?.routerAbEcdsaHssNormalSigning ||
      routerAbEcdsaHssNormalSigningFixture({
        walletId,
        evmFamilySigningKeySlotId:
          args.ecdsaRestore?.evmFamilySigningKeySlotId ||
          deriveEvmFamilySigningKeySlotId({
            walletId: toWalletId(walletId),
            signingRootId,
            signingRootVersion: args.signingRootVersion || 'root-v1',
            chainTargetKey: thresholdEcdsaChainTargetKey(chainTarget),
          }),
        ecdsaThresholdKeyId: args.ecdsaRestore?.ecdsaThresholdKeyId || 'ecdsa-key',
        signingRootId,
        signingRootVersion: args.signingRootVersion || 'root-v1',
        ethereumAddress: (args.ecdsaRestore?.ethereumAddress ||
          `0x${'33'.repeat(20)}`) as `0x${string}`,
        thresholdSessionId,
      }),
    runtimePolicyScope: args.ecdsaRestore?.runtimePolicyScope || runtimePolicyScope,
  };
  const record = buildCurrentSealedSessionRecord({
    curve: 'ecdsa',
    authMethod: 'email_otp',
    walletId,
    relayerUrl: args.relayerUrl || 'https://relay.example',
    keyVersion: args.keyVersion || 'signing-session-seal-kek-test-r1',
    shamirPrimeB64u: args.shamirPrimeB64u || 'prime-b64u',
    signingGrantId,
    thresholdSessionId,
    thresholdSessionIds: args.thresholdSessionIds || { ecdsa: thresholdSessionId },
    sealedSecretB64u: args.sealedSecretB64u || 'sealed-session-secret',
    ecdsaRestore,
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
}) {
  const workerCalls: any[] = [];
  let refreshCount = 0;
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
          kind: 'ecdsa',
          recovery: {
            challengeId: 'challenge-1',
            enrollmentSealKeyVersion: 'email-v1',
            unlockChallengeId: 'unlock-challenge',
            unlockChallengeB64u: 'unlock-challenge-b64u',
            clientUnlockPublicKeyB64u: 'unlock-public',
            unlockSignatureB64u: 'unlock-signature',
          },
          clientRootShareHandle: emailOtpEcdsaClientRootHandleFromWorkerCall(call),
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
          bootstraps: call.request.payload.publicationTargetPlans.map((plan: any) =>
            emailOtpWorkerEcdsaBootstrapFixture({
              call,
              chainTarget: plan.chainTarget,
              evmFamilySigningKeySlotId: plan.evmFamilySigningKeySlotId,
            }),
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
              ...signingRootFromRuntimePolicyScope(call.request.payload.restore.runtimePolicyScope),
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
          clientRootShareHandle: emailOtpEcdsaClientRootHandleFromWorkerCall(call),
        };
      }
      return { ok: true };
    },
  };
  const ecdsaCommitCalls: any[] = [];
  const sealedRecordWrites: CurrentSealedSessionRecord[] = [];
  const toSealedRecordReadback = (record: CurrentSealedSessionRecord): CurrentSealedSessionRecord =>
    record;
  const recordMatchesSealedPurpose = (
    write: any,
    thresholdSessionId: string | undefined,
    purpose?: any,
  ) => {
    if (thresholdSessionId && write.thresholdSessionIds?.ecdsa !== thresholdSessionId) {
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

  return {
    coordinator,
    workerCalls,
    ecdsaCommitCalls,
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
      providerIdentity: { kind: 'derive_from_route_auth' },
      ed25519YaoRecovery: { kind: 'not_requested' },
    });

    expect(result.bootstrap.thresholdEcdsaKeyRef.ecdsaThresholdKeyId).toBe('ecdsa-key');
    const expectedEvmFamilySigningKeySlotId = String(
      deriveEvmFamilySigningKeySlotId({
        walletId: 'alice.testnet',
        signingRootId: 'proj:dev',
        signingRootVersion: 'v1',
        chainTargetKey: thresholdEcdsaChainTargetKey(TEMPO_CHAIN_TARGET),
      }),
    );
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
          userId: 'google:subject',
          participantIds: [1, 3],
          publicationTargetPlans: expect.arrayContaining([
            expect.objectContaining({
              kind: 'existing_key_publication_target',
              chainTarget: TEMPO_CHAIN_TARGET,
              evmFamilySigningKeySlotId: expectedEvmFamilySigningKeySlotId,
              keyHandle,
            }),
          ]),
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
    expect(result).not.toHaveProperty('ed25519Reconstruction');
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
      providerIdentity: { kind: 'derive_from_route_auth' },
      ed25519YaoRecovery: { kind: 'not_requested' },
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
        providerIdentity: { kind: 'derive_from_route_auth' },
        ed25519YaoRecovery: { kind: 'not_requested' },
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

  test('registers an Email OTP ECDSA capability', async () => {
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
            kind: 'ecdsa',
            recovery: {
              loginGrant: 'login-grant',
              challengeId: 'challenge-1',
              enrollmentSealKeyVersion: 'email-v1',
              unlockChallengeId: 'unlock-challenge',
              unlockChallengeB64u: 'unlock-challenge-b64u',
              clientUnlockPublicKeyB64u: 'unlock-public',
              unlockSignatureB64u: 'unlock-sig',
            },
            clientRootShareHandle: emailOtpEcdsaClientRootHandleFromWorkerCall(call),
          };
        }
        if (call.request?.type === 'bootstrapEmailOtpEcdsaSessionsFromWorkerHandle') {
          return {
            bootstraps: call.request.payload.publicationTargetPlans.map((plan: any) =>
              emailOtpWorkerEcdsaBootstrapFixture({
                call,
                chainTarget: plan.chainTarget,
                evmFamilySigningKeySlotId: plan.evmFamilySigningKeySlotId,
                remainingUses: 9,
              }),
            ),
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
      providerIdentity: { kind: 'derive_from_route_auth' },
      ed25519YaoRecovery: { kind: 'not_requested' },
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
        providerIdentity: { kind: 'derive_from_route_auth' },
        ed25519YaoRecovery: { kind: 'not_requested' },
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
      providerIdentity: { kind: 'derive_from_route_auth' },
      ed25519YaoRecovery: { kind: 'not_requested' },
    });

    expect(
      workerCalls.some((call) => call.request?.type === 'sealEmailOtpWarmSessionMaterial'),
    ).toBe(true);
    expect(sealedRecordWrites.length).toBeGreaterThan(0);
  });

  test('Email OTP ECDSA signing step-up mints a budgeted signing grant id', async () => {
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
    const evmFamilySigningKeySlotId = deriveEvmFamilySigningKeySlotId({
      walletId: 'alice.testnet',
      signingRootId: 'signing-root',
      signingRootVersion: 'root-v1',
      chainTargetKey: thresholdEcdsaChainTargetKey(TEMPO_CHAIN_TARGET),
    });
    const walletSessionJwt = thresholdEcdsaSessionJwt({
      walletId: 'alice.testnet',
      keyHandle,
      thresholdSessionId: 'exhausted-threshold-session',
      signingGrantId: authorizingSigningGrantId,
      evmFamilySigningKeySlotId,
      relayerKeyId: 'relayer-key',
      thresholdExpiresAtMs: Date.now() + 60_000,
      participantIds: [1, 3],
      chainTarget: TEMPO_CHAIN_TARGET,
      runtimePolicyScope,
    });

    const record = {
      walletId: toWalletId('alice.testnet'),
      evmFamilySigningKeySlotId,
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
      remainingUses: 3,
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
    const tempoChainTarget = thresholdEcdsaChainTargetFromChainFamily({
      chain: 'tempo',
      chainId: 42431,
      networkSlug: 'tempo-testnet',
    });
    const runtimePolicyScope = {
      orgId: 'org-transaction',
      projectId: 'project-transaction',
      envId: 'dev',
      signingRootVersion: 'root-v1',
    };
    const signingRootId = `${runtimePolicyScope.projectId}:${runtimePolicyScope.envId}`;
    const keyHandle = toEvmFamilyEcdsaKeyHandle('key-handle-transaction');
    const thresholdOwnerAddress = '0x'.padEnd(42, 'a') as `0x${string}`;
    const evmFamilySigningKeySlotId = deriveEvmFamilySigningKeySlotId({
      walletId: 'alice.testnet',
      signingRootId,
      signingRootVersion: runtimePolicyScope.signingRootVersion,
      chainTargetKey: thresholdEcdsaChainTargetKey(tempoChainTarget),
    });
    const thresholdExpiresAtMs = Date.now() + 60_000;
    const walletSessionJwt = thresholdEcdsaSessionJwt({
      walletId: 'alice.testnet',
      keyHandle,
      thresholdSessionId: 'transaction-ecdsa-session',
      signingGrantId: 'transaction-signing-grant',
      evmFamilySigningKeySlotId,
      relayerKeyId: 'relayer-key',
      thresholdExpiresAtMs,
      participantIds: [1, 2],
      chainTarget: tempoChainTarget,
      runtimePolicyScope,
    });

    const record = {
      walletId: toWalletId('alice.testnet'),
      evmFamilySigningKeySlotId,
      chainTarget: tempoChainTarget,
      relayerUrl: 'https://relay.example',
      keyHandle,
      ecdsaThresholdKeyId: 'ecdsa-key',
      signingRootId,
      signingRootVersion: runtimePolicyScope.signingRootVersion,
      relayerKeyId: 'relayer-key',
      clientVerifyingShareB64u: 'client-verifying-share',
      ecdsaRoleLocalReadyRecord: makeEmailOtpRoleLocalReadyRecord({
        walletId: 'alice.testnet',
        rpId: 'localhost',
        chainTarget: tempoChainTarget,
        keyHandle,
        ecdsaThresholdKeyId: 'ecdsa-key',
        signingRootId,
        signingRootVersion: runtimePolicyScope.signingRootVersion,
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
      expiresAtMs: thresholdExpiresAtMs,
      remainingUses: 7,
      runtimePolicyScope,
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
                  call.request.payload.restore.runtimePolicyScope,
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
                  call.request.payload.restore.runtimePolicyScope,
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
      kind: 'discover_wallet_ecdsa_signing_sessions',
      walletId: 'alice.testnet',
      authMethod: 'email_otp',
      ecdsaChainTargets: [tempoChainTarget, evmChainTarget],
    });
    const second = await coordinator.discoverPersistedSessionsForWallet({
      kind: 'discover_wallet_ecdsa_signing_sessions',
      walletId: 'alice.testnet',
      authMethod: 'email_otp',
      ecdsaChainTargets: [tempoChainTarget, evmChainTarget],
    });

    expect(first).toMatchObject({ listed: 1, discovered: 1, truncated: 0 });
    expect(second).toMatchObject({ listed: 1, discovered: 1, truncated: 0 });
    expect(listFilters).toHaveLength(4);
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
                  chainTargetKey: thresholdEcdsaChainTargetKey(TEMPO_CHAIN_TARGET),
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

  test('enrolls an Email OTP ECDSA capability', async () => {
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
