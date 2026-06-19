import { expect, test } from '@playwright/test';
import { EmailOtpWalletSessionCoordinator } from '@/core/signingEngine/session/emailOtp/EmailOtpWalletSessionCoordinator';
import { requestEmailOtpExportAuthorization } from '@/core/signingEngine/stepUpConfirmation/otpPrompt/exportAuthorization';
import { toAuthorizingSigningGrantId } from '@/core/signingEngine/stepUpConfirmation/otpPrompt/authLane';
import { WALLET_EMAIL_OTP_EXPORT_OPERATION } from '@shared/utils/emailOtpDomain';
import { ROUTER_AB_ECDSA_HSS_WALLET_SESSION_JWT_KIND } from '@shared/utils/sessionTokens';
import { persistWarmSessionEd25519Capability } from '@/core/signingEngine/session/warmCapabilities/persistence';
import {
  clearAllStoredThresholdEd25519SessionRecords,
  clearAllThresholdEcdsaSessionRecords,
  getStoredThresholdEd25519SessionRecordByThresholdSessionId,
  upsertStoredThresholdEcdsaSessionRecord,
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
  buildVerifiedEcdsaPublicFacts,
  deriveEvmFamilyEcdsaKeyHandle,
  toEvmFamilyEcdsaKeyHandle,
} from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import {
  buildEcdsaRoleLocalEmailOtpAuthMethod,
  buildEcdsaRoleLocalPublicFacts,
  buildEcdsaRoleLocalReadyRecord,
} from '@/core/signingEngine/session/persistence/ecdsaRoleLocalRecords';
import type { EmailOtpEd25519SessionReconstructionPlan } from '@/core/signingEngine/session/emailOtp/provisioning';
import { computeEcdsaHssRoleLocalThresholdKeyId } from '@shared/threshold/ecdsaHssRoleLocalBootstrap';

const TEST_SUBJECT_ID = toWalletId('alice.testnet');
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
const DEFER_ED25519_RECONSTRUCTION_FOR_ECDSA = {
  kind: 'defer',
  reason: 'not_needed_for_ecdsa',
} satisfies EmailOtpEd25519SessionReconstructionPlan;

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
      rpId: args.rpId,
      chainTarget: args.chainTarget,
      keyHandle: args.keyHandle,
      ecdsaThresholdKeyId: args.ecdsaThresholdKeyId,
      signingRootId: args.signingRootId,
      signingRootVersion: args.signingRootVersion,
      clientParticipantId: 1,
      relayerParticipantId: 2,
      participantIds: [1, 2],
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
    sessionId: args.thresholdSessionId,
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
  const ecdsaThresholdKeyId = await computeEcdsaHssRoleLocalThresholdKeyId({
    walletId: args.walletId,
    rpId: args.rpId,
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
  userId?: string;
  signingRootId?: string;
  signingRootVersion?: string;
  relayerUrl?: string;
  keyVersion?: string;
  shamirPrimeB64u?: string;
  sealedSecretB64u?: string;
  chainTarget?: BuildCurrentEcdsaSealedSessionRecordInput['ecdsaRestore']['chainTarget'];
  ecdsaRestore?: Partial<BuildCurrentEcdsaSealedSessionRecordInput['ecdsaRestore']>;
  ed25519Restore?: Partial<NonNullable<BuildCurrentEcdsaSealedSessionRecordInput['ed25519Restore']>>;
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
    rpId: args.ecdsaRestore?.rpId || 'example.com',
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
          rpId: args.ed25519Restore?.rpId || 'localhost',
          relayerKeyId: args.ed25519Restore?.relayerKeyId || 'ed25519-relayer-key',
          participantIds: args.ed25519Restore?.participantIds || [1, 3],
          walletSessionJwt:
            args.ed25519Restore?.walletSessionJwt || 'threshold-session-jwt',
          sessionKind: args.ed25519Restore?.sessionKind || 'jwt',
          ...(args.ed25519Restore?.runtimePolicyScope === undefined
            ? {}
            : { runtimePolicyScope: args.ed25519Restore.runtimePolicyScope }),
          ...(args.ed25519Restore?.xClientBaseB64u
            ? { xClientBaseB64u: args.ed25519Restore.xClientBaseB64u }
            : {}),
          ...(args.ed25519Restore?.clientVerifyingShareB64u
            ? { clientVerifyingShareB64u: args.ed25519Restore.clientVerifyingShareB64u }
            : {}),
          ...(args.ed25519Restore?.routerAbNormalSigning
            ? { routerAbNormalSigning: args.ed25519Restore.routerAbNormalSigning }
            : {}),
        }
      : undefined;
  const record = buildCurrentSealedSessionRecord({
    curve: 'ecdsa',
    authMethod: 'email_otp',
    walletId,
    userId: args.userId || 'alice.testnet',
    relayerUrl: args.relayerUrl || 'https://relay.example',
    keyVersion: args.keyVersion || 'seal-v1',
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
  return {
    ...record,
    // Legacy top-level signing-root fields are retained in these fixtures to
    // exercise boundary compatibility during sealed recovery normalization.
    signingRootId: args.signingRootId || 'signing-root',
    signingRootVersion: args.signingRootVersion || 'root-v1',
  } as CurrentSealedSessionRecord;
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
    const signingGrantId =
      call.request.payload.signingGrantId || thresholdSessionId;
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
      keygen: { ok: true, rpId: 'example.com' },
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
          recovery: { thresholdEd25519PrfFirstB64u: 'prf-first-ecdsa-login' },
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
          keyVersion: 'seal-v1',
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
            keygen: { ok: true, rpId: 'example.com' },
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
          thresholdEd25519PrfFirstB64u: 'prf-first-ecdsa-enroll',
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
  const toSealedRecordReadback = (
    record: CurrentSealedSessionRecord,
  ): CurrentSealedSessionRecord => record;
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
      nearAccountId: 'alice.testnet',
      chain: 'near',
      authLane: {
        kind: 'signing_session',
        jwt: walletSessionJwt,
        thresholdSessionId: 'ed25519-session',
        authorizingSigningGrantId:
          toAuthorizingSigningGrantId('signing-grant'),
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

  test('NEAR transaction challenge falls back to app-session OTP without signing-session authority', async () => {
    const { coordinator, workerCalls, getRefreshCount } = createCoordinator();

    const challenge = await coordinator.requestTransactionSigningChallenge({
      kind: 'near_account_challenge',
      nearAccountId: 'alice.testnet',
      chain: 'near',
    });

    expect(challenge).toMatchObject({
      challengeId: 'challenge-1',
      emailHint: 'a***@example.com',
    });
    expect(getRefreshCount()).toBe(1);
    expect(workerCalls[0]).toMatchObject({
      kind: 'emailOtp',
      request: {
        type: 'requestEmailOtpChallenge',
        payload: {
          relayUrl: 'https://relay.example',
          walletId: 'alice.testnet',
          routePlan: {
            routeFamily: 'login',
            authLane: { kind: 'app_session' },
            operation: 'transaction_sign',
          },
          otpChannel: 'email_otp',
        },
      },
    });
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
        nearAccountId: 'alice.testnet',
        chain: 'evm',
        publicKey: '02'.padEnd(66, '1'),
        curve: 'ecdsa',
        challengeSource: {
          requestChallenge: async () =>
            await coordinator.requestExportChallenge({
              kind: 'near_account_challenge',
              nearAccountId: 'alice.testnet',
              chain: 'evm',
              authLane: {
                kind: 'signing_session',
                jwt: walletSessionJwt,
                thresholdSessionId: 'ecdsa-session',
                authorizingSigningGrantId:
                  toAuthorizingSigningGrantId('signing-grant'),
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
        nearAccountId: 'alice.testnet',
        chain: 'near',
        routeAuth: { kind: 'app_session', jwt },
      }),
    ).rejects.toThrow('Email OTP signing-session authority is unavailable; unlock wallet again');

    expect(getRefreshCount()).toBe(0);
    expect(workerCalls).toHaveLength(0);
  });

  test('logs in Ed25519 Email OTP capability with normalized auth context', async () => {
    const ed25519ReconstructionCalls: any[] = [];
    const ecdsaWalletSessionJwt = thresholdEcdsaSessionJwt({
      walletId: 'alice.testnet',
      keyHandle: 'key-handle-ecdsa',
      thresholdSessionId: 'ecdsa-session',
      signingGrantId: 'wallet-session-ecdsa',
      chainTarget: TEMPO_CHAIN_TARGET,
    });
    const { coordinator, workerCalls } = createCoordinator({
      listThresholdEcdsaSessionRecordsForWallet: (walletId) => [
        {
          walletId,
          subjectId: TEST_SUBJECT_ID,
          chainTarget: TEMPO_CHAIN_TARGET,
          source: 'email_otp',
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
          signingGrantId: 'wallet-session-ecdsa',
          walletSessionJwt: ecdsaWalletSessionJwt,
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 1,
          updatedAtMs: Date.now(),
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

    const result = await coordinator.loginWithEd25519CapabilityForSigning({
      nearAccountId: 'alice.testnet',
      challengeId: 'challenge-1',
      otpCode: '123456',
      routeAuth: { kind: 'wallet_session', jwt: walletSessionJwt },
      record: {
        thresholdSessionId: 'old-session',
        signingGrantId: 'wallet-session-ed25519',
        curve: 'ed25519',
        relayerUrl: '',
        rpId: '',
        relayerKeyId: 'relayer-key',
        keyVersion: 'v1',
        participantIds: [1, 2],
        thresholdSessionKind: 'jwt',
        walletSessionJwt,
        expiresAtMs: Date.now() + 60_000,
        remainingUses: 1,
        runtimePolicyScope: {
          orgId: 'org',
          projectId: 'project',
          envId: 'dev',
          signingRootVersion: 'root',
        },
        source: 'email_otp',
      } as any,
    });

    expect(result.sessionId).toBe('ed-session');
    expect(ed25519ReconstructionCalls).toHaveLength(1);
    expect(ed25519ReconstructionCalls[0]).toMatchObject({
      nearAccountId: 'alice.testnet',
      relayUrl: 'https://relay.example',
      rpId: 'localhost',
      prfFirstB64u: 'prf-first-ecdsa-login',
      routeAuth: { kind: 'wallet_session', jwt: expect.any(String) },
      ed25519Key: {
        relayerKeyId: 'relayer-key',
        keyVersion: 'threshold-ed25519-hss-v1',
        participantIds: [1, 2],
      },
      remainingUses: 1,
      ecdsaThresholdSessionId: 'ecdsa-session',
      emailOtpAuthContext: {
        policy: 'per_operation',
        retention: 'single_use',
        reason: 'sign',
        authMethod: 'email_otp',
      },
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
    const result = await coordinator.exportEd25519SeedWithAuthorization({
      nearAccountId: 'alice.testnet',
      challengeId: 'challenge-1',
      otpCode: '123456',
      keyVersion: 'v1',
      participantIds: [1, 2],
      thresholdSessionId: 'ed25519-restored-session',
      walletSessionJwt: walletSessionJwt,
      relayerKeyId: 'relayer-key',
      expectedPublicKey: 'ed25519:public',
      routeAuth: { kind: 'wallet_session', jwt: walletSessionJwt },
      record: {
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
        source: 'email_otp',
      } as any,
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
        keyVersion: 'v1',
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
      appSessionJwt: jwt,
      routeAuth: { kind: 'app_session', jwt },
      keyHandle,
      participantIds: [1, 3],
      sessionKind: 'jwt',
      ecdsaBootstrapAuthorization: { kind: 'route_plan_auth' },
      runtimePolicyScope,
      ed25519ReconstructionMode: 'skip',
      ed25519SessionReconstruction: DEFER_ED25519_RECONSTRUCTION_FOR_ECDSA,
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
          rpId: 'localhost',
          keyHandle,
          participantIds: [1, 3],
          sessionKind: 'jwt',
          remainingUses: 3,
          routeAuth: { kind: 'app_session', jwt },
        },
      },
    });
    expect(ecdsaCommitCalls[0]).toMatchObject({
      walletId: 'alice.testnet',
      primaryChain: { kind: 'tempo', chainId: 42431 },
      source: 'email_otp',
      emailOtpAuthContext: {
        policy: 'per_operation',
        retention: 'session',
        reason: 'login',
        authMethod: 'email_otp',
      },
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
      appSessionJwt: jwt,
      keyHandle,
      participantIds: [1, 3],
      sessionKind: 'jwt',
      ecdsaBootstrapAuthorization: { kind: 'route_plan_auth' },
      ed25519ReconstructionMode: 'skip',
      ed25519SessionReconstruction: DEFER_ED25519_RECONSTRUCTION_FOR_ECDSA,
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
        appSessionJwt: jwt,
        routeAuth: { kind: 'app_session', jwt },
        keyHandle: 'ehss-key-handle-1',
        participantIds: [1, 3],
        sessionKind: 'jwt',
        ecdsaBootstrapAuthorization: { kind: 'route_plan_auth' },
        ed25519ReconstructionMode: 'skip',
        ed25519SessionReconstruction: DEFER_ED25519_RECONSTRUCTION_FOR_ECDSA,
      }),
    ).rejects.toThrow('Email OTP ECDSA login requires runtimePolicyScope');

    expect(
      workerCalls.some((call) => call.request?.type === 'loginWithEmailOtpWallet'),
    ).toBe(false);
    expect(
      workerCalls.some(
        (call) => call.request?.type === 'bootstrapEmailOtpEcdsaSessionsFromWorkerHandle',
      ),
    ).toBe(false);
  });

  test('Email OTP registration bootstrap derives app-session route auth from appSessionJwt', async () => {
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
      appSessionJwt: jwt,
      participantIds: [1, 3],
      sessionKind: 'jwt',
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
      appSessionJwt: jwt,
      participantIds: [1, 3],
      sessionKind: 'jwt',
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
          sessionSeal: { keyVersion: 'seal-v1', shamirPrimeB64u: 'prime-b64u' },
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
              thresholdEd25519PrfFirstB64u: 'prf-first-ecdsa-login',
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
              keygen: { ok: true, rpId: 'example.com' },
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
            keyVersion: 'seal-v1',
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
      appSessionJwt: jwt,
      routeAuth: { kind: 'app_session', jwt },
      keyHandle,
      participantIds: [1, 3],
      sessionKind: 'jwt',
      ecdsaBootstrapAuthorization: { kind: 'route_plan_auth' },
      ed25519ReconstructionMode: 'skip',
      ed25519SessionReconstruction: DEFER_ED25519_RECONSTRUCTION_FOR_ECDSA,
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
            keyVersion: 'seal-v1',
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
        keyVersion: 'seal-v1',
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
          sessionSeal: { keyVersion: 'seal-v1', shamirPrimeB64u: 'prime-b64u' },
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
        routeAuth: { kind: 'app_session', jwt },
        keyHandle,
        participantIds: [1, 3],
        sessionKind: 'jwt',
        ecdsaBootstrapAuthorization: { kind: 'route_plan_auth' },
        ed25519ReconstructionMode: 'skip',
        ed25519SessionReconstruction: DEFER_ED25519_RECONSTRUCTION_FOR_ECDSA,
      }),
    ).rejects.toThrow('Email OTP sealed refresh tempo:42431 record was not durably persisted');
  });

  test('persists sealed Email OTP refresh records for wallet-unlock ECDSA login under per-operation policy', async () => {
    const { coordinator, workerCalls, sealedRecordWrites } = createCoordinator({
      configs: {
        signing: {
          emailOtp: { authPolicy: 'per_operation' },
          sessionPersistenceMode: 'sealed_refresh_v1',
          sessionSeal: { keyVersion: 'seal-v1', shamirPrimeB64u: 'prime-b64u' },
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
      appSessionJwt: jwt,
      routeAuth: { kind: 'app_session', jwt },
      keyHandle,
      participantIds: [1, 3],
      sessionKind: 'jwt',
      ecdsaBootstrapAuthorization: { kind: 'route_plan_auth' },
      ed25519ReconstructionMode: 'skip',
      ed25519SessionReconstruction: DEFER_ED25519_RECONSTRUCTION_FOR_ECDSA,
    });

    expect(
      workerCalls.some((call) => call.request?.type === 'sealEmailOtpWarmSessionMaterial'),
    ).toBe(true);
    expect(sealedRecordWrites.length).toBeGreaterThan(0);
  });

  test('Email OTP per-operation ECDSA signing mints a fresh wallet signing-session id', async () => {
    const { coordinator, workerCalls } = createCoordinator({
      configs: {
        signing: {
          emailOtp: { authPolicy: 'per_operation' },
          sessionPersistenceMode: 'sealed_refresh_v1',
          sessionSeal: { keyVersion: 'seal-v1', shamirPrimeB64u: 'prime-b64u' },
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

    const result = await coordinator.loginWithEcdsaCapabilityForSigning({
      walletSession: TEST_WALLET_SESSION,
      chainTarget: TEMPO_CHAIN_TARGET,
      challengeId: 'challenge-1',
      otpCode: '123456',
      routeAuth: { kind: 'wallet_session', jwt: walletSessionJwt },
      record: {
        walletId: 'alice.testnet' as any,
        authMetadata: { rpId: 'localhost' },
        chainTarget: TEMPO_CHAIN_TARGET,
        relayerUrl: 'https://relay.example',
        keyHandle: toEvmFamilyEcdsaKeyHandle(keyHandle),
        ecdsaThresholdKeyId: 'ecdsa-key' as any,
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
        emailOtpAuthContext: {
          policy: 'per_operation',
          retention: 'single_use',
          reason: 'sign',
          authMethod: 'email_otp',
        },
        updatedAtMs: Date.now(),
        source: 'email_otp',
      },
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
    const mintedSigningGrantId = String(
      bootstrapCall?.request.payload.signingGrantId || '',
    );
    expect(mintedSigningGrantId).toBeTruthy();
    expect(mintedSigningGrantId).not.toBe(authorizingSigningGrantId);
    expect(result.bootstrap.session.signingGrantId).toBe(mintedSigningGrantId);
  });

  test('export ECDSA reauth uses operation-scoped auth without replacing transaction sealed refresh', async () => {
    const {
      coordinator,
      workerCalls,
      sealedRecordWrites,
      ecdsaCommitCalls,
    } = createCoordinator({
      configs: {
        signing: {
          emailOtp: { authPolicy: 'session' },
          sessionPersistenceMode: 'sealed_refresh_v1',
          sessionSeal: { keyVersion: 'seal-v1', shamirPrimeB64u: 'prime-b64u' },
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

    const artifact = await coordinator.exportEcdsaKeyWithAuthorization({
      walletSession: {
        walletId: 'alice.testnet' as any,
        walletSessionUserId: 'alice.testnet',
      },
      challengeId: 'export-challenge-1',
      otpCode: '123456',
      rpId: 'localhost',
      routeAuth: { kind: 'wallet_session', jwt: walletSessionJwt },
      record: {
        walletId: 'alice.testnet' as any,
        authMetadata: { rpId: 'localhost' },
        chainTarget: tempoChainTarget,
        relayerUrl: 'https://relay.example',
        keyHandle,
        ecdsaThresholdKeyId: 'ecdsa-key' as any,
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
        emailOtpAuthContext: {
          policy: 'session',
          retention: 'session',
          reason: 'login',
          authMethod: 'email_otp',
        },
        updatedAtMs: Date.now(),
        source: 'email_otp',
      },
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
          sessionSeal: { keyVersion: 'seal-v1', shamirPrimeB64u: 'prime-b64u' },
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
              keygen: { ok: true, rpId: 'example.com' },
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

    const result = await coordinator.restorePersistedSessionForSigning({
      walletId: 'alice.testnet',
      authMethod: 'email_otp',
      curve: 'ecdsa',
      chainTarget: tempoChainTarget,
      signingGrantId: 'wallet-session-1',
      thresholdSessionId: 'ecdsa-session',
      reason: 'transaction',
    });

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
            keyVersion: 'seal-v1',
            shamirPrimeB64u: 'prime-b64u',
          },
          restore: {
            sessionId: 'ecdsa-session',
            walletId: 'alice.testnet',
            rpId: 'localhost',
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
      primaryChain: { kind: 'tempo', chainId: 42431 },
      source: 'email_otp',
      emailOtpAuthContext: {
        policy: 'session',
        retention: 'session',
        reason: 'login',
        authMethod: 'email_otp',
      },
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
          sessionSeal: { keyVersion: 'seal-v1', shamirPrimeB64u: 'prime-b64u' },
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
              keygen: { ok: true, rpId: 'example.com' },
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
              signingSessionSealKeyVersion: 'seal-v1',
              signingSessionSealShamirPrimeB64u: 'prime-b64u',
              expiresAtMs,
              remainingUses: 2,
              emailOtpAuthContext: {
                policy: 'session',
                retention: 'session',
                reason: 'login',
                authMethod: 'email_otp',
              },
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
        nearAccountId: 'alice.testnet',
        rpId: 'localhost',
        relayerUrl: 'https://relay.example',
        relayerKeyId: 'relayer-key',
        participantIds: [1, 2],
        sessionId: 'ed25519-session',
        signingGrantId: 'wallet-session-1',
        expiresAtMs,
        remainingUses: 2,
        sessionKind: 'jwt',
        jwt: appSessionJwt(),
        emailOtpAuthContext: {
          policy: 'session',
          retention: 'session',
          reason: 'login',
          authMethod: 'email_otp',
        },
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
          sessionSeal: { keyVersion: 'seal-v1', shamirPrimeB64u: 'prime-b64u' },
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
          sessionSeal: { keyVersion: 'seal-v1', shamirPrimeB64u: 'prime-b64u' },
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
        nearAccountId: 'alice.testnet',
        rpId: 'localhost',
        relayerUrl: 'https://relay.example',
        relayerKeyId: 'relayer-key',
        participantIds: [1, 2],
        sessionId: 'ed25519-session',
        signingGrantId: 'wallet-session-1',
        expiresAtMs,
        remainingUses: 2,
        sessionKind: 'jwt',
        jwt: appSessionJwt(),
        emailOtpAuthContext: {
          policy: 'session',
          retention: 'session',
          reason: 'login',
          authMethod: 'email_otp',
        },
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
          sessionSeal: { keyVersion: 'seal-v1', shamirPrimeB64u: 'prime-b64u' },
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
              keygen: { ok: true, rpId: 'example.com' },
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

    const restoreResult = await coordinator.restorePersistedSessionForSigning({
      walletId: 'alice.testnet',
      authMethod: 'email_otp',
      curve: 'ecdsa',
      chainTarget: tempoChainTarget,
      signingGrantId: 'wallet-session-1',
      thresholdSessionId: 'ecdsa-session',
      reason: 'transaction',
    });
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
          sessionSeal: { keyVersion: 'seal-v1', shamirPrimeB64u: 'prime-b64u' },
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

    const first = await coordinator.restorePersistedSessionForSigning({
      walletId: 'alice.testnet',
      authMethod: 'email_otp',
      curve: 'ed25519',
      chain: 'near',
      signingGrantId: 'wallet-session-1',
      thresholdSessionId: 'ed25519-session',
      reason: 'transaction',
    });
    const second = await coordinator.restorePersistedSessionForSigning({
      walletId: 'alice.testnet',
      authMethod: 'email_otp',
      curve: 'ed25519',
      chain: 'near',
      signingGrantId: 'wallet-session-1',
      thresholdSessionId: 'ed25519-session',
      reason: 'transaction',
    });

    expect(first).toMatchObject({ attempted: 0, restored: 0, deferred: 0 });
    expect(second).toMatchObject({ attempted: 0, restored: 0, deferred: 0 });
    expect(
      workerCalls.some(
        (call) => call.request?.type === 'rehydrateEmailOtpEcdsaWarmSessionMaterial',
      ),
    ).toBe(false);
  });

  test('wallet-scoped restore enumerates durable sealed ECDSA records after reload', async () => {
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
    const { coordinator, workerCalls, ecdsaCommitCalls } = createCoordinator({
      configs: {
        signing: {
          emailOtp: { authPolicy: 'session' },
          sessionPersistenceMode: 'sealed_refresh_v1',
          sessionSeal: { keyVersion: 'seal-v1', shamirPrimeB64u: 'prime-b64u' },
        },
      },
      requestWorkerOperation: async (call: any) => {
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
              keygen: { ok: true, rpId: 'example.com' },
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
      listExactSealedSessionsForWallet: async (args) => {
        expect(args).toMatchObject({
          walletId: 'alice.testnet',
          filter: { authMethod: 'email_otp' },
        });
        return args.filter?.curve === 'ecdsa' ? [sealedRecord] : [];
      },
      readExactSealedSession: async (thresholdSessionId, purpose) => {
        if (thresholdSessionId === 'ecdsa-session' && purpose?.curve === 'ecdsa') {
          return sealedRecord;
        }
        return null;
      },
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

    await coordinator.restorePersistedSessionsForWallet({
      kind: 'restore_wallet_all_signing_sessions',
      walletId: 'alice.testnet',
      authMethod: 'email_otp',
      ecdsaChainTargets: [tempoChainTarget, evmChainTarget],
    });
    await coordinator.restorePersistedSessionsForWallet({
      kind: 'restore_wallet_all_signing_sessions',
      walletId: 'alice.testnet',
      authMethod: 'email_otp',
      ecdsaChainTargets: [tempoChainTarget, evmChainTarget],
    });
    const restoreCall = workerCalls.find(
      (call) => call.request?.type === 'rehydrateEmailOtpEcdsaWarmSessionMaterial',
    );

    expect(restoreCall).toBeTruthy();
    expect(restoreCall.request.payload.restore).toMatchObject({
      sessionId: 'ecdsa-session',
      chainTarget: tempoChainTarget,
      signingGrantId: 'wallet-session-1',
    });
    expect(ecdsaCommitCalls).toHaveLength(1);
    expect(
      workerCalls.filter(
        (call) => call.request?.type === 'rehydrateEmailOtpEcdsaWarmSessionMaterial',
      ),
    ).toHaveLength(1);
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
      emailOtpAuthContext: {
        policy: 'session',
        retention: 'session',
        reason: 'login',
        authMethod: 'email_otp',
      },
      updatedAtMs: Date.now(),
      source: 'email_otp',
    };
    const { coordinator, workerCalls } = createCoordinator({
      configs: {
        signing: {
          emailOtp: { authPolicy: 'session' },
          sessionPersistenceMode: 'sealed_refresh_v1',
          sessionSeal: { keyVersion: 'seal-v1', shamirPrimeB64u: 'prime-b64u' },
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
              keygen: { ok: true, rpId: 'example.com' },
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
        rpId: 'localhost',
        relayerKeyId: 'ed25519-relayer-key',
        participantIds: [1, 3],
        walletSessionJwt: 'threshold-session-jwt',
        sessionKind: 'jwt',
        xClientBaseB64u: 'ed25519-x-client-base',
        clientVerifyingShareB64u: 'ed25519-client-verifying-share',
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
      signingSessionSealKeyVersion: 'seal-v1',
      signingSessionSealShamirPrimeB64u: 'prime-b64u',
      expiresAtMs,
      remainingUses: 2,
      emailOtpAuthContext: {
        policy: 'session',
        retention: 'session',
        reason: 'login',
        authMethod: 'email_otp',
      },
      updatedAtMs: Date.now(),
      source: 'email_otp',
    };
    const { coordinator, workerCalls } = createCoordinator({
      configs: {
        signing: {
          emailOtp: { authPolicy: 'session' },
          sessionPersistenceMode: 'sealed_refresh_v1',
          sessionSeal: { keyVersion: 'seal-v1', shamirPrimeB64u: 'prime-b64u' },
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

    const restoreResult = await coordinator.restorePersistedSessionForSigning({
      walletId: 'alice.testnet',
      authMethod: 'email_otp',
      curve: 'ecdsa',
      chainTarget: tempoChainTarget,
      signingGrantId: 'wallet-session-1',
      thresholdSessionId: 'ecdsa-session',
      reason: 'transaction',
    });

    expect(restoreResult).toMatchObject({ attempted: 1, restored: 0, deferred: 1 });
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
      emailOtpAuthContext: {
        policy: 'session',
        retention: 'session',
        reason: 'login',
        authMethod: 'email_otp',
      },
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
          sessionSeal: { keyVersion: 'seal-v1', shamirPrimeB64u: 'prime-b64u' },
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
        userId: 'alice.testnet',
        signingRootId: 'signing-root',
        signingRootVersion: 'root-v1',
        relayerUrl: 'https://relay.example',
        keyVersion: 'seal-v1',
        shamirPrimeB64u: 'prime-b64u',
        ecdsaRestore: {
          chainTarget: ecdsaRecord.chainTarget,
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
        nearAccountId: 'alice.testnet',
        rpId: 'localhost',
        relayerUrl: 'https://relay.example',
        relayerKeyId: 'relayer-key',
        participantIds: [1, 2],
        sessionId: 'ed25519-session',
        signingGrantId: 'wallet-session-1',
        expiresAtMs,
        remainingUses: 2,
        sessionKind: 'jwt',
        jwt: appSessionJwt(),
        emailOtpAuthContext: {
          policy: 'session',
          retention: 'session',
          reason: 'login',
          authMethod: 'email_otp',
        },
        source: 'email_otp',
      });

      await (coordinator as any).attachEd25519SessionToEmailOtpSigningSessionSealBestEffort({
        ecdsaThresholdSessionId: 'ecdsa-session',
        ed25519ThresholdSessionId: 'ed25519-session',
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
      routeAuth: { kind: 'app_session', jwt: routeJwt },
      participantIds: [1, 3],
      sessionKind: 'jwt',
      ecdsaBootstrapAuthorization: { kind: 'route_plan_auth' },
      ed25519ReconstructionMode: 'await',
      ed25519SessionReconstruction: {
        kind: 'defer',
        reason: 'missing_runtime_policy_scope',
        ed25519Key: {
          relayerKeyId: 'ed25519-relayer-key',
          keyVersion: 'threshold-ed25519-hss-v1',
          participantIds: [1, 2],
        },
      },
    });

    expect(result.ed25519Reconstruction.kind).toBe('completed');
    expect(reconstructionCalls).toHaveLength(1);
    expect(reconstructionCalls[0]).toMatchObject({
      kind: 'session_ed25519_reconstruction',
      nearAccountId: 'alice.testnet',
      relayUrl: 'https://relay.example',
      rpId: 'localhost',
      prfFirstB64u: 'prf-first-ecdsa-login',
      routeAuth: {
        kind: 'wallet_session',
        jwt: expect.any(String),
      },
      runtimePolicyScope,
      ed25519Key: {
        relayerKeyId: 'ed25519-relayer-key',
        keyVersion: 'threshold-ed25519-hss-v1',
        participantIds: [1, 2],
      },
      signingGrantId: expect.any(String),
      ecdsaThresholdSessionId: 'ecdsa-session',
      emailOtpAuthContext: {
        policy: 'session',
        retention: 'session',
        reason: 'login',
        authMethod: 'email_otp',
      },
    });
    expect(ecdsaCommitCalls[0].emailOtpAuthContext).toMatchObject({
      policy: 'per_operation',
      retention: 'session',
      reason: 'login',
      authMethod: 'email_otp',
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
      routeAuth: { kind: 'app_session', jwt: appSessionJwt() },
      participantIds: [1, 3],
      sessionKind: 'jwt',
      ecdsaBootstrapAuthorization: { kind: 'route_plan_auth' },
      runtimePolicyScope,
      ed25519ReconstructionMode: 'await',
      ed25519SessionReconstruction: {
        kind: 'defer',
        reason: 'missing_runtime_policy_scope',
        ed25519Key: {
          relayerKeyId: 'ed25519-relayer-key',
          keyVersion: 'threshold-ed25519-hss-v1',
          participantIds: [1, 2],
        },
      },
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
      appSessionJwt: jwt,
      routeAuth: { kind: 'app_session', jwt },
      clientSecret32: new Uint8Array(32).fill(7),
      registrationAttemptId: 'registration-attempt-1',
    });

    expect(result.enrollment.thresholdEcdsaClientVerifyingShareB64u).toBe('verifying-share');
    expect(ecdsaCommitCalls).toHaveLength(2);
    expect(ecdsaCommitCalls.map((call) => call.primaryChain.kind).sort()).toEqual([
      'evm',
      'tempo',
    ]);
  });
});
