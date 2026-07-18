import type { SeamsConfigsReadonly } from '@/core/types/seams';
import {
  thresholdEcdsaChainTargetKey,
  thresholdEcdsaChainTargetsEqual,
  type ThresholdEcdsaChainTarget,
  type WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  emailOtpAuthContextEmailHashHex,
  emailOtpAuthContextProvider,
  emailOtpAuthContextProviderUserId,
  emailOtpAuthContextRetention,
  type ThresholdEcdsaEmailOtpAuthContext,
} from '@/core/signingEngine/session/identity/laneIdentity';
import {
  readExactSealedSession,
  type BuildCurrentSealedSessionRecordInput,
} from '@/core/signingEngine/session/persistence/sealedSessionStore';
import type { ThresholdEcdsaSessionBootstrapResult } from '@/core/signingEngine/threshold/ecdsa/activation';
import {
  type ThresholdRuntimePolicyScope,
} from '@/core/signingEngine/threshold/sessionPolicy';
import type { EmailOtpEcdsaPublicationTargetPlan } from '@/core/signingEngine/workerManager/workerTypes';
import type { WarmSessionEcdsaCapabilityState } from '@/core/signingEngine/session/warmCapabilities/types';
import type { EmailOtpEcdsaReadyPersistInput } from '@/core/signingEngine/session/warmCapabilities/persistencePorts';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import { SigningSessionIds } from '../operationState/types';
import { configuredEmailOtpEcdsaSnapshotChainTargets } from './persistedSnapshot';
import { ecdsaBootstrapWithSigningGrantId } from './routePlan';
import { requestSealEmailOtpWarmSessionMaterial } from './workerRequests';
import { formatSigningSessionSealKeyVersionForWire } from '../keyMaterialBrands';
import { signingRootScopeFromRuntimePolicyScope } from '@shared/threshold/signingRootScope';
import { deriveEvmFamilySigningKeySlotIdFromRuntimePolicyScope } from '../identity/evmFamilyEcdsaIdentity';

export type EmailOtpEcdsaPublicationTimingBucket =
  | 'signingSessionSealApplyMs'
  | 'warmCapabilityPersistenceMs';

export type EmailOtpEcdsaPublicationTimings = Record<EmailOtpEcdsaPublicationTimingBucket, number>;

function nowMs(): number {
  return typeof performance !== 'undefined' && typeof performance.now === 'function'
    ? performance.now()
    : Date.now();
}

function createEmailOtpEcdsaPublicationTimings(): EmailOtpEcdsaPublicationTimings {
  return {
    signingSessionSealApplyMs: 0,
    warmCapabilityPersistenceMs: 0,
  };
}

function addEmailOtpEcdsaPublicationTiming(
  timings: EmailOtpEcdsaPublicationTimings,
  bucket: EmailOtpEcdsaPublicationTimingBucket,
  startedAtMs: number,
): void {
  timings[bucket] += Math.max(0, Math.round(nowMs() - startedAtMs));
}

function mergeEmailOtpEcdsaPublicationTimings(
  target: EmailOtpEcdsaPublicationTimings,
  source: EmailOtpEcdsaPublicationTimings,
): void {
  target.signingSessionSealApplyMs += source.signingSessionSealApplyMs;
  target.warmCapabilityPersistenceMs += source.warmCapabilityPersistenceMs;
}

function normalizeEthereumAddress(value: unknown): `0x${string}` | null {
  const normalized = String(value || '')
    .trim()
    .toLowerCase();
  return /^0x[0-9a-f]{40}$/.test(normalized) ? (normalized as `0x${string}`) : null;
}

export type EmailOtpEcdsaPublicationPorts = {
  configs: SeamsConfigsReadonly;
  getSignerWorkerContext: () => WorkerOperationContext | null | undefined;
  commitEvmFamilyThresholdEcdsaSessions: (args: {
    walletId: WalletId;
    chainTarget: ThresholdEcdsaChainTarget;
    bootstrap: ThresholdEcdsaSessionBootstrapResult;
    source: 'email_otp';
    emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
  }) => Promise<{
    bootstrap: ThresholdEcdsaSessionBootstrapResult;
    warmCapability: WarmSessionEcdsaCapabilityState;
  }>;
  registerSigningSession: (
    record: Extract<BuildCurrentSealedSessionRecordInput, { curve: 'ecdsa' }>,
  ) => Promise<void>;
  readExactSealedSession: typeof readExactSealedSession;
};

export function emailOtpEcdsaPublicationChainTargets(args: {
  configs: SeamsConfigsReadonly;
  chainTarget: ThresholdEcdsaChainTarget;
  emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
  additionalChainTargets?: readonly ThresholdEcdsaChainTarget[];
}): ThresholdEcdsaChainTarget[] {
  const targets: ThresholdEcdsaChainTarget[] = [];
  const seen = new Set<string>();
  const pushTarget = (target: ThresholdEcdsaChainTarget): void => {
    const key = thresholdEcdsaChainTargetKey(target);
    if (seen.has(key)) return;
    seen.add(key);
    targets.push(target);
  };
  pushTarget(args.chainTarget);
  const hasExplicitAdditionalTargets = args.additionalChainTargets !== undefined;
  for (const target of args.additionalChainTargets || []) {
    pushTarget(target);
  }
  if (
    !hasExplicitAdditionalTargets &&
    emailOtpAuthContextRetention(args.emailOtpAuthContext) === 'session'
  ) {
    for (const target of configuredEmailOtpEcdsaSnapshotChainTargets(args.configs)) {
      pushTarget(target);
    }
  }
  return targets;
}

export function emailOtpEcdsaPublicationTargetPlans(args: {
  walletId: WalletId;
  runtimePolicyScope: ThresholdRuntimePolicyScope;
  chainTarget: ThresholdEcdsaChainTarget;
  publicationChainTargets: readonly ThresholdEcdsaChainTarget[];
  keyHandle?: string;
}): EmailOtpEcdsaPublicationTargetPlan[] {
  const primaryKeyHandle = String(args.keyHandle || '').trim();
  return args.publicationChainTargets.map((publicationChainTarget) => {
    const base = {
      chainTarget: publicationChainTarget,
      evmFamilySigningKeySlotId: String(
        deriveEvmFamilySigningKeySlotIdFromRuntimePolicyScope({
          walletId: args.walletId,
          runtimePolicyScope: args.runtimePolicyScope,
        }),
      ),
    };
    if (primaryKeyHandle && thresholdEcdsaChainTargetsEqual(publicationChainTarget, args.chainTarget)) {
      return {
        ...base,
        kind: 'existing_key_publication_target',
        keyHandle: primaryKeyHandle,
      };
    }
    return {
      ...base,
      kind: 'new_key_publication_target',
    };
  });
}

export function buildEmailOtpEcdsaReadyPersistInput(args: {
  walletId: WalletId;
  chainTarget: ThresholdEcdsaChainTarget;
  signingGrantId: string;
  thresholdSessionId: string;
  emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
}): EmailOtpEcdsaReadyPersistInput {
  return {
    authMethod: 'email_otp',
    curve: 'ecdsa',
    walletId: args.walletId,
    chainTarget: args.chainTarget,
    signingGrantId: SigningSessionIds.signingGrant(args.signingGrantId),
    thresholdSessionId: SigningSessionIds.thresholdEcdsaSession(args.thresholdSessionId),
    emailOtpAuthContext: args.emailOtpAuthContext,
    material: {
      kind: 'worker_handle',
      workerSessionId: args.thresholdSessionId,
    },
  };
}

export async function commitEmailOtpEcdsaPublicationBootstraps(
  args: {
    walletId: WalletId;
    publicationChainTargets: ThresholdEcdsaChainTarget[];
    bootstraps: ThresholdEcdsaSessionBootstrapResult[];
    signingGrantId: string;
    runtimePolicyScope: ThresholdRuntimePolicyScope;
    emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
    relayerUrl: string;
    shamirPrimeB64u: string;
  },
  ports: EmailOtpEcdsaPublicationPorts,
): Promise<{
  bootstrap: ThresholdEcdsaSessionBootstrapResult;
  warmCapability: WarmSessionEcdsaCapabilityState;
  warmCapabilities: readonly [
    WarmSessionEcdsaCapabilityState,
    ...WarmSessionEcdsaCapabilityState[],
  ];
  timings: EmailOtpEcdsaPublicationTimings;
}> {
  if (args.bootstraps.length !== args.publicationChainTargets.length) {
    throw new Error('Email OTP ECDSA publication returned an unexpected lane count');
  }
  const timings = createEmailOtpEcdsaPublicationTimings();
  const committedResults: {
    bootstrap: ThresholdEcdsaSessionBootstrapResult;
    warmCapability: WarmSessionEcdsaCapabilityState;
  }[] = [];
  for (const [index, rawBootstrap] of args.bootstraps.entries()) {
    const expectedTarget = args.publicationChainTargets[index];
    const actualTarget = rawBootstrap.thresholdEcdsaKeyRef.chainTarget;
    if (!thresholdEcdsaChainTargetsEqual(actualTarget, expectedTarget)) {
      throw new Error(
        `Email OTP ECDSA publication returned ${thresholdEcdsaChainTargetKey(actualTarget)} for ${thresholdEcdsaChainTargetKey(expectedTarget)}`,
      );
    }
    const workerBootstrap = ecdsaBootstrapWithSigningGrantId({
      bootstrap: rawBootstrap,
      signingGrantId: args.signingGrantId,
    });
    const commitStartedAtMs = nowMs();
    const result = await ports.commitEvmFamilyThresholdEcdsaSessions({
      walletId: args.walletId,
      chainTarget: expectedTarget,
      bootstrap: workerBootstrap,
      source: 'email_otp',
      emailOtpAuthContext: args.emailOtpAuthContext,
    });
    addEmailOtpEcdsaPublicationTiming(timings, 'warmCapabilityPersistenceMs', commitStartedAtMs);
    const sealTimings = await persistEmailOtpEcdsaSigningSessionForRefresh(
      {
        walletId: args.walletId,
        chainTarget: expectedTarget,
        bootstrap: result.bootstrap,
        runtimePolicyScope: args.runtimePolicyScope,
        emailOtpAuthContext: args.emailOtpAuthContext,
        relayerUrl: args.relayerUrl,
        shamirPrimeB64u: args.shamirPrimeB64u,
      },
      ports,
    );
    mergeEmailOtpEcdsaPublicationTimings(timings, sealTimings);
    committedResults.push(result);
  }
  const [primaryResult, ...remainingResults] = committedResults;
  if (!primaryResult) {
    throw new Error('Email OTP ECDSA publication did not commit a primary lane');
  }
  return {
    bootstrap: primaryResult.bootstrap,
    warmCapability: primaryResult.warmCapability,
    warmCapabilities: [
      primaryResult.warmCapability,
      ...remainingResults.map((result) => result.warmCapability),
    ],
    timings,
  };
}

export async function persistEmailOtpEcdsaSigningSessionForRefresh(
  args: {
    walletId: WalletId;
    chainTarget: ThresholdEcdsaChainTarget;
    bootstrap: ThresholdEcdsaSessionBootstrapResult;
    runtimePolicyScope: ThresholdRuntimePolicyScope;
    emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
    relayerUrl: string;
    shamirPrimeB64u: string;
  },
  ports: EmailOtpEcdsaPublicationPorts,
): Promise<EmailOtpEcdsaPublicationTimings> {
  const timings = createEmailOtpEcdsaPublicationTimings();
  if (ports.configs.signing.sessionPersistenceMode !== 'sealed_refresh_v1') return timings;
  if (emailOtpAuthContextRetention(args.emailOtpAuthContext) !== 'session') return timings;

  const workerCtx = ports.getSignerWorkerContext();
  if (!workerCtx) {
    throw new Error('Email OTP sealed refresh requires the dedicated emailOtp worker');
  }

  const keyRef = args.bootstrap.thresholdEcdsaKeyRef;
  const session = args.bootstrap.session;
  const thresholdSessionId = String(
    session?.thresholdSessionId || keyRef.thresholdSessionId || '',
  ).trim();
  const signingGrantId = String(
    session?.signingGrantId || keyRef.signingGrantId || '',
  ).trim();
  const relayerUrl = String(args.relayerUrl || keyRef.relayerUrl || '').trim();
  const shamirPrimeB64u = String(
    args.shamirPrimeB64u || ports.configs.signing.sessionSeal?.shamirPrimeB64u || '',
  ).trim();
  if (!thresholdSessionId || !signingGrantId || !relayerUrl || !shamirPrimeB64u) {
    throw new Error('Email OTP sealed refresh is missing threshold-session persistence metadata');
  }
  const readyPersistenceInput = buildEmailOtpEcdsaReadyPersistInput({
    walletId: args.walletId,
    chainTarget: args.chainTarget,
    signingGrantId,
    thresholdSessionId,
    emailOtpAuthContext: args.emailOtpAuthContext,
  });

  const walletSessionJwt = String(session?.jwt || '').trim();
  const runtimePolicyScope = args.runtimePolicyScope;
  const signingRootScope = signingRootScopeFromRuntimePolicyScope(runtimePolicyScope);
  const signingRootId = String(signingRootScope?.signingRootId || '').trim();
  const signingRootVersion = String(signingRootScope?.signingRootVersion || '').trim();
  const keyVersion = ports.configs.signing.sessionSeal?.signingSessionSealKeyVersion
    ? formatSigningSessionSealKeyVersionForWire(
        ports.configs.signing.sessionSeal.signingSessionSealKeyVersion,
      )
    : '';
  const evmFamilySigningKeySlotId = String(
    args.bootstrap.keygen.evmFamilySigningKeySlotId || '',
  ).trim();
  const ecdsaThresholdKeyId = String(keyRef.ecdsaThresholdKeyId || '').trim();
  const userId = String(keyRef.userId || '').trim();
  const providerSubjectId = String(
    emailOtpAuthContextProviderUserId(args.emailOtpAuthContext) || userId,
  ).trim();
  const emailHashHex = String(
    emailOtpAuthContextEmailHashHex(args.emailOtpAuthContext),
  ).trim();
  const ethereumAddress = normalizeEthereumAddress(keyRef.ethereumAddress);
  const clientVerifyingShareB64u = String(
    keyRef.backendBinding?.clientVerifyingShareB64u || '',
  ).trim();
  const thresholdEcdsaPublicKeyB64u = String(keyRef.thresholdEcdsaPublicKeyB64u || '').trim();
  const relayerKeyId = String(keyRef.backendBinding?.relayerKeyId || '').trim();
  const routerAbEcdsaDerivationNormalSigning = keyRef.routerAbEcdsaDerivationNormalSigning;
  const publicCapability = keyRef.backendBinding?.ecdsaRoleLocalReadyRecord?.publicFacts.publicCapability;
  const participantIds = Array.isArray(keyRef.participantIds)
    ? keyRef.participantIds
        .map((participantId) => Math.floor(Number(participantId)))
        .filter((participantId) => Number.isFinite(participantId) && participantId > 0)
    : [];
  if (
    !ecdsaThresholdKeyId ||
    !evmFamilySigningKeySlotId ||
    !userId ||
    !providerSubjectId ||
    !emailHashHex ||
    !ethereumAddress ||
    !clientVerifyingShareB64u ||
    !relayerKeyId ||
    !routerAbEcdsaDerivationNormalSigning ||
    !publicCapability ||
    !participantIds.length ||
    !walletSessionJwt ||
    !signingRootId ||
    !signingRootVersion
  ) {
    throw new Error('Email OTP sealed refresh is missing ECDSA restore metadata');
  }
  if (readyPersistenceInput.material.kind !== 'worker_handle') {
    throw new Error('Email OTP sealed refresh requires worker-owned warm material');
  }
  const emailOtpWorkerSessionId = readyPersistenceInput.material.workerSessionId;

  const sealStartedAtMs = nowMs();
  const sealed = await requestSealEmailOtpWarmSessionMaterial({
    workerCtx,
    sessionId: emailOtpWorkerSessionId,
    transport: {
      relayerUrl,
      ...(walletSessionJwt ? { walletSessionJwt } : {}),
      ...(ports.configs.signing.sessionSeal?.signingSessionSealKeyVersion
        ? {
            signingSessionSealKeyVersion:
              ports.configs.signing.sessionSeal.signingSessionSealKeyVersion,
          }
        : {}),
      shamirPrimeB64u,
    },
  }).catch((error) => {
    const message = error instanceof Error ? error.message : String(error || 'unknown error');
    throw new Error(`Email OTP sealed refresh seal failed: ${message}`);
  });
  addEmailOtpEcdsaPublicationTiming(timings, 'signingSessionSealApplyMs', sealStartedAtMs);

  if (!sealed?.ok) {
    const message = String(sealed?.message || sealed?.code || 'unknown error').trim();
    throw new Error(`Email OTP sealed refresh seal failed: ${message}`);
  }
  const sealedSecretB64u = String(sealed.sealedSecretB64u || '').trim();
  const expiresAtMs = Math.floor(Number(sealed.expiresAtMs) || Number(session?.expiresAtMs) || 0);
  const remainingUses = Math.floor(
    Number(sealed.remainingUses) || Number(session?.remainingUses) || 0,
  );
  if (!sealedSecretB64u || expiresAtMs <= 0 || remainingUses < 0) {
    throw new Error('Email OTP sealed refresh seal returned invalid persistence metadata');
  }
  const persistedAtMs = Date.now();

  const sealedRecordBase = {
    thresholdSessionId: readyPersistenceInput.thresholdSessionId,
    sealedSecretB64u,
    curve: 'ecdsa' as const,
    authMethod: 'email_otp' as const,
    signingGrantId: readyPersistenceInput.signingGrantId,
    thresholdSessionIds: { ecdsa: readyPersistenceInput.thresholdSessionId },
    walletId: String(args.walletId || '').trim(),
    relayerUrl,
    ...(String(sealed.keyVersion || keyVersion).trim()
      ? { keyVersion: String(sealed.keyVersion || keyVersion).trim() }
      : {}),
    shamirPrimeB64u,
    issuedAtMs: persistedAtMs,
    expiresAtMs,
    remainingUses,
  };
  const actualChainTarget = keyRef.chainTarget as ThresholdEcdsaChainTarget | undefined;
  if (!actualChainTarget) {
    throw new Error('Email OTP sealed refresh requires exact ECDSA chain target');
  }
  if (!thresholdEcdsaChainTargetsEqual(actualChainTarget, readyPersistenceInput.chainTarget)) {
    throw new Error(
      `Email OTP sealed refresh chain target drifted from ${thresholdEcdsaChainTargetKey(readyPersistenceInput.chainTarget)} to ${thresholdEcdsaChainTargetKey(actualChainTarget)}`,
    );
  }
  const keyHandle = String(keyRef.keyHandle || '').trim();
  if (!keyHandle) {
    throw new Error('Email OTP sealed refresh requires exact ECDSA key handle');
  }
  const persistenceStartedAtMs = nowMs();
  await ports.registerSigningSession({
    ...sealedRecordBase,
    ecdsaRestore: {
      chainTarget: actualChainTarget,
      source: 'email_otp',
      evmFamilySigningKeySlotId,
      signingRootId,
      signingRootVersion,
      provider: emailOtpAuthContextProvider(args.emailOtpAuthContext),
      providerSubjectId,
      emailHashHex,
      walletSessionJwt,
      sessionKind: 'jwt',
      ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
      keyHandle,
      ecdsaThresholdKeyId,
      ethereumAddress,
      relayerKeyId,
      clientVerifyingShareB64u,
      ...(thresholdEcdsaPublicKeyB64u ? { thresholdEcdsaPublicKeyB64u } : {}),
      participantIds,
      routerAbEcdsaDerivationNormalSigning,
      publicCapability,
    },
    updatedAtMs: persistedAtMs,
  });

  const persisted = await ports
    .readExactSealedSession(thresholdSessionId, {
      authMethod: 'email_otp',
      curve: 'ecdsa',
      chainTarget: actualChainTarget,
    })
    .catch((error) => {
      const message = error instanceof Error ? error.message : String(error || 'unknown error');
      throw new Error(`Email OTP sealed refresh read-back failed: ${message}`);
    });
  addEmailOtpEcdsaPublicationTiming(timings, 'warmCapabilityPersistenceMs', persistenceStartedAtMs);
  if (!persisted) {
    throw new Error(
      `Email OTP sealed refresh ${thresholdEcdsaChainTargetKey(actualChainTarget)} record was not durably persisted`,
    );
  }
  if (
    persisted.authMethod !== 'email_otp' ||
    persisted.secretKind !== 'signing_session_secret32' ||
    persisted.thresholdSessionIds.ecdsa !== thresholdSessionId ||
    persisted.signingGrantId !== signingGrantId ||
    persisted.sealedSecretB64u !== sealedSecretB64u ||
    !persisted.ecdsaRestore?.chainTarget ||
    !thresholdEcdsaChainTargetsEqual(persisted.ecdsaRestore.chainTarget, actualChainTarget)
  ) {
    throw new Error(
      `Email OTP sealed refresh read-back record does not match ${thresholdEcdsaChainTargetKey(actualChainTarget)} unlock session`,
    );
  }
  return timings;
}
