import type { SeamsConfigsReadonly } from '@/core/types/seams';
import {
  thresholdEcdsaChainTargetKey,
  thresholdEcdsaChainTargetsEqual,
  type ThresholdEcdsaChainTarget,
  type WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  emailOtpAuthContextEmailHashHex,
  emailOtpAuthContextProviderUserId,
  emailOtpAuthContextReason,
  emailOtpAuthContextRetention,
  type ThresholdEcdsaEmailOtpAuthContext,
} from '@/core/signingEngine/session/identity/laneIdentity';
import {
  readExactSealedSession,
  type BuildCurrentSealedSessionRecordInput,
} from '@/core/signingEngine/session/persistence/sealedSessionStore';
import type { ThresholdEcdsaSessionBootstrapResult } from '@/core/signingEngine/threshold/ecdsa/activation';
import {
  parseThresholdRuntimePolicyScopeFromJwt,
  type ThresholdRuntimePolicyScope,
} from '@/core/signingEngine/threshold/sessionPolicy';
import type { WarmSessionEcdsaCapabilityState } from '@/core/signingEngine/session/warmCapabilities/types';
import type { EmailOtpEcdsaReadyPersistInput } from '@/core/signingEngine/session/warmCapabilities/persistencePorts';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import { SigningSessionIds } from '../operationState/types';
import { configuredEmailOtpEcdsaSnapshotChainTargets } from './persistedSnapshot';
import { ecdsaBootstrapWithSigningGrantId } from './routePlan';
import { requestSealEmailOtpWarmSessionMaterial } from './workerRequests';
import { formatSigningSessionSealKeyVersionForWire } from '../keyMaterialBrands';

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
  for (const target of args.additionalChainTargets || []) {
    pushTarget(target);
  }
  if (emailOtpAuthContextReason(args.emailOtpAuthContext) === 'login') {
    for (const target of configuredEmailOtpEcdsaSnapshotChainTargets(args.configs)) {
      pushTarget(target);
    }
  }
  return targets;
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
    emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
    relayerUrl: string;
    shamirPrimeB64u: string;
  },
  ports: EmailOtpEcdsaPublicationPorts,
): Promise<{
  bootstrap: ThresholdEcdsaSessionBootstrapResult;
  warmCapability: WarmSessionEcdsaCapabilityState;
}> {
  if (args.bootstraps.length !== args.publicationChainTargets.length) {
    throw new Error('Email OTP ECDSA publication returned an unexpected lane count');
  }
  let primaryResult: {
    bootstrap: ThresholdEcdsaSessionBootstrapResult;
    warmCapability: WarmSessionEcdsaCapabilityState;
  } | null = null;
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
    const result = await ports.commitEvmFamilyThresholdEcdsaSessions({
      walletId: args.walletId,
      chainTarget: expectedTarget,
      bootstrap: workerBootstrap,
      source: 'email_otp',
      emailOtpAuthContext: args.emailOtpAuthContext,
    });
    await persistEmailOtpEcdsaSigningSessionSealForUnlock(
      {
        walletId: args.walletId,
        chainTarget: expectedTarget,
        bootstrap: result.bootstrap,
        runtimePolicyScope: result.warmCapability.record?.runtimePolicyScope,
        emailOtpAuthContext: args.emailOtpAuthContext,
        relayerUrl: args.relayerUrl,
        shamirPrimeB64u: args.shamirPrimeB64u,
      },
      ports,
    );
    if (index === 0) primaryResult = result;
  }
  if (!primaryResult) {
    throw new Error('Email OTP ECDSA publication did not commit a primary lane');
  }
  return primaryResult;
}

async function persistEmailOtpEcdsaSigningSessionSealForUnlock(
  args: {
    walletId: WalletId;
    chainTarget: ThresholdEcdsaChainTarget;
    bootstrap: ThresholdEcdsaSessionBootstrapResult;
    runtimePolicyScope?: ThresholdRuntimePolicyScope;
    emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
    relayerUrl: string;
    shamirPrimeB64u: string;
  },
  ports: EmailOtpEcdsaPublicationPorts,
): Promise<void> {
  if (ports.configs.signing.sessionPersistenceMode !== 'sealed_refresh_v1') return;
  if (emailOtpAuthContextRetention(args.emailOtpAuthContext) !== 'session') return;

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
  const runtimePolicyScope =
    args.runtimePolicyScope || parseThresholdRuntimePolicyScopeFromJwt(walletSessionJwt);
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
  const routerAbEcdsaHssNormalSigning = keyRef.routerAbEcdsaHssNormalSigning;
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
    !routerAbEcdsaHssNormalSigning ||
    !participantIds.length ||
    !walletSessionJwt
  ) {
    throw new Error('Email OTP sealed refresh is missing ECDSA restore metadata');
  }
  if (readyPersistenceInput.material.kind !== 'worker_handle') {
    throw new Error('Email OTP sealed refresh requires worker-owned warm material');
  }
  const emailOtpWorkerSessionId = readyPersistenceInput.material.workerSessionId;

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
  await ports.registerSigningSession({
    ...sealedRecordBase,
    ecdsaRestore: {
      chainTarget: actualChainTarget,
      source: 'email_otp',
      evmFamilySigningKeySlotId,
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
      routerAbEcdsaHssNormalSigning,
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
}
