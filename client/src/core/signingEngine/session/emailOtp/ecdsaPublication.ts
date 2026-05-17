import type { AccountId } from '@/core/types/accountIds';
import type { SeamsConfigsReadonly } from '@/core/types/seams';
import {
  thresholdEcdsaChainTargetKey,
  thresholdEcdsaChainTargetsEqual,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdEcdsaEmailOtpAuthContext } from '@/core/signingEngine/session/identity/laneIdentity';
import {
  readExactSealedSession,
  type BuildCurrentSealedSessionRecordInput,
  type BuildCurrentSealedSessionRecordBaseInput,
} from '@/core/signingEngine/session/persistence/sealedSessionStore';
import type { ThresholdEcdsaSessionBootstrapResult } from '@/core/signingEngine/threshold/ecdsa/activation';
import type { WarmSessionEcdsaCapabilityState } from '@/core/signingEngine/session/warmCapabilities/types';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import { configuredEmailOtpEcdsaSnapshotChainTargets } from './persistedSnapshot';
import { ecdsaBootstrapWithWalletSigningSessionId } from './routePlan';
import { requestSealEmailOtpWarmSessionMaterial } from './workerRequests';

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
    walletId: AccountId;
    primaryChain: ThresholdEcdsaChainTarget;
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
  primaryChain: ThresholdEcdsaChainTarget;
  emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
}): ThresholdEcdsaChainTarget[] {
  const targets: ThresholdEcdsaChainTarget[] = [];
  const seen = new Set<string>();
  const pushTarget = (target: ThresholdEcdsaChainTarget): void => {
    const key = thresholdEcdsaChainTargetKey(target);
    if (seen.has(key)) return;
    seen.add(key);
    targets.push(target);
  };
  pushTarget(args.primaryChain);
  if (
    args.emailOtpAuthContext.retention === 'session' &&
    args.emailOtpAuthContext.reason === 'login'
  ) {
    for (const target of configuredEmailOtpEcdsaSnapshotChainTargets(args.configs)) {
      pushTarget(target);
    }
  }
  return targets;
}

export async function commitEmailOtpEcdsaPublicationBootstraps(
  args: {
    walletId: AccountId;
    publicationChainTargets: ThresholdEcdsaChainTarget[];
    bootstraps: ThresholdEcdsaSessionBootstrapResult[];
    walletSigningSessionId: string;
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
  let primaryResult:
    | {
        bootstrap: ThresholdEcdsaSessionBootstrapResult;
        warmCapability: WarmSessionEcdsaCapabilityState;
      }
    | null = null;
  for (const [index, rawBootstrap] of args.bootstraps.entries()) {
    const expectedTarget = args.publicationChainTargets[index];
    const actualTarget = rawBootstrap.thresholdEcdsaKeyRef.chainTarget;
    if (!thresholdEcdsaChainTargetsEqual(actualTarget, expectedTarget)) {
      throw new Error(
        `Email OTP ECDSA publication returned ${thresholdEcdsaChainTargetKey(actualTarget)} for ${thresholdEcdsaChainTargetKey(expectedTarget)}`,
      );
    }
    const workerBootstrap = ecdsaBootstrapWithWalletSigningSessionId({
      bootstrap: rawBootstrap,
      walletSigningSessionId: args.walletSigningSessionId,
    });
    const result = await ports.commitEvmFamilyThresholdEcdsaSessions({
      walletId: args.walletId,
      primaryChain: expectedTarget,
      bootstrap: workerBootstrap,
      source: 'email_otp',
      emailOtpAuthContext: args.emailOtpAuthContext,
    });
    await persistEmailOtpEcdsaSigningSessionSealForUnlock(
      {
        walletId: args.walletId,
        primaryChain: expectedTarget,
        bootstrap: result.bootstrap,
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
    walletId: AccountId | string;
    primaryChain: ThresholdEcdsaChainTarget;
    bootstrap: ThresholdEcdsaSessionBootstrapResult;
    emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
    relayerUrl: string;
    shamirPrimeB64u: string;
  },
  ports: EmailOtpEcdsaPublicationPorts,
): Promise<void> {
  if (ports.configs.signing.sessionPersistenceMode !== 'sealed_refresh_v1') return;
  if (args.emailOtpAuthContext.retention !== 'session') return;

  const workerCtx = ports.getSignerWorkerContext();
  if (!workerCtx) {
    throw new Error('Email OTP sealed refresh requires the dedicated emailOtp worker');
  }

  const keyRef = args.bootstrap.thresholdEcdsaKeyRef;
  const session = args.bootstrap.session;
  const thresholdSessionId = String(session?.sessionId || keyRef.thresholdSessionId || '').trim();
  const walletSigningSessionId = String(
    session?.walletSigningSessionId || keyRef.walletSigningSessionId || '',
  ).trim();
  const relayerUrl = String(args.relayerUrl || keyRef.relayerUrl || '').trim();
  const shamirPrimeB64u = String(
    args.shamirPrimeB64u || ports.configs.signing.sessionSeal?.shamirPrimeB64u || '',
  ).trim();
  if (!thresholdSessionId || !walletSigningSessionId || !relayerUrl || !shamirPrimeB64u) {
    throw new Error('Email OTP sealed refresh is missing threshold-session persistence metadata');
  }

  const thresholdSessionAuthToken = String(
    session?.jwt || keyRef.thresholdSessionAuthToken || '',
  ).trim();
  const keyVersion = String(ports.configs.signing.sessionSeal?.keyVersion || '').trim();
  const sessionKind = keyRef.thresholdSessionKind || (thresholdSessionAuthToken ? 'jwt' : 'cookie');
  const rpId = String(args.bootstrap.keygen.rpId || '').trim();
  const ecdsaThresholdKeyId = String(keyRef.ecdsaThresholdKeyId || '').trim();
  const ethereumAddress = normalizeEthereumAddress(keyRef.ethereumAddress);
  const thresholdEcdsaPublicKeyB64u = String(keyRef.thresholdEcdsaPublicKeyB64u || '').trim();
  const relayerKeyId = String(keyRef.backendBinding?.relayerKeyId || '').trim();
  const participantIds = Array.isArray(keyRef.participantIds)
    ? keyRef.participantIds
        .map((participantId) => Math.floor(Number(participantId)))
        .filter((participantId) => Number.isFinite(participantId) && participantId > 0)
    : [];
  if (
    !ecdsaThresholdKeyId ||
    !rpId ||
    !ethereumAddress ||
    !relayerKeyId ||
    !participantIds.length ||
    (sessionKind === 'jwt' && !thresholdSessionAuthToken)
  ) {
    throw new Error('Email OTP sealed refresh is missing ECDSA restore metadata');
  }

  const sealed = await requestSealEmailOtpWarmSessionMaterial({
    workerCtx,
    sessionId: thresholdSessionId,
    transport: {
      relayerUrl,
      ...(thresholdSessionAuthToken ? { thresholdSessionAuthToken } : {}),
      ...(keyVersion ? { keyVersion } : {}),
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

  const sealedRecordBase = {
    thresholdSessionId,
    sealedSecretB64u,
    curve: 'ecdsa' as const,
    authMethod: 'email_otp' as const,
    walletSigningSessionId,
    thresholdSessionIds: { ecdsa: thresholdSessionId },
    subjectId: String(keyRef.subjectId || '').trim(),
    walletId: String(args.walletId || '').trim(),
    userId: String(keyRef.userId || args.walletId || '').trim(),
    signingRootId: String(keyRef.signingRootId || '').trim(),
    ...(String(keyRef.signingRootVersion || '').trim()
      ? { signingRootVersion: String(keyRef.signingRootVersion || '').trim() }
      : {}),
    relayerUrl,
    ...(String(sealed.keyVersion || keyVersion).trim()
      ? { keyVersion: String(sealed.keyVersion || keyVersion).trim() }
      : {}),
    shamirPrimeB64u,
    expiresAtMs,
    remainingUses,
  };
  const actualChainTarget = keyRef.chainTarget as ThresholdEcdsaChainTarget | undefined;
  if (!actualChainTarget) {
    throw new Error('Email OTP sealed refresh requires exact ECDSA chain target');
  }
  if (!thresholdEcdsaChainTargetsEqual(actualChainTarget, args.primaryChain)) {
    throw new Error(
      `Email OTP sealed refresh chain target drifted from ${thresholdEcdsaChainTargetKey(args.primaryChain)} to ${thresholdEcdsaChainTargetKey(actualChainTarget)}`,
    );
  }
  const updatedAtMs = Date.now();
  await ports.registerSigningSession({
    ...sealedRecordBase,
    ecdsaRestore: {
      chainTarget: actualChainTarget,
      rpId,
      ...(thresholdSessionAuthToken ? { thresholdSessionAuthToken } : {}),
      sessionKind,
      ecdsaThresholdKeyId,
      ethereumAddress,
      relayerKeyId,
      ...(thresholdEcdsaPublicKeyB64u ? { thresholdEcdsaPublicKeyB64u } : {}),
      participantIds,
    },
    updatedAtMs,
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
    persisted.walletSigningSessionId !== walletSigningSessionId ||
    persisted.sealedSecretB64u !== sealedSecretB64u ||
    !persisted.ecdsaRestore?.chainTarget ||
    !thresholdEcdsaChainTargetsEqual(persisted.ecdsaRestore.chainTarget, actualChainTarget)
  ) {
    throw new Error(
      `Email OTP sealed refresh read-back record does not match ${thresholdEcdsaChainTargetKey(actualChainTarget)} unlock session`,
    );
  }
}
