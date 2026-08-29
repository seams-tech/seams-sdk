import type { SeamsConfigsReadonly } from '@/core/types/seams';
import {
  walletAuthAuthorityRef,
  type WalletAuthAuthorityRef,
} from '@shared/utils/walletAuthAuthority';
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
import { type ThresholdRuntimePolicyScope } from '@/core/signingEngine/threshold/sessionPolicy';
import type { RouterAbEcdsaDerivationPublicCapabilityV1 } from '@shared/utils/routerAbEcdsaDerivation';
import type { ExactWalletSessionAuthorization } from '../persistence/walletSessionAuthorizationProjection';
import type { EmailOtpEcdsaReadyPersistInput } from '@/core/signingEngine/session/warmCapabilities/persistencePorts';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import { SigningSessionIds } from '../operationState/types';
import { configuredEmailOtpEcdsaSnapshotChainTargets } from './persistedSnapshot';
import { requestSealEmailOtpWarmSessionMaterial } from './workerRequests';
import { SIGNING_SESSION_SEAL_GROUP_ID } from '@shared/utils/signingSessionSeal';
import { signingRootScopeFromRuntimePolicyScope } from '@shared/threshold/signingRootScope';
import {
  buildEvmFamilyEcdsaWalletKey,
  type EvmFamilyEcdsaWalletKey,
} from '../identity/evmFamilyEcdsaIdentity';
import { alphabetizeStringify } from '@shared/utils/digests';
import { mpcMaterialActivationRefsEqual } from '@shared/utils/domainIds';
import { buildEcdsaRoleLocalPublicFacts } from '../persistence/ecdsaRoleLocalRecords';
import {
  buildPersistedEcdsaRoleLocalMaterial,
  type PersistedEcdsaRoleLocalMaterial,
} from '../material/ecdsaRoleLocalMaterialResolver';
import {
  parseEcdsaRoleLocalPersistedMaterialRef,
  type EcdsaRoleLocalPersistedMaterialRef,
} from '../keyMaterialBrands';
import type { ActiveEcdsaCapabilityManifest } from '../material/ecdsaCapabilityManifest';

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
    authority: WalletAuthAuthorityRef;
    emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
  }) => Promise<{
    bootstrap: ThresholdEcdsaSessionBootstrapResult;
    authorization: ExactWalletSessionAuthorization;
  }>;
  registerSigningSession: (
    record: Extract<BuildCurrentSealedSessionRecordInput, { curve: 'ecdsa' }>,
  ) => Promise<void>;
  readExactSealedSession: typeof readExactSealedSession;
  listActiveEcdsaCapabilityManifestsForWallet: (
    walletId: WalletId,
  ) => Promise<readonly ActiveEcdsaCapabilityManifest[]>;
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

type EmailOtpEcdsaPersistedIdentity = {
  signingRootId: string;
  signingRootVersion: string;
};

function resolveEmailOtpEcdsaPersistedIdentity(args: {
  runtimePolicyScope: ThresholdRuntimePolicyScope;
}): EmailOtpEcdsaPersistedIdentity {
  const signingRoot = signingRootScopeFromRuntimePolicyScope(args.runtimePolicyScope);
  const signingRootId = String(signingRoot.signingRootId).trim();
  const signingRootVersion = String(signingRoot.signingRootVersion || 'default').trim();
  if (!signingRootId || !signingRootVersion) {
    throw new Error('Email OTP ECDSA persisted identity is incomplete');
  }
  return {
    signingRootId,
    signingRootVersion,
  };
}

export type ResolvedEmailOtpExistingEcdsaKey = {
  keyHandle: string;
  publicCapability: RouterAbEcdsaDerivationPublicCapabilityV1;
  walletKey: EvmFamilyEcdsaWalletKey;
  persistedRoleLocalMaterial: PersistedEcdsaRoleLocalMaterial;
  runtimePolicyScope: ThresholdRuntimePolicyScope;
};

export type EmailOtpEcdsaScopeSelector =
  | {
      kind: 'exact';
      runtimePolicyScope: ThresholdRuntimePolicyScope;
      authorityRef: WalletAuthAuthorityRef;
    }
  | {
      kind: 'exact_authority';
      authorityRef: WalletAuthAuthorityRef;
      runtimePolicyScope?: never;
    }
  | {
      kind: 'durable_manifest';
      runtimePolicyScope?: never;
      authorityRef?: never;
    };

export function projectEmailOtpExistingEcdsaKeyToChainTarget(args: {
  existingKey: ResolvedEmailOtpExistingEcdsaKey;
  chainTarget: ThresholdEcdsaChainTarget;
}): ResolvedEmailOtpExistingEcdsaKey {
  const sourceFacts = args.existingKey.persistedRoleLocalMaterial.publicFacts;
  const publicFacts = buildEcdsaRoleLocalPublicFacts({
    walletId: sourceFacts.walletId,
    chainTarget: args.chainTarget,
    keyHandle: sourceFacts.keyHandle,
    ecdsaThresholdKeyId: sourceFacts.ecdsaThresholdKeyId,
    signingRootId: sourceFacts.signingRootId,
    signingRootVersion: sourceFacts.signingRootVersion,
    applicationBindingDigestB64u: sourceFacts.applicationBindingDigestB64u,
    clientParticipantId: sourceFacts.clientParticipantId,
    relayerParticipantId: sourceFacts.relayerParticipantId,
    participantIds: sourceFacts.participantIds,
    contextBinding32B64u: sourceFacts.contextBinding32B64u,
    derivationClientSharePublicKey33B64u: sourceFacts.derivationClientSharePublicKey33B64u,
    relayerPublicKey33B64u: sourceFacts.relayerPublicKey33B64u,
    groupPublicKey33B64u: sourceFacts.groupPublicKey33B64u,
    ethereumAddress: sourceFacts.ethereumAddress,
    publicCapability: sourceFacts.publicCapability,
  });
  return {
    keyHandle: args.existingKey.keyHandle,
    publicCapability: publicFacts.publicCapability,
    walletKey: buildEvmFamilyEcdsaWalletKey({
      walletId: publicFacts.walletId,
      keyHandle: publicFacts.keyHandle,
      chainTarget: args.chainTarget,
      ecdsaThresholdKeyId: publicFacts.ecdsaThresholdKeyId,
      signingRootId: publicFacts.signingRootId,
      signingRootVersion: publicFacts.signingRootVersion,
      participantIds: publicFacts.participantIds,
      thresholdOwnerAddress: publicFacts.ethereumAddress,
      thresholdEcdsaPublicKeyB64u: publicFacts.groupPublicKey33B64u,
    }),
    persistedRoleLocalMaterial: buildPersistedEcdsaRoleLocalMaterial({
      authority: args.existingKey.persistedRoleLocalMaterial.authority,
      materialActivation: args.existingKey.persistedRoleLocalMaterial.materialActivation,
      publicFacts,
    }),
    runtimePolicyScope: args.existingKey.runtimePolicyScope,
  };
}

function manifestEmailOtpEcdsaCandidate(
  manifest: ActiveEcdsaCapabilityManifest,
): ResolvedEmailOtpExistingEcdsaKey {
  const publicFacts = manifest.durableMaterial.roleLocalPublicFacts;
  const walletKey = buildEvmFamilyEcdsaWalletKey({
    walletId: publicFacts.walletId,
    keyHandle: publicFacts.keyHandle,
    chainTarget: publicFacts.chainTarget,
    ecdsaThresholdKeyId: publicFacts.ecdsaThresholdKeyId,
    signingRootId: publicFacts.signingRootId,
    signingRootVersion: publicFacts.signingRootVersion,
    participantIds: publicFacts.participantIds,
    thresholdOwnerAddress: publicFacts.ethereumAddress,
    thresholdEcdsaPublicKeyB64u: publicFacts.groupPublicKey33B64u,
  });
  return {
    keyHandle: String(walletKey.keyHandle),
    publicCapability: publicFacts.publicCapability,
    walletKey,
    persistedRoleLocalMaterial: buildPersistedEcdsaRoleLocalMaterial({
      authority: manifest.signer.authority,
      materialActivation: manifest.activation.materialActivation,
      publicFacts,
    }),
    runtimePolicyScope: manifest.durableMaterial.runtimePolicyScope,
  };
}

export async function resolveEmailOtpExistingEcdsaKey(args: {
  walletId: WalletId;
  chainTarget: ThresholdEcdsaChainTarget;
  scope: EmailOtpEcdsaScopeSelector;
  keyHandle?: string;
  listActiveEcdsaCapabilityManifestsForWallet: EmailOtpEcdsaPublicationPorts['listActiveEcdsaCapabilityManifestsForWallet'];
}): Promise<ResolvedEmailOtpExistingEcdsaKey | null> {
  const identity =
    args.scope.kind === 'exact'
      ? resolveEmailOtpEcdsaPersistedIdentity({
          runtimePolicyScope: args.scope.runtimePolicyScope,
        })
      : null;
  const requestedKeyHandle = String(args.keyHandle || '').trim();
  const exactAuthorityRef = args.scope.kind === 'durable_manifest' ? null : args.scope.authorityRef;
  const manifests = await args.listActiveEcdsaCapabilityManifestsForWallet(args.walletId);
  const candidates = manifests
    .filter((manifest) => {
      const publicFacts = manifest.durableMaterial.roleLocalPublicFacts;
      return (
        manifest.signer.walletId === args.walletId &&
        (!exactAuthorityRef ||
          (manifest.signer.authority.walletAuthMethodId === exactAuthorityRef.walletAuthMethodId &&
            String(manifest.signer.authority.authorityDigest) ===
              String(exactAuthorityRef.authorityDigest))) &&
        manifest.signer.scope.targetMemberships.some((membership) =>
          thresholdEcdsaChainTargetsEqual(membership, args.chainTarget),
        ) &&
        (!requestedKeyHandle || String(publicFacts.keyHandle).trim() === requestedKeyHandle) &&
        (!identity || String(publicFacts.signingRootId).trim() === identity.signingRootId) &&
        (!identity ||
          String(publicFacts.signingRootVersion || 'default').trim() ===
            identity.signingRootVersion)
      );
    })
    .map(manifestEmailOtpEcdsaCandidate)
    .reduce((unique, candidate) => {
      const existing = unique.find((value) => value.keyHandle === candidate.keyHandle);
      if (!existing) {
        unique.push(candidate);
        return unique;
      }
      if (
        alphabetizeStringify(existing.publicCapability) !==
          alphabetizeStringify(candidate.publicCapability) ||
        !mpcMaterialActivationRefsEqual(
          existing.persistedRoleLocalMaterial.materialActivation,
          candidate.persistedRoleLocalMaterial.materialActivation,
        )
      ) {
        throw new Error(
          `Email OTP ECDSA has conflicting persisted role-local material for ${thresholdEcdsaChainTargetKey(args.chainTarget)}`,
        );
      }
      return unique;
    }, [] as ResolvedEmailOtpExistingEcdsaKey[]);
  if (candidates.length === 0) return null;
  if (candidates.length !== 1) {
    throw new Error(
      `Email OTP ECDSA has multiple persisted public capabilities for ${thresholdEcdsaChainTargetKey(args.chainTarget)}`,
    );
  }
  return projectEmailOtpExistingEcdsaKeyToChainTarget({
    existingKey: candidates[0]!,
    chainTarget: args.chainTarget,
  });
}

export function buildEmailOtpEcdsaReadyPersistInput(args: {
  walletId: WalletId;
  chainTarget: ThresholdEcdsaChainTarget;
  walletSessionId: EmailOtpEcdsaReadyPersistInput['walletSessionId'];
  quotaId: EmailOtpEcdsaReadyPersistInput['quotaId'];
  thresholdSessionId: string;
  emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
}): EmailOtpEcdsaReadyPersistInput {
  return {
    authMethod: 'email_otp',
    curve: 'ecdsa',
    walletId: args.walletId,
    chainTarget: args.chainTarget,
    walletSessionId: args.walletSessionId,
    quotaId: args.quotaId,
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
    runtimePolicyScope: ThresholdRuntimePolicyScope;
    authority: WalletAuthAuthorityRef;
    emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
    relayerUrl: string;
    groupId: string;
  },
  ports: EmailOtpEcdsaPublicationPorts,
): Promise<{
  bootstrap: ThresholdEcdsaSessionBootstrapResult;
  authorization: ExactWalletSessionAuthorization;
  authorizations: readonly [ExactWalletSessionAuthorization, ...ExactWalletSessionAuthorization[]];
  timings: EmailOtpEcdsaPublicationTimings;
}> {
  if (args.bootstraps.length !== args.publicationChainTargets.length) {
    throw new Error('Email OTP ECDSA publication returned an unexpected lane count');
  }
  const timings = createEmailOtpEcdsaPublicationTimings();
  const lanes: EmailOtpEcdsaPublicationLane[] = [];
  const expectedSession = args.bootstraps[0]?.session;
  if (!expectedSession) throw new Error('Email OTP ECDSA publication has no primary session');
  for (const [index, rawBootstrap] of args.bootstraps.entries()) {
    const expectedTarget = args.publicationChainTargets[index];
    const actualTarget = rawBootstrap.thresholdEcdsaKeyRef.chainTarget;
    if (!thresholdEcdsaChainTargetsEqual(actualTarget, expectedTarget)) {
      throw new Error(
        `Email OTP ECDSA publication returned ${thresholdEcdsaChainTargetKey(actualTarget)} for ${thresholdEcdsaChainTargetKey(expectedTarget)}`,
      );
    }
    if (
      rawBootstrap.session.walletSessionId !== expectedSession.walletSessionId ||
      rawBootstrap.session.quotaId !== expectedSession.quotaId
    ) {
      throw new Error('Email OTP ECDSA publication returned mismatched Wallet Session authority');
    }
    lanes.push({ chainTarget: expectedTarget, bootstrap: rawBootstrap });
  }
  const commitContext: CommitEmailOtpEcdsaPublicationLaneContext = { args, ports };
  const committedLanes = await Promise.all(
    lanes.map(commitEmailOtpEcdsaPublicationLane.bind(null, commitContext)),
  );
  const committedResults = committedLanes.map(readCommittedEmailOtpEcdsaPublicationResult);
  for (const lane of committedLanes) {
    mergeEmailOtpEcdsaPublicationTimings(timings, lane.timings);
  }
  const [primaryResult, ...remainingResults] = committedResults;
  if (!primaryResult) {
    throw new Error('Email OTP ECDSA publication did not commit a primary lane');
  }
  return {
    bootstrap: primaryResult.bootstrap,
    authorization: primaryResult.authorization,
    authorizations: [
      primaryResult.authorization,
      ...remainingResults.map((result) => result.authorization),
    ],
    timings,
  };
}

type EmailOtpEcdsaPublicationLane = {
  chainTarget: ThresholdEcdsaChainTarget;
  bootstrap: ThresholdEcdsaSessionBootstrapResult;
};

type CommitEmailOtpEcdsaPublicationLaneContext = {
  args: Parameters<typeof commitEmailOtpEcdsaPublicationBootstraps>[0];
  ports: EmailOtpEcdsaPublicationPorts;
};

type CommittedEmailOtpEcdsaPublicationLane = {
  result: {
    bootstrap: ThresholdEcdsaSessionBootstrapResult;
    authorization: ExactWalletSessionAuthorization;
  };
  timings: EmailOtpEcdsaPublicationTimings;
};

function readCommittedEmailOtpEcdsaPublicationResult(
  lane: CommittedEmailOtpEcdsaPublicationLane,
): CommittedEmailOtpEcdsaPublicationLane['result'] {
  return lane.result;
}

async function commitEmailOtpEcdsaPublicationLane(
  context: CommitEmailOtpEcdsaPublicationLaneContext,
  lane: EmailOtpEcdsaPublicationLane,
): Promise<CommittedEmailOtpEcdsaPublicationLane> {
  const timings = createEmailOtpEcdsaPublicationTimings();
  const workerBootstrap = lane.bootstrap;
  const commitStartedAtMs = nowMs();
  const result = await context.ports.commitEvmFamilyThresholdEcdsaSessions({
    walletId: context.args.walletId,
    chainTarget: lane.chainTarget,
    bootstrap: workerBootstrap,
    source: 'email_otp',
    authority: context.args.authority,
    emailOtpAuthContext: context.args.emailOtpAuthContext,
  });
  addEmailOtpEcdsaPublicationTiming(timings, 'warmCapabilityPersistenceMs', commitStartedAtMs);
  const sealTimings = await persistEmailOtpEcdsaSigningSessionForRefresh(
    {
      walletId: context.args.walletId,
      chainTarget: lane.chainTarget,
      bootstrap: result.bootstrap,
      runtimePolicyScope: context.args.runtimePolicyScope,
      emailOtpAuthContext: context.args.emailOtpAuthContext,
      relayerUrl: context.args.relayerUrl,
      groupId: context.args.groupId,
    },
    context.ports,
  );
  mergeEmailOtpEcdsaPublicationTimings(timings, sealTimings);
  return { result, timings };
}

export async function persistEmailOtpEcdsaSigningSessionForRefresh(
  args: {
    walletId: WalletId;
    chainTarget: ThresholdEcdsaChainTarget;
    bootstrap: ThresholdEcdsaSessionBootstrapResult;
    runtimePolicyScope: ThresholdRuntimePolicyScope;
    emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
    relayerUrl: string;
    groupId: string;
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
  const thresholdSessionId = String(session.thresholdSessionId || '').trim();
  const relayerUrl = String(args.relayerUrl || keyRef.relayerUrl || '').trim();
  if (args.groupId && args.groupId !== SIGNING_SESSION_SEAL_GROUP_ID) {
    throw new Error('Email OTP sealed refresh received an unsupported Shamir group');
  }
  const groupId = SIGNING_SESSION_SEAL_GROUP_ID;
  if (!thresholdSessionId || !relayerUrl) {
    throw new Error('Email OTP sealed refresh is missing threshold-session persistence metadata');
  }
  const readyPersistenceInput = buildEmailOtpEcdsaReadyPersistInput({
    walletId: args.walletId,
    chainTarget: args.chainTarget,
    walletSessionId: session.walletSessionId,
    quotaId: session.quotaId,
    thresholdSessionId,
    emailOtpAuthContext: args.emailOtpAuthContext,
  });

  const operationCredentialToken = String(session.operationCredential.token || '').trim();
  const runtimePolicyScope = args.runtimePolicyScope;
  const signingRootScope = signingRootScopeFromRuntimePolicyScope(runtimePolicyScope);
  const signingRootId = String(signingRootScope?.signingRootId || '').trim();
  const signingRootVersion = String(signingRootScope?.signingRootVersion || '').trim();
  const ecdsaThresholdKeyId = String(keyRef.ecdsaThresholdKeyId || '').trim();
  const userId = String(keyRef.userId || '').trim();
  const providerSubjectId = String(
    emailOtpAuthContextProviderUserId(args.emailOtpAuthContext) || userId,
  ).trim();
  const emailHashHex = String(emailOtpAuthContextEmailHashHex(args.emailOtpAuthContext)).trim();
  const ethereumAddress = normalizeEthereumAddress(keyRef.ethereumAddress);
  const clientVerifyingShareB64u = String(
    keyRef.backendBinding?.clientVerifyingShareB64u || '',
  ).trim();
  const thresholdEcdsaPublicKeyB64u = String(keyRef.thresholdEcdsaPublicKeyB64u || '').trim();
  const relayerKeyId = String(keyRef.backendBinding?.relayerKeyId || '').trim();
  const routerAbEcdsaDerivationNormalSigning = keyRef.routerAbEcdsaDerivationNormalSigning;
  const backendBinding = keyRef.backendBinding;
  let roleLocalMaterialRef: EcdsaRoleLocalPersistedMaterialRef | null = null;
  let publicCapability: RouterAbEcdsaDerivationPublicCapabilityV1 | null = null;
  if (backendBinding?.materialKind === 'role_local_worker_handle') {
    roleLocalMaterialRef = backendBinding.roleLocalMaterialRef;
    publicCapability = backendBinding.publicFacts.publicCapability;
  } else if (backendBinding?.materialKind === 'role_local_durable_sealed_ref') {
    roleLocalMaterialRef = backendBinding.roleLocalMaterialRef;
    publicCapability = backendBinding.publicFacts.publicCapability;
  }
  const participantIds = Array.isArray(keyRef.participantIds)
    ? keyRef.participantIds
        .map((participantId) => Math.floor(Number(participantId)))
        .filter((participantId) => Number.isFinite(participantId) && participantId > 0)
    : [];
  if (
    !ecdsaThresholdKeyId ||
    !userId ||
    !providerSubjectId ||
    !emailHashHex ||
    !ethereumAddress ||
    !clientVerifyingShareB64u ||
    !relayerKeyId ||
    !routerAbEcdsaDerivationNormalSigning ||
    !publicCapability ||
    !roleLocalMaterialRef ||
    !participantIds.length ||
    !operationCredentialToken ||
    !signingRootId ||
    !signingRootVersion
  ) {
    throw new Error('Email OTP sealed refresh is missing ECDSA restore metadata');
  }
  if (readyPersistenceInput.material.kind !== 'worker_handle') {
    throw new Error('Email OTP sealed refresh requires worker-owned warm material');
  }
  const emailOtpWorkerSessionId = readyPersistenceInput.material.workerSessionId;
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
  const expectedMaterialActivation = roleLocalMaterialRef.materialActivation;
  const exactAuthorityRef = await walletAuthAuthorityRef({
    authority: args.emailOtpAuthContext.authority,
  });
  const currentBeforeSeal = await resolveEmailOtpExistingEcdsaKey({
    walletId: args.walletId,
    chainTarget: args.chainTarget,
    scope: { kind: 'exact', runtimePolicyScope, authorityRef: exactAuthorityRef },
    keyHandle,
    listActiveEcdsaCapabilityManifestsForWallet: ports.listActiveEcdsaCapabilityManifestsForWallet,
  });
  if (
    !currentBeforeSeal ||
    !mpcMaterialActivationRefsEqual(
      currentBeforeSeal.persistedRoleLocalMaterial.materialActivation,
      expectedMaterialActivation,
    )
  ) {
    throw new Error('Email OTP sealed refresh material activation was superseded');
  }

  const sealStartedAtMs = nowMs();
  const sealed = await requestSealEmailOtpWarmSessionMaterial({
    workerCtx,
    target: { kind: 'ecdsa', thresholdSessionId: emailOtpWorkerSessionId },
    transport: {
      relayerUrl,
      walletSessionToken: operationCredentialToken,
      groupId,
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
  const sealKeyVersion = String(sealed.keyVersion || '').trim();
  if (!sealKeyVersion) {
    throw new Error('Email OTP sealed refresh seal returned no key version');
  }
  const persistedAtMs = Date.now();

  const sealedRecordBase = {
    thresholdSessionId: readyPersistenceInput.thresholdSessionId,
    sealedSecretB64u,
    curve: 'ecdsa' as const,
    authMethod: 'email_otp' as const,
    thresholdSessionIds: { ecdsa: readyPersistenceInput.thresholdSessionId },
    walletId: String(args.walletId || '').trim(),
    relayerUrl,
    keyVersion: sealKeyVersion,
    groupId,
    issuedAtMs: persistedAtMs,
    expiresAtMs,
    remainingUses,
  };
  const persistenceStartedAtMs = nowMs();
  const currentBeforeRegistration = await resolveEmailOtpExistingEcdsaKey({
    walletId: args.walletId,
    chainTarget: actualChainTarget,
    scope: { kind: 'exact', runtimePolicyScope, authorityRef: exactAuthorityRef },
    keyHandle,
    listActiveEcdsaCapabilityManifestsForWallet: ports.listActiveEcdsaCapabilityManifestsForWallet,
  });
  if (
    !currentBeforeRegistration ||
    !mpcMaterialActivationRefsEqual(
      currentBeforeRegistration.persistedRoleLocalMaterial.materialActivation,
      expectedMaterialActivation,
    )
  ) {
    throw new Error('Email OTP sealed refresh material activation was superseded');
  }
  // The manifest is the durable authority for ECDSA material. The route
  // authority remains on `emailOtpAuthority` for proof and restore context.
  const authority = currentBeforeRegistration.persistedRoleLocalMaterial.authority;
  await ports.registerSigningSession({
    ...sealedRecordBase,
    ecdsaRestore: {
      chainTarget: actualChainTarget,
      source: 'email_otp',
      signingRootId,
      signingRootVersion,
      provider: emailOtpAuthContextProvider(args.emailOtpAuthContext),
      providerSubjectId,
      emailHashHex,
      authority,
      emailOtpAuthority: args.emailOtpAuthContext.authority,
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
      roleLocalMaterialRef,
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
    persisted.sealedSecretB64u !== sealedSecretB64u ||
    alphabetizeStringify(persisted.ecdsaRestore?.roleLocalMaterialRef) !==
      alphabetizeStringify(roleLocalMaterialRef) ||
    !persisted.ecdsaRestore?.chainTarget ||
    !thresholdEcdsaChainTargetsEqual(persisted.ecdsaRestore.chainTarget, actualChainTarget)
  ) {
    throw new Error(
      `Email OTP sealed refresh read-back record does not match ${thresholdEcdsaChainTargetKey(actualChainTarget)} unlock session`,
    );
  }
  return timings;
}
