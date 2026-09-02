import type { SeamsConfigsReadonly } from '@/core/types/seams';
import {
  buildEmailOtpAuthContextForWalletAuthMethod,
  emailOtpAuthContextProviderUserId,
  emailOtpAuthContextRetention,
  type ThresholdEcdsaEmailOtpAuthContext,
  type ThresholdEcdsaEmailOtpSessionAuthContext,
} from '@/core/signingEngine/session/identity/laneIdentity';
import type { ThresholdEcdsaSessionBootstrapResult } from '@/core/signingEngine/threshold/ecdsa/activation';
import {
  thresholdEcdsaChainTargetsEqual,
  type ThresholdEcdsaChainTarget,
  toWalletId,
  type WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { WalletSessionAuthorizationExactOperationCredentialReadResult } from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import type { ResolveSelectedWalletAuthorityResultV1 } from '@/core/indexedDB/seamsWalletDB/repositories';
import type { WalletAuthorityId, WalletAuthMethodId } from '@shared/utils/domainIds';
import type { EmailOtpEcdsaSealedRecoveryRecord } from '@/core/signingEngine/session/sealedRecovery/recoveryRecord';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import { requestRehydrateEmailOtpEcdsaWarmSessionMaterial } from './workerRequests';
import { parseSigningSessionSealKeyVersion } from '../keyMaterialBrands';
import {
  walletAuthAuthorityRef,
  type EmailOtpWalletAuthAuthority,
} from '@shared/utils/walletAuthAuthority';
import { buildEcdsaRoleLocalPublicFacts } from '../persistence/ecdsaRoleLocalRecords';
import { buildPersistedEcdsaRoleLocalMaterial } from '../material/ecdsaRoleLocalMaterialResolver';
import {
  buildEvmFamilyEcdsaWalletKey,
  type EvmFamilyEcdsaWalletKey,
} from '../identity/evmFamilyEcdsaIdentity';
import {
  parseSdkEcdsaDerivationSigningRootId,
  parseSdkEcdsaDerivationSigningRootVersion,
  parseSdkEcdsaDerivationThresholdKeyId,
} from '@shared/threshold/ecdsaDerivationRoleLocalBootstrap';
import { parseEmailOtpWorkerIssuedSessionHandle } from '@/core/platform';
import { buildEmailOtpRecoveredKeyActivation } from './ecdsaLogin';
import type { ThresholdEcdsaActivationRequest } from '../passkey/ecdsaSessionProvision';
import {
  emailOtpEcdsaSealAuthorizationThresholdSessionId,
  type ResolvedEmailOtpExistingEcdsaKey,
} from './ecdsaPublication';
import { resolveThresholdEcdsaSigningQueueKey } from '../../threshold/ecdsa/signingQueue';
import type {
  ActiveEcdsaCapabilityRuntimeResolver,
  ActiveEcdsaCapabilityRuntimeResolution,
} from '../material/activeEcdsaCapabilityRuntime';
import type { ExactEcdsaSealedRuntime } from '../material/ecdsaSealedRuntime';
import { mpcMaterialActivationRefsEqual } from '@shared/utils/domainIds';
import {
  buildCanonicalEvmFamilyEcdsaSigningCapability,
  buildExactEvmFamilyWalletSessionAuthorization,
  type BuildExactEvmFamilyWalletSessionAuthorizationInput,
  type CanonicalEvmFamilyEcdsaSigningCapability,
  type ExactEvmFamilyWalletSessionAuthorization,
} from '../material/ecdsaSigningCapability';

export type EmailOtpThresholdEcdsaRehydrateResult = {
  bootstrap: ThresholdEcdsaSessionBootstrapResult;
  authorization: ExactEvmFamilyWalletSessionAuthorization;
  remainingUses: number;
  expiresAtMs: number;
};

export type EmailOtpEcdsaSealedRestoreSupersededPhase = 'before_rehydrate' | 'before_commit';

export class EmailOtpEcdsaSealedRestoreSupersededError extends Error {
  readonly code = 'material_activation_superseded' as const;

  constructor(readonly phase: EmailOtpEcdsaSealedRestoreSupersededPhase) {
    super(`Email OTP sealed refresh material activation was superseded ${phase.replace('_', ' ')}`);
    this.name = 'EmailOtpEcdsaSealedRestoreSupersededError';
  }
}

export type EmailOtpEcdsaSealedRecoveryRecordInput = {
  sealedRecord: EmailOtpEcdsaSealedRecoveryRecord;
};

export type EmailOtpEcdsaSealedRecoveryPorts = {
  configs: SeamsConfigsReadonly;
  withThresholdEcdsaSigningQueue: <T>(args: {
    queueKey: string;
    walletId: WalletId;
    enabled: boolean;
    task: () => Promise<T>;
  }) => Promise<T>;
  getSignerWorkerContext: () => WorkerOperationContext | null | undefined;
  resolveSelectedWalletAuthority: (
    walletId: string,
  ) => Promise<ResolveSelectedWalletAuthorityResultV1>;
  readExactWalletSessionAuthorization: (input: {
    walletId: WalletId;
    authorityId: WalletAuthorityId;
    authMethodId: WalletAuthMethodId;
  }) => Promise<WalletSessionAuthorizationExactOperationCredentialReadResult>;
  provisionThresholdEcdsaSession: (
    request: ThresholdEcdsaActivationRequest,
  ) => Promise<ThresholdEcdsaSessionBootstrapResult>;
  commitEvmFamilyThresholdEcdsaSessions: (args: {
    walletId: WalletId;
    chainTarget: ThresholdEcdsaChainTarget;
    bootstrap: ThresholdEcdsaSessionBootstrapResult;
    source: 'email_otp';
    authority: ResolvedEmailOtpExistingEcdsaKey['persistedRoleLocalMaterial']['authority'];
    emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
  }) => Promise<{
    bootstrap: ThresholdEcdsaSessionBootstrapResult;
  }>;
  resolveCurrentEcdsaCapabilityRuntime: ActiveEcdsaCapabilityRuntimeResolver;
};

export type EmailOtpEcdsaSealedRecoveryInput = EmailOtpEcdsaSealedRecoveryPorts &
  EmailOtpEcdsaSealedRecoveryRecordInput;

export type EmailOtpEcdsaRestoreSource = {
  kind: 'sealed_record_restore';
  sealedRecord: EmailOtpEcdsaSealedRecoveryRecord;
  emailOtpAuthContext: ThresholdEcdsaEmailOtpSessionAuthContext;
  authorization: ExactEvmFamilyWalletSessionAuthorization;
  relayerUrl: string;
  chainTarget: ThresholdEcdsaChainTarget;
  keyHandle: string;
  relayerKeyId: string;
  participantIds: readonly number[];
  signingSessionSealKeyVersion: string;
  signingSessionSealGroupId: string;
  runtimePolicyScope?: EmailOtpEcdsaSealedRecoveryRecord['runtimePolicyScope'];
};

function sealedRecordEmailOtpSessionAuthContext(
  authority: EmailOtpWalletAuthAuthority,
): ThresholdEcdsaEmailOtpSessionAuthContext {
  return buildEmailOtpAuthContextForWalletAuthMethod({
    policy: 'session',
    authority,
    retention: 'session',
    reason: 'login',
  });
}

function emailOtpSealedRoleLocalParticipantIds(participantIds: readonly number[]): readonly [1, 2] {
  if (participantIds.length !== 2 || participantIds[0] !== 1 || participantIds[1] !== 2) {
    throw new Error('Email OTP sealed refresh requires participantIds [1, 2]');
  }
  return [1, 2];
}

async function emailOtpSealedExistingKey(
  sealedRecord: EmailOtpEcdsaSealedRecoveryRecord,
): Promise<ResolvedEmailOtpExistingEcdsaKey> {
  const emailOtpAuthority = await walletAuthAuthorityRef({
    authority: sealedRecord.emailOtpAuthority,
  });
  if (emailOtpAuthority.walletId !== sealedRecord.authority.walletId) {
    throw new Error('Email OTP sealed refresh route authority wallet mismatch');
  }
  const capability = sealedRecord.publicCapability;
  const publicIdentity = capability.public_identity;
  const publicFacts = buildEcdsaRoleLocalPublicFacts({
    walletId: toWalletId(sealedRecord.walletId),
    chainTarget: sealedRecord.chainTarget,
    keyHandle: sealedRecord.keyHandle,
    ecdsaThresholdKeyId: parseSdkEcdsaDerivationThresholdKeyId(sealedRecord.ecdsaThresholdKeyId),
    signingRootId: parseSdkEcdsaDerivationSigningRootId(sealedRecord.signingRootId),
    signingRootVersion: parseSdkEcdsaDerivationSigningRootVersion(sealedRecord.signingRootVersion),
    applicationBindingDigestB64u: capability.context.application_binding_digest_b64u,
    participantIds: emailOtpSealedRoleLocalParticipantIds(sealedRecord.participantIds),
    clientParticipantId: 1,
    relayerParticipantId: 2,
    contextBinding32B64u: publicIdentity.context_binding_b64u,
    derivationClientSharePublicKey33B64u: publicIdentity.derivation_client_share_public_key33_b64u,
    relayerPublicKey33B64u: publicIdentity.server_public_key33_b64u,
    groupPublicKey33B64u: publicIdentity.threshold_public_key33_b64u,
    ethereumAddress: sealedRecord.ethereumAddress,
    publicCapability: capability,
  });
  const walletKey: EvmFamilyEcdsaWalletKey = buildEvmFamilyEcdsaWalletKey({
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
    publicCapability: capability,
    walletKey,
    runtimePolicyScope: sealedRecord.runtimePolicyScope,
    persistedRoleLocalMaterial: buildPersistedEcdsaRoleLocalMaterial({
      authority: sealedRecord.authority,
      materialActivation: sealedRecord.roleLocalMaterialRef.materialActivation,
      publicFacts,
    }),
  };
}

function requireEmailOtpEcdsaSealedTransportSource(
  sealedRecord: EmailOtpEcdsaSealedRecoveryRecord,
): {
  signingSessionSealKeyVersion: string;
  signingSessionSealGroupId: string;
} {
  const signingSessionSealKeyVersion = String(sealedRecord.keyVersion || '').trim();
  const signingSessionSealGroupId = String(sealedRecord.groupId || '').trim();
  if (!signingSessionSealKeyVersion || !signingSessionSealGroupId) {
    throw new Error('Email OTP sealed refresh is missing normalized seal transport metadata');
  }
  return {
    signingSessionSealKeyVersion,
    signingSessionSealGroupId,
  };
}

function buildSealedRecordEmailOtpEcdsaRestoreSource(args: {
  sealedRecord: EmailOtpEcdsaSealedRecoveryRecord;
  authorization: ExactEvmFamilyWalletSessionAuthorization;
}): EmailOtpEcdsaRestoreSource {
  const { sealedRecord } = args;
  const transport = requireEmailOtpEcdsaSealedTransportSource(sealedRecord);
  if (
    !sealedRecord.thresholdSessionId ||
    !sealedRecord.relayerUrl ||
    !sealedRecord.keyHandle ||
    !sealedRecord.relayerKeyId ||
    !sealedRecord.participantIds.length
  ) {
    throw new Error('Email OTP sealed refresh is missing durable ECDSA restore metadata');
  }
  return {
    kind: 'sealed_record_restore',
    sealedRecord,
    emailOtpAuthContext: sealedRecordEmailOtpSessionAuthContext(sealedRecord.emailOtpAuthority),
    authorization: args.authorization,
    relayerUrl: sealedRecord.relayerUrl,
    chainTarget: sealedRecord.chainTarget,
    keyHandle: sealedRecord.keyHandle,
    relayerKeyId: sealedRecord.relayerKeyId,
    participantIds: [...sealedRecord.participantIds],
    ...transport,
    ...(sealedRecord.runtimePolicyScope
      ? { runtimePolicyScope: sealedRecord.runtimePolicyScope }
      : {}),
  };
}

async function requireSelectedEmailOtpWalletAuthority(
  resolveSelectedWalletAuthority: EmailOtpEcdsaSealedRecoveryPorts['resolveSelectedWalletAuthority'],
  walletId: WalletId,
): Promise<BuildExactEvmFamilyWalletSessionAuthorizationInput['selected']> {
  const selected = await resolveSelectedWalletAuthority(String(walletId));
  if (
    selected.kind !== 'resolved' ||
    selected.selection.lockState !== 'unlocked' ||
    selected.selection.walletId !== walletId ||
    selected.selection.walletAuthMethodId !== selected.authMethod.walletAuthMethodId ||
    selected.authMethod.kind !== 'email_otp' ||
    selected.authMethod.status !== 'active' ||
    selected.authMethod.walletId !== walletId ||
    selected.authMethod.walletAuthorityId !== selected.authority.authorityId ||
    selected.authority.state !== 'active' ||
    selected.authority.walletId !== walletId
  ) {
    throw new Error('Email OTP sealed refresh selected authority is invalid');
  }
  return {
    kind: 'resolved',
    selection: selected.selection,
    authMethod: selected.authMethod,
    authority: selected.authority,
    signerMaterials: selected.signerMaterials,
    exportRoot: selected.exportRoot,
  };
}

function requireEmailOtpRuntimeAuthority(
  runtime: ExactEcdsaSealedRuntime,
): EmailOtpWalletAuthAuthority {
  if (runtime.authBinding.kind !== 'email_otp') {
    throw new Error('Email OTP sealed refresh runtime is not Email OTP bound');
  }
  return runtime.authBinding.emailOtpAuthority;
}

export function requireEmailOtpSealedRestoreAuthorization(args: {
  sealedRecord: EmailOtpEcdsaSealedRecoveryRecord;
  authorizationRead: WalletSessionAuthorizationExactOperationCredentialReadResult;
  selected: BuildExactEvmFamilyWalletSessionAuthorizationInput['selected'];
  runtime: ExactEcdsaSealedRuntime;
  capability: CanonicalEvmFamilyEcdsaSigningCapability;
  nowMs: number;
}): ExactEvmFamilyWalletSessionAuthorization {
  if (args.authorizationRead.kind !== 'found') {
    throw new Error(
      `Email OTP sealed refresh requires active Wallet Session authorization: ${args.authorizationRead.kind}`,
    );
  }
  const { record, operationCredential } = args.authorizationRead;
  if (args.runtime.kind !== 'exact_ecdsa_sealed_runtime_v1') {
    throw new Error('Email OTP sealed refresh ECDSA runtime is unavailable');
  }
  if (
    args.sealedRecord.authMethod !== 'email_otp' ||
    record.walletId !== toWalletId(args.sealedRecord.walletId) ||
    record.authorityId !== args.selected.authority.authorityId ||
    record.authMethodId !== args.selected.authMethod.walletAuthMethodId ||
    record.authorityDigestB64u !== args.selected.authority.authorityDigestB64u ||
    record.authorityRevocationEpoch !== args.selected.authority.revocationEpoch ||
    record.expiresAtMs <= args.nowMs ||
    operationCredential.walletSessionId.trim().length === 0 ||
    operationCredential.token.trim().length === 0 ||
    args.runtime.walletId !== record.walletId ||
    !thresholdEcdsaChainTargetsEqual(args.runtime.chainTarget, args.sealedRecord.chainTarget) ||
    args.runtime.sealedRecord.thresholdSessionId !== args.sealedRecord.thresholdSessionId ||
    args.runtime.sealedRecord.authMethod !== args.selected.authMethod.kind ||
    args.runtime.authBinding.kind !== 'email_otp' ||
    args.runtime.authBinding.emailOtpAuthority.bindingId !==
      args.selected.authMethod.walletAuthMethodId ||
    args.runtime.authBinding.emailOtpAuthority.walletId !== record.walletId
  ) {
    throw new Error('Email OTP sealed refresh Wallet Session authorization mismatch');
  }
  return buildExactEvmFamilyWalletSessionAuthorization({
    capability: args.capability,
    selected: args.selected,
    session: record,
    operationCredential,
    runtime: args.runtime,
    nowMs: args.nowMs,
  });
}

export function createEmailOtpEcdsaSigningSessionMaterialRestorer(
  ports: EmailOtpEcdsaSealedRecoveryPorts,
): (
  args: EmailOtpEcdsaSealedRecoveryRecordInput,
) => Promise<EmailOtpThresholdEcdsaRehydrateResult | null> {
  return async (args) =>
    await restoreEmailOtpEcdsaSigningSessionMaterialFromSealedRecord({
      ...ports,
      ...args,
    });
}

export async function restoreEmailOtpEcdsaSigningSessionMaterialFromSealedRecord(
  args: EmailOtpEcdsaSealedRecoveryInput,
): Promise<EmailOtpThresholdEcdsaRehydrateResult | null> {
  const sealedRecord = args.sealedRecord;
  if (sealedRecord.authMethod !== 'email_otp' || sealedRecord.curve !== 'ecdsa') {
    return null;
  }
  const materialActivation = sealedRecord.roleLocalMaterialRef.materialActivation;
  return await args.withThresholdEcdsaSigningQueue({
    queueKey: resolveThresholdEcdsaSigningQueueKey({ materialActivation }),
    walletId: toWalletId(sealedRecord.walletId),
    enabled: true,
    task: async () => await restoreEmailOtpEcdsaSigningSessionMaterialFromSealedRecordInQueue(args),
  });
}

async function restoreEmailOtpEcdsaSigningSessionMaterialFromSealedRecordInQueue(
  args: EmailOtpEcdsaSealedRecoveryInput,
): Promise<EmailOtpThresholdEcdsaRehydrateResult | null> {
  const sealedRecord = args.sealedRecord;
  const materialActivation = sealedRecord.roleLocalMaterialRef.materialActivation;
  const walletId = toWalletId(sealedRecord.walletId);
  const currentBeforeRehydrate: ActiveEcdsaCapabilityRuntimeResolution =
    await args.resolveCurrentEcdsaCapabilityRuntime({
      walletId,
      chainTarget: sealedRecord.chainTarget,
    });
  if (
    currentBeforeRehydrate.kind !== 'resolved' ||
    !mpcMaterialActivationRefsEqual(
      currentBeforeRehydrate.runtime.materialActivation,
      materialActivation,
    )
  ) {
    throw new EmailOtpEcdsaSealedRestoreSupersededError('before_rehydrate');
  }
  const selected = await requireSelectedEmailOtpWalletAuthority(
    args.resolveSelectedWalletAuthority,
    walletId,
  );
  const authorizationRead = await args.readExactWalletSessionAuthorization({
    walletId,
    authorityId: selected.authority.authorityId,
    authMethodId: selected.authMethod.walletAuthMethodId,
  });
  const existingKey = await emailOtpSealedExistingKey(sealedRecord);
  const capability = await buildCanonicalEvmFamilyEcdsaSigningCapability({
    authority: requireEmailOtpRuntimeAuthority(currentBeforeRehydrate.runtime),
    manifest: currentBeforeRehydrate.manifest,
    material: existingKey.persistedRoleLocalMaterial,
  });
  const authorization = requireEmailOtpSealedRestoreAuthorization({
    sealedRecord,
    authorizationRead,
    selected,
    runtime: currentBeforeRehydrate.runtime,
    capability,
    nowMs: Date.now(),
  });
  const restoreSource = buildSealedRecordEmailOtpEcdsaRestoreSource({
    sealedRecord,
    authorization,
  });
  if (restoreSource.authorization.runtime.kind !== 'exact_ecdsa_sealed_runtime_v1') {
    throw new Error('Email OTP sealed refresh requires a sealed ECDSA runtime');
  }
  const operationCredential = restoreSource.authorization.operationCredential;
  if (emailOtpAuthContextRetention(restoreSource.emailOtpAuthContext) !== 'session') return null;

  const workerCtx = args.getSignerWorkerContext();
  if (!workerCtx) {
    throw new Error('Email OTP sealed refresh requires the dedicated emailOtp worker');
  }

  if (sealedRecord.expiresAtMs <= Date.now()) {
    throw new Error('Email OTP sealed refresh expired sealed record');
  }
  if (sealedRecord.remainingUses <= 0) {
    throw new Error('Email OTP sealed refresh exhausted sealed record');
  }
  const expectedMaterialActivation = materialActivation;
  const thresholdSessionId = restoreSource.authorization.runtime.sealedRecord.thresholdSessionId;
  const authorizationThresholdSessionId = emailOtpEcdsaSealAuthorizationThresholdSessionId(
    sealedRecord.routerAbEcdsaDerivationNormalSigning,
  );
  const restored = await requestRehydrateEmailOtpEcdsaWarmSessionMaterial({
    workerCtx,
    target: { kind: 'ecdsa', thresholdSessionId },
    authorizationThresholdSessionId,
    sealedSecretB64u: sealedRecord.sealedSecretB64u,
    remainingUses: sealedRecord.remainingUses,
    expiresAtMs: sealedRecord.expiresAtMs,
    transport: {
      relayerUrl: restoreSource.relayerUrl,
      operationCredential,
      signingSessionSealKeyVersion: parseSigningSessionSealKeyVersion(
        restoreSource.signingSessionSealKeyVersion,
      ),
      groupId: restoreSource.signingSessionSealGroupId,
    },
    restore: {
      thresholdSessionId,
      walletId: sealedRecord.walletId,
      keyHandle: restoreSource.keyHandle,
      chainTarget: restoreSource.chainTarget,
      authSubjectId: emailOtpAuthContextProviderUserId(restoreSource.emailOtpAuthContext),
    },
  });
  if (!restored.ok) {
    throw new Error(restored.message || restored.code || 'Email OTP sealed refresh failed');
  }

  if (!restoreSource.runtimePolicyScope) {
    throw new Error('Email OTP sealed refresh requires runtime policy scope');
  }
  const emailOtpWorkerSessionHandle = parseEmailOtpWorkerIssuedSessionHandle(
    restored.emailOtpSessionHandle,
  );
  const bootstrap = await args.provisionThresholdEcdsaSession(
    buildEmailOtpRecoveredKeyActivation({
      existingKey,
      chainTarget: restoreSource.chainTarget,
      thresholdSessionId,
      ttlMs: Math.max(1, restored.expiresAtMs - Date.now()),
      remainingUses: restored.remainingUses,
      runtimePolicyScope: restoreSource.runtimePolicyScope,
      relayerUrl: restoreSource.relayerUrl,
      emailOtpAuthContext: restoreSource.emailOtpAuthContext,
      emailOtpWorkerSessionHandle,
      routeAuth: operationCredential,
    }),
  );
  const currentBeforeCommit: ActiveEcdsaCapabilityRuntimeResolution =
    await args.resolveCurrentEcdsaCapabilityRuntime({
      walletId: toWalletId(sealedRecord.walletId),
      chainTarget: restoreSource.chainTarget,
    });
  if (
    currentBeforeCommit.kind !== 'resolved' ||
    !mpcMaterialActivationRefsEqual(
      currentBeforeCommit.runtime.materialActivation,
      expectedMaterialActivation,
    )
  ) {
    throw new EmailOtpEcdsaSealedRestoreSupersededError('before_commit');
  }
  const committed = await args.commitEvmFamilyThresholdEcdsaSessions({
    walletId,
    chainTarget: restoreSource.chainTarget,
    bootstrap,
    source: 'email_otp',
    authority: existingKey.persistedRoleLocalMaterial.authority,
    emailOtpAuthContext: restoreSource.emailOtpAuthContext,
  });
  const committedAuthorization = buildExactEvmFamilyWalletSessionAuthorization({
    capability,
    selected,
    session: committed.bootstrap.session.walletSession,
    operationCredential: committed.bootstrap.session.operationCredential,
    runtime: currentBeforeCommit.runtime,
    nowMs: Date.now(),
  });
  return {
    bootstrap: committed.bootstrap,
    authorization: committedAuthorization,
    remainingUses: committed.bootstrap.session.remainingUses,
    expiresAtMs: committed.bootstrap.session.expiresAtMs,
  };
}
