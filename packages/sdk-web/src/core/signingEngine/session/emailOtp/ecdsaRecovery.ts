import type { SeamsConfigsReadonly } from '@/core/types/seams';
import {
  buildEmailOtpAuthContextForWalletAuthMethod,
  emailOtpAuthContextProviderUserId,
  emailOtpAuthContextRetention,
  type ThresholdEcdsaEmailOtpAuthContext,
} from '@/core/signingEngine/session/identity/laneIdentity';
import type { ThresholdEcdsaSessionBootstrapResult } from '@/core/signingEngine/threshold/ecdsa/activation';
import {
  type ThresholdEcdsaChainTarget,
  toWalletId,
  type WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ActiveWalletSessionAuthorizationProjection } from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import {
  sealedRecoverySessionKind,
  sealedRecoveryWalletSessionJwt,
  type EmailOtpEcdsaSealedRecoveryRecord,
} from '@/core/signingEngine/session/sealedRecovery/recoveryRecord';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import {
  requestBindEmailOtpEcdsaWarmSessionFromWorkerHandle,
  requestRehydrateEmailOtpEcdsaWarmSessionMaterial,
} from './workerRequests';
import {
  parseSigningSessionSealKeyVersion,
} from '../keyMaterialBrands';
import type { EvmFamilySigningKeySlotId } from '@shared/signing-lanes';
import {
  walletAuthAuthorityRef,
  type EmailOtpWalletAuthAuthority,
} from '@shared/utils/walletAuthAuthority';
import {
  buildEcdsaRoleLocalPublicFacts,
} from '../persistence/ecdsaRoleLocalRecords';
import {
  buildPersistedEcdsaRoleLocalMaterial,
} from '../material/ecdsaRoleLocalMaterialResolver';
import {
  buildEvmFamilyEcdsaWalletKey,
  deriveEvmFamilySigningKeySlotId,
  type EvmFamilyEcdsaWalletKey,
} from '../identity/evmFamilyEcdsaIdentity';
import {
  parseSdkEcdsaDerivationSigningRootId,
  parseSdkEcdsaDerivationSigningRootVersion,
  parseSdkEcdsaDerivationThresholdKeyId,
} from '@shared/threshold/ecdsaDerivationRoleLocalBootstrap';
import { parseEmailOtpWorkerIssuedSessionHandle } from '@/core/platform';
import {
  buildEmailOtpExistingKeyActivation,
} from './ecdsaLogin';
import type { ThresholdEcdsaActivationRequest } from '../passkey/ecdsaSessionProvision';
import type { ResolvedEmailOtpExistingEcdsaKey } from './ecdsaPublication';

export type EmailOtpThresholdEcdsaRehydrateResult = {
  bootstrap: ThresholdEcdsaSessionBootstrapResult;
  authorization: ActiveWalletSessionAuthorizationProjection;
  remainingUses: number;
  expiresAtMs: number;
};

export type EmailOtpEcdsaSealedRecoveryRecordInput = {
  sealedRecord: EmailOtpEcdsaSealedRecoveryRecord;
};

export type EmailOtpEcdsaSealedRecoveryPorts = {
  configs: SeamsConfigsReadonly;
  getSignerWorkerContext: () => WorkerOperationContext | null | undefined;
  provisionThresholdEcdsaSession: (
    request: ThresholdEcdsaActivationRequest,
  ) => Promise<ThresholdEcdsaSessionBootstrapResult>;
  commitEvmFamilyThresholdEcdsaSessions: (args: {
    walletId: WalletId;
    chainTarget: ThresholdEcdsaChainTarget;
    bootstrap: ThresholdEcdsaSessionBootstrapResult;
    source: 'email_otp';
    emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
  }) => Promise<{
    bootstrap: ThresholdEcdsaSessionBootstrapResult;
    authorization: ActiveWalletSessionAuthorizationProjection;
  }>;
};

export type EmailOtpEcdsaSealedRecoveryInput = EmailOtpEcdsaSealedRecoveryPorts &
  EmailOtpEcdsaSealedRecoveryRecordInput;

export type EmailOtpEcdsaRestoreSource = {
  kind: 'sealed_record_restore';
  sealedRecord: EmailOtpEcdsaSealedRecoveryRecord;
  emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
  walletSessionJwt: string;
  thresholdSessionId: string;
  signingGrantId: string;
  relayerUrl: string;
  chainTarget: ThresholdEcdsaChainTarget;
  keyHandle: string;
  provisioningKeySlotId: EvmFamilySigningKeySlotId;
  relayerKeyId: string;
  participantIds: readonly number[];
  sessionKind: 'jwt';
  signingSessionSealKeyVersion: string;
  signingSessionSealShamirPrimeB64u: string;
  runtimePolicyScope?: EmailOtpEcdsaSealedRecoveryRecord['runtimePolicyScope'];
};

function sealedRecordEmailOtpSessionAuthContext(
  authority: EmailOtpWalletAuthAuthority,
): ThresholdEcdsaEmailOtpAuthContext {
  return buildEmailOtpAuthContextForWalletAuthMethod({
    policy: 'session',
    walletId: toWalletId(authority.walletId),
    emailHashHex: authority.verifier.emailHashHex,
    retention: 'session',
    reason: 'login',
    provider: authority.factor.provider,
    providerUserId: authority.factor.providerUserId,
  });
}

function emailOtpSealedRoleLocalParticipantIds(
  participantIds: readonly number[],
): readonly [1, 2] {
  if (participantIds.length !== 2 || participantIds[0] !== 1 || participantIds[1] !== 2) {
    throw new Error('Email OTP sealed refresh requires participantIds [1, 2]');
  }
  return [1, 2];
}

async function emailOtpSealedExistingKey(
  sealedRecord: EmailOtpEcdsaSealedRecoveryRecord,
): Promise<ResolvedEmailOtpExistingEcdsaKey> {
  const authority = await walletAuthAuthorityRef({
    authority: sealedRecord.emailOtpAuthority,
  });
  if (
    authority.walletId !== sealedRecord.authority.walletId ||
    authority.authorityDigest !== sealedRecord.authority.authorityDigest
  ) {
    throw new Error('Email OTP sealed refresh authority reference mismatch');
  }
  const capability = sealedRecord.publicCapability;
  const publicIdentity = capability.public_identity;
  const provisioningKeySlotId = deriveEvmFamilySigningKeySlotId({
    walletId: sealedRecord.walletId,
    signingRootId: sealedRecord.signingRootId,
    signingRootVersion: sealedRecord.signingRootVersion,
  });
  const publicFacts = buildEcdsaRoleLocalPublicFacts({
    walletId: toWalletId(sealedRecord.walletId),
    evmFamilySigningKeySlotId: provisioningKeySlotId,
    chainTarget: sealedRecord.chainTarget,
    keyHandle: sealedRecord.keyHandle,
    ecdsaThresholdKeyId: parseSdkEcdsaDerivationThresholdKeyId(
      sealedRecord.ecdsaThresholdKeyId,
    ),
    signingRootId: parseSdkEcdsaDerivationSigningRootId(sealedRecord.signingRootId),
    signingRootVersion: parseSdkEcdsaDerivationSigningRootVersion(
      sealedRecord.signingRootVersion,
    ),
    applicationBindingDigestB64u: capability.context.application_binding_digest_b64u,
    participantIds: emailOtpSealedRoleLocalParticipantIds(sealedRecord.participantIds),
    clientParticipantId: 1,
    relayerParticipantId: 2,
    contextBinding32B64u: publicIdentity.context_binding_b64u,
    derivationClientSharePublicKey33B64u:
      publicIdentity.derivation_client_share_public_key33_b64u,
    relayerPublicKey33B64u: publicIdentity.server_public_key33_b64u,
    groupPublicKey33B64u: publicIdentity.threshold_public_key33_b64u,
    ethereumAddress: sealedRecord.ethereumAddress,
    publicCapability: capability,
  });
  const walletKey: EvmFamilyEcdsaWalletKey = buildEvmFamilyEcdsaWalletKey({
    walletId: publicFacts.walletId,
    evmFamilySigningKeySlotId: publicFacts.evmFamilySigningKeySlotId,
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
  signingSessionSealShamirPrimeB64u: string;
} {
  const signingSessionSealKeyVersion = String(sealedRecord.keyVersion || '').trim();
  const signingSessionSealShamirPrimeB64u = String(sealedRecord.shamirPrimeB64u || '').trim();
  if (!signingSessionSealKeyVersion || !signingSessionSealShamirPrimeB64u) {
    throw new Error('Email OTP sealed refresh is missing normalized seal transport metadata');
  }
  return {
    signingSessionSealKeyVersion,
    signingSessionSealShamirPrimeB64u,
  };
}

function requireEmailOtpSealedWalletSessionJwt(
  sealedRecord: EmailOtpEcdsaSealedRecoveryRecord,
): string {
  const walletSessionJwt = sealedRecoveryWalletSessionJwt(sealedRecord.walletSessionAuth);
  if (!walletSessionJwt) {
    throw new Error('Email OTP sealed refresh is missing sealed Wallet Session JWT');
  }
  return walletSessionJwt;
}

function buildSealedRecordEmailOtpEcdsaRestoreSource(args: {
  sealedRecord: EmailOtpEcdsaSealedRecoveryRecord;
}): EmailOtpEcdsaRestoreSource {
  const { sealedRecord } = args;
  const transport = requireEmailOtpEcdsaSealedTransportSource(sealedRecord);
  const sessionKind = sealedRecoverySessionKind(sealedRecord.walletSessionAuth);
  if (sessionKind !== 'jwt') {
    throw new Error('Email OTP sealed refresh requires JWT Wallet Session restore metadata');
  }
  const walletSessionJwt = requireEmailOtpSealedWalletSessionJwt(sealedRecord);
  if (
    !sealedRecord.thresholdSessionId ||
    !sealedRecord.signingGrantId ||
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
    walletSessionJwt,
    thresholdSessionId: sealedRecord.thresholdSessionId,
    signingGrantId: sealedRecord.signingGrantId,
    relayerUrl: sealedRecord.relayerUrl,
    chainTarget: sealedRecord.chainTarget,
    keyHandle: sealedRecord.keyHandle,
    provisioningKeySlotId: deriveEvmFamilySigningKeySlotId({
      walletId: sealedRecord.walletId,
      signingRootId: sealedRecord.signingRootId,
      signingRootVersion: sealedRecord.signingRootVersion,
    }),
    relayerKeyId: sealedRecord.relayerKeyId,
    participantIds: [...sealedRecord.participantIds],
    sessionKind,
    ...transport,
    ...(sealedRecord.runtimePolicyScope
      ? { runtimePolicyScope: sealedRecord.runtimePolicyScope }
      : {}),
  };
}

export function createEmailOtpEcdsaSigningSessionMaterialRestorer(
  ports: EmailOtpEcdsaSealedRecoveryPorts,
): (args: EmailOtpEcdsaSealedRecoveryRecordInput) => Promise<EmailOtpThresholdEcdsaRehydrateResult | null> {
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
  const existingKey = await emailOtpSealedExistingKey(sealedRecord);
  const restoreSource = buildSealedRecordEmailOtpEcdsaRestoreSource({ sealedRecord });
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
  const restored = await requestRehydrateEmailOtpEcdsaWarmSessionMaterial({
    workerCtx,
    sealedSecretB64u: sealedRecord.sealedSecretB64u,
    remainingUses: sealedRecord.remainingUses,
    expiresAtMs: sealedRecord.expiresAtMs,
    transport: {
      relayerUrl: restoreSource.relayerUrl,
      walletSessionJwt: restoreSource.walletSessionJwt,
      signingSessionSealKeyVersion: parseSigningSessionSealKeyVersion(
        restoreSource.signingSessionSealKeyVersion,
      ),
      shamirPrimeB64u: restoreSource.signingSessionSealShamirPrimeB64u,
    },
    restore: {
      sessionId: restoreSource.thresholdSessionId,
      walletId: sealedRecord.walletId,
      provisioningKeySlotId: String(restoreSource.provisioningKeySlotId),
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
    restored.clientRootShareHandle,
  );
  const bootstrap = await args.provisionThresholdEcdsaSession(
    buildEmailOtpExistingKeyActivation({
      existingKey,
      chainTarget: restoreSource.chainTarget,
      thresholdSessionId: restoreSource.thresholdSessionId,
      signingGrantId: restoreSource.signingGrantId,
      ttlMs: Math.max(1, restored.expiresAtMs - Date.now()),
      remainingUses: restored.remainingUses,
      runtimePolicyScope: restoreSource.runtimePolicyScope,
      relayerUrl: restoreSource.relayerUrl,
      emailOtpAuthContext: restoreSource.emailOtpAuthContext,
      emailOtpWorkerSessionHandle,
      walletSessionRouteAuth: {
        kind: 'wallet_session',
        jwt: restoreSource.walletSessionJwt,
      },
    }),
  );
  const bound = await requestBindEmailOtpEcdsaWarmSessionFromWorkerHandle({
    workerCtx,
    clientRootShareHandle: restored.clientRootShareHandle,
    thresholdSessionId: bootstrap.session.thresholdSessionId,
    remainingUses: bootstrap.session.remainingUses,
    expiresAtMs: bootstrap.session.expiresAtMs,
  });
  if (!bound.ok) {
    throw new Error(bound.message || bound.code || 'Email OTP sealed refresh binding failed');
  }
  const committed = await args.commitEvmFamilyThresholdEcdsaSessions({
    walletId: toWalletId(sealedRecord.walletId),
    chainTarget: restoreSource.chainTarget,
    bootstrap,
    source: 'email_otp',
    emailOtpAuthContext: restoreSource.emailOtpAuthContext,
  });
  return {
    bootstrap: committed.bootstrap,
    authorization: committed.authorization,
    remainingUses: committed.bootstrap.session.remainingUses,
    expiresAtMs: committed.bootstrap.session.expiresAtMs,
  };
}
