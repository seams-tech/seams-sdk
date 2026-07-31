import type { SeamsConfigsReadonly } from '@/core/types/seams';
import type { NearEd25519YaoSigningCapability } from '@/core/signingEngine/interfaces/near';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import { requireTrimmedString } from '@shared/utils/validation';
import { SIGNING_SESSION_SEAL_GROUP_ID } from '@shared/utils/signingSessionSeal';
import {
  mpcMaterialActivationRefsEqual,
  type MpcMaterialActivationRef,
} from '@shared/utils/domainIds';
import {
  readExactSealedSession,
  type BuildCurrentSealedSessionRecordInput,
} from '../persistence/sealedSessionStore';
import { nearEd25519YaoMaterialActivationFromMetadata } from '../material/nearEd25519YaoMaterialActivation';
import {
  requestSealEmailOtpWarmSessionMaterial,
  type EmailOtpWarmSessionTransport,
} from './workerRequests';

export type EmailOtpEd25519YaoPublicationContext = {
  rpId: string;
  provider: 'google' | 'email';
  providerSubjectId: string;
  emailHashHex: string;
  materialActivation: MpcMaterialActivationRef;
};

export type EmailOtpEd25519YaoPublicationInput = {
  capability: NearEd25519YaoSigningCapability;
  publicationContext: EmailOtpEd25519YaoPublicationContext;
};

export type EmailOtpEd25519YaoPublicationPorts = {
  configs: SeamsConfigsReadonly;
  getSignerWorkerContext: () => WorkerOperationContext | null | undefined;
  registerSigningSession: (
    record: Extract<BuildCurrentSealedSessionRecordInput, { curve: 'ed25519' }>,
  ) => Promise<void>;
  readExactSealedSession: typeof readExactSealedSession;
};

function requirePositiveInteger(value: unknown, label: string): number {
  const normalized = Number(value);
  if (!Number.isSafeInteger(normalized) || normalized < 1) {
    throw new Error(`${label} must be positive for Email OTP Ed25519 sealed refresh`);
  }
  return normalized;
}

function buildEd25519YaoSealTransport(args: {
  relayerUrl: string;
  walletSessionJwt: string;
  groupId: string;
}): EmailOtpWarmSessionTransport {
  return {
    relayerUrl: args.relayerUrl,
    walletSessionJwt: args.walletSessionJwt,
    groupId: args.groupId,
  };
}

function assertPublicationCapabilityContinuity(
  capability: NearEd25519YaoSigningCapability,
  publicationContext: EmailOtpEd25519YaoPublicationContext,
): void {
  const state = capability.walletSessionState;
  const lane = state.signingLane;
  const signer = lane.identity.signer;
  const metadata = capability.activeClient.metadata();
  const materialActivation = nearEd25519YaoMaterialActivationFromMetadata(metadata);
  if (
    String(lane.thresholdSessionId) !== state.thresholdSessionId ||
    String(lane.identity.thresholdSessionId) !== state.thresholdSessionId ||
    metadata.scope.account_id !== String(signer.account.wallet.walletId) ||
    metadata.applicationBinding.wallet_id !== String(signer.account.wallet.walletId) ||
    metadata.applicationBinding.near_ed25519_signing_key_id !==
      String(signer.nearEd25519SigningKeyId) ||
    metadata.applicationBinding.signing_root_id !== state.signingRootId ||
    metadata.applicationBinding.key_creation_signer_slot !== signer.signerSlot ||
    metadata.scope.root_share_epoch !== state.signingRootVersion ||
    metadata.scope.signing_worker_id !== state.routerAbNormalSigning.signingWorkerId ||
    !mpcMaterialActivationRefsEqual(materialActivation, publicationContext.materialActivation)
  ) {
    throw new Error('Email OTP Ed25519 sealed refresh capability identity mismatch');
  }
}

export async function persistEmailOtpEd25519YaoSessionForRefresh(
  args: EmailOtpEd25519YaoPublicationInput,
  ports: EmailOtpEd25519YaoPublicationPorts,
): Promise<void> {
  if (ports.configs.signing.sessionPersistenceMode !== 'sealed_refresh_v1') return;
  const capability = args.capability;
  const state = capability.walletSessionState;
  const lane = state.signingLane;
  if (lane.auth.kind !== 'email_otp' || lane.retention !== 'session') return;
  assertPublicationCapabilityContinuity(capability, args.publicationContext);

  const workerContext = ports.getSignerWorkerContext();
  if (!workerContext) {
    throw new Error('Email OTP Ed25519 sealed refresh requires the dedicated Email OTP worker');
  }
  const thresholdSessionId = requireTrimmedString(state.thresholdSessionId, 'thresholdSessionId');
  const signingGrantId = requireTrimmedString(state.signingGrantId, 'signingGrantId');
  const walletSessionJwt = requireTrimmedString(
    state.walletSessionAuth.walletSessionJwt,
    'walletSessionJwt',
  );
  const relayerUrl = requireTrimmedString(state.relayerUrl, 'relayerUrl');
  const groupId = SIGNING_SESSION_SEAL_GROUP_ID;
  const runtimePolicyScope = state.runtimePolicyScope;
  const transport = buildEd25519YaoSealTransport({
    relayerUrl,
    walletSessionJwt,
    groupId,
  });
  const sealed = await requestSealEmailOtpWarmSessionMaterial({
    workerCtx: workerContext,
    sessionId: thresholdSessionId,
    transport,
  });
  if (!sealed.ok) {
    throw new Error(`Email OTP Ed25519 sealed refresh failed (${sealed.code}): ${sealed.message}`);
  }
  if (sealed.materialKind !== 'ed25519_yao') {
    throw new Error('Email OTP Ed25519 sealed refresh returned another material kind');
  }
  if (
    !mpcMaterialActivationRefsEqual(
      sealed.materialActivation,
      args.publicationContext.materialActivation,
    )
  ) {
    throw new Error('Email OTP Ed25519 sealed refresh returned another material activation');
  }
  const nowMs = Date.now();
  const expiresAtMs = requirePositiveInteger(sealed.expiresAtMs, 'expiresAtMs');
  const remainingUses = requirePositiveInteger(sealed.remainingUses, 'remainingUses');
  const keyVersion = requireTrimmedString(sealed.keyVersion, 'keyVersion');
  const providerSubjectId = requireTrimmedString(
    args.publicationContext.providerSubjectId,
    'providerSubjectId',
  );
  const metadata = capability.activeClient.metadata();
  const signer = lane.identity.signer;
  await ports.registerSigningSession({
    thresholdSessionId,
    sealedSecretB64u: requireTrimmedString(sealed.sealedSecretB64u, 'sealedSecretB64u'),
    authMethod: 'email_otp',
    signingGrantId,
    keyVersion,
    groupId,
    issuedAtMs: nowMs,
    expiresAtMs,
    remainingUses,
    updatedAtMs: nowMs,
    curve: 'ed25519',
    thresholdSessionIds: { ed25519: thresholdSessionId },
    walletId: String(signer.account.wallet.walletId),
    relayerUrl,
    ed25519Restore: {
      materialActivation: sealed.materialActivation,
      nearAccountId: String(signer.account.nearAccountId),
      nearEd25519SigningKeyId: String(signer.nearEd25519SigningKeyId),
      rpId: requireTrimmedString(args.publicationContext.rpId, 'rpId'),
      providerSubjectId,
      provider: args.publicationContext.provider,
      emailHashHex: requireTrimmedString(args.publicationContext.emailHashHex, 'emailHashHex'),
      relayerKeyId: requireTrimmedString(
        state.routerAbNormalSigning.signingWorkerId,
        'relayerKeyId',
      ),
      participantIds: Array.from(metadata.participantIds),
      runtimePolicyScope,
      signerSlot: requirePositiveInteger(signer.signerSlot, 'signerSlot'),
      routerAbNormalSigning: state.routerAbNormalSigning,
      walletSessionJwt,
      sessionKind: 'jwt',
    },
  });
  const persisted = await ports.readExactSealedSession(thresholdSessionId, {
    authMethod: 'email_otp',
    curve: 'ed25519',
  });
  if (
    !persisted ||
    persisted.curve !== 'ed25519' ||
    persisted.thresholdSessionIds.ed25519 !== thresholdSessionId ||
    persisted.signingGrantId !== signingGrantId ||
    persisted.ed25519Restore.providerSubjectId !== providerSubjectId
  ) {
    throw new Error('Email OTP Ed25519 sealed refresh read-back did not match the exact session');
  }
}
