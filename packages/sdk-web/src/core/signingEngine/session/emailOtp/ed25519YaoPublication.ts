import type { SeamsConfigsReadonly } from '@/core/types/seams';
import type {
  NearEd25519YaoOperationMaterial,
  NearResolvedEd25519SigningSessionState,
} from '@/core/signingEngine/interfaces/near';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import { requireTrimmedString } from '@shared/utils/validation';
import { SIGNING_SESSION_SEAL_GROUP_ID } from '@shared/utils/signingSessionSeal';
import {
  mpcMaterialActivationRefsEqual,
  type MpcMaterialActivationRef,
} from '@shared/utils/domainIds';
import {
  routerAbMpcMaterialActivationRefToWire,
  sameRouterAbMpcMaterialActivationRef,
} from '@shared/utils/routerAbNormalSigningIdentity';
import {
  readExactEd25519SealedSession,
  type BuildCurrentSealedSessionRecordInput,
} from '../persistence/sealedSessionStore';
import { ed25519DurableMaterialLocator } from '../sealedRecovery/materialActivationKey';
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
  material: NearEd25519YaoOperationMaterial;
  walletSessionState: NearResolvedEd25519SigningSessionState;
  publicationContext: EmailOtpEd25519YaoPublicationContext;
};

export type EmailOtpEd25519YaoPublicationPorts = {
  configs: SeamsConfigsReadonly;
  getSignerWorkerContext: () => WorkerOperationContext | null | undefined;
  registerSigningSession: (
    record: Extract<BuildCurrentSealedSessionRecordInput, { curve: 'ed25519' }>,
  ) => Promise<void>;
  readExactEd25519SealedSession: typeof readExactEd25519SealedSession;
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

function sameRuntimePolicyScope(
  left: NearEd25519YaoOperationMaterial['facts']['runtimePolicyScope'],
  right: NearResolvedEd25519SigningSessionState['runtimePolicyScope'],
): boolean {
  return (
    left.orgId === right.orgId &&
    left.projectId === right.projectId &&
    left.envId === right.envId &&
    left.signingRootVersion === right.signingRootVersion
  );
}

function assertPublicationCapabilityContinuity(
  material: NearEd25519YaoOperationMaterial,
  state: NearResolvedEd25519SigningSessionState,
  publicationContext: EmailOtpEd25519YaoPublicationContext,
): void {
  const lane = state.signingLane;
  const signer = lane.identity.signer;
  const metadata = material.activeClient.metadata();
  const facts = material.facts;
  const factsSigner = facts.signer;
  const materialActivation = nearEd25519YaoMaterialActivationFromMetadata(metadata);
  if (
    facts.thresholdSessionId !== state.thresholdSessionId ||
    metadata.scope.threshold_session_id !== facts.thresholdSessionId ||
    String(factsSigner.account.wallet.walletId) !== String(signer.account.wallet.walletId) ||
    String(factsSigner.account.nearAccountId) !== String(signer.account.nearAccountId) ||
    String(factsSigner.nearEd25519SigningKeyId) !== String(signer.nearEd25519SigningKeyId) ||
    factsSigner.signerSlot !== signer.signerSlot ||
    facts.signingRootId !== state.signingRootId ||
    facts.signingRootVersion !== state.signingRootVersion ||
    facts.routerAbNormalSigning.kind !== state.routerAbNormalSigning.kind ||
    facts.routerAbNormalSigning.signingWorkerId !==
      state.routerAbNormalSigning.signingWorkerId ||
    !sameRuntimePolicyScope(facts.runtimePolicyScope, state.runtimePolicyScope) ||
    facts.relayerUrl !== state.relayerUrl ||
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
    !sameRouterAbMpcMaterialActivationRef(
      metadata.scope.material_activation,
      routerAbMpcMaterialActivationRefToWire(materialActivation),
    ) ||
    !mpcMaterialActivationRefsEqual(materialActivation, publicationContext.materialActivation)
  ) {
    throw new Error('Email OTP Ed25519 sealed refresh capability identity mismatch');
  }
}

export async function persistEmailOtpEd25519YaoCapabilityForRefresh(
  args: EmailOtpEd25519YaoPublicationInput,
  ports: EmailOtpEd25519YaoPublicationPorts,
): Promise<void> {
  if (ports.configs.signing.sessionPersistenceMode !== 'sealed_refresh_v1') return;
  const material = args.material;
  const state = args.walletSessionState;
  const lane = state.signingLane;
  if (lane.auth.kind !== 'email_otp' || lane.retention !== 'session') return;
  assertPublicationCapabilityContinuity(material, state, args.publicationContext);

  const workerContext = ports.getSignerWorkerContext();
  if (!workerContext) {
    throw new Error('Email OTP Ed25519 sealed refresh requires the dedicated Email OTP worker');
  }
  const thresholdSessionId = requireTrimmedString(state.thresholdSessionId, 'thresholdSessionId');
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
    target: {
      kind: 'ed25519_yao',
      thresholdSessionId,
      materialActivation: args.publicationContext.materialActivation,
    },
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
  const metadata = material.activeClient.metadata();
  const signer = lane.identity.signer;
  await ports.registerSigningSession({
    thresholdSessionId,
    sealedSecretB64u: requireTrimmedString(sealed.sealedSecretB64u, 'sealedSecretB64u'),
    authMethod: 'email_otp',
    keyVersion,
    groupId,
    issuedAtMs: nowMs,
    expiresAtMs,
    remainingUses,
    updatedAtMs: nowMs,
    curve: 'ed25519',
    thresholdSessionIds: { ed25519: thresholdSessionId },
    walletId: String(signer.account.wallet.walletId),
    signingRootId: state.signingRootId,
    signingRootVersion: state.signingRootVersion,
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
    },
  });
  const persisted = await ports.readExactEd25519SealedSession(
    ed25519DurableMaterialLocator({
      authMethod: 'email_otp',
      materialActivation: sealed.materialActivation,
    }),
  );
  if (
    !persisted ||
    persisted.curve !== 'ed25519' ||
    persisted.thresholdSessionIds.ed25519 !== thresholdSessionId ||
    persisted.ed25519Restore.providerSubjectId !== providerSubjectId
  ) {
    throw new Error('Email OTP Ed25519 sealed refresh read-back did not match the exact session');
  }
}
