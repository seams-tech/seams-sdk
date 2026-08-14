import { toAccountId } from '@/core/types/accountIds';
import type { WalletId, WalletSessionRef } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { NearEd25519YaoOperationMaterial } from '@/core/signingEngine/interfaces/near';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import type {
  EmailOtpEd25519YaoRecoveryBootstrapV1,
} from '@/core/signingEngine/workerManager/workerTypes';
import type { EmailOtpAuthPolicy } from '@/core/types/seams';
import {
  buildEmailOtpAuthContextForWalletAuthMethod,
} from '@/core/signingEngine/session/identity/laneIdentity';
import {
  buildEmailOtpRouterAbEd25519WalletSessionState,
  type ResolvedRouterAbEd25519WalletSessionState,
} from '@/core/signingEngine/session/warmCapabilities/routerAbEd25519WalletSessionState';
import {
  buildRouterAbEd25519SigningWalletSession,
} from '@/core/signingEngine/session/routerAbSigningWalletSession';
import type {
  Ed25519YaoActiveClientIdentityV1,
} from '@/core/signingEngine/threshold/ed25519/yaoActiveClientRegistry';
import type { RouterAbEd25519YaoActiveClientMetadataV1 } from '@/core/signingEngine/threshold/ed25519/yaoClient';
import {
  mpcMaterialActivationRefsEqual,
  parseThresholdEd25519SessionId,
  type ThresholdEd25519SessionId,
} from '@shared/utils/domainIds';
import {
  nearEd25519SigningKeyIdFromString,
  registrationNearEd25519BranchKey,
} from '@shared/utils/registrationIntent';
import { walletAuthAuthorityRef } from '@shared/utils/walletAuthAuthority';
import { base58Encode } from '@shared/utils/base58';
import {
  WalletCustodyEd25519ActiveClientV1,
} from './ed25519ActiveClient';

export type WalletCustodyEd25519ActivationResult = {
  thresholdSessionId: ThresholdEd25519SessionId;
  material: NearEd25519YaoOperationMaterial;
  walletSessionState: ResolvedRouterAbEd25519WalletSessionState;
};

type ActivationIdentity = {
  walletId: WalletId;
  nearAccountId: string;
  signerSlot: number;
  expectedOperationalPublicKey: string;
  expectedThresholdSessionId: string;
};

function requireNonEmpty(value: unknown, label: string): string {
  const normalized = String(value ?? '').trim();
  if (!normalized) throw new Error(`${label} is required`);
  return normalized;
}

function requirePositiveInteger(value: unknown, label: string): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 1) {
    throw new Error(`${label} must be a positive integer`);
  }
  return parsed;
}

function requireThresholdSessionId(value: unknown): ThresholdEd25519SessionId {
  const parsed = parseThresholdEd25519SessionId(value);
  if (!parsed.ok) throw new Error('thresholdSessionId is invalid');
  return parsed.value;
}

function assertBootstrapIdentity(args: {
  bootstrap: EmailOtpEd25519YaoRecoveryBootstrapV1;
  identity: ActivationIdentity;
}): void {
  const session = args.bootstrap.session;
  const capability = args.bootstrap.capability;
  if (
    session.sessionKind !== 'opaque' ||
    !session.walletSessionToken ||
    !session.walletId ||
    !session.walletSessionId ||
    !session.quotaId ||
    !session.thresholdSessionId
  ) {
    throw new Error('Wallet custody Ed25519 bootstrap Wallet Session binding is invalid');
  }
  const expectedWalletId = String(args.identity.walletId);
  if (
    String(session.walletId) !== expectedWalletId ||
    session.nearAccountId !== String(args.identity.nearAccountId) ||
    session.thresholdSessionId !== args.identity.expectedThresholdSessionId ||
    capability.applicationBinding.wallet_id !== expectedWalletId ||
    capability.applicationBinding.key_creation_signer_slot !== args.identity.signerSlot ||
    capability.nearAccountId !== String(args.identity.nearAccountId) ||
    capability.lifecycle.accountId !== expectedWalletId ||
    capability.lifecycle.thresholdSessionId !== args.identity.expectedThresholdSessionId ||
    capability.lifecycle.signerSetId !==
      String(registrationNearEd25519BranchKey(args.identity.signerSlot)) ||
    `ed25519:${base58Encode(Uint8Array.from(capability.registeredPublicKey))}` !==
      args.identity.expectedOperationalPublicKey
  ) {
    throw new Error('Wallet custody Ed25519 bootstrap identity changed');
  }
}

async function buildWalletSessionState(args: {
  bootstrap: EmailOtpEd25519YaoRecoveryBootstrapV1;
  identity: ActivationIdentity;
  providerSubject: string;
  emailHashHex: string;
  relayerUrl: string;
  authPolicy: EmailOtpAuthPolicy;
}): Promise<ResolvedRouterAbEd25519WalletSessionState> {
  const session = args.bootstrap.session;
  const authorityScope = session.authorityScope;
  if (authorityScope.kind !== 'email_otp') {
    throw new Error('Wallet custody Ed25519 bootstrap returned another authority kind');
  }
  const providerSubject = requireNonEmpty(args.providerSubject, 'providerSubject');
  if (authorityScope.providerUserId !== providerSubject) {
    throw new Error('Wallet custody Ed25519 bootstrap provider subject changed');
  }
  const authority = await walletAuthAuthorityRef({
    authority: buildEmailOtpAuthContextForWalletAuthMethod({
      policy: args.authPolicy,
      walletId: session.walletId,
      emailHashHex: requireNonEmpty(args.emailHashHex, 'emailHashHex'),
      retention: 'session',
      reason: 'login',
      provider: authorityScope.provider,
      providerUserId: providerSubject,
    }).authority,
  });
  const signingWalletSession = buildRouterAbEd25519SigningWalletSession({
    walletId: String(session.walletId),
    nearAccountId: session.nearAccountId,
    nearEd25519SigningKeyId: session.nearEd25519SigningKeyId,
    walletSessionId: session.walletSessionId,
    authorizationId: session.authorizationId,
    quotaId: session.quotaId,
    thresholdSessionId: session.thresholdSessionId,
    remainingUses: session.remainingUses,
    expiresAtMs: session.expiresAtMs,
    runtimePolicyScope: session.runtimePolicyScope,
    signingRootId: session.signingRootId,
    signingRootVersion: session.signingRootVersion,
    routerAbNormalSigning: session.routerAbNormalSigning,
    walletSessionToken: session.walletSessionToken,
    nowMs: Date.now(),
  });
  if (!signingWalletSession.ok) {
    throw new Error(
      `Wallet custody Ed25519 Wallet Session is unusable (${signingWalletSession.reason})`,
    );
  }
  return buildEmailOtpRouterAbEd25519WalletSessionState({
    walletId: session.walletId,
    nearAccountId: toAccountId(session.nearAccountId),
    nearEd25519SigningKeyId: nearEd25519SigningKeyIdFromString(
      session.nearEd25519SigningKeyId,
    ),
    providerSubjectId: providerSubject,
    signerSlot: requirePositiveInteger(
      args.bootstrap.capability.applicationBinding.key_creation_signer_slot,
      'server capability signerSlot',
    ),
    relayerUrl: requireNonEmpty(args.relayerUrl, 'relayerUrl'),
    authority,
    signingWalletSession: signingWalletSession.value,
  });
}

function buildMaterial(
  walletSessionState: ResolvedRouterAbEd25519WalletSessionState,
  activeClient: NearEd25519YaoOperationMaterial['activeClient'],
): NearEd25519YaoOperationMaterial {
  return {
    activeClient,
    facts: {
      thresholdSessionId: walletSessionState.thresholdSessionId,
      signer: walletSessionState.signingLane.identity.signer,
      signingRootId: walletSessionState.signingRootId,
      signingRootVersion: walletSessionState.signingRootVersion,
      routerAbNormalSigning: walletSessionState.routerAbNormalSigning,
      runtimePolicyScope: walletSessionState.runtimePolicyScope,
      relayerUrl: walletSessionState.relayerUrl,
    },
  };
}

export async function activateWalletCustodyEd25519CapabilityV1(args: {
  walletSession: WalletSessionRef;
  nearAccountId: string;
  providerSubject: string;
  emailHashHex: string;
  relayerUrl: string;
  authPolicy: EmailOtpAuthPolicy;
  signerSlot: number;
  expectedOperationalPublicKey: string;
  expectedThresholdSessionId: string;
  bootstrap: EmailOtpEd25519YaoRecoveryBootstrapV1;
  activeClientHandle: string;
  metadata: RouterAbEd25519YaoActiveClientMetadataV1;
  workerContext: WorkerOperationContext;
  activateCapability: (
    material: NearEd25519YaoOperationMaterial,
  ) => Promise<Ed25519YaoActiveClientIdentityV1>;
}): Promise<WalletCustodyEd25519ActivationResult> {
  const identity: ActivationIdentity = {
    walletId: args.walletSession.walletId,
    nearAccountId: requireNonEmpty(args.nearAccountId, 'nearAccountId'),
    signerSlot: requirePositiveInteger(args.signerSlot, 'signerSlot'),
    expectedOperationalPublicKey: requireNonEmpty(
      args.expectedOperationalPublicKey,
      'expectedOperationalPublicKey',
    ),
    expectedThresholdSessionId: requireNonEmpty(
      args.expectedThresholdSessionId,
      'expectedThresholdSessionId',
    ),
  };
  assertBootstrapIdentity({ bootstrap: args.bootstrap, identity });
  if (
    args.metadata.applicationBinding.wallet_id !== String(args.walletSession.walletId) ||
    args.metadata.applicationBinding.key_creation_signer_slot !== identity.signerSlot ||
    args.metadata.scope.threshold_session_id !== identity.expectedThresholdSessionId ||
    !mpcMaterialActivationRefsEqual(
      args.metadata.materialActivation,
      args.bootstrap.capability.materialActivation,
    )
  ) {
    throw new Error('Wallet custody Ed25519 active client metadata changed');
  }
  const walletSessionState = await buildWalletSessionState({
    bootstrap: args.bootstrap,
    identity,
    providerSubject: args.providerSubject,
    emailHashHex: args.emailHashHex,
    relayerUrl: args.relayerUrl,
    authPolicy: args.authPolicy,
  });
  let activeClient: NearEd25519YaoOperationMaterial['activeClient'] | null =
    new WalletCustodyEd25519ActiveClientV1(
      args.workerContext,
      args.activeClientHandle,
      args.metadata,
    );
  try {
    const material = buildMaterial(walletSessionState, activeClient);
    const activatedIdentity = await args.activateCapability(material);
    if (
      String(activatedIdentity.walletId) !== String(identity.walletId) ||
      String(activatedIdentity.nearAccountId) !== identity.nearAccountId ||
      !mpcMaterialActivationRefsEqual(
        activatedIdentity.materialActivation,
        args.metadata.materialActivation,
      )
    ) {
      throw new Error('Wallet custody Ed25519 active client identity changed during activation');
    }
    activeClient = null;
    return {
      thresholdSessionId: requireThresholdSessionId(walletSessionState.thresholdSessionId),
      material,
      walletSessionState,
    };
  } finally {
    activeClient?.dispose();
  }
}
