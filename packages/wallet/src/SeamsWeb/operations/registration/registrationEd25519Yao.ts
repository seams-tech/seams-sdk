import { parseThresholdEd25519SessionId, type WebAuthnRpId } from '@shared/utils/domainIds';
import type { ThresholdEd25519SessionId } from '@/core/signingEngine/session/operationState/types';
import type {
  RegistrationAuthMethodInput,
  RegistrationIntentV1,
  WalletId,
} from '@shared/utils/registrationIntent';
import { parseNearEd25519SigningKeyId } from '@shared/utils/registrationIntent';
import {
  type WalletRegistrationRespondEd25519DeferredWork,
  type WalletRegistrationEd25519YaoPublicResult,
  type WalletRegistrationFinalizeResponse,
} from '@/core/rpcClients/relayer/walletRegistration';
import { collectPasskeyRegistrationAuthority } from '@/SeamsWeb/operations/authMethods/passkey/registrationAuthority';
import type { PrepareEmailOtpRegistrationEnrollmentMaterialInternalResult as EmailOtpRegistrationEnrollmentMaterial } from '@/core/signingEngine/flows/signEvmFamily/emailOtpPublic';
import {
  emailOtpAuthContextProviderUserId,
  type ThresholdEcdsaEmailOtpAuthContext,
} from '@/core/signingEngine/session/identity/laneIdentity';
import {
  buildPasskeyWalletAuthAuthority,
  walletAuthAuthorityRef,
  type WalletAuthAuthority,
} from '@shared/utils/walletAuthAuthority';
import {
  buildEmailOtpRouterAbEd25519WalletSessionState,
  type ResolvedRouterAbEd25519WalletSessionState,
} from '@/core/signingEngine/session/warmCapabilities/routerAbEd25519WalletSessionState';
import { buildRouterAbEd25519SigningWalletSession } from '@/core/signingEngine/session/routerAbSigningWalletSession';
import { toAccountId } from '@/core/types/accountIds';
import {
  normalizeRuntimePolicyScope,
  signingRootScopeFromRuntimePolicyScope,
} from '@shared/threshold/signingRootScope';
import type {
  RegistrationEstablishedEd25519SessionProjectionV2,
  RegistrationEstablishedSessionV2,
} from '@shared/utils/registrationEstablishedSession';
import { ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND } from '@shared/utils/signingSessionSeal';
import { assertNever } from './registrationTiming';
import { sameRuntimePolicyScope } from './registrationStrictEcdsa';
type PasskeyAuthorityCredential = {
  readonly id?: unknown;
  readonly rawId?: unknown;
};

export function passkeyWalletAuthAuthorityFromCredential(args: {
  walletId: WalletId | string;
  rpId: WebAuthnRpId | string;
  credential: PasskeyAuthorityCredential;
}): WalletAuthAuthority {
  return buildPasskeyWalletAuthAuthority({
    walletId: args.walletId,
    rpId: args.rpId,
    credentialIdB64u: String(args.credential.rawId || args.credential.id || '').trim(),
  });
}

export async function requireEmailOtpRegistrationEnrollmentMaterial(input: {
  material: Promise<EmailOtpRegistrationEnrollmentMaterial> | null;
  operation: string;
}): Promise<EmailOtpRegistrationEnrollmentMaterial> {
  if (!input.material) {
    throw new Error(`Email OTP registration ${input.operation} is missing enrollment material`);
  }
  return await input.material;
}

type RegistrationEd25519MaterialFacts = {
  identity: {
    walletId: string;
    nearAccountId: string;
    nearEd25519SigningKeyId: string;
    thresholdSessionId: ThresholdEd25519SessionId;
    signerSlot: number;
    signingRootId: string;
    signingRootVersion: string;
    signingWorkerId: string;
  };
  stableServerScope: {
    relayerKeyId: string;
    participantIds: readonly [number, number];
    runtimePolicyScope: ReturnType<typeof normalizeRuntimePolicyScope>;
    routerAbNormalSigning: {
      kind: typeof ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND;
      signingWorkerId: string;
    };
  };
};

export function requireDeferredNearWork(
  value: WalletRegistrationRespondEd25519DeferredWork | null,
): WalletRegistrationRespondEd25519DeferredWork {
  if (!value) throw new Error('Mixed registration is missing deferred NEAR material facts');
  return value;
}

export function registrationEd25519MaterialFacts(args: {
  deferredNear: WalletRegistrationRespondEd25519DeferredWork;
  finalized: WalletRegistrationEd25519YaoPublicResult;
  walletId: WalletId;
  expectedRuntimePolicyScope: ReturnType<typeof normalizeRuntimePolicyScope>;
}): RegistrationEd25519MaterialFacts {
  const admission = args.deferredNear.admissionRequest;
  const thresholdSessionId = parseThresholdEd25519SessionId(admission.scope.threshold_session_id);
  if (!thresholdSessionId.ok) {
    throw new Error('Ed25519 registration threshold-session identity is invalid');
  }
  const participantIds = admission.participant_ids;
  const finalizedRuntimePolicyScope = normalizeRuntimePolicyScope(
    args.finalized.runtimePolicyScope,
  );
  if (
    admission.application_binding.wallet_id !== args.walletId ||
    admission.application_binding.near_ed25519_signing_key_id !==
      args.finalized.nearEd25519SigningKeyId ||
    admission.application_binding.key_creation_signer_slot !== args.finalized.signerSlot ||
    participantIds[0] !== args.finalized.participantIds[0] ||
    participantIds[1] !== args.finalized.participantIds[1] ||
    !sameRuntimePolicyScope(finalizedRuntimePolicyScope, args.expectedRuntimePolicyScope) ||
    admission.application_binding.signing_root_id !==
      `${finalizedRuntimePolicyScope.projectId}:${finalizedRuntimePolicyScope.envId}` ||
    admission.scope.root_share_epoch !== finalizedRuntimePolicyScope.signingRootVersion ||
    admission.scope.signing_worker_id !== args.finalized.routerAbNormalSigning.signingWorkerId ||
    args.finalized.relayerKeyId !== args.finalized.routerAbNormalSigning.signingWorkerId
  ) {
    throw new Error('Ed25519 registration material changed the admitted signer identity');
  }
  return {
    identity: {
      walletId: String(args.walletId),
      nearAccountId: args.finalized.nearAccountId,
      nearEd25519SigningKeyId: args.finalized.nearEd25519SigningKeyId,
      thresholdSessionId: thresholdSessionId.value,
      signerSlot: args.finalized.signerSlot,
      signingRootId: admission.application_binding.signing_root_id,
      signingRootVersion: admission.scope.root_share_epoch,
      signingWorkerId: admission.scope.signing_worker_id,
    },
    stableServerScope: {
      relayerKeyId: args.finalized.relayerKeyId,
      participantIds: args.finalized.participantIds,
      runtimePolicyScope: finalizedRuntimePolicyScope,
      routerAbNormalSigning: args.finalized.routerAbNormalSigning,
    },
  };
}

export function registrationEstablishedEd25519Session(
  session: RegistrationEstablishedSessionV2,
): RegistrationEstablishedEd25519SessionProjectionV2 {
  switch (session.tokens.kind) {
    case 'near_ed25519':
    case 'near_ed25519_and_evm_family_ecdsa':
      return session.tokens.ed25519;
    case 'evm_family_ecdsa':
      throw new Error('Registration-established session is missing Ed25519 authorization');
    default:
      return assertNever(session.tokens);
  }
}

export async function buildRegistrationEmailOtpEd25519SessionState(args: {
  registrationEstablishedSession: RegistrationEstablishedSessionV2;
  walletId: WalletId;
  nearAccountId: string;
  nearEd25519SigningKeyId: string;
  thresholdSessionId: string;
  runtimePolicyScope: ReturnType<typeof normalizeRuntimePolicyScope>;
  signerSlot: number;
  relayerUrl: string;
  emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
}): Promise<ResolvedRouterAbEd25519WalletSessionState> {
  const token = registrationEstablishedEd25519Session(args.registrationEstablishedSession);
  if (
    token.nearAccountId !== String(args.nearAccountId) ||
    token.nearEd25519SigningKeyId !== String(args.nearEd25519SigningKeyId) ||
    token.thresholdSessionId !== String(args.thresholdSessionId) ||
    !sameRuntimePolicyScope(token.runtimePolicyScope, args.runtimePolicyScope)
  ) {
    throw new Error('Registration-established Email OTP Ed25519 session changed signer identity');
  }
  const signingRoot = signingRootScopeFromRuntimePolicyScope(token.runtimePolicyScope);
  const signingRootVersion = signingRoot.signingRootVersion;
  if (!signingRootVersion) {
    throw new Error('Registration-established Ed25519 session is missing a signing-root version');
  }
  const signingWalletSession = buildRouterAbEd25519SigningWalletSession({
    walletId: String(args.walletId),
    nearAccountId: String(args.nearAccountId),
    nearEd25519SigningKeyId: String(args.nearEd25519SigningKeyId),
    walletSessionId: String(args.registrationEstablishedSession.walletSessionId),
    authorizationId: String(args.registrationEstablishedSession.authorizationId),
    quotaId: String(args.registrationEstablishedSession.quotaId),
    thresholdSessionId: token.thresholdSessionId,
    remainingUses: args.registrationEstablishedSession.remainingUses,
    expiresAtMs: args.registrationEstablishedSession.expiresAtMs,
    runtimePolicyScope: token.runtimePolicyScope,
    signingRootId: signingRoot.signingRootId,
    signingRootVersion,
    routerAbNormalSigning: token.routerAbNormalSigning,
    walletSessionToken: args.registrationEstablishedSession.operationCredential.token,
    nowMs: Date.now(),
  });
  if (!signingWalletSession.ok) {
    throw new Error(
      `Registration-established Email OTP Ed25519 session is unusable (${signingWalletSession.reason})`,
    );
  }
  const authority = await walletAuthAuthorityRef({
    authority: args.emailOtpAuthContext.authority,
  });
  return buildEmailOtpRouterAbEd25519WalletSessionState({
    walletId: args.walletId,
    nearAccountId: toAccountId(args.nearAccountId),
    nearEd25519SigningKeyId: parseNearEd25519SigningKeyId(args.nearEd25519SigningKeyId),
    providerSubjectId: emailOtpAuthContextProviderUserId(args.emailOtpAuthContext),
    signerSlot: args.signerSlot,
    relayerUrl: args.relayerUrl,
    authority,
    signingWalletSession: signingWalletSession.value,
  });
}

export type RegistrationPasskeyAuthority = Awaited<
  ReturnType<typeof collectPasskeyRegistrationAuthority>
>;

export function requirePasskeyRegistrationIntent(
  intent: RegistrationIntentV1,
): RegistrationIntentV1 & {
  authMethod: Extract<RegistrationAuthMethodInput, { kind: 'passkey' }>;
} {
  if (intent.authMethod.kind !== 'passkey') {
    throw new Error('Ed25519 Yao registration requires a passkey registration intent');
  }
  return {
    version: intent.version,
    walletId: intent.walletId,
    authMethod: intent.authMethod,
    signerSelection: intent.signerSelection,
    /* Carried, not dropped: the digest covers it, so an intent rebuilt without
       it would hash differently than the one the server issued. */
    foundingWalletAuthMethodId: intent.foundingWalletAuthMethodId,
    ...(intent.runtimePolicyScope ? { runtimePolicyScope: intent.runtimePolicyScope } : {}),
    nonceB64u: intent.nonceB64u,
  };
}

export function requireEd25519YaoRegistrationPublicResultMatches(args: {
  clientPublicKey: string;
  finalized: Extract<
    WalletRegistrationFinalizeResponse,
    { kind: 'near_ed25519' | 'near_ed25519_and_evm_family_ecdsa' }
  >;
  expectedRpId: string;
  expectedWalletId: WalletId;
}): { rpId: string; credentialIdB64u: string } {
  if (args.finalized.authMethod.kind !== 'passkey' || args.finalized.rpId !== args.expectedRpId) {
    throw new Error('Ed25519 Yao finalize returned a different passkey authority');
  }
  if (args.finalized.walletId !== args.expectedWalletId) {
    throw new Error('Ed25519 Yao finalize returned a different wallet');
  }
  if (
    args.finalized.ed25519.publicKey !== args.clientPublicKey ||
    args.finalized.ed25519.nearEd25519SigningKeyId !==
      args.finalized.resolvedAccount.nearEd25519SigningKeyId ||
    args.finalized.ed25519.nearAccountId !== args.finalized.resolvedAccount.nearAccountId
  ) {
    throw new Error('Ed25519 Yao finalize returned mismatched signer identity');
  }
  return {
    rpId: args.finalized.rpId,
    credentialIdB64u: args.finalized.authMethod.credentialIdB64u,
  };
}

export function requireEmailOtpEd25519YaoRegistrationPublicResultMatches(args: {
  clientPublicKey: string;
  finalized: Extract<
    WalletRegistrationFinalizeResponse,
    { kind: 'near_ed25519' | 'near_ed25519_and_evm_family_ecdsa' }
  >;
  expectedRegistrationAuthorityId: string;
  expectedWalletId: WalletId;
}): void {
  if (
    args.finalized.authMethod.kind !== 'email_otp' ||
    args.finalized.authMethod.registrationAuthorityId !== args.expectedRegistrationAuthorityId
  ) {
    throw new Error('Ed25519 Yao finalize returned a different Email OTP authority');
  }
  if (args.finalized.walletId !== args.expectedWalletId) {
    throw new Error('Ed25519 Yao finalize returned a different wallet');
  }
  if (
    args.finalized.ed25519.publicKey !== args.clientPublicKey ||
    args.finalized.ed25519.nearEd25519SigningKeyId !==
      args.finalized.resolvedAccount.nearEd25519SigningKeyId ||
    args.finalized.ed25519.nearAccountId !== args.finalized.resolvedAccount.nearAccountId
  ) {
    throw new Error('Ed25519 Yao finalize returned mismatched signer identity');
  }
}
