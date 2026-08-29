import { activeWalletSessionV1RecordsEqual } from '@shared/device-linking/activeWalletSession';
import {
  mpcMaterialActivationRefsEqual,
  type MpcMaterialActivationRef,
} from '@shared/utils/domainIds';
import type {
  ActiveWalletSessionV1,
  WalletSessionOperationCredentialV1,
} from '@shared/device-linking/contracts';
import type { ActiveWalletAuthorityV1 } from '@shared/authorization/walletAuthority';
import type { ActiveWalletAuthMethodV2 } from '../identity/ownerLaneScope';
import type { ReusableWalletSessionStatus } from '@/core/rpcClients/relayer/walletSessionAuthorizationStatus';
import type { SigningLaneAuthBinding } from '../identity/signingLaneAuthBinding';
import type { MpcCapabilityHydrationPlan } from './mpcCapabilityHydration';
import type {
  WalletAuthAuthority,
  WalletAuthAuthorityRef,
} from '@shared/utils/walletAuthAuthority';

export type ActiveNearEd25519WalletSessionStatus = Extract<
  ReusableWalletSessionStatus,
  { readonly status: 'active' }
>;

/**
 * The exact Ed25519 operation authorization. A V6 row is only one half of
 * this value; the active relayer status is the authenticated server-side
 * proof that the session still has usable quota.
 */
export type ExactNearEd25519WalletSessionAuthorization = {
  readonly kind: 'exact_near_ed25519_wallet_session_authorization_v1';
  readonly selectedAuthority: ActiveWalletAuthorityV1;
  readonly selectedAuthMethod: ActiveWalletAuthMethodV2;
  readonly selectedFactorAuthority: WalletAuthAuthority;
  readonly session: ActiveWalletSessionV1;
  readonly operationCredential: WalletSessionOperationCredentialV1;
  readonly status: ActiveNearEd25519WalletSessionStatus;
};

export type NearEd25519WalletSessionAuthorizationReadResult =
  | {
      readonly kind: 'found';
      readonly authorization: ExactNearEd25519WalletSessionAuthorization;
    }
  | {
      readonly kind:
        | 'missing'
        | 'corrupt'
        | 'persistence_unavailable'
        | 'upgrade_required'
        | 'expired'
        | 'exhausted'
        | 'superseded'
        | 'authority_unavailable'
        | 'method_unavailable'
        | 'capability_unavailable'
        | 'unavailable';
      readonly authorization?: never;
    };

export type NearEd25519OperationAuthorizationState =
  | {
      readonly kind: 'authorized';
      readonly authorization: ExactNearEd25519WalletSessionAuthorization;
      readonly requirement?: never;
    }
  | {
      readonly kind: 'authorization_required';
      readonly requirement: SigningLaneAuthBinding;
      readonly authorization?: never;
    };

export type NearEd25519YaoSigningPreparation = {
  readonly kind: 'near_ed25519_yao_signing_preparation';
  readonly hydration: MpcCapabilityHydrationPlan;
  readonly authorization: NearEd25519OperationAuthorizationState;
  readonly entryPoint?: never;
  readonly provenance?: never;
  readonly hydrate?: never;
  readonly prepareOperationStepUp?: never;
};

function hydrationAuthority(hydration: MpcCapabilityHydrationPlan): WalletAuthAuthorityRef | null {
  switch (hydration.kind) {
    case 'use_live_runtime':
    case 'rehydrate_material_activation':
    case 'reauthorize_public_anchor':
      return hydration.authority;
    case 'blocked':
      return null;
    default:
      hydration satisfies never;
      throw new Error('[SigningEngine][near] unsupported MPC hydration plan');
  }
}

function selectedAuthorityMatchesAuthMethod(args: {
  readonly selectedAuthority: ActiveWalletAuthorityV1;
  readonly selectedAuthMethod: ActiveWalletAuthMethodV2;
  readonly selectedFactorAuthority: WalletAuthAuthority;
}): boolean {
  const { selectedAuthority, selectedAuthMethod, selectedFactorAuthority } = args;
  if (
    selectedAuthority.state !== 'active' ||
    selectedAuthority.walletId !== selectedAuthMethod.walletId ||
    selectedAuthority.authorityId !== selectedAuthMethod.walletAuthorityId ||
    selectedAuthority.signerActivations.ed25519 === undefined ||
    selectedFactorAuthority.walletId !== selectedAuthMethod.walletId ||
    selectedFactorAuthority.bindingId !== selectedAuthMethod.walletAuthMethodId
  ) {
    return false;
  }
  if (selectedAuthMethod.kind === 'passkey') {
    return (
      selectedFactorAuthority.factor.kind === 'passkey' &&
      selectedFactorAuthority.factor.credentialIdB64u === selectedAuthMethod.credentialIdB64u &&
      selectedFactorAuthority.verifier.kind === 'webauthn' &&
      selectedFactorAuthority.verifier.rpId === selectedAuthMethod.rpId
    );
  }
  return (
    selectedFactorAuthority.factor.kind === 'email_otp' &&
    selectedFactorAuthority.verifier.kind === 'email_otp_wallet_auth_method' &&
    selectedFactorAuthority.verifier.emailHashHex === selectedAuthMethod.emailHashHex &&
    selectedFactorAuthority.factor.providerUserId.trim().length > 0
  );
}

function exactNearEd25519AuthorizationIdentityMatches(args: {
  readonly authorization: ExactNearEd25519WalletSessionAuthorization;
  readonly nowMs: number;
}): boolean {
  const { authorization, nowMs } = args;
  const { selectedAuthority, selectedAuthMethod, session, operationCredential, status } =
    authorization;
  if (
    !selectedAuthorityMatchesAuthMethod({
      selectedAuthority,
      selectedAuthMethod,
      selectedFactorAuthority: authorization.selectedFactorAuthority,
    }) ||
    session.kind !== 'active_wallet_session_v1' ||
    session.walletId !== selectedAuthority.walletId ||
    session.authorityId !== selectedAuthority.authorityId ||
    session.authMethodId !== selectedAuthMethod.walletAuthMethodId ||
    session.authorityDigestB64u !== selectedAuthority.authorityDigestB64u ||
    session.authorityRevocationEpoch !== selectedAuthority.revocationEpoch ||
    operationCredential.kind !== 'opaque_wallet_session_operation_credential_v1' ||
    operationCredential.token.trim().length === 0 ||
    operationCredential.walletSessionId.trim().length === 0 ||
    session.authorizationId.trim().length === 0 ||
    session.quotaId.trim().length === 0 ||
    session.expiresAtMs <= nowMs ||
    status.status !== 'active' ||
    status.walletSessionId !== operationCredential.walletSessionId ||
    status.quotaId !== session.quotaId ||
    status.remainingUses <= 0 ||
    status.expiresAtMs <= nowMs ||
    status.quotaLifecycle !== 'active' ||
    status.authorization.expiresAtMs !== session.expiresAtMs ||
    !activeWalletSessionV1RecordsEqual(status.authorization, session)
  ) {
    return false;
  }
  return true;
}

/** A V6 session must carry exactly one Ed25519 signing subject for the lane. */
export function nearEd25519SessionMatchesMaterialActivation(args: {
  readonly session: ActiveWalletSessionV1;
  readonly materialActivation: MpcMaterialActivationRef;
}): boolean {
  const matches = args.session.capabilitySubjects.filter(
    (subject) =>
      subject.kind === 'sign' &&
      subject.keyFamily === 'ed25519' &&
      mpcMaterialActivationRefsEqual(subject.materialActivation, args.materialActivation),
  );
  return matches.length === 1;
}

function assertAuthorizationMatchesHydration(args: {
  readonly hydration: MpcCapabilityHydrationPlan;
  readonly authorization: ExactNearEd25519WalletSessionAuthorization;
}): void {
  const authority = hydrationAuthority(args.hydration);
  if (!authority) return;
  const selectedAuthority = args.authorization.selectedAuthority;
  if (
    authority.walletId !== selectedAuthority.walletId ||
    String(authority.authorityDigest) !== String(selectedAuthority.authorityDigestB64u)
  ) {
    throw new Error(
      '[SigningEngine][near] Wallet Session authorization does not match material authority',
    );
  }
}

function assertAuthorizationMatchesRequirement(args: {
  readonly requirement: SigningLaneAuthBinding;
  readonly authorization: ExactNearEd25519WalletSessionAuthorization;
}): void {
  const { requirement, authorization } = args;
  if (requirement.kind !== authorization.selectedAuthMethod.kind) {
    throw new Error(
      '[SigningEngine][near] Wallet Session authorization does not match material factor',
    );
  }
  if (requirement.kind === 'passkey') {
    if (
      authorization.selectedAuthMethod.kind !== 'passkey' ||
      String(requirement.rpId) !== String(authorization.selectedAuthMethod.rpId) ||
      requirement.credentialIdB64u !== authorization.selectedAuthMethod.credentialIdB64u
    ) {
      throw new Error(
        '[SigningEngine][near] Wallet Session authorization does not match Passkey factor',
      );
    }
    return;
  }
  if (
    authorization.selectedAuthMethod.kind !== 'email_otp' ||
    authorization.selectedFactorAuthority.factor.kind !== 'email_otp' ||
    requirement.providerSubjectId !== authorization.selectedFactorAuthority.factor.providerUserId
  ) {
    throw new Error(
      '[SigningEngine][near] Wallet Session authorization does not match Email OTP factor',
    );
  }
}

export function buildActiveNearEd25519WalletSessionAuthorization(args: {
  readonly selectedAuthority: ActiveWalletAuthorityV1;
  readonly selectedAuthMethod: ActiveWalletAuthMethodV2;
  readonly selectedFactorAuthority: WalletAuthAuthority;
  readonly session: ActiveWalletSessionV1;
  readonly operationCredential: WalletSessionOperationCredentialV1;
  readonly status: ActiveNearEd25519WalletSessionStatus;
  readonly nowMs: number;
}): ExactNearEd25519WalletSessionAuthorization {
  if (!Number.isSafeInteger(args.nowMs) || args.nowMs < 0) {
    throw new Error(
      '[SigningEngine][near] Wallet Session authorization requires a valid timestamp',
    );
  }
  const authorization: ExactNearEd25519WalletSessionAuthorization = {
    kind: 'exact_near_ed25519_wallet_session_authorization_v1',
    selectedAuthority: args.selectedAuthority,
    selectedAuthMethod: args.selectedAuthMethod,
    selectedFactorAuthority: args.selectedFactorAuthority,
    session: args.session,
    operationCredential: args.operationCredential,
    status: args.status,
  };
  if (!exactNearEd25519AuthorizationIdentityMatches({ authorization, nowMs: args.nowMs })) {
    throw new Error('[SigningEngine][near] Exact Wallet Session authorization identity is invalid');
  }
  return authorization;
}

export function buildAuthorizedNearEd25519YaoSigningPreparation(args: {
  hydration: MpcCapabilityHydrationPlan;
  requirement: SigningLaneAuthBinding;
  authorization: ExactNearEd25519WalletSessionAuthorization;
}): NearEd25519YaoSigningPreparation {
  assertAuthorizationMatchesRequirement(args);
  assertAuthorizationMatchesHydration(args);
  return {
    kind: 'near_ed25519_yao_signing_preparation',
    hydration: args.hydration,
    authorization: {
      kind: 'authorized',
      authorization: args.authorization,
    },
  };
}

export function buildAuthorizationRequiredNearEd25519YaoSigningPreparation(args: {
  hydration: MpcCapabilityHydrationPlan;
  requirement: SigningLaneAuthBinding;
}): NearEd25519YaoSigningPreparation {
  return {
    kind: 'near_ed25519_yao_signing_preparation',
    hydration: args.hydration,
    authorization: {
      kind: 'authorization_required',
      requirement: args.requirement,
    },
  };
}
