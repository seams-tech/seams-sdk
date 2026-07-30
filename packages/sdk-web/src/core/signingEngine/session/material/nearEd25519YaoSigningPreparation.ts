import type { ActiveWalletSessionAuthorizationProjection } from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import type { SigningLaneAuthBinding } from '../identity/signingLaneAuthBinding';
import type { MpcCapabilityHydrationPlan } from './mpcCapabilityHydration';
import type { WalletAuthAuthorityRef } from '@shared/utils/walletAuthAuthority';

export type NearEd25519OperationAuthorizationState =
  | {
      readonly kind: 'authorized';
      readonly authorization: ActiveWalletSessionAuthorizationProjection;
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

function hydrationAuthority(
  hydration: MpcCapabilityHydrationPlan,
): WalletAuthAuthorityRef | null {
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

function assertAuthorizationMatchesHydration(args: {
  hydration: MpcCapabilityHydrationPlan;
  authorization: ActiveWalletSessionAuthorizationProjection;
}): void {
  const authority = hydrationAuthority(args.hydration);
  if (!authority) return;
  if (
    String(authority.walletId) !== String(args.authorization.walletId) ||
    String(authority.authorityDigest) !== String(args.authorization.authority.authorityDigest)
  ) {
    throw new Error(
      '[SigningEngine][near] Wallet Session authorization does not match material authority',
    );
  }
}

function assertAuthorizationMatchesRequirement(args: {
  requirement: SigningLaneAuthBinding;
  authorization: ActiveWalletSessionAuthorizationProjection;
}): void {
  if (args.requirement.kind !== args.authorization.authMethod) {
    throw new Error(
      '[SigningEngine][near] Wallet Session authorization does not match material factor',
    );
  }
}

export function buildAuthorizedNearEd25519YaoSigningPreparation(args: {
  hydration: MpcCapabilityHydrationPlan;
  requirement: SigningLaneAuthBinding;
  authorization: ActiveWalletSessionAuthorizationProjection;
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
