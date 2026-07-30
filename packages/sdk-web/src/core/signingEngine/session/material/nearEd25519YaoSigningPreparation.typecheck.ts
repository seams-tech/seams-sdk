import type { ActiveWalletSessionAuthorizationProjection } from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import type { SigningLaneAuthBinding } from '../identity/signingLaneAuthBinding';
import type { MpcCapabilityHydrationPlan } from './mpcCapabilityHydration';
import {
  buildAuthorizationRequiredNearEd25519YaoSigningPreparation,
  buildAuthorizedNearEd25519YaoSigningPreparation,
  type NearEd25519YaoSigningPreparation,
} from './nearEd25519YaoSigningPreparation';

declare const hydration: MpcCapabilityHydrationPlan;
declare const requirement: SigningLaneAuthBinding;
declare const authorization: ActiveWalletSessionAuthorizationProjection;

const authorized = buildAuthorizedNearEd25519YaoSigningPreparation({
  hydration,
  requirement,
  authorization,
});

const authorizationRequired = buildAuthorizationRequiredNearEd25519YaoSigningPreparation({
  hydration,
  requirement,
});

const invalidAuthorized: NearEd25519YaoSigningPreparation = {
  kind: 'near_ed25519_yao_signing_preparation',
  hydration,
  // @ts-expect-error Authorized material cannot also request authorization.
  authorization: {
    kind: 'authorized',
    authorization,
    requirement,
  },
};

const invalidAuthorizationRequired: NearEd25519YaoSigningPreparation = {
  kind: 'near_ed25519_yao_signing_preparation',
  hydration,
  // @ts-expect-error Authorization-required material cannot carry authorization.
  authorization: {
    kind: 'authorization_required',
    requirement,
    authorization,
  },
};

const invalidHydrationEffect: NearEd25519YaoSigningPreparation = {
  kind: 'near_ed25519_yao_signing_preparation',
  hydration,
  authorization: {
    kind: 'authorization_required',
    requirement,
  },
  // @ts-expect-error Hydration effects belong to the protocol-local executor port.
  hydrate: async () => undefined,
};

void [
  authorized,
  authorizationRequired,
  invalidAuthorized,
  invalidAuthorizationRequired,
  invalidHydrationEffect,
];
