import type { ActiveWalletSessionAuthorizationProjection } from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import type {
  ReusableWalletSessionStatus,
} from '@/core/rpcClients/relayer/walletSessionAuthorizationStatus';
import type { SigningLaneAuthBinding } from '../identity/signingLaneAuthBinding';
import type { MpcCapabilityHydrationPlan } from './mpcCapabilityHydration';
import {
  buildAuthorizationRequiredNearEd25519YaoSigningPreparation,
  buildActiveNearEd25519WalletSessionAuthorization,
  buildAuthorizedNearEd25519YaoSigningPreparation,
  type NearEd25519YaoSigningPreparation,
} from './nearEd25519YaoSigningPreparation';

declare const hydration: MpcCapabilityHydrationPlan;
declare const requirement: SigningLaneAuthBinding;
declare const projection: ActiveWalletSessionAuthorizationProjection;
declare const status: Extract<ReusableWalletSessionStatus, { readonly status: 'active' }>;

const authorization = buildActiveNearEd25519WalletSessionAuthorization({
  projection,
  status,
});

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

buildAuthorizedNearEd25519YaoSigningPreparation({
  hydration,
  requirement,
  // @ts-expect-error A projection without authoritative active status is not authorization.
  authorization: projection,
});

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
