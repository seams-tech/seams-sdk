import type {
  ActiveNearEd25519WalletSessionStatus,
  ExactNearEd25519WalletSessionAuthorization,
} from './nearEd25519YaoSigningPreparation';
import type {
  ActiveWalletSessionV1,
  WalletSessionOperationCredentialV1,
} from '@shared/device-linking/contracts';
import type { ActiveWalletAuthorityV1 } from '@shared/authorization/walletAuthority';
import type { ActiveWalletAuthMethodV2 } from '../identity/ownerLaneScope';
import type { WalletAuthAuthority } from '@shared/utils/walletAuthAuthority';
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
declare const selectedAuthority: ActiveWalletAuthorityV1;
declare const selectedAuthMethod: ActiveWalletAuthMethodV2;
declare const selectedFactorAuthority: WalletAuthAuthority;
declare const session: ActiveWalletSessionV1;
declare const operationCredential: WalletSessionOperationCredentialV1;
declare const status: ActiveNearEd25519WalletSessionStatus;
declare const nowMs: number;

const authorization = buildActiveNearEd25519WalletSessionAuthorization({
  selectedAuthority,
  selectedAuthMethod,
  selectedFactorAuthority,
  session,
  operationCredential,
  status,
  nowMs,
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
  // @ts-expect-error A value without the exact selected authority/session/status is not authorization.
  authorization: { kind: 'legacy_projection' },
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
