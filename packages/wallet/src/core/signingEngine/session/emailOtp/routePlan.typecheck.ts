import { thresholdEcdsaChainTargetFromChainFamily } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  buildEmailOtpRoutePlan,
  type EmailOtpSigningSessionAuthLane,
} from '../../stepUpConfirmation/otpPrompt/authLane';
import {
  type EmailOtpEcdsaBootstrapAuthorization,
  type EmailOtpEcdsaBootstrapRouteAuth,
  type EmailOtpThresholdEd25519RouteAuth,
} from './routePlan';
import type { WalletSessionOperationCredentialV1 } from '@shared/device-linking';

declare const operationCredential: WalletSessionOperationCredentialV1;

const chainTarget = thresholdEcdsaChainTargetFromChainFamily({
  chain: 'tempo',
  chainId: 42431,
});
void ({
  kind: 'signing_session',
  operationCredential,
  thresholdSessionId: 'threshold-session',
  curve: 'ecdsa',
  chainTarget,
} satisfies EmailOtpSigningSessionAuthLane);

void buildEmailOtpRoutePlan({
  routeFamily: 'signing_session',
  authLane: {
    kind: 'signing_session',
    operationCredential,
    thresholdSessionId: 'threshold-session',
    curve: 'ecdsa',
    chainTarget,
  },
  operation: 'transaction_sign',
});

const ecdsaBootstrapRouteAuth = {
  kind: 'threshold_ecdsa_session',
  operationCredential,
  curve: 'ecdsa',
  thresholdSessionId: 'ecdsa-threshold-session',
  chainTarget,
} satisfies EmailOtpEcdsaBootstrapRouteAuth;

void ({
  kind: 'explicit_route_auth',
  routeAuth: ecdsaBootstrapRouteAuth,
} satisfies EmailOtpEcdsaBootstrapAuthorization);

const ed25519RouteAuth = {
  kind: 'threshold_ed25519_session',
  operationCredential,
  curve: 'ed25519',
} satisfies EmailOtpThresholdEd25519RouteAuth;

void ed25519RouteAuth;

void ({
  kind: 'explicit_route_auth',
  // @ts-expect-error Ed25519 Wallet Session auth cannot authorize ECDSA bootstrap.
  routeAuth: ed25519RouteAuth,
} satisfies EmailOtpEcdsaBootstrapAuthorization);

export {};
