import { thresholdEcdsaChainTargetFromChainFamily } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  buildEmailOtpRoutePlan,
  toAuthorizingWalletSigningSessionId,
  toMintedWalletSigningSessionId,
  type AuthorizingWalletSigningSessionId,
  type EmailOtpSigningSessionAuthLane,
  type MintedWalletSigningSessionId,
} from '../../stepUpConfirmation/otpPrompt/authLane';
import {
  assertPerOperationEmailOtpMintDoesNotReuseAuthorizingSession,
  buildPerOperationEmailOtpEcdsaMintingSession,
  type EmailOtpEcdsaBootstrapAuthorization,
  type EmailOtpEcdsaBootstrapRouteAuth,
  type EmailOtpThresholdEd25519RouteAuth,
} from './routePlan';

const chainTarget = thresholdEcdsaChainTargetFromChainFamily({
  chain: 'tempo',
  chainId: 42431,
});
const authorizingWalletSigningSessionId = toAuthorizingWalletSigningSessionId(
  'authorizing-wallet-signing-session',
);
const mintedWalletSigningSessionId = toMintedWalletSigningSessionId(
  'minted-wallet-signing-session',
);

void ({
  kind: 'signing_session',
  jwt: 'threshold-session-jwt',
  thresholdSessionId: 'threshold-session',
  authorizingWalletSigningSessionId,
  curve: 'ecdsa',
  chainTarget,
} satisfies EmailOtpSigningSessionAuthLane);

const routePlan = buildEmailOtpRoutePlan({
  routeFamily: 'signing_session',
  authLane: {
    kind: 'signing_session',
    jwt: 'threshold-session-jwt',
    thresholdSessionId: 'threshold-session',
    authorizingWalletSigningSessionId,
    curve: 'ecdsa',
    chainTarget,
  },
  operation: 'transaction_sign',
});

void buildPerOperationEmailOtpEcdsaMintingSession({
  routePlan,
  generateWalletSigningSessionId: () => mintedWalletSigningSessionId,
});

const ecdsaBootstrapRouteAuth = {
  kind: 'threshold_ecdsa_session',
  jwt: 'threshold-ecdsa-session-jwt',
  curve: 'ecdsa',
  thresholdSessionId: 'ecdsa-threshold-session',
  walletSigningSessionId: authorizingWalletSigningSessionId,
  chainTarget,
} satisfies EmailOtpEcdsaBootstrapRouteAuth;

void ({
  kind: 'explicit_route_auth',
  routeAuth: ecdsaBootstrapRouteAuth,
} satisfies EmailOtpEcdsaBootstrapAuthorization);

const ed25519RouteAuth = {
  kind: 'threshold_ed25519_session',
  jwt: 'threshold-ed25519-session-jwt',
  curve: 'ed25519',
  thresholdSessionId: 'ed25519-threshold-session',
  walletSigningSessionId: authorizingWalletSigningSessionId,
} satisfies EmailOtpThresholdEd25519RouteAuth;

void ed25519RouteAuth;

void ({
  kind: 'explicit_route_auth',
  // @ts-expect-error Ed25519 threshold-session auth cannot authorize ECDSA bootstrap.
  routeAuth: ed25519RouteAuth,
} satisfies EmailOtpEcdsaBootstrapAuthorization);

assertPerOperationEmailOtpMintDoesNotReuseAuthorizingSession({
  mintedWalletSigningSessionId,
  authorizingWalletSigningSessionId,
});

// @ts-expect-error authorizing session ids cannot be used as minted session ids
const invalidMintedWalletSigningSessionId: MintedWalletSigningSessionId =
  authorizingWalletSigningSessionId;

// @ts-expect-error minted session ids cannot authorize signing-session routes
const invalidAuthorizingWalletSigningSessionId: AuthorizingWalletSigningSessionId =
  mintedWalletSigningSessionId;

const invalidAuthLane = {
  kind: 'signing_session',
  jwt: 'threshold-session-jwt',
  thresholdSessionId: 'threshold-session',
  walletSigningSessionId: mintedWalletSigningSessionId,
  curve: 'ecdsa',
  chainTarget,
};

// @ts-expect-error auth lanes carry authorizing ids, not minted ids
void (invalidAuthLane satisfies EmailOtpSigningSessionAuthLane);

assertPerOperationEmailOtpMintDoesNotReuseAuthorizingSession({
  // @ts-expect-error per-operation minting requires a minted wallet signing-session id
  mintedWalletSigningSessionId: authorizingWalletSigningSessionId,
  authorizingWalletSigningSessionId,
});

void invalidMintedWalletSigningSessionId;
void invalidAuthorizingWalletSigningSessionId;

export {};
