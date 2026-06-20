import { thresholdEcdsaChainTargetFromChainFamily } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  buildEmailOtpRoutePlan,
  toAuthorizingSigningGrantId,
  toMintedSigningGrantId,
  type AuthorizingSigningGrantId,
  type EmailOtpSigningSessionAuthLane,
  type MintedSigningGrantId,
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
const authorizingSigningGrantId = toAuthorizingSigningGrantId(
  'authorizing-signing-grant',
);
const mintedSigningGrantId = toMintedSigningGrantId(
  'minted-signing-grant',
);

void ({
  kind: 'signing_session',
  jwt: 'threshold-session-jwt',
  thresholdSessionId: 'threshold-session',
  authorizingSigningGrantId,
  curve: 'ecdsa',
  chainTarget,
} satisfies EmailOtpSigningSessionAuthLane);

const routePlan = buildEmailOtpRoutePlan({
  routeFamily: 'signing_session',
  authLane: {
    kind: 'signing_session',
    jwt: 'threshold-session-jwt',
    thresholdSessionId: 'threshold-session',
    authorizingSigningGrantId,
    curve: 'ecdsa',
    chainTarget,
  },
  operation: 'transaction_sign',
});

void buildPerOperationEmailOtpEcdsaMintingSession({
  routePlan,
  generateSigningGrantId: () => mintedSigningGrantId,
});

const ecdsaBootstrapRouteAuth = {
  kind: 'threshold_ecdsa_session',
  jwt: 'threshold-ecdsa-session-jwt',
  curve: 'ecdsa',
  thresholdSessionId: 'ecdsa-threshold-session',
  signingGrantId: authorizingSigningGrantId,
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
  signingGrantId: authorizingSigningGrantId,
} satisfies EmailOtpThresholdEd25519RouteAuth;

void ed25519RouteAuth;

void ({
  kind: 'explicit_route_auth',
  // @ts-expect-error Ed25519 Wallet Session auth cannot authorize ECDSA bootstrap.
  routeAuth: ed25519RouteAuth,
} satisfies EmailOtpEcdsaBootstrapAuthorization);

assertPerOperationEmailOtpMintDoesNotReuseAuthorizingSession({
  mintedSigningGrantId,
  authorizingSigningGrantId,
});

// @ts-expect-error authorizing session ids cannot be used as minted session ids
const invalidMintedSigningGrantId: MintedSigningGrantId =
  authorizingSigningGrantId;

// @ts-expect-error minted session ids cannot authorize signing-session routes
const invalidAuthorizingSigningGrantId: AuthorizingSigningGrantId =
  mintedSigningGrantId;

const invalidAuthLane = {
  kind: 'signing_session',
  jwt: 'threshold-session-jwt',
  thresholdSessionId: 'threshold-session',
  signingGrantId: mintedSigningGrantId,
  curve: 'ecdsa',
  chainTarget,
};

// @ts-expect-error auth lanes carry authorizing ids, not minted ids
void (invalidAuthLane satisfies EmailOtpSigningSessionAuthLane);

assertPerOperationEmailOtpMintDoesNotReuseAuthorizingSession({
  // @ts-expect-error per-operation minting requires a minted signing grant id
  mintedSigningGrantId: authorizingSigningGrantId,
  authorizingSigningGrantId,
});

void invalidMintedSigningGrantId;
void invalidAuthorizingSigningGrantId;

export {};
