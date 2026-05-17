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
