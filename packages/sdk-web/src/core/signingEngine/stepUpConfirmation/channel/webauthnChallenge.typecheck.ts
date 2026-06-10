import type { RegisterAccountPayload, SignIntentDigestPayload } from './confirmTypes';

const passkeyPlan = {
  kind: 'passkeyReauth',
  method: 'passkey',
} as const;

const emailOtpPlan = {
  kind: 'emailOtpReauth',
  method: 'email_otp',
} as const;

const validPasskeyIntentPayload: SignIntentDigestPayload = {
  nearAccountId: 'alice.testnet',
  challengeB64u: 'transaction-digest',
  signingAuthPlan: passkeyPlan,
  webauthnChallenge: {
    kind: 'ecdsa_role_local_bootstrap',
    digest32B64u: 'role-local-bootstrap-digest',
    requestId: 'tecdsa-keygen-1',
    thresholdSessionId: 'threshold-session-1',
    walletSigningSessionId: 'wallet-session-1',
  },
};
void validPasskeyIntentPayload;

// @ts-expect-error passkey intent signing requires typed WebAuthn challenge intent.
const invalidPasskeyIntentPayload: SignIntentDigestPayload = {
  nearAccountId: 'alice.testnet',
  challengeB64u: 'transaction-digest',
  signingAuthPlan: passkeyPlan,
};
void invalidPasskeyIntentPayload;

const validEmailOtpIntentPayload: SignIntentDigestPayload = {
  nearAccountId: 'alice.testnet',
  challengeB64u: 'transaction-digest',
  signingAuthPlan: emailOtpPlan,
};
void validEmailOtpIntentPayload;

const validRegistrationPayload: RegisterAccountPayload = {
  nearAccountId: 'alice.testnet',
  signerSlot: 1,
  webauthnChallenge: {
    kind: 'intent_digest',
    challengeB64u: 'registration-intent-digest',
  },
};
void validRegistrationPayload;

void ({
  nearAccountId: 'alice.testnet',
  signerSlot: 1,
  // @ts-expect-error registration credential prompts must not carry NEAR RPC context
  rpcCall: {
    nearRpcUrl: 'https://rpc.testnet.near.org',
    nearAccountId: 'alice.testnet',
  },
} satisfies RegisterAccountPayload);
