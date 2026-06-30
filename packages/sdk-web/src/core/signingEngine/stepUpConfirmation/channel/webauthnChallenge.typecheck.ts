import type {
  RegisterAccountPayload,
  SignIntentDigestPayload,
  SignIntentDigestSubject,
} from './confirmTypes';

const passkeyPlan = {
  kind: 'passkeyReauth',
  method: 'passkey',
} as const;

const emailOtpPlan = {
  kind: 'emailOtpReauth',
  method: 'email_otp',
} as const;

const validPasskeyIntentPayload: SignIntentDigestPayload = {
  signingSubject: {
    kind: 'evm_wallet',
    walletId: 'frost-vermillion-k7p9m2',
  },
  challengeB64u: 'transaction-digest',
  signingAuthPlan: passkeyPlan,
  webauthnChallenge: {
    kind: 'ecdsa_role_local_bootstrap',
    digest32B64u: 'role-local-bootstrap-digest',
    requestId: 'tecdsa-keygen-1',
    thresholdSessionId: 'threshold-session-1',
    signingGrantId: 'wallet-session-1',
  },
};
void validPasskeyIntentPayload;

// @ts-expect-error passkey intent signing requires typed WebAuthn challenge intent.
const invalidPasskeyIntentPayload: SignIntentDigestPayload = {
  signingSubject: {
    kind: 'evm_wallet',
    walletId: 'frost-vermillion-k7p9m2',
  },
  challengeB64u: 'transaction-digest',
  signingAuthPlan: passkeyPlan,
};
void invalidPasskeyIntentPayload;

const validEmailOtpIntentPayload: SignIntentDigestPayload = {
  signingSubject: {
    kind: 'evm_wallet',
    walletId: 'frost-vermillion-k7p9m2',
  },
  challengeB64u: 'transaction-digest',
  signingAuthPlan: emailOtpPlan,
};
void validEmailOtpIntentPayload;

const validNearWalletSubject: SignIntentDigestSubject = {
  kind: 'near_wallet',
  walletId: 'frost-vermillion-k7p9m2',
  nearAccountId: 'alice.testnet',
};
void validNearWalletSubject;

// @ts-expect-error NEAR signing subjects must carry wallet identity.
const invalidNearWalletSubjectMissingWallet: SignIntentDigestSubject = {
  kind: 'near_wallet',
  nearAccountId: 'alice.testnet',
};
void invalidNearWalletSubjectMissingWallet;

// @ts-expect-error EVM-family signing subjects do not carry NEAR account identity.
const invalidEvmWalletSubjectWithNearAccount: SignIntentDigestSubject = {
  kind: 'evm_wallet',
  walletId: 'frost-vermillion-k7p9m2',
  nearAccountId: 'alice.testnet',
};
void invalidEvmWalletSubjectWithNearAccount;

const validRegistrationPayload: RegisterAccountPayload = {
  walletId: 'frost-vermillion-k7p9m2',
  nearAccountId: 'alice.testnet',
  signerSlot: 1,
  webauthnChallenge: {
    kind: 'intent_digest',
    challengeB64u: 'registration-intent-digest',
  },
};
void validRegistrationPayload;

void ({
  walletId: 'frost-vermillion-k7p9m2',
  nearAccountId: 'alice.testnet',
  signerSlot: 1,
  // @ts-expect-error registration credential prompts must not carry NEAR RPC context
  rpcCall: {
    nearRpcUrl: 'https://rpc.testnet.near.org',
    nearAccountId: 'alice.testnet',
  },
} satisfies RegisterAccountPayload);

// @ts-expect-error registration credential prompts require walletId.
const invalidRegistrationPayloadMissingWalletId: RegisterAccountPayload = {
  nearAccountId: 'alice.testnet',
  signerSlot: 1,
};
void invalidRegistrationPayloadMissingWalletId;
