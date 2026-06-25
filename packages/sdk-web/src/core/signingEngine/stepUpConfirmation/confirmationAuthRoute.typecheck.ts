import type { RpcCallPayload } from '@/core/types/signer-worker';
import type { TransactionInputWasm } from '@/core/types/actions';
import type {
  EmailOtpConfirmPrompt,
  SigningAuthPlan,
} from './types';
import type {
  WebAuthnChallenge,
} from './channel/confirmTypes';
import type {
  OrchestrateNearTransactionSigningConfirmationParams,
} from './confirmOperation';

const ctx = {} as OrchestrateNearTransactionSigningConfirmationParams['ctx'];
const rpcCall = {} as RpcCallPayload;
const txSigningRequests = [] as TransactionInputWasm[];
const challenge: WebAuthnChallenge = {
  kind: 'intent_digest',
  challengeB64u: 'challenge',
};
const prompt: EmailOtpConfirmPrompt = {
  challengeId: 'email-challenge',
};
const warmPlan: Extract<SigningAuthPlan, { kind: 'warmSession' }> = {
  kind: 'warmSession',
  method: 'passkey',
  accountId: 'wallet',
  intent: 'transaction_sign',
  sessionId: 'threshold-session',
  expiresAtMs: Date.now() + 60_000,
  remainingUses: 1,
};
const passkeyPlan: Extract<SigningAuthPlan, { kind: 'passkeyReauth' }> = {
  kind: 'passkeyReauth',
  method: 'passkey',
};
const emailOtpPlan: Extract<SigningAuthPlan, { kind: 'emailOtpReauth' }> = {
  kind: 'emailOtpReauth',
  method: 'email_otp',
  emailOtpPrompt: prompt,
};

const baseTransaction = {
  ctx,
  sessionId: 'session',
  chain: 'near',
  kind: 'transaction',
  walletId: 'wallet',
  txSigningRequests,
  rpcCall,
} as const;

const validWarmTransaction: OrchestrateNearTransactionSigningConfirmationParams = {
  ...baseTransaction,
  signingAuthPlan: warmPlan,
};

const validPasskeyTransaction: OrchestrateNearTransactionSigningConfirmationParams = {
  ...baseTransaction,
  signingAuthPlan: passkeyPlan,
  webauthnChallenge: challenge,
};

const validEmailOtpTransaction: OrchestrateNearTransactionSigningConfirmationParams = {
  ...baseTransaction,
  signingAuthPlan: emailOtpPlan,
  emailOtpPrompt: prompt,
};

const invalidWarmWithChallenge = {
  ...baseTransaction,
  signingAuthPlan: warmPlan,
  webauthnChallenge: challenge,
  // @ts-expect-error Warm-session route cannot carry a WebAuthn challenge.
} satisfies OrchestrateNearTransactionSigningConfirmationParams;

const invalidPasskeyWithEmailPrompt = {
  ...baseTransaction,
  signingAuthPlan: passkeyPlan,
  emailOtpPrompt: prompt,
  // @ts-expect-error Passkey route cannot carry an Email OTP prompt.
} satisfies OrchestrateNearTransactionSigningConfirmationParams;

const invalidEmailOtpMissingPrompt = {
  ...baseTransaction,
  signingAuthPlan: emailOtpPlan,
  // @ts-expect-error Email OTP route requires a top-level prompt.
} satisfies OrchestrateNearTransactionSigningConfirmationParams;

const invalidEmailOtpWithChallenge = {
  ...baseTransaction,
  signingAuthPlan: emailOtpPlan,
  emailOtpPrompt: prompt,
  webauthnChallenge: challenge,
  // @ts-expect-error Email OTP route cannot carry a WebAuthn challenge.
} satisfies OrchestrateNearTransactionSigningConfirmationParams;

void validWarmTransaction;
void validPasskeyTransaction;
void validEmailOtpTransaction;
void invalidWarmWithChallenge;
void invalidPasskeyWithEmailPrompt;
void invalidEmailOtpMissingPrompt;
void invalidEmailOtpWithChallenge;
