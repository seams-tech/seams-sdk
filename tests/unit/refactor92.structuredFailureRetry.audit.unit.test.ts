import { expect, test } from '@playwright/test';
import { SIGNER_AUTH_METHODS } from '@shared/utils/signerDomain';
import { WALLET_SESSION_FAILURE_CODES } from '@shared/utils/walletSessionFailure';
import {
  classifyEvmFamilyFreshAuthRetry,
  type EvmFamilyFreshAuthRetryDecision,
} from '@/core/signingEngine/flows/signEvmFamily/freshAuthRetryPolicy';
import {
  WalletSessionFailureError,
  walletSessionFailureErrorFromPayload,
  walletSessionFailureFromError,
} from '@/core/signingEngine/session/lifecycle/walletSessionFailure';

test('Refactor 92 parses every authoritative Wallet Session failure distinctly', () => {
  const expectedKinds = new Map<string, string>([
    [WALLET_SESSION_FAILURE_CODES.expired, 'expired'],
    [WALLET_SESSION_FAILURE_CODES.missing, 'missing'],
    [WALLET_SESSION_FAILURE_CODES.signatureInvalid, 'invalid'],
    [WALLET_SESSION_FAILURE_CODES.claimsInvalid, 'invalid'],
    [WALLET_SESSION_FAILURE_CODES.scopeMismatch, 'invalid'],
    [WALLET_SESSION_FAILURE_CODES.unavailable, 'unavailable'],
    [WALLET_SESSION_FAILURE_CODES.budgetExhausted, 'exhausted'],
  ]);
  for (const [code, kind] of expectedKinds) {
    const parsed = walletSessionFailureErrorFromPayload({ code, message: code });
    expect(parsed?.failure.kind).toBe(kind);
  }
});

test('Refactor 92 does not classify prose as an authoritative Wallet Session failure', () => {
  expect(
    walletSessionFailureFromError(
      new Error('Expired or incomplete Wallet Session claims'),
    ),
  ).toBeNull();
});

test('Refactor 92 retries an authoritative EVM-family expiry once', () => {
  const failure = new WalletSessionFailureError({
    failure: {
      kind: 'expired',
      code: WALLET_SESSION_FAILURE_CODES.expired,
    },
    message: 'authoritative expiry',
  });
  expect(classifyWalletSessionRetry(failure)).toEqual({
    kind: 'retry',
    trigger: 'wallet_session_reauthorization_required',
    sideEffectState: 'no_auth_side_effect_started',
    retryMode: 'fresh_auth',
  });
  expect(
    classifyWalletSessionRetry(failure, { alreadyRetryingFreshAuth: true }),
  ).toEqual({
    kind: 'do_not_retry',
    trigger: 'wallet_session_reauthorization_required',
    sideEffectState: 'no_auth_side_effect_started',
    blockedReason: 'already_retrying',
  });
});

for (const code of [
  WALLET_SESSION_FAILURE_CODES.unavailable,
  WALLET_SESSION_FAILURE_CODES.budgetExhausted,
  WALLET_SESSION_FAILURE_CODES.scopeMismatch,
] as const) {
  test(`Refactor 92 does not expiry-retry structured ${code}`, () => {
    const failure = walletSessionFailureErrorFromPayload({ code, message: code });
    if (failure === null) throw new Error(`expected ${code} to parse`);
    expect(classifyWalletSessionRetry(failure)).toEqual({
      kind: 'do_not_retry',
      trigger: 'wallet_session_reauthorization_required',
      sideEffectState: 'no_auth_side_effect_started',
      blockedReason: 'error_not_retryable',
    });
  });
}

function classifyWalletSessionRetry(
  error: unknown,
  overrides: { readonly alreadyRetryingFreshAuth?: boolean } = {},
): EvmFamilyFreshAuthRetryDecision {
  return classifyEvmFamilyFreshAuthRetry({
    trigger: 'wallet_session_reauthorization_required',
    error,
    senderSignatureAlgorithm: 'secp256k1',
    accountAuth: {
      primaryAuthMethod: SIGNER_AUTH_METHODS.passkey,
      linkedAuthMethods: [SIGNER_AUTH_METHODS.passkey],
    },
    alreadyRetryingFreshAuth: overrides.alreadyRetryingFreshAuth,
    sideEffectState: 'no_auth_side_effect_started',
  });
}
