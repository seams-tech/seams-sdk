import { toAccountId } from '@/core/types/accountIds';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { ed25519KeyScopeIdFromString } from '@shared/utils/registrationIntent';
import { buildNearTransactionSigningLane } from '../operationState/lanes';
import { SigningSessionIds } from '../operationState/types';
import { exactSigningLaneIdentity } from '../identity/exactSigningLaneIdentity';
import {
  emailOtpRefreshIdentity,
  type EmailOtpRefreshIdentity,
  type EmailOtpSessionRefreshResult,
} from './appSessionJwtCache';

const walletId = toWalletId('wallet.testnet');
const nearAccountId = toAccountId('wallet.testnet');
const ed25519KeyScopeId = ed25519KeyScopeIdFromString('scope-wallet-testnet');
const laneIdentity = exactSigningLaneIdentity(
  buildNearTransactionSigningLane({
    walletId,
    nearAccountId,
    ed25519KeyScopeId,
    auth: {
      kind: 'email_otp',
      providerSubjectId: 'google:subject-1',
    },
    signingGrantId: SigningSessionIds.signingGrant('wallet-session'),
    thresholdSessionId: SigningSessionIds.thresholdEd25519Session('threshold-session'),
  }),
);

const identity = emailOtpRefreshIdentity({
  walletId,
  walletSessionUserId: 'wallet.testnet',
  operationId: SigningSessionIds.signingOperation('operation-1'),
  operationFingerprint: SigningSessionIds.signingOperationFingerprint('fingerprint-1'),
  laneIdentity,
});
void identity;

// @ts-expect-error Email OTP refresh identity requires exact lane identity.
const missingLaneIdentity = emailOtpRefreshIdentity({
  walletId,
  walletSessionUserId: 'wallet.testnet',
  operationId: SigningSessionIds.signingOperation('operation-1'),
  operationFingerprint: SigningSessionIds.signingOperationFingerprint('fingerprint-1'),
});
void missingLaneIdentity;

// @ts-expect-error Email OTP refresh identity requires operation fingerprint.
const missingOperationFingerprint = emailOtpRefreshIdentity({
  walletId,
  walletSessionUserId: 'wallet.testnet',
  operationId: SigningSessionIds.signingOperation('operation-1'),
  laneIdentity,
});
void missingOperationFingerprint;

const rejection: EmailOtpSessionRefreshResult = {
  kind: 'email_otp_refresh_rejected',
  identity,
  reason: 'session_refresh_unauthorized',
  httpStatus: 401,
};
void rejection;

// @ts-expect-error rejected refresh results cannot carry app-session JWTs.
const invalidRejection: EmailOtpSessionRefreshResult = {
  kind: 'email_otp_refresh_rejected',
  identity,
  reason: 'session_refresh_unauthorized',
  httpStatus: 403,
  appSessionJwt: 'jwt',
};
void invalidRejection;

// @ts-expect-error refresh identity requires wallet id.
const missingWalletId: EmailOtpRefreshIdentity = {
  kind: 'email_otp_refresh_identity',
  walletSessionUserId: 'wallet.testnet',
  operationId: SigningSessionIds.signingOperation('operation-1'),
  operationFingerprint: SigningSessionIds.signingOperationFingerprint('fingerprint-1'),
  laneIdentity,
  laneIdentityKey: identity.laneIdentityKey,
};
void missingWalletId;
