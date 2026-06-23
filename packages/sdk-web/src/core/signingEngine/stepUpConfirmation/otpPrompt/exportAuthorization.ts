import { toAccountId, type AccountId } from '@/core/types/accountIds';
import { secureRandomId } from '@shared/utils/secureRandomId';
import type { WalletAuthCurve } from '@/core/types/seams';
import { SigningAuthPlanKind, type EmailOtpConfirmPrompt } from '../types';
import {
  UserConfirmationType,
  type UserConfirmDecision,
  type UserConfirmRequest,
} from '@/core/signingEngine/stepUpConfirmation/channel/confirmTypes';
import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';

export type EmailOtpExportAuthorizationChain = 'near' | ThresholdEcdsaChainTarget['kind'];

export type EmailOtpExportAuthorizationChallenge = {
  challengeId: string;
  emailHint?: string;
};

export type EmailOtpExportAuthorizationResult = {
  challengeId: string;
  otpCode: string;
};

export type EmailOtpExportAuthorizationChallengeSource = {
  requestChallenge: () => Promise<EmailOtpExportAuthorizationChallenge>;
};

export type EmailOtpExportAuthorizationConfirmer = {
  requestUserConfirmation: (request: UserConfirmRequest) => Promise<UserConfirmDecision>;
};

export type EmailOtpExportAuthorizationIdentity =
  | {
      kind: 'near_account';
      nearAccountId: AccountId | string;
    }
  | {
      kind: 'wallet_session';
      walletId: string;
    };

function createEmailOtpExportUiRequestId(prefix: string): string {
  return secureRandomId(prefix, 32, 'Email OTP export UI request IDs');
}

function accountIdForEmailOtpExportUi(identity: EmailOtpExportAuthorizationIdentity): string {
  switch (identity.kind) {
    case 'near_account':
      return String(toAccountId(identity.nearAccountId));
    case 'wallet_session': {
      const walletId = String(identity.walletId || '').trim();
      if (!walletId) {
        throw new Error('Email OTP export requires wallet identity');
      }
      return walletId;
    }
    default: {
      const exhaustive: never = identity;
      return exhaustive;
    }
  }
}

function buildEmailOtpExportPrompt(args: {
  challenge: EmailOtpExportAuthorizationChallenge;
  onResend: () => Promise<EmailOtpExportAuthorizationChallenge>;
}): EmailOtpConfirmPrompt {
  return {
    challengeId: args.challenge.challengeId,
    ...(args.challenge.emailHint ? { emailHint: args.challenge.emailHint } : {}),
    title: 'Enter email code to export',
    body: 'This one-time code authorizes private key export only.',
    helperText: 'Enter the 6-digit code sent to your email',
    onResend: args.onResend,
  };
}

export async function requestEmailOtpExportAuthorization(args: {
  identity: EmailOtpExportAuthorizationIdentity;
  chain: EmailOtpExportAuthorizationChain;
  publicKey: string;
  curve: WalletAuthCurve;
  challengeSource: EmailOtpExportAuthorizationChallengeSource;
  confirmer: EmailOtpExportAuthorizationConfirmer;
}): Promise<EmailOtpExportAuthorizationResult> {
  const accountIdForUi = accountIdForEmailOtpExportUi(args.identity);
  const requestExportChallenge = async (): Promise<EmailOtpExportAuthorizationChallenge> => {
    const challenge = await args.challengeSource.requestChallenge();
    const challengeId = String(challenge.challengeId || '').trim();
    if (!challengeId) {
      throw new Error('Email OTP export challenge response did not include challengeId');
    }
    return {
      challengeId,
      ...(String(challenge.emailHint || '').trim()
        ? { emailHint: String(challenge.emailHint || '').trim() }
        : {}),
    };
  };

  let challenge = await requestExportChallenge();
  const resend = async (): Promise<EmailOtpExportAuthorizationChallenge> => {
    challenge = await requestExportChallenge();
    return challenge;
  };
  const emailOtpPrompt = buildEmailOtpExportPrompt({ challenge, onResend: resend });

  const decision = await args.confirmer.requestUserConfirmation({
    requestId: createEmailOtpExportUiRequestId(`export-${args.curve}-email-otp-auth`),
    type: UserConfirmationType.SIGN_INTENT_DIGEST,
    summary: {
      operation: 'Export Private Key',
      accountId: accountIdForUi,
      publicKey: args.publicKey,
      warning:
        'Enter the email code to export this key. Anyone with the private key can fully control the account.',
    },
    payload: {
      nearAccountId: accountIdForUi,
      publicKey: args.publicKey,
      challengeB64u: challenge.challengeId,
      signingAuthPlan: {
        kind: SigningAuthPlanKind.EmailOtpReauth,
        method: 'email_otp',
        emailOtpPrompt,
      },
      emailOtpPrompt,
    },
    intentDigest: `export-keys:${accountIdForUi}:${args.chain}:${args.curve}:email-otp`,
  });

  if (!decision.confirmed) {
    throw new Error(decision.error || 'User cancelled Email OTP export request');
  }
  const otpCode = String(decision.otpCode || '')
    .replace(/\D/g, '')
    .slice(0, 6);
  if (otpCode.length !== 6) {
    throw new Error('Email OTP export requires a 6-digit code');
  }
  const responseChallengeId = String(decision.emailOtpChallengeId || challenge.challengeId).trim();
  return {
    challengeId: responseChallengeId,
    otpCode,
  };
}
