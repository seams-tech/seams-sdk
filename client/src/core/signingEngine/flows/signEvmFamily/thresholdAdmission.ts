import type { ThresholdEcdsaSecp256k1KeyRef } from '../../interfaces/signing';
import type { WebAuthnAuthenticationCredential } from '@/core/types/webauthn';
import type { SelectedEcdsaLane } from '../../session/identity/laneIdentity';
import type { BudgetAdmittedTransactionOperation } from '../../session/operationState/transactionState';
import type { SigningAuthPlan } from '../../stepUpConfirmation/types';

export type EvmFamilyThresholdEcdsaOperation = BudgetAdmittedTransactionOperation<
  SelectedEcdsaLane,
  SigningAuthPlan
>;

export type EvmFamilyThresholdEcdsaReauthResult = {
  keyRef: ThresholdEcdsaSecp256k1KeyRef;
  operation: EvmFamilyThresholdEcdsaOperation;
};

export type EvmFamilyThresholdEcdsaAdmissionBoundary =
  | {
      kind: 'not_required';
    }
  | {
      kind: 'admitted';
      operation: EvmFamilyThresholdEcdsaOperation;
    };

export type EvmFamilyThresholdEcdsaAuthPlanInput =
  | {
      kind: 'not_required';
    }
  | {
      kind: 'planned';
      signingAuthPlan: SigningAuthPlan;
    };

export type EvmFamilyThresholdEcdsaEmailOtpSigning = {
  complete: (
    otpCode: string,
    challengeId?: string,
  ) => Promise<EvmFamilyThresholdEcdsaReauthResult>;
};

export type EvmFamilyThresholdEcdsaPasskeyReconnect = {
  reconnect: (args: {
    credential: WebAuthnAuthenticationCredential;
    usesNeeded: number;
    sessionId: string;
    walletSigningSessionId: string;
  }) => Promise<EvmFamilyThresholdEcdsaReauthResult>;
};

export type EvmFamilyThresholdEcdsaPasskeyReconnectPlan = {
  sessionId: string;
  walletSigningSessionId: string;
  sessionPolicyDigest32?: string;
};

export type EvmFamilyThresholdEcdsaAdmissionCompletion = {
  source: 'email_otp' | 'passkey' | 'threshold_reconnect';
  result: EvmFamilyThresholdEcdsaReauthResult;
};

export type EvmFamilyThresholdEcdsaAdmissionMode =
  | {
      kind: 'not_required';
    }
  | {
      kind: 'already_admitted';
    }
  | {
      kind: 'email_otp';
      emailOtpSigning: EvmFamilyThresholdEcdsaEmailOtpSigning;
    }
  | {
      kind: 'passkey_reconnect';
      passkeyEcdsaReconnect: EvmFamilyThresholdEcdsaPasskeyReconnect;
      plannedPasskeyReconnect: EvmFamilyThresholdEcdsaPasskeyReconnectPlan;
      onThresholdReconnectStarted?: () => void;
    }
  | {
      kind: 'threshold_reconnect';
      ensureThresholdEcdsaKeyRefReady: () => Promise<EvmFamilyThresholdEcdsaReauthResult>;
      onThresholdReconnectStarted?: () => void;
    };

export async function completeEvmFamilyThresholdEcdsaAdmissionAfterConfirmation(args: {
  mode: EvmFamilyThresholdEcdsaAdmissionMode;
  confirmation: {
    credential?: unknown;
    otpCode?: string;
    emailOtpChallengeId?: string;
  };
  usesNeeded: number;
}): Promise<EvmFamilyThresholdEcdsaAdmissionCompletion | null> {
  if (args.mode.kind === 'not_required' || args.mode.kind === 'already_admitted') return null;

  if (args.mode.kind === 'email_otp') {
    const otpCode = String(args.confirmation.otpCode || '').trim();
    if (!/^\d{6}$/.test(otpCode)) {
      throw new Error('[chains] missing Email OTP code from touchConfirm');
    }
    const result = await args.mode.emailOtpSigning.complete(
      otpCode,
      args.confirmation.emailOtpChallengeId,
    );
    if (!result?.keyRef || !result?.operation) {
      throw new Error('[chains] Email OTP ECDSA reauth must return admitted operation');
    }
    return { source: 'email_otp', result };
  }

  if (args.mode.kind === 'passkey_reconnect') {
    if (!args.confirmation.credential) {
      throw new Error('[chains] missing WebAuthn credential for threshold ECDSA reconnect');
    }
    args.mode.onThresholdReconnectStarted?.();
    const result = await args.mode.passkeyEcdsaReconnect.reconnect({
      credential: args.confirmation.credential as WebAuthnAuthenticationCredential,
      usesNeeded: args.usesNeeded,
      sessionId: args.mode.plannedPasskeyReconnect.sessionId,
      walletSigningSessionId: args.mode.plannedPasskeyReconnect.walletSigningSessionId,
    });
    if (!result?.keyRef || !result?.operation) {
      throw new Error('[chains] passkey ECDSA reconnect must return admitted operation');
    }
    if (
      String(result.operation.lane.thresholdSessionId || '').trim() !==
        args.mode.plannedPasskeyReconnect.sessionId
    ) {
      throw new Error(
        '[chains] threshold ECDSA reconnect admitted a different session id than the confirmed session policy',
      );
    }
    if (
      String(result.operation.lane.walletSigningSessionId || '').trim() !==
        args.mode.plannedPasskeyReconnect.walletSigningSessionId
    ) {
      throw new Error(
        '[chains] threshold ECDSA reconnect admitted a different wallet signing-session id than the confirmed session policy',
      );
    }
    return { source: 'passkey', result };
  }

  if (args.mode.kind === 'threshold_reconnect') {
    args.mode.onThresholdReconnectStarted?.();
    const result = await args.mode.ensureThresholdEcdsaKeyRefReady();
    if (!result?.keyRef || !result?.operation) {
      throw new Error('[chains] threshold ECDSA reconnect must return admitted operation');
    }
    return { source: 'threshold_reconnect', result };
  }

  args.mode satisfies never;
  return null;
}
