import {
  toReadyEcdsaSignerSessionFromReadyMaterial,
  type ReadyEcdsaSignerSession,
  type ReadyEvmFamilyEcdsaMaterial,
} from '../../session/identity/evmFamilyEcdsaIdentity';
import type { SelectedEcdsaLane } from '../../session/identity/laneIdentity';
import type { BudgetAdmittedTransactionOperation } from '../../session/operationState/transactionState';
import type { SigningAuthPlan } from '../../stepUpConfirmation/types';
import type {
  EvmFamilyEcdsaEmailOtpStepUpAuthorization,
  EvmFamilyEcdsaPasskeyStepUpAuthorization,
  EvmFamilyEcdsaWarmSessionStepUpAuthorization,
} from './stepUpAuthorization';

export type EvmFamilyThresholdEcdsaOperation = BudgetAdmittedTransactionOperation<
  SelectedEcdsaLane,
  SigningAuthPlan
>;

export type EvmFamilyThresholdEcdsaReauthResult = {
  readyMaterial: ReadyEvmFamilyEcdsaMaterial;
  signerSession: ReadyEcdsaSignerSession;
  operation: EvmFamilyThresholdEcdsaOperation;
};

export async function buildEvmFamilyThresholdEcdsaReauthResult(args: {
  readyMaterial: ReadyEvmFamilyEcdsaMaterial;
  operation: EvmFamilyThresholdEcdsaOperation;
}): Promise<EvmFamilyThresholdEcdsaReauthResult> {
  return {
    readyMaterial: args.readyMaterial,
    signerSession: await toReadyEcdsaSignerSessionFromReadyMaterial({
      material: args.readyMaterial,
    }),
    operation: args.operation,
  };
}

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
    authorization: EvmFamilyEcdsaEmailOtpStepUpAuthorization,
  ) => Promise<EvmFamilyThresholdEcdsaReauthResult>;
};

export type EvmFamilyThresholdEcdsaPasskeyReconnect = {
  reconnect: (args: {
    authorization: EvmFamilyEcdsaPasskeyStepUpAuthorization;
    usesNeeded: number;
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

export type EvmFamilyThresholdEcdsaAdmissionConfirmation =
  | {
      kind: 'none';
    }
  | {
      kind: 'warm_session';
      authorization: EvmFamilyEcdsaWarmSessionStepUpAuthorization;
    }
  | {
      kind: 'email_otp';
      authorization: EvmFamilyEcdsaEmailOtpStepUpAuthorization;
    }
  | {
      kind: 'passkey';
      authorization: EvmFamilyEcdsaPasskeyStepUpAuthorization;
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
      onThresholdReconnectStarted?: () => void;
    }
  | {
      kind: 'threshold_reconnect';
      ensureThresholdEcdsaReadyMaterial: (args: {
        authorization: EvmFamilyEcdsaWarmSessionStepUpAuthorization;
        usesNeeded: number;
      }) => Promise<EvmFamilyThresholdEcdsaReauthResult>;
      onThresholdReconnectStarted?: () => void;
    };

export async function completeEvmFamilyThresholdEcdsaAdmissionAfterConfirmation(args: {
  mode: EvmFamilyThresholdEcdsaAdmissionMode;
  confirmation: EvmFamilyThresholdEcdsaAdmissionConfirmation;
  usesNeeded: number;
}): Promise<EvmFamilyThresholdEcdsaAdmissionCompletion | null> {
  if (args.mode.kind === 'not_required' || args.mode.kind === 'already_admitted') return null;

  if (args.mode.kind === 'email_otp') {
    if (args.confirmation.kind !== 'email_otp') {
      throw new Error('[chains] Email OTP admission requires Email OTP confirmation');
    }
    const result = await args.mode.emailOtpSigning.complete(args.confirmation.authorization);
    if (!result?.readyMaterial || !result?.signerSession || !result?.operation) {
      throw new Error('[chains] Email OTP ECDSA reauth must return admitted operation');
    }
    return { source: 'email_otp', result };
  }

  if (args.mode.kind === 'passkey_reconnect') {
    if (args.confirmation.kind !== 'passkey') {
      throw new Error('[chains] passkey admission requires WebAuthn confirmation');
    }
    args.mode.onThresholdReconnectStarted?.();
    const result = await args.mode.passkeyEcdsaReconnect.reconnect({
      authorization: args.confirmation.authorization,
      usesNeeded: args.usesNeeded,
    });
    if (!result?.readyMaterial || !result?.signerSession || !result?.operation) {
      throw new Error('[chains] passkey ECDSA reconnect must return admitted operation');
    }
    if (!args.confirmation.authorization.plannedPasskeyReconnect) {
      throw new Error(
        '[chains] passkey ECDSA reconnect requires planned session identity in authorization',
      );
    }
    if (
      String(result.operation.lane.thresholdSessionId || '').trim() !==
        args.confirmation.authorization.plannedPasskeyReconnect.sessionId
    ) {
      throw new Error(
        '[chains] threshold ECDSA reconnect admitted a different session id than the confirmed session policy',
      );
    }
    if (
      String(result.operation.lane.walletSigningSessionId || '').trim() !==
        args.confirmation.authorization.plannedPasskeyReconnect.walletSigningSessionId
    ) {
      throw new Error(
        '[chains] threshold ECDSA reconnect admitted a different wallet signing-session id than the confirmed session policy',
      );
    }
    return { source: 'passkey', result };
  }

  if (args.mode.kind === 'threshold_reconnect') {
    if (args.confirmation.kind !== 'warm_session') {
      throw new Error('[chains] threshold ECDSA reconnect requires warm-session authorization');
    }
    args.mode.onThresholdReconnectStarted?.();
    const result = await args.mode.ensureThresholdEcdsaReadyMaterial({
      authorization: args.confirmation.authorization,
      usesNeeded: args.usesNeeded,
    });
    if (!result?.readyMaterial || !result?.signerSession || !result?.operation) {
      throw new Error('[chains] threshold ECDSA reconnect must return admitted operation');
    }
    return { source: 'threshold_reconnect', result };
  }

  args.mode satisfies never;
  return null;
}
