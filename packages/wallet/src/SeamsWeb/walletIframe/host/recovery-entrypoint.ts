import {
  WalletRecoveryCoordinator,
  type WalletRecoveryEmailOtpVerifiedHandle,
  type WalletRecoveryCredentialCreatedHandle,
  type WalletRecoveryGoogleVerifiedHandle,
  type WalletRecoveryPreparedHandle,
} from '@/SeamsWeb/operations/recovery/walletRecovery';
import type { WalletRecoveryWebContext } from '@/SeamsWeb/signingSurface/ports';
import type {
  HostedRecoveryEmailOtpVerified,
  HostedRecoveryCredentialCreated,
  HostedRecoveryFailure,
  HostedRecoveryFinalizationOperation,
  HostedRecoveryGoogleVerified,
  HostedRecoveryPort,
  HostedRecoveryPrepared,
  HostedRecoveryTargetKind,
} from './recovery-port';
import { parseWebAuthnRpId, type WebAuthnRpId } from '@shared/utils/domainIds';
import type { WalletRecoveryTargetV1 } from '@shared/wallet-recovery/walletRecoveryTarget';
import {
  finalizeWalletRecoveryGoogleEmailOtp,
  verifyWalletRecoveryEmailOtp,
  verifyWalletRecoveryGoogle,
} from '@/core/rpcClients/relayer/walletRecoveryGoogleEmailOtp';

class CoordinatorHostedRecoveryPort implements HostedRecoveryPort {
  readonly #coordinator = new WalletRecoveryCoordinator({
    verifyGoogle: verifyWalletRecoveryGoogle,
    verifyEmailOtp: verifyWalletRecoveryEmailOtp,
    finalizeEmailOtp: finalizeWalletRecoveryGoogleEmailOtp,
  });

  constructor(
    private readonly context: WalletRecoveryWebContext,
    private readonly relayUrl: string,
  ) {
    const rpId = parseWebAuthnRpId(context.signingEngine.getRpId());
    if (!rpId.ok) throw new Error(`wallet recovery RP ID ${rpId.error.message}`);
    this.#passkeyRpId = rpId.value;
  }

  readonly #passkeyRpId: WebAuthnRpId;

  targetFor(kind: HostedRecoveryTargetKind): WalletRecoveryTargetV1 {
    switch (kind) {
      case 'passkey':
        return { kind, rpId: this.#passkeyRpId };
      case 'google_email_otp':
        return { kind, googleProvider: 'google' };
    }
  }

  async prepare(input: {
    readonly recoveryCode: string;
    readonly target: WalletRecoveryTargetV1;
    readonly signal: AbortSignal;
  }): Promise<HostedRecoveryPrepared | HostedRecoveryFailure> {
    const result = await this.#coordinator.prepareWithCode({
      context: this.context,
      relayUrl: this.relayUrl,
      recoveryCode: input.recoveryCode,
      target: input.target,
      signal: input.signal,
    });
    if (result.kind !== 'prepared') return result;
    if (result.target.kind === 'passkey') {
      return {
        kind: 'hosted_recovery_prepared',
        recoveryOperationId: result.recoveryOperationId,
        walletId: result.walletId,
        target: result.target,
      };
    }
    return {
      kind: 'hosted_recovery_prepared',
      recoveryOperationId: result.recoveryOperationId,
      walletId: result.walletId,
      target: result.target,
    };
  }

  createPasskey(
    operation: HostedRecoveryPrepared,
  ): Promise<HostedRecoveryCredentialCreated | HostedRecoveryFailure> {
    return this.#createPasskey({
      kind: 'prepared',
      recoveryOperationId: operation.recoveryOperationId,
      walletId: operation.walletId,
      target: operation.target,
    });
  }

  async verifyGoogle(
    operation: HostedRecoveryPrepared,
    idToken: string,
  ): Promise<HostedRecoveryGoogleVerified | HostedRecoveryFailure> {
    const result = await this.#coordinator.verifyGoogle({
      relayUrl: this.relayUrl,
      operation: {
        kind: 'prepared',
        recoveryOperationId: operation.recoveryOperationId,
        walletId: operation.walletId,
        target: operation.target,
      },
      idToken,
    });
    if (result.kind !== 'google_verified') return result;
    return {
      kind: 'hosted_recovery_google_verified',
      recoveryOperationId: result.recoveryOperationId,
      walletId: result.walletId,
      target: result.target,
      challengeId: result.challengeId,
      delivery: result.delivery,
      expiresAtMs: result.expiresAtMs,
    };
  }

  async verifyEmailOtp(
    operation: HostedRecoveryGoogleVerified,
    input: { readonly challengeId: string; readonly otpCode: string },
  ): Promise<HostedRecoveryEmailOtpVerified | HostedRecoveryFailure> {
    const result = await this.#coordinator.verifyEmailOtp({
      context: this.context,
      operation: {
        kind: 'google_verified',
        recoveryOperationId: operation.recoveryOperationId,
        walletId: operation.walletId,
        target: operation.target,
        challengeId: operation.challengeId,
        delivery: operation.delivery,
        expiresAtMs: operation.expiresAtMs,
      },
      challengeId: input.challengeId,
      otpCode: input.otpCode,
    });
    if (result.kind !== 'email_otp_verified') return result;
    return {
      kind: 'hosted_recovery_email_otp_verified',
      recoveryOperationId: result.recoveryOperationId,
      walletId: result.walletId,
      target: result.target,
      challengeId: result.challengeId,
    };
  }

  async finalize(operation: HostedRecoveryFinalizationOperation): Promise<
    | {
        readonly kind: 'ready_for_sign_in';
        readonly walletId: HostedRecoveryCredentialCreated['walletId'];
      }
    | HostedRecoveryFailure
  > {
    if (operation.kind === 'hosted_recovery_credential_created') {
      return await this.#coordinator.finalize({
        context: this.context,
        operation: {
          kind: 'credential_created',
          recoveryOperationId: operation.recoveryOperationId,
          walletId: operation.walletId,
          target: operation.target,
        },
      });
    }
    return await this.#coordinator.finalize({
      context: this.context,
      operation: {
        kind: 'email_otp_verified',
        recoveryOperationId: operation.recoveryOperationId,
        walletId: operation.walletId,
        target: operation.target,
        challengeId: operation.challengeId,
      },
    });
  }

  async cancel(
    operation:
      | HostedRecoveryPrepared
      | HostedRecoveryCredentialCreated
      | HostedRecoveryGoogleVerified
      | HostedRecoveryEmailOtpVerified,
  ): Promise<void> {
    this.#coordinator.cancel(operation.recoveryOperationId);
  }

  async #createPasskey(
    operation: WalletRecoveryPreparedHandle,
  ): Promise<HostedRecoveryCredentialCreated | HostedRecoveryFailure> {
    const result = await this.#coordinator.createPasskey({
      context: this.context,
      operation,
    });
    if (result.kind !== 'credential_created') return result;
    return this.#hostedCredentialCreated(result);
  }

  #hostedCredentialCreated(
    result: WalletRecoveryCredentialCreatedHandle,
  ): HostedRecoveryCredentialCreated {
    return {
      kind: 'hosted_recovery_credential_created',
      recoveryOperationId: result.recoveryOperationId,
      walletId: result.walletId,
      target: result.target,
    };
  }
}

export function createHostedRecoveryPort(input: {
  readonly context: WalletRecoveryWebContext;
  readonly relayUrl: string;
}): HostedRecoveryPort {
  return new CoordinatorHostedRecoveryPort(input.context, input.relayUrl);
}
