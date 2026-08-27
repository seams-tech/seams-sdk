import {
  WalletRecoveryCoordinator,
  type WalletRecoveryCredentialCreatedHandle,
  type WalletRecoveryPreparedHandle,
} from '@/SeamsWeb/operations/recovery/walletRecovery';
import type { WalletRecoveryWebContext } from '@/SeamsWeb/signingSurface/ports';
import type {
  HostedRecoveryCredentialCreated,
  HostedRecoveryFailure,
  HostedRecoveryPort,
  HostedRecoveryPrepared,
  HostedRecoveryTargetKind,
} from './recovery-port';
import {
  parseWebAuthnRpId,
  type WebAuthnRpId,
} from '@shared/utils/domainIds';
import type { WalletRecoveryTargetV1 } from '@shared/wallet-recovery/walletRecoveryTarget';

class CoordinatorHostedRecoveryPort implements HostedRecoveryPort {
  readonly #coordinator = new WalletRecoveryCoordinator();

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

  async finalize(operation: HostedRecoveryCredentialCreated): Promise<
    | {
        readonly kind: 'ready_for_sign_in';
        readonly walletId: HostedRecoveryCredentialCreated['walletId'];
      }
    | HostedRecoveryFailure
  > {
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

  async cancel(operation: HostedRecoveryPrepared | HostedRecoveryCredentialCreated): Promise<void> {
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
