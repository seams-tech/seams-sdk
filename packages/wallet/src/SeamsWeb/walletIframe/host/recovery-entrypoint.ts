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
} from './recovery-port';

class CoordinatorHostedRecoveryPort implements HostedRecoveryPort {
  readonly #coordinator = new WalletRecoveryCoordinator();

  constructor(
    private readonly context: WalletRecoveryWebContext,
    private readonly relayUrl: string,
  ) {}

  async prepare(input: {
    readonly recoveryCode: string;
    readonly signal: AbortSignal;
  }): Promise<HostedRecoveryPrepared | HostedRecoveryFailure> {
    const result = await this.#coordinator.prepareWithCode({
      context: this.context,
      relayUrl: this.relayUrl,
      recoveryCode: input.recoveryCode,
      signal: input.signal,
    });
    if (result.kind !== 'prepared') return result;
    return {
      kind: 'hosted_recovery_prepared',
      recoveryOperationId: result.recoveryOperationId,
      walletId: result.walletId,
    };
  }

  createPasskey(
    operation: HostedRecoveryPrepared,
  ): Promise<HostedRecoveryCredentialCreated | HostedRecoveryFailure> {
    return this.#createPasskey({
      kind: 'prepared',
      recoveryOperationId: operation.recoveryOperationId,
      walletId: operation.walletId,
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
    };
  }
}

export function createHostedRecoveryPort(input: {
  readonly context: WalletRecoveryWebContext;
  readonly relayUrl: string;
}): HostedRecoveryPort {
  return new CoordinatorHostedRecoveryPort(input.context, input.relayUrl);
}
