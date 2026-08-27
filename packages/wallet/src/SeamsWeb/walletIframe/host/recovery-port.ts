import type { WalletId } from '@shared/utils/domainIds';
import type { WalletRecoveryTargetV1 } from '@shared/wallet-recovery/walletRecoveryTarget';

export type HostedRecoveryTargetKind = WalletRecoveryTargetV1['kind'];

export type HostedRecoveryFailure =
  | { readonly kind: 'dismissed' }
  | { readonly kind: 'refused' }
  | { readonly kind: 'retryable_conflict' }
  | { readonly kind: 'transport_uncertain' };

export type HostedRecoveryPrepared = {
  readonly kind: 'hosted_recovery_prepared';
  readonly recoveryOperationId: string;
  readonly walletId: WalletId;
  readonly target: WalletRecoveryTargetV1;
};

export type HostedRecoveryCredentialCreated = {
  readonly kind: 'hosted_recovery_credential_created';
  readonly recoveryOperationId: string;
  readonly walletId: WalletId;
  readonly target: WalletRecoveryTargetV1;
};

export type HostedRecoveryPort = {
  targetFor(kind: HostedRecoveryTargetKind): WalletRecoveryTargetV1;

  prepare(input: {
    readonly recoveryCode: string;
    readonly target: WalletRecoveryTargetV1;
    readonly signal: AbortSignal;
  }): Promise<HostedRecoveryPrepared | HostedRecoveryFailure>;

  createPasskey(
    operation: HostedRecoveryPrepared,
  ): Promise<HostedRecoveryCredentialCreated | HostedRecoveryFailure>;

  finalize(
    operation: HostedRecoveryCredentialCreated,
  ): Promise<
    { readonly kind: 'ready_for_sign_in'; readonly walletId: WalletId } | HostedRecoveryFailure
  >;

  cancel(operation: HostedRecoveryPrepared | HostedRecoveryCredentialCreated): Promise<void>;
};
