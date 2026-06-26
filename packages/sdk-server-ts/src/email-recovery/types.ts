import type { MinimalNearClient, SignedTransaction } from '../core/rpcClients/near/NearClient';
import type { ActionArgsWasm } from '@shared/near/actions';
import type { RecoverySubjectBinding, RecoveryTargetKeySet } from '@shared/utils';
import type { Logger } from '../core/logger';
import type { RecoveryEmailPayload } from '@shared/utils/recoveryEmail';

export interface EmailRecoveryServiceDeps {
  relayerAccount: string;
  networkId: string;
  emailDkimVerifierContract: string;
  nearClient: MinimalNearClient;
  /**
   * Optional logger. When unset, EmailRecoveryService is silent (no `console.*`).
   * Pass `logger: console` to enable default logging.
   */
  logger?: Logger | null;
  ensureSignerAndRelayerAccount: () => Promise<void>;
  queueTransaction<T>(fn: () => Promise<T>, label: string): Promise<T>;
  fetchTxContext(
    accountId: string,
    publicKey: string,
  ): Promise<{ nextNonce: string; blockHash: string }>;
  signGasRelayerNearTransaction(input: {
    receiverId: string;
    nonce: string;
    blockHash: string;
    actions: ActionArgsWasm[];
  }): Promise<SignedTransaction>;
  getRelayerPublicKey(): string;
}

export interface EmailRecoveryRequest {
  accountId: RecoverySubjectBinding['nearAccountId'];
  emailBlob: string;
  recoveryPayload: RecoveryEmailPayload;
}

export interface VerifiedEmailRecoveryRequest {
  version: 'verified_email_recovery_request_v1';
  nearAccountId: RecoverySubjectBinding['nearAccountId'];
  recoverySessionId: RecoverySubjectBinding['recoverySessionId'];
  newNearPublicKey: RecoveryTargetKeySet['newNearPublicKey'];
  newEvmOwnerAddress: RecoveryTargetKeySet['newEvmOwnerAddress'];
  deadlineEpochSeconds: RecoverySubjectBinding['deadlineEpochSeconds'];
  scope?: RecoverySubjectBinding['scope'];
}

export interface EmailRecoveryResult {
  success: boolean;
  transactionHash?: string;
  message?: string;
  error?: string;
}
