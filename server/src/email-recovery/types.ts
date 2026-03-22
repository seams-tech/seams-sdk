import type { MinimalNearClient, SignedTransaction } from '@/core/rpcClients/near/NearClient';
import type { ActionArgsWasm } from '@/core/types/actions';
import type { Logger } from '../core/logger';
import type { RecoveryEmailPayload } from '@shared/utils/recoveryEmail';

export interface EmailRecoveryServiceDeps {
  relayerAccount: string;
  relayerPrivateKey: string;
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
  signWithPrivateKey(input: {
    nearPrivateKey: string;
    signerAccountId: string;
    receiverId: string;
    nonce: string;
    blockHash: string;
    actions: ActionArgsWasm[];
  }): Promise<SignedTransaction>;
  getRelayerPublicKey(): string;
}

export interface EmailRecoveryRequest {
  accountId: string;
  emailBlob: string;
  recoveryPayload: RecoveryEmailPayload;
}

export interface EmailRecoveryResult {
  success: boolean;
  transactionHash?: string;
  message?: string;
  error?: string;
}
