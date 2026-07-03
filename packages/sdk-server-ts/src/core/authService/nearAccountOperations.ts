import type { FinalExecutionOutcome, TxExecutionStatus } from '@near-js/types';
import { ActionType, type ActionArgsWasm, validateActionArgsWasm } from '@shared/near/actions';
import { errorMessage } from '@shared/utils/errors';
import { isValidAccountId } from '@shared/utils/validation';
import type { SignedDelegate } from '@shared/near/delegate';
import type { NormalizedLogger } from '../logger';
import type { MinimalNearClient, SignedTransaction } from '../rpcClients/near/NearClient';
import { fundImplicitNearAccountWithRelayer } from '../nearRelayerAccountProvisioning';
import {
  type AccountCreationRequest,
  type AccountCreationResult,
  type AuthServiceConfig,
  type FundImplicitNearAccountRequest,
  type FundImplicitNearAccountResult,
} from '../types';
import {
  type DelegateActionPolicy,
  type ExecuteSignedDelegateResult,
  executeSignedDelegateWithRelayer,
} from '../../delegateAction';
import {
  type AccountAccessKeyVisibilityOptions,
  dispatchNearSignedTransactionBorshWithClient,
  checkNearAccountExistsWithClient,
  fetchNearTxContextWithClient,
  signGasRelayerNearTransactionWithDeps,
  verifyAccountAccessKeysPresentWithClient,
  viewAccessKeyListWithClient,
} from './nearTransactions';
import {
  buildFullAccessAddKeyAction,
  normalizeBootstrapPublicKeys,
} from './registrationThresholdHelpers';

const ACCOUNT_CREATE_BROADCAST_WAIT_UNTIL: TxExecutionStatus = 'EXECUTED_OPTIMISTIC';
const ACCOUNT_CREATE_FAST_KEY_VISIBILITY_CHECK = {
  attempts: 2,
  delayMs: 100,
  finality: 'optimistic' as const,
};
const ACCOUNT_CREATE_BACKGROUND_KEY_VISIBILITY_AUDIT = {
  attempts: 8,
  delayMs: 250,
  finality: 'final' as const,
};

type NearAccountOperationsInput = {
  readonly config: AuthServiceConfig;
  readonly nearClient: MinimalNearClient;
  readonly logger: NormalizedLogger;
  readonly ensureSignerAndRelayerAccount: () => Promise<void>;
  readonly ensureSignerWasm: () => Promise<void>;
  readonly getRelayerPublicKey: () => string;
};

export class NearAccountOperations {
  private transactionQueue: Promise<unknown> = Promise.resolve();
  private queueStats = { pending: 0, completed: 0, failed: 0 };

  constructor(private readonly input: NearAccountOperationsInput) {}

  async viewAccessKeyList(accountId: string) {
    await this.input.ensureSignerAndRelayerAccount();
    return await viewAccessKeyListWithClient({
      nearClient: this.input.nearClient,
      accountId,
    });
  }

  async dispatchNearSignedTransactionBorsh(input: {
    signedTransactionBorshB64u: string;
  }): Promise<{ rpcResult: FinalExecutionOutcome }> {
    await this.input.ensureSignerAndRelayerAccount();
    return await dispatchNearSignedTransactionBorshWithClient({
      nearClient: this.input.nearClient,
      signedTransactionBorshB64u: input.signedTransactionBorshB64u,
    });
  }

  async txStatus(txHash: string, senderAccountId: string): Promise<FinalExecutionOutcome> {
    await this.input.ensureSignerAndRelayerAccount();
    return this.input.nearClient.txStatus(txHash, senderAccountId);
  }

  async createAccount(request: AccountCreationRequest): Promise<AccountCreationResult> {
    await this.input.ensureSignerAndRelayerAccount();
    return this.queueTransaction(
      this.createAccountQueueTask(request),
      `create account ${request.accountId}`,
    );
  }

  async fundImplicitNearAccount(
    request: FundImplicitNearAccountRequest,
  ): Promise<FundImplicitNearAccountResult> {
    await this.input.ensureSignerAndRelayerAccount();
    return await this.queueTransaction(
      this.createFundImplicitNearAccountQueueTask(request),
      `fund implicit NEAR account ${request.nearAccountId}`,
    );
  }

  async checkAccountExists(accountId: string): Promise<boolean> {
    await this.input.ensureSignerAndRelayerAccount();
    return await checkNearAccountExistsWithClient({
      nearClient: this.input.nearClient,
      logger: this.input.logger,
      accountId,
    });
  }

  async executeSignedDelegate(input: {
    hash: string;
    signedDelegate: SignedDelegate;
    policy?: DelegateActionPolicy;
  }): Promise<ExecuteSignedDelegateResult> {
    await this.input.ensureSignerAndRelayerAccount();

    if (!input?.hash || !input?.signedDelegate) {
      return {
        ok: false,
        code: 'invalid_delegate_request',
        error: 'hash and signedDelegate are required',
      };
    }

    const senderId = input.signedDelegate?.delegateAction?.senderId ?? 'unknown-sender';

    return this.queueTransaction(
      () =>
        executeSignedDelegateWithRelayer({
          nearClient: this.input.nearClient,
          relayerAccount: this.input.config.relayerAccount,
          relayerPublicKey: this.input.getRelayerPublicKey(),
          hash: input.hash,
          signedDelegate: input.signedDelegate,
          policy: input.policy,
          signGasRelayerNearTransaction: (args) => this.signGasRelayerNearTransaction(args),
        }),
      `execute signed delegate for ${senderId}`,
    );
  }

  async fetchTxContext(
    accountId: string,
    publicKey: string,
  ): Promise<{ nextNonce: string; blockHash: string }> {
    return await fetchNearTxContextWithClient({
      nearClient: this.input.nearClient,
      accountId,
      publicKey,
    });
  }

  async signGasRelayerNearTransaction(input: {
    receiverId: string;
    nonce: string;
    blockHash: string;
    actions: ActionArgsWasm[];
  }): Promise<SignedTransaction> {
    return await signGasRelayerNearTransactionWithDeps({
      ensureSignerWasm: this.input.ensureSignerWasm,
      relayerAccount: this.input.config.relayerAccount,
      relayerPrivateKey: this.input.config.relayerPrivateKey,
      receiverId: input.receiverId,
      nonce: input.nonce,
      blockHash: input.blockHash,
      actions: input.actions,
    });
  }

  async queueTransaction<T>(operation: () => Promise<T>, description: string): Promise<T> {
    this.queueStats.pending++;
    this.input.logger.debug(
      `[AuthService] Queueing: ${description} (pending: ${this.queueStats.pending})`,
    );

    const next = this.transactionQueue.then(async () => {
      try {
        this.input.logger.debug(`[AuthService] Executing: ${description}`);
        const result = await operation();
        this.queueStats.completed++;
        this.queueStats.pending--;
        this.input.logger.debug(
          `[AuthService] Completed: ${description} (pending: ${this.queueStats.pending})`,
        );
        return result;
      } catch (error: unknown) {
        this.queueStats.failed++;
        this.queueStats.pending--;
        this.input.logger.error(
          `[AuthService] Failed: ${description} (failed: ${this.queueStats.failed}):`,
          errorMessage(error) || 'unknown error',
        );
        throw error;
      }
    });
    this.transactionQueue = next.catch(() => undefined);
    return await next;
  }

  private createAccountQueueTask(request: AccountCreationRequest): () => Promise<AccountCreationResult> {
    return this.createAccountFromQueue.bind(this, request);
  }

  private async createAccountFromQueue(
    request: AccountCreationRequest,
  ): Promise<AccountCreationResult> {
    try {
      if (!isValidAccountId(request.accountId)) {
        throw new Error(`Invalid account ID format: ${request.accountId}`);
      }

      this.input.logger.info(`Checking if account ${request.accountId} already exists...`);
      const accountExists = await this.checkAccountExists(request.accountId);
      if (accountExists) {
        throw new Error(
          `Account ${request.accountId} already exists. Cannot create duplicate account.`,
        );
      }
      this.input.logger.info(`Account ${request.accountId} is available for creation`);

      const initialBalance = this.input.config.accountInitialBalance;
      const { publicKey, recoveryPublicKey, expectedPublicKeys } = normalizeBootstrapPublicKeys({
        publicKey: request.publicKey,
        recoveryPublicKey: request.recoveryPublicKey,
      });

      this.input.logger.info(`Creating account: ${request.accountId}`);
      this.input.logger.info(`Initial balance: ${initialBalance} yoctoNEAR`);

      const actions: ActionArgsWasm[] = [
        { action_type: ActionType.CreateAccount },
        { action_type: ActionType.Transfer, deposit: String(initialBalance) },
        buildFullAccessAddKeyAction(publicKey),
        ...(recoveryPublicKey ? [buildFullAccessAddKeyAction(recoveryPublicKey)] : []),
      ];
      actions.forEach(validateActionArgsWasm);

      const { nextNonce, blockHash } = await this.fetchTxContext(
        this.input.config.relayerAccount,
        this.input.getRelayerPublicKey(),
      );
      const signed = await this.signGasRelayerNearTransaction({
        receiverId: request.accountId,
        nonce: nextNonce,
        blockHash,
        actions,
      });

      const createAccountBroadcastStartedAt = Date.now();
      const result = await this.input.nearClient.sendTransaction(
        signed,
        ACCOUNT_CREATE_BROADCAST_WAIT_UNTIL,
      );
      this.input.logger.info(
        `Account creation for ${request.accountId} reached ${ACCOUNT_CREATE_BROADCAST_WAIT_UNTIL} in ${
          Date.now() - createAccountBroadcastStartedAt
        }ms`,
      );
      const createAccountKeyCheckStartedAt = Date.now();
      const keysVerified = await this.verifyAccountAccessKeysPresent(
        request.accountId,
        expectedPublicKeys,
        ACCOUNT_CREATE_FAST_KEY_VISIBILITY_CHECK,
      );
      this.input.logger.info(
        `Account creation for ${request.accountId} key visibility verified=${keysVerified} in ${
          Date.now() - createAccountKeyCheckStartedAt
        }ms`,
      );
      if (!keysVerified) {
        this.input.logger.warn(
          recoveryPublicKey
            ? 'Bootstrap committed before both access keys were visible on final state; scheduling background audit'
            : 'Bootstrap committed before the operational access key was visible on final state; scheduling background audit',
        );
        this.scheduleAccountAccessKeyVisibilityAudit({
          accountId: request.accountId,
          expectedPublicKeys,
          contextLabel: `Account creation for ${request.accountId}`,
        });
      }

      this.input.logger.info(`Account creation completed: ${result.transaction.hash}`);
      const nearAmount = (Number(BigInt(initialBalance)) / 1e24).toFixed(6);
      return {
        success: true,
        transactionHash: result.transaction.hash,
        accountId: request.accountId,
        message: `Account ${request.accountId} created with ${nearAmount} NEAR initial balance`,
      };
    } catch (error: unknown) {
      this.input.logger.error(`Account creation failed for ${request.accountId}:`, error);
      const msg = errorMessage(error) || 'Unknown account creation error';
      return {
        success: false,
        error: msg,
        message: `Failed to create account ${request.accountId}: ${msg}`,
      };
    }
  }

  private createFundImplicitNearAccountQueueTask(
    request: FundImplicitNearAccountRequest,
  ): () => Promise<FundImplicitNearAccountResult> {
    return this.fundImplicitNearAccountFromQueue.bind(this, request);
  }

  private async fundImplicitNearAccountFromQueue(
    request: FundImplicitNearAccountRequest,
  ): Promise<FundImplicitNearAccountResult> {
    return await fundImplicitNearAccountWithRelayer({
      ...request,
      relayerAccount: this.input.config.relayerAccount,
      relayerPrivateKey: this.input.config.relayerPrivateKey,
      relayerPublicKey: this.input.getRelayerPublicKey(),
      nearRpcUrl: this.input.config.nearRpcUrl,
      fundedAmountYocto: this.input.config.accountInitialBalance,
      nearClient: this.input.nearClient,
      ensureSignerWasm: this.input.ensureSignerWasm,
    });
  }

  private async verifyAccountAccessKeysPresent(
    accountId: string,
    expectedPublicKeys: string[],
    opts?: AccountAccessKeyVisibilityOptions,
  ): Promise<boolean> {
    return await verifyAccountAccessKeysPresentWithClient({
      nearClient: this.input.nearClient,
      accountId,
      expectedPublicKeys,
      options: opts,
    });
  }

  private scheduleAccountAccessKeyVisibilityAudit(input: {
    accountId: string;
    expectedPublicKeys: string[];
    contextLabel: string;
  }): void {
    void this.runAccountAccessKeyVisibilityAudit(input);
  }

  private async runAccountAccessKeyVisibilityAudit(input: {
    accountId: string;
    expectedPublicKeys: string[];
    contextLabel: string;
  }): Promise<void> {
    try {
      const startedAt = Date.now();
      const verified = await this.verifyAccountAccessKeysPresent(
        input.accountId,
        input.expectedPublicKeys,
        ACCOUNT_CREATE_BACKGROUND_KEY_VISIBILITY_AUDIT,
      );
      if (verified) {
        this.input.logger.info(
          `${input.contextLabel} final key visibility verified=true in ${Date.now() - startedAt}ms`,
        );
        return;
      }
      this.input.logger.warn(
        `${input.contextLabel} final key visibility is still pending after ${
          Date.now() - startedAt
        }ms`,
      );
    } catch (error: unknown) {
      this.input.logger.warn(`${input.contextLabel} final key visibility audit failed`, error);
    }
  }
}
