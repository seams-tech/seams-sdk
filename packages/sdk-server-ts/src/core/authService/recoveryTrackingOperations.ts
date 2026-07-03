import type { RecoveryExecutionStatus } from '../RecoveryExecutionStore';
import type { RecoverySessionStatus } from '../RecoverySessionStore';
import type { RecoveryExecutionStore } from '../RecoveryExecutionStore';
import type { RecoverySessionStore } from '../RecoverySessionStore';
import {
  getRecoveryExecutionWithStore,
  getRecoverySessionWithStore,
  listRecoveryExecutionsByStatusWithStore,
  listRecoveryExecutionsWithStore,
  recordRecoveryExecutionWithStores,
  updateRecoverySessionStatusWithStore,
  type GetRecoveryExecutionResult,
  type GetRecoverySessionResult,
  type ListRecoveryExecutionsResult,
  type RecordRecoveryExecutionResult,
  type UpdateRecoverySessionStatusResult,
} from './recoveryTracking';

type RecoveryTrackingOperationsInput = {
  readonly recoverySessionStore: RecoverySessionStore;
  readonly recoveryExecutionStore: RecoveryExecutionStore;
};

export class RecoveryTrackingOperations {
  constructor(private readonly input: RecoveryTrackingOperationsInput) {}

  async getRecoverySession(input: { sessionId: string }): Promise<GetRecoverySessionResult> {
    return await getRecoverySessionWithStore({
      store: this.input.recoverySessionStore,
      sessionId: input.sessionId,
    });
  }

  async updateRecoverySessionStatus(input: {
    sessionId: string;
    status: RecoverySessionStatus;
    metadataPatch?: Record<string, unknown> | null;
  }): Promise<UpdateRecoverySessionStatusResult> {
    return await updateRecoverySessionStatusWithStore({
      store: this.input.recoverySessionStore,
      sessionId: input.sessionId,
      status: input.status,
      metadataPatch: input.metadataPatch,
    });
  }

  async getRecoveryExecution(input: {
    sessionId: string;
    chainIdKey: string;
    accountAddress: string;
    action: string;
  }): Promise<GetRecoveryExecutionResult> {
    return await getRecoveryExecutionWithStore({
      store: this.input.recoveryExecutionStore,
      sessionId: input.sessionId,
      chainIdKey: input.chainIdKey,
      accountAddress: input.accountAddress,
      action: input.action,
    });
  }

  async listRecoveryExecutions(input: {
    sessionId: string;
  }): Promise<ListRecoveryExecutionsResult> {
    return await listRecoveryExecutionsWithStore({
      store: this.input.recoveryExecutionStore,
      sessionId: input.sessionId,
    });
  }

  async listRecoveryExecutionsByStatus(input: {
    status: RecoveryExecutionStatus;
    action?: string;
    updatedBeforeMs?: number;
    limit?: number;
  }): Promise<ListRecoveryExecutionsResult> {
    return await listRecoveryExecutionsByStatusWithStore({
      store: this.input.recoveryExecutionStore,
      status: input.status,
      action: input.action,
      updatedBeforeMs: input.updatedBeforeMs,
      limit: input.limit,
    });
  }

  async recordRecoveryExecution(input: {
    sessionId: string;
    chainIdKey: string;
    accountAddress: string;
    action: string;
    status: RecoveryExecutionStatus;
    transactionHash?: string;
    errorCode?: string;
    errorMessage?: string;
    metadata?: Record<string, unknown>;
  }): Promise<RecordRecoveryExecutionResult> {
    return await recordRecoveryExecutionWithStores({
      recoverySessionStore: this.input.recoverySessionStore,
      recoveryExecutionStore: this.input.recoveryExecutionStore,
      sessionId: input.sessionId,
      chainIdKey: input.chainIdKey,
      accountAddress: input.accountAddress,
      action: input.action,
      status: input.status,
      transactionHash: input.transactionHash,
      errorCode: input.errorCode,
      errorMessage: input.errorMessage,
      metadata: input.metadata,
    });
  }
}
