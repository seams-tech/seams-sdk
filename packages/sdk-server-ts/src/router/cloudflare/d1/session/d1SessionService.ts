import { toOptionalTrimmedString } from '@shared/utils/validation';
import { buildRecoveryExecutionRecord } from '../../core/recoveryExecutionRecords';
import type {
  RouterApiRecoveryRouteService,
  RouterApiSessionVersionService,
} from '../authServicePort';
import {
  normalizeAccountAddress,
  parseRecoverySessionStatus,
  recoverySessionWithStatus,
} from './d1SessionRecords';
import { CloudflareD1SessionStore } from './d1SessionStore';
import { isRecordValue } from './d1RouterApiAuthBoundary';

type GetRecoverySessionInput = Parameters<RouterApiRecoveryRouteService['getRecoverySession']>[0];
type GetRecoverySessionResult = Awaited<
  ReturnType<RouterApiRecoveryRouteService['getRecoverySession']>
>;
type UpdateRecoverySessionStatusInput =
  Parameters<RouterApiRecoveryRouteService['updateRecoverySessionStatus']>[0];
type UpdateRecoverySessionStatusResult = Awaited<
  ReturnType<RouterApiRecoveryRouteService['updateRecoverySessionStatus']>
>;
type RecordRecoveryExecutionInput =
  Parameters<RouterApiRecoveryRouteService['recordRecoveryExecution']>[0];
type RecordRecoveryExecutionResult = Awaited<
  ReturnType<RouterApiRecoveryRouteService['recordRecoveryExecution']>
>;
type GetOrCreateAppSessionVersionInput =
  Parameters<RouterApiSessionVersionService['getOrCreateAppSessionVersion']>[0];
type GetOrCreateAppSessionVersionResult = Awaited<
  ReturnType<RouterApiSessionVersionService['getOrCreateAppSessionVersion']>
>;
type RotateAppSessionVersionInput =
  Parameters<RouterApiSessionVersionService['rotateAppSessionVersion']>[0];
type RotateAppSessionVersionResult = Awaited<
  ReturnType<RouterApiSessionVersionService['rotateAppSessionVersion']>
>;
type ValidateAppSessionVersionInput =
  Parameters<RouterApiSessionVersionService['validateAppSessionVersion']>[0];
type ValidateAppSessionVersionResult = Awaited<
  ReturnType<RouterApiSessionVersionService['validateAppSessionVersion']>
>;

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error || '');
}

export class CloudflareD1SessionService {
  private readonly sessionStore: CloudflareD1SessionStore;

  constructor(input: { readonly sessionStore: CloudflareD1SessionStore }) {
    this.sessionStore = input.sessionStore;
  }

  async getRecoverySession(input: GetRecoverySessionInput): Promise<GetRecoverySessionResult> {
    try {
      const sessionId = toOptionalTrimmedString(input.sessionId);
      if (!sessionId) return { ok: false, code: 'invalid_args', message: 'Missing sessionId' };
      return { ok: true, record: await this.sessionStore.readRecoverySessionRecord(sessionId) };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to read recovery session',
      };
    }
  }

  async updateRecoverySessionStatus(
    input: UpdateRecoverySessionStatusInput,
  ): Promise<UpdateRecoverySessionStatusResult> {
    try {
      const sessionId = toOptionalTrimmedString(input.sessionId);
      const status = parseRecoverySessionStatus(input.status);
      if (!sessionId || !status) {
        return { ok: false, code: 'invalid_args', message: 'Invalid recovery session update' };
      }
      if (input.metadataPatch != null && !isRecordValue(input.metadataPatch)) {
        return { ok: false, code: 'invalid_args', message: 'Invalid recovery metadata patch' };
      }

      const existing = await this.sessionStore.readRecoverySessionRecord(sessionId);
      if (!existing) {
        return {
          ok: false,
          code: 'invalid_args',
          message: `Unknown recovery session: ${sessionId}`,
        };
      }
      const record = recoverySessionWithStatus({
        record: existing,
        status,
        updatedAtMs: Date.now(),
        ...(input.metadataPatch ? { metadataPatch: input.metadataPatch } : {}),
      });
      await this.sessionStore.putRecoverySessionRecord(record);
      return { ok: true, record };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to update recovery session',
      };
    }
  }

  async recordRecoveryExecution(
    input: RecordRecoveryExecutionInput,
  ): Promise<RecordRecoveryExecutionResult> {
    try {
      const sessionId = toOptionalTrimmedString(input.sessionId);
      const chainIdKey = toOptionalTrimmedString(input.chainIdKey)?.toLowerCase() || '';
      const accountAddress = normalizeAccountAddress(input.accountAddress);
      const action = toOptionalTrimmedString(input.action);
      if (!sessionId || !chainIdKey || !accountAddress || !action) {
        return { ok: false, code: 'invalid_args', message: 'Missing recovery execution fields' };
      }

      const recoverySession = await this.sessionStore.readRecoverySessionRecord(sessionId);
      if (!recoverySession) {
        return {
          ok: false,
          code: 'invalid_args',
          message: `Unknown recovery session: ${sessionId}`,
        };
      }

      const existing = await this.sessionStore.readRecoveryExecutionRecord({
        sessionId,
        chainIdKey,
        accountAddress,
        action,
      });
      const nowMs = Date.now();
      const record = buildRecoveryExecutionRecord({
        sessionId,
        userId: recoverySession.userId,
        nearAccountId: recoverySession.nearAccountId,
        chainIdKey,
        accountAddress,
        action,
        status: input.status,
        createdAtMs: existing?.createdAtMs ?? nowMs,
        nowMs,
        transactionHash: input.transactionHash,
        errorCode: input.errorCode,
        errorMessage: input.errorMessage,
        metadata: input.metadata,
      });
      if (!record) {
        return {
          ok: false,
          code: 'invalid_args',
          message: 'Invalid recovery execution payload',
        };
      }

      await this.sessionStore.putRecoveryExecutionRecord(record);
      return { ok: true, record };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to persist recovery execution',
      };
    }
  }

  async getOrCreateAppSessionVersion(
    input: GetOrCreateAppSessionVersionInput,
  ): Promise<GetOrCreateAppSessionVersionResult> {
    try {
      const userId = toOptionalTrimmedString(input.userId);
      if (!userId) return { ok: false, code: 'invalid_args', message: 'Missing userId' };
      return {
        ok: true,
        appSessionVersion: await this.sessionStore.getOrCreateAppSessionVersion(userId),
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to ensure app session version',
      };
    }
  }

  async rotateAppSessionVersion(
    input: RotateAppSessionVersionInput,
  ): Promise<RotateAppSessionVersionResult> {
    try {
      const userId = toOptionalTrimmedString(input.userId);
      if (!userId) return { ok: false, code: 'invalid_args', message: 'Missing userId' };
      return {
        ok: true,
        appSessionVersion: await this.sessionStore.rotateAppSessionVersion(userId),
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to rotate app session version',
      };
    }
  }

  async validateAppSessionVersion(
    input: ValidateAppSessionVersionInput,
  ): Promise<ValidateAppSessionVersionResult> {
    try {
      const userId = toOptionalTrimmedString(input.userId);
      const appSession = toOptionalTrimmedString(input.appSessionVersion);
      if (!userId || !appSession) {
        return { ok: false, code: 'unauthorized', message: 'Invalid app session' };
      }
      const current = await this.sessionStore.readAppSessionVersion(userId);
      if (!current || current !== appSession) {
        return { ok: false, code: 'invalid_session_version', message: 'App session revoked' };
      }
      return { ok: true };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to validate app session version',
      };
    }
  }
}
